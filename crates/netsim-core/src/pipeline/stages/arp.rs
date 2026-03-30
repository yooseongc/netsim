//! ARP processing stage
//!
//! Handles arp_ignore level 1 and 2 checks. Only applies to ARP packets.
//! Also provides ARP resolution for forwarded packets (resolve next-hop MAC).

use std::net::IpAddr;

use ipnet::IpNet;

use crate::model::interface::find_interface;
use crate::model::neighbor::{NeighborEntry, NeighborState};
use crate::model::packet::EtherType;
use crate::pipeline::context::{PipelineContext, RoutingOutcome, StageOutcome};
use crate::trace::{FinalVerdict, PipelineStage, StageDecision};

/// Process ARP packets: check arp_ignore settings.
pub fn process_arp(ctx: &mut PipelineContext) -> StageOutcome {
    if !matches!(ctx.packet.ethertype, EtherType::Arp) {
        return StageOutcome::Continue;
    }

    let arp_conf = ctx.scenario.sysctl.get_interface_conf(&ctx.packet.ingress_if);
    if arp_conf.arp_ignore < 1 {
        return StageOutcome::Continue;
    }

    let target_ip = ctx.scenario.packet.arp.as_ref().and_then(|a| a.target_ip);
    let mut should_drop = false;
    let mut explain = String::new();

    if let Some(tip) = target_ip {
        let iface_has_ip = find_interface(&ctx.scenario.interfaces, &ctx.packet.ingress_if)
            .map(|iface| iface.addresses.iter().any(|a| a.ip == tip))
            .unwrap_or(false);

        if !iface_has_ip {
            should_drop = true;
            explain = format!(
                "arp_ignore={}: ARP target IP {} is not configured on ingress interface '{}' — ARP reply suppressed",
                arp_conf.arp_ignore, tip, ctx.packet.ingress_if
            );
        } else if arp_conf.arp_ignore >= 2 {
            let sender_ip = ctx.scenario.packet.arp.as_ref().and_then(|a| a.sender_ip);
            if let Some(sip) = sender_ip {
                let same_subnet = find_interface(&ctx.scenario.interfaces, &ctx.packet.ingress_if)
                    .map(|iface| {
                        iface.addresses.iter().any(|a| is_same_subnet(&a.ip, &sip, a.prefix_len))
                    })
                    .unwrap_or(false);
                if !same_subnet {
                    should_drop = true;
                    explain = format!(
                        "arp_ignore={}: ARP sender IP {} is not in the same subnet as any address on '{}' — ARP reply suppressed",
                        arp_conf.arp_ignore, sip, ctx.packet.ingress_if
                    );
                }
            }
        }
    }

    if should_drop {
        ctx.record_info_step(
            PipelineStage::ArpProcess,
            "arp_ignore check",
            StageDecision::Drop {
                reason: format!("ARP reply suppressed by arp_ignore={}", arp_conf.arp_ignore),
            },
            explain,
        );
        return StageOutcome::Terminal(FinalVerdict::Drop);
    }

    StageOutcome::Continue
}

/// Resolve ARP for forwarded packets: determine the next-hop MAC address.
///
/// Runs after routing decision (ForwardTo) to resolve the L2 destination MAC.
/// 1. If routing result is not ForwardTo, skip (return Continue).
/// 2. Determine resolve_ip: next_hop (gateway) or dst_ip (direct route).
/// 3. Look up (egress_if, resolve_ip) in ctx.arp_table.
/// 4. If found → set dst_mac, record trace, return Continue.
/// 5. If not found → simulate ARP request to find a responder.
pub fn resolve_arp(ctx: &mut PipelineContext) -> StageOutcome {
    // 1. Only applies to forwarded packets
    let (egress_if, next_hop) = match &ctx.routing_result {
        Some(RoutingOutcome::ForwardTo { egress_if, next_hop }) => {
            (egress_if.clone(), *next_hop)
        }
        _ => return StageOutcome::Continue,
    };

    // Skip for L2-only packets
    if ctx.packet.ethertype.is_l2_only() {
        return StageOutcome::Continue;
    }

    // 2. Skip ARP resolution if no neighbor table is configured
    // (backward compatibility: scenarios without explicit neighbors skip L2 resolution)
    if ctx.arp_table.is_empty() && ctx.scenario.neighbors.is_empty() {
        return StageOutcome::Continue;
    }

    // 3. Determine resolve_ip: use next_hop for gateway routing, else dst_ip for direct
    let dst_ip = match ctx.packet.dst_ip {
        Some(ip) => ip,
        None => return StageOutcome::Continue,
    };
    let resolve_ip = next_hop.unwrap_or(dst_ip);

    // 4. Look up in ARP table
    let arp_key = (egress_if.clone(), resolve_ip);
    if let Some(entry) = ctx.arp_table.get(&arp_key) {
        let mac = entry.mac.clone();
        ctx.packet.dst_mac = Some(mac.clone());
        ctx.record_info_step(
            PipelineStage::ArpResolve,
            "ARP table hit",
            StageDecision::Continue,
            format!(
                "ARP table hit: {} → MAC {} on interface '{}'.",
                resolve_ip, mac, egress_if
            ),
        );
        return StageOutcome::Continue;
    }

    // 5. ARP table miss — simulate ARP request
    if let Some((mac, explain)) = simulate_arp_request(ctx, &egress_if, resolve_ip) {
        // Add to ARP table
        ctx.arp_table.insert(
            arp_key,
            NeighborEntry {
                ip: resolve_ip,
                mac: mac.clone(),
                interface: egress_if.clone(),
                state: NeighborState::Reachable,
            },
        );
        ctx.packet.dst_mac = Some(mac.clone());
        ctx.record_info_step(
            PipelineStage::ArpResolve,
            "ARP resolution success",
            StageDecision::Continue,
            format!(
                "ARP resolved: {} → MAC {} on '{}'. {}",
                resolve_ip, mac, egress_if, explain
            ),
        );
        return StageOutcome::Continue;
    }

    // ARP resolution failed
    ctx.record_info_step(
        PipelineStage::ArpResolve,
        "ARP resolution failed",
        StageDecision::Drop {
            reason: format!("ARP resolution failed for {} on '{}'", resolve_ip, egress_if),
        },
        format!(
            "No host responded to ARP request for {} on interface '{}'. \
             No matching interface IP, no proxy_arp responder, and no topology endpoint found.",
            resolve_ip, egress_if
        ),
    );
    StageOutcome::Terminal(FinalVerdict::Drop)
}

/// Simulate an ARP request to find which entity (if any) would respond.
///
/// Checks:
/// (a) Scenario interfaces for matching IP (with arp_ignore / arp_filter checks)
/// (b) Proxy ARP: if enabled on egress interface's segment, check if target is routable
///     via a different interface
/// (c) Topology endpoints for matching IP
///
/// Returns Some((mac, explanation)) if a responder is found, None otherwise.
fn simulate_arp_request(
    ctx: &PipelineContext,
    egress_if: &str,
    target_ip: IpAddr,
) -> Option<(String, String)> {
    let scenario = ctx.scenario;

    // (a) Check all scenario interfaces for matching IP
    for iface in &scenario.interfaces {
        let has_ip = iface.addresses.iter().any(|a| a.ip == target_ip);
        if !has_ip {
            continue;
        }

        // Check arp_ignore on the responding interface
        let arp_conf = scenario.sysctl.get_interface_conf(&iface.name);
        if arp_conf.arp_ignore >= 1 {
            // arp_ignore=1: only respond if target IP is on the receiving interface
            // In simulation, the "receiving interface" for the ARP request is the
            // egress interface of the forwarded packet (or the interface the ARP goes out on)
            if iface.name != egress_if {
                // For arp_ignore >= 1, skip interfaces that don't match the egress
                continue;
            }
        }

        // Check arp_filter: if enabled, only respond if target_ip is routable via this interface
        if arp_conf.arp_filter {
            // Check if any route for target_ip would go through this interface
            let routable_via_self = scenario.routing_tables.iter().any(|table| {
                table.routes.iter().any(|route| {
                    route_matches_ip(&route.destination, target_ip)
                        && route.dev.as_deref() == Some(&iface.name)
                })
            });
            if !routable_via_self {
                continue;
            }
        }

        // Found a responding interface
        let mac = iface
            .mac
            .clone()
            .unwrap_or_else(|| format!("auto:{}", iface.name));
        return Some((
            mac,
            format!("Interface '{}' has IP {} and responded to ARP.", iface.name, target_ip),
        ));
    }

    // (b) Check proxy_arp: if enabled on egress interface, check if target is routable
    // via a different interface
    let egress_conf = scenario.sysctl.get_interface_conf(egress_if);
    if egress_conf.proxy_arp {
        // Check if target_ip is routable via a different interface than egress
        for table in &scenario.routing_tables {
            for route in &table.routes {
                if route_matches_ip(&route.destination, target_ip) {
                    if let Some(ref dev) = route.dev {
                        if dev != egress_if {
                            // Target is reachable via another interface → proxy ARP responds
                            let proxy_mac = find_interface(&scenario.interfaces, egress_if)
                                .and_then(|iface| iface.mac.clone())
                                .unwrap_or_else(|| format!("auto:{}", egress_if));
                            return Some((
                                proxy_mac,
                                format!(
                                    "Proxy ARP on '{}': target {} is routable via '{}', \
                                     responding with egress interface MAC.",
                                    egress_if, target_ip, dev
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    // (c) Check topology endpoints for matching IP
    if let Some(topology) = &scenario.topology {
        for endpoint in &topology.endpoints {
            if endpoint.ip == target_ip {
                // Generate a deterministic MAC for the endpoint
                let ep_mac = format!("ep:{}:{}", endpoint.name, target_ip);
                return Some((
                    ep_mac,
                    format!(
                        "Topology endpoint '{}' (IP {}) responded to ARP.",
                        endpoint.name, target_ip
                    ),
                ));
            }
        }
    }

    None
}

/// Check if a route destination (IpNet) contains the given IP
fn route_matches_ip(destination: &IpNet, ip: IpAddr) -> bool {
    destination.contains(&ip)
}

/// Check if two IPs are in the same subnet
fn is_same_subnet(a: &IpAddr, b: &IpAddr, prefix_len: u8) -> bool {
    match (a, b) {
        (IpAddr::V4(a4), IpAddr::V4(b4)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix_len)
            };
            let a_bits = u32::from(*a4);
            let b_bits = u32::from(*b4);
            (a_bits & mask) == (b_bits & mask)
        }
        (IpAddr::V6(a6), IpAddr::V6(b6)) => {
            if prefix_len > 128 {
                return false;
            }
            let a_bits = u128::from(*a6);
            let b_bits = u128::from(*b6);
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix_len)
            };
            (a_bits & mask) == (b_bits & mask)
        }
        _ => false,
    }
}
