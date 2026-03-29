//! Sysctl-related pipeline checks
//!
//! - rp_filter (Reverse Path Filtering)
//! - route_localnet
//! - icmp_echo_ignore_all
//! - ip_forward
//! - egress interface existence/state

use std::net::IpAddr;

use crate::model::interface::find_interface;
use crate::model::packet::{IpProtocol, PacketState};
use crate::model::sysctl::RpFilterMode;
use crate::pipeline::context::{PipelineContext, StageOutcome};
use crate::pipeline::StageResult;
use crate::trace::{FinalVerdict, PipelineStage, StageDecision};

/// Reverse Path Filter check
pub fn check_rp_filter(ctx: &mut PipelineContext) -> StageOutcome {
    let sysctl = &ctx.scenario.sysctl;
    let mode = sysctl.rp_filter_mode(&ctx.packet.ingress_if);
    if matches!(mode, RpFilterMode::Off) {
        return StageOutcome::Continue;
    }

    let src_ip = match ctx.packet.src_ip {
        Some(ip) => ip,
        None => return StageOutcome::Continue,
    };

    let reverse_result = crate::pipeline::routing::reverse_path_lookup(
        &ctx.scenario.ip_rules,
        &ctx.scenario.routing_tables,
        &ctx.scenario.interfaces,
        &src_ip,
    );

    let drop_result = match mode {
        RpFilterMode::Strict => {
            match reverse_result {
                Some(egress_if) if egress_if == ctx.packet.ingress_if => None,
                Some(egress_if) => Some(StageResult::drop(
                    format!("rp_filter strict: reverse route for {} via {} != ingress {}", src_ip, egress_if, ctx.packet.ingress_if),
                    format!(
                        "Reverse path filter (strict): source {} would be routed via {}, but arrived on {}. \
                         Set net.ipv4.conf.{}.rp_filter=0 to disable.",
                        src_ip, egress_if, ctx.packet.ingress_if, ctx.packet.ingress_if
                    ),
                )),
                None => Some(StageResult::drop(
                    format!("rp_filter strict: no reverse route for {}", src_ip),
                    format!(
                        "Reverse path filter (strict): no route found for source {}. \
                         Set net.ipv4.conf.{}.rp_filter=0 to disable.",
                        src_ip, ctx.packet.ingress_if
                    ),
                )),
            }
        }
        RpFilterMode::Loose => {
            match reverse_result {
                Some(_) => None,
                None => Some(StageResult::drop(
                    format!("rp_filter loose: no reverse route for {}", src_ip),
                    format!(
                        "Reverse path filter (loose): no route found for source {}. \
                         Set net.ipv4.conf.{}.rp_filter=0 to disable.",
                        src_ip, ctx.packet.ingress_if
                    ),
                )),
            }
        }
        RpFilterMode::Off => None,
    };

    if let Some(result) = drop_result {
        ctx.record_info_step(
            PipelineStage::RpFilter,
            "rp_filter check",
            result.decision.clone(),
            result.explain.clone(),
        );
        return StageOutcome::Terminal(FinalVerdict::Drop);
    }

    StageOutcome::Continue
}

/// route_localnet check: drop packets to loopback if route_localnet is disabled
pub fn check_route_localnet(ctx: &mut PipelineContext) -> StageOutcome {
    if let Some(dst) = ctx.packet.dst_ip {
        if is_loopback(&dst) && !ctx.scenario.sysctl.is_route_localnet(&ctx.packet.ingress_if) {
            ctx.record_info_step(
                PipelineStage::RoutingDecision,
                "route_localnet check",
                StageDecision::Drop {
                    reason: "Destination is loopback but route_localnet is disabled".to_string(),
                },
                format!(
                    "Packet destination {} is in loopback range. \
                     net.ipv4.conf.{}.route_localnet=0 (disabled). \
                     Enable route_localnet to allow DNAT to 127.0.0.1.",
                    dst, ctx.packet.ingress_if
                ),
            );
            return StageOutcome::Terminal(FinalVerdict::Drop);
        }
    }
    StageOutcome::Continue
}

/// icmp_echo_ignore_all check
pub fn check_icmp_echo_ignore(ctx: &mut PipelineContext) -> StageOutcome {
    if ctx.scenario.sysctl.icmp_echo_ignore_all()
        && ctx.packet.protocol.is_icmp()
        && is_icmp_echo_request(&ctx.packet)
    {
        ctx.record_info_step(
            PipelineStage::LocalInput,
            "icmp_echo_ignore_all",
            StageDecision::Drop {
                reason: "ICMP echo ignored by icmp_echo_ignore_all=1".to_string(),
            },
            "net.ipv4.icmp_echo_ignore_all=1 — all ICMP echo requests silently dropped",
        );
        return StageOutcome::Terminal(FinalVerdict::Drop);
    }
    StageOutcome::Continue
}

/// ip_forward check: drop if forwarding is disabled
pub fn check_ip_forward(ctx: &mut PipelineContext) -> StageOutcome {
    if !ctx.scenario.sysctl.is_forwarding_enabled(&ctx.packet.ingress_if) {
        ctx.record_info_step(
            PipelineStage::Forward,
            "ip_forward disabled",
            StageDecision::Drop {
                reason: "IP forwarding disabled".to_string(),
            },
            format!(
                "net.ipv4.ip_forward=0 — packet requires forwarding but forwarding is disabled on {}",
                ctx.packet.ingress_if
            ),
        );
        return StageOutcome::Terminal(FinalVerdict::Drop);
    }
    StageOutcome::Continue
}

/// Egress interface existence and state check
pub fn check_egress_interface(ctx: &mut PipelineContext) -> StageOutcome {
    if let Some(ref egress_name) = ctx.packet.egress_if {
        match find_interface(&ctx.scenario.interfaces, egress_name) {
            None => {
                ctx.record_info_step(
                    PipelineStage::InterfaceCheck,
                    "egress interface check",
                    StageDecision::Drop {
                        reason: "Unknown egress interface".to_string(),
                    },
                    format!(
                        "Egress interface '{}' does not exist in scenario interfaces",
                        egress_name
                    ),
                );
                return StageOutcome::Terminal(FinalVerdict::Drop);
            }
            Some(egress_iface) if !egress_iface.is_up() => {
                ctx.record_info_step(
                    PipelineStage::InterfaceCheck,
                    "egress interface state check",
                    StageDecision::Drop {
                        reason: "Egress interface is down".to_string(),
                    },
                    format!(
                        "Egress interface '{}' is in DOWN state — packet cannot be forwarded",
                        egress_name
                    ),
                );
                return StageOutcome::Terminal(FinalVerdict::Drop);
            }
            _ => {} // exists and up
        }
    }
    StageOutcome::Continue
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn is_icmp_echo_request(state: &PacketState) -> bool {
    match state.protocol {
        IpProtocol::Icmp => state.icmp_type == Some(8),
        IpProtocol::Icmpv6 => state.icmp_type == Some(128),
        _ => false,
    }
}
