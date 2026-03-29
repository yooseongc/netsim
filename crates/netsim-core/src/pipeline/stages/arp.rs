//! ARP processing stage
//!
//! Handles arp_ignore level 1 and 2 checks. Only applies to ARP packets.

use std::net::IpAddr;

use crate::model::interface::find_interface;
use crate::model::packet::EtherType;
use crate::pipeline::context::{PipelineContext, StageOutcome};
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
