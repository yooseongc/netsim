//! L2 header rewriting stage
//!
//! Rewrites src_mac (and validates dst_mac) on forwarded IP packets before egress.
//! In Linux, when a packet is forwarded, the kernel sets src_mac to the egress
//! interface's MAC and dst_mac to the resolved next-hop MAC from ARP/neighbor table.

use crate::model::interface::find_interface;
use crate::pipeline::context::{PipelineContext, StageOutcome};
use crate::trace::{PipelineStage, StageDecision};

/// Rewrite L2 headers (src_mac/dst_mac) for forwarded IP packets.
///
/// Only applies to forwarded packets (egress_if is Some) with IP ethertype.
/// Sets src_mac = egress interface MAC. dst_mac should already be set by ARP resolve.
pub fn rewrite_l2_headers(ctx: &mut PipelineContext) -> StageOutcome {
    // Only applies to forwarded packets
    let egress_if_name = match &ctx.packet.egress_if {
        Some(name) => name.clone(),
        None => return StageOutcome::Continue,
    };

    // Only for IP packets (skip L2-only like ARP)
    if !ctx.packet.ethertype.is_ip() {
        return StageOutcome::Continue;
    }

    // Skip if no neighbor table configured (backward compatibility)
    if ctx.scenario.neighbors.is_empty() && ctx.arp_table.is_empty() {
        return StageOutcome::Continue;
    }

    let old_src_mac = ctx.packet.src_mac.clone();
    let old_dst_mac = ctx.packet.dst_mac.clone();

    // Set src_mac = egress interface MAC
    let egress_mac = find_interface(&ctx.scenario.interfaces, &egress_if_name)
        .and_then(|iface| iface.mac.clone());

    let mut changes = Vec::new();

    if let Some(ref new_src_mac) = egress_mac {
        if old_src_mac.as_deref() != Some(new_src_mac.as_str()) {
            ctx.packet.src_mac = Some(new_src_mac.clone());
            changes.push(format!(
                "src_mac: {:?} → {}",
                old_src_mac.as_deref().unwrap_or("none"),
                new_src_mac
            ));
        }
    }

    // dst_mac should already be set by ARP resolve stage — just report it
    if old_dst_mac != ctx.packet.dst_mac {
        changes.push(format!(
            "dst_mac: {:?} → {:?}",
            old_dst_mac.as_deref().unwrap_or("none"),
            ctx.packet.dst_mac.as_deref().unwrap_or("none")
        ));
    }

    let explain = if changes.is_empty() {
        format!(
            "L2 rewrite on egress '{}': no changes needed (src_mac={}, dst_mac={}).",
            egress_if_name,
            ctx.packet.src_mac.as_deref().unwrap_or("none"),
            ctx.packet.dst_mac.as_deref().unwrap_or("none"),
        )
    } else {
        format!(
            "L2 rewrite on egress '{}': {}.",
            egress_if_name,
            changes.join(", ")
        )
    };

    ctx.record_info_step(
        PipelineStage::L2Rewrite,
        "L2 header rewrite",
        StageDecision::Continue,
        explain,
    );

    StageOutcome::Continue
}
