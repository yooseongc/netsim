//! Bridge member detection and L2 forwarding stage
//!
//! Checks if ingress interface is a bridge member. If bridge_nf_call_iptables=false,
//! the packet is forwarded at L2 without passing through the IP netfilter stack.
//! If bridge_nf_call_iptables=true, the bridge nf pipeline (br_nf PREROUTING,
//! FORWARD, POSTROUTING) is executed before continuing to the normal IP stack.

use crate::model::bridge_fdb::FdbEntry;
use crate::model::interface::find_interface;
use crate::model::netfilter::NfHook;
use crate::pipeline;
use crate::pipeline::context::{PipelineContext, StageOutcome};
use crate::trace::{FinalVerdict, PipelineStage, StageDecision};

/// Result of an FDB lookup
pub enum FdbLookupResult {
    /// Packet should be sent to a specific port
    Port(String),
    /// Packet should be flooded to all member ports (unknown unicast or multicast)
    Flood,
}

/// Check if the first octet's LSB is 1 (multicast/broadcast MAC)
pub fn is_multicast_mac(mac: &str) -> bool {
    let mac_clean = mac.replace([':', '-'], "");
    if mac_clean.len() < 2 {
        return false;
    }
    if let Ok(first_byte) = u8::from_str_radix(&mac_clean[..2], 16) {
        (first_byte & 0x01) != 0
    } else {
        false
    }
}

/// Learn source MAC on ingress port — inserts into ctx.fdb if not present.
/// Records a BridgeFdbLookup trace step.
pub fn learn_mac(ctx: &mut PipelineContext, bridge_name: &str, src_mac: &str, port: &str) {
    let key = (bridge_name.to_string(), src_mac.to_lowercase());
    if !ctx.fdb.contains_key(&key) {
        ctx.fdb.insert(
            key,
            FdbEntry {
                mac: src_mac.to_lowercase(),
                port: port.to_string(),
                vlan: None,
                is_static: false,
            },
        );
        ctx.record_info_step(
            PipelineStage::BridgeFdbLookup,
            "FDB MAC learning",
            StageDecision::Continue,
            format!(
                "Learned MAC {} on port '{}' of bridge '{}'.",
                src_mac, port, bridge_name
            ),
        );
    }
}

/// Look up dst_mac in ctx.fdb for the given bridge. Returns port or flooding.
pub fn fdb_lookup(ctx: &mut PipelineContext, bridge_name: &str) -> FdbLookupResult {
    let dst_mac = ctx.packet.dst_mac.clone().unwrap_or_default().to_lowercase();

    // Multicast/broadcast → flood
    if dst_mac.is_empty() || is_multicast_mac(&dst_mac) {
        ctx.record_info_step(
            PipelineStage::BridgeFdbLookup,
            "FDB lookup — flooding",
            StageDecision::Continue,
            format!(
                "Destination MAC '{}' is multicast/broadcast or empty — flooding to all bridge member ports.",
                dst_mac
            ),
        );
        return FdbLookupResult::Flood;
    }

    let key = (bridge_name.to_string(), dst_mac.clone());
    if let Some(entry) = ctx.fdb.get(&key) {
        let port = entry.port.clone();
        ctx.record_info_step(
            PipelineStage::BridgeFdbLookup,
            "FDB lookup — hit",
            StageDecision::Continue,
            format!(
                "FDB hit: MAC {} → port '{}' on bridge '{}'.",
                dst_mac, port, bridge_name
            ),
        );
        FdbLookupResult::Port(port)
    } else {
        ctx.record_info_step(
            PipelineStage::BridgeFdbLookup,
            "FDB lookup — unknown unicast flooding",
            StageDecision::Continue,
            format!(
                "FDB miss: MAC {} not found on bridge '{}' — flooding to all member ports.",
                dst_mac, bridge_name
            ),
        );
        FdbLookupResult::Flood
    }
}

/// Check if ingress interface is a bridge member and handle L2 forwarding.
pub fn check_bridge(ctx: &mut PipelineContext) -> StageOutcome {
    // Extract values from packet/scenario before mutable borrows
    let ingress_if = ctx.packet.ingress_if.clone();
    let src_mac = ctx.packet.src_mac.clone();
    let ingress_iface = find_interface(&ctx.scenario.interfaces, &ingress_if);

    if let Some(iface) = ingress_iface {
        if let Some(master) = &iface.master {
            let bridge_name = master.clone();

            ctx.record_info_step(
                PipelineStage::InterfaceCheck,
                "bridge member detection",
                StageDecision::Continue,
                format!(
                    "Interface '{}' is a member of bridge '{}'.",
                    ingress_if, bridge_name
                ),
            );

            // Step 1: Learn source MAC on ingress port
            if let Some(ref smac) = src_mac {
                learn_mac(ctx, &bridge_name, smac, &ingress_if);
            }

            if !ctx.scenario.sysctl.bridge_nf_call_iptables {
                // Step 2: FDB lookup before forwarding (when bridge_nf_call_iptables=false)
                let _fdb_result = fdb_lookup(ctx, &bridge_name);

                ctx.record_info_step(
                    PipelineStage::BridgeForward,
                    "bridge L2 forwarding",
                    StageDecision::Continue,
                    format!(
                        "bridge_nf_call_iptables=0: packet forwarded at L2 by bridge '{}' \
                         without passing through IP netfilter stack.",
                        bridge_name
                    ),
                );
                return StageOutcome::Terminal(FinalVerdict::Forwarded);
            }
            // bridge_nf_call_iptables=true: execute bridge nf pipeline then continue to IP stack
        }
    }
    StageOutcome::Continue
}

/// Execute the bridge netfilter pipeline when bridge_nf_call_iptables=true.
///
/// Steps:
/// 1. br_nf PREROUTING: evaluate PREROUTING chains, record as BrNfPrerouting
/// 2. Bridge forwarding decision (simplified: forward to another member port)
/// 3. br_nf FORWARD: evaluate FORWARD chains, record as BrNfForward
/// 4. br_nf POSTROUTING: evaluate POSTROUTING chains, record as BrNfPostrouting
///
/// Returns Terminal if any chain drops/rejects, otherwise Continue to normal IP stack.
pub fn execute_bridge_nf_pipeline(ctx: &mut PipelineContext) -> StageOutcome {
    let scenario = ctx.scenario;

    // 1. br_nf PREROUTING
    {
        let state_before = ctx.packet.clone();
        let result = pipeline::evaluate_netfilter_hook(
            &scenario.netfilter,
            &NfHook::Prerouting,
            &mut ctx.packet,
            &scenario.interfaces,
        );
        ctx.record_step(PipelineStage::BrNfPrerouting, &state_before, &result);
        if let Some(v) = super::super::super::engine::terminal_verdict_from_decision(&result.decision) {
            return StageOutcome::Terminal(v);
        }
    }

    // 2. Bridge forwarding decision with FDB lookup
    {
        // Determine bridge name from ingress interface
        let ingress_if = ctx.packet.ingress_if.clone();
        let bridge_name = find_interface(&ctx.scenario.interfaces, &ingress_if)
            .and_then(|iface| iface.master.clone())
            .unwrap_or_default();

        let fdb_result = fdb_lookup(ctx, &bridge_name);
        let fdb_explain = match &fdb_result {
            FdbLookupResult::Port(port) => format!(
                "Bridge forwarding: FDB lookup found port '{}' for destination MAC.",
                port
            ),
            FdbLookupResult::Flood => {
                "Bridge forwarding: flooding to all member ports (FDB miss or multicast).".to_string()
            }
        };

        ctx.record_info_step(
            PipelineStage::BridgeForward,
            "bridge forwarding decision",
            StageDecision::Continue,
            fdb_explain,
        );
    }

    // 3. br_nf FORWARD
    {
        let state_before = ctx.packet.clone();
        let result = pipeline::evaluate_netfilter_hook(
            &scenario.netfilter,
            &NfHook::Forward,
            &mut ctx.packet,
            &scenario.interfaces,
        );
        ctx.record_step(PipelineStage::BrNfForward, &state_before, &result);
        if let Some(v) = super::super::super::engine::terminal_verdict_from_decision(&result.decision) {
            return StageOutcome::Terminal(v);
        }
    }

    // 4. br_nf POSTROUTING
    {
        let state_before = ctx.packet.clone();
        let result = pipeline::evaluate_netfilter_hook(
            &scenario.netfilter,
            &NfHook::Postrouting,
            &mut ctx.packet,
            &scenario.interfaces,
        );
        ctx.record_step(PipelineStage::BrNfPostrouting, &state_before, &result);
        if let Some(v) = super::super::super::engine::terminal_verdict_from_decision(&result.decision) {
            return StageOutcome::Terminal(v);
        }
    }

    // Continue to normal IP stack
    StageOutcome::Continue
}
