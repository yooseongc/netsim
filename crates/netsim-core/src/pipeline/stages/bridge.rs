//! Bridge member detection and L2 forwarding stage
//!
//! Checks if ingress interface is a bridge member. If bridge_nf_call_iptables=false,
//! the packet is forwarded at L2 without passing through the IP netfilter stack.
//! If bridge_nf_call_iptables=true, the bridge nf pipeline (br_nf PREROUTING,
//! FORWARD, POSTROUTING) is executed before continuing to the normal IP stack.

use crate::model::interface::find_interface;
use crate::model::netfilter::NfHook;
use crate::pipeline;
use crate::pipeline::context::{PipelineContext, StageOutcome};
use crate::trace::{FinalVerdict, PipelineStage, StageDecision};

/// Check if ingress interface is a bridge member and handle L2 forwarding.
pub fn check_bridge(ctx: &mut PipelineContext) -> StageOutcome {
    let ingress_iface = find_interface(&ctx.scenario.interfaces, &ctx.packet.ingress_if);
    if let Some(iface) = ingress_iface {
        if let Some(master) = &iface.master {
            ctx.record_info_step(
                PipelineStage::InterfaceCheck,
                "bridge member detection",
                StageDecision::Continue,
                format!(
                    "Interface '{}' is a member of bridge '{}'.",
                    ctx.packet.ingress_if, master
                ),
            );

            if !ctx.scenario.sysctl.bridge_nf_call_iptables {
                ctx.record_info_step(
                    PipelineStage::BridgeForward,
                    "bridge L2 forwarding",
                    StageDecision::Continue,
                    format!(
                        "bridge_nf_call_iptables=0: packet forwarded at L2 by bridge '{}' \
                         without passing through IP netfilter stack.",
                        master
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

    // 2. Bridge forwarding decision (simplified)
    ctx.record_info_step(
        PipelineStage::BridgeForward,
        "bridge forwarding decision",
        StageDecision::Continue,
        "Bridge forwarding: packet will be forwarded to another bridge member port.",
    );

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
