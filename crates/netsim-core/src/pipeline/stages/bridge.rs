//! Bridge member detection and L2 forwarding stage
//!
//! Checks if ingress interface is a bridge member. If bridge_nf_call_iptables=false,
//! the packet is forwarded at L2 without passing through the IP netfilter stack.

use crate::model::interface::find_interface;
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
            // bridge_nf_call_iptables=true: continue with normal IP stack
        }
    }
    StageOutcome::Continue
}
