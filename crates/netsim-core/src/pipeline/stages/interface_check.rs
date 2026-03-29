//! Ingress interface validation stage
//!
//! Checks: interface existence, UP/DOWN state, Physical NIC frame size.

use crate::model::interface::{find_interface, InterfaceKind};
use crate::pipeline::context::{PipelineContext, StageOutcome};
use crate::trace::{FinalVerdict, PipelineStage, StageDecision};

/// Check that the ingress interface exists, is up, and (for physical NICs)
/// that the frame fits within the NIC's receive limit.
pub fn check_ingress(ctx: &mut PipelineContext) -> StageOutcome {
    let ingress_iface = find_interface(&ctx.scenario.interfaces, &ctx.packet.ingress_if);
    match ingress_iface {
        None => {
            ctx.record_info_step(
                PipelineStage::InterfaceCheck,
                "ingress interface check",
                StageDecision::Drop {
                    reason: "Unknown ingress interface".to_string(),
                },
                format!(
                    "Ingress interface '{}' does not exist in scenario interfaces",
                    ctx.packet.ingress_if
                ),
            );
            StageOutcome::Terminal(FinalVerdict::Drop)
        }
        Some(iface) => {
            // Interface state check
            if !iface.is_up() {
                ctx.record_info_step(
                    PipelineStage::InterfaceCheck,
                    "ingress interface state check",
                    StageDecision::Drop {
                        reason: "Ingress interface is down".to_string(),
                    },
                    format!(
                        "Ingress interface '{}' is in DOWN state — packets cannot be received",
                        ctx.packet.ingress_if
                    ),
                );
                return StageOutcome::Terminal(FinalVerdict::Drop);
            }

            // Physical NIC ingress frame size check
            if matches!(iface.kind, InterfaceKind::Physical) {
                if let Some(pkt_len) = ctx.packet.packet_length {
                    let l2_max_frame = iface.mtu.saturating_add(18).max(9216);
                    if pkt_len > l2_max_frame {
                        ctx.record_info_step(
                            PipelineStage::InterfaceCheck,
                            "physical NIC frame size check",
                            StageDecision::Drop {
                                reason: format!(
                                    "Frame too large for physical NIC (max={})",
                                    l2_max_frame
                                ),
                            },
                            format!(
                                "Packet length {} exceeds physical NIC '{}' max receive frame size {} \
                                 (MTU={} + 18 L2 overhead, min 9216 jumbo). \
                                 Physical NICs drop oversized frames at driver level.",
                                pkt_len, ctx.packet.ingress_if, l2_max_frame, iface.mtu
                            ),
                        );
                        return StageOutcome::Terminal(FinalVerdict::Drop);
                    }
                }
            }

            StageOutcome::Continue
        }
    }
}
