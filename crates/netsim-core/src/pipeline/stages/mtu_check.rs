//! MTU check stage
//!
//! Checks if packet exceeds egress interface MTU. If DF flag is set, packet is dropped.
//! Otherwise, fragmentation is noted.

use crate::model::interface::find_interface;
use crate::pipeline::context::{PipelineContext, StageOutcome};
use crate::trace::{FinalVerdict, PipelineStage, StageDecision};

/// Check MTU on egress interface. Returns Terminal(Drop) if DF flag is set and packet
/// exceeds MTU; otherwise Continue.
pub fn check_mtu(ctx: &mut PipelineContext) -> StageOutcome {
    if let Some(ref egress_name) = ctx.packet.egress_if {
        if let Some(egress_iface) = find_interface(&ctx.scenario.interfaces, egress_name) {
            let mtu = egress_iface.mtu;
            if let Some(pkt_len) = ctx.packet.packet_length {
                if pkt_len > mtu {
                    if ctx.packet.df_flag {
                        ctx.record_info_step(
                            PipelineStage::MtuCheck,
                            "MTU exceeded with DF flag",
                            StageDecision::Drop {
                                reason: "Packet exceeds MTU and DF flag is set (ICMP Fragmentation Needed would be sent)".to_string(),
                            },
                            format!(
                                "Packet length {} exceeds egress interface '{}' MTU {} and DF (Don't Fragment) flag is set. \
                                 Kernel would send ICMP Fragmentation Needed (Type 3, Code 4) back to sender.",
                                pkt_len, egress_name, mtu
                            ),
                        );
                        return StageOutcome::Terminal(FinalVerdict::Drop);
                    } else {
                        ctx.record_info_step(
                            PipelineStage::MtuCheck,
                            "MTU exceeded, fragmentation needed",
                            StageDecision::Continue,
                            format!(
                                "Packet length {} exceeds egress interface '{}' MTU {}. \
                                 Packet would be fragmented before transmission.",
                                pkt_len, egress_name, mtu
                            ),
                        );
                    }
                }
            } else {
                ctx.record_info_step(
                    PipelineStage::MtuCheck,
                    "MTU check skipped",
                    StageDecision::Continue,
                    "MTU check skipped: packet length not specified",
                );
            }
        }
    }
    StageOutcome::Continue
}

/// Check MTU for output path (slightly different explain messages).
pub fn check_mtu_output(ctx: &mut PipelineContext) -> StageOutcome {
    if let Some(ref egress_name) = ctx.packet.egress_if {
        if let Some(egress_iface) = find_interface(&ctx.scenario.interfaces, egress_name) {
            let mtu = egress_iface.mtu;
            if let Some(pkt_len) = ctx.packet.packet_length {
                if pkt_len > mtu {
                    if ctx.packet.df_flag {
                        ctx.record_info_step(
                            PipelineStage::MtuCheck,
                            "MTU exceeded with DF flag",
                            StageDecision::Drop {
                                reason: "Packet exceeds MTU and DF flag is set".to_string(),
                            },
                            format!(
                                "Packet length {} exceeds egress interface '{}' MTU {} and DF flag is set.",
                                pkt_len, egress_name, mtu
                            ),
                        );
                        return StageOutcome::Terminal(FinalVerdict::Drop);
                    } else {
                        ctx.record_info_step(
                            PipelineStage::MtuCheck,
                            "MTU exceeded, fragmentation needed",
                            StageDecision::Continue,
                            format!(
                                "Packet length {} exceeds egress interface '{}' MTU {}. \
                                 Packet would be fragmented before transmission.",
                                pkt_len, egress_name, mtu
                            ),
                        );
                    }
                }
            }
        }
    }
    StageOutcome::Continue
}
