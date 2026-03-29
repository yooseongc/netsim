//! 시뮬레이션 오케스트레이터
//!
//! Scenario를 받아 Linux 커널 ingress 패킷 처리 경로를 순서대로 실행하고
//! SimulationResult를 반환한다.
//!
//! 파이프라인 순서:
//!   NIC → XDP → tc ingress → conntrack lookup →
//!   PREROUTING (raw→mangle→nat/DNAT) →
//!   Routing Decision →
//!     LOCAL: INPUT chains → LOCAL_DELIVERY
//!     FORWARD: FORWARD chains → POSTROUTING (SNAT/MASQ) → FORWARDED
//!
//! sysctl 파라미터가 다음에 영향:
//!   - ip_forward: 포워딩 허용 여부
//!   - route_localnet: 127.0.0.0/8 라우팅 허용
//!   - rp_filter: Reverse Path 필터링
//!   - icmp_echo_ignore_all: ICMP echo 무시

use std::net::IpAddr;

use uuid::Uuid;

use crate::model::interface::{find_interface, Interface, InterfaceKind};
use crate::model::packet::{EtherType, IpProtocol, PacketState};
use crate::model::scenario::Scenario;
use crate::model::sysctl::{RpFilterMode, SysctlConfig};
use crate::pipeline::{self, StageResult};
use crate::trace::{
    compute_state_changes, FinalVerdict, MatchedRuleRef, PipelineStage, SimulationResult,
    SimulationSummary, StageDecision, TraceStep,
};

/// 시뮬레이션 실행
pub fn run(scenario: &Scenario) -> SimulationResult {
    let mut state = PacketState::from_packet_def(&scenario.packet);
    let mut trace = Vec::new();
    let mut all_matched_rules: Vec<MatchedRuleRef> = Vec::new();
    let mut seq: u32 = 0;
    let sysctl = &scenario.sysctl;

    // --- Stage 0: Interface validation ---
    {
        // (a) Interface existence check
        let ingress_iface = find_interface(&scenario.interfaces, &state.ingress_if);
        match ingress_iface {
            None => {
                seq += 1;
                trace.push(TraceStep {
                    seq,
                    stage: PipelineStage::InterfaceCheck,
                    description: "ingress interface check".to_string(),
                    state_before: state.clone(),
                    state_after: state.clone(),
                    state_changes: vec![],
                    matched_rules: vec![],
                    decision: StageDecision::Drop {
                        reason: "Unknown ingress interface".to_string(),
                    },
                    explain: format!(
                        "Ingress interface '{}' does not exist in scenario interfaces",
                        state.ingress_if
                    ),
                });
                return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
            }
            Some(iface) => {
                // (b) Interface state check
                if !iface.is_up() {
                    seq += 1;
                    trace.push(TraceStep {
                        seq,
                        stage: PipelineStage::InterfaceCheck,
                        description: "ingress interface state check".to_string(),
                        state_before: state.clone(),
                        state_after: state.clone(),
                        state_changes: vec![],
                        matched_rules: vec![],
                        decision: StageDecision::Drop {
                            reason: "Ingress interface is down".to_string(),
                        },
                        explain: format!(
                            "Ingress interface '{}' is in DOWN state — packets cannot be received",
                            state.ingress_if
                        ),
                    });
                    return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
                }

                // (c) Bridge member check
                if let Some(master) = &iface.master {
                    seq += 1;
                    trace.push(TraceStep {
                        seq,
                        stage: PipelineStage::InterfaceCheck,
                        description: "bridge member detection".to_string(),
                        state_before: state.clone(),
                        state_after: state.clone(),
                        state_changes: vec![],
                        matched_rules: vec![],
                        decision: StageDecision::Continue,
                        explain: format!(
                            "Interface '{}' is a member of bridge '{}'. \
                             In Linux, packets arriving on a bridge member go through bridge processing first.",
                            state.ingress_if, master
                        ),
                    });

                    // Bridge L2 forwarding path when bridge_nf_call_iptables=false
                    if !sysctl.bridge_nf_call_iptables {
                        seq += 1;
                        trace.push(TraceStep {
                            seq,
                            stage: PipelineStage::BridgeForward,
                            description: "bridge L2 forwarding".to_string(),
                            state_before: state.clone(),
                            state_after: state.clone(),
                            state_changes: vec![],
                            matched_rules: vec![],
                            decision: StageDecision::Continue,
                            explain: format!(
                                "bridge_nf_call_iptables=0: packet is forwarded at L2 by bridge '{}' \
                                 without passing through the IP netfilter stack. \
                                 Bridge FDB lookup determines the output port.",
                                master
                            ),
                        });
                        return finalize(
                            scenario,
                            trace,
                            all_matched_rules,
                            FinalVerdict::Forwarded,
                            &state,
                        );
                    }
                    // bridge_nf_call_iptables=true: continue with normal IP stack path
                }
            }
        }
    }

    // --- Physical NIC ingress frame size check ---
    // Physical NICs enforce maximum frame size at the hardware/driver level.
    // Note: IP MTU (interface.mtu) governs what the host SENDS, not what it receives.
    // The NIC can receive frames larger than the configured IP MTU.
    // The actual receive limit is the NIC's max frame size (usually 1518 for standard
    // Ethernet, 9216 for jumbo frames). We compare against mtu + L2 overhead (18 bytes
    // for Ethernet header + FCS) as the minimum receivable frame size.
    // Virtual interfaces (veth, bridge, tun, tap) skip this check entirely.
    if let Some(ingress_iface) = find_interface(&scenario.interfaces, &state.ingress_if) {
        if matches!(ingress_iface.kind, InterfaceKind::Physical) {
            if let Some(pkt_len) = state.packet_length {
                // L2 max frame = MTU + 14 (Ethernet header) + 4 (FCS) = MTU + 18
                // But NIC hardware typically accepts up to 9216 (jumbo) even if MTU is 1500.
                // Use the larger of (mtu + 18) and 9216 as the receive limit.
                let l2_max_frame = ingress_iface.mtu.saturating_add(18).max(9216);
                if pkt_len > l2_max_frame {
                    seq += 1;
                    trace.push(TraceStep {
                        seq,
                        stage: PipelineStage::InterfaceCheck,
                        description: "physical NIC ingress frame size check".to_string(),
                        state_before: state.clone(),
                        state_after: state.clone(),
                        state_changes: vec![],
                        matched_rules: vec![],
                        decision: StageDecision::Drop {
                            reason: format!(
                                "Frame too large for physical NIC (MTU={})",
                                ingress_iface.mtu
                            ),
                        },
                        explain: format!(
                            "Packet length {} exceeds physical NIC '{}' maximum receive frame size {}. \
                             Physical NICs drop oversized frames at the driver level. \
                             Virtual interfaces (veth, bridge, tun, tap) do not enforce this.",
                            pkt_len, state.ingress_if, l2_max_frame
                        ),
                    });
                    return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
                }
            }
        }
    }

    // --- Stage 1: XDP ---
    // XDP runs first at driver level, before any L2/L3 processing
    seq += 1;
    let state_before = state.clone();
    let result = pipeline::xdp::execute(&scenario.xdp, &mut state);
    trace.push(make_trace_step(seq, PipelineStage::Xdp, &state_before, &state, &result));
    all_matched_rules.extend(result.matched_rules.clone());
    match &result.decision {
        StageDecision::Drop { .. } => {
            return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
        }
        StageDecision::Redirect { target } => {
            let verdict = if *target == state.ingress_if {
                FinalVerdict::Tx
            } else {
                FinalVerdict::Redirect
            };
            return finalize(scenario, trace, all_matched_rules, verdict, &state);
        }
        _ => {}
    }

    // --- ARP processing (after XDP, before L2 bypass) ---
    // Linux kernel: ARP is processed in the network stack after XDP
    if matches!(state.ethertype, EtherType::Arp) {
        let arp_conf = sysctl.get_interface_conf(&state.ingress_if);
        if arp_conf.arp_ignore >= 1 {
            let target_ip = scenario.packet.arp.as_ref().and_then(|a| a.target_ip);
            let mut should_drop = false;
            let mut explain = String::new();

            if let Some(tip) = target_ip {
                let iface_has_ip = find_interface(&scenario.interfaces, &state.ingress_if)
                    .map(|iface| iface.addresses.iter().any(|a| a.ip == tip))
                    .unwrap_or(false);

                if !iface_has_ip {
                    should_drop = true;
                    explain = format!(
                        "arp_ignore={}: ARP target IP {} is not configured on ingress interface '{}' — ARP reply suppressed",
                        arp_conf.arp_ignore, tip, state.ingress_if
                    );
                } else if arp_conf.arp_ignore >= 2 {
                    let sender_ip = scenario.packet.arp.as_ref().and_then(|a| a.sender_ip);
                    if let Some(sip) = sender_ip {
                        let same_subnet = find_interface(&scenario.interfaces, &state.ingress_if)
                            .map(|iface| {
                                iface.addresses.iter().any(|a| is_same_subnet(&a.ip, &sip, a.prefix_len))
                            })
                            .unwrap_or(false);
                        if !same_subnet {
                            should_drop = true;
                            explain = format!(
                                "arp_ignore={}: ARP sender IP {} is not in the same subnet as any address on '{}' — ARP reply suppressed",
                                arp_conf.arp_ignore, sip, state.ingress_if
                            );
                        }
                    }
                }
            }

            if should_drop {
                seq += 1;
                trace.push(TraceStep {
                    seq,
                    stage: PipelineStage::ArpProcess,
                    description: "arp_ignore check".to_string(),
                    state_before: state.clone(),
                    state_after: state.clone(),
                    state_changes: vec![],
                    matched_rules: vec![],
                    decision: StageDecision::Drop {
                        reason: format!("ARP reply suppressed by arp_ignore={}", arp_conf.arp_ignore),
                    },
                    explain,
                });
                return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
            }
        }
    }

    // L2-only 패킷은 XDP 이후 netfilter/routing 건너뛰기
    if state.ethertype.is_l2_only() {
        seq += 1;
        trace.push(TraceStep {
            seq,
            stage: PipelineStage::L2Bypass,
            description: "L2 bypass".to_string(),
            state_before: state.clone(),
            state_after: state.clone(),
            state_changes: vec![],
            matched_rules: vec![],
            decision: StageDecision::LocalDelivery,
            explain: format!(
                "L2-only packet ({}) — bypasses netfilter and routing.",
                state.ethertype
            ),
        });
        return finalize(scenario, trace, all_matched_rules, FinalVerdict::LocalDelivery, &state);
    }

    // --- sysctl: rp_filter (Reverse Path Filtering) ---
    if let Some(drop_result) = check_rp_filter(
        sysctl, &state, &scenario.ip_rules, &scenario.routing_tables, &scenario.interfaces,
    ) {
        seq += 1;
        trace.push(TraceStep {
            seq,
            stage: PipelineStage::RpFilter,
            description: "rp_filter check".to_string(),
            state_before: state.clone(),
            state_after: state.clone(),
            state_changes: vec![],
            matched_rules: vec![],
            decision: drop_result.decision.clone(),
            explain: drop_result.explain.clone(),
        });
        return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
    }

    // --- Stage 2: tc ingress ---
    seq += 1;
    let state_before = state.clone();
    let result = pipeline::tc_ingress::execute(&state);
    trace.push(make_trace_step(seq, PipelineStage::TcIngress, &state_before, &state, &result));

    // --- Stage 3-4: PREROUTING (split into raw → conntrack → mangle/nat) ---
    // In Linux, the PREROUTING hook processes chains in priority order:
    //   raw (-300) → conntrack → mangle (-150) → nat (-100)
    // RAW table runs BEFORE conntrack, others run AFTER.
    {
        let all_prerouting_chains = pipeline::collect_chains_for_hook(
            &scenario.netfilter,
            &crate::model::netfilter::NfHook::Prerouting,
        );

        // Split chains: raw (priority <= -200) vs post-conntrack (priority > -200)
        let (raw_chains, post_ct_chains): (Vec<_>, Vec<_>) =
            all_prerouting_chains.into_iter().partition(|c| c.priority <= -200);

        // (a) Evaluate RAW chains (before conntrack)
        if !raw_chains.is_empty() {
            seq += 1;
            let state_before = state.clone();
            let result = pipeline::evaluate_chains_subset(
                &raw_chains,
                "PREROUTING_RAW",
                &mut state,
                &scenario.interfaces,
            );
            trace.push(make_trace_step(
                seq,
                PipelineStage::PreRoutingRaw,
                &state_before,
                &state,
                &result,
            ));
            all_matched_rules.extend(result.matched_rules.clone());
            if let Some(verdict) = terminal_verdict(&result.decision) {
                return finalize(scenario, trace, all_matched_rules, verdict, &state);
            }
        }

        // (b) Conntrack lookup (after raw, before mangle/nat)
        // TODO: If raw chain sets NOTRACK, skip conntrack
        seq += 1;
        trace.push(TraceStep {
            seq,
            stage: PipelineStage::ConntrackIn,
            description: "conntrack lookup".to_string(),
            state_before: state.clone(),
            state_after: state.clone(),
            state_changes: vec![],
            matched_rules: vec![],
            decision: StageDecision::Continue,
            explain: format!(
                "Conntrack lookup: packet classified as ct_state={} (user-declared)",
                state.ct_state
            ),
        });

        // (c) Evaluate post-conntrack chains (mangle, nat, etc.)
        seq += 1;
        let state_before = state.clone();
        let result = pipeline::evaluate_chains_subset(
            &post_ct_chains,
            "PREROUTING",
            &mut state,
            &scenario.interfaces,
        );
        trace.push(make_trace_step(
            seq,
            PipelineStage::PreRouting,
            &state_before,
            &state,
            &result,
        ));
        all_matched_rules.extend(result.matched_rules.clone());
        // TPROXY: do NOT return Stolen — packet continues through routing → INPUT
        if state.tproxy_applied {
            // TPROXY sets mark and dst, packet continues through normal routing path
            // (mark causes policy routing to local table → local delivery → INPUT)
        } else if let Some(verdict) = terminal_verdict(&result.decision) {
            return finalize(scenario, trace, all_matched_rules, verdict, &state);
        }
    }

    // --- sysctl: route_localnet check ---
    // DNAT 후 dst가 127.0.0.0/8이면 route_localnet 필요
    if let Some(dst) = state.dst_ip {
        if is_loopback(&dst) && !sysctl.is_route_localnet(&state.ingress_if) {
            seq += 1;
            trace.push(TraceStep {
                seq,
                stage: PipelineStage::RoutingDecision,
                description: "route_localnet check".to_string(),
                state_before: state.clone(),
                state_after: state.clone(),
                state_changes: vec![],
                matched_rules: vec![],
                decision: StageDecision::Drop {
                    reason: "Destination is loopback but route_localnet is disabled".to_string(),
                },
                explain: format!(
                    "Packet destination {} is in loopback range. \
                     net.ipv4.conf.{}.route_localnet=0 (disabled). \
                     Enable route_localnet to allow DNAT to 127.0.0.1.",
                    dst, state.ingress_if
                ),
            });
            return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
        }
    }

    // --- Stage 5: Routing Decision ---
    seq += 1;
    let state_before = state.clone();
    let result = pipeline::routing::execute(
        &scenario.ip_rules,
        &scenario.routing_tables,
        &scenario.interfaces,
        &mut state,
    );
    trace.push(make_trace_step(seq, PipelineStage::RoutingDecision, &state_before, &state, &result));
    all_matched_rules.extend(result.matched_rules.clone());

    match &result.decision {
        StageDecision::LocalDelivery => {
            // --- sysctl: icmp_echo_ignore_all ---
            if sysctl.icmp_echo_ignore_all()
                && state.protocol.is_icmp()
                && is_icmp_echo_request(&state)
            {
                seq += 1;
                trace.push(TraceStep {
                    seq,
                    stage: PipelineStage::LocalInput,
                    description: "icmp_echo_ignore_all".to_string(),
                    state_before: state.clone(),
                    state_after: state.clone(),
                    state_changes: vec![],
                    matched_rules: vec![],
                    decision: StageDecision::Drop {
                        reason: "ICMP echo ignored by icmp_echo_ignore_all=1".to_string(),
                    },
                    explain: "net.ipv4.icmp_echo_ignore_all=1 — all ICMP echo requests silently dropped".to_string(),
                });
                return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
            }

            // --- Stage 6a: INPUT chains ---
            seq += 1;
            let state_before = state.clone();
            let result = pipeline::local_input::execute(&scenario.netfilter, &mut state, &scenario.interfaces);
            trace.push(make_trace_step(seq, PipelineStage::LocalInput, &state_before, &state, &result));
            all_matched_rules.extend(result.matched_rules.clone());
            if let Some(verdict) = terminal_verdict(&result.decision) {
                return finalize(scenario, trace, all_matched_rules, verdict, &state);
            }
            finalize(scenario, trace, all_matched_rules, FinalVerdict::LocalDelivery, &state)
        }
        StageDecision::ForwardTo { .. } => {
            // --- (d) Egress interface existence + state check ---
            if let Some(ref egress_name) = state.egress_if {
                match find_interface(&scenario.interfaces, egress_name) {
                    None => {
                        seq += 1;
                        trace.push(TraceStep {
                            seq,
                            stage: PipelineStage::InterfaceCheck,
                            description: "egress interface check".to_string(),
                            state_before: state.clone(),
                            state_after: state.clone(),
                            state_changes: vec![],
                            matched_rules: vec![],
                            decision: StageDecision::Drop {
                                reason: "Unknown egress interface".to_string(),
                            },
                            explain: format!(
                                "Egress interface '{}' does not exist in scenario interfaces",
                                egress_name
                            ),
                        });
                        return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
                    }
                    Some(egress_iface) if !egress_iface.is_up() => {
                        seq += 1;
                        trace.push(TraceStep {
                            seq,
                            stage: PipelineStage::InterfaceCheck,
                            description: "egress interface state check".to_string(),
                            state_before: state.clone(),
                            state_after: state.clone(),
                            state_changes: vec![],
                            matched_rules: vec![],
                            decision: StageDecision::Drop {
                                reason: "Egress interface is down".to_string(),
                            },
                            explain: format!(
                                "Egress interface '{}' is in DOWN state — packet cannot be forwarded",
                                egress_name
                            ),
                        });
                        return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
                    }
                    _ => {} // exists and up
                }
            }

            // --- sysctl: ip_forward check ---
            if !sysctl.is_forwarding_enabled(&state.ingress_if) {
                seq += 1;
                trace.push(TraceStep {
                    seq,
                    stage: PipelineStage::Forward,
                    description: "ip_forward disabled".to_string(),
                    state_before: state.clone(),
                    state_after: state.clone(),
                    state_changes: vec![],
                    matched_rules: vec![],
                    decision: StageDecision::Drop {
                        reason: "IP forwarding disabled".to_string(),
                    },
                    explain: format!(
                        "net.ipv4.ip_forward=0 — packet requires forwarding but forwarding is disabled on {}",
                        state.ingress_if
                    ),
                });
                return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
            }

            // --- Stage 6b: FORWARD chains ---
            seq += 1;
            let state_before = state.clone();
            let result = pipeline::forward::execute(&scenario.netfilter, &mut state, &scenario.interfaces);
            trace.push(make_trace_step(seq, PipelineStage::Forward, &state_before, &state, &result));
            all_matched_rules.extend(result.matched_rules.clone());
            if let Some(verdict) = terminal_verdict(&result.decision) {
                return finalize(scenario, trace, all_matched_rules, verdict, &state);
            }

            // --- Stage 7: POSTROUTING ---
            seq += 1;
            let state_before = state.clone();
            let result = pipeline::postrouting::execute(&scenario.netfilter, &mut state, &scenario.interfaces);
            trace.push(make_trace_step(seq, PipelineStage::PostRouting, &state_before, &state, &result));
            all_matched_rules.extend(result.matched_rules.clone());
            if let Some(verdict) = terminal_verdict(&result.decision) {
                return finalize(scenario, trace, all_matched_rules, verdict, &state);
            }

            // --- (e) MTU check ---
            if let Some(ref egress_name) = state.egress_if {
                if let Some(egress_iface) = find_interface(&scenario.interfaces, egress_name) {
                    let mtu = egress_iface.mtu;
                    if let Some(pkt_len) = state.packet_length {
                        if pkt_len > mtu {
                            seq += 1;
                            if state.df_flag {
                                trace.push(TraceStep {
                                    seq,
                                    stage: PipelineStage::MtuCheck,
                                    description: "MTU exceeded with DF flag".to_string(),
                                    state_before: state.clone(),
                                    state_after: state.clone(),
                                    state_changes: vec![],
                                    matched_rules: vec![],
                                    decision: StageDecision::Drop {
                                        reason: "Packet exceeds MTU and DF flag is set (ICMP Fragmentation Needed would be sent)".to_string(),
                                    },
                                    explain: format!(
                                        "Packet length {} exceeds egress interface '{}' MTU {} and DF (Don't Fragment) flag is set. \
                                         Kernel would send ICMP Fragmentation Needed (Type 3, Code 4) back to sender.",
                                        pkt_len, egress_name, mtu
                                    ),
                                });
                                return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
                            } else {
                                trace.push(TraceStep {
                                    seq,
                                    stage: PipelineStage::MtuCheck,
                                    description: "MTU exceeded, fragmentation needed".to_string(),
                                    state_before: state.clone(),
                                    state_after: state.clone(),
                                    state_changes: vec![],
                                    matched_rules: vec![],
                                    decision: StageDecision::Continue,
                                    explain: format!(
                                        "Packet length {} exceeds egress interface '{}' MTU {}. \
                                         Packet would be fragmented before transmission.",
                                        pkt_len, egress_name, mtu
                                    ),
                                });
                            }
                        }
                    } else {
                        // packet_length unknown — record informational step
                        seq += 1;
                        trace.push(TraceStep {
                            seq,
                            stage: PipelineStage::MtuCheck,
                            description: "MTU check skipped".to_string(),
                            state_before: state.clone(),
                            state_after: state.clone(),
                            state_changes: vec![],
                            matched_rules: vec![],
                            decision: StageDecision::Continue,
                            explain: "MTU check skipped: packet length not specified".to_string(),
                        });
                    }
                }
            }

            // --- Stage 8: conntrack confirm ---
            seq += 1;
            trace.push(TraceStep {
                seq,
                stage: PipelineStage::ConntrackConfirm,
                description: "conntrack confirm".to_string(),
                state_before: state.clone(),
                state_after: state.clone(),
                state_changes: vec![],
                matched_rules: vec![],
                decision: StageDecision::Continue,
                explain: "Conntrack entry confirmed for forwarded packet".to_string(),
            });

            finalize(scenario, trace, all_matched_rules, FinalVerdict::Forwarded, &state)
        }
        StageDecision::Drop { .. } => {
            finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state)
        }
        StageDecision::Reject { .. } => {
            finalize(scenario, trace, all_matched_rules, FinalVerdict::Rejected, &state)
        }
        StageDecision::Stolen => {
            finalize(scenario, trace, all_matched_rules, FinalVerdict::Tproxy, &state)
        }
        StageDecision::Redirect { .. } => {
            finalize(scenario, trace, all_matched_rules, FinalVerdict::Redirect, &state)
        }
        _ => {
            finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state)
        }
    }
}

/// Reverse Path Filter 검사
fn check_rp_filter(
    sysctl: &SysctlConfig,
    state: &PacketState,
    ip_rules: &[crate::model::policy_routing::IpRule],
    routing_tables: &[crate::model::routing::RoutingTable],
    interfaces: &[Interface],
) -> Option<StageResult> {
    let mode = sysctl.rp_filter_mode(&state.ingress_if);
    if matches!(mode, RpFilterMode::Off) {
        return None;
    }

    let src_ip = match state.src_ip {
        Some(ip) => ip,
        None => return None, // L2-only, skip
    };

    // src_ip에 대해 역방향 라우팅 조회
    let reverse_result = pipeline::routing::reverse_path_lookup(
        ip_rules, routing_tables, interfaces, &src_ip,
    );

    match mode {
        RpFilterMode::Strict => {
            // strict: 역라우팅 결과의 egress가 ingress와 같아야 함
            match reverse_result {
                Some(egress_if) if egress_if == state.ingress_if => None,
                Some(egress_if) => Some(StageResult::drop(
                    format!("rp_filter strict: reverse route for {} via {} != ingress {}", src_ip, egress_if, state.ingress_if),
                    format!(
                        "Reverse path filter (strict): source {} would be routed via {}, but arrived on {}. \
                         Set net.ipv4.conf.{}.rp_filter=0 to disable.",
                        src_ip, egress_if, state.ingress_if, state.ingress_if
                    ),
                )),
                None => Some(StageResult::drop(
                    format!("rp_filter strict: no reverse route for {}", src_ip),
                    format!(
                        "Reverse path filter (strict): no route found for source {}. \
                         Set net.ipv4.conf.{}.rp_filter=0 to disable.",
                        src_ip, state.ingress_if
                    ),
                )),
            }
        }
        RpFilterMode::Loose => {
            // loose: 어떤 인터페이스든 역라우팅 가능하면 통과
            match reverse_result {
                Some(_) => None,
                None => Some(StageResult::drop(
                    format!("rp_filter loose: no reverse route for {}", src_ip),
                    format!(
                        "Reverse path filter (loose): no route found for source {}. \
                         Set net.ipv4.conf.{}.rp_filter=0 to disable.",
                        src_ip, state.ingress_if
                    ),
                )),
            }
        }
        RpFilterMode::Off => None,
    }
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

/// 두 IP가 같은 서브넷에 있는지 확인
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
        _ => false, // different families
    }
}

fn terminal_verdict(decision: &StageDecision) -> Option<FinalVerdict> {
    match decision {
        StageDecision::Drop { .. } => Some(FinalVerdict::Drop),
        StageDecision::Reject { .. } => Some(FinalVerdict::Rejected),
        StageDecision::Stolen => Some(FinalVerdict::Tproxy),
        StageDecision::Redirect { .. } => Some(FinalVerdict::Redirect),
        _ => None,
    }
}

fn finalize(
    _scenario: &Scenario,
    trace: Vec<TraceStep>,
    matched_rules: Vec<MatchedRuleRef>,
    verdict: FinalVerdict,
    state: &PacketState,
) -> SimulationResult {
    let nat_applied = state.dnat_applied || state.snat_applied;
    let next_hop = trace.iter()
        .find(|s| matches!(s.stage, PipelineStage::RoutingDecision))
        .and_then(|s| match &s.decision {
            StageDecision::ForwardTo { next_hop, .. } => *next_hop,
            _ => None,
        });

    SimulationResult {
        id: Uuid::new_v4().to_string(),
        verdict: verdict.clone(),
        summary: SimulationSummary {
            verdict,
            egress_interface: state.egress_if.clone(),
            next_hop,
            matched_rules: matched_rules.clone(),
            nat_applied,
            total_steps: trace.len(),
        },
        trace,
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

fn make_trace_step(
    seq: u32,
    stage: PipelineStage,
    state_before: &PacketState,
    state_after: &PacketState,
    result: &StageResult,
) -> TraceStep {
    let state_changes = compute_state_changes(state_before, state_after);
    TraceStep {
        seq,
        stage: stage.clone(),
        description: format!("{}", stage),
        state_before: state_before.clone(),
        state_after: state_after.clone(),
        state_changes,
        matched_rules: result.matched_rules.clone(),
        decision: result.decision.clone(),
        explain: result.explain.clone(),
    }
}

/// 로컬 발신 패킷 시뮬레이션 (OUTPUT 경로)
///
/// 파이프라인:
///   OUTPUT chains (raw → conntrack → mangle → filter → nat)
///   → Routing Decision (post-OUTPUT)
///   → POSTROUTING chains
///   → egress MTU check
///   → conntrack confirm
///   → SENT
pub fn run_output(scenario: &Scenario) -> SimulationResult {
    let mut state = PacketState::from_packet_def(&scenario.packet);
    let mut trace = Vec::new();
    let mut all_matched_rules: Vec<MatchedRuleRef> = Vec::new();
    let mut seq: u32 = 0;

    // --- Stage 1: OUTPUT chains ---
    // Like PREROUTING, OUTPUT is split: raw → conntrack → mangle/filter/nat
    {
        let all_output_chains = pipeline::collect_chains_for_hook(
            &scenario.netfilter,
            &crate::model::netfilter::NfHook::Output,
        );

        // Split: raw (priority <= -200) vs post-conntrack
        let (raw_chains, post_ct_chains): (Vec<_>, Vec<_>) =
            all_output_chains.into_iter().partition(|c| c.priority <= -200);

        // (a) RAW chains
        if !raw_chains.is_empty() {
            seq += 1;
            let state_before = state.clone();
            let result = pipeline::evaluate_chains_subset(
                &raw_chains,
                "OUTPUT_RAW",
                &mut state,
                &scenario.interfaces,
            );
            trace.push(make_trace_step(
                seq,
                PipelineStage::Output,
                &state_before,
                &state,
                &result,
            ));
            all_matched_rules.extend(result.matched_rules.clone());
            if let Some(verdict) = terminal_verdict(&result.decision) {
                return finalize(scenario, trace, all_matched_rules, verdict, &state);
            }
        }

        // (b) Conntrack
        seq += 1;
        trace.push(TraceStep {
            seq,
            stage: PipelineStage::ConntrackIn,
            description: "conntrack lookup (output)".to_string(),
            state_before: state.clone(),
            state_after: state.clone(),
            state_changes: vec![],
            matched_rules: vec![],
            decision: StageDecision::Continue,
            explain: format!(
                "Conntrack lookup for locally-originated packet: ct_state={} (user-declared)",
                state.ct_state
            ),
        });

        // (c) Post-conntrack OUTPUT chains (mangle, filter, nat)
        seq += 1;
        let state_before = state.clone();
        let result = pipeline::evaluate_chains_subset(
            &post_ct_chains,
            "OUTPUT",
            &mut state,
            &scenario.interfaces,
        );
        trace.push(make_trace_step(
            seq,
            PipelineStage::Output,
            &state_before,
            &state,
            &result,
        ));
        all_matched_rules.extend(result.matched_rules.clone());
        if let Some(verdict) = terminal_verdict(&result.decision) {
            return finalize(scenario, trace, all_matched_rules, verdict, &state);
        }
    }

    // --- Stage 2: Routing Decision (post-OUTPUT) ---
    seq += 1;
    let state_before = state.clone();
    let result = pipeline::routing::execute(
        &scenario.ip_rules,
        &scenario.routing_tables,
        &scenario.interfaces,
        &mut state,
    );
    trace.push(make_trace_step(
        seq,
        PipelineStage::RoutingDecision,
        &state_before,
        &state,
        &result,
    ));
    all_matched_rules.extend(result.matched_rules.clone());

    match &result.decision {
        StageDecision::Drop { .. } => {
            return finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state);
        }
        StageDecision::Reject { .. } => {
            return finalize(scenario, trace, all_matched_rules, FinalVerdict::Rejected, &state);
        }
        _ => {}
    }

    // --- Stage 3: POSTROUTING chains ---
    seq += 1;
    let state_before = state.clone();
    let result =
        pipeline::postrouting::execute(&scenario.netfilter, &mut state, &scenario.interfaces);
    trace.push(make_trace_step(
        seq,
        PipelineStage::PostRouting,
        &state_before,
        &state,
        &result,
    ));
    all_matched_rules.extend(result.matched_rules.clone());
    if let Some(verdict) = terminal_verdict(&result.decision) {
        return finalize(scenario, trace, all_matched_rules, verdict, &state);
    }

    // --- Stage 4: Egress MTU check ---
    if let Some(ref egress_name) = state.egress_if {
        if let Some(egress_iface) = find_interface(&scenario.interfaces, egress_name) {
            let mtu = egress_iface.mtu;
            if let Some(pkt_len) = state.packet_length {
                if pkt_len > mtu {
                    seq += 1;
                    if state.df_flag {
                        trace.push(TraceStep {
                            seq,
                            stage: PipelineStage::MtuCheck,
                            description: "MTU exceeded with DF flag".to_string(),
                            state_before: state.clone(),
                            state_after: state.clone(),
                            state_changes: vec![],
                            matched_rules: vec![],
                            decision: StageDecision::Drop {
                                reason: "Packet exceeds MTU and DF flag is set".to_string(),
                            },
                            explain: format!(
                                "Packet length {} exceeds egress interface '{}' MTU {} and DF flag is set.",
                                pkt_len, egress_name, mtu
                            ),
                        });
                        return finalize(
                            scenario,
                            trace,
                            all_matched_rules,
                            FinalVerdict::Drop,
                            &state,
                        );
                    } else {
                        trace.push(TraceStep {
                            seq,
                            stage: PipelineStage::MtuCheck,
                            description: "MTU exceeded, fragmentation needed".to_string(),
                            state_before: state.clone(),
                            state_after: state.clone(),
                            state_changes: vec![],
                            matched_rules: vec![],
                            decision: StageDecision::Continue,
                            explain: format!(
                                "Packet length {} exceeds egress interface '{}' MTU {}. \
                                 Packet would be fragmented before transmission.",
                                pkt_len, egress_name, mtu
                            ),
                        });
                    }
                }
            }
        }
    }

    // --- Stage 5: Conntrack confirm ---
    seq += 1;
    trace.push(TraceStep {
        seq,
        stage: PipelineStage::ConntrackConfirm,
        description: "conntrack confirm".to_string(),
        state_before: state.clone(),
        state_after: state.clone(),
        state_changes: vec![],
        matched_rules: vec![],
        decision: StageDecision::Continue,
        explain: "Conntrack entry confirmed for locally-originated packet".to_string(),
    });

    finalize(scenario, trace, all_matched_rules, FinalVerdict::Sent, &state)
}
