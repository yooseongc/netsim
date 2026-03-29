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

use crate::model::interface::Interface;
use crate::model::packet::{IpProtocol, PacketState};
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

    // --- Stage 1: XDP ---
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

    // L2-only 패킷은 XDP 이후 netfilter/routing 건너뛰기
    if state.ethertype.is_l2_only() {
        seq += 1;
        trace.push(TraceStep {
            seq,
            stage: PipelineStage::RoutingDecision,
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
            stage: PipelineStage::TcIngress,
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

    // --- Stage 3: conntrack lookup ---
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

    // --- Stage 4: PREROUTING ---
    seq += 1;
    let state_before = state.clone();
    let result = pipeline::prerouting::execute(&scenario.netfilter, &mut state, &scenario.interfaces);
    trace.push(make_trace_step(seq, PipelineStage::PreRouting, &state_before, &state, &result));
    all_matched_rules.extend(result.matched_rules.clone());
    if let Some(verdict) = terminal_verdict(&result.decision) {
        return finalize(scenario, trace, all_matched_rules, verdict, &state);
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
