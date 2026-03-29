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
//! L2-only 패킷 (ARP, STP):
//!   XDP만 거치고 netfilter/routing은 건너뛴다.
//!   bridge 모드가 아닌 이상 로컬 처리 또는 드롭.

use uuid::Uuid;

use crate::model::packet::PacketState;
use crate::model::scenario::Scenario;
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

    // --- Stage 1: XDP ---
    seq += 1;
    let state_before = state.clone();
    let result = pipeline::xdp::execute(&scenario.xdp, &mut state);
    trace.push(make_trace_step(seq, PipelineStage::Xdp, &state_before, &state, &result));
    all_matched_rules.extend(result.matched_rules.clone());
    // XDP terminal: DROP, TX(=Redirect to same if), REDIRECT(=Redirect to other if)
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
        _ => {} // Continue, Accept → 다음 단계로
    }

    // L2-only 패킷은 XDP 이후 netfilter/routing 건너뛰기
    if state.ethertype.is_l2_only() {
        seq += 1;
        let explain = format!(
            "L2-only packet ({}) — bypasses netfilter and routing. Delivered locally for ARP processing.",
            state.ethertype
        );
        trace.push(TraceStep {
            seq,
            stage: PipelineStage::RoutingDecision,
            description: "L2 bypass".to_string(),
            state_before: state.clone(),
            state_after: state.clone(),
            state_changes: vec![],
            matched_rules: vec![],
            decision: StageDecision::LocalDelivery,
            explain,
        });
        return finalize(scenario, trace, all_matched_rules, FinalVerdict::LocalDelivery, &state);
    }

    // --- Stage 2: tc ingress ---
    seq += 1;
    let state_before = state.clone();
    let result = pipeline::tc_ingress::execute(&state);
    trace.push(make_trace_step(seq, PipelineStage::TcIngress, &state_before, &state, &result));

    // --- Stage 3: conntrack lookup ---
    seq += 1;
    let state_before = state.clone();
    let ct_explain = format!(
        "Conntrack lookup: packet classified as ct_state={} (user-declared)",
        state.ct_state
    );
    trace.push(TraceStep {
        seq,
        stage: PipelineStage::ConntrackIn,
        description: "conntrack lookup".to_string(),
        state_before: state_before.clone(),
        state_after: state.clone(),
        state_changes: vec![],
        matched_rules: vec![],
        decision: StageDecision::Continue,
        explain: ct_explain,
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
            // Continue, Accept 등 routing에서 예상치 못한 결정
            finalize(scenario, trace, all_matched_rules, FinalVerdict::Drop, &state)
        }
    }
}

/// StageDecision이 파이프라인을 종료하는 결정인지 확인하고 FinalVerdict 변환
fn terminal_verdict(decision: &StageDecision) -> Option<FinalVerdict> {
    match decision {
        StageDecision::Drop { .. } => Some(FinalVerdict::Drop),
        StageDecision::Reject { .. } => Some(FinalVerdict::Rejected),
        StageDecision::Stolen => Some(FinalVerdict::Tproxy),
        StageDecision::Redirect { .. } => Some(FinalVerdict::Redirect),
        _ => None,
    }
}

/// SimulationResult 생성
fn finalize(
    _scenario: &Scenario,
    trace: Vec<TraceStep>,
    matched_rules: Vec<MatchedRuleRef>,
    verdict: FinalVerdict,
    state: &PacketState,
) -> SimulationResult {
    let nat_applied = state.dnat_applied || state.snat_applied;

    // routing 단계에서 next_hop 추출
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

/// TraceStep 생성 헬퍼
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
