use crate::model::packet::PacketState;
use crate::model::scenario::Scenario;
use crate::pipeline::StageResult;
use crate::trace::{
    compute_state_changes, FinalVerdict, MatchedRuleRef, PipelineStage, SimulationResult,
    SimulationSummary, StageDecision, TraceStep,
};

/// Routing decision outcome, stored in context for re-routing support
#[derive(Debug, Clone)]
pub enum RoutingOutcome {
    Local,
    ForwardTo {
        egress_if: String,
        next_hop: Option<std::net::IpAddr>,
    },
    Drop {
        reason: String,
    },
    Reject {
        reason: String,
    },
}

/// Pipeline execution context — carries all state through the pipeline
pub struct PipelineContext<'a> {
    pub packet: PacketState,
    pub scenario: &'a Scenario,
    pub trace: Vec<TraceStep>,
    pub matched_rules: Vec<MatchedRuleRef>,
    pub seq: u32,
    /// Result of most recent routing decision (can be set multiple times on reroute)
    pub routing_result: Option<RoutingOutcome>,
    /// Flag: routing needs to be re-evaluated (DNAT changed dst, mark changed for PBR)
    pub needs_reroute: bool,
}

/// Pipeline stage outcome
#[derive(Debug, Clone)]
pub enum StageOutcome {
    /// Continue to next stage
    Continue,
    /// Pipeline terminates with this verdict
    Terminal(FinalVerdict),
    /// Jump back to routing decision (after DNAT/mark change)
    Reroute,
}

impl<'a> PipelineContext<'a> {
    pub fn from_scenario(scenario: &'a Scenario) -> Self {
        Self {
            packet: PacketState::from_packet_def(&scenario.packet),
            scenario,
            trace: Vec::new(),
            matched_rules: Vec::new(),
            seq: 0,
            routing_result: None,
            needs_reroute: false,
        }
    }

    /// Record a trace step with automatic state diff computation.
    /// Uses `format!("{}", stage)` as the description (matching previous `make_trace_step` behavior).
    pub fn record_step(
        &mut self,
        stage: PipelineStage,
        state_before: &PacketState,
        result: &StageResult,
    ) {
        self.seq += 1;
        let state_changes = compute_state_changes(state_before, &self.packet);
        let description = format!("{}", stage);
        self.trace.push(TraceStep {
            seq: self.seq,
            stage,
            description,
            state_before: state_before.clone(),
            state_after: self.packet.clone(),
            state_changes,
            matched_rules: result.matched_rules.clone(),
            decision: result.decision.clone(),
            explain: result.explain.clone(),
        });
        self.matched_rules.extend(result.matched_rules.clone());
    }

    /// Record a simple informational step (no StageResult)
    pub fn record_info_step(
        &mut self,
        stage: PipelineStage,
        description: impl Into<String>,
        decision: StageDecision,
        explain: impl Into<String>,
    ) {
        self.seq += 1;
        self.trace.push(TraceStep {
            seq: self.seq,
            stage,
            description: description.into(),
            state_before: self.packet.clone(),
            state_after: self.packet.clone(),
            state_changes: vec![],
            matched_rules: vec![],
            decision,
            explain: explain.into(),
        });
    }

    /// Build the final SimulationResult from context state
    pub fn finalize(self, verdict: FinalVerdict) -> SimulationResult {
        let nat_applied = self.packet.dnat_applied || self.packet.snat_applied;
        let next_hop = self
            .trace
            .iter()
            .find(|s| matches!(s.stage, PipelineStage::RoutingDecision))
            .and_then(|s| match &s.decision {
                StageDecision::ForwardTo { next_hop, .. } => *next_hop,
                _ => None,
            });

        SimulationResult {
            id: uuid::Uuid::new_v4().to_string(),
            verdict: verdict.clone(),
            summary: SimulationSummary {
                verdict,
                egress_interface: self.packet.egress_if.clone(),
                next_hop,
                matched_rules: self.matched_rules,
                nat_applied,
                total_steps: self.trace.len(),
            },
            trace: self.trace,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}
