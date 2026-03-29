pub mod context;
pub mod xdp;
pub mod tc_ingress;
pub mod prerouting;
pub mod routing;
pub mod local_input;
pub mod forward;
pub mod postrouting;
pub mod stages;
pub mod chain_eval;
pub mod nat;

pub use context::{PipelineContext, StageOutcome, RoutingOutcome};

// Re-export chain evaluation types and functions for backward compatibility
pub use chain_eval::{
    OrderedChain, ChainEvalResult,
    collect_chains_for_hook, collect_all_chains_in_tables,
    evaluate_chain, evaluate_netfilter_hook, evaluate_chains_subset,
    find_user_chain, hook_to_iptables_chain_name, hook_label,
    format_rule_summary, source_label,
};

// Re-export NAT function for backward compatibility
pub use nat::apply_nat;

use crate::trace::StageDecision;

/// 파이프라인 각 단계의 공통 결과 타입
#[derive(Debug, Clone)]
pub struct StageResult {
    pub decision: StageDecision,
    pub matched_rules: Vec<crate::trace::MatchedRuleRef>,
    pub explain: String,
}

impl StageResult {
    pub fn pass(explain: impl Into<String>) -> Self {
        Self {
            decision: StageDecision::Continue,
            matched_rules: Vec::new(),
            explain: explain.into(),
        }
    }

    pub fn drop(reason: impl Into<String>, explain: impl Into<String>) -> Self {
        Self {
            decision: StageDecision::Drop {
                reason: reason.into(),
            },
            matched_rules: Vec::new(),
            explain: explain.into(),
        }
    }

    pub fn accept(explain: impl Into<String>) -> Self {
        Self {
            decision: StageDecision::Accept,
            matched_rules: Vec::new(),
            explain: explain.into(),
        }
    }
}
