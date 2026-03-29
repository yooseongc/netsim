//! XDP 파이프라인 단계
//!
//! 인그레스 인터페이스에 연결된 XDP 프로그램의 규칙을 평가한다.
//! XDP는 L2 레벨에서 동작하므로 ARP/STP 등 L2-only 패킷도 처리한다.
//! 프로그램이 없으면 XDP_PASS (Continue).

use crate::model::packet::PacketState;
use crate::model::xdp::{XdpAction, XdpConfig};
use crate::matcher::evaluate_matches;
use crate::trace::{MatchedRuleRef, RuleSource, StageDecision};

use super::StageResult;

/// XDP 단계를 실행한다.
pub fn execute(
    xdp_config: &XdpConfig,
    state: &mut PacketState,
) -> StageResult {
    // 인그레스 인터페이스에 연결된 XDP 프로그램 찾기
    let program = xdp_config
        .programs
        .iter()
        .find(|p| p.interface == state.ingress_if);

    let program = match program {
        Some(p) => p,
        None => {
            return StageResult::pass(format!(
                "No XDP program on interface {}",
                state.ingress_if
            ));
        }
    };

    // 규칙 순서대로 평가
    for (idx, rule) in program.rules.iter().enumerate() {
        if !evaluate_matches(&rule.matches, state) {
            continue;
        }

        let rule_ref = MatchedRuleRef {
            source: RuleSource::Xdp,
            table: "xdp".to_string(),
            chain: program.interface.clone(),
            rule_index: idx,
            rule_summary: format!(
                "{} match(es) -> {}{}",
                rule.matches.len(),
                rule.action,
                rule.comment
                    .as_deref()
                    .map(|c| format!(" /* {} */", c))
                    .unwrap_or_default()
            ),
        };

        return match &rule.action {
            XdpAction::Pass => StageResult {
                decision: StageDecision::Continue,
                matched_rules: vec![rule_ref],
                explain: format!(
                    "XDP rule #{} on {} matched: XDP_PASS",
                    idx, state.ingress_if
                ),
            },
            XdpAction::Drop => StageResult {
                decision: StageDecision::Drop {
                    reason: format!(
                        "XDP_DROP on interface {}",
                        state.ingress_if
                    ),
                },
                matched_rules: vec![rule_ref],
                explain: format!(
                    "XDP rule #{} on {} matched: XDP_DROP",
                    idx, state.ingress_if
                ),
            },
            XdpAction::Tx => StageResult {
                decision: StageDecision::Redirect {
                    target: state.ingress_if.clone(),
                },
                matched_rules: vec![rule_ref],
                explain: format!(
                    "XDP rule #{} on {} matched: XDP_TX (bounce back on same interface)",
                    idx, state.ingress_if
                ),
            },
            XdpAction::Redirect { target_if } => StageResult {
                decision: StageDecision::Redirect {
                    target: target_if.clone(),
                },
                matched_rules: vec![rule_ref],
                explain: format!(
                    "XDP rule #{} on {} matched: XDP_REDIRECT to {}",
                    idx, state.ingress_if, target_if
                ),
            },
            XdpAction::Aborted => StageResult {
                decision: StageDecision::Drop {
                    reason: format!(
                        "XDP_ABORTED on interface {}",
                        state.ingress_if
                    ),
                },
                matched_rules: vec![rule_ref],
                explain: format!(
                    "XDP rule #{} on {} matched: XDP_ABORTED (error path, packet dropped)",
                    idx, state.ingress_if
                ),
            },
        };
    }

    // 매칭된 규칙 없음 → default action
    match &program.default_action {
        XdpAction::Pass => StageResult::pass(format!(
            "No XDP rule matched on {}; default action XDP_PASS",
            state.ingress_if
        )),
        XdpAction::Drop => StageResult::drop(
            format!("XDP default DROP on {}", state.ingress_if),
            format!(
                "No XDP rule matched on {}; default action XDP_DROP",
                state.ingress_if
            ),
        ),
        XdpAction::Tx => StageResult {
            decision: StageDecision::Redirect {
                target: state.ingress_if.clone(),
            },
            matched_rules: Vec::new(),
            explain: format!(
                "No XDP rule matched on {}; default action XDP_TX",
                state.ingress_if
            ),
        },
        XdpAction::Redirect { target_if } => StageResult {
            decision: StageDecision::Redirect {
                target: target_if.clone(),
            },
            matched_rules: Vec::new(),
            explain: format!(
                "No XDP rule matched on {}; default action XDP_REDIRECT to {}",
                state.ingress_if, target_if
            ),
        },
        XdpAction::Aborted => StageResult::drop(
            format!("XDP default ABORTED on {}", state.ingress_if),
            format!(
                "No XDP rule matched on {}; default action XDP_ABORTED",
                state.ingress_if
            ),
        ),
    }
}
