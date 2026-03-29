//! FORWARD 체인 파이프라인 단계
//!
//! netfilter FORWARD hook의 모든 체인을 priority 순으로 평가한다.
//! 포워딩 대상 패킷에 대해 실행되며, TTL을 1 감소시킨다.
//! TTL이 0이 되면 패킷은 DROP된다 (실제로는 ICMP Time Exceeded 전송).

use crate::model::interface::Interface;
use crate::model::netfilter::{NetfilterConfig, NfHook};
use crate::model::packet::PacketState;
use crate::trace::StageDecision;

use super::{evaluate_netfilter_hook, StageResult};

/// FORWARD 단계를 실행한다.
pub fn execute(
    config: &NetfilterConfig,
    state: &mut PacketState,
    interfaces: &[Interface],
) -> StageResult {
    // TTL 감소 (IP 패킷만) — Linux 커널과 동일하게 감소 후 확인
    if !state.ethertype.is_l2_only() {
        let original_ttl = state.ttl;
        state.ttl = state.ttl.saturating_sub(1);
        if state.ttl == 0 {
            return StageResult {
                decision: StageDecision::Drop {
                    reason: "TTL expired in transit".to_string(),
                },
                matched_rules: Vec::new(),
                explain: format!(
                    "TTL decremented from {} to 0 — packet dropped (ICMP Time Exceeded would be sent to sender)",
                    original_ttl
                ),
            };
        }
    }

    evaluate_netfilter_hook(config, &NfHook::Forward, state, interfaces)
}
