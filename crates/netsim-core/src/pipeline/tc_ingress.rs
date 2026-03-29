//! tc ingress 파이프라인 단계
//!
//! MVP에서는 pass-through. 항상 Continue를 반환한다.

use crate::model::packet::PacketState;

use super::StageResult;

/// tc ingress 단계를 실행한다. (MVP: pass-through)
pub fn execute(state: &PacketState) -> StageResult {
    StageResult::pass(format!(
        "tc ingress on {} — pass-through (MVP)",
        state.ingress_if
    ))
}
