//! INPUT 체인 파이프라인 단계
//!
//! netfilter INPUT hook의 모든 체인을 priority 순으로 평가한다.
//! 로컬 전달(local delivery)로 결정된 패킷에 대해 실행된다.

use crate::model::interface::Interface;
use crate::model::netfilter::{NetfilterConfig, NfHook};
use crate::model::packet::PacketState;

use super::{evaluate_netfilter_hook, StageResult};

/// INPUT 단계를 실행한다.
pub fn execute(
    config: &NetfilterConfig,
    state: &mut PacketState,
    interfaces: &[Interface],
) -> StageResult {
    evaluate_netfilter_hook(config, &NfHook::Input, state, interfaces)
}
