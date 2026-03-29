//! POSTROUTING 파이프라인 단계
//!
//! netfilter POSTROUTING hook의 모든 체인을 priority 순으로 평가한다.
//! SNAT/MASQUERADE 처리:
//! - MASQUERADE: egress 인터페이스의 첫 번째 IP를 SNAT 주소로 사용
//! - ICMP: SNAT은 src_ip만 변경 (포트 없음)

use crate::model::interface::Interface;
use crate::model::netfilter::{NetfilterConfig, NfHook};
use crate::model::packet::PacketState;

use super::{evaluate_netfilter_hook, StageResult};

/// POSTROUTING 단계를 실행한다.
pub fn execute(
    config: &NetfilterConfig,
    state: &mut PacketState,
    interfaces: &[Interface],
) -> StageResult {
    evaluate_netfilter_hook(config, &NfHook::Postrouting, state, interfaces)
}
