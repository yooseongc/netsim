//! PREROUTING 파이프라인 단계
//!
//! netfilter PREROUTING hook의 모든 체인을 priority 순으로 평가한다.
//! - nftables: hook=prerouting 체인
//! - iptables: raw(-300), mangle(-150), nat(-100) 테이블의 PREROUTING 체인
//!
//! NAT 액션(DNAT, REDIRECT, TPROXY) 처리 시 PacketState를 수정한다.
//! ICMP의 경우 포트가 없으므로 NAT는 IP만 변경한다.
//! L2-only 패킷(ARP, STP)은 netfilter를 건너뛴다.

use crate::model::interface::Interface;
use crate::model::netfilter::{NetfilterConfig, NfHook};
use crate::model::packet::PacketState;

use super::{evaluate_netfilter_hook, StageResult};

/// PREROUTING 단계를 실행한다.
pub fn execute(
    config: &NetfilterConfig,
    state: &mut PacketState,
    interfaces: &[Interface],
) -> StageResult {
    evaluate_netfilter_hook(config, &NfHook::Prerouting, state, interfaces)
}
