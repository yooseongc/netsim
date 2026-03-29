//! 세션 단위 시뮬레이션 엔진
//!
//! SessionDef를 받아 관련 패킷 시퀀스를 생성하고,
//! 각 패킷을 순서대로 시뮬레이션한다.
//! NAT 매핑이 reply 패킷에 반영된다.

use crate::engine;
use crate::model::scenario::Scenario;
use crate::model::session::SessionDef;
use crate::trace::{FinalVerdict, SimulationResult};

/// 세션 시뮬레이션 결과
#[derive(Debug, Clone)]
pub struct SessionResult {
    /// 세션 내 각 패킷의 시뮬레이션 결과
    pub packet_results: Vec<PacketSimResult>,
    /// 세션 전체 요약
    pub session_verdict: SessionVerdict,
}

#[derive(Debug, Clone)]
pub struct PacketSimResult {
    /// 패킷 라벨 (e.g., "TCP SYN", "ICMP Echo Reply")
    pub label: String,
    /// 개별 패킷 시뮬레이션 결과
    pub result: SimulationResult,
}

/// 세션 전체 결과
#[derive(Debug, Clone, PartialEq)]
pub enum SessionVerdict {
    /// 모든 패킷이 성공적으로 전달됨
    Established,
    /// 특정 패킷에서 실패
    Failed {
        failed_at: String,
        reason: FinalVerdict,
    },
    /// 부분 성공 (일부만 통과)
    Partial {
        passed: usize,
        total: usize,
    },
}

/// 세션 기반 시뮬레이션 실행
///
/// 세션을 개별 패킷으로 확장하고, 네트워크 설정(scenario의 나머지 부분)을
/// 공유하면서 각 패킷을 순서대로 시뮬레이션한다.
///
/// NAT가 적용된 경우, reply 패킷의 주소/포트가 NAT 매핑에 따라 자동 조정된다.
pub fn run_session(
    base_scenario: &Scenario,
    session: &SessionDef,
) -> SessionResult {
    let packets = session.expand_to_packets();

    if packets.is_empty() {
        return SessionResult {
            packet_results: vec![],
            session_verdict: SessionVerdict::Established,
        };
    }

    let mut results = Vec::new();
    let mut nat_mapping: Option<NatMapping> = None;

    for (label, packet_def) in &packets {
        // NAT 매핑이 있으면 reply 패킷에 적용
        let adjusted_packet = match &nat_mapping {
            Some(mapping) => mapping.apply_to_reply(packet_def),
            None => packet_def.clone(),
        };

        // 이 패킷으로 시나리오 구성
        let mut scenario = base_scenario.clone();
        scenario.packet = adjusted_packet;

        let sim_result = engine::run(&scenario);

        // 첫 번째 (forward) 패킷에서 NAT 매핑 추출
        if nat_mapping.is_none() {
            nat_mapping = extract_nat_mapping(&sim_result);
        }

        let is_terminal = is_terminal_verdict(&sim_result.verdict);
        results.push(PacketSimResult {
            label: label.clone(),
            result: sim_result,
        });

        // 패킷이 드롭되면 세션 중단
        if is_terminal {
            let failed = results.last().unwrap();
            return SessionResult {
                session_verdict: SessionVerdict::Failed {
                    failed_at: failed.label.clone(),
                    reason: failed.result.verdict.clone(),
                },
                packet_results: results,
            };
        }
    }

    let total = results.len();
    let passed = results
        .iter()
        .filter(|r| !is_terminal_verdict(&r.result.verdict))
        .count();

    let verdict = if passed == total {
        SessionVerdict::Established
    } else {
        SessionVerdict::Partial { passed, total }
    };

    SessionResult {
        packet_results: results,
        session_verdict: verdict,
    }
}

/// NAT 매핑 정보 — forward 패킷에서 추출하여 reply 패킷에 적용
#[derive(Debug, Clone)]
struct NatMapping {
    /// DNAT: original dst → translated dst
    dnat_original_dst_ip: Option<std::net::IpAddr>,
    dnat_translated_dst_ip: Option<std::net::IpAddr>,
    dnat_original_dst_port: Option<u16>,
    dnat_translated_dst_port: Option<u16>,
    /// SNAT: original src → translated src
    snat_original_src_ip: Option<std::net::IpAddr>,
    snat_translated_src_ip: Option<std::net::IpAddr>,
    snat_original_src_port: Option<u16>,
    snat_translated_src_port: Option<u16>,
}

impl NatMapping {
    /// Reply 패킷에 NAT 매핑을 역으로 적용
    ///
    /// Forward: client(A:a) → server(B:b), DNAT → B':b', SNAT → A':a'
    /// Reply:   server(B':b') → client(A':a') (NAT 역변환)
    fn apply_to_reply(
        &self,
        original_reply: &crate::model::packet::PacketDef,
    ) -> crate::model::packet::PacketDef {
        let mut reply = original_reply.clone();

        // DNAT 역변환: reply의 src가 translated dst여야 함
        if let (Some(orig), Some(translated)) =
            (self.dnat_original_dst_ip, self.dnat_translated_dst_ip)
        {
            // reply 패킷의 src_ip가 original dst → translated dst로 변경
            if reply.src_ip == Some(orig) {
                reply.src_ip = Some(translated);
            }
            if let (Some(orig_port), Some(trans_port)) =
                (self.dnat_original_dst_port, self.dnat_translated_dst_port)
            {
                if reply.src_port == Some(orig_port) {
                    reply.src_port = Some(trans_port);
                }
            }
        }

        // SNAT 역변환: reply의 dst가 translated src여야 함
        if let (Some(orig), Some(translated)) =
            (self.snat_original_src_ip, self.snat_translated_src_ip)
        {
            if reply.dst_ip == Some(orig) {
                reply.dst_ip = Some(translated);
            }
            if let (Some(orig_port), Some(trans_port)) =
                (self.snat_original_src_port, self.snat_translated_src_port)
            {
                if reply.dst_port == Some(orig_port) {
                    reply.dst_port = Some(trans_port);
                }
            }
        }

        reply
    }
}

/// 시뮬레이션 결과에서 NAT 매핑 추출
fn extract_nat_mapping(result: &SimulationResult) -> Option<NatMapping> {
    // 마지막 trace step의 state에서 NAT 정보 추출
    let final_state = result.trace.last().map(|s| &s.state_after)?;

    if !final_state.dnat_applied && !final_state.snat_applied {
        return None;
    }

    Some(NatMapping {
        dnat_original_dst_ip: final_state.original_dst_ip,
        dnat_translated_dst_ip: if final_state.dnat_applied {
            final_state.dst_ip
        } else {
            None
        },
        dnat_original_dst_port: final_state.original_dst_port,
        dnat_translated_dst_port: if final_state.dnat_applied {
            final_state.dst_port
        } else {
            None
        },
        snat_original_src_ip: final_state.original_src_ip,
        snat_translated_src_ip: if final_state.snat_applied {
            final_state.src_ip
        } else {
            None
        },
        snat_original_src_port: final_state.original_src_port,
        snat_translated_src_port: if final_state.snat_applied {
            final_state.src_port
        } else {
            None
        },
    })
}

fn is_terminal_verdict(verdict: &FinalVerdict) -> bool {
    matches!(
        verdict,
        FinalVerdict::Drop | FinalVerdict::Rejected | FinalVerdict::Blackhole
    )
}
