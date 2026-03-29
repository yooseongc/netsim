//! 세션 단위 시뮬레이션 모델
//!
//! 단일 패킷이 아닌 세션(연결) 단위의 시뮬레이션을 지원한다.
//! TCP 3-way handshake, ICMP echo req/resp 등 연관된 패킷들의
//! 전체 흐름을 시뮬레이션할 수 있다.
//!
//! ## 설계 원칙
//!
//! - 기존 단일 패킷 시뮬레이션(`engine::run`)을 재사용
//! - 세션은 순서가 있는 패킷 시퀀스로 정의
//! - conntrack 상태가 패킷 간에 전파됨
//! - NAT 매핑이 세션 내에서 유지됨
//!
//! ## 지원 세션 타입
//!
//! - TCP: SYN → SYN-ACK → ACK (3-way handshake) + 데이터 + FIN
//! - ICMP: Echo Request → Echo Reply
//! - UDP: 요청 → 응답 (conntrack based)
//! - 커스텀: 사용자 정의 패킷 시퀀스

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::conntrack::ConntrackState;
use super::packet::{EtherType, IpProtocol, PacketDef, TcpFlags};

/// 세션 정의 — 관련 패킷들의 시퀀스
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionDef {
    /// 세션 타입 (자동 생성 또는 커스텀)
    #[serde(flatten)]
    pub session_type: SessionType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionType {
    /// TCP 3-way handshake + optional data + optional close
    TcpHandshake {
        /// 클라이언트 측 (SYN 발신자)
        client: SessionEndpoint,
        /// 서버 측
        server: SessionEndpoint,
        /// handshake 이후 추가 패킷 포함 여부
        #[serde(default)]
        include_data: bool,
        /// FIN 종료 시퀀스 포함 여부
        #[serde(default)]
        include_close: bool,
    },
    /// ICMP Echo Request → Echo Reply
    IcmpEcho {
        source: SessionEndpoint,
        destination: SessionEndpoint,
        /// ICMPv6 여부
        #[serde(default)]
        ipv6: bool,
    },
    /// UDP 요청 → 응답
    UdpExchange {
        client: SessionEndpoint,
        server: SessionEndpoint,
    },
    /// 사용자 정의 패킷 시퀀스
    Custom {
        packets: Vec<SessionPacket>,
    },
}

/// 세션 참여자 정보
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionEndpoint {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub interface: String,
    #[serde(default)]
    pub mac: Option<String>,
}

/// 커스텀 세션 내 개별 패킷 정의
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionPacket {
    /// 패킷 방향: "forward" (client→server) 또는 "reply" (server→client)
    pub direction: PacketDirection,
    /// 이 패킷의 conntrack 상태 (자동 추론 또는 수동 지정)
    #[serde(default)]
    pub conntrack_state: Option<ConntrackState>,
    /// TCP 플래그 (TCP 세션인 경우)
    #[serde(default)]
    pub tcp_flags: Option<TcpFlags>,
    /// ICMP type (ICMP 세션인 경우)
    #[serde(default)]
    pub icmp_type: Option<u8>,
    /// ICMP code
    #[serde(default)]
    pub icmp_code: Option<u8>,
    /// 설명
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PacketDirection {
    /// client → server (original direction)
    Forward,
    /// server → client (reply direction)
    Reply,
}

/// 세션을 개별 PacketDef 시퀀스로 확장
impl SessionDef {
    pub fn expand_to_packets(&self) -> Vec<(String, PacketDef)> {
        match &self.session_type {
            SessionType::TcpHandshake {
                client,
                server,
                include_data,
                include_close,
            } => expand_tcp_handshake(client, server, *include_data, *include_close),
            SessionType::IcmpEcho {
                source,
                destination,
                ipv6,
            } => expand_icmp_echo(source, destination, *ipv6),
            SessionType::UdpExchange { client, server } => {
                expand_udp_exchange(client, server)
            }
            SessionType::Custom { packets } => {
                // Custom은 외부에서 PacketDef를 직접 조합해야 함
                // 여기서는 빈 벡터 반환 (Scenario에서 직접 처리)
                packets
                    .iter()
                    .enumerate()
                    .map(|(i, p)| {
                        let label = p
                            .label
                            .clone()
                            .unwrap_or_else(|| format!("packet-{}", i + 1));
                        // Custom packets need a base PacketDef from the scenario
                        // This is a placeholder - actual implementation needs more context
                        (label, PacketDef::default())
                    })
                    .collect()
            }
        }
    }
}

/// TCP 3-way handshake를 패킷 시퀀스로 확장
fn expand_tcp_handshake(
    client: &SessionEndpoint,
    server: &SessionEndpoint,
    include_data: bool,
    include_close: bool,
) -> Vec<(String, PacketDef)> {
    let mut packets = Vec::new();

    // 1. SYN (client → server)
    packets.push((
        "TCP SYN".to_string(),
        PacketDef {
            ingress_interface: client.interface.clone(),
            ethertype: ip_family(&client.ip),
            src_ip: Some(client.ip),
            dst_ip: Some(server.ip),
            protocol: IpProtocol::Tcp,
            src_port: client.port,
            dst_port: server.port,
            tcp_flags: Some(TcpFlags {
                syn: true,
                ..Default::default()
            }),
            conntrack_state: ConntrackState::New,
            ..PacketDef::default()
        },
    ));

    // 2. SYN-ACK (server → client)
    packets.push((
        "TCP SYN-ACK".to_string(),
        PacketDef {
            ingress_interface: server.interface.clone(),
            ethertype: ip_family(&server.ip),
            src_ip: Some(server.ip),
            dst_ip: Some(client.ip),
            protocol: IpProtocol::Tcp,
            src_port: server.port,
            dst_port: client.port,
            tcp_flags: Some(TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            }),
            conntrack_state: ConntrackState::Established,
            ..PacketDef::default()
        },
    ));

    // 3. ACK (client → server)
    packets.push((
        "TCP ACK".to_string(),
        PacketDef {
            ingress_interface: client.interface.clone(),
            ethertype: ip_family(&client.ip),
            src_ip: Some(client.ip),
            dst_ip: Some(server.ip),
            protocol: IpProtocol::Tcp,
            src_port: client.port,
            dst_port: server.port,
            tcp_flags: Some(TcpFlags {
                ack: true,
                ..Default::default()
            }),
            conntrack_state: ConntrackState::Established,
            ..PacketDef::default()
        },
    ));

    // 4. DATA (optional)
    if include_data {
        packets.push((
            "TCP DATA (client→server)".to_string(),
            PacketDef {
                ingress_interface: client.interface.clone(),
                ethertype: ip_family(&client.ip),
                src_ip: Some(client.ip),
                dst_ip: Some(server.ip),
                protocol: IpProtocol::Tcp,
                src_port: client.port,
                dst_port: server.port,
                tcp_flags: Some(TcpFlags {
                    ack: true,
                    psh: true,
                    ..Default::default()
                }),
                conntrack_state: ConntrackState::Established,
                ..PacketDef::default()
            },
        ));

        packets.push((
            "TCP DATA (server→client)".to_string(),
            PacketDef {
                ingress_interface: server.interface.clone(),
                ethertype: ip_family(&server.ip),
                src_ip: Some(server.ip),
                dst_ip: Some(client.ip),
                protocol: IpProtocol::Tcp,
                src_port: server.port,
                dst_port: client.port,
                tcp_flags: Some(TcpFlags {
                    ack: true,
                    psh: true,
                    ..Default::default()
                }),
                conntrack_state: ConntrackState::Established,
                ..PacketDef::default()
            },
        ));
    }

    // 5. FIN close (optional)
    if include_close {
        packets.push((
            "TCP FIN (client→server)".to_string(),
            PacketDef {
                ingress_interface: client.interface.clone(),
                ethertype: ip_family(&client.ip),
                src_ip: Some(client.ip),
                dst_ip: Some(server.ip),
                protocol: IpProtocol::Tcp,
                src_port: client.port,
                dst_port: server.port,
                tcp_flags: Some(TcpFlags {
                    fin: true,
                    ack: true,
                    ..Default::default()
                }),
                conntrack_state: ConntrackState::Established,
                ..PacketDef::default()
            },
        ));

        packets.push((
            "TCP FIN-ACK (server→client)".to_string(),
            PacketDef {
                ingress_interface: server.interface.clone(),
                ethertype: ip_family(&server.ip),
                src_ip: Some(server.ip),
                dst_ip: Some(client.ip),
                protocol: IpProtocol::Tcp,
                src_port: server.port,
                dst_port: client.port,
                tcp_flags: Some(TcpFlags {
                    fin: true,
                    ack: true,
                    ..Default::default()
                }),
                conntrack_state: ConntrackState::Established,
                ..PacketDef::default()
            },
        ));
    }

    packets
}

/// ICMP Echo Request/Reply 시퀀스
fn expand_icmp_echo(
    source: &SessionEndpoint,
    destination: &SessionEndpoint,
    ipv6: bool,
) -> Vec<(String, PacketDef)> {
    let protocol = if ipv6 {
        IpProtocol::Icmpv6
    } else {
        IpProtocol::Icmp
    };
    let (req_type, reply_type) = if ipv6 { (128, 129) } else { (8, 0) };

    vec![
        (
            "ICMP Echo Request".to_string(),
            PacketDef {
                ingress_interface: source.interface.clone(),
                ethertype: ip_family(&source.ip),
                src_ip: Some(source.ip),
                dst_ip: Some(destination.ip),
                protocol: protocol.clone(),
                icmp_type: Some(req_type),
                icmp_code: Some(0),
                conntrack_state: ConntrackState::New,
                ..PacketDef::default()
            },
        ),
        (
            "ICMP Echo Reply".to_string(),
            PacketDef {
                ingress_interface: destination.interface.clone(),
                ethertype: ip_family(&destination.ip),
                src_ip: Some(destination.ip),
                dst_ip: Some(source.ip),
                protocol,
                icmp_type: Some(reply_type),
                icmp_code: Some(0),
                conntrack_state: ConntrackState::Established,
                ..PacketDef::default()
            },
        ),
    ]
}

/// UDP 요청/응답 시퀀스
fn expand_udp_exchange(
    client: &SessionEndpoint,
    server: &SessionEndpoint,
) -> Vec<(String, PacketDef)> {
    vec![
        (
            "UDP Request".to_string(),
            PacketDef {
                ingress_interface: client.interface.clone(),
                ethertype: ip_family(&client.ip),
                src_ip: Some(client.ip),
                dst_ip: Some(server.ip),
                protocol: IpProtocol::Udp,
                src_port: client.port,
                dst_port: server.port,
                conntrack_state: ConntrackState::New,
                ..PacketDef::default()
            },
        ),
        (
            "UDP Reply".to_string(),
            PacketDef {
                ingress_interface: server.interface.clone(),
                ethertype: ip_family(&server.ip),
                src_ip: Some(server.ip),
                dst_ip: Some(client.ip),
                protocol: IpProtocol::Udp,
                src_port: server.port,
                dst_port: client.port,
                conntrack_state: ConntrackState::Established,
                ..PacketDef::default()
            },
        ),
    ]
}

fn ip_family(ip: &IpAddr) -> EtherType {
    match ip {
        IpAddr::V4(_) => EtherType::Ipv4,
        IpAddr::V6(_) => EtherType::Ipv6,
    }
}

impl Default for PacketDef {
    fn default() -> Self {
        Self {
            ingress_interface: String::new(),
            ethertype: EtherType::Ipv4,
            vlan_id: None,
            src_mac: None,
            dst_mac: None,
            src_ip: None,
            dst_ip: None,
            protocol: IpProtocol::Tcp,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            icmp_type: None,
            icmp_code: None,
            arp: None,
            packet_length: None,
            df_flag: false,
            dscp: None,
            ttl: None,
            initial_mark: 0,
            initial_ct_mark: 0,
            conntrack_state: ConntrackState::New,
        }
    }
}
