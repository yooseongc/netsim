use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// 시뮬레이션 참여자의 역할
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRole {
    /// 시뮬레이션 호스트에서 외부로 요청 발신 (OUTPUT → routing → POSTROUTING)
    LocalClient,
    /// 외부에서 시뮬레이션 호스트로 요청 수신 (ingress → PREROUTING → routing → INPUT)
    RemoteClient,
    /// 시뮬레이션 호스트의 로컬 서비스 (로컬 수신 → OUTPUT 응답)
    LocalServer,
    /// 외부 서비스 (포워딩 대상)
    RemoteServer,
    /// 일반 프록시 (DNAT → INPUT → application → OUTPUT → POSTROUTING)
    LocalProxy,
    /// 투명 프록시 (TPROXY → INPUT → application → OUTPUT → original dst)
    LocalTProxy,
}

/// 시뮬레이션 엔드포인트 정의
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Endpoint {
    pub role: EndpointRole,
    pub name: String,
    pub ip: IpAddr,
    #[serde(default)]
    pub port: Option<u16>,
    /// 이 엔드포인트가 연결된 인터페이스 (LocalClient/LocalServer: 없음, RemoteClient/RemoteServer: ingress/egress)
    #[serde(default)]
    pub interface: Option<String>,
}

/// 시뮬레이션 흐름 정의 — 엔드포인트 간 통신 경로
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrafficFlow {
    pub name: String,
    pub source: String,      // endpoint name
    pub destination: String,  // endpoint name
    #[serde(default)]
    pub protocol: Option<String>,  // tcp, udp, icmp
    #[serde(default)]
    pub description: Option<String>,
}

/// 시뮬레이션 토폴로지 — 엔드포인트들과 트래픽 흐름
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Topology {
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub flows: Vec<TrafficFlow>,
}
