use serde::{Deserialize, Serialize};

use super::endpoint::Topology;
use super::interface::Interface;
use super::netfilter::NetfilterConfig;
use super::packet::PacketDef;
use super::policy_routing::IpRule;
use super::routing::RoutingTable;
use super::sysctl::SysctlConfig;
use super::xdp::XdpConfig;
use super::neighbor::NeighborEntry;
use super::bridge_fdb::FdbEntry;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Scenario {
    #[serde(default = "default_version")]
    pub version: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub interfaces: Vec<Interface>,
    #[serde(default)]
    pub routing_tables: Vec<RoutingTable>,
    #[serde(default)]
    pub ip_rules: Vec<IpRule>,
    #[serde(default)]
    pub netfilter: NetfilterConfig,
    #[serde(default)]
    pub xdp: XdpConfig,
    /// 커널 파라미터 (sysctl)
    #[serde(default)]
    pub sysctl: SysctlConfig,
    pub packet: PacketDef,
    /// 시뮬레이션 토폴로지 (엔드포인트 및 트래픽 흐름 정의)
    #[serde(default)]
    pub topology: Option<Topology>,
    /// ARP/Neighbor 테이블 초기 상태 (`ip neigh show`)
    #[serde(default)]
    pub neighbors: Vec<NeighborEntry>,
    /// Bridge FDB 정적 엔트리 (`bridge fdb show`)
    #[serde(default)]
    pub bridge_fdb: Vec<FdbEntry>,
}

fn default_version() -> String {
    "1.0".to_string()
}
