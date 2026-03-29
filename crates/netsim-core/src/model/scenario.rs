use serde::{Deserialize, Serialize};

use super::interface::Interface;
use super::netfilter::NetfilterConfig;
use super::packet::PacketDef;
use super::policy_routing::IpRule;
use super::routing::RoutingTable;
use super::xdp::XdpConfig;

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
    pub packet: PacketDef,
}

fn default_version() -> String {
    "1.0".to_string()
}
