use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::conntrack::ConntrackState;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PacketDef {
    pub ingress_interface: String,
    #[serde(default)]
    pub ethertype: EtherType,
    #[serde(default)]
    pub vlan_id: Option<u16>,
    #[serde(default)]
    pub src_mac: Option<String>,
    #[serde(default)]
    pub dst_mac: Option<String>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    #[serde(default)]
    pub protocol: IpProtocol,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    #[serde(default)]
    pub tcp_flags: Option<TcpFlags>,
    #[serde(default)]
    pub packet_length: Option<u32>,
    #[serde(default)]
    pub dscp: Option<u8>,
    #[serde(default)]
    pub ttl: Option<u8>,
    #[serde(default)]
    pub initial_mark: u32,
    #[serde(default)]
    pub initial_ct_mark: u32,
    #[serde(default)]
    pub conntrack_state: ConntrackState,
}

/// 파이프라인 통과 중 변경되는 가변 패킷 상태
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PacketState {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: IpProtocol,
    pub mark: u32,
    pub ct_mark: u32,
    pub ct_state: ConntrackState,
    pub ingress_if: String,
    pub egress_if: Option<String>,
    pub ttl: u8,
    pub dscp: u8,
    pub dnat_applied: bool,
    pub snat_applied: bool,
    pub original_dst_ip: Option<IpAddr>,
    pub original_dst_port: Option<u16>,
    pub original_src_ip: Option<IpAddr>,
    pub original_src_port: Option<u16>,
}

impl PacketState {
    pub fn from_packet_def(def: &PacketDef) -> Self {
        Self {
            src_ip: def.src_ip,
            dst_ip: def.dst_ip,
            src_port: def.src_port,
            dst_port: def.dst_port,
            protocol: def.protocol.clone(),
            mark: def.initial_mark,
            ct_mark: def.initial_ct_mark,
            ct_state: def.conntrack_state.clone(),
            ingress_if: def.ingress_interface.clone(),
            egress_if: None,
            ttl: def.ttl.unwrap_or(64),
            dscp: def.dscp.unwrap_or(0),
            dnat_applied: false,
            snat_applied: false,
            original_dst_ip: None,
            original_dst_port: None,
            original_src_ip: None,
            original_src_port: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum EtherType {
    #[default]
    Ipv4,
    Ipv6,
    Arp,
    Vlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpProtocol {
    #[default]
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

impl std::fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpProtocol::Tcp => write!(f, "tcp"),
            IpProtocol::Udp => write!(f, "udp"),
            IpProtocol::Icmp => write!(f, "icmp"),
            IpProtocol::Icmpv6 => write!(f, "icmpv6"),
            IpProtocol::Other(n) => write!(f, "proto:{}", n),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TcpFlags {
    #[serde(default)]
    pub syn: bool,
    #[serde(default)]
    pub ack: bool,
    #[serde(default)]
    pub fin: bool,
    #[serde(default)]
    pub rst: bool,
    #[serde(default)]
    pub psh: bool,
    #[serde(default)]
    pub urg: bool,
}
