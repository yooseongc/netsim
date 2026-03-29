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

    // --- L3 fields (IP) ---
    /// Source IP. Required for IP packets, optional for L2-only (ARP, STP).
    #[serde(default)]
    pub src_ip: Option<IpAddr>,
    /// Destination IP. Required for IP packets, optional for L2-only.
    #[serde(default)]
    pub dst_ip: Option<IpAddr>,
    #[serde(default)]
    pub protocol: IpProtocol,

    // --- L4 fields (TCP/UDP) ---
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    #[serde(default)]
    pub tcp_flags: Option<TcpFlags>,

    // --- L4 fields (ICMP/ICMPv6) ---
    /// ICMP/ICMPv6 type (e.g., 8=echo request, 0=echo reply)
    #[serde(default)]
    pub icmp_type: Option<u8>,
    /// ICMP/ICMPv6 code
    #[serde(default)]
    pub icmp_code: Option<u8>,

    // --- ARP fields ---
    #[serde(default)]
    pub arp: Option<ArpFields>,

    // --- Common fields ---
    #[serde(default)]
    pub packet_length: Option<u32>,
    /// Don't Fragment flag (IPv4)
    #[serde(default)]
    pub df_flag: bool,
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

/// ARP 패킷의 추가 필드
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArpFields {
    /// ARP operation: 1=request, 2=reply, 3=RARP request, 4=RARP reply
    pub operation: u16,
    #[serde(default)]
    pub sender_mac: Option<String>,
    #[serde(default)]
    pub sender_ip: Option<IpAddr>,
    #[serde(default)]
    pub target_mac: Option<String>,
    #[serde(default)]
    pub target_ip: Option<IpAddr>,
}

/// 파이프라인 통과 중 변경되는 가변 패킷 상태
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PacketState {
    pub ethertype: EtherType,
    pub vlan_id: Option<u16>,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
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
    /// ICMP type (carried through pipeline, not changed by NAT)
    pub icmp_type: Option<u8>,
    /// ICMP code
    pub icmp_code: Option<u8>,
    /// TCP flags (carried through pipeline)
    pub tcp_flags: Option<TcpFlags>,
    /// ARP operation (for L2 ARP packets)
    pub arp_op: Option<u16>,
    /// Packet length (bytes)
    pub packet_length: Option<u32>,
    /// Don't Fragment flag
    pub df_flag: bool,
    pub dnat_applied: bool,
    pub snat_applied: bool,
    /// TPROXY가 적용되었는지 (패킷이 stolen이 아닌 로컬 전달 경로를 따름)
    pub tproxy_applied: bool,
    pub original_dst_ip: Option<IpAddr>,
    pub original_dst_port: Option<u16>,
    pub original_src_ip: Option<IpAddr>,
    pub original_src_port: Option<u16>,
}

impl PacketState {
    /// L4 식별자를 프로토콜별로 반환
    pub fn l4_id_string(&self) -> String {
        let src = self.src_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "?".into());
        let dst = self.dst_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "?".into());
        match self.protocol {
            IpProtocol::Tcp | IpProtocol::Udp | IpProtocol::Sctp => {
                format!("{}:{} -> {}:{}",
                    src,
                    self.src_port.map(|p| p.to_string()).unwrap_or_default(),
                    dst,
                    self.dst_port.map(|p| p.to_string()).unwrap_or_default(),
                )
            }
            IpProtocol::Icmp | IpProtocol::Icmpv6 => {
                format!("{} -> {} type={} code={}",
                    src, dst,
                    self.icmp_type.unwrap_or(0),
                    self.icmp_code.unwrap_or(0),
                )
            }
            _ => {
                format!("{} -> {} {}", src, dst, self.protocol)
            }
        }
    }

    /// 프로토콜이 포트를 가지는지 여부
    pub fn has_ports(&self) -> bool {
        self.protocol.has_ports()
    }
}

impl PacketState {
    pub fn from_packet_def(def: &PacketDef) -> Self {
        Self {
            ethertype: def.ethertype.clone(),
            vlan_id: def.vlan_id,
            src_mac: def.src_mac.clone(),
            dst_mac: def.dst_mac.clone(),
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
            icmp_type: def.icmp_type,
            icmp_code: def.icmp_code,
            tcp_flags: def.tcp_flags.clone(),
            arp_op: def.arp.as_ref().map(|a| a.operation),
            packet_length: def.packet_length,
            df_flag: def.df_flag,
            dnat_applied: false,
            snat_applied: false,
            tproxy_applied: false,
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
    /// IEEE 802.1D Spanning Tree Protocol (BPDU via LLC)
    Stp,
    /// Link Layer Discovery Protocol
    Lldp,
    Other(u16),
}

impl std::fmt::Display for EtherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EtherType::Ipv4 => write!(f, "IPv4"),
            EtherType::Ipv6 => write!(f, "IPv6"),
            EtherType::Arp => write!(f, "ARP"),
            EtherType::Vlan => write!(f, "802.1Q"),
            EtherType::Stp => write!(f, "STP"),
            EtherType::Lldp => write!(f, "LLDP"),
            EtherType::Other(v) => write!(f, "0x{:04x}", v),
        }
    }
}

impl EtherType {
    /// L3 처리가 필요한 프레임인지 (IP 기반)
    pub fn is_ip(&self) -> bool {
        matches!(self, EtherType::Ipv4 | EtherType::Ipv6)
    }

    /// L2 전용 프로토콜인지 (IP 스택을 타지 않음)
    pub fn is_l2_only(&self) -> bool {
        matches!(self, EtherType::Arp | EtherType::Stp | EtherType::Lldp)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpProtocol {
    #[default]
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    /// VRRP (IP protocol 112)
    Vrrp,
    /// OSPF (IP protocol 89)
    Ospf,
    /// GRE (IP protocol 47)
    Gre,
    /// ESP (IP protocol 50) — IPsec
    Esp,
    /// AH (IP protocol 51) — IPsec
    Ah,
    /// SCTP (IP protocol 132)
    Sctp,
    Other(u8),
}

impl IpProtocol {
    /// IP 프로토콜 번호 반환
    pub fn protocol_number(&self) -> u8 {
        match self {
            IpProtocol::Icmp => 1,
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Gre => 47,
            IpProtocol::Esp => 50,
            IpProtocol::Ah => 51,
            IpProtocol::Ospf => 89,
            IpProtocol::Vrrp => 112,
            IpProtocol::Sctp => 132,
            IpProtocol::Icmpv6 => 58,
            IpProtocol::Other(n) => *n,
        }
    }

    /// 포트 기반 프로토콜인지
    pub fn has_ports(&self) -> bool {
        matches!(self, IpProtocol::Tcp | IpProtocol::Udp | IpProtocol::Sctp)
    }

    /// ICMP 계열인지
    pub fn is_icmp(&self) -> bool {
        matches!(self, IpProtocol::Icmp | IpProtocol::Icmpv6)
    }
}

impl std::fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpProtocol::Tcp => write!(f, "tcp"),
            IpProtocol::Udp => write!(f, "udp"),
            IpProtocol::Icmp => write!(f, "icmp"),
            IpProtocol::Icmpv6 => write!(f, "icmpv6"),
            IpProtocol::Vrrp => write!(f, "vrrp"),
            IpProtocol::Ospf => write!(f, "ospf"),
            IpProtocol::Gre => write!(f, "gre"),
            IpProtocol::Esp => write!(f, "esp"),
            IpProtocol::Ah => write!(f, "ah"),
            IpProtocol::Sctp => write!(f, "sctp"),
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
