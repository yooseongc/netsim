use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConntrackState {
    #[default]
    New,
    Established,
    Related,
    Invalid,
    Untracked,
}

impl std::fmt::Display for ConntrackState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConntrackState::New => write!(f, "new"),
            ConntrackState::Established => write!(f, "established"),
            ConntrackState::Related => write!(f, "related"),
            ConntrackState::Invalid => write!(f, "invalid"),
            ConntrackState::Untracked => write!(f, "untracked"),
        }
    }
}

/// NAT tuple stored in conntrack for established connections
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NatTuple {
    pub dnat: Option<DnatMapping>,
    pub snat: Option<SnatMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnatMapping {
    pub original_dst_ip: IpAddr,
    pub original_dst_port: Option<u16>,
    pub translated_dst_ip: IpAddr,
    pub translated_dst_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SnatMapping {
    pub original_src_ip: IpAddr,
    pub original_src_port: Option<u16>,
    pub translated_src_ip: IpAddr,
    pub translated_src_port: Option<u16>,
}

/// Conntrack entry for a connection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConntrackEntry {
    pub state: ConntrackState,
    pub nat_tuple: Option<NatTuple>,
}
