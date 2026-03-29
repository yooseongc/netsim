use serde::{Deserialize, Serialize};

use super::nat::NatAction;

/// 통합 Netfilter 설정 (nftables + iptables)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NetfilterConfig {
    #[serde(default)]
    pub nftables: Option<NftablesRuleset>,
    #[serde(default)]
    pub iptables: Option<IptablesRuleset>,
}

// --- nftables ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NftablesRuleset {
    #[serde(default)]
    pub tables: Vec<NfTable>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NfTable {
    pub family: NfFamily,
    pub name: String,
    #[serde(default)]
    pub chains: Vec<NfChain>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NfFamily {
    Ip,
    Ip6,
    Inet,
    Bridge,
    Arp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NfChain {
    pub name: String,
    #[serde(default)]
    pub chain_type: Option<NfChainType>,
    #[serde(default)]
    pub hook: Option<NfHook>,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub policy: Option<NfVerdict>,
    #[serde(default)]
    pub rules: Vec<NfRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NfChainType {
    Filter,
    Nat,
    Route,
    Mangle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum NfHook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NfRule {
    #[serde(default)]
    pub handle: Option<u64>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub matches: Vec<NfMatch>,
    pub action: NfAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NfMatch {
    /// IP layer match (src/dst addr, version)
    Ip {
        field: IpField,
        op: MatchOp,
        value: String,
    },
    /// Transport layer match (TCP/UDP port, flags)
    Transport {
        protocol: TransportProto,
        field: TransportField,
        op: MatchOp,
        value: String,
    },
    /// Input interface match
    Iif { name: String },
    /// Output interface match
    Oif { name: String },
    /// Meta match (mark, protocol, length, etc.)
    Meta {
        key: MetaKey,
        op: MatchOp,
        value: String,
    },
    /// Conntrack match
    Ct {
        key: CtKey,
        op: MatchOp,
        value: String,
    },
    /// Packet mark match
    Mark {
        op: MatchOp,
        value: u32,
        #[serde(default)]
        mask: Option<u32>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IpField {
    Saddr,
    Daddr,
    Protocol,
    Version,
    Length,
    Dscp,
    Ttl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransportProto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransportField {
    Sport,
    Dport,
    /// TCP flags (syn, ack, fin, rst, psh, urg)
    Flags,
    /// ICMP/ICMPv6 type
    #[serde(rename = "icmp_type")]
    IcmpType,
    /// ICMP/ICMPv6 code
    #[serde(rename = "icmp_code")]
    IcmpCode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MatchOp {
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
    In,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MetaKey {
    Mark,
    Protocol,
    Length,
    Iifname,
    Oifname,
    Skuid,
    Nfproto,
    L4proto,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CtKey {
    State,
    Mark,
    Status,
    Direction,
    Expiration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NfAction {
    Verdict { verdict: NfVerdict },
    Nat(NatAction),
    SetMark { value: u32, #[serde(default)] mask: Option<u32> },
    Log { #[serde(default)] prefix: Option<String>, #[serde(default)] level: Option<u8> },
    Counter,
    Jump { target: String },
    Goto { target: String },
    Return,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NfVerdict {
    Accept,
    Drop,
    Reject,
    Queue,
    Continue,
}

// --- iptables ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct IptablesRuleset {
    #[serde(default)]
    pub tables: Vec<IptablesTable>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IptablesTable {
    pub name: String,
    #[serde(default)]
    pub chains: Vec<IptablesChain>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IptablesChain {
    pub name: String,
    #[serde(default)]
    pub policy: Option<NfVerdict>,
    #[serde(default)]
    pub rules: Vec<NfRule>,
}

impl IptablesTable {
    /// iptables 테이블의 기본 hook priority 반환
    pub fn default_priority(&self, hook: &NfHook) -> i32 {
        match (self.name.as_str(), hook) {
            ("raw", _) => -300,
            ("mangle", _) => -150,
            ("nat", NfHook::Prerouting) => -100,
            ("nat", NfHook::Postrouting) => 100,
            ("nat", NfHook::Output) => -100,
            ("filter", _) => 0,
            _ => 0,
        }
    }
}
