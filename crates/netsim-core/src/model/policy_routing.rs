use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IpRule {
    pub priority: u32,
    #[serde(default)]
    pub selector: RuleSelector,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RuleSelector {
    #[serde(default)]
    pub from: Option<IpNet>,
    #[serde(default)]
    pub to: Option<IpNet>,
    #[serde(default)]
    pub fwmark: Option<u32>,
    #[serde(default)]
    pub fwmask: Option<u32>,
    #[serde(default)]
    pub iif: Option<String>,
    #[serde(default)]
    pub oif: Option<String>,
    #[serde(default)]
    pub tos: Option<u8>,
    #[serde(default)]
    pub ipproto: Option<u8>,
    #[serde(default)]
    pub sport: Option<PortRange>,
    #[serde(default)]
    pub dport: Option<PortRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Lookup(u32),
    Blackhole,
    Unreachable,
    Prohibit,
}
