use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub addresses: Vec<InterfaceAddress>,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    #[serde(default)]
    pub state: InterfaceState,
    #[serde(default)]
    pub kind: InterfaceKind,
}

fn default_mtu() -> u32 {
    1500
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InterfaceAddress {
    pub ip: IpAddr,
    pub prefix_len: u8,
    #[serde(default)]
    pub scope: AddressScope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceState {
    #[default]
    Up,
    Down,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceKind {
    Loopback,
    #[default]
    Physical,
    Veth,
    Bridge,
    Vlan,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AddressScope {
    #[default]
    Global,
    Link,
    Host,
}
