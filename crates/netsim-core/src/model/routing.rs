use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoutingTable {
    pub id: u32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Route {
    pub destination: IpNet,
    #[serde(default)]
    pub gateway: Option<IpAddr>,
    #[serde(default)]
    pub dev: Option<String>,
    #[serde(default)]
    pub src: Option<IpAddr>,
    #[serde(default)]
    pub metric: u32,
    #[serde(default)]
    pub scope: RouteScope,
    #[serde(default)]
    pub route_type: RouteType,
    #[serde(default)]
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RouteScope {
    #[default]
    Global,
    Link,
    Host,
    Nowhere,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RouteType {
    #[default]
    Unicast,
    Local,
    Broadcast,
    Blackhole,
    Unreachable,
    Prohibit,
    Throw,
}
