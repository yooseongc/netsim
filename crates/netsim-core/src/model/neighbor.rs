use std::net::IpAddr;
use serde::{Deserialize, Serialize};

/// ARP/Neighbor table entry state (like `ip neigh show` output)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NeighborState {
    Permanent,
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
    Incomplete,
}

impl Default for NeighborState {
    fn default() -> Self {
        NeighborState::Permanent
    }
}

/// ARP/Neighbor table entry — maps IP to MAC on a specific interface
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NeighborEntry {
    pub ip: IpAddr,
    pub mac: String,
    pub interface: String,
    #[serde(default)]
    pub state: NeighborState,
}
