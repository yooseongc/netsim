use serde::{Deserialize, Serialize};

/// Bridge Forwarding Database entry — maps MAC to bridge port
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FdbEntry {
    pub mac: String,
    pub port: String,
    #[serde(default)]
    pub vlan: Option<u16>,
    #[serde(default)]
    pub is_static: bool,
}
