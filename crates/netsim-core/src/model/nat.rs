use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NatAction {
    Dnat {
        #[serde(default)]
        addr: Option<IpAddr>,
        #[serde(default)]
        port: Option<u16>,
    },
    Snat {
        #[serde(default)]
        addr: Option<IpAddr>,
        #[serde(default)]
        port: Option<u16>,
    },
    Masquerade {
        #[serde(default)]
        port: Option<u16>,
    },
    Redirect {
        #[serde(default)]
        port: Option<u16>,
    },
    Tproxy {
        #[serde(default)]
        addr: Option<IpAddr>,
        port: u16,
        #[serde(default)]
        mark: Option<u32>,
    },
}
