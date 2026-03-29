use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// 네트워크 인터페이스
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

    // --- 가상 인터페이스 관계 ---

    /// veth peer 인터페이스 이름 (kind=Veth인 경우)
    #[serde(default)]
    pub veth_peer: Option<String>,

    /// 브릿지 멤버 인터페이스 이름 목록 (kind=Bridge인 경우)
    #[serde(default)]
    pub bridge_members: Vec<String>,

    /// 이 인터페이스가 속한 브릿지 이름 (브릿지 멤버인 경우)
    #[serde(default)]
    pub master: Option<String>,

    /// VLAN 부모 인터페이스 이름 (kind=Vlan인 경우)
    #[serde(default)]
    pub vlan_parent: Option<String>,

    /// VLAN ID (kind=Vlan인 경우)
    #[serde(default)]
    pub vlan_id: Option<u16>,

    /// Bond 멤버 인터페이스 목록 (kind=Bond인 경우)
    #[serde(default)]
    pub bond_members: Vec<String>,
}

fn default_mtu() -> u32 {
    1500
}

impl Interface {
    /// 인터페이스가 브릿지인지
    pub fn is_bridge(&self) -> bool {
        matches!(self.kind, InterfaceKind::Bridge)
    }

    /// 인터페이스가 브릿지의 멤버인지
    pub fn is_bridge_member(&self) -> bool {
        self.master.is_some()
    }

    /// 인터페이스가 veth pair의 한 쪽인지
    pub fn is_veth(&self) -> bool {
        matches!(self.kind, InterfaceKind::Veth)
    }

    /// 인터페이스가 활성 상태인지
    pub fn is_up(&self) -> bool {
        matches!(self.state, InterfaceState::Up)
    }
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
    Bond,
    Tun,
    Tap,
    Wireguard,
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

/// 인터페이스 목록에서 이름으로 검색
pub fn find_interface<'a>(interfaces: &'a [Interface], name: &str) -> Option<&'a Interface> {
    interfaces.iter().find(|i| i.name == name)
}

/// 인터페이스의 특정 주소 패밀리에 맞는 IP 주소 반환
pub fn find_interface_ip(
    interfaces: &[Interface],
    if_name: &str,
    family_hint: Option<IpAddr>,
) -> Option<IpAddr> {
    let iface = find_interface(interfaces, if_name)?;
    if iface.addresses.is_empty() {
        return None;
    }

    if let Some(hint) = family_hint {
        let matching = iface.addresses.iter().find(|a| {
            matches!(
                (&a.ip, &hint),
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
            )
        });
        if let Some(addr) = matching {
            return Some(addr.ip);
        }
    }

    Some(iface.addresses.first()?.ip)
}
