//! `ip addr show` 출력 파서
//!
//! 리눅스 `ip addr show` 명령어의 출력을 파싱하여 `Vec<Interface>`로 변환한다.

use std::net::IpAddr;

use netsim_core::model::{
    AddressScope, Interface, InterfaceAddress, InterfaceKind, InterfaceState,
};
use regex::Regex;

use crate::validation::{ParseResult, ValidationReport};

/// `ip addr show` 출력을 파싱하여 `Vec<Interface>`를 반환한다.
pub fn parse_ip_addr(input: &str) -> ParseResult<Vec<Interface>> {
    let mut interfaces = Vec::new();
    let mut report = ValidationReport::new();

    // 인터페이스 헤더 라인 정규식:
    // "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN ..."
    let header_re = Regex::new(
        r"^(\d+):\s+(\S+?)(@\S+)?:\s+<([^>]*)>\s+mtu\s+(\d+).*?state\s+(\S+)"
    ).unwrap();

    // master 감지 (예: "master br0")
    let master_re = Regex::new(r"\bmaster\s+(\S+)").unwrap();

    // link/ether 라인
    let mac_re = Regex::new(
        r"^\s+link/ether\s+([0-9a-fA-F:]+)"
    ).unwrap();

    // inet 주소 라인: "inet 10.0.0.1/24 brd ... scope global eth0"
    let inet_re = Regex::new(
        r"^\s+inet\s+(\S+?)(?:/(\d+))?\s+.*?scope\s+(\S+)"
    ).unwrap();

    // inet6 주소 라인: "inet6 ::1/128 scope host"
    let inet6_re = Regex::new(
        r"^\s+inet6\s+(\S+?)(?:/(\d+))?\s+scope\s+(\S+)"
    ).unwrap();

    let lines: Vec<&str> = input.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        if let Some(caps) = header_re.captures(line) {
            let index: u32 = caps[1].parse().unwrap_or(0);
            let raw_name = caps[2].to_string();
            let peer_suffix = caps.get(3).map(|m| m.as_str().to_string());
            let flags_str = &caps[4];
            let mtu: u32 = caps[5].parse().unwrap_or(1500);
            let state_str = &caps[6];

            // 이름에서 @peer 제거
            let name = raw_name.clone();

            // 플래그 파싱
            let flags: Vec<&str> = flags_str.split(',').collect();
            let state = if flags.contains(&"UP") || state_str == "UP" {
                InterfaceState::Up
            } else {
                InterfaceState::Down
            };

            // master 감지
            let master = master_re.captures(line).map(|c| c[1].to_string());

            // 인터페이스 종류 감지
            let kind = detect_interface_kind(&name, flags_str, &peer_suffix);

            // veth peer 감지 (name@peer 형식)
            let veth_peer = if matches!(kind, InterfaceKind::Veth) {
                peer_suffix.as_ref().map(|p| p.trim_start_matches('@').to_string())
            } else {
                None
            };

            // VLAN 감지 (name.id@parent 형식)
            let (vlan_parent, vlan_id) = if matches!(kind, InterfaceKind::Vlan) {
                parse_vlan_info(&name, &peer_suffix)
            } else {
                (None, None)
            };

            let mut mac = None;
            let mut addresses = Vec::new();

            // 다음 라인들 파싱 (들여쓰기된 라인)
            i += 1;
            while i < lines.len() {
                let sub_line = lines[i];

                // 새 인터페이스 시작이면 중단
                if !sub_line.is_empty() && !sub_line.starts_with(' ') && !sub_line.starts_with('\t') {
                    break;
                }

                if let Some(caps) = mac_re.captures(sub_line) {
                    mac = Some(caps[1].to_string());
                } else if let Some(caps) = inet_re.captures(sub_line) {
                    if let Ok(ip) = caps[1].parse::<IpAddr>() {
                        let prefix_len: u8 = caps.get(2)
                            .and_then(|m| m.as_str().parse().ok())
                            .unwrap_or(32);
                        let scope = parse_scope(&caps[3]);
                        addresses.push(InterfaceAddress {
                            ip,
                            prefix_len,
                            scope,
                        });
                    }
                } else if let Some(caps) = inet6_re.captures(sub_line) {
                    if let Ok(ip) = caps[1].parse::<IpAddr>() {
                        let prefix_len: u8 = caps.get(2)
                            .and_then(|m| m.as_str().parse().ok())
                            .unwrap_or(128);
                        let scope = parse_scope(&caps[3]);
                        addresses.push(InterfaceAddress {
                            ip,
                            prefix_len,
                            scope,
                        });
                    }
                }

                i += 1;
            }

            let iface = Interface {
                name,
                index,
                mac,
                addresses,
                mtu,
                state,
                kind,
                veth_peer,
                bridge_members: Vec::new(),
                master,
                vlan_parent,
                vlan_id,
                bond_members: Vec::new(),
            };

            report.add_ok(format!("Parsed interface {}", &iface.name));
            interfaces.push(iface);
        } else {
            // 헤더로 인식되지 않는 라인은 건너뜀
            i += 1;
        }
    }

    // 브릿지 멤버 관계 구축: master 필드가 설정된 인터페이스의 이름을 해당 브릿지의 bridge_members에 추가
    let member_map: Vec<(String, String)> = interfaces
        .iter()
        .filter_map(|iface| {
            iface.master.as_ref().map(|m| (m.clone(), iface.name.clone()))
        })
        .collect();

    for (bridge_name, member_name) in member_map {
        if let Some(bridge) = interfaces.iter_mut().find(|i| i.name == bridge_name) {
            bridge.bridge_members.push(member_name);
        }
    }

    report.add_ok(format!("Total {} interfaces parsed", interfaces.len()));

    ParseResult {
        data: interfaces,
        report,
    }
}

fn detect_interface_kind(name: &str, flags: &str, peer_suffix: &Option<String>) -> InterfaceKind {
    if flags.contains("LOOPBACK") {
        return InterfaceKind::Loopback;
    }

    // VLAN: name contains '.' and has @parent (e.g., eth0.100@eth0)
    if name.contains('.') && peer_suffix.is_some() {
        // Check if the part after '.' is numeric
        if let Some(dot_pos) = name.rfind('.') {
            if name[dot_pos + 1..].parse::<u16>().is_ok() {
                return InterfaceKind::Vlan;
            }
        }
    }

    // Veth: name starts with "veth" or has @ifN peer suffix
    if name.starts_with("veth") {
        return InterfaceKind::Veth;
    }
    if let Some(suffix) = peer_suffix {
        let peer = suffix.trim_start_matches('@');
        if peer.starts_with("if") && peer[2..].parse::<u32>().is_ok() {
            return InterfaceKind::Veth;
        }
    }

    // Bridge: name starts with "br" or "docker" or "virbr"
    if name.starts_with("br") || name.starts_with("docker") || name.starts_with("virbr") {
        return InterfaceKind::Bridge;
    }

    // Bond: name starts with "bond"
    if name.starts_with("bond") {
        return InterfaceKind::Bond;
    }

    // Tun/Tap
    if name.starts_with("tun") {
        return InterfaceKind::Tun;
    }
    if name.starts_with("tap") {
        return InterfaceKind::Tap;
    }

    // Wireguard
    if name.starts_with("wg") {
        return InterfaceKind::Wireguard;
    }

    InterfaceKind::Physical
}

fn parse_vlan_info(name: &str, peer_suffix: &Option<String>) -> (Option<String>, Option<u16>) {
    // Format: eth0.100@eth0 -> parent=eth0, id=100
    if let Some(dot_pos) = name.rfind('.') {
        if let Ok(id) = name[dot_pos + 1..].parse::<u16>() {
            let parent = peer_suffix
                .as_ref()
                .map(|p| p.trim_start_matches('@').to_string())
                .unwrap_or_else(|| name[..dot_pos].to_string());
            return (Some(parent), Some(id));
        }
    }
    (None, None)
}

fn parse_scope(s: &str) -> AddressScope {
    match s {
        "host" => AddressScope::Host,
        "link" => AddressScope::Link,
        _ => AddressScope::Global,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const SAMPLE_INPUT: &str = r#"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.1/24 brd 10.0.0.255 scope global eth0
       valid_lft forever preferred_lft forever
3: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.1/24 scope global br0
4: veth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br0 state UP group default qlen 1000
    link/ether 11:22:33:44:55:66 brd ff:ff:ff:ff:ff:ff link-netnsid 0
5: eth0.100@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
    inet 172.16.0.1/24 scope global eth0.100"#;

    #[test]
    fn test_parse_ip_addr_count() {
        let result = parse_ip_addr(SAMPLE_INPUT);
        assert_eq!(result.data.len(), 5);
    }

    #[test]
    fn test_parse_loopback() {
        let result = parse_ip_addr(SAMPLE_INPUT);
        let lo = &result.data[0];
        assert_eq!(lo.name, "lo");
        assert_eq!(lo.index, 1);
        assert_eq!(lo.mtu, 65536);
        assert_eq!(lo.kind, InterfaceKind::Loopback);
        assert_eq!(lo.addresses.len(), 2);
        assert_eq!(lo.addresses[0].ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(lo.addresses[0].prefix_len, 8);
        assert_eq!(lo.addresses[0].scope, AddressScope::Host);
        assert_eq!(lo.addresses[1].ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(lo.addresses[1].prefix_len, 128);
    }

    #[test]
    fn test_parse_eth0() {
        let result = parse_ip_addr(SAMPLE_INPUT);
        let eth0 = &result.data[1];
        assert_eq!(eth0.name, "eth0");
        assert_eq!(eth0.index, 2);
        assert_eq!(eth0.mtu, 1500);
        assert_eq!(eth0.state, InterfaceState::Up);
        assert_eq!(eth0.kind, InterfaceKind::Physical);
        assert_eq!(eth0.mac, Some("00:11:22:33:44:55".to_string()));
        assert_eq!(eth0.addresses.len(), 1);
        assert_eq!(eth0.addresses[0].ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(eth0.addresses[0].prefix_len, 24);
        assert_eq!(eth0.addresses[0].scope, AddressScope::Global);
    }

    #[test]
    fn test_parse_bridge() {
        let result = parse_ip_addr(SAMPLE_INPUT);
        let br0 = &result.data[2];
        assert_eq!(br0.name, "br0");
        assert_eq!(br0.kind, InterfaceKind::Bridge);
        // veth0 should be listed as a bridge member
        assert!(br0.bridge_members.contains(&"veth0".to_string()));
    }

    #[test]
    fn test_parse_veth() {
        let result = parse_ip_addr(SAMPLE_INPUT);
        let veth0 = &result.data[3];
        assert_eq!(veth0.name, "veth0");
        assert_eq!(veth0.kind, InterfaceKind::Veth);
        assert_eq!(veth0.master, Some("br0".to_string()));
        assert_eq!(veth0.veth_peer, Some("if5".to_string()));
    }

    #[test]
    fn test_parse_vlan() {
        let result = parse_ip_addr(SAMPLE_INPUT);
        let vlan = &result.data[4];
        assert_eq!(vlan.name, "eth0.100");
        assert_eq!(vlan.kind, InterfaceKind::Vlan);
        assert_eq!(vlan.vlan_id, Some(100));
        assert_eq!(vlan.vlan_parent, Some("eth0".to_string()));
        assert_eq!(vlan.addresses.len(), 1);
        assert_eq!(vlan.addresses[0].ip, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
    }

    #[test]
    fn test_empty_input() {
        let result = parse_ip_addr("");
        assert!(result.data.is_empty());
    }
}
