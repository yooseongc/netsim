//! 공유 룰 매칭 로직
//!
//! NfMatch 조건을 PacketState에 대해 평가한다.
//! 프로토콜별 L4 동작 차이를 충실히 반영:
//! - TCP/UDP/SCTP: 포트 기반 매칭
//! - ICMP/ICMPv6: type/code 기반 매칭 (포트 없음)
//! - VRRP/OSPF/GRE 등: L4 필드 없음, IP 레벨 매칭만
//! - ARP/STP: L2 전용, IP 매칭 불가

use std::net::IpAddr;

use ipnet::IpNet;

use crate::model::netfilter::{
    CtKey, IpField, MatchOp, MetaKey, NfMatch, TransportField, TransportProto,
};
use crate::model::packet::{IpProtocol, PacketState};

/// 단일 NfMatch 조건을 PacketState에 대해 평가
pub fn evaluate_match(m: &NfMatch, state: &PacketState) -> bool {
    match m {
        NfMatch::Ip { field, op, value } => match_ip(field, op, value, state),
        NfMatch::Transport {
            protocol,
            field,
            op,
            value,
        } => match_transport(protocol, field, op, value, state),
        NfMatch::Iif { name } => state.ingress_if == *name,
        NfMatch::Oif { name } => state.egress_if.as_deref() == Some(name.as_str()),
        NfMatch::Meta { key, op, value } => match_meta(key, op, value, state),
        NfMatch::Ct { key, op, value } => match_ct(key, op, value, state),
        NfMatch::Mark { op, value, mask } => {
            let pkt_mark = match mask {
                Some(m) => state.mark & m,
                None => state.mark,
            };
            compare_u32(op, pkt_mark, *value)
        }
    }
}

/// 모든 match 조건이 충족되는지 평가 (AND 결합)
pub fn evaluate_matches(matches: &[NfMatch], state: &PacketState) -> bool {
    matches.iter().all(|m| evaluate_match(m, state))
}

// --- IP layer matching ---

fn match_ip(field: &IpField, op: &MatchOp, value: &str, state: &PacketState) -> bool {
    match field {
        IpField::Saddr => match_ip_addr(op, value, state.src_ip),
        IpField::Daddr => match_ip_addr(op, value, state.dst_ip),
        IpField::Protocol => {
            let proto_str = state.protocol.to_string();
            compare_str(op, &proto_str, value)
        }
        IpField::Version => {
            let ver = match (state.src_ip, state.dst_ip) {
                (Some(IpAddr::V4(_)), _) | (_, Some(IpAddr::V4(_))) => "4",
                (Some(IpAddr::V6(_)), _) | (_, Some(IpAddr::V6(_))) => "6",
                _ => "0",
            };
            compare_str(op, ver, value)
        }
        IpField::Dscp => {
            if let Ok(v) = value.parse::<u8>() {
                compare_u32(op, state.dscp as u32, v as u32)
            } else {
                false
            }
        }
        IpField::Ttl => {
            if let Ok(v) = value.parse::<u8>() {
                compare_u32(op, state.ttl as u32, v as u32)
            } else {
                false
            }
        }
        IpField::Length => false, // 패킷 길이는 PacketState에 없음 (향후 추가 가능)
    }
}

fn match_ip_addr(op: &MatchOp, value: &str, addr: Option<IpAddr>) -> bool {
    let addr = match addr {
        Some(a) => a,
        None => return false, // L2-only 패킷은 IP 매칭 실패
    };

    // value가 네트워크 CIDR 표기인 경우
    if let Ok(net) = value.parse::<IpNet>() {
        return match op {
            MatchOp::Eq => net.contains(&addr),
            MatchOp::Neq => !net.contains(&addr),
            _ => false,
        };
    }

    // value가 단일 IP인 경우
    if let Ok(target) = value.parse::<IpAddr>() {
        return match op {
            MatchOp::Eq => addr == target,
            MatchOp::Neq => addr != target,
            _ => false,
        };
    }

    // comma-separated list (nftables set)
    if matches!(op, MatchOp::In) {
        return value
            .split(',')
            .map(|s| s.trim())
            .any(|s| {
                if let Ok(net) = s.parse::<IpNet>() {
                    net.contains(&addr)
                } else if let Ok(ip) = s.parse::<IpAddr>() {
                    addr == ip
                } else {
                    false
                }
            });
    }

    false
}

// --- Transport layer matching ---
// TCP/UDP: sport, dport, flags
// ICMP/ICMPv6: icmp_type, icmp_code (sport/dport는 의미 없음)

fn match_transport(
    protocol: &TransportProto,
    field: &TransportField,
    op: &MatchOp,
    value: &str,
    state: &PacketState,
) -> bool {
    // 프로토콜이 일치해야 transport 매칭 가능
    if !transport_proto_matches(protocol, &state.protocol) {
        return false;
    }

    match field {
        TransportField::Sport => {
            // TCP/UDP/SCTP만 포트 있음. ICMP에서는 항상 false.
            if state.protocol.is_icmp() {
                return false;
            }
            match state.src_port {
                Some(port) => match_port(op, value, port),
                None => false,
            }
        }
        TransportField::Dport => {
            if state.protocol.is_icmp() {
                return false;
            }
            match state.dst_port {
                Some(port) => match_port(op, value, port),
                None => false,
            }
        }
        TransportField::Flags => {
            // TCP flags만 적용
            if !matches!(state.protocol, IpProtocol::Tcp) {
                return false;
            }
            match &state.tcp_flags {
                Some(flags) => match_tcp_flags(op, value, flags),
                None => false,
            }
        }
        TransportField::IcmpType => {
            // ICMP/ICMPv6만 적용
            if !state.protocol.is_icmp() {
                return false;
            }
            match state.icmp_type {
                Some(t) => {
                    if let Ok(v) = value.parse::<u8>() {
                        compare_u32(op, t as u32, v as u32)
                    } else {
                        // 이름 기반 매칭 (echo-request, echo-reply 등)
                        match_icmp_type_name(op, value, t, &state.protocol)
                    }
                }
                None => false,
            }
        }
        TransportField::IcmpCode => {
            if !state.protocol.is_icmp() {
                return false;
            }
            match state.icmp_code {
                Some(c) => {
                    if let Ok(v) = value.parse::<u8>() {
                        compare_u32(op, c as u32, v as u32)
                    } else {
                        false
                    }
                }
                None => false,
            }
        }
    }
}

fn transport_proto_matches(expected: &TransportProto, actual: &IpProtocol) -> bool {
    match expected {
        TransportProto::Tcp => matches!(actual, IpProtocol::Tcp),
        TransportProto::Udp => matches!(actual, IpProtocol::Udp),
        TransportProto::Icmp => matches!(actual, IpProtocol::Icmp),
        TransportProto::Icmpv6 => matches!(actual, IpProtocol::Icmpv6),
    }
}

fn match_port(op: &MatchOp, value: &str, port: u16) -> bool {
    // range 표기 (e.g., "1024-65535")
    if let Some((start, end)) = value.split_once('-') {
        if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
            return match op {
                MatchOp::Eq | MatchOp::In => port >= s && port <= e,
                MatchOp::Neq => port < s || port > e,
                _ => false,
            };
        }
    }

    // comma-separated set
    if matches!(op, MatchOp::In) || value.contains(',') {
        return value
            .split(',')
            .map(|s| s.trim())
            .any(|s| s.parse::<u16>().map(|v| v == port).unwrap_or(false));
    }

    // 단일 값
    if let Ok(v) = value.parse::<u16>() {
        compare_u32(op, port as u32, v as u32)
    } else {
        false
    }
}

fn match_tcp_flags(
    op: &MatchOp,
    value: &str,
    flags: &crate::model::packet::TcpFlags,
) -> bool {
    // value: "syn", "syn,ack", "syn & syn,ack" 등
    let flag_names: Vec<&str> = value.split(',').map(|s| s.trim().to_ascii_lowercase().leak() as &str).collect();

    let has_all = flag_names.iter().all(|name| match *name {
        "syn" => flags.syn,
        "ack" => flags.ack,
        "fin" => flags.fin,
        "rst" => flags.rst,
        "psh" => flags.psh,
        "urg" => flags.urg,
        _ => false,
    });

    match op {
        MatchOp::Eq | MatchOp::In => has_all,
        MatchOp::Neq => !has_all,
        _ => false,
    }
}

/// ICMP type 이름 매칭 (nftables에서 사용하는 이름)
fn match_icmp_type_name(op: &MatchOp, name: &str, actual_type: u8, protocol: &IpProtocol) -> bool {
    let expected = match protocol {
        IpProtocol::Icmp => match name.to_lowercase().as_str() {
            "echo-reply" => Some(0),
            "destination-unreachable" => Some(3),
            "source-quench" => Some(4),
            "redirect" => Some(5),
            "echo-request" => Some(8),
            "router-advertisement" => Some(9),
            "router-solicitation" => Some(10),
            "time-exceeded" => Some(11),
            "parameter-problem" => Some(12),
            "timestamp-request" => Some(13),
            "timestamp-reply" => Some(14),
            _ => None,
        },
        IpProtocol::Icmpv6 => match name.to_lowercase().as_str() {
            "destination-unreachable" => Some(1),
            "packet-too-big" => Some(2),
            "time-exceeded" => Some(3),
            "parameter-problem" => Some(4),
            "echo-request" => Some(128),
            "echo-reply" => Some(129),
            "router-solicitation" | "nd-router-solicit" => Some(133),
            "router-advertisement" | "nd-router-advert" => Some(134),
            "neighbour-solicitation" | "nd-neighbor-solicit" => Some(135),
            "neighbour-advertisement" | "nd-neighbor-advert" => Some(136),
            _ => None,
        },
        _ => None,
    };

    match expected {
        Some(expected_type) => match op {
            MatchOp::Eq => actual_type == expected_type,
            MatchOp::Neq => actual_type != expected_type,
            _ => false,
        },
        None => false,
    }
}

// --- Meta matching ---

fn match_meta(key: &MetaKey, op: &MatchOp, value: &str, state: &PacketState) -> bool {
    match key {
        MetaKey::Mark => {
            if let Ok(v) = parse_u32_maybe_hex(value) {
                compare_u32(op, state.mark, v)
            } else {
                false
            }
        }
        MetaKey::Protocol => {
            // nfproto or ethertype
            compare_str(op, &state.ethertype.to_string().to_lowercase(), &value.to_lowercase())
        }
        MetaKey::Iifname => compare_str(op, &state.ingress_if, value),
        MetaKey::Oifname => {
            match &state.egress_if {
                Some(oif) => compare_str(op, oif, value),
                None => matches!(op, MatchOp::Neq),
            }
        }
        MetaKey::L4proto => {
            let proto_str = state.protocol.to_string();
            // nftables에서 l4proto는 프로토콜 이름 또는 번호
            if let Ok(num) = value.parse::<u8>() {
                compare_u32(op, state.protocol.protocol_number() as u32, num as u32)
            } else {
                compare_str(op, &proto_str, value)
            }
        }
        MetaKey::Nfproto => {
            // ip = 2, ip6 = 10
            let actual = match (state.src_ip, state.dst_ip) {
                (Some(IpAddr::V4(_)), _) | (_, Some(IpAddr::V4(_))) => "ipv4",
                (Some(IpAddr::V6(_)), _) | (_, Some(IpAddr::V6(_))) => "ipv6",
                _ => "unknown",
            };
            compare_str(op, actual, &value.to_lowercase())
        }
        MetaKey::Length | MetaKey::Skuid => false, // 미지원
    }
}

// --- Conntrack matching ---

fn match_ct(key: &CtKey, op: &MatchOp, value: &str, state: &PacketState) -> bool {
    match key {
        CtKey::State => {
            // value can be comma-separated: "established,related"
            let states: Vec<&str> = value.split(',').map(|s| s.trim()).collect();
            let current = state.ct_state.to_string();

            match op {
                MatchOp::Eq | MatchOp::In => states.iter().any(|s| s.to_lowercase() == current),
                MatchOp::Neq => !states.iter().any(|s| s.to_lowercase() == current),
                _ => false,
            }
        }
        CtKey::Mark => {
            if let Ok(v) = parse_u32_maybe_hex(value) {
                compare_u32(op, state.ct_mark, v)
            } else {
                false
            }
        }
        CtKey::Direction => {
            // "original" or "reply" — 정적 시뮬레이션에서는 항상 original
            compare_str(op, "original", value)
        }
        CtKey::Status | CtKey::Expiration => false, // 정적 시뮬레이션에서 미지원
    }
}

// --- Utility functions ---

fn compare_u32(op: &MatchOp, actual: u32, expected: u32) -> bool {
    match op {
        MatchOp::Eq => actual == expected,
        MatchOp::Neq => actual != expected,
        MatchOp::Lt => actual < expected,
        MatchOp::Gt => actual > expected,
        MatchOp::Lte => actual <= expected,
        MatchOp::Gte => actual >= expected,
        MatchOp::In => actual == expected,
    }
}

fn compare_str(op: &MatchOp, actual: &str, expected: &str) -> bool {
    match op {
        MatchOp::Eq => actual.eq_ignore_ascii_case(expected),
        MatchOp::Neq => !actual.eq_ignore_ascii_case(expected),
        MatchOp::In => expected
            .split(',')
            .map(|s| s.trim())
            .any(|s| actual.eq_ignore_ascii_case(s)),
        _ => false,
    }
}

fn parse_u32_maybe_hex(s: &str) -> Result<u32, std::num::ParseIntError> {
    if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::conntrack::ConntrackState;
    use crate::model::packet::*;

    fn make_tcp_state() -> PacketState {
        PacketState {
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("192.168.1.1".parse().unwrap()),
            src_port: Some(54321),
            dst_port: Some(80),
            protocol: IpProtocol::Tcp,
            mark: 0,
            ct_mark: 0,
            ct_state: ConntrackState::New,
            ingress_if: "eth0".to_string(),
            egress_if: None,
            ttl: 64,
            dscp: 0,
            icmp_type: None,
            icmp_code: None,
            tcp_flags: Some(TcpFlags {
                syn: true,
                ..Default::default()
            }),
            arp_op: None,
            dnat_applied: false,
            snat_applied: false,
            original_dst_ip: None,
            original_dst_port: None,
            original_src_ip: None,
            original_src_port: None,
        }
    }

    fn make_icmp_state() -> PacketState {
        PacketState {
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.2".parse().unwrap()),
            src_port: None,
            dst_port: None,
            protocol: IpProtocol::Icmp,
            mark: 0,
            ct_mark: 0,
            ct_state: ConntrackState::New,
            ingress_if: "eth0".to_string(),
            egress_if: None,
            ttl: 64,
            dscp: 0,
            icmp_type: Some(8), // echo request
            icmp_code: Some(0),
            tcp_flags: None,
            arp_op: None,
            dnat_applied: false,
            snat_applied: false,
            original_dst_ip: None,
            original_dst_port: None,
            original_src_ip: None,
            original_src_port: None,
        }
    }

    fn make_udp_state() -> PacketState {
        PacketState {
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(12345),
            dst_port: Some(53),
            protocol: IpProtocol::Udp,
            mark: 0,
            ct_mark: 0,
            ct_state: ConntrackState::New,
            ingress_if: "eth0".to_string(),
            egress_if: None,
            ttl: 64,
            dscp: 0,
            icmp_type: None,
            icmp_code: None,
            tcp_flags: None,
            arp_op: None,
            dnat_applied: false,
            snat_applied: false,
            original_dst_ip: None,
            original_dst_port: None,
            original_src_ip: None,
            original_src_port: None,
        }
    }

    #[test]
    fn test_ip_saddr_match() {
        let state = make_tcp_state();
        let m = NfMatch::Ip {
            field: IpField::Saddr,
            op: MatchOp::Eq,
            value: "10.0.0.0/24".to_string(),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_ip_daddr_exact() {
        let state = make_tcp_state();
        let m = NfMatch::Ip {
            field: IpField::Daddr,
            op: MatchOp::Eq,
            value: "192.168.1.1".to_string(),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_tcp_dport_match() {
        let state = make_tcp_state();
        let m = NfMatch::Transport {
            protocol: TransportProto::Tcp,
            field: TransportField::Dport,
            op: MatchOp::Eq,
            value: "80".to_string(),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_tcp_flags_syn() {
        let state = make_tcp_state();
        let m = NfMatch::Transport {
            protocol: TransportProto::Tcp,
            field: TransportField::Flags,
            op: MatchOp::Eq,
            value: "syn".to_string(),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_icmp_type_match() {
        let state = make_icmp_state();
        let m = NfMatch::Transport {
            protocol: TransportProto::Icmp,
            field: TransportField::IcmpType,
            op: MatchOp::Eq,
            value: "echo-request".to_string(),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_icmp_type_numeric_match() {
        let state = make_icmp_state();
        let m = NfMatch::Transport {
            protocol: TransportProto::Icmp,
            field: TransportField::IcmpType,
            op: MatchOp::Eq,
            value: "8".to_string(),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_icmp_has_no_ports() {
        let state = make_icmp_state();
        // ICMP 패킷에 대해 dport 매칭은 실패해야 함
        let m = NfMatch::Transport {
            protocol: TransportProto::Tcp,
            field: TransportField::Dport,
            op: MatchOp::Eq,
            value: "80".to_string(),
        };
        assert!(!evaluate_match(&m, &state));
    }

    #[test]
    fn test_udp_dport_match() {
        let state = make_udp_state();
        let m = NfMatch::Transport {
            protocol: TransportProto::Udp,
            field: TransportField::Dport,
            op: MatchOp::Eq,
            value: "53".to_string(),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_ct_state_match() {
        let state = make_tcp_state();
        let m = NfMatch::Ct {
            key: CtKey::State,
            op: MatchOp::Eq,
            value: "new".to_string(),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_ct_state_set_match() {
        let state = make_tcp_state();
        let m = NfMatch::Ct {
            key: CtKey::State,
            op: MatchOp::In,
            value: "established,related".to_string(),
        };
        assert!(!evaluate_match(&m, &state)); // state is New
    }

    #[test]
    fn test_iif_match() {
        let state = make_tcp_state();
        let m = NfMatch::Iif {
            name: "eth0".to_string(),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_mark_match_with_mask() {
        let mut state = make_tcp_state();
        state.mark = 0x100;
        let m = NfMatch::Mark {
            op: MatchOp::Eq,
            value: 0x100,
            mask: Some(0xff00),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_port_range_match() {
        let state = make_tcp_state(); // src_port=54321
        let m = NfMatch::Transport {
            protocol: TransportProto::Tcp,
            field: TransportField::Sport,
            op: MatchOp::Eq,
            value: "1024-65535".to_string(),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_meta_l4proto() {
        let state = make_tcp_state();
        let m = NfMatch::Meta {
            key: MetaKey::L4proto,
            op: MatchOp::Eq,
            value: "tcp".to_string(),
        };
        assert!(evaluate_match(&m, &state));
    }

    #[test]
    fn test_multiple_matches_and() {
        let state = make_tcp_state();
        let matches = vec![
            NfMatch::Iif {
                name: "eth0".to_string(),
            },
            NfMatch::Transport {
                protocol: TransportProto::Tcp,
                field: TransportField::Dport,
                op: MatchOp::Eq,
                value: "80".to_string(),
            },
            NfMatch::Ct {
                key: CtKey::State,
                op: MatchOp::Eq,
                value: "new".to_string(),
            },
        ];
        assert!(evaluate_matches(&matches, &state));
    }
}
