//! 시뮬레이션 엔진 통합 테스트
//!
//! Linux 커널의 알려진 패킷 처리 동작을 검증한다.

use std::net::IpAddr;

use netsim_core::engine;
use netsim_core::model::conntrack::ConntrackState;
use netsim_core::model::interface::*;
use netsim_core::model::nat::NatAction;
use netsim_core::model::netfilter::*;
use netsim_core::model::packet::*;
use netsim_core::model::policy_routing::*;
use netsim_core::model::routing::*;
use netsim_core::model::scenario::Scenario;
use netsim_core::model::xdp::*;
use netsim_core::trace::FinalVerdict;

/// 기본 인터페이스 셋 (eth0: 10.0.0.1/24, eth1: 192.168.1.1/24, lo)
fn default_interfaces() -> Vec<Interface> {
    vec![
        Interface {
            name: "lo".to_string(),
            index: 1,
            mac: None,
            addresses: vec![InterfaceAddress {
                ip: "127.0.0.1".parse().unwrap(),
                prefix_len: 8,
                scope: AddressScope::Host,
            }],
            mtu: 65536,
            state: InterfaceState::Up,
            kind: InterfaceKind::Loopback,
        },
        Interface {
            name: "eth0".to_string(),
            index: 2,
            mac: Some("00:11:22:33:44:55".to_string()),
            addresses: vec![InterfaceAddress {
                ip: "10.0.0.1".parse().unwrap(),
                prefix_len: 24,
                scope: AddressScope::Global,
            }],
            mtu: 1500,
            state: InterfaceState::Up,
            kind: InterfaceKind::Physical,
        },
        Interface {
            name: "eth1".to_string(),
            index: 3,
            mac: Some("00:11:22:33:44:66".to_string()),
            addresses: vec![InterfaceAddress {
                ip: "192.168.1.1".parse().unwrap(),
                prefix_len: 24,
                scope: AddressScope::Global,
            }],
            mtu: 1500,
            state: InterfaceState::Up,
            kind: InterfaceKind::Physical,
        },
    ]
}

/// 기본 라우팅: local + main
fn default_routing() -> (Vec<IpRule>, Vec<RoutingTable>) {
    let rules = vec![
        IpRule {
            priority: 0,
            selector: RuleSelector::default(),
            action: RuleAction::Lookup(255), // local
        },
        IpRule {
            priority: 32766,
            selector: RuleSelector::default(),
            action: RuleAction::Lookup(254), // main
        },
    ];

    let tables = vec![
        RoutingTable {
            id: 255,
            name: Some("local".to_string()),
            routes: vec![
                Route {
                    destination: "10.0.0.1/32".parse().unwrap(),
                    route_type: RouteType::Local,
                    dev: Some("eth0".to_string()),
                    ..default_route()
                },
                Route {
                    destination: "192.168.1.1/32".parse().unwrap(),
                    route_type: RouteType::Local,
                    dev: Some("eth1".to_string()),
                    ..default_route()
                },
                Route {
                    destination: "127.0.0.1/32".parse().unwrap(),
                    route_type: RouteType::Local,
                    dev: Some("lo".to_string()),
                    ..default_route()
                },
            ],
        },
        RoutingTable {
            id: 254,
            name: Some("main".to_string()),
            routes: vec![
                Route {
                    destination: "10.0.0.0/24".parse().unwrap(),
                    dev: Some("eth0".to_string()),
                    scope: RouteScope::Link,
                    ..default_route()
                },
                Route {
                    destination: "192.168.1.0/24".parse().unwrap(),
                    dev: Some("eth1".to_string()),
                    scope: RouteScope::Link,
                    ..default_route()
                },
                Route {
                    destination: "0.0.0.0/0".parse().unwrap(),
                    gateway: Some("10.0.0.254".parse().unwrap()),
                    dev: Some("eth0".to_string()),
                    ..default_route()
                },
            ],
        },
    ];

    (rules, tables)
}

fn default_route() -> Route {
    Route {
        destination: "0.0.0.0/0".parse().unwrap(),
        gateway: None,
        dev: None,
        src: None,
        metric: 0,
        scope: RouteScope::Global,
        route_type: RouteType::Unicast,
        mtu: None,
    }
}

fn empty_netfilter() -> NetfilterConfig {
    NetfilterConfig::default()
}

// ============================================================
// 시나리오 1: 기본 로컬 패킷 수신 (TCP SYN → 로컬 IP)
// ============================================================
#[test]
fn test_local_delivery_tcp() {
    let (rules, tables) = default_routing();
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "local-tcp".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("203.0.113.50".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(80),
            tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
    assert!(result.trace.len() >= 6); // XDP, tc, ct, prerouting, routing, input
}

// ============================================================
// 시나리오 2: 기본 포워딩 (UDP DNS)
// ============================================================
#[test]
fn test_forwarding_udp() {
    let (rules, tables) = default_routing();
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "forward-udp".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("192.168.1.100".parse().unwrap()),
            protocol: IpProtocol::Udp,
            src_port: Some(12345),
            dst_port: Some(53),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Forwarded);
    assert_eq!(result.summary.egress_interface.as_deref(), Some("eth1"));
}

// ============================================================
// 시나리오 3: ICMP Echo Request → 로컬 수신
// ============================================================
#[test]
fn test_local_delivery_icmp() {
    let (rules, tables) = default_routing();
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "local-icmp".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("203.0.113.50".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            protocol: IpProtocol::Icmp,
            icmp_type: Some(8),  // echo request
            icmp_code: Some(0),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
}

// ============================================================
// 시나리오 4: DNAT + 포워딩
// ============================================================
#[test]
fn test_dnat_forwarding() {
    let (rules, tables) = default_routing();
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "nat".to_string(),
                chains: vec![NfChain {
                    name: "prerouting".to_string(),
                    chain_type: Some(NfChainType::Nat),
                    hook: Some(NfHook::Prerouting),
                    priority: Some(-100),
                    policy: Some(NfVerdict::Accept),
                    rules: vec![NfRule {
                        handle: None,
                        comment: None,
                        matches: vec![
                            NfMatch::Transport {
                                protocol: TransportProto::Tcp,
                                field: TransportField::Dport,
                                op: MatchOp::Eq,
                                value: "80".to_string(),
                            },
                        ],
                        action: NfAction::Nat(NatAction::Dnat {
                            addr: Some("192.168.1.100".parse().unwrap()),
                            port: Some(8080),
                        }),
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "dnat-forward".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("203.0.113.50".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(80),
            tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Forwarded);

    // DNAT이 적용되었는지 확인
    let last_state = &result.trace.last().unwrap().state_after;
    assert_eq!(last_state.dst_ip, Some("192.168.1.100".parse::<IpAddr>().unwrap()));
    assert_eq!(last_state.dst_port, Some(8080));
    assert!(last_state.dnat_applied);
    assert!(result.summary.nat_applied);
}

// ============================================================
// 시나리오 5: FORWARD 체인에서 DROP (방화벽)
// ============================================================
#[test]
fn test_forward_drop_by_firewall() {
    let (rules, tables) = default_routing();
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "filter".to_string(),
                chains: vec![NfChain {
                    name: "forward".to_string(),
                    chain_type: Some(NfChainType::Filter),
                    hook: Some(NfHook::Forward),
                    priority: Some(0),
                    policy: Some(NfVerdict::Drop), // default DROP
                    rules: vec![
                        // established,related만 허용
                        NfRule {
                            handle: None,
                            comment: Some("allow established".to_string()),
                            matches: vec![NfMatch::Ct {
                                key: CtKey::State,
                                op: MatchOp::In,
                                value: "established,related".to_string(),
                            }],
                            action: NfAction::Verdict { verdict: NfVerdict::Accept },
                        },
                    ],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "firewall-drop".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("192.168.1.100".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(22),
            tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
            conntrack_state: ConntrackState::New, // NEW는 허용 규칙에 안 걸림
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Drop);
}

// ============================================================
// 시나리오 6: SNAT/MASQUERADE
// ============================================================
#[test]
fn test_snat_masquerade() {
    let (rules, tables) = default_routing();
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "nat".to_string(),
                chains: vec![NfChain {
                    name: "postrouting".to_string(),
                    chain_type: Some(NfChainType::Nat),
                    hook: Some(NfHook::Postrouting),
                    priority: Some(100),
                    policy: Some(NfVerdict::Accept),
                    rules: vec![NfRule {
                        handle: None,
                        comment: None,
                        matches: vec![NfMatch::Oif { name: "eth0".to_string() }],
                        action: NfAction::Nat(NatAction::Masquerade { port: None }),
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "masquerade".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth1".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("192.168.1.100".parse().unwrap()),
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            protocol: IpProtocol::Udp,
            src_port: Some(12345),
            dst_port: Some(53),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Forwarded);

    // MASQUERADE로 src_ip가 eth0의 IP(10.0.0.1)로 변경되었는지
    let last_state = &result.trace.last().unwrap().state_after;
    assert_eq!(last_state.src_ip, Some("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(last_state.snat_applied);
}

// ============================================================
// 시나리오 7: XDP DROP
// ============================================================
#[test]
fn test_xdp_drop() {
    let (rules, tables) = default_routing();
    let xdp = XdpConfig {
        programs: vec![XdpProgram {
            interface: "eth0".to_string(),
            mode: XdpMode::Generic,
            rules: vec![XdpRule {
                matches: vec![NfMatch::Ip {
                    field: IpField::Saddr,
                    op: MatchOp::Eq,
                    value: "203.0.113.0/24".to_string(),
                }],
                action: XdpAction::Drop,
                comment: Some("block bad network".to_string()),
            }],
            default_action: XdpAction::Pass,
        }],
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "xdp-drop".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("203.0.113.50".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(80),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Drop);
    assert_eq!(result.trace.len(), 1); // XDP에서 바로 종료
}

// ============================================================
// 시나리오 8: 정책 라우팅 (fwmark 기반)
// ============================================================
#[test]
fn test_policy_routing_fwmark() {
    let interfaces = default_interfaces();
    let rules = vec![
        IpRule {
            priority: 0,
            selector: RuleSelector::default(),
            action: RuleAction::Lookup(255),
        },
        IpRule {
            priority: 100,
            selector: RuleSelector {
                fwmark: Some(100),
                ..Default::default()
            },
            action: RuleAction::Lookup(100), // 커스텀 테이블
        },
        IpRule {
            priority: 32766,
            selector: RuleSelector::default(),
            action: RuleAction::Lookup(254),
        },
    ];
    let tables = vec![
        RoutingTable {
            id: 255,
            name: Some("local".to_string()),
            routes: vec![
                Route {
                    destination: "10.0.0.1/32".parse().unwrap(),
                    route_type: RouteType::Local,
                    dev: Some("eth0".to_string()),
                    ..default_route()
                },
                Route {
                    destination: "192.168.1.1/32".parse().unwrap(),
                    route_type: RouteType::Local,
                    dev: Some("eth1".to_string()),
                    ..default_route()
                },
            ],
        },
        RoutingTable {
            id: 100,
            name: Some("custom".to_string()),
            routes: vec![Route {
                destination: "0.0.0.0/0".parse().unwrap(),
                gateway: Some("192.168.1.254".parse().unwrap()),
                dev: Some("eth1".to_string()), // eth1로 보냄
                ..default_route()
            }],
        },
        RoutingTable {
            id: 254,
            name: Some("main".to_string()),
            routes: vec![Route {
                destination: "0.0.0.0/0".parse().unwrap(),
                gateway: Some("10.0.0.254".parse().unwrap()),
                dev: Some("eth0".to_string()),
                ..default_route()
            }],
        },
    ];

    // mangle PREROUTING에서 mark 100 설정
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "mangle".to_string(),
                chains: vec![NfChain {
                    name: "prerouting".to_string(),
                    chain_type: Some(NfChainType::Mangle),
                    hook: Some(NfHook::Prerouting),
                    priority: Some(-150),
                    policy: Some(NfVerdict::Accept),
                    rules: vec![NfRule {
                        handle: None,
                        comment: None,
                        matches: vec![NfMatch::Transport {
                            protocol: TransportProto::Tcp,
                            field: TransportField::Dport,
                            op: MatchOp::Eq,
                            value: "443".to_string(),
                        }],
                        action: NfAction::SetMark { value: 100, mask: None },
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "policy-routing".to_string(),
        description: None,
        interfaces,
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("1.1.1.1".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(443),
            tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Forwarded);
    // mark=100 → table 100 → eth1 경유
    assert_eq!(result.summary.egress_interface.as_deref(), Some("eth1"));
}

// ============================================================
// 시나리오 9: Blackhole 라우트
// ============================================================
#[test]
fn test_blackhole_route() {
    let rules = vec![IpRule {
        priority: 0,
        selector: RuleSelector::default(),
        action: RuleAction::Lookup(254),
    }];
    let tables = vec![RoutingTable {
        id: 254,
        name: Some("main".to_string()),
        routes: vec![Route {
            destination: "198.51.100.0/24".parse().unwrap(),
            route_type: RouteType::Blackhole,
            ..default_route()
        }],
    }];

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "blackhole".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("198.51.100.50".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(80),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Drop);
}

// ============================================================
// 시나리오 10: ARP 패킷 (L2-only)
// ============================================================
#[test]
fn test_arp_packet_l2_only() {
    let (rules, tables) = default_routing();
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "arp-request".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Arp,
            src_ip: None,
            dst_ip: None,
            protocol: IpProtocol::Other(0),
            arp: Some(ArpFields {
                operation: 1, // ARP request
                sender_mac: Some("00:aa:bb:cc:dd:ee".to_string()),
                sender_ip: Some("10.0.0.100".parse().unwrap()),
                target_mac: None,
                target_ip: Some("10.0.0.1".parse().unwrap()),
            }),
            conntrack_state: ConntrackState::Untracked,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    // ARP는 XDP → L2 bypass → LOCAL_DELIVERY
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
    assert!(result.trace.len() <= 3); // XDP + L2 bypass
}

// ============================================================
// 시나리오 11: ICMP에 대한 DNAT (포트 없이 IP만 변경)
// ============================================================
#[test]
fn test_dnat_icmp_no_port_change() {
    let (rules, tables) = default_routing();
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "nat".to_string(),
                chains: vec![NfChain {
                    name: "prerouting".to_string(),
                    chain_type: Some(NfChainType::Nat),
                    hook: Some(NfHook::Prerouting),
                    priority: Some(-100),
                    policy: Some(NfVerdict::Accept),
                    rules: vec![NfRule {
                        handle: None,
                        comment: None,
                        matches: vec![NfMatch::Ip {
                            field: IpField::Daddr,
                            op: MatchOp::Eq,
                            value: "10.0.0.1".to_string(),
                        }],
                        action: NfAction::Nat(NatAction::Dnat {
                            addr: Some("192.168.1.100".parse().unwrap()),
                            port: Some(8080), // ICMP에는 적용되지 않아야 함
                        }),
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "dnat-icmp".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("203.0.113.50".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            protocol: IpProtocol::Icmp,
            icmp_type: Some(8),
            icmp_code: Some(0),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Forwarded);

    // dst_ip가 변경되었지만 port는 여전히 None
    let last_state = &result.trace.last().unwrap().state_after;
    assert_eq!(last_state.dst_ip, Some("192.168.1.100".parse::<IpAddr>().unwrap()));
    assert_eq!(last_state.dst_port, None); // ICMP이므로 포트 없음
    assert!(last_state.dnat_applied);
}

// ============================================================
// 시나리오 12: TTL 만료
// ============================================================
#[test]
fn test_ttl_expired() {
    let (rules, tables) = default_routing();
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "ttl-expired".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("192.168.1.100".parse().unwrap()),
            protocol: IpProtocol::Udp,
            src_port: Some(12345),
            dst_port: Some(53),
            ttl: Some(1), // TTL=1, 포워딩 시 0이 되어 drop
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Drop);
}

// ============================================================
// 시나리오 13: VRRP 프로토콜 (포트 없는 IP 프로토콜)
// ============================================================
#[test]
fn test_vrrp_local_delivery() {
    let (rules, tables) = default_routing();
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "vrrp".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.2".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            protocol: IpProtocol::Vrrp,
            // VRRP에는 포트가 없음
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
}

// ============================================================
// Helper
// ============================================================
fn default_packet_def() -> PacketDef {
    PacketDef {
        ingress_interface: String::new(),
        ethertype: EtherType::Ipv4,
        vlan_id: None,
        src_mac: None,
        dst_mac: None,
        src_ip: None,
        dst_ip: None,
        protocol: IpProtocol::Tcp,
        src_port: None,
        dst_port: None,
        tcp_flags: None,
        icmp_type: None,
        icmp_code: None,
        arp: None,
        packet_length: None,
        dscp: None,
        ttl: None,
        initial_mark: 0,
        initial_ct_mark: 0,
        conntrack_state: ConntrackState::New,
    }
}
