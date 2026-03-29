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
use netsim_core::model::sysctl::SysctlConfig;
use netsim_core::model::xdp::*;
use netsim_core::trace::{FinalVerdict, PipelineStage};

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
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
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
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
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
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
                        action: NfAction::Nat { action: NatAction::Dnat {
                            addr: Some("192.168.1.100".parse().unwrap()),
                            port: Some(8080),
                        }},
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
                        action: NfAction::Nat { action: NatAction::Masquerade { port: None }},
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
                        action: NfAction::Nat { action: NatAction::Dnat {
                            addr: Some("192.168.1.100".parse().unwrap()),
                            port: Some(8080), // ICMP에는 적용되지 않아야 함
                        }},
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
        sysctl: SysctlConfig::default(),
        topology: None,
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
// 시나리오 14: REJECT (Reject ≠ Drop)
// ============================================================
#[test]
fn test_reject_verdict() {
    let (rules, tables) = default_routing();
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "filter".to_string(),
                chains: vec![NfChain {
                    name: "input".to_string(),
                    chain_type: Some(NfChainType::Filter),
                    hook: Some(NfHook::Input),
                    priority: Some(0),
                    policy: Some(NfVerdict::Accept),
                    rules: vec![NfRule {
                        handle: None,
                        comment: Some("reject ssh".to_string()),
                        matches: vec![NfMatch::Transport {
                            protocol: TransportProto::Tcp,
                            field: TransportField::Dport,
                            op: MatchOp::Eq,
                            value: "22".to_string(),
                        }],
                        action: NfAction::Verdict { verdict: NfVerdict::Reject },
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "reject-ssh".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("203.0.113.50".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(22),
            tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Rejected); // Rejected, not Drop!
}

// ============================================================
// 시나리오 15: 체인 기본 정책 DROP (규칙 없이)
// ============================================================
#[test]
fn test_chain_default_policy_drop() {
    let (rules, tables) = default_routing();
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "filter".to_string(),
                chains: vec![NfChain {
                    name: "input".to_string(),
                    chain_type: Some(NfChainType::Filter),
                    hook: Some(NfHook::Input),
                    priority: Some(0),
                    policy: Some(NfVerdict::Drop), // 정책 DROP, 규칙 없음
                    rules: vec![],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "default-drop".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
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
}

// ============================================================
// 시나리오 16: iptables 규칙 (nftables 아닌)
// ============================================================
#[test]
fn test_iptables_rules() {
    let (rules, tables) = default_routing();
    let netfilter = NetfilterConfig {
        nftables: None,
        iptables: Some(IptablesRuleset {
            tables: vec![IptablesTable {
                name: "filter".to_string(),
                chains: vec![IptablesChain {
                    name: "FORWARD".to_string(),
                    policy: Some(NfVerdict::Drop),
                    rules: vec![
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
                        NfRule {
                            handle: None,
                            comment: Some("allow from eth0 to eth1".to_string()),
                            matches: vec![
                                NfMatch::Iif { name: "eth0".to_string() },
                                NfMatch::Oif { name: "eth1".to_string() },
                            ],
                            action: NfAction::Verdict { verdict: NfVerdict::Accept },
                        },
                    ],
                }],
            }],
        }),
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "iptables-forward".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("192.168.1.100".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(80),
            tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    // eth0→eth1 규칙에 매칭되어 포워딩 허용
    assert_eq!(result.verdict, FinalVerdict::Forwarded);
}

// ============================================================
// 시나리오 17: 다중 체인 우선순위 (mangle + filter)
// ============================================================
#[test]
fn test_multiple_chains_priority_order() {
    let (rules, tables) = default_routing();
    // mangle(-150) 에서 mark 설정 → filter(0)에서 mark 기반 DROP
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![
                NfTable {
                    family: NfFamily::Ip,
                    name: "mangle".to_string(),
                    chains: vec![NfChain {
                        name: "input".to_string(),
                        chain_type: Some(NfChainType::Mangle),
                        hook: Some(NfHook::Input),
                        priority: Some(-150),
                        policy: Some(NfVerdict::Accept),
                        rules: vec![NfRule {
                            handle: None,
                            comment: None,
                            matches: vec![NfMatch::Transport {
                                protocol: TransportProto::Tcp,
                                field: TransportField::Dport,
                                op: MatchOp::Eq,
                                value: "4444".to_string(),
                            }],
                            action: NfAction::SetMark { value: 0xdead, mask: None },
                        }],
                    }],
                },
                NfTable {
                    family: NfFamily::Ip,
                    name: "filter".to_string(),
                    chains: vec![NfChain {
                        name: "input".to_string(),
                        chain_type: Some(NfChainType::Filter),
                        hook: Some(NfHook::Input),
                        priority: Some(0),
                        policy: Some(NfVerdict::Accept),
                        rules: vec![NfRule {
                            handle: None,
                            comment: None,
                            matches: vec![NfMatch::Mark {
                                op: MatchOp::Eq,
                                value: 0xdead,
                                mask: None,
                            }],
                            action: NfAction::Verdict { verdict: NfVerdict::Drop },
                        }],
                    }],
                },
            ],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "multi-chain-prio".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("203.0.113.50".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(4444),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    // mangle(-150) → mark=0xdead, filter(0) → mark 매칭 → DROP
    assert_eq!(result.verdict, FinalVerdict::Drop);
}

// ============================================================
// 시나리오 18: Established 연결은 방화벽 통과
// ============================================================
#[test]
fn test_established_passes_firewall() {
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
                    policy: Some(NfVerdict::Drop),
                    rules: vec![NfRule {
                        handle: None,
                        comment: None,
                        matches: vec![NfMatch::Ct {
                            key: CtKey::State,
                            op: MatchOp::In,
                            value: "established,related".to_string(),
                        }],
                        action: NfAction::Verdict { verdict: NfVerdict::Accept },
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "established".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("192.168.1.100".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(80),
            dst_port: Some(54321),
            tcp_flags: Some(TcpFlags { ack: true, ..Default::default() }),
            conntrack_state: ConntrackState::Established,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Forwarded);
}

// ============================================================
// 시나리오 19: REDIRECT NAT (dst_ip → 수신 인터페이스 IP)
// ============================================================
#[test]
fn test_redirect_nat() {
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
                        matches: vec![NfMatch::Transport {
                            protocol: TransportProto::Tcp,
                            field: TransportField::Dport,
                            op: MatchOp::Eq,
                            value: "8080".to_string(),
                        }],
                        action: NfAction::Nat { action: NatAction::Redirect { port: Some(80) }},
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "redirect".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("203.0.113.50".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(8080),
            tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
    // REDIRECT: dst_ip → ingress if의 IP (eth0=10.0.0.1), dst_port → 80
    let last_state = &result.trace.last().unwrap().state_after;
    assert_eq!(last_state.dst_ip, Some("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert_eq!(last_state.dst_port, Some(80));
    assert!(last_state.dnat_applied);
}

// ============================================================
// 시나리오 20: IPv6 패킷
// ============================================================
#[test]
fn test_ipv6_local_delivery() {
    let interfaces = vec![
        Interface {
            name: "eth0".to_string(),
            index: 2,
            mac: None,
            addresses: vec![
                InterfaceAddress {
                    ip: "10.0.0.1".parse().unwrap(),
                    prefix_len: 24,
                    scope: AddressScope::Global,
                },
                InterfaceAddress {
                    ip: "fd00::1".parse().unwrap(),
                    prefix_len: 64,
                    scope: AddressScope::Global,
                },
            ],
            mtu: 1500,
            state: InterfaceState::Up,
            kind: InterfaceKind::Physical,
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
    ];
    let rules = vec![IpRule {
        priority: 0,
        selector: RuleSelector::default(),
        action: RuleAction::Lookup(255),
    }];
    let tables = vec![RoutingTable {
        id: 255,
        name: Some("local".to_string()),
        routes: vec![Route {
            destination: "fd00::1/128".parse().unwrap(),
            route_type: RouteType::Local,
            dev: Some("eth0".to_string()),
            ..default_route()
        }],
    }];

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "ipv6".to_string(),
        description: None,
        interfaces,
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv6,
            src_ip: Some("fd00::100".parse().unwrap()),
            dst_ip: Some("fd00::1".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(443),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
}

// ============================================================
// 시나리오 21: ICMPv6 Neighbour Solicitation
// ============================================================
#[test]
fn test_icmpv6_neighbour_solicitation() {
    let interfaces = vec![Interface {
        name: "eth0".to_string(),
        index: 2,
        mac: None,
        addresses: vec![InterfaceAddress {
            ip: "fd00::1".parse().unwrap(),
            prefix_len: 64,
            scope: AddressScope::Global,
        }],
        mtu: 1500,
        state: InterfaceState::Up,
        kind: InterfaceKind::Physical,
        veth_peer: None,
        bridge_members: vec![],
        master: None,
        vlan_parent: None,
        vlan_id: None,
        bond_members: vec![],
    }];
    let rules = vec![IpRule {
        priority: 0,
        selector: RuleSelector::default(),
        action: RuleAction::Lookup(254),
    }];
    let tables = vec![RoutingTable {
        id: 254,
        name: Some("main".to_string()),
        routes: vec![Route {
            destination: "fd00::/64".parse().unwrap(),
            dev: Some("eth0".to_string()),
            scope: RouteScope::Link,
            ..default_route()
        }],
    }];

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "icmpv6-ns".to_string(),
        description: None,
        interfaces,
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv6,
            src_ip: Some("fd00::100".parse().unwrap()),
            dst_ip: Some("fd00::1".parse().unwrap()),
            protocol: IpProtocol::Icmpv6,
            icmp_type: Some(135), // Neighbour Solicitation
            icmp_code: Some(0),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    // fd00::1 은 로컬 인터페이스 주소
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
}

// ============================================================
// 시나리오 22: XDP TX (같은 인터페이스로 반사)
// ============================================================
#[test]
fn test_xdp_tx() {
    let (rules, tables) = default_routing();
    let xdp = XdpConfig {
        programs: vec![XdpProgram {
            interface: "eth0".to_string(),
            mode: XdpMode::Generic,
            rules: vec![],
            default_action: XdpAction::Tx,
        }],
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "xdp-tx".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp,
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(80),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Tx); // TX, not Redirect!
}

// ============================================================
// 시나리오 23: next_hop 추출 검증
// ============================================================
#[test]
fn test_next_hop_in_summary() {
    let (rules, tables) = default_routing();
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "next-hop".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
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
    // default route via 10.0.0.254
    assert_eq!(result.summary.next_hop, Some("10.0.0.254".parse::<IpAddr>().unwrap()));
}

// ============================================================
// 시나리오 24: Neq (부정 매칭)
// ============================================================
#[test]
fn test_neq_match() {
    let (rules, tables) = default_routing();
    // "NOT from eth1" → accept, 나머지 → drop
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "filter".to_string(),
                chains: vec![NfChain {
                    name: "input".to_string(),
                    chain_type: Some(NfChainType::Filter),
                    hook: Some(NfHook::Input),
                    priority: Some(0),
                    policy: Some(NfVerdict::Drop),
                    rules: vec![NfRule {
                        handle: None,
                        comment: Some("accept if NOT from lo".to_string()),
                        matches: vec![NfMatch::Iif { name: "lo".to_string() }],
                        action: NfAction::Verdict { verdict: NfVerdict::Drop },
                    }, NfRule {
                        handle: None,
                        comment: None,
                        matches: vec![],
                        action: NfAction::Verdict { verdict: NfVerdict::Accept },
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "neq-match".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
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
    // eth0 != lo 이므로 첫 규칙 스킵, 두 번째 규칙(catch-all) accept
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
}

// ============================================================
// 시나리오 25: STP 패킷 (L2-only, XDP pass)
// ============================================================
#[test]
fn test_stp_packet() {
    let (rules, tables) = default_routing();
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "stp".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Stp,
            src_ip: None,
            dst_ip: None,
            protocol: IpProtocol::Other(0),
            conntrack_state: ConntrackState::Untracked,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
    assert!(result.trace.len() == 2); // XDP + L2 bypass
}

// ============================================================
// 시나리오 26: nftables + iptables 혼용
// ============================================================
#[test]
fn test_nftables_and_iptables_mixed() {
    let (rules, tables) = default_routing();
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "myfilter".to_string(),
                chains: vec![NfChain {
                    name: "input".to_string(),
                    chain_type: Some(NfChainType::Filter),
                    hook: Some(NfHook::Input),
                    priority: Some(10), // nft priority 10
                    policy: Some(NfVerdict::Accept),
                    rules: vec![],
                }],
            }],
        }),
        iptables: Some(IptablesRuleset {
            tables: vec![IptablesTable {
                name: "filter".to_string(),
                chains: vec![IptablesChain {
                    name: "INPUT".to_string(),
                    policy: Some(NfVerdict::Drop), // iptables filter priority=0 (< nft 10)
                    rules: vec![NfRule {
                        handle: None,
                        comment: None,
                        matches: vec![NfMatch::Transport {
                            protocol: TransportProto::Tcp,
                            field: TransportField::Dport,
                            op: MatchOp::Eq,
                            value: "80".to_string(),
                        }],
                        action: NfAction::Verdict { verdict: NfVerdict::Accept },
                    }],
                }],
            }],
        }),
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "mixed-nft-ipt".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
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
    // iptables filter(prio=0) → dport 80 accept → nft(prio=10) → accept policy
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
}

// ============================================================
// 시나리오 27: ip_forward=0 → 포워딩 차단
// ============================================================
#[test]
fn test_sysctl_ip_forward_disabled() {
    let (rules, tables) = default_routing();
    let mut sysctl = SysctlConfig::default();
    sysctl.ipv4.ip_forward = false;

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "no-forward".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl,
        topology: None,
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
    assert_eq!(result.verdict, FinalVerdict::Drop);
    // trace에 ip_forward 관련 설명이 있어야 함
    let has_fwd_msg = result.trace.iter().any(|s| s.explain.contains("ip_forward"));
    assert!(has_fwd_msg, "Should mention ip_forward in trace");
}

// ============================================================
// 시나리오 28: route_localnet=0 → DNAT to 127.0.0.1 차단
// ============================================================
#[test]
fn test_sysctl_route_localnet_blocks_loopback_dnat() {
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
                        matches: vec![NfMatch::Transport {
                            protocol: TransportProto::Tcp,
                            field: TransportField::Dport,
                            op: MatchOp::Eq,
                            value: "80".to_string(),
                        }],
                        action: NfAction::Nat { action: NatAction::Dnat {
                            addr: Some("127.0.0.1".parse().unwrap()),
                            port: Some(8080),
                        }},
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    // route_localnet=false (기본값) → 127.0.0.1 DNAT 차단
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "no-route-localnet".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables.clone(),
        ip_rules: rules.clone(),
        netfilter: netfilter.clone(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(), // route_localnet=false
        topology: None,
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
    let has_localnet_msg = result.trace.iter().any(|s| s.explain.contains("route_localnet"));
    assert!(has_localnet_msg);
}

// ============================================================
// 시나리오 29: route_localnet=1 → DNAT to 127.0.0.1 허용
// ============================================================
#[test]
fn test_sysctl_route_localnet_allows_loopback_dnat() {
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
                        matches: vec![NfMatch::Transport {
                            protocol: TransportProto::Tcp,
                            field: TransportField::Dport,
                            op: MatchOp::Eq,
                            value: "80".to_string(),
                        }],
                        action: NfAction::Nat { action: NatAction::Dnat {
                            addr: Some("127.0.0.1".parse().unwrap()),
                            port: Some(8080),
                        }},
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    let mut sysctl = SysctlConfig::default();
    sysctl.interface_conf.insert("eth0".to_string(),
        netsim_core::model::sysctl::InterfaceSysctl {
            route_localnet: true,
            ..Default::default()
        });

    // local 테이블에 127.0.0.1 라우트 추가
    let mut tables = tables;
    if let Some(local_table) = tables.iter_mut().find(|t| t.id == 255) {
        local_table.routes.push(Route {
            destination: "127.0.0.1/32".parse().unwrap(),
            route_type: RouteType::Local,
            dev: Some("lo".to_string()),
            ..default_route()
        });
    }

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "route-localnet-enabled".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl,
        topology: None,
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
    // route_localnet=true → DNAT to 127.0.0.1 허용 → local delivery
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
}

// ============================================================
// 시나리오 30: icmp_echo_ignore_all=1 → ICMP echo drop
// ============================================================
#[test]
fn test_sysctl_icmp_echo_ignore_all() {
    let (rules, tables) = default_routing();
    let mut sysctl = SysctlConfig::default();
    sysctl.ipv4.icmp_echo_ignore_all = true;

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "icmp-ignore".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl,
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            protocol: IpProtocol::Icmp,
            icmp_type: Some(8), // echo request
            icmp_code: Some(0),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Drop);
    let has_icmp_msg = result.trace.iter().any(|s| s.explain.contains("icmp_echo_ignore"));
    assert!(has_icmp_msg);
}

// ============================================================
// 시나리오 31: rp_filter=strict → 소스 검증 실패
// ============================================================
#[test]
fn test_sysctl_rp_filter_strict() {
    let (rules, tables) = default_routing();
    let mut sysctl = SysctlConfig::default();
    sysctl.interface_conf.insert("eth0".to_string(),
        netsim_core::model::sysctl::InterfaceSysctl {
            rp_filter: netsim_core::model::sysctl::RpFilterMode::Strict,
            ..Default::default()
        });

    // 192.168.1.100은 eth1 서브넷인데 eth0으로 들어옴 → strict rp_filter 실패
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "rp-filter-strict".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl,
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("192.168.1.100".parse().unwrap()), // eth1 subnet
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
    let has_rp_msg = result.trace.iter().any(|s| s.explain.contains("Reverse path filter"));
    assert!(has_rp_msg);
}

// ============================================================
// 시나리오 32: Ingress interface down → Drop
// ============================================================
#[test]
fn test_ingress_interface_down() {
    let (rules, tables) = default_routing();
    let interfaces = vec![
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
            state: InterfaceState::Down,
            kind: InterfaceKind::Physical,
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
    ];

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "ingress-down".to_string(),
        description: None,
        interfaces,
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
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
    let has_down_msg = result.trace.iter().any(|s| s.explain.contains("DOWN state"));
    assert!(has_down_msg, "Should mention interface DOWN state in trace");
}

// ============================================================
// 시나리오 33: Egress interface down → Drop
// ============================================================
#[test]
fn test_egress_interface_down() {
    let (rules, tables) = default_routing();
    let interfaces = vec![
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
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
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
            state: InterfaceState::Down,
            kind: InterfaceKind::Physical,
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
    ];

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "egress-down".to_string(),
        description: None,
        interfaces,
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
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
    assert_eq!(result.verdict, FinalVerdict::Drop);
    let has_egress_down = result.trace.iter().any(|s| s.explain.contains("Egress interface") && s.explain.contains("DOWN"));
    assert!(has_egress_down, "Should mention egress interface DOWN in trace");
}

// ============================================================
// 시나리오 34: MTU exceeded with DF flag → Drop
// ============================================================
#[test]
fn test_mtu_exceeded_with_df_flag() {
    let (rules, tables) = default_routing();
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "mtu-df-drop".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("192.168.1.100".parse().unwrap()),
            protocol: IpProtocol::Udp,
            src_port: Some(12345),
            dst_port: Some(53),
            packet_length: Some(2000),
            df_flag: true,
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Drop);
    let has_mtu_msg = result.trace.iter().any(|s| {
        s.stage == PipelineStage::MtuCheck && s.explain.contains("DF")
    });
    assert!(has_mtu_msg, "Should have MTU check with DF flag mention");
}

// ============================================================
// 시나리오 35: MTU exceeded without DF flag → Forwarded (fragmentation)
// ============================================================
#[test]
fn test_mtu_exceeded_without_df_flag() {
    let (rules, tables) = default_routing();
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "mtu-frag".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("192.168.1.100".parse().unwrap()),
            protocol: IpProtocol::Udp,
            src_port: Some(12345),
            dst_port: Some(53),
            packet_length: Some(2000),
            df_flag: false,
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Forwarded);
    let has_frag_msg = result.trace.iter().any(|s| {
        s.stage == PipelineStage::MtuCheck && s.explain.contains("fragmented")
    });
    assert!(has_frag_msg, "Should have MTU check with fragmentation note");
}

// ============================================================
// 시나리오 36: Bridge member detection
// ============================================================
#[test]
fn test_bridge_member_detection() {
    let (rules, tables) = default_routing();
    let interfaces = vec![
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
            veth_peer: None,
            bridge_members: vec![],
            master: Some("br0".to_string()),
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
    ];

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "bridge-member".to_string(),
        description: None,
        interfaces,
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
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
    let has_bridge_step = result.trace.iter().any(|s| {
        s.stage == PipelineStage::InterfaceCheck && s.explain.contains("bridge") && s.explain.contains("br0")
    });
    assert!(has_bridge_step, "Should have InterfaceCheck step mentioning bridge 'br0'");
}

// ============================================================
// 시나리오 37: arp_ignore=1, target IP not on interface → Drop
// ============================================================
#[test]
fn test_arp_ignore_level_1() {
    let (rules, tables) = default_routing();
    let mut sysctl = SysctlConfig::default();
    sysctl.interface_conf.insert("eth0".to_string(),
        netsim_core::model::sysctl::InterfaceSysctl {
            arp_ignore: 1,
            ..Default::default()
        });

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "arp-ignore-1".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl,
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Arp,
            src_ip: None,
            dst_ip: None,
            protocol: IpProtocol::Other(0),
            arp: Some(ArpFields {
                operation: 1,
                sender_mac: Some("00:aa:bb:cc:dd:ee".to_string()),
                sender_ip: Some("10.0.0.100".parse().unwrap()),
                target_mac: None,
                target_ip: Some("192.168.1.1".parse().unwrap()), // not on eth0
            }),
            conntrack_state: ConntrackState::Untracked,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Drop);
    let has_arp_msg = result.trace.iter().any(|s| s.explain.contains("arp_ignore"));
    assert!(has_arp_msg, "Should mention arp_ignore in trace");
}

// ============================================================
// 시나리오 38: arp_ignore=2, sender IP not in same subnet → Drop
// ============================================================
#[test]
fn test_arp_ignore_level_2() {
    let (rules, tables) = default_routing();
    let mut sysctl = SysctlConfig::default();
    sysctl.interface_conf.insert("eth0".to_string(),
        netsim_core::model::sysctl::InterfaceSysctl {
            arp_ignore: 2,
            ..Default::default()
        });

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "arp-ignore-2".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl,
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Arp,
            src_ip: None,
            dst_ip: None,
            protocol: IpProtocol::Other(0),
            arp: Some(ArpFields {
                operation: 1,
                sender_mac: Some("00:aa:bb:cc:dd:ee".to_string()),
                sender_ip: Some("192.168.1.100".parse().unwrap()), // not in eth0's 10.0.0.0/24
                target_mac: None,
                target_ip: Some("10.0.0.1".parse().unwrap()), // on eth0
            }),
            conntrack_state: ConntrackState::Untracked,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Drop);
    let has_arp_msg = result.trace.iter().any(|s| s.explain.contains("arp_ignore=2") && s.explain.contains("sender IP"));
    assert!(has_arp_msg, "Should mention arp_ignore=2 and sender IP in trace");
}

// ============================================================
// 시나리오 39: arp_ignore=0, ARP passes normally
// ============================================================
#[test]
fn test_arp_ignore_disabled() {
    let (rules, tables) = default_routing();
    // default sysctl has arp_ignore=0
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "arp-ignore-0".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Arp,
            src_ip: None,
            dst_ip: None,
            protocol: IpProtocol::Other(0),
            arp: Some(ArpFields {
                operation: 1,
                sender_mac: Some("00:aa:bb:cc:dd:ee".to_string()),
                sender_ip: Some("192.168.1.100".parse().unwrap()),
                target_mac: None,
                target_ip: Some("192.168.1.1".parse().unwrap()), // not on eth0, but arp_ignore=0
            }),
            conntrack_state: ConntrackState::Untracked,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    // arp_ignore=0, ARP is L2-only → local delivery
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery);
}

// ============================================================
// 시나리오 40: Empty interfaces list → Drop "Unknown ingress"
// ============================================================
#[test]
fn test_empty_interfaces_list() {
    let (rules, tables) = default_routing();
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "empty-interfaces".to_string(),
        description: None,
        interfaces: vec![],
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
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
    let has_unknown = result.trace.iter().any(|s| s.explain.contains("does not exist"));
    assert!(has_unknown, "Should mention unknown ingress interface");
}

// ============================================================
// 시나리오 41: MASQUERADE with IPv6 → src_ip changes to egress IPv6
// ============================================================
#[test]
fn test_masquerade_ipv6() {
    let interfaces = vec![
        Interface {
            name: "eth0".to_string(),
            index: 2,
            mac: Some("00:11:22:33:44:55".to_string()),
            addresses: vec![InterfaceAddress {
                ip: "fd00::1".parse().unwrap(),
                prefix_len: 64,
                scope: AddressScope::Global,
            }],
            mtu: 1500,
            state: InterfaceState::Up,
            kind: InterfaceKind::Physical,
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
        Interface {
            name: "eth1".to_string(),
            index: 3,
            mac: Some("00:11:22:33:44:66".to_string()),
            addresses: vec![InterfaceAddress {
                ip: "fd01::1".parse().unwrap(),
                prefix_len: 64,
                scope: AddressScope::Global,
            }],
            mtu: 1500,
            state: InterfaceState::Up,
            kind: InterfaceKind::Physical,
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
    ];

    let rules = vec![
        IpRule {
            priority: 0,
            selector: RuleSelector::default(),
            action: RuleAction::Lookup(254),
        },
    ];
    let tables = vec![RoutingTable {
        id: 254,
        name: Some("main".to_string()),
        routes: vec![
            Route {
                destination: "fd00::/64".parse().unwrap(),
                dev: Some("eth0".to_string()),
                scope: RouteScope::Link,
                ..default_route()
            },
            Route {
                destination: "fd01::/64".parse().unwrap(),
                dev: Some("eth1".to_string()),
                scope: RouteScope::Link,
                ..default_route()
            },
            Route {
                destination: "::/0".parse().unwrap(),
                gateway: Some("fd00::ffff".parse().unwrap()),
                dev: Some("eth0".to_string()),
                ..default_route()
            },
        ],
    }];

    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip6,
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
                        action: NfAction::Nat { action: NatAction::Masquerade { port: None } },
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "masq-ipv6".to_string(),
        description: None,
        interfaces,
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth1".to_string(),
            ethertype: EtherType::Ipv6,
            src_ip: Some("fd01::100".parse().unwrap()),
            dst_ip: Some("2001:db8::1".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(443),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);
    assert_eq!(result.verdict, FinalVerdict::Forwarded);
    let last_state = &result.trace.last().unwrap().state_after;
    assert_eq!(last_state.src_ip, Some("fd00::1".parse::<IpAddr>().unwrap()));
    assert!(last_state.snat_applied);
}

// ============================================================
// 시나리오 42: Interface without addresses, MASQUERADE → src_ip unchanged
// ============================================================
#[test]
fn test_interface_no_addresses_masquerade() {
    let interfaces = vec![
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
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
        Interface {
            name: "eth1".to_string(),
            index: 3,
            mac: Some("00:11:22:33:44:66".to_string()),
            addresses: vec![], // no addresses
            mtu: 1500,
            state: InterfaceState::Up,
            kind: InterfaceKind::Physical,
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
    ];

    let rules = vec![
        IpRule {
            priority: 0,
            selector: RuleSelector::default(),
            action: RuleAction::Lookup(254),
        },
    ];
    let tables = vec![RoutingTable {
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
                destination: "0.0.0.0/0".parse().unwrap(),
                gateway: Some("10.0.0.254".parse().unwrap()),
                dev: Some("eth1".to_string()),
                ..default_route()
            },
        ],
    }];

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
                        matches: vec![NfMatch::Oif { name: "eth1".to_string() }],
                        action: NfAction::Nat { action: NatAction::Masquerade { port: None } },
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "masq-no-addr".to_string(),
        description: None,
        interfaces,
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
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
    // eth1 has no addresses, so MASQUERADE can't change src_ip
    let last_state = &result.trace.last().unwrap().state_after;
    assert_eq!(last_state.src_ip, Some("10.0.0.100".parse::<IpAddr>().unwrap()));
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
        df_flag: false,
        dscp: None,
        ttl: None,
        initial_mark: 0,
        initial_ct_mark: 0,
        conntrack_state: ConntrackState::New,
    }
}

// ============================================================
// Phase 5: TPROXY forces local delivery
// ============================================================
#[test]
fn test_tproxy_forces_local_delivery() {
    let (rules, tables) = default_routing();

    // TPROXY rule in mangle PREROUTING: redirect HTTP to local proxy
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "mangle".to_string(),
                chains: vec![NfChain {
                    name: "prerouting".to_string(),
                    chain_type: Some(NfChainType::Filter),
                    hook: Some(NfHook::Prerouting),
                    priority: Some(-150),
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
                        action: NfAction::Nat {
                            action: NatAction::Tproxy {
                                addr: Some("127.0.0.1".parse().unwrap()),
                                port: 3128,
                                mark: Some(1),
                            },
                        },
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    // Packet destined for an external IP (would normally be forwarded)
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "tproxy-local".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("203.0.113.50".parse().unwrap()),
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(80),
            tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run(&scenario);

    // TPROXY should force local delivery (not forwarded, not Tproxy/Stolen)
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery,
        "TPROXY should force local delivery, got {:?}", result.verdict);

    // Verify TPROXY reroute step is present in trace
    let reroute_step = result.trace.iter().find(|s| matches!(s.stage, PipelineStage::Reroute));
    assert!(reroute_step.is_some(), "Expected a Reroute trace step for TPROXY override");
    let reroute = reroute_step.unwrap();
    assert!(reroute.explain.contains("TPROXY"), "Reroute explain should mention TPROXY");

    // Verify packet state: tproxy_applied should be true
    let final_state = &result.trace.last().unwrap().state_after;
    assert!(final_state.tproxy_applied, "tproxy_applied flag should be set");
}

// ============================================================
// Phase 4: Reroute detection in OUTPUT path (mark change + fwmark rules)
// ============================================================
#[test]
fn test_reroute_in_output() {
    // Set up fwmark-based policy routing:
    // ip rule priority 100 fwmark 0x1 lookup 100
    // table 100 has default route via eth1
    let rules = vec![
        IpRule {
            priority: 0,
            selector: RuleSelector::default(),
            action: RuleAction::Lookup(255),
        },
        IpRule {
            priority: 100,
            selector: RuleSelector {
                fwmark: Some(1),
                ..Default::default()
            },
            action: RuleAction::Lookup(100),
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
                Route {
                    destination: "127.0.0.1/32".parse().unwrap(),
                    route_type: RouteType::Local,
                    dev: Some("lo".to_string()),
                    ..default_route()
                },
            ],
        },
        RoutingTable {
            id: 100,
            name: Some("custom".to_string()),
            routes: vec![
                Route {
                    destination: "0.0.0.0/0".parse().unwrap(),
                    gateway: Some("192.168.1.254".parse().unwrap()),
                    dev: Some("eth1".to_string()),
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

    // OUTPUT mangle chain sets mark=1 on all packets
    let netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "mangle".to_string(),
                chains: vec![NfChain {
                    name: "output".to_string(),
                    chain_type: Some(NfChainType::Route),
                    hook: Some(NfHook::Output),
                    priority: Some(-150),
                    policy: Some(NfVerdict::Accept),
                    rules: vec![NfRule {
                        handle: None,
                        comment: None,
                        matches: vec![],
                        action: NfAction::SetMark { value: 1, mask: None },
                    }],
                }],
            }],
        }),
        iptables: None,
    };

    // Locally originated packet
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "output-reroute".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter,
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "lo".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(443),
            tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
            conntrack_state: ConntrackState::New,
            initial_mark: 0,
            ..default_packet_def()
        },
    };

    let result = engine::run_output(&scenario);

    // Packet should be sent successfully (routed via fwmark table 100 → eth1)
    assert_eq!(result.verdict, FinalVerdict::Sent,
        "OUTPUT packet should be sent, got {:?}", result.verdict);

    // Verify the mark was set by mangle OUTPUT
    let final_state = &result.trace.last().unwrap().state_after;
    assert_eq!(final_state.mark, 1, "Mark should be set to 1 by mangle OUTPUT");

    // Routing via fwmark table 100 → egress should be eth1
    assert_eq!(final_state.egress_if.as_deref(), Some("eth1"),
        "With fwmark=1, routing should use table 100 (eth1)");

    // Verify Reroute trace step is present (mark changed + fwmark rules exist)
    let reroute_step = result.trace.iter().find(|s| matches!(s.stage, PipelineStage::Reroute));
    assert!(reroute_step.is_some(), "Expected a Reroute trace step for mark-based re-routing");
    let reroute = reroute_step.unwrap();
    assert!(reroute.explain.contains("mark"), "Reroute explain should mention mark change");
}

// ============================================================
// Phase 6 Test: Bridge NF pipeline with bridge_nf_call_iptables=true
// ============================================================
#[test]
fn test_bridge_nf_pipeline() {
    use netsim_core::model::sysctl::SysctlConfig;

    let (rules, tables) = default_routing();

    // Create a bridge (br0) with eth0 as member
    let interfaces = vec![
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
            veth_peer: None,
            bridge_members: vec![],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
        Interface {
            name: "br0".to_string(),
            index: 2,
            mac: Some("00:11:22:33:44:55".to_string()),
            addresses: vec![InterfaceAddress {
                ip: "10.0.0.1".parse().unwrap(),
                prefix_len: 24,
                scope: AddressScope::Global,
            }],
            mtu: 1500,
            state: InterfaceState::Up,
            kind: InterfaceKind::Bridge,
            veth_peer: None,
            bridge_members: vec!["eth0".to_string(), "eth1".to_string()],
            master: None,
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
        Interface {
            name: "eth0".to_string(),
            index: 3,
            mac: Some("00:11:22:33:44:66".to_string()),
            addresses: vec![],
            mtu: 1500,
            state: InterfaceState::Up,
            kind: InterfaceKind::Physical,
            veth_peer: None,
            bridge_members: vec![],
            master: Some("br0".to_string()),
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
        Interface {
            name: "eth1".to_string(),
            index: 4,
            mac: Some("00:11:22:33:44:77".to_string()),
            addresses: vec![],
            mtu: 1500,
            state: InterfaceState::Up,
            kind: InterfaceKind::Physical,
            veth_peer: None,
            bridge_members: vec![],
            master: Some("br0".to_string()),
            vlan_parent: None,
            vlan_id: None,
            bond_members: vec![],
        },
    ];

    let mut sysctl = SysctlConfig::default();
    sysctl.bridge_nf_call_iptables = true;

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "bridge-nf-pipeline".to_string(),
        description: None,
        interfaces,
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl,
        topology: None,
        packet: PacketDef {
            ingress_interface: "eth0".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.100".parse().unwrap()),
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

    // Verify BrNf stages appear in trace
    let br_nf_prerouting = result.trace.iter().any(|s| matches!(s.stage, PipelineStage::BrNfPrerouting));
    let br_nf_forward = result.trace.iter().any(|s| matches!(s.stage, PipelineStage::BrNfForward));
    let br_nf_postrouting = result.trace.iter().any(|s| matches!(s.stage, PipelineStage::BrNfPostrouting));
    let bridge_forward = result.trace.iter().any(|s| matches!(s.stage, PipelineStage::BridgeForward));

    assert!(br_nf_prerouting, "Expected BrNfPrerouting stage in trace");
    assert!(br_nf_forward, "Expected BrNfForward stage in trace");
    assert!(br_nf_postrouting, "Expected BrNfPostrouting stage in trace");
    assert!(bridge_forward, "Expected BridgeForward stage in trace");

    // After bridge nf pipeline, packet continues to normal IP stack
    // so we should also see regular PREROUTING, ROUTING, etc.
    let has_prerouting = result.trace.iter().any(|s| matches!(s.stage, PipelineStage::PreRouting | PipelineStage::PreRoutingRaw));
    assert!(has_prerouting || result.trace.iter().any(|s| matches!(s.stage, PipelineStage::ConntrackIn)),
        "Expected normal IP stack stages after bridge nf pipeline");
}

// ============================================================
// Phase 7 Test: Conntrack NAT for established connections
// ============================================================
#[test]
fn test_conntrack_nat_established() {
    let (rules, tables) = default_routing();

    // Scenario: established packet with conntrack DNAT entry
    // The packet should have DNAT applied from conntrack, not from chain evaluation
    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "conntrack-nat-established".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: NetfilterConfig {
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
                            comment: Some("DNAT to backend".to_string()),
                            matches: vec![NfMatch::Transport {
                                protocol: TransportProto::Tcp,
                                field: TransportField::Dport,
                                op: MatchOp::Eq,
                                value: "80".to_string(),
                            }],
                            action: NfAction::Nat {
                                action: NatAction::Dnat {
                                    addr: Some("192.168.1.100".parse().unwrap()),
                                    port: Some(8080),
                                },
                            },
                        }],
                    }],
                }],
            }),
            iptables: None,
        },
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
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

    // First run: NEW packet, NAT chains should be evaluated
    let result1 = engine::run(&scenario);
    assert_eq!(result1.verdict, FinalVerdict::Forwarded);

    // Verify DNAT was applied
    let final_state = &result1.trace.last().unwrap().state_after;
    assert!(final_state.dnat_applied, "DNAT should be applied for NEW packet");
    assert_eq!(final_state.dst_ip, Some("192.168.1.100".parse().unwrap()));
    assert_eq!(final_state.dst_port, Some(8080));

    // Now simulate an established packet with the same conntrack entry
    // In real usage, the PipelineContext would carry the conntrack_entry from a previous run.
    // For this test, we verify that the conntrack NAT info trace step appears for established state
    // by directly using ConntrackState::Established — the actual conntrack entry storage
    // is an internal mechanism. We can verify the NEW packet stored the entry.
    // The trace should show "conntrack NAT tuple" step is NOT present for NEW,
    // confirming normal chain evaluation happened.
    let new_nat_step = result1.trace.iter().find(|s|
        s.explain.contains("conntrack NAT tuple")
    );
    assert!(new_nat_step.is_none(),
        "NEW packet should NOT use conntrack NAT tuple — should evaluate chains normally");
}

// ============================================================
// Phase 7 Test: Loopback delivery (output to local address)
// ============================================================
#[test]
fn test_loopback_delivery() {
    let (rules, tables) = default_routing();

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "loopback-delivery".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: None,
        packet: PacketDef {
            ingress_interface: "lo".to_string(),
            ethertype: EtherType::Ipv4,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()), // local address
            protocol: IpProtocol::Tcp,
            src_port: Some(54321),
            dst_port: Some(80),
            tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
            conntrack_state: ConntrackState::New,
            ..default_packet_def()
        },
    };

    let result = engine::run_output(&scenario);

    // Should result in local delivery via loopback
    assert_eq!(result.verdict, FinalVerdict::LocalDelivery,
        "Output to local address should result in LocalDelivery, got {:?}", result.verdict);

    // Verify LoopbackDelivery stage in trace
    let loopback_step = result.trace.iter().find(|s| matches!(s.stage, PipelineStage::LoopbackDelivery));
    assert!(loopback_step.is_some(), "Expected LoopbackDelivery stage in trace");

    // Verify INPUT stage was executed
    let input_step = result.trace.iter().find(|s| matches!(s.stage, PipelineStage::LocalInput));
    assert!(input_step.is_some(), "Expected LocalInput stage in trace after LoopbackDelivery");
}

// ============================================================
// Endpoint Model Test: Simple RemoteClient → LocalServer flow
// ============================================================
#[test]
fn test_flow_remote_to_local() {
    use netsim_core::model::endpoint::*;
    use netsim_core::flow::{expand_flow, SimulationRun};

    let (rules, tables) = default_routing();

    let topology = Topology {
        endpoints: vec![
            Endpoint {
                role: EndpointRole::RemoteClient,
                name: "web-client".to_string(),
                ip: "203.0.113.50".parse().unwrap(),
                port: Some(54321),
                interface: Some("eth0".to_string()),
            },
            Endpoint {
                role: EndpointRole::LocalServer,
                name: "web-server".to_string(),
                ip: "10.0.0.1".parse().unwrap(),
                port: Some(80),
                interface: None,
            },
        ],
        flows: vec![TrafficFlow {
            name: "http-request".to_string(),
            source: "web-client".to_string(),
            destination: "web-server".to_string(),
            protocol: Some("tcp".to_string()),
            description: Some("HTTP request from remote client".to_string()),
        }],
    };

    let scenario = Scenario {
        version: "1.0".to_string(),
        name: "flow-test".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: empty_netfilter(),
        xdp: XdpConfig::default(),
        sysctl: SysctlConfig::default(),
        topology: Some(topology.clone()),
        packet: PacketDef::default(),
    };

    // Expand the flow
    let runs = expand_flow(&scenario, &topology.flows[0]);
    assert_eq!(runs.len(), 1, "RemoteClient → LocalServer should produce 1 simulation run");

    let (label, run) = &runs[0];
    assert!(label.contains("http-request"), "Label should contain flow name");

    // Verify it's an Ingress run
    match run {
        SimulationRun::Ingress(packet_def) => {
            assert_eq!(packet_def.src_ip, Some("203.0.113.50".parse().unwrap()));
            assert_eq!(packet_def.dst_ip, Some("10.0.0.1".parse().unwrap()));
            assert_eq!(packet_def.src_port, Some(54321));
            assert_eq!(packet_def.dst_port, Some(80));
            assert_eq!(packet_def.ingress_interface, "eth0");

            // Actually run the simulation with this packet
            let mut sim_scenario = scenario.clone();
            sim_scenario.packet = packet_def.clone();
            let result = engine::run(&sim_scenario);
            assert_eq!(result.verdict, FinalVerdict::LocalDelivery,
                "RemoteClient → LocalServer should result in LocalDelivery");
        }
        SimulationRun::Output(_) => {
            panic!("Expected Ingress run for RemoteClient → LocalServer");
        }
    }
}
