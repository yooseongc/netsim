//! 세션 단위 시뮬레이션 테스트

use netsim_core::model::interface::*;
use netsim_core::model::nat::NatAction;
use netsim_core::model::netfilter::*;
use netsim_core::model::packet::*;
use netsim_core::model::policy_routing::*;
use netsim_core::model::routing::*;
use netsim_core::model::scenario::Scenario;
use netsim_core::model::session::*;
use netsim_core::model::xdp::*;
use netsim_core::session_engine::{self, SessionVerdict};
use netsim_core::trace::FinalVerdict;

fn default_interfaces() -> Vec<Interface> {
    vec![
        Interface {
            name: "eth0".to_string(),
            index: 2,
            mac: None,
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
            mac: None,
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

fn default_routing() -> (Vec<IpRule>, Vec<RoutingTable>) {
    let rules = vec![
        IpRule {
            priority: 0,
            selector: RuleSelector::default(),
            action: RuleAction::Lookup(255),
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

fn base_scenario() -> Scenario {
    let (rules, tables) = default_routing();
    Scenario {
        version: "1.0".to_string(),
        name: "session-test".to_string(),
        description: None,
        interfaces: default_interfaces(),
        routing_tables: tables,
        ip_rules: rules,
        netfilter: NetfilterConfig::default(),
        xdp: XdpConfig::default(),
        packet: PacketDef::default(), // placeholder, will be overridden
    }
}

// ============================================================
// 세션 1: TCP Handshake → 로컬 서버
// ============================================================
#[test]
fn test_tcp_handshake_to_local() {
    let session = SessionDef {
        session_type: SessionType::TcpHandshake {
            client: SessionEndpoint {
                ip: "10.0.0.100".parse().unwrap(),
                port: Some(54321),
                interface: "eth0".to_string(),
                mac: None,
            },
            server: SessionEndpoint {
                ip: "10.0.0.1".parse().unwrap(),
                port: Some(80),
                interface: "eth0".to_string(),
                mac: None,
            },
            include_data: false,
            include_close: false,
        },
    };

    let result = session_engine::run_session(&base_scenario(), &session);
    assert_eq!(result.session_verdict, SessionVerdict::Established);
    assert_eq!(result.packet_results.len(), 3); // SYN, SYN-ACK, ACK

    // SYN: client(10.0.0.100) → server(10.0.0.1) → local delivery
    assert_eq!(result.packet_results[0].result.verdict, FinalVerdict::LocalDelivery);
    // SYN-ACK: server(10.0.0.1) → client(10.0.0.100) → forwarded (같은 서브넷이지만 로컬 아님)
    assert_eq!(result.packet_results[1].result.verdict, FinalVerdict::Forwarded);
    // ACK: client(10.0.0.100) → server(10.0.0.1) → local delivery
    assert_eq!(result.packet_results[2].result.verdict, FinalVerdict::LocalDelivery);
}

// ============================================================
// 세션 2: ICMP Ping (Echo Request + Echo Reply)
// ============================================================
#[test]
fn test_icmp_ping_session() {
    let session = SessionDef {
        session_type: SessionType::IcmpEcho {
            source: SessionEndpoint {
                ip: "10.0.0.100".parse().unwrap(),
                port: None,
                interface: "eth0".to_string(),
                mac: None,
            },
            destination: SessionEndpoint {
                ip: "10.0.0.1".parse().unwrap(),
                port: None,
                interface: "eth0".to_string(),
                mac: None,
            },
            ipv6: false,
        },
    };

    let result = session_engine::run_session(&base_scenario(), &session);
    assert_eq!(result.session_verdict, SessionVerdict::Established);
    assert_eq!(result.packet_results.len(), 2);

    assert_eq!(result.packet_results[0].label, "ICMP Echo Request");
    assert_eq!(result.packet_results[1].label, "ICMP Echo Reply");
}

// ============================================================
// 세션 3: TCP Handshake with DNAT (NAT 매핑이 reply에 반영)
// ============================================================
#[test]
fn test_tcp_session_with_dnat() {
    let mut scenario = base_scenario();
    scenario.netfilter = NetfilterConfig {
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
    };

    let session = SessionDef {
        session_type: SessionType::TcpHandshake {
            client: SessionEndpoint {
                ip: "10.0.0.100".parse().unwrap(),
                port: Some(54321),
                interface: "eth0".to_string(),
                mac: None,
            },
            server: SessionEndpoint {
                ip: "10.0.0.1".parse().unwrap(), // VIP → DNAT to 192.168.1.100:8080
                port: Some(80),
                interface: "eth1".to_string(),
                mac: None,
            },
            include_data: false,
            include_close: false,
        },
    };

    let result = session_engine::run_session(&scenario, &session);

    // SYN: DNAT 적용 → 192.168.1.100:8080으로 포워딩
    let syn_result = &result.packet_results[0];
    assert_eq!(syn_result.label, "TCP SYN");
    assert_eq!(syn_result.result.verdict, FinalVerdict::Forwarded);
    assert!(syn_result.result.summary.nat_applied);

    // SYN-ACK: reply는 NAT 매핑 반영 (src=192.168.1.100:8080, dst=10.0.0.100:54321)
    let syn_ack_result = &result.packet_results[1];
    assert_eq!(syn_ack_result.label, "TCP SYN-ACK");
    // reply 패킷의 src가 DNAT된 주소(192.168.1.100)로 조정됨
    let syn_ack_trace = &syn_ack_result.result.trace;
    let first_state = &syn_ack_trace[0].state_before;
    assert_eq!(first_state.src_ip, Some("192.168.1.100".parse().unwrap()));
    assert_eq!(first_state.src_port, Some(8080));
}

// ============================================================
// 세션 4: 방화벽에 의해 실패하는 세션
// ============================================================
#[test]
fn test_tcp_session_blocked_by_firewall() {
    let mut scenario = base_scenario();
    scenario.netfilter = NetfilterConfig {
        nftables: Some(NftablesRuleset {
            tables: vec![NfTable {
                family: NfFamily::Ip,
                name: "filter".to_string(),
                chains: vec![NfChain {
                    name: "input".to_string(),
                    chain_type: Some(NfChainType::Filter),
                    hook: Some(NfHook::Input),
                    priority: Some(0),
                    policy: Some(NfVerdict::Drop), // 모든 입력 차단
                    rules: vec![],
                }],
            }],
        }),
        iptables: None,
    };

    let session = SessionDef {
        session_type: SessionType::TcpHandshake {
            client: SessionEndpoint {
                ip: "10.0.0.100".parse().unwrap(),
                port: Some(54321),
                interface: "eth0".to_string(),
                mac: None,
            },
            server: SessionEndpoint {
                ip: "10.0.0.1".parse().unwrap(),
                port: Some(22),
                interface: "eth0".to_string(),
                mac: None,
            },
            include_data: false,
            include_close: false,
        },
    };

    let result = session_engine::run_session(&scenario, &session);

    // SYN이 INPUT에서 DROP → 세션 실패
    assert!(matches!(result.session_verdict, SessionVerdict::Failed { .. }));
    assert_eq!(result.packet_results.len(), 1); // SYN만 시도
    assert_eq!(result.packet_results[0].result.verdict, FinalVerdict::Drop);
}

// ============================================================
// 세션 5: UDP DNS 교환
// ============================================================
#[test]
fn test_udp_dns_session() {
    let session = SessionDef {
        session_type: SessionType::UdpExchange {
            client: SessionEndpoint {
                ip: "10.0.0.100".parse().unwrap(),
                port: Some(12345),
                interface: "eth0".to_string(),
                mac: None,
            },
            server: SessionEndpoint {
                ip: "10.0.0.1".parse().unwrap(),
                port: Some(53),
                interface: "eth0".to_string(),
                mac: None,
            },
        },
    };

    let result = session_engine::run_session(&base_scenario(), &session);
    assert_eq!(result.session_verdict, SessionVerdict::Established);
    assert_eq!(result.packet_results.len(), 2);
    assert_eq!(result.packet_results[0].label, "UDP Request");
    assert_eq!(result.packet_results[1].label, "UDP Reply");
}

// ============================================================
// 세션 6: TCP with DATA + CLOSE
// ============================================================
#[test]
fn test_tcp_full_session_with_data_and_close() {
    let session = SessionDef {
        session_type: SessionType::TcpHandshake {
            client: SessionEndpoint {
                ip: "10.0.0.100".parse().unwrap(),
                port: Some(54321),
                interface: "eth0".to_string(),
                mac: None,
            },
            server: SessionEndpoint {
                ip: "10.0.0.1".parse().unwrap(),
                port: Some(443),
                interface: "eth0".to_string(),
                mac: None,
            },
            include_data: true,
            include_close: true,
        },
    };

    let result = session_engine::run_session(&base_scenario(), &session);
    assert_eq!(result.session_verdict, SessionVerdict::Established);
    // SYN + SYN-ACK + ACK + DATA×2 + FIN + FIN-ACK = 7
    assert_eq!(result.packet_results.len(), 7);
    assert_eq!(result.packet_results[0].label, "TCP SYN");
    assert_eq!(result.packet_results[3].label, "TCP DATA (client→server)");
    assert_eq!(result.packet_results[5].label, "TCP FIN (client→server)");
}
