//! 라우팅 결정 파이프라인 단계
//!
//! Policy routing (ip rule) → routing table lookup → 라우팅 결정
//!
//! 1. ip_rules를 priority 오름차순으로 순회
//! 2. 매칭되는 규칙의 action에 따라 routing table 참조
//! 3. 해당 테이블에서 dst_ip에 대해 longest prefix match
//! 4. route_type에 따라 결과 결정:
//!    - Local → LocalDelivery
//!    - Unicast + gateway → ForwardTo
//!    - Unicast (no gateway, on-link) → ForwardTo
//!    - Blackhole/Unreachable/Prohibit → terminal
//!    - Throw → 다음 ip rule로 이동
//! 5. dst_ip가 로컬 인터페이스 주소에 해당하면 Local delivery
//! 6. L2-only 패킷은 라우팅 대상이 아님 (엔진에서 처리)

use std::net::IpAddr;

use crate::model::interface::Interface;
use crate::model::packet::PacketState;
use crate::model::policy_routing::{IpRule, RuleAction, RuleSelector};
use crate::model::routing::{Route, RouteType, RoutingTable};
use crate::trace::{MatchedRuleRef, RuleSource, StageDecision};

use super::StageResult;

/// 라우팅 결정 단계를 실행한다.
pub fn execute(
    ip_rules: &[IpRule],
    routing_tables: &[RoutingTable],
    interfaces: &[Interface],
    state: &mut PacketState,
) -> StageResult {
    // L2-only 패킷은 라우팅 불필요
    if state.ethertype.is_l2_only() {
        return StageResult::pass(format!(
            "L2-only packet ({}) does not require IP routing",
            state.ethertype
        ));
    }

    let dst_ip = match state.dst_ip {
        Some(ip) => ip,
        None => {
            return StageResult::drop(
                "No destination IP for routing",
                "Packet has no dst_ip, cannot perform routing decision",
            );
        }
    };

    // 먼저 dst_ip가 로컬 인터페이스 주소인지 확인
    if is_local_address(&dst_ip, interfaces) {
        return StageResult {
            decision: StageDecision::LocalDelivery,
            matched_rules: Vec::new(),
            explain: format!(
                "Destination {} matches a local interface address → local delivery",
                dst_ip
            ),
        };
    }

    // ip rules를 priority 오름차순으로 정렬하여 평가
    let mut sorted_rules: Vec<&IpRule> = ip_rules.iter().collect();
    sorted_rules.sort_by_key(|r| r.priority);

    let mut explanations = Vec::new();
    let mut all_matched = Vec::new();

    for ip_rule in &sorted_rules {
        if !selector_matches(&ip_rule.selector, state) {
            continue;
        }

        match &ip_rule.action {
            RuleAction::Lookup(table_id) => {
                let table = routing_tables.iter().find(|t| t.id == *table_id);
                let table = match table {
                    Some(t) => t,
                    None => {
                        explanations.push(format!(
                            "ip rule prio {} → lookup table {} (not found, skip)",
                            ip_rule.priority, table_id
                        ));
                        continue;
                    }
                };

                match longest_prefix_match(&table.routes, &dst_ip) {
                    Some(route) => {
                        let table_id_str = table.id.to_string();
                        let table_name = table
                            .name
                            .as_deref()
                            .unwrap_or(&table_id_str);

                        let rule_ref = MatchedRuleRef {
                            source: RuleSource::Routing,
                            table: table_name.to_string(),
                            chain: format!("ip-rule-prio-{}", ip_rule.priority),
                            rule_index: 0,
                            rule_summary: format!(
                                "{} via {} dev {}",
                                route.destination,
                                route
                                    .gateway
                                    .map(|g| g.to_string())
                                    .unwrap_or_else(|| "direct".to_string()),
                                route.dev.as_deref().unwrap_or("?")
                            ),
                        };
                        all_matched.push(rule_ref);

                        match &route.route_type {
                            RouteType::Local => {
                                return StageResult {
                                    decision: StageDecision::LocalDelivery,
                                    matched_rules: all_matched,
                                    explain: format!(
                                        "Route {} in table {} is type local → local delivery",
                                        route.destination, table_name
                                    ),
                                };
                            }
                            RouteType::Broadcast => {
                                return StageResult {
                                    decision: StageDecision::LocalDelivery,
                                    matched_rules: all_matched,
                                    explain: format!(
                                        "Route {} in table {} is type broadcast → local delivery",
                                        route.destination, table_name
                                    ),
                                };
                            }
                            RouteType::Unicast => {
                                let egress = route
                                    .dev
                                    .clone()
                                    .unwrap_or_else(|| "unknown".to_string());
                                state.egress_if = Some(egress.clone());

                                return StageResult {
                                    decision: StageDecision::ForwardTo {
                                        egress_if: egress,
                                        next_hop: route.gateway,
                                    },
                                    matched_rules: all_matched,
                                    explain: format!(
                                        "Route {} via {} dev {} in table {}",
                                        route.destination,
                                        route
                                            .gateway
                                            .map(|g| g.to_string())
                                            .unwrap_or_else(|| "direct".to_string()),
                                        route.dev.as_deref().unwrap_or("?"),
                                        table_name
                                    ),
                                };
                            }
                            RouteType::Blackhole => {
                                return StageResult {
                                    decision: StageDecision::Drop {
                                        reason: format!(
                                            "Blackhole route for {} in table {}",
                                            dst_ip, table_name
                                        ),
                                    },
                                    matched_rules: all_matched,
                                    explain: format!(
                                        "Route {} in table {} is type blackhole",
                                        route.destination, table_name
                                    ),
                                };
                            }
                            RouteType::Unreachable => {
                                return StageResult {
                                    decision: StageDecision::Drop {
                                        reason: format!(
                                            "Unreachable route for {} in table {}",
                                            dst_ip, table_name
                                        ),
                                    },
                                    matched_rules: all_matched,
                                    explain: format!(
                                        "Route {} in table {} is type unreachable",
                                        route.destination, table_name
                                    ),
                                };
                            }
                            RouteType::Prohibit => {
                                return StageResult {
                                    decision: StageDecision::Drop {
                                        reason: format!(
                                            "Prohibited route for {} in table {}",
                                            dst_ip, table_name
                                        ),
                                    },
                                    matched_rules: all_matched,
                                    explain: format!(
                                        "Route {} in table {} is type prohibit",
                                        route.destination, table_name
                                    ),
                                };
                            }
                            RouteType::Throw => {
                                // Throw → try next ip rule
                                explanations.push(format!(
                                    "Route {} in table {} is type throw → try next rule",
                                    route.destination, table_name
                                ));
                                continue;
                            }
                        }
                    }
                    None => {
                        // 이 테이블에는 매칭 경로 없음 → 다음 ip rule
                        explanations.push(format!(
                            "ip rule prio {} → table {} has no matching route for {}",
                            ip_rule.priority,
                            table.name.as_deref().unwrap_or(&format!("{}", table.id)),
                            dst_ip
                        ));
                        continue;
                    }
                }
            }
            RuleAction::Blackhole => {
                return StageResult {
                    decision: StageDecision::Drop {
                        reason: format!(
                            "ip rule prio {} action blackhole",
                            ip_rule.priority
                        ),
                    },
                    matched_rules: all_matched,
                    explain: format!(
                        "ip rule prio {} matched with action blackhole",
                        ip_rule.priority
                    ),
                };
            }
            RuleAction::Unreachable => {
                return StageResult {
                    decision: StageDecision::Drop {
                        reason: format!(
                            "ip rule prio {} action unreachable",
                            ip_rule.priority
                        ),
                    },
                    matched_rules: all_matched,
                    explain: format!(
                        "ip rule prio {} matched with action unreachable",
                        ip_rule.priority
                    ),
                };
            }
            RuleAction::Prohibit => {
                return StageResult {
                    decision: StageDecision::Drop {
                        reason: format!(
                            "ip rule prio {} action prohibit",
                            ip_rule.priority
                        ),
                    },
                    matched_rules: all_matched,
                    explain: format!(
                        "ip rule prio {} matched with action prohibit",
                        ip_rule.priority
                    ),
                };
            }
        }
    }

    // 모든 ip rule을 소진했으나 경로를 찾지 못함
    StageResult {
        decision: StageDecision::Drop {
            reason: format!("No route to host {}", dst_ip),
        },
        matched_rules: all_matched,
        explain: if explanations.is_empty() {
            format!("No ip rules matched for destination {}", dst_ip)
        } else {
            format!(
                "No route found after evaluating all ip rules: {}",
                explanations.join("; ")
            )
        },
    }
}

/// dst_ip가 로컬 인터페이스 주소인지 확인
fn is_local_address(ip: &IpAddr, interfaces: &[Interface]) -> bool {
    interfaces.iter().any(|iface| {
        iface.addresses.iter().any(|addr| addr.ip == *ip)
    })
}

/// ip rule selector가 현재 패킷 상태에 매칭되는지 확인
fn selector_matches(selector: &RuleSelector, state: &PacketState) -> bool {
    // from (src address)
    if let Some(from) = &selector.from {
        match state.src_ip {
            Some(ip) => {
                if !from.contains(&ip) {
                    return false;
                }
            }
            None => return false,
        }
    }

    // to (dst address)
    if let Some(to) = &selector.to {
        match state.dst_ip {
            Some(ip) => {
                if !to.contains(&ip) {
                    return false;
                }
            }
            None => return false,
        }
    }

    // fwmark
    if let Some(fwmark) = selector.fwmark {
        let mask = selector.fwmask.unwrap_or(0xFFFF_FFFF);
        if (state.mark & mask) != (fwmark & mask) {
            return false;
        }
    }

    // iif
    if let Some(iif) = &selector.iif {
        if state.ingress_if != *iif {
            return false;
        }
    }

    // oif
    if let Some(oif) = &selector.oif {
        match &state.egress_if {
            Some(egress) => {
                if egress != oif {
                    return false;
                }
            }
            None => return false,
        }
    }

    // ipproto
    if let Some(proto) = selector.ipproto {
        if state.protocol.protocol_number() != proto {
            return false;
        }
    }

    // sport
    if let Some(range) = &selector.sport {
        match state.src_port {
            Some(p) => {
                if p < range.start || p > range.end {
                    return false;
                }
            }
            None => return false,
        }
    }

    // dport
    if let Some(range) = &selector.dport {
        match state.dst_port {
            Some(p) => {
                if p < range.start || p > range.end {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

/// Longest prefix match: 가장 구체적인 (prefix length가 큰) 매칭 경로를 반환
fn longest_prefix_match<'a>(routes: &'a [Route], dst_ip: &IpAddr) -> Option<&'a Route> {
    let mut best: Option<&Route> = None;
    let mut best_prefix_len: u8 = 0;

    for route in routes {
        if !route.destination.contains(dst_ip) {
            continue;
        }
        let prefix_len = route.destination.prefix_len();
        if best.is_none() || prefix_len > best_prefix_len {
            best = Some(route);
            best_prefix_len = prefix_len;
        } else if prefix_len == best_prefix_len {
            // 같은 prefix length에서는 metric이 낮은 것 우선
            if let Some(current_best) = best {
                if route.metric < current_best.metric {
                    best = Some(route);
                }
            }
        }
    }

    best
}
