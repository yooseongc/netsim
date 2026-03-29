//! Chain evaluation logic for netfilter
//!
//! Contains all chain collection, evaluation, and helper functions for
//! processing nftables and iptables chains.

use crate::model::netfilter::{
    NfAction, NfHook, NfRule, NfVerdict, NetfilterConfig,
};
use crate::model::packet::PacketState;
use crate::matcher::evaluate_matches;
use crate::trace::{MatchedRuleRef, RuleSource, StageDecision};

use super::nat::apply_nat;
use super::StageResult;

/// 우선순위와 함께 정렬된 체인 항목 (nftables 또는 iptables 출처)
#[derive(Debug, Clone)]
pub struct OrderedChain {
    pub source: RuleSource,
    pub table_name: String,
    pub chain_name: String,
    pub priority: i32,
    pub policy: Option<NfVerdict>,
    pub rules: Vec<NfRule>,
}

/// 체인 평가 결과
#[derive(Debug)]
pub struct ChainEvalResult {
    pub decision: Option<StageDecision>,
    pub matched_rules: Vec<MatchedRuleRef>,
    pub stop: bool,
}

/// NetfilterConfig에서 특정 hook에 해당하는 모든 체인을 수집하고 priority로 정렬
pub fn collect_chains_for_hook(
    config: &NetfilterConfig,
    hook: &NfHook,
) -> Vec<OrderedChain> {
    let mut chains: Vec<OrderedChain> = Vec::new();

    // nftables 체인 수집
    if let Some(nft) = &config.nftables {
        for table in &nft.tables {
            for chain in &table.chains {
                if chain.hook.as_ref() == Some(hook) {
                    chains.push(OrderedChain {
                        source: RuleSource::Nftables,
                        table_name: table.name.clone(),
                        chain_name: chain.name.clone(),
                        priority: chain.priority.unwrap_or(0),
                        policy: chain.policy.clone(),
                        rules: chain.rules.clone(),
                    });
                }
            }
        }
    }

    // iptables 체인 수집
    if let Some(ipt) = &config.iptables {
        for table in &ipt.tables {
            let hook_chain_name = hook_to_iptables_chain_name(hook);
            for chain in &table.chains {
                if chain.name.eq_ignore_ascii_case(&hook_chain_name) {
                    let priority = table.default_priority(hook);
                    chains.push(OrderedChain {
                        source: RuleSource::Iptables,
                        table_name: table.name.clone(),
                        chain_name: chain.name.clone(),
                        priority,
                        policy: chain.policy.clone(),
                        rules: chain.rules.clone(),
                    });
                }
            }
        }
    }

    // priority 오름차순 정렬
    chains.sort_by_key(|c| c.priority);
    chains
}

/// 특정 테이블의 모든 체인(base + user)을 수집한다.
/// Jump/Goto 대상 체인 조회에 사용.
pub fn collect_all_chains_in_tables(config: &NetfilterConfig) -> Vec<OrderedChain> {
    let mut chains = Vec::new();

    if let Some(nft) = &config.nftables {
        for table in &nft.tables {
            for chain in &table.chains {
                chains.push(OrderedChain {
                    source: RuleSource::Nftables,
                    table_name: table.name.clone(),
                    chain_name: chain.name.clone(),
                    priority: chain.priority.unwrap_or(0),
                    policy: chain.policy.clone(),
                    rules: chain.rules.clone(),
                });
            }
        }
    }

    if let Some(ipt) = &config.iptables {
        for table in &ipt.tables {
            for chain in &table.chains {
                chains.push(OrderedChain {
                    source: RuleSource::Iptables,
                    table_name: table.name.clone(),
                    chain_name: chain.name.clone(),
                    priority: 0,
                    policy: chain.policy.clone(),
                    rules: chain.rules.clone(),
                });
            }
        }
    }

    chains
}

/// 체인의 규칙을 평가하여 결과 반환.
/// NAT 액션이 있으면 PacketState를 직접 수정한다.
/// `config`는 Jump/Goto 대상의 커스텀 체인 조회에 사용한다.
/// returns: (decision, matched_rules, should_stop)
///   should_stop=true이면 이후 체인도 중단
pub fn evaluate_chain(
    chain: &OrderedChain,
    state: &mut PacketState,
    interfaces: &[crate::model::interface::Interface],
) -> ChainEvalResult {
    evaluate_chain_inner(chain, state, interfaces, &[], 0)
}

/// 체인 평가 내부 함수 (커스텀 체인 재귀 지원)
/// `all_chains_in_table`은 Jump/Goto 대상을 찾기 위한 같은 테이블의 모든 체인.
/// `depth`는 무한 재귀 방지용 (최대 16단계).
fn evaluate_chain_inner(
    chain: &OrderedChain,
    state: &mut PacketState,
    interfaces: &[crate::model::interface::Interface],
    all_chains_in_table: &[OrderedChain],
    depth: u32,
) -> ChainEvalResult {
    const MAX_CHAIN_DEPTH: u32 = 16;
    let mut matched_rules = Vec::new();

    for (idx, rule) in chain.rules.iter().enumerate() {
        if !evaluate_matches(&rule.matches, state) {
            continue;
        }

        let rule_ref = MatchedRuleRef {
            source: chain.source.clone(),
            table: chain.table_name.clone(),
            chain: chain.chain_name.clone(),
            rule_index: idx,
            rule_summary: format_rule_summary(rule),
        };
        matched_rules.push(rule_ref);

        match &rule.action {
            NfAction::Verdict { verdict } => match verdict {
                NfVerdict::Accept => {
                    return ChainEvalResult {
                        decision: Some(StageDecision::Accept),
                        matched_rules,
                        stop: true,
                    };
                }
                NfVerdict::Drop => {
                    return ChainEvalResult {
                        decision: Some(StageDecision::Drop {
                            reason: format!(
                                "Dropped by {} {}/{}",
                                source_label(&chain.source),
                                chain.table_name,
                                chain.chain_name
                            ),
                        }),
                        matched_rules,
                        stop: true,
                    };
                }
                NfVerdict::Reject => {
                    return ChainEvalResult {
                        decision: Some(StageDecision::Reject {
                            reason: format!(
                                "Rejected by {} {}/{}",
                                source_label(&chain.source),
                                chain.table_name,
                                chain.chain_name
                            ),
                        }),
                        matched_rules,
                        stop: true,
                    };
                }
                NfVerdict::Continue => {
                    // continue evaluating next rule
                }
                NfVerdict::Queue => {
                    return ChainEvalResult {
                        decision: Some(StageDecision::Stolen),
                        matched_rules,
                        stop: true,
                    };
                }
            },
            NfAction::Nat { action: nat_action } => {
                apply_nat(nat_action, state, interfaces);
                return ChainEvalResult {
                    decision: Some(StageDecision::Accept),
                    matched_rules,
                    stop: false,
                };
            }
            NfAction::SetMark { value, mask } => {
                let new_mark = match mask {
                    Some(m) => (state.mark & !m) | (value & m),
                    None => *value,
                };
                state.mark = new_mark;
            }
            NfAction::Log { .. } | NfAction::Counter => {
                // non-terminating actions
            }
            NfAction::Jump { target } => {
                // Jump: 타겟 체인 평가 후 Return 시 현재 체인의 다음 규칙으로 복귀
                if depth >= MAX_CHAIN_DEPTH {
                    continue; // 무한 재귀 방지
                }
                if let Some(target_chain) = find_user_chain(all_chains_in_table, &chain.table_name, target) {
                    let sub_result = evaluate_chain_inner(
                        &target_chain, state, interfaces, all_chains_in_table, depth + 1,
                    );
                    matched_rules.extend(sub_result.matched_rules);
                    // 타겟 체인에서 terminal decision이 나오면 전파
                    if let Some(decision) = sub_result.decision {
                        match &decision {
                            StageDecision::Continue => {
                                // Return from target chain → continue in current chain
                            }
                            _ => {
                                // Accept/Drop/Reject/Stolen → 전파
                                return ChainEvalResult {
                                    decision: Some(decision),
                                    matched_rules,
                                    stop: sub_result.stop,
                                };
                            }
                        }
                    }
                    // target chain에서 decision=None (no match, no policy) → continue in current chain
                }
            }
            NfAction::Goto { target } => {
                // Goto: 타겟 체인으로 이동, Return 시 현재 체인이 아닌 base chain 정책으로
                // 구현: 타겟 체인 평가 후 현재 체인 종료 (다음 규칙으로 복귀하지 않음)
                if depth >= MAX_CHAIN_DEPTH {
                    continue;
                }
                if let Some(target_chain) = find_user_chain(all_chains_in_table, &chain.table_name, target) {
                    let sub_result = evaluate_chain_inner(
                        &target_chain, state, interfaces, all_chains_in_table, depth + 1,
                    );
                    matched_rules.extend(sub_result.matched_rules);
                    if let Some(decision) = sub_result.decision {
                        return ChainEvalResult {
                            decision: Some(decision),
                            matched_rules,
                            stop: sub_result.stop,
                        };
                    }
                    // Goto에서 no decision → base chain policy로 (현재 체인 종료)
                    break;
                }
            }
            NfAction::Return => {
                // Return: 호출한 체인(Jump)으로 복귀하거나, base chain이면 정책 적용
                break;
            }
        }
    }

    // No terminal rule matched → apply chain policy
    if let Some(policy) = &chain.policy {
        match policy {
            NfVerdict::Accept => {
                return ChainEvalResult {
                    decision: None, // policy accept doesn't stop other chains
                    matched_rules,
                    stop: false,
                };
            }
            NfVerdict::Drop => {
                return ChainEvalResult {
                    decision: Some(StageDecision::Drop {
                        reason: format!(
                            "Chain policy DROP in {} {}/{}",
                            source_label(&chain.source),
                            chain.table_name,
                            chain.chain_name
                        ),
                    }),
                    matched_rules,
                    stop: true,
                };
            }
            _ => {}
        }
    }

    ChainEvalResult {
        decision: None,
        matched_rules,
        stop: false,
    }
}

/// netfilter 체인 평가를 수행하는 공통 함수 (prerouting, input, forward, postrouting에서 사용)
pub fn evaluate_netfilter_hook(
    config: &NetfilterConfig,
    hook: &NfHook,
    state: &mut PacketState,
    interfaces: &[crate::model::interface::Interface],
) -> StageResult {
    // L2-only 패킷은 netfilter를 건너뛴다
    if state.ethertype.is_l2_only() {
        return StageResult::pass(format!(
            "L2-only packet ({}) bypasses netfilter {}",
            state.ethertype,
            hook_label(hook)
        ));
    }

    let chains = collect_chains_for_hook(config, hook);

    if chains.is_empty() {
        return StageResult::pass(format!(
            "No {} chains configured",
            hook_label(hook)
        ));
    }

    // 커스텀 체인 (Jump/Goto 대상) 조회를 위한 전체 체인 목록
    let all_table_chains = collect_all_chains_in_tables(config);

    let mut all_matched = Vec::new();
    let mut explanations = Vec::new();

    for chain in &chains {
        let result = evaluate_chain_inner(chain, state, interfaces, &all_table_chains, 0);
        all_matched.extend(result.matched_rules);

        if let Some(decision) = result.decision {
            match &decision {
                StageDecision::Drop { reason } => {
                    explanations.push(format!("DROP: {}", reason));
                    return StageResult {
                        decision,
                        matched_rules: all_matched,
                        explain: explanations.join("; "),
                    };
                }
                StageDecision::Reject { reason } => {
                    explanations.push(format!("REJECT: {}", reason));
                    return StageResult {
                        decision,
                        matched_rules: all_matched,
                        explain: explanations.join("; "),
                    };
                }
                StageDecision::Stolen => {
                    explanations.push("Packet stolen (QUEUE)".to_string());
                    return StageResult {
                        decision,
                        matched_rules: all_matched,
                        explain: explanations.join("; "),
                    };
                }
                StageDecision::Accept => {
                    explanations.push(format!(
                        "Accepted by {} {}/{}",
                        source_label(&chain.source),
                        chain.table_name,
                        chain.chain_name
                    ));
                    if result.stop {
                        // Terminal accept (verdict ACCEPT) — stop all chains
                        return StageResult {
                            decision: StageDecision::Continue,
                            matched_rules: all_matched,
                            explain: explanations.join("; "),
                        };
                    }
                    // NAT accept — continue to next chain
                }
                _ => {}
            }
        } else {
            explanations.push(format!(
                "Passed through {} {}/{} (policy: {:?})",
                source_label(&chain.source),
                chain.table_name,
                chain.chain_name,
                chain.policy
            ));
        }
    }

    StageResult {
        decision: StageDecision::Continue,
        matched_rules: all_matched,
        explain: if explanations.is_empty() {
            format!("Passed through all {} chains", hook_label(hook))
        } else {
            explanations.join("; ")
        },
    }
}

/// 사전 필터링된 체인 목록을 평가하는 함수 (prerouting split 등에서 사용)
pub fn evaluate_chains_subset(
    chains: &[OrderedChain],
    label: &str,
    state: &mut PacketState,
    interfaces: &[crate::model::interface::Interface],
    all_table_chains: &[OrderedChain],
) -> StageResult {
    // L2-only 패킷은 netfilter를 건너뛴다
    if state.ethertype.is_l2_only() {
        return StageResult::pass(format!(
            "L2-only packet ({}) bypasses netfilter {}",
            state.ethertype, label
        ));
    }

    if chains.is_empty() {
        return StageResult::pass(format!(
            "No {} chains configured", label
        ));
    }

    let mut all_matched = Vec::new();
    let mut explanations = Vec::new();

    for chain in chains {
        let result = evaluate_chain_inner(chain, state, interfaces, all_table_chains, 0);
        all_matched.extend(result.matched_rules);

        if let Some(decision) = result.decision {
            match &decision {
                StageDecision::Drop { reason } => {
                    explanations.push(format!("DROP: {}", reason));
                    return StageResult {
                        decision,
                        matched_rules: all_matched,
                        explain: explanations.join("; "),
                    };
                }
                StageDecision::Reject { reason } => {
                    explanations.push(format!("REJECT: {}", reason));
                    return StageResult {
                        decision,
                        matched_rules: all_matched,
                        explain: explanations.join("; "),
                    };
                }
                StageDecision::Stolen => {
                    explanations.push("Packet stolen (QUEUE)".to_string());
                    return StageResult {
                        decision,
                        matched_rules: all_matched,
                        explain: explanations.join("; "),
                    };
                }
                StageDecision::Accept => {
                    explanations.push(format!(
                        "Accepted by {} {}/{}",
                        source_label(&chain.source),
                        chain.table_name,
                        chain.chain_name
                    ));
                    if result.stop {
                        return StageResult {
                            decision: StageDecision::Continue,
                            matched_rules: all_matched,
                            explain: explanations.join("; "),
                        };
                    }
                }
                _ => {}
            }
        } else {
            explanations.push(format!(
                "Passed through {} {}/{} (policy: {:?})",
                source_label(&chain.source),
                chain.table_name,
                chain.chain_name,
                chain.policy
            ));
        }
    }

    StageResult {
        decision: StageDecision::Continue,
        matched_rules: all_matched,
        explain: if explanations.is_empty() {
            format!("Passed through all {} chains", label)
        } else {
            explanations.join("; ")
        },
    }
}

/// NfHook에 대응하는 iptables 체인 이름
pub fn hook_to_iptables_chain_name(hook: &NfHook) -> String {
    match hook {
        NfHook::Prerouting => "PREROUTING".to_string(),
        NfHook::Input => "INPUT".to_string(),
        NfHook::Forward => "FORWARD".to_string(),
        NfHook::Output => "OUTPUT".to_string(),
        NfHook::Postrouting => "POSTROUTING".to_string(),
    }
}

pub fn hook_label(hook: &NfHook) -> &'static str {
    match hook {
        NfHook::Prerouting => "PREROUTING",
        NfHook::Input => "INPUT",
        NfHook::Forward => "FORWARD",
        NfHook::Output => "OUTPUT",
        NfHook::Postrouting => "POSTROUTING",
    }
}

/// 규칙 요약 문자열 생성
pub fn format_rule_summary(rule: &NfRule) -> String {
    let match_str = if rule.matches.is_empty() {
        "any".to_string()
    } else {
        format!("{} match(es)", rule.matches.len())
    };
    let action_str = match &rule.action {
        NfAction::Verdict { verdict } => format!("{:?}", verdict),
        NfAction::Nat { action: nat } => format!("NAT({:?})", nat),
        NfAction::SetMark { value, mask } => {
            if let Some(m) = mask {
                format!("MARK(0x{:x}/0x{:x})", value, m)
            } else {
                format!("MARK(0x{:x})", value)
            }
        }
        NfAction::Log { prefix, .. } => format!(
            "LOG({})",
            prefix.as_deref().unwrap_or("")
        ),
        NfAction::Counter => "COUNTER".to_string(),
        NfAction::Jump { target } => format!("JUMP({})", target),
        NfAction::Goto { target } => format!("GOTO({})", target),
        NfAction::Return => "RETURN".to_string(),
    };
    let comment = rule
        .comment
        .as_deref()
        .map(|c| format!(" /* {} */", c))
        .unwrap_or_default();
    format!("{} -> {}{}", match_str, action_str, comment)
}

pub fn source_label(source: &RuleSource) -> &'static str {
    match source {
        RuleSource::Nftables => "nftables",
        RuleSource::Iptables => "iptables",
        RuleSource::Xdp => "XDP",
        RuleSource::Routing => "routing",
    }
}

/// 같은 테이블 내에서 이름으로 커스텀(user) 체인을 찾는다.
/// hook이 없는(base chain이 아닌) 체인, 또는 이름이 일치하는 체인을 반환.
pub fn find_user_chain(
    all_chains: &[OrderedChain],
    table_name: &str,
    chain_name: &str,
) -> Option<OrderedChain> {
    all_chains
        .iter()
        .find(|c| c.table_name == table_name && c.chain_name == chain_name)
        .cloned()
}
