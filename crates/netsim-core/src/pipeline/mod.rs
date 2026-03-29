pub mod xdp;
pub mod tc_ingress;
pub mod prerouting;
pub mod routing;
pub mod local_input;
pub mod forward;
pub mod postrouting;

use crate::model::netfilter::{
    NfAction, NfHook, NfRule, NfVerdict, NetfilterConfig,
};
use crate::model::nat::NatAction;
use crate::model::packet::PacketState;
use crate::matcher::evaluate_matches;
use crate::trace::{MatchedRuleRef, RuleSource, StageDecision};

/// 파이프라인 각 단계의 공통 결과 타입
#[derive(Debug, Clone)]
pub struct StageResult {
    pub decision: StageDecision,
    pub matched_rules: Vec<MatchedRuleRef>,
    pub explain: String,
}

impl StageResult {
    pub fn pass(explain: impl Into<String>) -> Self {
        Self {
            decision: StageDecision::Continue,
            matched_rules: Vec::new(),
            explain: explain.into(),
        }
    }

    pub fn drop(reason: impl Into<String>, explain: impl Into<String>) -> Self {
        Self {
            decision: StageDecision::Drop {
                reason: reason.into(),
            },
            matched_rules: Vec::new(),
            explain: explain.into(),
        }
    }

    pub fn accept(explain: impl Into<String>) -> Self {
        Self {
            decision: StageDecision::Accept,
            matched_rules: Vec::new(),
            explain: explain.into(),
        }
    }
}

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

/// NfHook에 대응하는 iptables 체인 이름
fn hook_to_iptables_chain_name(hook: &NfHook) -> String {
    match hook {
        NfHook::Prerouting => "PREROUTING".to_string(),
        NfHook::Input => "INPUT".to_string(),
        NfHook::Forward => "FORWARD".to_string(),
        NfHook::Output => "OUTPUT".to_string(),
        NfHook::Postrouting => "POSTROUTING".to_string(),
    }
}

/// 체인의 규칙을 평가하여 결과 반환.
/// NAT 액션이 있으면 PacketState를 직접 수정한다.
/// returns: (decision, matched_rules, should_stop)
///   should_stop=true이면 이후 체인도 중단
pub fn evaluate_chain(
    chain: &OrderedChain,
    state: &mut PacketState,
    interfaces: &[crate::model::interface::Interface],
) -> ChainEvalResult {
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
                    // treat as stolen for simulation purposes
                    return ChainEvalResult {
                        decision: Some(StageDecision::Stolen),
                        matched_rules,
                        stop: true,
                    };
                }
            },
            NfAction::Nat { action: nat_action } => {
                apply_nat(nat_action, state, interfaces);
                // NAT rules implicitly accept in their chain
                return ChainEvalResult {
                    decision: Some(StageDecision::Accept),
                    matched_rules,
                    stop: false, // NAT accept doesn't stop other chains
                };
            }
            NfAction::SetMark { value, mask } => {
                let new_mark = match mask {
                    Some(m) => (state.mark & !m) | (value & m),
                    None => *value,
                };
                state.mark = new_mark;
                // continue evaluating
            }
            NfAction::Log { .. } | NfAction::Counter => {
                // non-terminating actions, continue
            }
            NfAction::Jump { .. } | NfAction::Goto { .. } => {
                // jump/goto to user chains — for MVP, treat as continue
                // (full implementation would recurse into the target chain)
            }
            NfAction::Return => {
                // return to chain policy
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

/// 체인 평가 결과
#[derive(Debug)]
pub struct ChainEvalResult {
    pub decision: Option<StageDecision>,
    pub matched_rules: Vec<MatchedRuleRef>,
    pub stop: bool,
}

/// NAT 액션을 PacketState에 적용
pub fn apply_nat(
    nat_action: &NatAction,
    state: &mut PacketState,
    interfaces: &[crate::model::interface::Interface],
) {
    match nat_action {
        NatAction::Dnat { addr, port } => {
            if !state.dnat_applied {
                state.original_dst_ip = state.dst_ip;
                state.original_dst_port = state.dst_port;
            }
            if let Some(a) = addr {
                state.dst_ip = Some(*a);
            }
            // ICMP has no ports — only set port for port-based protocols
            if state.has_ports() {
                if let Some(p) = port {
                    state.dst_port = Some(*p);
                }
            }
            state.dnat_applied = true;
        }
        NatAction::Snat { addr, port } => {
            if !state.snat_applied {
                state.original_src_ip = state.src_ip;
                state.original_src_port = state.src_port;
            }
            if let Some(a) = addr {
                state.src_ip = Some(*a);
            }
            if state.has_ports() {
                if let Some(p) = port {
                    state.src_port = Some(*p);
                }
            }
            state.snat_applied = true;
        }
        NatAction::Masquerade { port } => {
            // Use egress interface's IP address matching packet's address family
            if !state.snat_applied {
                state.original_src_ip = state.src_ip;
                state.original_src_port = state.src_port;
            }
            if let Some(egress_name) = &state.egress_if {
                let masq_ip = crate::model::interface::find_interface_ip(interfaces, egress_name, state.src_ip);
                if let Some(ip) = masq_ip {
                    state.src_ip = Some(ip);
                }
            }
            if state.has_ports() {
                if let Some(p) = port {
                    state.src_port = Some(*p);
                }
            }
            state.snat_applied = true;
        }
        NatAction::Redirect { port } => {
            // REDIRECT changes dst to local address on ingress interface
            if !state.dnat_applied {
                state.original_dst_ip = state.dst_ip;
                state.original_dst_port = state.dst_port;
            }
            // Use ingress interface's IP matching packet's address family
            let local_ip = crate::model::interface::find_interface_ip(interfaces, &state.ingress_if, state.dst_ip);
            if let Some(ip) = local_ip {
                state.dst_ip = Some(ip);
            }
            if state.has_ports() {
                if let Some(p) = port {
                    state.dst_port = Some(*p);
                }
            }
            state.dnat_applied = true;
        }
        NatAction::Tproxy { addr, port, mark } => {
            if !state.dnat_applied {
                state.original_dst_ip = state.dst_ip;
                state.original_dst_port = state.dst_port;
            }
            if let Some(a) = addr {
                state.dst_ip = Some(*a);
            }
            if state.has_ports() {
                state.dst_port = Some(*port);
            }
            if let Some(m) = mark {
                state.mark = *m;
            }
            state.dnat_applied = true;
        }
    }
}

/// 규칙 요약 문자열 생성
fn format_rule_summary(rule: &NfRule) -> String {
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

fn source_label(source: &RuleSource) -> &'static str {
    match source {
        RuleSource::Nftables => "nftables",
        RuleSource::Iptables => "iptables",
        RuleSource::Xdp => "XDP",
        RuleSource::Routing => "routing",
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

    let mut all_matched = Vec::new();
    let mut explanations = Vec::new();

    for chain in &chains {
        let result = evaluate_chain(chain, state, interfaces);
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

fn hook_label(hook: &NfHook) -> &'static str {
    match hook {
        NfHook::Prerouting => "PREROUTING",
        NfHook::Input => "INPUT",
        NfHook::Forward => "FORWARD",
        NfHook::Output => "OUTPUT",
        NfHook::Postrouting => "POSTROUTING",
    }
}
