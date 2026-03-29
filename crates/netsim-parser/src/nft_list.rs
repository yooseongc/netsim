//! `nft list ruleset` 출력 파서
//!
//! nftables 규칙 셋 출력을 파싱하여 `NftablesRuleset`로 변환한다.
//! 실용적 수준에서 일반적인 nftables 표현식을 지원하며,
//! 파싱할 수 없는 항목은 `ValidationReport`에 기록한다.

use std::net::IpAddr;

use netsim_core::model::{
    NatAction, NfAction, NfChain, NfChainType, NfFamily, NfHook, NfMatch, NfRule, NfTable,
    NfVerdict, NftablesRuleset,
    CtKey, IpField, MatchOp, MetaKey, TransportField, TransportProto,
};

use crate::validation::{ParseResult, ValidationReport};

/// nftables priority 이름을 숫자로 변환한다.
fn priority_name_to_value(name: &str) -> Option<i32> {
    match name {
        "raw" => Some(-300),
        "mangle" => Some(-150),
        "dstnat" => Some(-100),
        "filter" => Some(0),
        "security" => Some(50),
        "srcnat" => Some(100),
        _ => name.parse::<i32>().ok(),
    }
}

/// `nft list ruleset` 출력을 파싱한다.
pub fn parse_nft_list(input: &str) -> ParseResult<NftablesRuleset> {
    let mut ruleset = NftablesRuleset::default();
    let mut report = ValidationReport::new();

    let lines: Vec<&str> = input.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        // table 시작: "table ip filter {"
        if line.starts_with("table ") && line.ends_with('{') {
            let (table, end_idx) = parse_table(&lines, i, &mut report);
            if let Some(t) = table {
                report.add_ok(format!("Parsed nft table {} {}", format_family(&t.family), &t.name));
                ruleset.tables.push(t);
            }
            i = end_idx + 1;
        } else {
            i += 1;
        }
    }

    report.add_ok(format!("Total {} nft tables parsed", ruleset.tables.len()));

    ParseResult {
        data: ruleset,
        report,
    }
}

fn format_family(f: &NfFamily) -> &'static str {
    match f {
        NfFamily::Ip => "ip",
        NfFamily::Ip6 => "ip6",
        NfFamily::Inet => "inet",
        NfFamily::Bridge => "bridge",
        NfFamily::Arp => "arp",
    }
}

/// table 블록을 파싱한다. 반환값은 (파싱된 테이블, 닫는 중괄호의 라인 인덱스).
fn parse_table(
    lines: &[&str],
    start: usize,
    report: &mut ValidationReport,
) -> (Option<NfTable>, usize) {
    let header = lines[start].trim();
    // "table ip filter {"
    let header = header.trim_end_matches('{').trim();
    let parts: Vec<&str> = header.split_whitespace().collect();

    if parts.len() < 3 {
        report.add_partial(format!("Invalid table header: {}", lines[start]));
        // Find closing brace
        let end = find_closing_brace(lines, start);
        return (None, end);
    }

    let family = parse_family(parts[1]);
    let name = parts[2].to_string();

    let mut chains = Vec::new();
    let mut i = start + 1;

    while i < lines.len() {
        let line = lines[i].trim();

        if line == "}" {
            // End of table
            break;
        }

        if line.starts_with("chain ") && line.ends_with('{') {
            let (chain, end_idx) = parse_chain(lines, i, report);
            if let Some(c) = chain {
                chains.push(c);
            }
            i = end_idx + 1;
        } else {
            i += 1;
        }
    }

    let table = NfTable {
        family,
        name,
        chains,
    };

    (Some(table), i)
}

/// chain 블록을 파싱한다.
fn parse_chain(
    lines: &[&str],
    start: usize,
    report: &mut ValidationReport,
) -> (Option<NfChain>, usize) {
    let header = lines[start].trim();
    // "chain input {"
    let header = header.trim_end_matches('{').trim();
    let parts: Vec<&str> = header.split_whitespace().collect();

    let chain_name = if parts.len() >= 2 {
        parts[1].to_string()
    } else {
        report.add_partial(format!("Invalid chain header: {}", lines[start]));
        let end = find_closing_brace(lines, start);
        return (None, end);
    };

    let mut chain_type = None;
    let mut hook = None;
    let mut priority = None;
    let mut policy = None;
    let mut rules = Vec::new();
    let mut i = start + 1;

    while i < lines.len() {
        let line = lines[i].trim();

        if line == "}" {
            break;
        }

        // Check for chain type declaration:
        // "type filter hook input priority filter; policy accept;"
        if line.starts_with("type ") {
            let (ct, h, p, pol) = parse_chain_type_line(line);
            chain_type = ct;
            hook = h;
            priority = p;
            policy = pol;
            i += 1;
            continue;
        }

        // Parse rule line
        if !line.is_empty() {
            match parse_nf_rule_line(line) {
                Ok(rule) => rules.push(rule),
                Err(msg) => {
                    report.add_partial(format!(
                        "Unsupported nft rule in chain '{}': {} ({})",
                        chain_name, line, msg
                    ));
                }
            }
        }

        i += 1;
    }

    let chain = NfChain {
        name: chain_name,
        chain_type,
        hook,
        priority,
        policy,
        rules,
    };

    (Some(chain), i)
}

/// 체인 타입 선언 라인을 파싱한다.
/// "type filter hook input priority filter; policy accept;"
fn parse_chain_type_line(
    line: &str,
) -> (Option<NfChainType>, Option<NfHook>, Option<i32>, Option<NfVerdict>) {
    let mut chain_type = None;
    let mut hook = None;
    let mut priority = None;
    let mut policy = None;

    // Remove semicolons for easier tokenization
    let clean = line.replace(';', " ");
    let tokens: Vec<&str> = clean.split_whitespace().collect();

    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            "type" => {
                i += 1;
                if i < tokens.len() {
                    chain_type = Some(match tokens[i] {
                        "filter" => NfChainType::Filter,
                        "nat" => NfChainType::Nat,
                        "route" => NfChainType::Route,
                        "mangle" => NfChainType::Mangle,
                        _ => NfChainType::Filter,
                    });
                }
            }
            "hook" => {
                i += 1;
                if i < tokens.len() {
                    hook = Some(match tokens[i] {
                        "prerouting" => NfHook::Prerouting,
                        "input" => NfHook::Input,
                        "forward" => NfHook::Forward,
                        "output" => NfHook::Output,
                        "postrouting" => NfHook::Postrouting,
                        _ => NfHook::Input,
                    });
                }
            }
            "priority" => {
                i += 1;
                if i < tokens.len() {
                    priority = priority_name_to_value(tokens[i]);
                }
            }
            "policy" => {
                i += 1;
                if i < tokens.len() {
                    policy = Some(parse_verdict(tokens[i]));
                }
            }
            _ => {}
        }
        i += 1;
    }

    (chain_type, hook, priority, policy)
}

/// 단일 nftables 규칙 라인을 파싱한다.
fn parse_nf_rule_line(line: &str) -> Result<NfRule, String> {
    let tokens = tokenize_nf_rule(line);
    if tokens.is_empty() {
        return Err("empty rule".to_string());
    }

    let mut matches = Vec::new();
    let mut action = None;
    let mut i = 0;

    while i < tokens.len() {
        let tok = &tokens[i];

        match tok.as_str() {
            // --- Actions (terminal) ---
            "accept" => {
                action = Some(NfAction::Verdict {
                    verdict: NfVerdict::Accept,
                });
            }
            "drop" => {
                action = Some(NfAction::Verdict {
                    verdict: NfVerdict::Drop,
                });
            }
            "reject" => {
                action = Some(NfAction::Verdict {
                    verdict: NfVerdict::Reject,
                });
            }
            "return" => {
                action = Some(NfAction::Return);
            }
            "counter" => {
                // counter can appear before or as an action
                // If it's the last token, treat as action
                if i == tokens.len() - 1 || is_verdict_token(tokens.get(i + 1)) {
                    action = Some(NfAction::Counter);
                }
                // Otherwise skip (counter is a statement modifier)
            }
            "log" => {
                let mut prefix = None;
                let mut level = None;
                // Check for "prefix" and "level" after log
                let mut j = i + 1;
                while j < tokens.len() {
                    if tokens[j] == "prefix" {
                        j += 1;
                        if j < tokens.len() {
                            prefix = Some(unquote(&tokens[j]));
                        }
                    } else if tokens[j] == "level" {
                        j += 1;
                        if j < tokens.len() {
                            level = tokens[j].parse().ok();
                        }
                    } else {
                        break;
                    }
                    j += 1;
                }
                action = Some(NfAction::Log { prefix, level });
                i = j.saturating_sub(1);
            }
            "jump" => {
                i += 1;
                if i < tokens.len() {
                    action = Some(NfAction::Jump {
                        target: unquote(&tokens[i]),
                    });
                }
            }
            "goto" => {
                i += 1;
                if i < tokens.len() {
                    action = Some(NfAction::Goto {
                        target: unquote(&tokens[i]),
                    });
                }
            }
            "dnat" => {
                // "dnat to ADDR:PORT" or "dnat to ADDR"
                i += 1; // skip "to"
                if i < tokens.len() && tokens[i] == "to" {
                    i += 1;
                }
                if i < tokens.len() {
                    let (addr, port) = parse_addr_port(&tokens[i]);
                    action = Some(NfAction::Nat {
                        action: NatAction::Dnat { addr, port },
                    });
                }
            }
            "snat" => {
                i += 1;
                if i < tokens.len() && tokens[i] == "to" {
                    i += 1;
                }
                if i < tokens.len() {
                    let (addr, port) = parse_addr_port(&tokens[i]);
                    action = Some(NfAction::Nat {
                        action: NatAction::Snat { addr, port },
                    });
                }
            }
            "masquerade" => {
                action = Some(NfAction::Nat {
                    action: NatAction::Masquerade { port: None },
                });
            }
            "redirect" => {
                // "redirect to :PORT"
                let mut port = None;
                i += 1;
                if i < tokens.len() && tokens[i] == "to" {
                    i += 1;
                    if i < tokens.len() {
                        let p = tokens[i].trim_start_matches(':');
                        port = p.parse().ok();
                    }
                }
                action = Some(NfAction::Nat {
                    action: NatAction::Redirect { port },
                });
            }
            "mark" => {
                // "mark set 0x100"
                i += 1;
                if i < tokens.len() && tokens[i] == "set" {
                    i += 1;
                    if i < tokens.len() {
                        if let Some(val) = parse_u32_hex(&tokens[i]) {
                            action = Some(NfAction::SetMark {
                                value: val,
                                mask: None,
                            });
                        }
                    }
                }
            }

            // --- Matches ---
            "ip" => {
                i += 1;
                if i < tokens.len() {
                    let field_name = tokens[i].clone();
                    i += 1;
                    // optional operator (!=, etc.)
                    let (op, val_idx) = parse_match_op(&tokens, i);
                    i = val_idx;
                    if i < tokens.len() {
                        let ip_field = match field_name.as_str() {
                            "saddr" => IpField::Saddr,
                            "daddr" => IpField::Daddr,
                            "protocol" => IpField::Protocol,
                            "version" => IpField::Version,
                            "length" => IpField::Length,
                            "dscp" => IpField::Dscp,
                            "ttl" => IpField::Ttl,
                            _ => {
                                // Unknown ip field, skip
                                continue;
                            }
                        };
                        matches.push(NfMatch::Ip {
                            field: ip_field,
                            op,
                            value: unquote(&tokens[i]),
                        });
                    } else {
                        i = i.saturating_sub(1);
                    }
                }
            }
            "tcp" | "udp" => {
                let proto = if tok == "tcp" {
                    TransportProto::Tcp
                } else {
                    TransportProto::Udp
                };
                i += 1;
                if i < tokens.len() {
                    let field_name = tokens[i].clone();
                    i += 1;
                    let (op, val_idx) = parse_match_op(&tokens, i);
                    i = val_idx;
                    if i < tokens.len() {
                        let transport_field = match field_name.as_str() {
                            "dport" => TransportField::Dport,
                            "sport" => TransportField::Sport,
                            "flags" => TransportField::Flags,
                            _ => {
                                continue;
                            }
                        };
                        matches.push(NfMatch::Transport {
                            protocol: proto,
                            field: transport_field,
                            op,
                            value: unquote(&tokens[i]),
                        });
                    } else {
                        i = i.saturating_sub(1);
                    }
                }
            }
            "iif" => {
                i += 1;
                if i < tokens.len() {
                    matches.push(NfMatch::Iif {
                        name: unquote(&tokens[i]),
                    });
                }
            }
            "oif" => {
                i += 1;
                if i < tokens.len() {
                    matches.push(NfMatch::Oif {
                        name: unquote(&tokens[i]),
                    });
                }
            }
            "iifname" => {
                i += 1;
                if i < tokens.len() {
                    matches.push(NfMatch::Meta {
                        key: MetaKey::Iifname,
                        op: MatchOp::Eq,
                        value: unquote(&tokens[i]),
                    });
                }
            }
            "oifname" => {
                i += 1;
                if i < tokens.len() {
                    matches.push(NfMatch::Meta {
                        key: MetaKey::Oifname,
                        op: MatchOp::Eq,
                        value: unquote(&tokens[i]),
                    });
                }
            }
            "ct" => {
                i += 1;
                if i < tokens.len() {
                    let key_name = tokens[i].clone();
                    i += 1;
                    let (op, val_idx) = parse_match_op(&tokens, i);
                    i = val_idx;
                    if i < tokens.len() {
                        let ct_key = match key_name.as_str() {
                            "state" => CtKey::State,
                            "mark" => CtKey::Mark,
                            "status" => CtKey::Status,
                            _ => CtKey::State,
                        };
                        matches.push(NfMatch::Ct {
                            key: ct_key,
                            op,
                            value: unquote(&tokens[i]),
                        });
                    } else {
                        i = i.saturating_sub(1);
                    }
                }
            }
            "meta" => {
                i += 1;
                if i < tokens.len() {
                    let key_name = tokens[i].clone();
                    i += 1;
                    let (op, val_idx) = parse_match_op(&tokens, i);
                    i = val_idx;
                    if i < tokens.len() {
                        let meta_key = match key_name.as_str() {
                            "mark" => MetaKey::Mark,
                            "protocol" => MetaKey::Protocol,
                            "length" => MetaKey::Length,
                            "iifname" => MetaKey::Iifname,
                            "oifname" => MetaKey::Oifname,
                            "skuid" => MetaKey::Skuid,
                            "nfproto" => MetaKey::Nfproto,
                            "l4proto" => MetaKey::L4proto,
                            _ => MetaKey::Mark,
                        };
                        matches.push(NfMatch::Meta {
                            key: meta_key,
                            op,
                            value: unquote(&tokens[i]),
                        });
                    } else {
                        i = i.saturating_sub(1);
                    }
                }
            }
            _ => {
                // Unknown token — continue to next
            }
        }

        i += 1;
    }

    // If no explicit action was found, return error
    let action = action.ok_or_else(|| "no action found in rule".to_string())?;

    Ok(NfRule {
        handle: None,
        comment: None,
        matches,
        action,
    })
}

/// nftables 규칙 라인을 토큰으로 분리한다. 따옴표 안의 공백을 존중한다.
fn tokenize_nf_rule(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = '"';

    for ch in line.chars() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
                current.push(ch);
            } else {
                current.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = true;
            quote_char = ch;
            current.push(ch);
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
        } else {
            current.push(ch);
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn unquote(s: &str) -> String {
    s.trim_matches('"').trim_matches('\'').to_string()
}

fn parse_verdict(s: &str) -> NfVerdict {
    match s {
        "accept" => NfVerdict::Accept,
        "drop" => NfVerdict::Drop,
        "reject" => NfVerdict::Reject,
        "queue" => NfVerdict::Queue,
        "continue" => NfVerdict::Continue,
        _ => NfVerdict::Accept,
    }
}

fn parse_family(s: &str) -> NfFamily {
    match s {
        "ip" => NfFamily::Ip,
        "ip6" => NfFamily::Ip6,
        "inet" => NfFamily::Inet,
        "bridge" => NfFamily::Bridge,
        "arp" => NfFamily::Arp,
        _ => NfFamily::Ip,
    }
}

fn is_verdict_token(tok: Option<&String>) -> bool {
    match tok {
        Some(t) => matches!(
            t.as_str(),
            "accept" | "drop" | "reject" | "return" | "jump" | "goto"
        ),
        None => true,
    }
}

fn parse_match_op(tokens: &[String], i: usize) -> (MatchOp, usize) {
    if i >= tokens.len() {
        return (MatchOp::Eq, i);
    }
    match tokens[i].as_str() {
        "!=" => (MatchOp::Neq, i + 1),
        "<" => (MatchOp::Lt, i + 1),
        ">" => (MatchOp::Gt, i + 1),
        "<=" => (MatchOp::Lte, i + 1),
        ">=" => (MatchOp::Gte, i + 1),
        _ => (MatchOp::Eq, i), // no explicit operator means Eq, don't consume token
    }
}

fn parse_addr_port(s: &str) -> (Option<IpAddr>, Option<u16>) {
    // "192.168.1.100:8080" or "192.168.1.100" or ":8080"
    if let Some(colon_pos) = s.rfind(':') {
        let addr_part = &s[..colon_pos];
        let port_part = &s[colon_pos + 1..];
        let addr = if addr_part.is_empty() {
            None
        } else {
            addr_part.parse::<IpAddr>().ok()
        };
        let port = port_part.parse::<u16>().ok();
        (addr, port)
    } else {
        let addr = s.parse::<IpAddr>().ok();
        (addr, None)
    }
}

fn parse_u32_hex(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn find_closing_brace(lines: &[&str], start: usize) -> usize {
    let mut depth = 0;
    for (idx, line) in lines[start..].iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.ends_with('{') {
            depth += 1;
        }
        if trimmed == "}" || trimmed.starts_with('}') {
            depth -= 1;
            if depth == 0 {
                return start + idx;
            }
        }
    }
    lines.len().saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_INPUT: &str = r#"table ip filter {
	chain input {
		type filter hook input priority filter; policy accept;
		iif "lo" accept
		ct state established,related accept
		tcp dport 22 accept
		tcp dport 80 accept
		counter drop
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related accept
		iifname "eth0" oifname "eth1" accept
	}
}
table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		tcp dport 80 dnat to 192.168.1.100:8080
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth0" masquerade
	}
}"#;

    #[test]
    fn test_parse_nft_table_count() {
        let result = parse_nft_list(SAMPLE_INPUT);
        assert_eq!(result.data.tables.len(), 2);
    }

    #[test]
    fn test_parse_filter_table() {
        let result = parse_nft_list(SAMPLE_INPUT);
        let filter = &result.data.tables[0];
        assert_eq!(filter.family, NfFamily::Ip);
        assert_eq!(filter.name, "filter");
        assert_eq!(filter.chains.len(), 2);
    }

    #[test]
    fn test_parse_input_chain() {
        let result = parse_nft_list(SAMPLE_INPUT);
        let input_chain = &result.data.tables[0].chains[0];
        assert_eq!(input_chain.name, "input");
        assert_eq!(input_chain.chain_type, Some(NfChainType::Filter));
        assert_eq!(input_chain.hook, Some(NfHook::Input));
        assert_eq!(input_chain.priority, Some(0));
        assert_eq!(input_chain.policy, Some(NfVerdict::Accept));
        assert_eq!(input_chain.rules.len(), 5);
    }

    #[test]
    fn test_parse_iif_accept() {
        let result = parse_nft_list(SAMPLE_INPUT);
        let rule = &result.data.tables[0].chains[0].rules[0];
        assert_eq!(rule.matches.len(), 1);
        assert!(matches!(&rule.matches[0], NfMatch::Iif { name } if name == "lo"));
        assert!(matches!(&rule.action, NfAction::Verdict { verdict: NfVerdict::Accept }));
    }

    #[test]
    fn test_parse_ct_state() {
        let result = parse_nft_list(SAMPLE_INPUT);
        let rule = &result.data.tables[0].chains[0].rules[1];
        assert!(matches!(&rule.matches[0], NfMatch::Ct { key: CtKey::State, op: MatchOp::Eq, value } if value == "established,related"));
    }

    #[test]
    fn test_parse_tcp_dport() {
        let result = parse_nft_list(SAMPLE_INPUT);
        let rule = &result.data.tables[0].chains[0].rules[2];
        assert!(matches!(
            &rule.matches[0],
            NfMatch::Transport {
                protocol: TransportProto::Tcp,
                field: TransportField::Dport,
                op: MatchOp::Eq,
                value,
            } if value == "22"
        ));
    }

    #[test]
    fn test_parse_counter_drop() {
        let result = parse_nft_list(SAMPLE_INPUT);
        let rule = &result.data.tables[0].chains[0].rules[4];
        // "counter drop" — counter before drop means action is counter+drop.
        // Our parser treats "counter" as modifier and "drop" as final action.
        assert!(matches!(&rule.action, NfAction::Verdict { verdict: NfVerdict::Drop }));
    }

    #[test]
    fn test_parse_forward_chain_policy() {
        let result = parse_nft_list(SAMPLE_INPUT);
        let forward = &result.data.tables[0].chains[1];
        assert_eq!(forward.name, "forward");
        assert_eq!(forward.policy, Some(NfVerdict::Drop));
        assert_eq!(forward.rules.len(), 2);
    }

    #[test]
    fn test_parse_iifname_oifname() {
        let result = parse_nft_list(SAMPLE_INPUT);
        let rule = &result.data.tables[0].chains[1].rules[1];
        // iifname "eth0" oifname "eth1" accept
        assert_eq!(rule.matches.len(), 2);
        assert!(matches!(&rule.matches[0], NfMatch::Meta { key: MetaKey::Iifname, value, .. } if value == "eth0"));
        assert!(matches!(&rule.matches[1], NfMatch::Meta { key: MetaKey::Oifname, value, .. } if value == "eth1"));
    }

    #[test]
    fn test_parse_nat_table() {
        let result = parse_nft_list(SAMPLE_INPUT);
        let nat = &result.data.tables[1];
        assert_eq!(nat.name, "nat");
        assert_eq!(nat.chains.len(), 2);
    }

    #[test]
    fn test_parse_dnat() {
        let result = parse_nft_list(SAMPLE_INPUT);
        let rule = &result.data.tables[1].chains[0].rules[0];
        // tcp dport 80 dnat to 192.168.1.100:8080
        assert!(matches!(
            &rule.action,
            NfAction::Nat {
                action: NatAction::Dnat { addr: Some(addr), port: Some(8080) }
            } if *addr == "192.168.1.100".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn test_parse_masquerade() {
        let result = parse_nft_list(SAMPLE_INPUT);
        let rule = &result.data.tables[1].chains[1].rules[0];
        assert!(matches!(
            &rule.action,
            NfAction::Nat {
                action: NatAction::Masquerade { port: None }
            }
        ));
    }

    #[test]
    fn test_empty_input() {
        let result = parse_nft_list("");
        assert!(result.data.tables.is_empty());
    }
}
