//! `iptables-save` 출력 파서
//!
//! `iptables-save` 명령어의 출력을 파싱하여 `IptablesRuleset`로 변환한다.

use std::net::IpAddr;

use netsim_core::model::{
    IptablesChain, IptablesRuleset, IptablesTable, NatAction, NfAction, NfMatch, NfRule,
    NfVerdict,
    CtKey, IpField, MatchOp, TransportField, TransportProto,
};

use crate::validation::{ParseResult, ValidationReport};

/// `iptables-save` 출력을 파싱한다.
pub fn parse_iptables_save(input: &str) -> ParseResult<IptablesRuleset> {
    let mut ruleset = IptablesRuleset::default();
    let mut report = ValidationReport::new();

    let mut current_table: Option<IptablesTable> = None;

    for line in input.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Table start: "*filter", "*nat", etc.
        if let Some(table_name) = line.strip_prefix('*') {
            // Save previous table if any
            if let Some(table) = current_table.take() {
                report.add_ok(format!("Parsed iptables table '{}'", &table.name));
                ruleset.tables.push(table);
            }
            current_table = Some(IptablesTable {
                name: table_name.to_string(),
                chains: Vec::new(),
            });
            continue;
        }

        // COMMIT
        if line == "COMMIT" {
            if let Some(table) = current_table.take() {
                report.add_ok(format!("Parsed iptables table '{}'", &table.name));
                ruleset.tables.push(table);
            }
            continue;
        }

        // Chain declaration: ":INPUT ACCEPT [0:0]"
        if line.starts_with(':') {
            if let Some(ref mut table) = current_table {
                if let Some(chain) = parse_chain_declaration(line) {
                    table.chains.push(chain);
                } else {
                    report.add_partial(format!("Invalid chain declaration: {}", line));
                }
            }
            continue;
        }

        // Rule: "-A INPUT -i lo -j ACCEPT"
        if line.starts_with("-A ") {
            if let Some(ref mut table) = current_table {
                match parse_iptables_rule(line) {
                    Ok((chain_name, rule)) => {
                        // Find or create the chain
                        if let Some(chain) = table.chains.iter_mut().find(|c| c.name == chain_name)
                        {
                            chain.rules.push(rule);
                        } else {
                            // Chain not declared yet (user-defined chain)
                            table.chains.push(IptablesChain {
                                name: chain_name,
                                policy: None,
                                rules: vec![rule],
                            });
                        }
                    }
                    Err(msg) => {
                        report.add_partial(format!("Failed to parse iptables rule: {} ({})", line, msg));
                    }
                }
            }
            continue;
        }

        // Unknown line
        report.add_unsupported(format!("Unknown iptables-save line: {}", line));
    }

    // Handle case where COMMIT was missing
    if let Some(table) = current_table.take() {
        report.add_ok(format!("Parsed iptables table '{}'", &table.name));
        ruleset.tables.push(table);
    }

    report.add_ok(format!("Total {} iptables tables parsed", ruleset.tables.len()));

    ParseResult {
        data: ruleset,
        report,
    }
}

/// 체인 선언을 파싱한다: ":INPUT ACCEPT [0:0]"
fn parse_chain_declaration(line: &str) -> Option<IptablesChain> {
    let line = line.trim_start_matches(':');
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let name = parts[0].to_string();
    let policy = match parts[1] {
        "ACCEPT" => Some(NfVerdict::Accept),
        "DROP" => Some(NfVerdict::Drop),
        "REJECT" => Some(NfVerdict::Reject),
        "-" => None, // User-defined chains have "-" policy
        _ => None,
    };

    Some(IptablesChain {
        name,
        policy,
        rules: Vec::new(),
    })
}

/// iptables 규칙 라인을 파싱한다.
/// 반환: (chain_name, NfRule)
fn parse_iptables_rule(line: &str) -> Result<(String, NfRule), String> {
    let tokens = shell_tokenize(line);
    if tokens.len() < 2 || tokens[0] != "-A" {
        return Err("not a rule line".to_string());
    }

    let chain_name = tokens[1].clone();
    let mut matches = Vec::new();
    let mut action: Option<NfAction> = None;
    let mut i = 2;

    while i < tokens.len() {
        let tok = &tokens[i];

        match tok.as_str() {
            "-i" | "--in-interface" => {
                i += 1;
                if i < tokens.len() {
                    matches.push(NfMatch::Iif {
                        name: tokens[i].clone(),
                    });
                }
            }
            "-o" | "--out-interface" => {
                i += 1;
                if i < tokens.len() {
                    matches.push(NfMatch::Oif {
                        name: tokens[i].clone(),
                    });
                }
            }
            "-s" | "--source" => {
                i += 1;
                if i < tokens.len() {
                    matches.push(NfMatch::Ip {
                        field: IpField::Saddr,
                        op: MatchOp::Eq,
                        value: tokens[i].clone(),
                    });
                }
            }
            "-d" | "--destination" => {
                i += 1;
                if i < tokens.len() {
                    matches.push(NfMatch::Ip {
                        field: IpField::Daddr,
                        op: MatchOp::Eq,
                        value: tokens[i].clone(),
                    });
                }
            }
            "-p" | "--protocol" => {
                i += 1;
                // Protocol is consumed; port matches that follow use this protocol
                // We don't add a direct match for protocol itself unless needed
                // The protocol info is used with --dport/--sport
            }
            "--dport" | "--destination-port" => {
                i += 1;
                if i < tokens.len() {
                    let proto = find_protocol(&tokens[..i]);
                    matches.push(NfMatch::Transport {
                        protocol: proto,
                        field: TransportField::Dport,
                        op: MatchOp::Eq,
                        value: tokens[i].clone(),
                    });
                }
            }
            "--sport" | "--source-port" => {
                i += 1;
                if i < tokens.len() {
                    let proto = find_protocol(&tokens[..i]);
                    matches.push(NfMatch::Transport {
                        protocol: proto,
                        field: TransportField::Sport,
                        op: MatchOp::Eq,
                        value: tokens[i].clone(),
                    });
                }
            }
            "-m" | "--match" => {
                i += 1;
                if i < tokens.len() {
                    let module = tokens[i].clone();
                    match module.as_str() {
                        "state" => {
                            // Look for --state
                            i += 1;
                            if i < tokens.len() && tokens[i] == "--state" {
                                i += 1;
                                if i < tokens.len() {
                                    matches.push(NfMatch::Ct {
                                        key: CtKey::State,
                                        op: MatchOp::Eq,
                                        value: tokens[i].to_lowercase(),
                                    });
                                }
                            }
                        }
                        "conntrack" => {
                            i += 1;
                            if i < tokens.len() && tokens[i] == "--ctstate" {
                                i += 1;
                                if i < tokens.len() {
                                    matches.push(NfMatch::Ct {
                                        key: CtKey::State,
                                        op: MatchOp::Eq,
                                        value: tokens[i].to_lowercase(),
                                    });
                                }
                            }
                        }
                        "mark" => {
                            i += 1;
                            if i < tokens.len() && tokens[i] == "--mark" {
                                i += 1;
                                if i < tokens.len() {
                                    let val_str = &tokens[i];
                                    let parts: Vec<&str> = val_str.split('/').collect();
                                    if let Some(val) = parse_u32_hex(parts[0]) {
                                        let mask = parts.get(1).and_then(|m| parse_u32_hex(m));
                                        matches.push(NfMatch::Mark {
                                            op: MatchOp::Eq,
                                            value: val,
                                            mask,
                                        });
                                    }
                                }
                            }
                        }
                        "tcp" | "udp" => {
                            // module matches for tcp/udp may have --dport/--sport next
                            // handled by the outer loop
                        }
                        "multiport" => {
                            // --dports or --sports
                            i += 1;
                            if i < tokens.len() {
                                let field = match tokens[i].as_str() {
                                    "--dports" | "--destination-ports" => Some(TransportField::Dport),
                                    "--sports" | "--source-ports" => Some(TransportField::Sport),
                                    _ => None,
                                };
                                if let Some(f) = field {
                                    i += 1;
                                    if i < tokens.len() {
                                        let proto = find_protocol(&tokens[..i]);
                                        matches.push(NfMatch::Transport {
                                            protocol: proto,
                                            field: f,
                                            op: MatchOp::Eq,
                                            value: tokens[i].clone(),
                                        });
                                    }
                                }
                            }
                        }
                        _ => {
                            // Unknown module, skip
                        }
                    }
                }
            }
            "-j" | "--jump" => {
                i += 1;
                if i < tokens.len() {
                    action = Some(parse_iptables_target(&tokens, &mut i));
                }
            }
            "!" => {
                // Negation — next token is the flag to negate
                // For simplicity, skip negation handling (record partial)
                i += 1;
            }
            _ => {
                // Unknown option, skip
            }
        }

        i += 1;
    }

    let action = action.ok_or_else(|| "no target/action found".to_string())?;

    Ok((
        chain_name,
        NfRule {
            handle: None,
            comment: None,
            matches,
            action,
        },
    ))
}

/// iptables 타겟을 파싱한다.
fn parse_iptables_target(tokens: &[String], i: &mut usize) -> NfAction {
    let target = &tokens[*i];

    match target.as_str() {
        "ACCEPT" => NfAction::Verdict {
            verdict: NfVerdict::Accept,
        },
        "DROP" => NfAction::Verdict {
            verdict: NfVerdict::Drop,
        },
        "REJECT" => NfAction::Verdict {
            verdict: NfVerdict::Reject,
        },
        "RETURN" => NfAction::Return,
        "LOG" => {
            let mut prefix = None;
            let mut level = None;
            let mut j = *i + 1;
            while j < tokens.len() {
                match tokens[j].as_str() {
                    "--log-prefix" => {
                        j += 1;
                        if j < tokens.len() {
                            prefix = Some(tokens[j].clone());
                        }
                    }
                    "--log-level" => {
                        j += 1;
                        if j < tokens.len() {
                            level = tokens[j].parse().ok();
                        }
                    }
                    _ => break,
                }
                j += 1;
            }
            *i = j.saturating_sub(1);
            NfAction::Log { prefix, level }
        }
        "DNAT" => {
            let mut addr = None;
            let mut port = None;
            let mut j = *i + 1;
            if j < tokens.len() && tokens[j] == "--to-destination" {
                j += 1;
                if j < tokens.len() {
                    let (a, p) = parse_addr_port(&tokens[j]);
                    addr = a;
                    port = p;
                }
            }
            *i = j;
            NfAction::Nat {
                action: NatAction::Dnat { addr, port },
            }
        }
        "SNAT" => {
            let mut addr = None;
            let mut port = None;
            let mut j = *i + 1;
            if j < tokens.len() && tokens[j] == "--to-source" {
                j += 1;
                if j < tokens.len() {
                    let (a, p) = parse_addr_port(&tokens[j]);
                    addr = a;
                    port = p;
                }
            }
            *i = j;
            NfAction::Nat {
                action: NatAction::Snat { addr, port },
            }
        }
        "MASQUERADE" => NfAction::Nat {
            action: NatAction::Masquerade { port: None },
        },
        "REDIRECT" => {
            let mut port = None;
            let mut j = *i + 1;
            if j < tokens.len() && tokens[j] == "--to-port" {
                j += 1;
                if j < tokens.len() {
                    port = tokens[j].parse().ok();
                }
            }
            *i = j;
            NfAction::Nat {
                action: NatAction::Redirect { port },
            }
        }
        "MARK" => {
            let mut value = 0;
            let mut mask = None;
            let mut j = *i + 1;
            if j < tokens.len() && tokens[j] == "--set-mark" {
                j += 1;
                if j < tokens.len() {
                    let parts: Vec<&str> = tokens[j].split('/').collect();
                    value = parse_u32_hex(parts[0]).unwrap_or(0);
                    mask = parts.get(1).and_then(|m| parse_u32_hex(m));
                }
            } else if j < tokens.len() && tokens[j] == "--set-xmark" {
                j += 1;
                if j < tokens.len() {
                    let parts: Vec<&str> = tokens[j].split('/').collect();
                    value = parse_u32_hex(parts[0]).unwrap_or(0);
                    mask = parts.get(1).and_then(|m| parse_u32_hex(m));
                }
            }
            *i = j;
            NfAction::SetMark { value, mask }
        }
        // User-defined chain jump
        other => NfAction::Jump {
            target: other.to_string(),
        },
    }
}

/// 토큰 배열에서 -p 프로토콜 값을 찾는다.
fn find_protocol(tokens: &[String]) -> TransportProto {
    for (i, t) in tokens.iter().enumerate() {
        if (t == "-p" || t == "--protocol") && i + 1 < tokens.len() {
            return match tokens[i + 1].as_str() {
                "tcp" => TransportProto::Tcp,
                "udp" => TransportProto::Udp,
                "icmp" => TransportProto::Icmp,
                _ => TransportProto::Tcp,
            };
        }
    }
    TransportProto::Tcp
}

fn parse_addr_port(s: &str) -> (Option<IpAddr>, Option<u16>) {
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
        (s.parse::<IpAddr>().ok(), None)
    }
}

fn parse_u32_hex(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// 셸 형식의 토큰 분리 (따옴표 존중)
fn shell_tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = '"';

    for ch in line.chars() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
            } else {
                current.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = true;
            quote_char = ch;
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_INPUT: &str = r#"# Generated by iptables-save
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -i eth0 -o eth1 -j ACCEPT
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.100:8080
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT"#;

    #[test]
    fn test_parse_table_count() {
        let result = parse_iptables_save(SAMPLE_INPUT);
        assert_eq!(result.data.tables.len(), 2);
    }

    #[test]
    fn test_parse_filter_table() {
        let result = parse_iptables_save(SAMPLE_INPUT);
        let filter = &result.data.tables[0];
        assert_eq!(filter.name, "filter");
        assert_eq!(filter.chains.len(), 3);
    }

    #[test]
    fn test_parse_chain_policies() {
        let result = parse_iptables_save(SAMPLE_INPUT);
        let filter = &result.data.tables[0];
        let input_chain = filter.chains.iter().find(|c| c.name == "INPUT").unwrap();
        assert_eq!(input_chain.policy, Some(NfVerdict::Accept));

        let forward_chain = filter.chains.iter().find(|c| c.name == "FORWARD").unwrap();
        assert_eq!(forward_chain.policy, Some(NfVerdict::Drop));
    }

    #[test]
    fn test_parse_input_rules() {
        let result = parse_iptables_save(SAMPLE_INPUT);
        let filter = &result.data.tables[0];
        let input_chain = filter.chains.iter().find(|c| c.name == "INPUT").unwrap();
        assert_eq!(input_chain.rules.len(), 3);

        // First rule: -A INPUT -i lo -j ACCEPT
        let rule0 = &input_chain.rules[0];
        assert_eq!(rule0.matches.len(), 1);
        assert!(matches!(&rule0.matches[0], NfMatch::Iif { name } if name == "lo"));
        assert!(matches!(
            &rule0.action,
            NfAction::Verdict {
                verdict: NfVerdict::Accept
            }
        ));
    }

    #[test]
    fn test_parse_state_match() {
        let result = parse_iptables_save(SAMPLE_INPUT);
        let filter = &result.data.tables[0];
        let input_chain = filter.chains.iter().find(|c| c.name == "INPUT").unwrap();

        // Second rule: -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        let rule1 = &input_chain.rules[1];
        assert!(matches!(
            &rule1.matches[0],
            NfMatch::Ct {
                key: CtKey::State,
                op: MatchOp::Eq,
                value
            } if value == "established,related"
        ));
    }

    #[test]
    fn test_parse_dport_match() {
        let result = parse_iptables_save(SAMPLE_INPUT);
        let filter = &result.data.tables[0];
        let input_chain = filter.chains.iter().find(|c| c.name == "INPUT").unwrap();

        // Third rule: -A INPUT -p tcp --dport 22 -j ACCEPT
        let rule2 = &input_chain.rules[2];
        assert!(matches!(
            &rule2.matches[0],
            NfMatch::Transport {
                protocol: TransportProto::Tcp,
                field: TransportField::Dport,
                op: MatchOp::Eq,
                value
            } if value == "22"
        ));
    }

    #[test]
    fn test_parse_nat_table() {
        let result = parse_iptables_save(SAMPLE_INPUT);
        let nat = &result.data.tables[1];
        assert_eq!(nat.name, "nat");
        assert_eq!(nat.chains.len(), 2);
    }

    #[test]
    fn test_parse_dnat_rule() {
        let result = parse_iptables_save(SAMPLE_INPUT);
        let nat = &result.data.tables[1];
        let prerouting = nat.chains.iter().find(|c| c.name == "PREROUTING").unwrap();
        assert_eq!(prerouting.rules.len(), 1);

        let rule = &prerouting.rules[0];
        assert!(matches!(
            &rule.action,
            NfAction::Nat {
                action: NatAction::Dnat { addr: Some(addr), port: Some(8080) }
            } if *addr == "192.168.1.100".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn test_parse_masquerade_rule() {
        let result = parse_iptables_save(SAMPLE_INPUT);
        let nat = &result.data.tables[1];
        let postrouting = nat
            .chains
            .iter()
            .find(|c| c.name == "POSTROUTING")
            .unwrap();
        assert_eq!(postrouting.rules.len(), 1);

        let rule = &postrouting.rules[0];
        assert!(matches!(
            &rule.action,
            NfAction::Nat {
                action: NatAction::Masquerade { port: None }
            }
        ));
        assert!(matches!(&rule.matches[0], NfMatch::Oif { name } if name == "eth0"));
    }

    #[test]
    fn test_empty_input() {
        let result = parse_iptables_save("");
        assert!(result.data.tables.is_empty());
    }
}
