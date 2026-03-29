//! `ip rule show` 출력 파서
//!
//! 리눅스 `ip rule show` 명령어의 출력을 파싱하여 `Vec<IpRule>`로 변환한다.

use ipnet::IpNet;
use netsim_core::model::{IpRule, RuleAction, RuleSelector};
use regex::Regex;

use crate::validation::{ParseResult, ValidationReport};

/// 잘 알려진 라우팅 테이블 이름을 ID로 변환한다.
fn table_name_to_id(name: &str) -> u32 {
    match name {
        "local" => 255,
        "main" => 254,
        "default" => 253,
        "unspec" => 0,
        _ => name.parse::<u32>().unwrap_or(0),
    }
}

/// `ip rule show` 출력을 파싱하여 `Vec<IpRule>`을 반환한다.
pub fn parse_ip_rule(input: &str) -> ParseResult<Vec<IpRule>> {
    let mut rules = Vec::new();
    let mut report = ValidationReport::new();

    // 기본 형식: "0:\tfrom all lookup local"
    let line_re = Regex::new(r"^(\d+):\s+(.+)$").unwrap();

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let caps = match line_re.captures(line) {
            Some(c) => c,
            None => {
                report.add_partial(format!("Unrecognized ip rule line: {}", line));
                continue;
            }
        };

        let priority: u32 = caps[1].parse().unwrap_or(0);
        let rest = caps[2].to_string();
        let tokens: Vec<&str> = rest.split_whitespace().collect();

        let mut selector = RuleSelector::default();
        let mut action = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "from" => {
                    i += 1;
                    if i < tokens.len() && tokens[i] != "all" {
                        if let Ok(net) = tokens[i].parse::<IpNet>() {
                            selector.from = Some(net);
                        } else {
                            // Try as a bare IP address (add /32 or /128)
                            if let Ok(ip) = tokens[i].parse::<std::net::IpAddr>() {
                                let prefix = if ip.is_ipv4() { 32 } else { 128 };
                                selector.from = Some(IpNet::new(ip, prefix).unwrap());
                            } else {
                                report.add_partial(format!(
                                    "Could not parse 'from' value: {}",
                                    tokens[i]
                                ));
                            }
                        }
                    }
                }
                "to" => {
                    i += 1;
                    if i < tokens.len() && tokens[i] != "all" {
                        if let Ok(net) = tokens[i].parse::<IpNet>() {
                            selector.to = Some(net);
                        } else if let Ok(ip) = tokens[i].parse::<std::net::IpAddr>() {
                            let prefix = if ip.is_ipv4() { 32 } else { 128 };
                            selector.to = Some(IpNet::new(ip, prefix).unwrap());
                        }
                    }
                }
                "fwmark" => {
                    i += 1;
                    if i < tokens.len() {
                        let mark_str = tokens[i];
                        // fwmark can be "0x64" or "0x64/0xff"
                        let parts: Vec<&str> = mark_str.split('/').collect();
                        if let Some(mark) = parse_u32_maybe_hex(parts[0]) {
                            selector.fwmark = Some(mark);
                            if parts.len() > 1 {
                                selector.fwmask = parse_u32_maybe_hex(parts[1]);
                            }
                        }
                    }
                }
                "iif" => {
                    i += 1;
                    if i < tokens.len() {
                        selector.iif = Some(tokens[i].to_string());
                    }
                }
                "oif" => {
                    i += 1;
                    if i < tokens.len() {
                        selector.oif = Some(tokens[i].to_string());
                    }
                }
                "tos" => {
                    i += 1;
                    if i < tokens.len() {
                        selector.tos = tokens[i].parse().ok();
                    }
                }
                "lookup" | "table" => {
                    i += 1;
                    if i < tokens.len() {
                        let table_id = table_name_to_id(tokens[i]);
                        action = Some(RuleAction::Lookup(table_id));
                    }
                }
                "blackhole" => {
                    action = Some(RuleAction::Blackhole);
                }
                "unreachable" => {
                    action = Some(RuleAction::Unreachable);
                }
                "prohibit" => {
                    action = Some(RuleAction::Prohibit);
                }
                _ => {
                    // Unknown token, skip
                }
            }
            i += 1;
        }

        if let Some(act) = action {
            rules.push(IpRule {
                priority,
                selector,
                action: act,
            });
            report.add_ok(format!("Parsed ip rule priority {}", priority));
        } else {
            report.add_partial(format!(
                "No action found for ip rule priority {}: {}",
                priority, rest
            ));
        }
    }

    report.add_ok(format!("Total {} ip rules parsed", rules.len()));

    ParseResult {
        data: rules,
        report,
    }
}

fn parse_u32_maybe_hex(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_INPUT: &str = r#"0:	from all lookup local
100:	from 10.0.0.0/24 lookup 100
200:	from all fwmark 0x64 lookup 200
32766:	from all lookup main
32767:	from all lookup default"#;

    #[test]
    fn test_parse_ip_rule_count() {
        let result = parse_ip_rule(SAMPLE_INPUT);
        assert_eq!(result.data.len(), 5);
    }

    #[test]
    fn test_parse_rule_local() {
        let result = parse_ip_rule(SAMPLE_INPUT);
        let rule = &result.data[0];
        assert_eq!(rule.priority, 0);
        assert_eq!(rule.selector.from, None); // "all" -> None
        assert_eq!(rule.action, RuleAction::Lookup(255));
    }

    #[test]
    fn test_parse_rule_with_from() {
        let result = parse_ip_rule(SAMPLE_INPUT);
        let rule = &result.data[1];
        assert_eq!(rule.priority, 100);
        assert_eq!(
            rule.selector.from,
            Some("10.0.0.0/24".parse::<IpNet>().unwrap())
        );
        assert_eq!(rule.action, RuleAction::Lookup(100));
    }

    #[test]
    fn test_parse_rule_fwmark() {
        let result = parse_ip_rule(SAMPLE_INPUT);
        let rule = &result.data[2];
        assert_eq!(rule.priority, 200);
        assert_eq!(rule.selector.fwmark, Some(0x64));
        assert_eq!(rule.action, RuleAction::Lookup(200));
    }

    #[test]
    fn test_parse_rule_main() {
        let result = parse_ip_rule(SAMPLE_INPUT);
        let rule = &result.data[3];
        assert_eq!(rule.priority, 32766);
        assert_eq!(rule.action, RuleAction::Lookup(254)); // main = 254
    }

    #[test]
    fn test_parse_rule_default() {
        let result = parse_ip_rule(SAMPLE_INPUT);
        let rule = &result.data[4];
        assert_eq!(rule.priority, 32767);
        assert_eq!(rule.action, RuleAction::Lookup(253)); // default = 253
    }

    #[test]
    fn test_empty_input() {
        let result = parse_ip_rule("");
        assert!(result.data.is_empty());
    }
}
