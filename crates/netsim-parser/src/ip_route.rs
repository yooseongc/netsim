//! `ip route show` 출력 파서
//!
//! 리눅스 `ip route show` 명령어의 출력을 파싱하여 `Vec<Route>`를 포함하는
//! `RoutingTable`로 변환한다.

use std::net::IpAddr;

use ipnet::IpNet;
use netsim_core::model::{Route, RouteScope, RouteType, RoutingTable};

use crate::validation::{ParseResult, ValidationReport};

/// `ip route show` 출력을 파싱하여 `RoutingTable`을 반환한다.
/// `table_id`는 라우팅 테이블 ID를 지정한다 (기본: 254 = main).
pub fn parse_ip_route(input: &str, table_id: u32) -> ParseResult<RoutingTable> {
    let mut routes = Vec::new();
    let mut report = ValidationReport::new();

    let table_name = match table_id {
        255 => Some("local".to_string()),
        254 => Some("main".to_string()),
        253 => Some("default".to_string()),
        _ => None,
    };

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match parse_route_line(line) {
            Ok(route) => {
                report.add_ok(format!("Parsed route: {}", line));
                routes.push(route);
            }
            Err(msg) => {
                report.add_partial(format!("Failed to parse route: {} ({})", line, msg));
            }
        }
    }

    report.add_ok(format!(
        "Total {} routes parsed for table {}",
        routes.len(),
        table_id
    ));

    ParseResult {
        data: RoutingTable {
            id: table_id,
            name: table_name,
            routes,
        },
        report,
    }
}

/// 단일 라우트 라인을 파싱한다.
fn parse_route_line(line: &str) -> Result<Route, String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return Err("empty line".to_string());
    }

    let mut route_type = RouteType::Unicast;
    let mut destination: Option<IpNet> = None;
    let mut gateway: Option<IpAddr> = None;
    let mut dev: Option<String> = None;
    let mut src: Option<IpAddr> = None;
    let mut metric: u32 = 0;
    let mut scope = RouteScope::Global;
    let mut mtu: Option<u32> = None;

    let mut i = 0;

    // 라우트 타입 접두어 확인
    match tokens[i] {
        "blackhole" => {
            route_type = RouteType::Blackhole;
            i += 1;
        }
        "unreachable" => {
            route_type = RouteType::Unreachable;
            i += 1;
        }
        "prohibit" => {
            route_type = RouteType::Prohibit;
            i += 1;
        }
        "throw" => {
            route_type = RouteType::Throw;
            i += 1;
        }
        "local" => {
            route_type = RouteType::Local;
            i += 1;
        }
        "broadcast" => {
            route_type = RouteType::Broadcast;
            i += 1;
        }
        _ => {}
    }

    // 목적지 파싱
    if i < tokens.len() {
        let dest_str = tokens[i];
        if dest_str == "default" {
            destination = Some("0.0.0.0/0".parse::<IpNet>().unwrap());
            i += 1;
        } else if let Ok(net) = dest_str.parse::<IpNet>() {
            destination = Some(net);
            i += 1;
        } else if let Ok(ip) = dest_str.parse::<IpAddr>() {
            // Bare IP -> /32 or /128
            let prefix = if ip.is_ipv4() { 32 } else { 128 };
            destination = Some(IpNet::new(ip, prefix).unwrap());
            i += 1;
        } else {
            // Might be a keyword we don't recognize as destination; keep i unchanged
        }
    }

    let destination = destination.ok_or_else(|| "no destination found".to_string())?;

    // 나머지 키-값 쌍 파싱
    while i < tokens.len() {
        match tokens[i] {
            "via" => {
                i += 1;
                if i < tokens.len() {
                    gateway = tokens[i].parse().ok();
                }
            }
            "dev" => {
                i += 1;
                if i < tokens.len() {
                    dev = Some(tokens[i].to_string());
                }
            }
            "src" => {
                i += 1;
                if i < tokens.len() {
                    src = tokens[i].parse().ok();
                }
            }
            "metric" => {
                i += 1;
                if i < tokens.len() {
                    metric = tokens[i].parse().unwrap_or(0);
                }
            }
            "scope" => {
                i += 1;
                if i < tokens.len() {
                    scope = parse_route_scope(tokens[i]);
                }
            }
            "mtu" => {
                i += 1;
                if i < tokens.len() {
                    mtu = tokens[i].parse().ok();
                }
            }
            "proto" | "table" | "linkdown" | "onlink" => {
                // skip proto value, table value, flags
                i += 1;
            }
            _ => {
                // unknown token, skip
            }
        }
        i += 1;
    }

    Ok(Route {
        destination,
        gateway,
        dev,
        src,
        metric,
        scope,
        route_type,
        mtu,
    })
}

fn parse_route_scope(s: &str) -> RouteScope {
    match s {
        "link" => RouteScope::Link,
        "host" => RouteScope::Host,
        "nowhere" => RouteScope::Nowhere,
        _ => RouteScope::Global,
    }
}

/// 여러 테이블의 라우트를 한 번에 파싱하기 위한 헬퍼.
/// 각 (table_id, output_text) 쌍을 받아 `Vec<RoutingTable>`을 반환한다.
pub fn parse_ip_routes_multi(
    tables: &[(u32, &str)],
) -> ParseResult<Vec<RoutingTable>> {
    let mut result_tables = Vec::new();
    let mut report = ValidationReport::new();

    for (table_id, text) in tables {
        let r = parse_ip_route(text, *table_id);
        report.merge(r.report);
        result_tables.push(r.data);
    }

    ParseResult {
        data: result_tables,
        report,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const SAMPLE_INPUT: &str = r#"default via 10.0.0.254 dev eth0 proto static metric 100
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.1
192.168.1.0/24 dev eth1 proto kernel scope link src 192.168.1.1
blackhole 198.51.100.0/24
unreachable 203.0.113.0/24"#;

    #[test]
    fn test_parse_ip_route_count() {
        let result = parse_ip_route(SAMPLE_INPUT, 254);
        assert_eq!(result.data.routes.len(), 5);
        assert_eq!(result.data.id, 254);
        assert_eq!(result.data.name, Some("main".to_string()));
    }

    #[test]
    fn test_parse_default_route() {
        let result = parse_ip_route(SAMPLE_INPUT, 254);
        let route = &result.data.routes[0];
        assert_eq!(
            route.destination,
            "0.0.0.0/0".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            route.gateway,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)))
        );
        assert_eq!(route.dev, Some("eth0".to_string()));
        assert_eq!(route.metric, 100);
        assert_eq!(route.route_type, RouteType::Unicast);
    }

    #[test]
    fn test_parse_connected_route() {
        let result = parse_ip_route(SAMPLE_INPUT, 254);
        let route = &result.data.routes[1];
        assert_eq!(
            route.destination,
            "10.0.0.0/24".parse::<IpNet>().unwrap()
        );
        assert_eq!(route.gateway, None);
        assert_eq!(route.dev, Some("eth0".to_string()));
        assert_eq!(route.scope, RouteScope::Link);
        assert_eq!(
            route.src,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn test_parse_blackhole() {
        let result = parse_ip_route(SAMPLE_INPUT, 254);
        let route = &result.data.routes[3];
        assert_eq!(route.route_type, RouteType::Blackhole);
        assert_eq!(
            route.destination,
            "198.51.100.0/24".parse::<IpNet>().unwrap()
        );
    }

    #[test]
    fn test_parse_unreachable() {
        let result = parse_ip_route(SAMPLE_INPUT, 254);
        let route = &result.data.routes[4];
        assert_eq!(route.route_type, RouteType::Unreachable);
        assert_eq!(
            route.destination,
            "203.0.113.0/24".parse::<IpNet>().unwrap()
        );
    }

    #[test]
    fn test_custom_table_id() {
        let result = parse_ip_route("10.0.0.0/24 dev eth0", 100);
        assert_eq!(result.data.id, 100);
        assert_eq!(result.data.name, None);
        assert_eq!(result.data.routes.len(), 1);
    }

    #[test]
    fn test_empty_input() {
        let result = parse_ip_route("", 254);
        assert!(result.data.routes.is_empty());
    }
}
