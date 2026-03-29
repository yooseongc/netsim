pub mod error;
pub mod ip_addr;
pub mod ip_route;
pub mod ip_rule;
pub mod iptables_save;
pub mod nft_list;
pub mod validation;

use netsim_core::model::{
    Interface, IpRule, NetfilterConfig, RoutingTable,
};

use crate::validation::{ParseResult, ValidationReport};

/// 시스템 설정 입력을 위한 구조체.
/// 각 필드는 해당 명령어의 출력을 담는다.
#[derive(Debug, Clone, Default)]
pub struct SystemConfigInput {
    pub ip_addr: Option<String>,
    pub ip_rule: Option<String>,
    /// ip route show 출력 (기본 테이블 254 main)
    pub ip_route: Option<String>,
    pub nft_list_ruleset: Option<String>,
    pub iptables_save: Option<String>,
}

/// 부분적으로 파싱된 시나리오.
/// 각 시스템 설정 파서의 결과를 모아놓은 구조체이다.
#[derive(Debug, Clone, Default)]
pub struct PartialScenario {
    pub interfaces: Vec<Interface>,
    pub routing_tables: Vec<RoutingTable>,
    pub ip_rules: Vec<IpRule>,
    pub netfilter: NetfilterConfig,
}

/// 시스템 설정 입력을 파싱하여 `PartialScenario`를 반환한다.
///
/// 각 필드가 `Some`이면 해당 파서를 호출하고, `None`이면 빈 기본값을 사용한다.
/// 파싱 결과와 유효성 보고서를 함께 반환한다.
pub fn parse_system_config(input: &SystemConfigInput) -> ParseResult<PartialScenario> {
    let mut scenario = PartialScenario::default();
    let mut report = ValidationReport::new();

    // ip addr
    if let Some(ref text) = input.ip_addr {
        let r = ip_addr::parse_ip_addr(text);
        report.merge(r.report);
        scenario.interfaces = r.data;
    }

    // ip rule
    if let Some(ref text) = input.ip_rule {
        let r = ip_rule::parse_ip_rule(text);
        report.merge(r.report);
        scenario.ip_rules = r.data;
    }

    // ip route (default table 254 = main)
    if let Some(ref text) = input.ip_route {
        let r = ip_route::parse_ip_route(text, 254);
        report.merge(r.report);
        scenario.routing_tables.push(r.data);
    }

    // nft list ruleset
    if let Some(ref text) = input.nft_list_ruleset {
        let r = nft_list::parse_nft_list(text);
        report.merge(r.report);
        scenario.netfilter.nftables = Some(r.data);
    }

    // iptables-save
    if let Some(ref text) = input.iptables_save {
        let r = iptables_save::parse_iptables_save(text);
        report.merge(r.report);
        scenario.netfilter.iptables = Some(r.data);
    }

    ParseResult {
        data: scenario,
        report,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_system_config_empty() {
        let input = SystemConfigInput::default();
        let result = parse_system_config(&input);
        assert!(result.data.interfaces.is_empty());
        assert!(result.data.routing_tables.is_empty());
        assert!(result.data.ip_rules.is_empty());
        assert!(result.data.netfilter.nftables.is_none());
        assert!(result.data.netfilter.iptables.is_none());
    }

    #[test]
    fn test_parse_system_config_all() {
        let input = SystemConfigInput {
            ip_addr: Some("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo".to_string()),
            ip_rule: Some("0:\tfrom all lookup local\n32766:\tfrom all lookup main".to_string()),
            ip_route: Some("default via 10.0.0.254 dev eth0".to_string()),
            nft_list_ruleset: Some("table ip filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\taccept\n\t}\n}".to_string()),
            iptables_save: Some("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT".to_string()),
        };

        let result = parse_system_config(&input);
        assert_eq!(result.data.interfaces.len(), 1);
        assert_eq!(result.data.ip_rules.len(), 2);
        assert_eq!(result.data.routing_tables.len(), 1);
        assert!(result.data.netfilter.nftables.is_some());
        assert!(result.data.netfilter.iptables.is_some());
    }
}
