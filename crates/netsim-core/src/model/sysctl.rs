//! 커널 파라미터 (sysctl) 모델
//!
//! 시뮬레이션 동작에 영향을 미치는 Linux 커널 파라미터를 정의한다.
//! 실제 `/proc/sys/net/` 하위의 파라미터 중 시뮬레이션에 영향을 주는 것만 모델링한다.
//!
//! ## 영향을 주는 주요 파라미터
//!
//! | sysctl 경로 | 기본값 | 영향 |
//! |-------------|--------|------|
//! | net.ipv4.ip_forward | 0 | IP 포워딩 활성화 여부 |
//! | net.ipv4.conf.{iface}.forwarding | (ip_forward) | 인터페이스별 포워딩 |
//! | net.ipv4.conf.{iface}.route_localnet | 0 | 127.0.0.0/8 라우팅 허용 |
//! | net.ipv4.conf.{iface}.rp_filter | 1 | Reverse Path 필터링 |
//! | net.ipv4.conf.{iface}.accept_local | 0 | 로컬 소스 주소 허용 |
//! | net.ipv4.conf.{iface}.send_redirects | 1 | ICMP redirect 전송 |
//! | net.ipv4.icmp_echo_ignore_all | 0 | 모든 ICMP echo 무시 |
//! | net.ipv4.icmp_echo_ignore_broadcasts | 1 | 브로드캐스트 ICMP echo 무시 |
//! | net.ipv4.conf.{iface}.log_martians | 0 | 비정상 패킷 로깅 |
//! | net.ipv4.conf.{iface}.proxy_arp | 0 | Proxy ARP |
//! | net.ipv6.conf.{iface}.forwarding | 0 | IPv6 포워딩 |
//! | net.bridge.bridge-nf-call-iptables | 0 | 브릿지 패킷에 iptables 적용 |

use serde::{Deserialize, Serialize};

/// 시뮬레이션에 영향을 주는 커널 파라미터
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SysctlConfig {
    /// 전역 IPv4 설정
    #[serde(default)]
    pub ipv4: Ipv4Sysctl,

    /// 전역 IPv6 설정
    #[serde(default)]
    pub ipv6: Ipv6Sysctl,

    /// 인터페이스별 설정 (key = interface name, "all"/"default" 가능)
    #[serde(default)]
    pub interface_conf: std::collections::HashMap<String, InterfaceSysctl>,
}

impl Default for SysctlConfig {
    fn default() -> Self {
        Self {
            ipv4: Ipv4Sysctl::default(),
            ipv6: Ipv6Sysctl::default(),
            interface_conf: std::collections::HashMap::new(),
        }
    }
}

impl SysctlConfig {
    /// 특정 인터페이스의 설정 조회 (iface → all → default 순으로 fallback)
    pub fn get_interface_conf(&self, iface: &str) -> InterfaceSysctl {
        // 1. 해당 인터페이스의 명시적 설정
        if let Some(conf) = self.interface_conf.get(iface) {
            return conf.clone();
        }
        // 2. "all" 설정
        if let Some(conf) = self.interface_conf.get("all") {
            return conf.clone();
        }
        // 3. "default" 설정
        if let Some(conf) = self.interface_conf.get("default") {
            return conf.clone();
        }
        // 4. 기본값
        InterfaceSysctl::default()
    }

    /// 포워딩이 활성화되어 있는지 (전역 또는 인터페이스별)
    pub fn is_forwarding_enabled(&self, ingress_if: &str) -> bool {
        // 인터페이스별 설정이 있으면 우선
        let iface_conf = self.get_interface_conf(ingress_if);
        if let Some(fwd) = iface_conf.forwarding {
            return fwd;
        }
        // 전역 설정
        self.ipv4.ip_forward
    }

    /// 인터페이스에서 route_localnet이 활성화되어 있는지
    pub fn is_route_localnet(&self, iface: &str) -> bool {
        self.get_interface_conf(iface).route_localnet
    }

    /// Reverse Path Filter 모드 조회
    pub fn rp_filter_mode(&self, iface: &str) -> RpFilterMode {
        self.get_interface_conf(iface).rp_filter
    }

    /// ICMP echo를 무시하는지
    pub fn icmp_echo_ignore_all(&self) -> bool {
        self.ipv4.icmp_echo_ignore_all
    }

    /// 브로드캐스트 ICMP echo를 무시하는지
    pub fn icmp_echo_ignore_broadcasts(&self) -> bool {
        self.ipv4.icmp_echo_ignore_broadcasts
    }
}

/// 전역 IPv4 커널 파라미터
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ipv4Sysctl {
    /// net.ipv4.ip_forward — IP 포워딩 활성화
    /// 기본값: true (시뮬레이션에서는 일반적으로 라우터를 시뮬레이션)
    #[serde(default = "default_true")]
    pub ip_forward: bool,

    /// net.ipv4.icmp_echo_ignore_all — 모든 ICMP echo request 무시
    #[serde(default)]
    pub icmp_echo_ignore_all: bool,

    /// net.ipv4.icmp_echo_ignore_broadcasts — 브로드캐스트 ICMP echo 무시
    #[serde(default = "default_true")]
    pub icmp_echo_ignore_broadcasts: bool,

    /// net.ipv4.tcp_syncookies — SYN cookies 활성화
    #[serde(default = "default_true")]
    pub tcp_syncookies: bool,
}

impl Default for Ipv4Sysctl {
    fn default() -> Self {
        Self {
            ip_forward: true,
            icmp_echo_ignore_all: false,
            icmp_echo_ignore_broadcasts: true,
            tcp_syncookies: true,
        }
    }
}

/// 전역 IPv6 커널 파라미터
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ipv6Sysctl {
    /// net.ipv6.conf.all.forwarding
    #[serde(default = "default_true")]
    pub forwarding: bool,
}

impl Default for Ipv6Sysctl {
    fn default() -> Self {
        Self { forwarding: true }
    }
}

/// 인터페이스별 커널 파라미터
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InterfaceSysctl {
    /// net.ipv4.conf.{iface}.forwarding — 인터페이스별 포워딩 오버라이드
    /// None이면 전역 ip_forward 사용
    #[serde(default)]
    pub forwarding: Option<bool>,

    /// net.ipv4.conf.{iface}.route_localnet — 127.0.0.0/8에 대한 라우팅 허용
    /// true면 DNAT로 127.0.0.1:port 로 리다이렉트 가능
    #[serde(default)]
    pub route_localnet: bool,

    /// net.ipv4.conf.{iface}.rp_filter — Reverse Path 필터링
    #[serde(default)]
    pub rp_filter: RpFilterMode,

    /// net.ipv4.conf.{iface}.accept_local — 로컬 소스 주소 패킷 수신 허용
    #[serde(default)]
    pub accept_local: bool,

    /// net.ipv4.conf.{iface}.send_redirects — ICMP redirect 전송
    #[serde(default = "default_true")]
    pub send_redirects: bool,

    /// net.ipv4.conf.{iface}.log_martians — 비정상 소스 주소 패킷 로깅
    #[serde(default)]
    pub log_martians: bool,

    /// net.ipv4.conf.{iface}.proxy_arp — Proxy ARP 활성화
    #[serde(default)]
    pub proxy_arp: bool,
}

impl Default for InterfaceSysctl {
    fn default() -> Self {
        Self {
            forwarding: None,
            route_localnet: false,
            // 시뮬레이션 기본값: Off (실제 Linux 기본값은 Strict이지만,
            // 시뮬레이션에서는 rp_filter가 의도적 설정이 아닌 한 방해하지 않도록)
            rp_filter: RpFilterMode::Off,
            accept_local: false,
            send_redirects: true,
            log_martians: false,
            proxy_arp: false,
        }
    }
}

/// Reverse Path Filter 모드
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RpFilterMode {
    /// 비활성화 (0)
    Off,
    /// Strict mode (1) — 패킷이 들어온 인터페이스로 역라우팅 가능해야 함
    #[default]
    Strict,
    /// Loose mode (2) — 어떤 인터페이스로든 역라우팅 가능하면 통과
    Loose,
}

fn default_true() -> bool {
    true
}
