# Model: Sysctl

Linux 커널 파라미터(sysctl) 모델. 시뮬레이션 동작에 영향을 미치는 `/proc/sys/net/` 파라미터를 정의한다.

## 코드 참조

- `crates/netsim-core/src/model/sysctl.rs`

## SysctlConfig

최상위 sysctl 설정.

| 필드 | 타입 | 기본값 | sysctl 경로 |
|------|------|--------|-------------|
| `ipv4` | `Ipv4Sysctl` | (아래 참조) | `net.ipv4.*` |
| `ipv6` | `Ipv6Sysctl` | (아래 참조) | `net.ipv6.*` |
| `interface_conf` | `HashMap<String, InterfaceSysctl>` | `{}` | `net.ipv4.conf.{iface}.*` |
| `bridge_nf_call_iptables` | `bool` | `false` | `net.bridge.bridge-nf-call-iptables` |
| `bridge_nf_call_ip6tables` | `bool` | `false` | `net.bridge.bridge-nf-call-ip6tables` |
| `bridge_nf_call_arptables` | `bool` | `false` | `net.bridge.bridge-nf-call-arptables` |

## Ipv4Sysctl (전역 IPv4)

| 필드 | 기본값 | sysctl 경로 | 영향 |
|------|--------|-------------|------|
| `ip_forward` | `true` | `net.ipv4.ip_forward` | IP 포워딩 활성화 |
| `icmp_echo_ignore_all` | `false` | `net.ipv4.icmp_echo_ignore_all` | ICMP echo request 전체 무시 |
| `icmp_echo_ignore_broadcasts` | `true` | `net.ipv4.icmp_echo_ignore_broadcasts` | 브로드캐스트 ICMP echo 무시 |
| `tcp_syncookies` | `true` | `net.ipv4.tcp_syncookies` | SYN cookies 활성화 |

> 참고: 시뮬레이터에서 `ip_forward` 기본값은 `true` (라우터 시뮬레이션 기본 가정). 실제 Linux 기본값은 `0`이다.

## Ipv6Sysctl (전역 IPv6)

| 필드 | 기본값 | sysctl 경로 | 영향 |
|------|--------|-------------|------|
| `forwarding` | `true` | `net.ipv6.conf.all.forwarding` | IPv6 포워딩 |

## InterfaceSysctl (인터페이스별)

`interface_conf`의 key는 인터페이스 이름, `"all"`, 또는 `"default"`. Fallback 순서: iface -> all -> default -> 코드 기본값.

| 필드 | 기본값 | sysctl 경로 | 영향 |
|------|--------|-------------|------|
| `forwarding` | `None` | `conf.{iface}.forwarding` | 인터페이스별 포워딩 오버라이드 (None이면 전역) |
| `route_localnet` | `false` | `conf.{iface}.route_localnet` | 127.0.0.0/8 라우팅 허용 |
| `rp_filter` | `Off` | `conf.{iface}.rp_filter` | Reverse Path Filter (Off/Strict/Loose) |
| `accept_local` | `false` | `conf.{iface}.accept_local` | 로컬 소스 주소 패킷 수신 허용 |
| `send_redirects` | `true` | `conf.{iface}.send_redirects` | ICMP redirect 전송 |
| `log_martians` | `false` | `conf.{iface}.log_martians` | 비정상 패킷 로깅 |
| `proxy_arp` | `false` | `conf.{iface}.proxy_arp` | Proxy ARP |
| `proxy_arp_pvlan` | `false` | `conf.{iface}.proxy_arp_pvlan` | Private VLAN proxy ARP |
| `arp_ignore` | `0` | `conf.{iface}.arp_ignore` | ARP 응답 제어 (0-8) |
| `arp_announce` | `0` | `conf.{iface}.arp_announce` | ARP 요청 소스 IP 선택 (0-2) |
| `arp_filter` | `false` | `conf.{iface}.arp_filter` | ARP 필터링 |

## RpFilterMode

| 모드 | 값 | 동작 |
|------|---|------|
| `Off` | 0 | 비활성화 |
| `Strict` | 1 | ingress 인터페이스로 역라우팅 가능해야 함 (코드상 기본값) |
| `Loose` | 2 | 어떤 인터페이스로든 역라우팅 가능하면 통과 |

> 참고: 코드의 `RpFilterMode` default는 `Strict`이지만, `InterfaceSysctl`의 `rp_filter` 기본값은 `Off`이다.

## 파이프라인 영향 관계

| sysctl | 검사 단계 | 조건 | 결과 |
|--------|-----------|------|------|
| `ip_forward` | Forward | false | DROP |
| `conf.forwarding` | Forward | false (전역 무시) | DROP |
| `rp_filter` | rp_filter (routing 전) | 역경로 불일치 | DROP |
| `route_localnet` | Routing (전) | dst=127.x, false | DROP |
| `icmp_echo_ignore_all` | Local Input (전) | true + ICMP echo | DROP |
| `bridge_nf_call_iptables` | Bridge | true | BrNf Pipeline 실행 |
| `bridge_nf_call_iptables` | Bridge | false | L2 포워딩 |
| `arp_ignore` | ARP Process | >= 1 | 조건부 ARP DROP |

## 헬퍼 메서드

| 메서드 | 설명 |
|--------|------|
| `get_interface_conf(iface)` | 인터페이스별 설정 조회 (fallback 포함) |
| `is_forwarding_enabled(iface)` | 포워딩 활성화 여부 (인터페이스별 우선) |
| `is_route_localnet(iface)` | route_localnet 활성화 여부 |
| `rp_filter_mode(iface)` | rp_filter 모드 조회 |
| `icmp_echo_ignore_all()` | ICMP echo 무시 여부 |
| `icmp_echo_ignore_broadcasts()` | 브로드캐스트 ICMP echo 무시 여부 |
