# netsim 테스트 현황

## 1. 테스트 요약

| 카테고리 | 파일 | 테스트 수 | 상태 |
|---------|------|----------|------|
| matcher 단위 테스트 | `netsim-core/src/matcher.rs` | 26 | 완료 |
| 통합 테스트 | `netsim-core/tests/integration_test.rs` | 48 | 완료 |
| 세션 테스트 | `netsim-core/tests/session_test.rs` | 6 | 완료 |
| 파서 테스트 | `netsim-parser/src/*.rs` | 46 | 완료 |
| **합계** | | **126** | |

---

## 2. Matcher 단위 테스트 (26개)

파일: `crates/netsim-core/src/matcher.rs`

NfMatch 조건별 매칭 로직을 검증한다.

| # | 테스트명 | 설명 |
|---|---------|------|
| 1 | `test_ip_saddr_match` | IP src CIDR 매칭 |
| 2 | `test_ip_daddr_exact` | IP dst 정확한 주소 매칭 |
| 3 | `test_tcp_dport_match` | TCP 목적지 포트 매칭 |
| 4 | `test_tcp_flags_syn` | TCP SYN 플래그 매칭 |
| 5 | `test_icmp_type_match` | ICMP type 이름 매칭 (echo-request) |
| 6 | `test_icmp_type_numeric_match` | ICMP type 숫자 매칭 (8) |
| 7 | `test_icmp_has_no_ports` | ICMP 패킷에 TCP dport 매칭 실패 확인 |
| 8 | `test_udp_dport_match` | UDP 목적지 포트 매칭 |
| 9 | `test_ct_state_match` | conntrack state 단일값 매칭 |
| 10 | `test_ct_state_set_match` | conntrack state set 매칭 (established,related) |
| 11 | `test_iif_match` | ingress 인터페이스 이름 매칭 |
| 12 | `test_mark_match_with_mask` | mark 비트마스크 매칭 |
| 13 | `test_port_range_match` | 포트 범위 매칭 (1024-65535) |
| 14 | `test_meta_l4proto` | meta l4proto 문자열 매칭 |
| 15 | `test_ip_neq` | IP not-equal 연산자 |
| 16 | `test_ip_addr_set_in` | IP 주소 set (comma-separated) 포함 매칭 |
| 17 | `test_tcp_flags_syn_ack` | TCP SYN+ACK 복합 플래그 매칭 |
| 18 | `test_port_set_match` | 포트 set 매칭 (22,80,443) |
| 19 | `test_port_set_no_match` | 포트 set 미매칭 확인 |
| 20 | `test_icmpv6_type_name` | ICMPv6 type 이름 매칭 (echo-request=128) |
| 21 | `test_meta_l4proto_numeric` | meta l4proto 숫자 매칭 (TCP=6) |
| 22 | `test_ct_mark_hex` | conntrack mark 16진수 매칭 |
| 23 | `test_l2_only_packet_ip_match_fails` | ARP 패킷은 IP 매칭 실패 |
| 24 | `test_ttl_match` | TTL 비교 매칭 (gt) |
| 25 | `test_empty_matches_always_true` | 빈 match 배열은 항상 true (catch-all) |
| 26 | `test_multiple_matches_and` | 다중 조건 AND 결합 검증 |

---

## 3. 통합 테스트 (48개)

파일: `crates/netsim-core/tests/integration_test.rs`

전체 시뮬레이션 파이프라인을 시나리오 단위로 검증한다.

| # | 테스트명 | 설명 |
|---|---------|------|
| 1 | `test_local_delivery_tcp` | TCP 패킷의 로컬 전달 (ingress → routing → INPUT → LOCAL_DELIVERY) |
| 2 | `test_forwarding_udp` | UDP 패킷 포워딩 (routing → FORWARD → POSTROUTING → FORWARDED) |
| 3 | `test_local_delivery_icmp` | ICMP 패킷의 로컬 전달 |
| 4 | `test_dnat_forwarding` | DNAT 적용 후 포워딩 (PREROUTING nat → routing → FORWARD) |
| 5 | `test_forward_drop_by_firewall` | FORWARD 체인에서 DROP |
| 6 | `test_snat_masquerade` | POSTROUTING에서 MASQUERADE 적용 |
| 7 | `test_xdp_drop` | XDP 단계에서 DROP |
| 8 | `test_policy_routing_fwmark` | fwmark 기반 정책 라우팅 |
| 9 | `test_blackhole_route` | blackhole 라우트 → BLACKHOLE verdict |
| 10 | `test_arp_packet_l2_only` | ARP 패킷 L2 바이패스 |
| 11 | `test_dnat_icmp_no_port_change` | ICMP DNAT 시 포트 변경 없음 확인 |
| 12 | `test_ttl_expired` | TTL=1 패킷 포워딩 시 DROP |
| 13 | `test_vrrp_local_delivery` | VRRP 프로토콜 로컬 전달 |
| 14 | `test_reject_verdict` | REJECT verdict (ICMP unreachable 응답) |
| 15 | `test_chain_default_policy_drop` | 체인 기본 정책 DROP |
| 16 | `test_iptables_rules` | iptables 규칙 평가 |
| 17 | `test_multiple_chains_priority_order` | 다중 체인 priority 순서 평가 |
| 18 | `test_established_passes_firewall` | established 상태 패킷 방화벽 통과 |
| 19 | `test_redirect_nat` | REDIRECT NAT (dst를 ingress 인터페이스 IP로) |
| 20 | `test_ipv6_local_delivery` | IPv6 패킷 로컬 전달 |
| 21 | `test_icmpv6_neighbour_solicitation` | ICMPv6 Neighbour Solicitation 처리 |
| 22 | `test_xdp_tx` | XDP TX (ingress 인터페이스로 반사) |
| 23 | `test_next_hop_in_summary` | summary에 next_hop 포함 확인 |
| 24 | `test_neq_match` | not-equal 매칭 연산자 |
| 25 | `test_stp_packet` | STP 패킷 L2 바이패스 |
| 26 | `test_nftables_and_iptables_mixed` | nftables + iptables 혼합 시나리오 |
| 27 | `test_sysctl_ip_forward_disabled` | ip_forward=false 시 포워딩 차단 |
| 28 | `test_sysctl_route_localnet_blocks_loopback_dnat` | route_localnet=false 시 127.x DNAT 차단 |
| 29 | `test_sysctl_route_localnet_allows_loopback_dnat` | route_localnet=true 시 127.x DNAT 허용 |
| 30 | `test_sysctl_icmp_echo_ignore_all` | icmp_echo_ignore_all=true 시 ICMP echo 무시 |
| 31 | `test_sysctl_rp_filter_strict` | rp_filter strict 모드 검증 |
| 32 | `test_ingress_interface_down` | ingress 인터페이스 DOWN 상태 → DROP |
| 33 | `test_egress_interface_down` | egress 인터페이스 DOWN 상태 → DROP |
| 34 | `test_mtu_exceeded_with_df_flag` | DF=true + MTU 초과 → DROP |
| 35 | `test_mtu_exceeded_without_df_flag` | DF=false + MTU 초과 → 통과 (fragmentation) |
| 36 | `test_bridge_member_detection` | 브릿지 멤버 인터페이스 감지 및 L2 포워딩 |
| 37 | `test_arp_ignore_level_1` | arp_ignore=1: 수신 인터페이스 IP만 ARP 응답 |
| 38 | `test_arp_ignore_level_2` | arp_ignore=2: 같은 서브넷 sender만 ARP 응답 |
| 39 | `test_arp_ignore_disabled` | arp_ignore=0: 모든 ARP 요청에 응답 |
| 40 | `test_empty_interfaces_list` | 빈 인터페이스 목록 → InterfaceCheck에서 DROP |
| 41 | `test_masquerade_ipv6` | IPv6 MASQUERADE |
| 42 | `test_interface_no_addresses_masquerade` | 주소 없는 인터페이스에서 MASQUERADE |
| 43 | `test_tproxy_forces_local_delivery` | TPROXY → 로컬 전달 (routing 우회) |
| 44 | `test_reroute_in_output` | OUTPUT 경로에서 mark 변경 후 reroute |
| 45 | `test_bridge_nf_pipeline` | bridge_nf_call_iptables=true 시 브릿지 NF 파이프라인 |
| 46 | `test_conntrack_nat_established` | established 패킷 conntrack NAT tuple 자동 적용 |
| 47 | `test_loopback_delivery` | OUTPUT → 라우팅 결과 LOCAL → loopback → INPUT → LOCAL_DELIVERY |
| 48 | `test_flow_remote_to_local` | TrafficFlow 확장 (Remote → Local) |

---

## 4. 세션 테스트 (6개)

파일: `crates/netsim-core/tests/session_test.rs`

세션 단위 시뮬레이션 (다중 패킷 시퀀스)을 검증한다.

| # | 테스트명 | 설명 |
|---|---------|------|
| 1 | `test_tcp_handshake_to_local` | TCP 3-way handshake → 로컬 서버 (SYN/SYN-ACK/ACK 3패킷) |
| 2 | `test_icmp_ping_session` | ICMP Echo Request + Echo Reply (2패킷) |
| 3 | `test_tcp_session_with_dnat` | TCP handshake + DNAT (NAT 매핑이 reply에 반영됨) |
| 4 | `test_tcp_session_blocked_by_firewall` | 방화벽 DROP 시 세션 실패 (SYN 1패킷만 시도) |
| 5 | `test_udp_dns_session` | UDP DNS 요청/응답 교환 (2패킷) |
| 6 | `test_tcp_full_session_with_data_and_close` | TCP 전체 세션: handshake + DATA + FIN (7패킷) |

---

## 5. 파서 테스트 (46개)

### ip_addr.rs (7개)

| # | 테스트명 | 설명 |
|---|---------|------|
| 1 | `test_parse_ip_addr_count` | 파싱된 인터페이스 수 검증 |
| 2 | `test_parse_loopback` | loopback 인터페이스 파싱 |
| 3 | `test_parse_eth0` | eth0 인터페이스 (IP, MAC, MTU, state) |
| 4 | `test_parse_bridge` | 브릿지 인터페이스 파싱 |
| 5 | `test_parse_veth` | veth 인터페이스 파싱 |
| 6 | `test_parse_vlan` | VLAN 인터페이스 파싱 |
| 7 | `test_empty_input` | 빈 입력 처리 |

### ip_route.rs (7개)

| # | 테스트명 | 설명 |
|---|---------|------|
| 1 | `test_parse_ip_route_count` | 파싱된 라우트 수 검증 |
| 2 | `test_parse_default_route` | 기본 라우트 (default via gateway) |
| 3 | `test_parse_connected_route` | 직접 연결 라우트 |
| 4 | `test_parse_blackhole` | blackhole 라우트 |
| 5 | `test_parse_unreachable` | unreachable 라우트 |
| 6 | `test_custom_table_id` | 커스텀 테이블 ID |
| 7 | `test_empty_input` | 빈 입력 처리 |

### ip_rule.rs (7개)

| # | 테스트명 | 설명 |
|---|---------|------|
| 1 | `test_parse_ip_rule_count` | 파싱된 규칙 수 검증 |
| 2 | `test_parse_rule_local` | local 테이블 규칙 |
| 3 | `test_parse_rule_with_from` | from selector 규칙 |
| 4 | `test_parse_rule_fwmark` | fwmark 규칙 |
| 5 | `test_parse_rule_main` | main 테이블 규칙 |
| 6 | `test_parse_rule_default` | default 테이블 규칙 |
| 7 | `test_empty_input` | 빈 입력 처리 |

### nft_list.rs (13개)

| # | 테스트명 | 설명 |
|---|---------|------|
| 1 | `test_parse_nft_table_count` | 파싱된 테이블 수 검증 |
| 2 | `test_parse_filter_table` | filter 테이블 구조 |
| 3 | `test_parse_input_chain` | input 체인 (hook, priority, policy) |
| 4 | `test_parse_iif_accept` | iif 매칭 + accept 규칙 |
| 5 | `test_parse_ct_state` | ct state 매칭 |
| 6 | `test_parse_tcp_dport` | TCP dport 매칭 |
| 7 | `test_parse_counter_drop` | counter + drop 액션 |
| 8 | `test_parse_forward_chain_policy` | forward 체인 정책 |
| 9 | `test_parse_iifname_oifname` | iifname/oifname 매칭 |
| 10 | `test_parse_nat_table` | nat 테이블 |
| 11 | `test_parse_dnat` | DNAT 규칙 |
| 12 | `test_parse_masquerade` | masquerade 규칙 |
| 13 | `test_empty_input` | 빈 입력 처리 |

### iptables_save.rs (10개)

| # | 테스트명 | 설명 |
|---|---------|------|
| 1 | `test_parse_table_count` | 파싱된 테이블 수 검증 |
| 2 | `test_parse_filter_table` | filter 테이블 구조 |
| 3 | `test_parse_chain_policies` | 체인 기본 정책 |
| 4 | `test_parse_input_rules` | INPUT 규칙 파싱 |
| 5 | `test_parse_state_match` | conntrack state 매칭 |
| 6 | `test_parse_dport_match` | dport 매칭 |
| 7 | `test_parse_nat_table` | nat 테이블 |
| 8 | `test_parse_dnat_rule` | DNAT 규칙 |
| 9 | `test_parse_masquerade_rule` | masquerade 규칙 |
| 10 | `test_empty_input` | 빈 입력 처리 |

### lib.rs (2개)

| # | 테스트명 | 설명 |
|---|---------|------|
| 1 | `test_parse_system_config_empty` | 빈 입력으로 전체 파싱 |
| 2 | `test_parse_system_config_all` | 모든 필드 입력으로 전체 파싱 |

---

## 6. 테스트 실행 방법

```bash
# 전체 테스트 실행
cargo test

# crate별 실행
cargo test -p netsim-core          # 엔진: matcher 26 + integration 48 + session 6 = 80
cargo test -p netsim-parser        # 파서: 46
cargo test -p netsim-server        # 서버: (현재 테스트 없음)

# 특정 테스트 실행
cargo test -p netsim-core test_dnat_forwarding
cargo test -p netsim-core test_tcp_handshake_to_local

# matcher 테스트만
cargo test -p netsim-core matcher::tests

# 통합 테스트만
cargo test -p netsim-core --test integration_test

# 세션 테스트만
cargo test -p netsim-core --test session_test

# 파서 테스트만
cargo test -p netsim-parser
```

---

## 7. 테스트 커버리지 요약

### netsim-core 커버리지

| 영역 | 커버리지 |
|------|---------|
| matcher (NfMatch 전 타입) | 높음 — 26개 단위 테스트로 모든 NfMatch variant 커버 |
| engine::run (ingress) | 높음 — 48개 통합 테스트로 모든 PipelineStage 경유 |
| engine::run_output (output) | 중간 — reroute, loopback 테스트 포함 |
| session_engine | 높음 — TCP/ICMP/UDP 세션 + NAT 반영 + 실패 케이스 |
| pipeline/chain_eval | 높음 — Jump/Goto, policy DROP, priority order 검증 |
| pipeline/nat | 높음 — DNAT/SNAT/Masquerade/Redirect/Tproxy 모두 검증 |
| pipeline/stages | 높음 — interface_check, bridge, arp, sysctl, mtu 모두 검증 |
| model/ | 간접 — 통합 테스트를 통해 직렬화/역직렬화 커버 |

### netsim-parser 커버리지

| 파서 | 커버리지 |
|------|---------|
| ip_addr | 높음 — 다양한 인터페이스 타입 (lo, eth, bridge, veth, vlan) |
| ip_route | 높음 — default/connected/blackhole/unreachable, 커스텀 테이블 |
| ip_rule | 높음 — local/main/default, from selector, fwmark |
| nft_list | 높음 — filter/nat 테이블, 다양한 match/action |
| iptables_save | 높음 — filter/nat, policy, state match, DNAT, masquerade |

### 미구현 테스트 영역

- API 엔드포인트 테스트 (netsim-server)
- 프론트엔드 컴포넌트 테스트
- Scenario YAML/JSON 직렬화 라운드트립 테스트
- flow.rs 확장 로직 추가 테스트 (현재 1개)
