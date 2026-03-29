# 네트워크 스택 시뮬레이션 명세

netsim 엔진이 시뮬레이션하는 Linux 커널 패킷 처리 경로의 상세 문서.

## 코드 참조

- 엔진 진입점: `crates/netsim-core/src/engine.rs`
- 파이프라인 컨텍스트: `crates/netsim-core/src/pipeline/context.rs`

## Ingress 경로 (`engine::run`)

```
  Packet In
     |
     v
  [01. Interface Check] ---- iface 미존재/DOWN/NIC frame size --> DROP
     |
     v
  [02. XDP] ---- XDP_DROP/XDP_ABORTED --> DROP
     |          |- XDP_TX --> TX
     |          '- XDP_REDIRECT --> REDIRECT
     v
  [03. Bridge Check] ---- bridge member && br_nf_call_iptables=0 --> L2 FORWARDED
     |                '--- bridge member && br_nf_call_iptables=1 --> BrNf Pipeline
     v
  [04. ARP Process] ---- arp_ignore 조건 불일치 --> DROP
     |
     v
  [L2 Bypass] ---- EtherType=ARP/STP/LLDP --> LOCAL_DELIVERY (netfilter 건너뜀)
     |
     v
  [05. tc ingress] ---- (MVP: pass-through)
     |
     v
  [06. PREROUTING]
     |-- (a) RAW chains (priority <= -200)
     |-- (b) Conntrack lookup (ct_state 분류)
     |-- (b-1) Conntrack NAT 1-time (established/related --> 저장된 NAT tuple 적용)
     '-- (c) Post-conntrack chains (mangle/nat/filter, DNAT/TPROXY 여기서 적용)
     |
     v
  [rp_filter] ---- strict/loose 역경로 검사 실패 --> DROP
     |
     v
  [TPROXY Override] ---- tproxy_applied=true --> routing_result=Local 강제
     |
     v
  [route_localnet Check] ---- dst=127.x && route_localnet=0 --> DROP
     |
     v
  [07. Routing Decision]
     |-- dst가 로컬 주소 --> LOCAL path
     |-- dst에 대한 경로 존재 --> FORWARD path
     |-- blackhole/unreachable/prohibit --> DROP
     '-- 경로 없음 --> DROP
     |
     +----------- LOCAL path -----------+---------- FORWARD path ----------+
     |                                  |                                  |
     v                                  v                                  |
  [icmp_echo_ignore_all]            [Egress Interface Check]              |
     |                                  |                                  |
     v                                  v                                  |
  [08. INPUT chains]                [ip_forward Check]                     |
     |                                  |                                  |
     v                                  v                                  |
  LOCAL_DELIVERY                    [09. FORWARD chains] (TTL -1)          |
                                        |                                  |
                                        v                                  |
                                    [10. POSTROUTING chains] (SNAT/MASQ)   |
                                        |                                  |
                                        v                                  |
                                    [11. MTU Check]                        |
                                        |                                  |
                                        v                                  |
                                    [Conntrack Confirm]                    |
                                        |                                  |
                                        v                                  |
                                    FORWARDED                              |
```

## Output 경로 (`engine::run_output`)

```
  Local Process
     |
     v
  [12. OUTPUT chains]
     |-- (a) RAW chains (priority <= -200)
     |-- (b) Conntrack lookup
     '-- (c) Post-conntrack chains (mangle/filter/nat)
     |
     v
  [Routing Decision (post-OUTPUT)]
     |-- dst가 로컬 주소 --> Loopback path --> INPUT --> LOCAL_DELIVERY
     |-- dst에 대한 경로 존재 --> egress 결정
     '-- 경로 없음 --> DROP
     |
     v
  [Reroute Check] ---- mark 변경 + fwmark policy rules --> 재라우팅 기록
     |
     v
  [POSTROUTING chains] (SNAT/MASQ)
     |
     v
  [MTU Check]
     |
     v
  [Conntrack Confirm]
     |
     v
  SENT
```

## Bridge NF Pipeline (`bridge_nf_call_iptables=1`)

```
  Bridge member detection
     |
     v
  [BrNf PREROUTING] --> PREROUTING chains 평가
     |
     v
  [Bridge Forwarding Decision]
     |
     v
  [BrNf FORWARD] --> FORWARD chains 평가
     |
     v
  [BrNf POSTROUTING] --> POSTROUTING chains 평가
     |
     v
  Continue to normal IP stack
```

## FinalVerdict 종류

| Verdict | 설명 |
|---------|------|
| `Drop` | 패킷 폐기 |
| `LocalDelivery` | 로컬 프로세스에 전달 |
| `Forwarded` | 다른 인터페이스로 포워딩 완료 |
| `Redirect` | XDP redirect |
| `Tx` | XDP TX (동일 인터페이스로 반송) |
| `Rejected` | REJECT (ICMP unreachable 응답 전송) |
| `Blackhole` | Blackhole route |
| `Tproxy` | TPROXY stolen |
| `Sent` | 로컬 발신 패킷 전송 완료 |

## 문서 목록

### Pipeline Stage 문서

- [01. Interface Check](01-interface-check.md)
- [02. XDP](02-xdp.md)
- [03. Bridge](03-bridge.md)
- [04. ARP](04-arp.md)
- [05. tc ingress](05-tc-ingress.md)
- [06. PREROUTING](06-prerouting.md)
- [07. Routing](07-routing.md)
- [08. Local Input](08-local-input.md)
- [09. Forward](09-forward.md)
- [10. POSTROUTING](10-postrouting.md)
- [11. MTU Check](11-mtu-check.md)
- [12. Output](12-output.md)

### Model 문서

- [Packet Model](model-packet.md)
- [Netfilter Model](model-netfilter.md)
- [Conntrack Model](model-conntrack.md)
- [Interface Model](model-interface.md)
- [Sysctl Model](model-sysctl.md)
- [Endpoint Model](model-endpoint.md)
- [Session Model](model-session.md)
