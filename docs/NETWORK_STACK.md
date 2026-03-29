# 리눅스 네트워크 스택 시뮬레이션 구현 명세

> 이 문서는 `netsim-core` 엔진의 **현재 구현**을 기준으로 작성되었습니다.
> 소스 참조: `engine.rs`, `trace.rs`, `pipeline/mod.rs`, `model/sysctl.rs`, `model/interface.rs`, `model/packet.rs`, `session_engine.rs`, `matcher.rs`

---

## 1. 개요

netsim 엔진은 리눅스 커널의 패킷 처리 경로를 충실히 시뮬레이션한다. 두 가지 독립적인 파이프라인을 제공한다.

| 경로 | 함수 | 설명 |
|------|------|------|
| **Ingress** | `engine::run()` | 외부에서 수신된 패킷의 처리 경로 (NIC → XDP → netfilter → routing → 전달/로컬) |
| **Output** | `engine::run_output()` | 로컬에서 발신된 패킷의 처리 경로 (OUTPUT chains → routing → POSTROUTING → 전송) |

각 단계는 `TraceStep`으로 기록되며, 최종 판정(`FinalVerdict`)과 패킷 상태 변화 이력을 반환한다.

---

## 2. Ingress 파이프라인 (`engine::run`)

### 2.1 흐름도

```
 [패킷 수신]
     │
     ▼
 ┌─────────────────────────────────────┐
 │  Stage 0: InterfaceCheck            │
 │  (a) 인터페이스 존재 확인            │──── 없음 ──→ DROP
 │  (b) UP/DOWN 상태 확인              │──── DOWN ──→ DROP
 │  (c) Physical NIC 프레임 크기 검사   │──── 초과 ──→ DROP
 │      (Physical 타입만, pkt_len >     │
 │       max(MTU+18, 9216))            │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 1: XDP                       │
 │  XDP_PASS / XDP_DROP / XDP_TX /     │
 │  XDP_REDIRECT                       │
 └──────────────┬──────────────────────┘
                │ PASS
                ▼
 ┌─────────────────────────────────────┐
 │  Bridge Member Check                │
 │  ingress_if.master 존재?            │
 │  ├─ Yes: bridge_nf_call_iptables?   │
 │  │  ├─ false → BridgeForward        │──→ FORWARDED
 │  │  └─ true  → continue (IP stack)  │
 │  └─ No: continue                    │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  ARP Processing                     │
 │  ethertype == Arp?                  │
 │  ├─ Yes: arp_ignore >= 1?           │
 │  │  ├─ target_ip not on iface       │──→ DROP
 │  │  └─ arp_ignore >= 2?             │
 │  │     └─ sender not same subnet    │──→ DROP
 │  └─ No: continue                    │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  L2 Bypass Check                    │
 │  ethertype.is_l2_only()?            │
 │  (ARP, STP, LLDP)                  │
 │  ├─ Yes → L2Bypass                  │──→ LOCAL_DELIVERY
 │  └─ No: continue                    │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 2: TC Ingress                │
 │  (현재 정보만 기록, pass-through)    │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 3a: PREROUTING RAW           │
 │  priority <= -200 체인만             │
 │  (raw 테이블, conntrack 이전)        │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 3b: Conntrack Lookup         │
 │  ct_state 분류 (user-declared)      │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 3c: PREROUTING post-CT       │
 │  priority > -200 체인               │
 │  (mangle -150, nat -100,            │
 │   filter 0, security 50,            │
 │   srcnat 100)                       │
 │  TPROXY 적용 시 Stolen 반환 안 함    │
 │  (routing으로 계속 진행)             │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  sysctl: rp_filter                  │
 │  Reverse Path Filtering             │
 │  Off(0): skip                       │
 │  Strict(1): reverse route ==        │
 │             ingress_if 필요          │──── 불일치 ──→ DROP
 │  Loose(2): 역경로 존재만 확인        │──── 없음 ──→ DROP
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  sysctl: route_localnet             │
 │  dst가 127.0.0.0/8이면              │
 │  route_localnet=true 필요            │──── false ──→ DROP
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 5: Routing Decision          │
 │  ip_rules → routing_tables 조회     │
 │  결과: LOCAL / FORWARD / DROP /     │
 │        REJECT / BLACKHOLE           │
 └──────────┬───────────┬──────────────┘
            │           │
      LOCAL │           │ FORWARD
            ▼           ▼
 ┌──────────────┐  ┌──────────────────────────────────┐
 │ icmp_echo_   │  │ (d) Egress IF 존재/UP 확인       │── 실패 → DROP
 │ ignore_all?  │  ├───────────────────────────────────┤
 │ + ICMP echo? │  │ sysctl: ip_forward 확인           │── 비활성 → DROP
 │ → DROP       │  ├───────────────────────────────────┤
 ├──────────────┤  │ Stage 6b: FORWARD chains          │
 │ Stage 6a:    │  │ (TTL 감소 후 체인 평가,            │
 │ INPUT chains │  │  TTL=0 → DROP + Time Exceeded)    │
 │              │  ├───────────────────────────────────┤
 │ 통과 시:     │  │ Stage 7: POSTROUTING chains       │
 │ LOCAL_       │  │ (SNAT, MASQUERADE 적용)           │
 │ DELIVERY     │  ├───────────────────────────────────┤
 └──────────────┘  │ (e) MTU Check                     │
                   │  pkt_len > egress MTU?            │
                   │  ├─ DF=true → DROP (ICMP needed)  │
                   │  └─ DF=false → fragmentation      │
                   ├───────────────────────────────────┤
                   │ Stage 8: ConntrackConfirm          │
                   │ → FORWARDED                        │
                   └───────────────────────────────────┘
```

### 2.2 Routing Decision 분기 상세

`pipeline::routing::execute()` 반환값에 따른 분기:

| `StageDecision` | 후속 처리 |
|---|---|
| `LocalDelivery` | icmp_echo_ignore_all 체크 → INPUT chains → `LOCAL_DELIVERY` |
| `ForwardTo { egress_if, next_hop }` | egress IF 검증 → ip_forward 체크 → FORWARD → POSTROUTING → MTU → ConntrackConfirm → `FORWARDED` |
| `Drop` | 즉시 `DROP` |
| `Reject` | 즉시 `REJECTED` |
| `Stolen` | `TPROXY` (TPROXY에 의해 패킷이 로컬로 전달됨) |
| `Redirect` | `REDIRECT` |
| 기타 | `DROP` |

---

## 2.1 Output 파이프라인 (`engine::run_output`)

### 흐름도

```
 [로컬 발신 패킷]
     │
     ▼
 ┌─────────────────────────────────────┐
 │  Stage 1a: OUTPUT RAW               │
 │  priority <= -200 체인               │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 1b: Conntrack Lookup         │
 │  ct_state 분류 (user-declared)      │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 1c: OUTPUT post-CT           │
 │  priority > -200 체인               │
 │  (mangle, filter, nat)              │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 2: Routing Decision          │
 │  ip_rules → routing_tables 조회     │
 │  DROP/REJECT → 즉시 종료            │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 3: POSTROUTING chains        │
 │  (SNAT, MASQUERADE 적용)            │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 4: MTU Check                 │
 │  pkt_len > egress MTU?              │
 │  ├─ DF=true → DROP                  │
 │  └─ DF=false → fragmentation        │
 └──────────────┬──────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────┐
 │  Stage 5: ConntrackConfirm          │
 └──────────────┬──────────────────────┘
                │
                ▼
            [ SENT ]
```

---

## 3. 단계별 상세

### 3.1 InterfaceCheck

| 항목 | 값 |
|---|---|
| **PipelineStage** | `InterfaceCheck` |
| **위치** | Ingress Stage 0 / Forward 경로 내 egress 검증 |
| **동작** | (a) 인터페이스 존재 여부 확인, (b) UP/DOWN 상태 확인, (c) Physical NIC 프레임 크기 검사 |
| **sysctl 의존** | 없음 |
| **결과** | Continue / Drop |

- **(a)** `find_interface()`로 `ingress_if` 조회. 없으면 DROP.
- **(b)** `iface.is_up()` 확인. DOWN이면 DROP.
- **(c)** `InterfaceKind::Physical`일 때만 수행. `packet_length`가 `max(MTU + 18, 9216)` 초과 시 DROP. 18은 L2 오버헤드(Ethernet header 14 + FCS 4), 9216은 jumbo frame 최소 수용 크기.
- Forward 경로에서는 egress 인터페이스에 대해 (a), (b)를 추가 수행.

### 3.2 Xdp

| 항목 | 값 |
|---|---|
| **PipelineStage** | `Xdp` |
| **위치** | Ingress Stage 1 |
| **동작** | XDP 프로그램 평가 (드라이버 레벨, L2/L3 처리 이전) |
| **sysctl 의존** | 없음 |
| **결과** | Continue(PASS) / Drop(DROP) / Redirect(TX 또는 REDIRECT) |

- XDP_PASS: 다음 단계로 진행.
- XDP_DROP: 즉시 `FinalVerdict::Drop`.
- XDP_TX/XDP_REDIRECT: target이 ingress_if와 같으면 `Tx`, 다르면 `Redirect`.

### 3.3 BridgeForward

| 항목 | 값 |
|---|---|
| **PipelineStage** | `BridgeForward` |
| **위치** | Ingress, XDP 이후 |
| **동작** | 브릿지 멤버 인터페이스의 L2 포워딩 처리 |
| **sysctl 의존** | `bridge_nf_call_iptables` (기본값: `false`) |
| **결과** | Continue / FORWARDED (L2 포워딩) |

- `ingress_if.master`가 존재하면 브릿지 멤버로 감지.
- `bridge_nf_call_iptables == false`: IP netfilter 스택을 건너뛰고 L2에서 바로 `FORWARDED`.
- `bridge_nf_call_iptables == true`: 정상적인 IP 스택 처리를 계속.

### 3.4 ArpProcess

| 항목 | 값 |
|---|---|
| **PipelineStage** | `ArpProcess` |
| **위치** | Ingress, XDP 이후 / Bridge check 이후 |
| **동작** | ARP 패킷의 arp_ignore sysctl에 따른 응답 제어 |
| **sysctl 의존** | `arp_ignore` (기본값: `0`) |
| **결과** | Continue / Drop |

- `ethertype == Arp`일 때만 수행.
- `arp_ignore >= 1`: ARP target IP가 수신 인터페이스에 설정되지 않으면 DROP.
- `arp_ignore >= 2`: 위 조건 + ARP sender IP가 수신 인터페이스 주소와 같은 서브넷이 아니면 DROP.

### 3.5 L2Bypass

| 항목 | 값 |
|---|---|
| **PipelineStage** | `L2Bypass` |
| **위치** | Ingress, ARP 처리 이후 |
| **동작** | L2 전용 프로토콜의 netfilter/routing 우회 |
| **sysctl 의존** | 없음 |
| **결과** | LocalDelivery |

- `ethertype.is_l2_only()` = `Arp | Stp | Lldp` 인 경우 즉시 `LOCAL_DELIVERY`.
- ARP는 위의 ArpProcess에서 먼저 arp_ignore 체크를 받고 통과해야 이 단계에 도달.

### 3.6 TcIngress

| 항목 | 값 |
|---|---|
| **PipelineStage** | `TcIngress` |
| **위치** | Ingress Stage 2 |
| **동작** | TC (Traffic Control) ingress 훅 |
| **sysctl 의존** | 없음 |
| **결과** | Continue (현재 pass-through 구현) |

### 3.7 PreRoutingRaw

| 항목 | 값 |
|---|---|
| **PipelineStage** | `PreRoutingRaw` |
| **위치** | Ingress Stage 3a |
| **동작** | PREROUTING 훅 중 priority <= -200인 체인 평가 (raw 테이블) |
| **sysctl 의존** | 없음 |
| **결과** | Continue / Drop / Reject / Stolen |

- conntrack 이전에 실행되므로 NOTRACK 설정이 가능 (TODO).
- Linux 기본 raw 테이블 priority는 -300.

### 3.8 ConntrackIn

| 항목 | 값 |
|---|---|
| **PipelineStage** | `ConntrackIn` |
| **위치** | Ingress Stage 3b / Output Stage 1b |
| **동작** | Connection Tracking 조회, 패킷을 ct_state로 분류 |
| **sysctl 의존** | 없음 |
| **결과** | Continue |

- 현재 구현에서는 사용자가 선언한 `conntrack_state`를 그대로 사용 (정적 시뮬레이션).

### 3.9 PreRouting (post-CT)

| 항목 | 값 |
|---|---|
| **PipelineStage** | `PreRouting` |
| **위치** | Ingress Stage 3c |
| **동작** | PREROUTING 훅 중 priority > -200인 체인 평가 |
| **sysctl 의존** | 없음 |
| **결과** | Continue / Drop / Reject / Stolen |

- 포함되는 테이블/우선순위: mangle(-150), nat/dstnat(-100), filter(0), security(50), srcnat(100).
- DNAT, REDIRECT, TPROXY 등 NAT 액션이 이 단계에서 적용.
- TPROXY 적용 시: `tproxy_applied = true`, Stolen을 반환하지 않고 routing으로 계속 진행 (mark 기반 policy routing으로 로컬 전달).

### 3.10 RpFilter

| 항목 | 값 |
|---|---|
| **PipelineStage** | `RpFilter` |
| **위치** | Ingress, PREROUTING 이후 / Routing Decision 이전 |
| **동작** | src IP에 대해 역방향 경로 조회로 spoofing 방지 |
| **sysctl 의존** | `rp_filter` (기본값: `Off` / 코드 기본값 0) |
| **결과** | (없음: 통과) / Drop |

- `Off(0)`: 검사 안 함.
- `Strict(1)`: 역경로의 egress가 ingress_if와 일치해야 통과.
- `Loose(2)`: 어떤 인터페이스로든 역경로가 존재하면 통과.
- PREROUTING mangle이 mark를 변경할 수 있어 policy routing에 영향. 따라서 PREROUTING 이후에 실행.

### 3.11 RoutingDecision

| 항목 | 값 |
|---|---|
| **PipelineStage** | `RoutingDecision` |
| **위치** | Ingress Stage 5 / Output Stage 2 |
| **동작** | IP rules + routing tables 조회로 패킷 경로 결정 |
| **sysctl 의존** | `route_localnet` (기본값: `false`) — routing 직전에 체크 |
| **결과** | LocalDelivery / ForwardTo / Drop / Reject / Stolen / Redirect |

- route_localnet 체크: dst가 127.0.0.0/8이고 `route_localnet=false`이면 DROP (DNAT to loopback 차단).
- 이 체크는 코드상 routing decision 함수 호출 직전에 수행.

### 3.12 LocalInput

| 항목 | 값 |
|---|---|
| **PipelineStage** | `LocalInput` |
| **위치** | Ingress Stage 6a (LOCAL 경로) |
| **동작** | INPUT 훅 체인 평가 |
| **sysctl 의존** | `icmp_echo_ignore_all` (기본값: `false`) — INPUT 직전에 체크 |
| **결과** | Continue → LOCAL_DELIVERY / Drop / Reject |

- `icmp_echo_ignore_all=true`이고 ICMP echo request(type 8/128)이면 INPUT 체인 평가 전에 DROP.

### 3.13 Forward

| 항목 | 값 |
|---|---|
| **PipelineStage** | `Forward` |
| **위치** | Ingress Stage 6b (FORWARD 경로) |
| **동작** | FORWARD 훅 체인 평가 |
| **sysctl 의존** | `ip_forward` (기본값: `true`), 인터페이스별 `forwarding` (기본값: `None` → 전역 사용) |
| **결과** | Continue / Drop / Reject |

- FORWARD 체인 평가 전에 `ip_forward` / 인터페이스별 `forwarding` 확인. 비활성이면 DROP.

### 3.14 PostRouting

| 항목 | 값 |
|---|---|
| **PipelineStage** | `PostRouting` |
| **위치** | Ingress FORWARD 경로 Stage 7 / Output Stage 3 |
| **동작** | POSTROUTING 훅 체인 평가 (SNAT, MASQUERADE) |
| **sysctl 의존** | 없음 |
| **결과** | Continue / Drop / Reject |

### 3.15 MtuCheck

| 항목 | 값 |
|---|---|
| **PipelineStage** | `MtuCheck` |
| **위치** | POSTROUTING 이후, ConntrackConfirm 이전 |
| **동작** | 패킷 크기와 egress 인터페이스 MTU 비교 |
| **sysctl 의존** | 없음 |
| **결과** | Continue / Drop |

- `packet_length > egress_iface.mtu`:
  - `df_flag == true`: DROP (ICMP Fragmentation Needed 전송).
  - `df_flag == false`: Continue (fragmentation 수행).
- `packet_length` 미지정: 정보만 기록, Continue.

### 3.16 ConntrackConfirm

| 항목 | 값 |
|---|---|
| **PipelineStage** | `ConntrackConfirm` |
| **위치** | 최종 단계 (FORWARDED/SENT 직전) |
| **동작** | conntrack 엔트리 확정 |
| **sysctl 의존** | 없음 |
| **결과** | Continue |

### 3.17 Output

| 항목 | 값 |
|---|---|
| **PipelineStage** | `Output` |
| **위치** | Output 파이프라인 Stage 1 |
| **동작** | OUTPUT 훅 체인 평가 (RAW + post-CT 분리) |
| **sysctl 의존** | 없음 |
| **결과** | Continue / Drop / Reject / Stolen |

- PREROUTING과 동일한 priority -200 경계로 RAW / post-CT 분할.

---

## 4. Netfilter 체인 평가

### 4.1 체인 수집 및 정렬

`collect_chains_for_hook(config, hook)`:

1. **nftables**: 각 테이블의 체인 중 `chain.hook == hook`인 것을 수집. priority는 `chain.priority` (기본 0).
2. **iptables**: 각 테이블의 체인 중 이름이 hook에 대응하는 것을 수집. priority는 `table.default_priority(hook)`.
3. **정렬**: priority 오름차순.

### 4.2 규칙 평가 (`evaluate_chain_inner`)

체인의 규칙을 순서대로 평가:

1. `evaluate_matches(rule.matches, state)`: 모든 match 조건이 AND로 결합. 하나라도 불일치하면 skip.
2. 매칭되면 `rule.action`에 따라 처리:

| NfAction | 동작 | 종료 여부 |
|---|---|---|
| `Verdict { Accept }` | Accept 반환 | 현재 체인 종료, 모든 체인 중단 (`stop=true`) |
| `Verdict { Drop }` | Drop 반환 | 모든 체인 중단 |
| `Verdict { Reject }` | Reject 반환 | 모든 체인 중단 |
| `Verdict { Continue }` | 다음 규칙으로 | 아니오 |
| `Verdict { Queue }` | Stolen 반환 | 모든 체인 중단 |
| `Nat { action }` | NAT 적용 후 Accept 반환 | 현재 체인 종료, 다음 체인 계속 (`stop=false`) |
| `SetMark { value, mask }` | `mark = (mark & !mask) \| (value & mask)` | 아니오 |
| `Log` / `Counter` | 비종료 액션 | 아니오 |
| `Jump { target }` | 타겟 체인 평가 후 복귀 | 타겟 결과에 따름 |
| `Goto { target }` | 타겟 체인으로 이동 (복귀 안 함) | 타겟 결과에 따름 |
| `Return` | 현재 체인 종료 (호출자로 복귀) | 현재 체인만 종료 |

3. 모든 규칙을 평가한 후 매칭 없으면 **체인 정책** 적용:
   - `Accept` 정책: decision=None (다음 체인 계속)
   - `Drop` 정책: 즉시 DROP

### 4.3 Jump / Goto / Return

- **Jump**: 타겟 커스텀 체인을 평가. terminal decision(Accept/Drop/Reject/Stolen)이 나오면 전파. `Continue`(Return에 의한)이면 현재 체인의 다음 규칙으로 복귀.
- **Goto**: 타겟 체인을 평가. terminal decision이 나오면 전파. no decision이면 현재 체인 종료 (base chain 정책으로).
- **Return**: 현재 체인 평가 종료. Jump에서 호출된 경우 호출 체인으로 복귀, base chain이면 정책 적용.
- **최대 깊이**: 16단계 (`MAX_CHAIN_DEPTH`). 초과 시 Jump/Goto 무시.
- 커스텀 체인 조회: `collect_all_chains_in_tables()`로 같은 테이블 내 모든 체인을 수집하여 이름으로 검색.

### 4.4 PREROUTING / OUTPUT 분할 로직

PREROUTING과 OUTPUT 훅은 priority -200을 경계로 분할:

```
priority <= -200  →  RAW 그룹 (conntrack 이전)
priority >  -200  →  POST_CT 그룹 (conntrack 이후)
```

Linux netfilter priority 체계:

| 테이블 | Hook | Priority |
|---|---|---|
| raw | PREROUTING/OUTPUT | -300 |
| mangle | PREROUTING/OUTPUT | -150 |
| nat (dstnat) | PREROUTING | -100 |
| filter | 모든 hook | 0 |
| security | 모든 hook | 50 |
| nat (srcnat) | POSTROUTING | 100 |

### 4.5 NAT 적용 (`apply_nat`)

| NatAction | 동작 | 포트 처리 |
|---|---|---|
| `Dnat { addr, port }` | dst_ip/dst_port 변경, original 저장 | TCP/UDP/SCTP만 port 적용. ICMP는 IP만 변경. |
| `Snat { addr, port }` | src_ip/src_port 변경, original 저장 | 동일 |
| `Masquerade { port }` | egress IF의 IP를 src_ip로 설정 | 동일 |
| `Redirect { port }` | ingress IF의 IP를 dst_ip로 설정 | 동일 |
| `Tproxy { addr, port, mark }` | dst 변경 + mark 설정, `tproxy_applied=true` | 동일 |

- 첫 NAT 적용 시 `original_*` 필드에 원본 값 저장 (이미 적용된 경우 덮어쓰지 않음).
- `has_ports()`: `Tcp | Udp | Sctp` 프로토콜만 true. ICMP는 포트가 없으므로 port 필드 무시.

### 4.6 NfMatch 타입

| 타입 | 필드 | 설명 |
|---|---|---|
| `Ip` | `field: IpField`, `op: MatchOp`, `value: String` | IP 계층 매칭 (saddr, daddr, protocol, version, dscp, ttl) |
| `Transport` | `protocol: TransportProto`, `field: TransportField`, `op`, `value` | L4 매칭. TCP/UDP: sport/dport/flags. ICMP: icmp_type/icmp_code. |
| `Iif` | `name: String` | 입력 인터페이스 이름 일치 |
| `Oif` | `name: String` | 출력 인터페이스 이름 일치 |
| `Meta` | `key: MetaKey`, `op`, `value` | 메타데이터 매칭 (mark, protocol, iifname, oifname, l4proto, nfproto) |
| `Ct` | `key: CtKey`, `op`, `value` | Conntrack 매칭 (state, mark, direction) |
| `Mark` | `op`, `value: u32`, `mask: Option<u32>` | 패킷 mark 매칭 (mask 적용) |

### 4.7 NfAction 타입

| 타입 | 필드 | 설명 |
|---|---|---|
| `Verdict` | `verdict: NfVerdict` | Accept / Drop / Reject / Queue / Continue |
| `Nat` | `action: NatAction` | DNAT / SNAT / Masquerade / Redirect / Tproxy |
| `SetMark` | `value: u32`, `mask: Option<u32>` | 패킷 mark 설정 |
| `Log` | `prefix: Option<String>`, `level: Option<u8>` | 로깅 (비종료) |
| `Counter` | - | 카운터 (비종료) |
| `Jump` | `target: String` | 커스텀 체인으로 점프 (Return 시 복귀) |
| `Goto` | `target: String` | 커스텀 체인으로 이동 (Return 시 base chain 정책) |
| `Return` | - | 현재 체인 종료 |

---

## 5. sysctl 커널 파라미터

### 5.1 전역 IPv4 파라미터 (`Ipv4Sysctl`)

| 파라미터 경로 | 코드 기본값 | 체크 시점 | 효과 |
|---|---|---|---|
| `net.ipv4.ip_forward` | **`true`** | FORWARD 경로 진입 시 | false이면 포워딩 불가, DROP |
| `net.ipv4.icmp_echo_ignore_all` | **`false`** | LOCAL 경로, INPUT 체인 직전 | true이면 ICMP echo request(type 8/128) DROP |
| `net.ipv4.icmp_echo_ignore_broadcasts` | **`true`** | (모델만 존재, 엔진 미사용) | true이면 브로드캐스트 ICMP echo 무시 |
| `net.ipv4.tcp_syncookies` | **`true`** | (모델만 존재, 엔진 미사용) | SYN cookies 활성화 |

> **주의**: `ip_forward`의 코드 기본값은 `true`이다. 이는 시뮬레이션이 일반적으로 라우터를 대상으로 하기 때문이며, 실제 Linux 기본값(`0`)과 다르다.

### 5.2 전역 IPv6 파라미터 (`Ipv6Sysctl`)

| 파라미터 경로 | 코드 기본값 | 체크 시점 | 효과 |
|---|---|---|---|
| `net.ipv6.conf.all.forwarding` | **`true`** | (모델만 존재) | IPv6 포워딩 |

### 5.3 인터페이스별 파라미터 (`InterfaceSysctl`)

조회 우선순위: 명시적 인터페이스 설정 → `"all"` → `"default"` → 코드 기본값.

| 파라미터 경로 | 코드 기본값 | 체크 시점 | 효과 |
|---|---|---|---|
| `net.ipv4.conf.{iface}.forwarding` | **`None`** (전역 사용) | FORWARD 경로 진입 시 | Some(v)이면 전역 ip_forward 대신 v 사용 |
| `net.ipv4.conf.{iface}.route_localnet` | **`false`** | Routing Decision 직전 | true여야 DNAT to 127.0.0.0/8 허용 |
| `net.ipv4.conf.{iface}.rp_filter` | **`Off`** (0) | PREROUTING 이후, Routing 이전 | Off/Strict/Loose 모드. Strict: 역경로=ingress 필요 |
| `net.ipv4.conf.{iface}.accept_local` | **`false`** | (모델만 존재) | 로컬 소스 주소 패킷 수신 허용 |
| `net.ipv4.conf.{iface}.send_redirects` | **`true`** | (모델만 존재) | ICMP redirect 전송 |
| `net.ipv4.conf.{iface}.log_martians` | **`false`** | (모델만 존재) | 비정상 소스 주소 패킷 로깅 |
| `net.ipv4.conf.{iface}.proxy_arp` | **`false`** | (모델만 존재) | Proxy ARP 활성화 |
| `net.ipv4.conf.{iface}.proxy_arp_pvlan` | **`false`** | (모델만 존재) | Private VLAN proxy ARP |
| `net.ipv4.conf.{iface}.arp_ignore` | **`0`** | ARP 처리 시 | 0: 모든 로컬 IP 응답, 1: 수신 IF의 IP만, 2: +같은 서브넷 |
| `net.ipv4.conf.{iface}.arp_announce` | **`0`** | (모델만 존재) | ARP 요청 시 소스 IP 선택 |
| `net.ipv4.conf.{iface}.arp_filter` | **`false`** | (모델만 존재) | ARP 필터링 |

### 5.4 브릿지 파라미터

| 파라미터 경로 | 코드 기본값 | 체크 시점 | 효과 |
|---|---|---|---|
| `net.bridge.bridge-nf-call-iptables` | **`false`** | Bridge member check 시 | false: L2 포워딩 (netfilter bypass), true: IP 스택 처리 |
| `net.bridge.bridge-nf-call-ip6tables` | **`false`** | (모델만 존재) | IPv6 브릿지 패킷에 ip6tables 적용 |
| `net.bridge.bridge-nf-call-arptables` | **`false`** | (모델만 존재) | ARP 브릿지 패킷에 arptables 적용 |

### 5.5 RpFilterMode 열거형

| 값 | 의미 | 코드 기본값 |
|---|---|---|
| `Off` | 비활성화 (0) | **`InterfaceSysctl` 기본값** |
| `Strict` | 역경로가 ingress IF와 일치해야 함 (1) | `#[default]` derive (serde 역직렬화 기본값) |
| `Loose` | 역경로가 어떤 IF로든 존재하면 통과 (2) | - |

> **주의**: `RpFilterMode`의 `#[default]` derive는 `Strict`이지만, `InterfaceSysctl::default()`에서 `rp_filter: RpFilterMode::Off`로 명시적 설정. 따라서 실제 기본 동작은 **Off**.

---

## 6. 인터페이스 모델

### 6.1 Interface 구조체

| 필드 | 타입 | 기본값 | 설명 |
|---|---|---|---|
| `name` | `String` | (필수) | 인터페이스 이름 (e.g., "eth0") |
| `index` | `u32` | (필수) | 인터페이스 인덱스 |
| `mac` | `Option<String>` | `None` | MAC 주소 |
| `addresses` | `Vec<InterfaceAddress>` | `[]` | IP 주소 목록 |
| `mtu` | `u32` | `1500` | Maximum Transmission Unit |
| `state` | `InterfaceState` | `Up` | 인터페이스 상태 |
| `kind` | `InterfaceKind` | `Physical` | 인터페이스 종류 |
| `veth_peer` | `Option<String>` | `None` | Veth peer 이름 (kind=Veth) |
| `bridge_members` | `Vec<String>` | `[]` | 브릿지 멤버 목록 (kind=Bridge) |
| `master` | `Option<String>` | `None` | 소속 브릿지 이름 |
| `vlan_parent` | `Option<String>` | `None` | VLAN 부모 인터페이스 (kind=Vlan) |
| `vlan_id` | `Option<u16>` | `None` | VLAN ID (kind=Vlan) |
| `bond_members` | `Vec<String>` | `[]` | Bond 멤버 목록 (kind=Bond) |

### 6.2 InterfaceKind 열거형

| 값 | 설명 |
|---|---|
| `Loopback` | 루프백 인터페이스 (lo) |
| `Physical` | 물리 NIC (**기본값**) |
| `Veth` | Virtual Ethernet pair |
| `Bridge` | 소프트웨어 브릿지 |
| `Vlan` | 802.1Q VLAN 인터페이스 |
| `Bond` | 본딩 인터페이스 |
| `Tun` | TUN 디바이스 |
| `Tap` | TAP 디바이스 |
| `Wireguard` | WireGuard 인터페이스 |
| `Other(String)` | 기타 |

### 6.3 인터페이스 관계

- **Bridge**: `bridge_members`에 멤버 목록. 멤버의 `master`가 브릿지 이름을 참조.
- **Veth**: `veth_peer`로 peer 이름을 참조. 양쪽 모두 설정.
- **VLAN**: `vlan_parent`로 부모 인터페이스, `vlan_id`로 VLAN 태그.

### 6.4 InterfaceAddress 구조체

| 필드 | 타입 | 설명 |
|---|---|---|
| `ip` | `IpAddr` | IP 주소 |
| `prefix_len` | `u8` | 서브넷 prefix 길이 |
| `scope` | `AddressScope` | 주소 범위 (Global/Link/Host, 기본: Global) |

---

## 7. 패킷 상태 추적

### 7.1 PacketState 필드

| 필드 | 타입 | 초기값 | 변경 시점 |
|---|---|---|---|
| `ethertype` | `EtherType` | PacketDef에서 복사 | 변경 안 됨 |
| `vlan_id` | `Option<u16>` | PacketDef에서 복사 | 변경 안 됨 |
| `src_mac` | `Option<String>` | PacketDef에서 복사 | 변경 안 됨 |
| `dst_mac` | `Option<String>` | PacketDef에서 복사 | 변경 안 됨 |
| `src_ip` | `Option<IpAddr>` | PacketDef에서 복사 | SNAT, Masquerade |
| `dst_ip` | `Option<IpAddr>` | PacketDef에서 복사 | DNAT, Redirect, Tproxy |
| `src_port` | `Option<u16>` | PacketDef에서 복사 | SNAT (TCP/UDP/SCTP만) |
| `dst_port` | `Option<u16>` | PacketDef에서 복사 | DNAT, Redirect, Tproxy (TCP/UDP/SCTP만) |
| `protocol` | `IpProtocol` | PacketDef에서 복사 | 변경 안 됨 |
| `mark` | `u32` | `initial_mark` | SetMark 액션, Tproxy |
| `ct_mark` | `u32` | `initial_ct_mark` | (현재 변경 로직 없음) |
| `ct_state` | `ConntrackState` | `conntrack_state` | (user-declared 유지) |
| `ingress_if` | `String` | `ingress_interface` | 변경 안 됨 |
| `egress_if` | `Option<String>` | `None` | Routing Decision 시 설정 |
| `ttl` | `u8` | `ttl` 또는 `64` | (엔진에서 직접 감소 로직 없음) |
| `dscp` | `u8` | `dscp` 또는 `0` | (엔진에서 직접 변경 로직 없음) |
| `icmp_type` | `Option<u8>` | PacketDef에서 복사 | 변경 안 됨 |
| `icmp_code` | `Option<u8>` | PacketDef에서 복사 | 변경 안 됨 |
| `tcp_flags` | `Option<TcpFlags>` | PacketDef에서 복사 | 변경 안 됨 |
| `arp_op` | `Option<u16>` | `arp.operation` | 변경 안 됨 |
| `packet_length` | `Option<u32>` | PacketDef에서 복사 | 변경 안 됨 |
| `df_flag` | `bool` | PacketDef에서 복사 | 변경 안 됨 |
| `dnat_applied` | `bool` | `false` | DNAT/Redirect/Tproxy 적용 시 `true` |
| `snat_applied` | `bool` | `false` | SNAT/Masquerade 적용 시 `true` |
| `tproxy_applied` | `bool` | `false` | Tproxy 적용 시 `true` |
| `original_dst_ip` | `Option<IpAddr>` | `None` | 첫 DNAT 시 원본 dst_ip 저장 |
| `original_dst_port` | `Option<u16>` | `None` | 첫 DNAT 시 원본 dst_port 저장 |
| `original_src_ip` | `Option<IpAddr>` | `None` | 첫 SNAT 시 원본 src_ip 저장 |
| `original_src_port` | `Option<u16>` | `None` | 첫 SNAT 시 원본 src_port 저장 |

### 7.2 TraceStep 구조체

| 필드 | 타입 | 설명 |
|---|---|---|
| `seq` | `u32` | 단계 순번 (1부터) |
| `stage` | `PipelineStage` | 파이프라인 단계 식별자 |
| `description` | `String` | 단계 설명 |
| `state_before` | `PacketState` | 이 단계 진입 시 상태 |
| `state_after` | `PacketState` | 이 단계 완료 후 상태 |
| `state_changes` | `Vec<StateChange>` | before/after 간 차이 목록 |
| `matched_rules` | `Vec<MatchedRuleRef>` | 이 단계에서 매칭된 규칙 |
| `decision` | `StageDecision` | 이 단계의 결정 |
| `explain` | `String` | 사람이 읽을 수 있는 설명 |

### 7.3 compute_state_changes 추적 필드

`compute_state_changes(before, after)`가 비교하는 필드 목록:

- L2: `vlan_id`, `src_mac`, `dst_mac`
- L3: `src_ip`, `dst_ip`, `src_port`, `dst_port`
- Meta: `mark`, `ct_mark`, `ct_state`, `egress_if`, `ttl`, `dscp`
- NAT: `dnat_applied`, `snat_applied`, `tproxy_applied`
- Protocol: `protocol`, `icmp_type`, `icmp_code`

---

## 8. 최종 판정 (FinalVerdict)

| 값 | 표시 | 설명 |
|---|---|---|
| `Drop` | `DROP` | 패킷이 드롭됨 (netfilter, sysctl, 인터페이스 검증 실패 등) |
| `LocalDelivery` | `LOCAL_DELIVERY` | 패킷이 로컬 프로세스로 전달됨 (INPUT 체인 통과) |
| `Forwarded` | `FORWARDED` | 패킷이 다른 인터페이스로 포워딩됨 (FORWARD + POSTROUTING 통과) |
| `Redirect` | `REDIRECT` | XDP_REDIRECT에 의해 다른 인터페이스로 리다이렉트 |
| `Tx` | `TX` | XDP_TX에 의해 수신 인터페이스로 재전송 |
| `Rejected` | `REJECTED` | REJECT 액션에 의해 거부됨 (ICMP unreachable 응답 전송) |
| `Blackhole` | `BLACKHOLE` | 블랙홀 라우트에 의해 무음 폐기 |
| `Tproxy` | `TPROXY` | TPROXY에 의해 투명 프록시로 전달 (routing의 Stolen) |
| `Sent` | `SENT` | 로컬 발신 패킷이 성공적으로 전송됨 (Output 파이프라인) |

### 8.1 terminal_verdict 매핑

엔진 내부에서 `StageDecision` → `FinalVerdict` 변환:

| StageDecision | FinalVerdict |
|---|---|
| `Drop` | `Drop` |
| `Reject` | `Rejected` |
| `Stolen` | `Tproxy` |
| `Redirect` | `Redirect` |
| 기타 | (종료하지 않음, 다음 단계 계속) |

---

## 9. 세션 시뮬레이션

### 9.1 개요

`session_engine::run_session()`은 세션 단위 시뮬레이션을 수행한다. 세션을 개별 패킷으로 확장하고, 각 패킷을 `engine::run()`으로 순서대로 시뮬레이션한다.

### 9.2 세션 타입 (`SessionType`)

| 타입 | 설명 | 생성 패킷 |
|---|---|---|
| `TcpHandshake` | TCP 3-way handshake | SYN → SYN-ACK → ACK (+ 선택적 data/close) |
| `IcmpEcho` | ICMP ping | Echo Request → Echo Reply |
| `UdpExchange` | UDP 요청/응답 | Request → Response |
| `Custom` | 사용자 정의 패킷 시퀀스 | 직접 지정 |

### 9.3 NAT 매핑 전파

1. 첫 번째(forward) 패킷 시뮬레이션 실행.
2. 결과의 마지막 `TraceStep.state_after`에서 NAT 정보 추출 (`extract_nat_mapping`).
3. `dnat_applied` 또는 `snat_applied`가 true인 경우 `NatMapping` 생성.
4. 이후 reply 패킷에 `NatMapping::apply_to_reply()` 적용:
   - DNAT 역변환: reply의 `src_ip`가 original dst → translated dst로 변경.
   - SNAT 역변환: reply의 `dst_ip`가 original src → translated src로 변경.
   - 포트도 동일하게 역변환.

### 9.4 SessionVerdict

| 값 | 조건 |
|---|---|
| `Established` | 모든 패킷이 성공적으로 전달됨 |
| `Failed { failed_at, reason }` | 특정 패킷에서 terminal verdict (Drop/Rejected/Blackhole) 발생. 세션 즉시 중단. |
| `Partial { passed, total }` | 일부 패킷만 통과 (terminal이 아닌 실패가 포함된 경우) |

### 9.5 Terminal Verdict 판정

세션에서 terminal로 간주하는 verdict: `Drop`, `Rejected`, `Blackhole`. 이 중 하나가 발생하면 이후 패킷은 시뮬레이션하지 않고 세션을 `Failed`로 종료.
