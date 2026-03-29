# netsim 네트워크 스택 시뮬레이션 명세

## 1. 개요

netsim은 Linux 커널의 ingress 패킷 처리 경로를 정적으로 시뮬레이션한다. 이 문서는 시뮬레이션 엔진이 구현하는 패킷 처리 파이프라인의 정확한 동작을 기술한다.

---

## 2. 전체 파이프라인 다이어그램

```
                              ┌──────────────────────────────────────┐
                              │           NIC (수신)                  │
                              └──────────────┬───────────────────────┘
                                             │
                                             ▼
                              ┌──────────────────────────────────────┐
                              │     INTERFACE_CHECK                   │
                              │  • 인터페이스 존재 확인                │
                              │  • 인터페이스 상태 확인 (UP/DOWN)      │
                              │  • 브릿지 멤버 감지                    │
                              └──────────────┬───────────────────────┘
                                             │ DOWN이면 DROP
                                             ▼
                              ┌──────────────────────────────────────┐
                              │          XDP                          │
                              │  (eXpress Data Path)                 │
                              │  • 인터페이스별 XDP 프로그램 평가       │
                              │  • 드라이버 레벨, L2/L3 처리 이전      │
                              ├──────────────────────────────────────┤
                              │  결과: PASS / DROP / TX / REDIRECT    │
                              └────┬─────┬─────┬─────┬──────────────┘
                              DROP │PASS │ TX  │REDIR│
                                ▼  │     ▼     ▼     │
                              종료  │   종료   종료    │
                                   ▼                  │
                              ┌──────────────────────────────────────┐
                              │     ARP_PROCESS (ARP 패킷만)          │
                              │  • sysctl arp_ignore 검사             │
                              │    level 1: target IP가 수신 iface에   │
                              │             설정되어 있는지 확인        │
                              │    level 2: + sender IP가 같은        │
                              │             서브넷인지 확인             │
                              └──────────────┬───────────────────────┘
                                             │ 불합격 시 DROP
                                             ▼
                          ┌──── EtherType 확인 ────┐
                          │                        │
                    L2-only (ARP,                 IP (IPv4/IPv6)
                     STP, LLDP)                    │
                          │                        │
                          ▼                        ▼
                ┌─────────────────┐    ┌──────────────────────────────┐
                │   L2_BYPASS     │    │     RP_FILTER                 │
                │ netfilter/      │    │  Reverse Path 필터링 (sysctl)  │
                │ routing 건너뜀  │    │  • strict: 역라우팅 iface =    │
                │ → LOCAL_DELIVERY│    │           ingress iface 확인    │
                └─────────────────┘    │  • loose: 역라우팅 가능 여부    │
                                       └──────────────┬───────────────┘
                                                      │ 불합격 시 DROP
                                                      ▼
                                       ┌──────────────────────────────┐
                                       │     TC_INGRESS               │
                                       │  (traffic control ingress)   │
                                       │  MVP: pass-through           │
                                       └──────────────┬───────────────┘
                                                      │
                                                      ▼
                                       ┌──────────────────────────────┐
                                       │     CONNTRACK_IN             │
                                       │  conntrack 상태 조회          │
                                       │  • NEW / ESTABLISHED /       │
                                       │    RELATED / INVALID         │
                                       │  (사용자 선언 기반)            │
                                       └──────────────┬───────────────┘
                                                      │
                                                      ▼
                              ┌────────────────────────────────────────────────┐
                              │                PREROUTING                       │
                              │  netfilter hook: prerouting                     │
                              │  nftables + iptables 체인을 priority 순으로 평가 │
                              │                                                │
                              │  iptables 기본 priority:                        │
                              │    raw (-300) → mangle (-150) → nat (-100)     │
                              │                                                │
                              │  주요 처리:                                     │
                              │  • raw: conntrack 바이패스 (NOTRACK)            │
                              │  • mangle: mark 변경, DSCP 수정                │
                              │  • nat: DNAT, REDIRECT, TPROXY                 │
                              │                                                │
                              │  NAT 처리:                                     │
                              │  • DNAT: dst_ip/dst_port 변경                  │
                              │  • REDIRECT: dst_ip를 수신 iface의 IP로 변경   │
                              │  • TPROXY: 패킷 stolen, mark 설정              │
                              │  • ICMP: IP만 변경, 포트 변경 없음              │
                              └────────────────────────┬───────────────────────┘
                                                       │ DROP/REJECT → 종료
                                                       ▼
                              ┌────────────────────────────────────────────────┐
                              │           route_localnet 검사 (sysctl)          │
                              │  DNAT 후 dst가 127.0.0.0/8이면:                │
                              │  • route_localnet=0 → DROP                     │
                              │  • route_localnet=1 → 통과                     │
                              └────────────────────────┬───────────────────────┘
                                                       │
                                                       ▼
                              ┌────────────────────────────────────────────────┐
                              │              ROUTING DECISION                   │
                              │                                                │
                              │  1. dst_ip가 로컬 인터페이스 주소인지 확인       │
                              │     → 매칭 시 LOCAL                             │
                              │                                                │
                              │  2. ip rule 순회 (priority 오름차순)             │
                              │     selector 매칭: from, to, fwmark,           │
                              │       iif, oif, ipproto, sport, dport          │
                              │     fwmark: (packet_mark & mask) == fwmark     │
                              │                                                │
                              │  3. 매칭된 rule의 action에 따라:               │
                              │     • Lookup(table_id) → 라우팅 테이블 조회     │
                              │     • Blackhole/Unreachable/Prohibit → DROP     │
                              │                                                │
                              │  4. 라우팅 테이블에서 Longest Prefix Match       │
                              │     tie-break: prefix_len > metric              │
                              │                                                │
                              │  5. Route Type에 따른 결정:                     │
                              │     • Local/Broadcast → LOCAL_DELIVERY          │
                              │     • Unicast → FORWARD (egress_if 설정)       │
                              │     • Blackhole/Unreachable/Prohibit → DROP     │
                              │     • Throw → 다음 ip rule로 계속              │
                              └──────────┬──────────────────┬──────────────────┘
                                         │                  │
                                   LOCAL  │                  │ FORWARD
                                         ▼                  ▼
            ┌──────────────────────────────┐  ┌─────────────────────────────────────┐
            │   icmp_echo_ignore_all       │  │  EGRESS INTERFACE_CHECK              │
            │   (sysctl, ICMP echo만)      │  │  • 인터페이스 존재 확인              │
            │   → DROP                     │  │  • 인터페이스 상태 확인 (UP/DOWN)    │
            └──────────────┬───────────────┘  └──────────────┬──────────────────────┘
                           │                                 │ DOWN/미존재 → DROP
                           ▼                                 ▼
            ┌──────────────────────────────┐  ┌─────────────────────────────────────┐
            │         INPUT                │  │  ip_forward 검사 (sysctl)            │
            │  netfilter hook: input       │  │  • ip_forward=0 → DROP              │
            │  체인 priority 순 평가       │  │  • 인터페이스별 forwarding 오버라이드  │
            │  • mangle → filter           │  └──────────────┬──────────────────────┘
            └──────────────┬───────────────┘                 │
                           │ DROP/REJECT                     ▼
                           │ → 종료            ┌─────────────────────────────────────┐
                           ▼                   │         FORWARD                      │
                    LOCAL_DELIVERY              │  netfilter hook: forward             │
                                               │                                     │
                                               │  1. TTL 감소 (decrement then check) │
                                               │     TTL=0 → DROP                    │
                                               │     (ICMP Time Exceeded 전송)       │
                                               │                                     │
                                               │  2. 체인 priority 순 평가           │
                                               │     • mangle → filter               │
                                               └──────────────┬──────────────────────┘
                                                              │ DROP/REJECT → 종료
                                                              ▼
                                               ┌─────────────────────────────────────┐
                                               │         POSTROUTING                  │
                                               │  netfilter hook: postrouting         │
                                               │  체인 priority 순 평가              │
                                               │                                     │
                                               │  iptables 기본 priority:             │
                                               │    mangle (-150) → nat (100)        │
                                               │                                     │
                                               │  주요 처리:                          │
                                               │  • SNAT: src_ip/src_port 변경       │
                                               │  • MASQUERADE: egress iface의       │
                                               │    IP로 SNAT (주소 패밀리 매칭)      │
                                               │  • ICMP: IP만 변경, 포트 없음       │
                                               └──────────────┬──────────────────────┘
                                                              │ DROP/REJECT → 종료
                                                              ▼
                                               ┌─────────────────────────────────────┐
                                               │         MTU_CHECK                    │
                                               │  egress 인터페이스의 MTU 검사        │
                                               │                                     │
                                               │  packet_length > MTU 인 경우:        │
                                               │  • DF flag=1 → DROP                 │
                                               │    (ICMP Frag Needed Type3 Code4)   │
                                               │  • DF flag=0 → fragmentation 주석   │
                                               │                                     │
                                               │  packet_length 미지정 → 건너뜀      │
                                               └──────────────┬──────────────────────┘
                                                              │
                                                              ▼
                                               ┌─────────────────────────────────────┐
                                               │      CONNTRACK_CONFIRM               │
                                               │  conntrack 항목 확정                  │
                                               └──────────────┬──────────────────────┘
                                                              │
                                                              ▼
                                                        FORWARDED
                                                   (egress 인터페이스로 전송)
```

---

## 3. 단계별 상세

### 3.1 INTERFACE_CHECK

NIC에서 패킷이 수신되면 가장 먼저 인터페이스 상태를 확인한다.

| 검사 | 조건 | 결과 |
|------|------|------|
| 존재 확인 | `ingress_interface`가 시나리오에 없음 | DROP |
| 상태 확인 | 인터페이스 state=Down | DROP |
| 브릿지 멤버 | `master` 필드가 설정됨 | CONTINUE (정보 기록) |

**구현 파일**: `engine.rs` Stage 0

---

### 3.2 XDP (eXpress Data Path)

드라이버 레벨에서 실행되는 eBPF 프로그램. L2/L3 처리 이전에 동작한다.

**처리 순서:**
1. ingress 인터페이스에 연결된 XDP 프로그램 찾기
2. 프로그램의 규칙을 순서대로 평가 (match-action)
3. 매칭되는 규칙이 없으면 `default_action` 적용

| XDP Action | 동작 | FinalVerdict |
|------------|------|-------------|
| `XDP_PASS` | 다음 단계로 진행 | — |
| `XDP_DROP` | 패킷 즉시 폐기 | Drop |
| `XDP_TX` | 같은 인터페이스로 반사 전송 | Tx |
| `XDP_REDIRECT` | 다른 인터페이스로 전환 | Redirect |
| `XDP_ABORTED` | 오류, 패킷 폐기 | Drop |

**특징:**
- ARP/STP 등 L2 패킷도 XDP를 통과
- XDP에서 DROP되면 netfilter/routing 도달하지 않음
- 간소화된 match-action 모델 (eBPF 바이트코드 해석 아님)

**구현 파일**: `pipeline/xdp.rs`

---

### 3.3 ARP 처리

ARP 패킷(EtherType=ARP)에만 적용. XDP 이후, L2 바이패스 이전.

**sysctl `arp_ignore` 동작:**

| 레벨 | 조건 | 동작 |
|------|------|------|
| 0 | — | 모든 ARP에 응답 (기본) |
| 1 | target IP가 수신 인터페이스에 설정되지 않음 | ARP 응답 억제 (DROP) |
| 2 | + sender IP가 수신 인터페이스와 같은 서브넷이 아님 | ARP 응답 억제 (DROP) |

**관련 sysctl:**
- `arp_ignore`: ARP 응답 제어 (0~2)
- `arp_announce`: ARP 요청 소스 IP 선택 (0~2)
- `arp_filter`: ARP 필터링
- `proxy_arp`: 다른 서브넷의 ARP에 대리 응답

**구현 파일**: `engine.rs` ARP processing 블록

---

### 3.4 L2 바이패스

L2-only 프로토콜(ARP, STP, LLDP)은 IP 스택을 타지 않으므로 netfilter와 routing을 건너뛴다.

```
EtherType이 L2-only → L2_BYPASS → LOCAL_DELIVERY
```

**L2-only 판별:**
- `EtherType::Arp`
- `EtherType::Stp`
- `EtherType::Lldp`

**구현 파일**: `engine.rs`, `model/packet.rs` (`EtherType::is_l2_only()`)

---

### 3.5 RP_FILTER (Reverse Path Filter)

소스 IP에 대한 역방향 라우팅 검증. 스푸핑 방지 목적.

**sysctl `rp_filter` 동작:**

| 모드 | 값 | 동작 |
|------|---|------|
| Off | 0 | 검사 안 함 |
| Strict | 1 | 역라우팅 결과의 egress == ingress 확인 |
| Loose | 2 | 역라우팅이 가능하기만 하면 통과 |

**역라우팅 (reverse_path_lookup):**
1. src_ip를 dst로 하여 ip rule + routing table 조회
2. 매칭되는 route의 dev (출력 인터페이스) 반환
3. Strict: 반환된 dev == 패킷의 ingress_if 여야 통과

**구현 파일**: `engine.rs` (`check_rp_filter`), `pipeline/routing.rs` (`reverse_path_lookup`)

---

### 3.6 TC_INGRESS (Traffic Control)

트래픽 제어 ingress qdisc. **MVP에서는 pass-through.**

향후 확장: tc filter, clsact, eBPF classifier

**구현 파일**: `pipeline/tc_ingress.rs`

---

### 3.7 CONNTRACK_IN (Conntrack Lookup)

연결 추적 테이블 조회. 패킷의 conntrack 상태를 결정한다.

**정적 시뮬레이션 제한:**
- 실제 conntrack 테이블을 유지하지 않음
- 사용자가 `PacketDef.conntrack_state`로 직접 선언
- 세션 엔진 사용 시: forward=NEW, reply=ESTABLISHED 자동 설정

| conntrack 상태 | 의미 |
|---------------|------|
| `NEW` | 새로운 연결 시도 |
| `ESTABLISHED` | 양방향 트래픽 확인된 연결 |
| `RELATED` | 기존 연결과 관련된 새 연결 (예: FTP data) |
| `INVALID` | 어떤 연결에도 속하지 않는 비정상 패킷 |
| `UNTRACKED` | conntrack 추적하지 않음 (raw table NOTRACK) |

**구현 파일**: `engine.rs` Stage 3, `model/conntrack.rs`

---

### 3.8 PREROUTING (Netfilter)

netfilter `prerouting` hook의 모든 체인을 priority 순으로 평가.

**체인 수집 및 정렬:**
```
nftables의 hook=prerouting 체인들
  + iptables 테이블의 PREROUTING 체인들
→ priority 오름차순 정렬
```

**iptables 기본 priority:**

| 테이블 | priority | 역할 |
|--------|---------|------|
| raw | -300 | conntrack bypass (NOTRACK) |
| mangle | -150 | mark 변경, DSCP 수정 |
| nat | -100 | DNAT, REDIRECT, TPROXY |

**규칙 평가:**
1. 체인 내 규칙을 순서대로 평가
2. 모든 match 조건이 AND로 결합, 모두 충족 시 action 실행
3. 빈 matches → catch-all (모든 패킷 매칭)

**NAT 액션 (PREROUTING):**

| NAT 타입 | 변경 대상 | 프로토콜별 동작 |
|---------|----------|--------------|
| DNAT | dst_ip, dst_port | TCP/UDP/SCTP: IP+포트 변경. ICMP: IP만 변경 |
| REDIRECT | dst_ip → ingress iface IP, dst_port | 같은 머신의 다른 포트로 전환 |
| TPROXY | mark 설정, 패킷 Stolen | 투명 프록시로 전달 |

**mark 변경:**
```rust
// mask 있는 경우: 특정 비트만 설정
new_mark = (old_mark & !mask) | (value & mask)
// mask 없는 경우: 전체 덮어쓰기
new_mark = value
```

mangle PREROUTING에서 설정된 mark는 이후 라우팅 결정에 영향 (fwmark 기반 정책 라우팅).

**구현 파일**: `pipeline/prerouting.rs`, `pipeline/mod.rs` (`evaluate_chain`, `apply_nat`)

---

### 3.9 route_localnet 검사

PREROUTING DNAT 이후, 라우팅 결정 이전에 dst_ip가 127.0.0.0/8인지 확인.

```
dst_ip ∈ 127.0.0.0/8 AND route_localnet=0 → DROP
dst_ip ∈ 127.0.0.0/8 AND route_localnet=1 → 통과 (DNAT to localhost 허용)
```

**사용 사례:** DNAT로 `127.0.0.1:8080`과 같은 로컬 서비스로 리다이렉트.

**구현 파일**: `engine.rs` route_localnet 블록

---

### 3.10 ROUTING DECISION

패킷의 목적지를 결정하는 핵심 단계.

**처리 순서:**

```
1. dst_ip가 로컬 인터페이스 주소인지 확인
   └── 매칭 → LOCAL_DELIVERY

2. ip rule 순회 (priority 오름차순)
   ├── selector 매칭 (from, to, fwmark, iif, oif, ipproto, sport, dport)
   │   fwmark 매칭: (packet_mark & fwmask) == fwmark
   └── action 실행
       ├── Lookup(table_id) → 3.
       ├── Blackhole → DROP
       ├── Unreachable → DROP
       └── Prohibit → DROP

3. 라우팅 테이블에서 Longest Prefix Match
   ├── 같은 prefix_len → metric 낮은 것 우선
   └── Route Type에 따른 결정:
       ├── Local → LOCAL_DELIVERY
       ├── Broadcast → LOCAL_DELIVERY
       ├── Unicast → FORWARD (egress_if, next_hop 설정)
       ├── Blackhole → DROP
       ├── Unreachable → DROP
       ├── Prohibit → DROP
       └── Throw → 다음 ip rule로 계속

4. 매칭 없음 → "No route to host" DROP
```

**구현 파일**: `pipeline/routing.rs`

---

### 3.11 LOCAL 경로: INPUT

라우팅 결정이 LOCAL인 경우.

**icmp_echo_ignore_all 검사:**
- `sysctl.ipv4.icmp_echo_ignore_all=1`이고 패킷이 ICMP Echo Request (type=8 또는 ICMPv6 type=128)이면 DROP

**INPUT 체인 평가:**
- netfilter `input` hook의 모든 체인을 priority 순으로 평가
- mangle → filter

**최종 결과:** `LOCAL_DELIVERY` 또는 DROP/REJECT

**구현 파일**: `pipeline/local_input.rs`, `engine.rs` LOCAL 분기

---

### 3.12 FORWARD 경로: FORWARD + POSTROUTING

라우팅 결정이 FORWARD인 경우.

**Egress 인터페이스 검증:**
- 존재 확인 (없으면 DROP)
- 상태 확인 (DOWN이면 DROP)

**ip_forward 검사:**
- `sysctl.ipv4.ip_forward=0`이면 DROP
- 인터페이스별 `forwarding` 오버라이드 가능

**FORWARD 체인:**
1. **TTL 감소** (IP 패킷만)
   - `ttl = ttl.saturating_sub(1)`
   - `ttl == 0` → DROP (ICMP Time Exceeded 전송)
2. netfilter `forward` hook 체인 평가
   - mangle → filter

**POSTROUTING 체인:**
- netfilter `postrouting` hook 체인 평가
- mangle → nat (SNAT/MASQUERADE)

| NAT 타입 | 변경 대상 | 동작 |
|---------|----------|------|
| SNAT | src_ip, src_port | 지정된 주소로 변경 |
| MASQUERADE | src_ip → egress iface IP | IPv4/IPv6 주소 패밀리 매칭 |

**MTU 검사:**
- `packet_length > egress_iface.mtu` 인 경우:
  - `df_flag=true` → DROP (ICMP Fragmentation Needed)
  - `df_flag=false` → fragmentation 주석

**Conntrack Confirm:**
- 포워딩된 패킷의 conntrack 항목 확정

**최종 결과:** `FORWARDED` 또는 DROP/REJECT

**구현 파일**: `pipeline/forward.rs`, `pipeline/postrouting.rs`, `engine.rs` FORWARD 분기

---

## 4. Netfilter 체인 평가 상세

### 4.1 체인 수집

```
NetfilterConfig
├── nftables: NftablesRuleset
│   └── tables[]: NfTable
│       └── chains[]: NfChain (hook, priority)
└── iptables: IptablesRuleset
    └── tables[]: IptablesTable
        └── chains[]: IptablesChain (name → hook 매핑)
```

동일 hook의 체인들을 병합 후 priority 오름차순 정렬.

### 4.2 규칙 평가

```
for rule in chain.rules:
    if ALL(rule.matches) match packet_state:
        execute rule.action
        → Verdict(Accept/Drop/Reject/Continue)
        → NAT(Dnat/Snat/Masquerade/Redirect/Tproxy)
        → SetMark(value, mask)
        → Log / Counter (비종료)
        → Jump / Goto (서브체인)
        → Return (체인 정책으로 복귀)

no rule matched → apply chain.policy (Accept/Drop)
```

### 4.3 매칭 조건 (NfMatch)

| 매칭 타입 | 필드 | 프로토콜 제약 |
|----------|------|-------------|
| `Ip` | saddr, daddr, protocol, version, dscp, ttl | IP 패킷만 |
| `Transport` | sport, dport, flags, icmp_type, icmp_code | 프로토콜별 |
| `Iif` | ingress 인터페이스 이름 | — |
| `Oif` | egress 인터페이스 이름 | — |
| `Meta` | mark, protocol, iifname, oifname, l4proto, nfproto | — |
| `Ct` | state, mark, direction | — |
| `Mark` | 패킷 mark (mask 지원) | — |

**프로토콜별 L4 매칭:**

| 프로토콜 | 포트 매칭 | 특수 필드 |
|---------|----------|----------|
| TCP | sport, dport | flags (syn, ack, fin, rst, psh, urg) |
| UDP | sport, dport | — |
| SCTP | sport, dport | — |
| ICMP | — (포트 없음) | icmp_type, icmp_code (이름 또는 숫자) |
| ICMPv6 | — (포트 없음) | icmp_type, icmp_code (이름 또는 숫자) |
| VRRP/OSPF/GRE/ESP/AH | — | — (IP 레벨만) |

**포트 값 형식:**
- 단일: `"80"`
- 범위: `"1024-65535"`
- 셋: `"22,80,443"`

**IP 주소 값 형식:**
- 단일: `"10.0.0.1"`
- CIDR: `"10.0.0.0/24"`
- 셋: `"10.0.0.1, 192.168.0.0/16"`

---

## 5. sysctl 커널 파라미터

### 5.1 전역 설정

| 파라미터 | 기본값 | 체크 포인트 | 효과 |
|---------|--------|-----------|------|
| `ipv4.ip_forward` | true | FORWARD 전 | false→포워딩 차단 |
| `ipv4.icmp_echo_ignore_all` | false | INPUT 전 | true→ICMP echo DROP |
| `ipv4.icmp_echo_ignore_broadcasts` | true | — | 브로드캐스트 echo 무시 |
| `ipv6.forwarding` | true | — | IPv6 포워딩 |

### 5.2 인터페이스별 설정

조회 순서: `interface_conf[iface]` → `interface_conf["all"]` → `interface_conf["default"]` → 빌트인 기본값

| 파라미터 | 기본값 | 체크 포인트 | 효과 |
|---------|--------|-----------|------|
| `forwarding` | None (전역 따름) | FORWARD 전 | 인터페이스별 포워딩 오버라이드 |
| `route_localnet` | false | PREROUTING 후 | true→127.0.0.0/8 DNAT 허용 |
| `rp_filter` | off | XDP 후 | strict/loose 역경로 검증 |
| `accept_local` | false | — | 로컬 소스 주소 허용 |
| `arp_ignore` | 0 | ARP 처리 | 0~2 레벨 ARP 응답 제어 |
| `arp_announce` | 0 | — | ARP 요청 소스 IP 선택 |
| `arp_filter` | false | — | ARP 필터링 |
| `proxy_arp` | false | — | Proxy ARP |
| `send_redirects` | true | — | ICMP redirect 전송 |
| `log_martians` | false | — | 비정상 패킷 로깅 |

### 5.3 브릿지 설정

| 파라미터 | 기본값 | 효과 |
|---------|--------|------|
| `bridge_nf_call_iptables` | false | 브릿지 패킷에 iptables 적용 |
| `bridge_nf_call_ip6tables` | false | 브릿지 IPv6에 ip6tables 적용 |
| `bridge_nf_call_arptables` | false | 브릿지 ARP에 arptables 적용 |

---

## 6. 인터페이스 모델

### 6.1 인터페이스 타입

| Kind | 설명 | 특수 필드 |
|------|------|----------|
| Physical | 물리 NIC | — |
| Loopback | 루프백 (lo) | — |
| Veth | 가상 이더넷 페어 | `veth_peer` |
| Bridge | 가상 브릿지 | `bridge_members` |
| Vlan | VLAN 서브인터페이스 | `vlan_parent`, `vlan_id` |
| Bond | 본딩 인터페이스 | `bond_members` |
| Tun / Tap | 가상 터널 | — |
| Wireguard | WireGuard VPN | — |

### 6.2 브릿지 멤버 관계

```
br0 (Bridge)
├── bridge_members: ["eth0", "eth1"]
│
eth0 (Physical)
├── master: "br0"    ← 브릿지 포트
│
eth1 (Physical)
├── master: "br0"    ← 브릿지 포트
```

브릿지 멤버로 수신된 패킷은 `INTERFACE_CHECK`에서 브릿지 관계를 trace에 기록.

### 6.3 인터페이스 속성

| 속성 | 용도 |
|------|------|
| `name` | 인터페이스 식별자 (iif/oif 매칭) |
| `index` | 인터페이스 인덱스 |
| `mac` | MAC 주소 |
| `addresses` | IP 주소 목록 (IPv4/IPv6, prefix_len, scope) |
| `mtu` | Maximum Transmission Unit (MTU 검사) |
| `state` | Up/Down (수신/전송 가능 여부) |

---

## 7. 패킷 상태 추적

### 7.1 PacketState 필드

시뮬레이션 중 변경되는 가변 상태:

| 필드 | 변경 시점 | 설명 |
|------|----------|------|
| `src_ip` / `dst_ip` | NAT (DNAT/SNAT) | IP 주소 |
| `src_port` / `dst_port` | NAT | L4 포트 (TCP/UDP/SCTP만) |
| `mark` | mangle SetMark | 패킷 mark (정책 라우팅에 영향) |
| `ct_mark` | — | conntrack mark |
| `ct_state` | conntrack lookup | 연결 추적 상태 |
| `egress_if` | 라우팅 결정 | 출력 인터페이스 |
| `ttl` | FORWARD | TTL 감소 |
| `dnat_applied` / `snat_applied` | NAT | NAT 적용 여부 |
| `original_dst_*` / `original_src_*` | NAT | NAT 전 원본 주소 |

### 7.2 TraceStep 구조

각 파이프라인 단계마다 기록:

```
TraceStep {
    seq: 단계 번호
    stage: 파이프라인 단계
    state_before: 단계 진입 시 패킷 상태
    state_after: 단계 완료 후 패킷 상태
    state_changes: [{ field, from, to }]  ← 자동 diff
    matched_rules: [{ source, table, chain, rule_index, summary }]
    decision: Continue/Drop/Reject/Accept/...
    explain: 자연어 설명
}
```

---

## 8. 최종 판정 (FinalVerdict)

| Verdict | 의미 |
|---------|------|
| `LocalDelivery` | 로컬 프로세스로 전달 |
| `Forwarded` | 다른 인터페이스로 포워딩 |
| `Drop` | 패킷 폐기 (무응답) |
| `Rejected` | 패킷 거부 (ICMP unreachable 응답) |
| `Blackhole` | 블랙홀 라우트에 의한 폐기 |
| `Tx` | XDP TX — 수신 인터페이스로 반사 |
| `Redirect` | XDP REDIRECT — 다른 인터페이스로 전환 |
| `Tproxy` | 투명 프록시로 패킷 전달 |

---

## 9. 세션 시뮬레이션

단일 패킷이 아닌 세션(연결) 단위의 시뮬레이션을 지원한다.

### 9.1 세션 타입

| 타입 | 패킷 시퀀스 | conntrack 상태 |
|------|-----------|---------------|
| TCP Handshake | SYN → SYN-ACK → ACK (+DATA, +FIN) | NEW → ESTABLISHED → ESTABLISHED |
| ICMP Echo | Echo Request → Echo Reply | NEW → ESTABLISHED |
| UDP Exchange | Request → Reply | NEW → ESTABLISHED |
| Custom | 사용자 정의 시퀀스 | 사용자 지정 |

### 9.2 NAT 매핑 전파

Forward 패킷에서 DNAT/SNAT가 적용되면, Reply 패킷의 주소가 자동 조정된다.

```
Forward: client(A) → VIP(B:80) ──DNAT──→ backend(B':8080)
Reply:   세션 정의상 VIP(B:80) → client(A)
         NAT 매핑 적용 후: backend(B':8080) → client(A)
```

### 9.3 세션 판정

| Verdict | 조건 |
|---------|------|
| `Established` | 모든 패킷이 성공적으로 전달 |
| `Failed` | 특정 패킷에서 DROP/REJECT (세션 중단) |
| `Partial` | 일부만 통과 |
