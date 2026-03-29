# netsim 백엔드 설계안

## 1. 개요

netsim 백엔드는 Rust 1.93 기반으로 구현하며, 시뮬레이션 엔진과 웹 서버를 논리적으로 분리한 Workspace 구조를 사용한다.

---

## 2. 프로젝트 구조

```
netsim/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── netsim-core/              # 시뮬레이션 엔진 라이브러리
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── model/            # IR 데이터 모델
│   │       │   ├── mod.rs
│   │       │   ├── interface.rs
│   │       │   ├── routing.rs
│   │       │   ├── policy_routing.rs
│   │       │   ├── netfilter.rs
│   │       │   ├── xdp.rs
│   │       │   ├── nat.rs
│   │       │   ├── packet.rs
│   │       │   ├── conntrack.rs
│   │       │   └── scenario.rs
│   │       ├── pipeline/         # 시뮬레이션 파이프라인
│   │       │   ├── mod.rs
│   │       │   ├── xdp.rs
│   │       │   ├── tc_ingress.rs
│   │       │   ├── prerouting.rs
│   │       │   ├── routing.rs
│   │       │   ├── local_input.rs
│   │       │   ├── forward.rs
│   │       │   └── postrouting.rs
│   │       ├── engine.rs         # 시뮬레이션 오케스트레이터
│   │       ├── trace.rs          # Trace 기록 및 explain
│   │       ├── matcher.rs        # 공유 룰 매칭 로직
│   │       └── error.rs
│   ├── netsim-parser/            # 시스템 설정 파서
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── ip_addr.rs        # `ip addr` 출력 파서
│   │       ├── ip_rule.rs        # `ip rule` 출력 파서
│   │       ├── ip_route.rs       # `ip route` 출력 파서
│   │       ├── nft_list.rs       # `nft list ruleset` 출력 파서
│   │       ├── iptables_save.rs  # `iptables-save` 출력 파서
│   │       ├── validation.rs     # 파싱 결과 검증
│   │       └── error.rs
│   └── netsim-server/            # 웹 계층 (axum)
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── app.rs            # 라우터 설정, 정적 파일 서빙
│           ├── api/
│           │   ├── mod.rs
│           │   ├── simulation.rs
│           │   ├── project.rs
│           │   ├── import.rs
│           │   └── health.rs
│           ├── storage.rs        # 파일 기반 프로젝트 저장소
│           ├── state.rs          # 앱 상태 (시뮬레이션 태스크 추적)
│           └── error.rs
```

---

## 3. Crate 의존성

### netsim-core
- serde, serde_json, serde_yaml
- uuid
- thiserror
- ipnet (IP 네트워크 표현)
- chrono (타임스탬프)

### netsim-parser
- netsim-core
- nom (파싱 컴비네이터)
- thiserror

### netsim-server
- netsim-core, netsim-parser
- axum
- tokio (full features)
- tower, tower-http (cors, static files)
- serde, serde_json, serde_yaml
- uuid
- tracing, tracing-subscriber

---

## 4. 핵심 IR 모델

### 4.1 Scenario (최상위)

```rust
pub struct Scenario {
    pub version: String,             // "1.0"
    pub name: String,
    pub description: Option<String>,
    pub interfaces: Vec<Interface>,
    pub routing_tables: Vec<RoutingTable>,
    pub ip_rules: Vec<IpRule>,
    pub netfilter: NetfilterConfig,
    pub xdp: XdpConfig,
    pub packet: PacketDef,
}
```

### 4.2 Interface

```rust
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub mac: Option<String>,
    pub addresses: Vec<InterfaceAddress>,
    pub mtu: u32,
    pub state: InterfaceState,       // Up / Down
    pub kind: InterfaceKind,         // Physical / Veth / Bridge / Vlan / Loopback
}

pub struct InterfaceAddress {
    pub ip: IpAddr,
    pub prefix_len: u8,
    pub scope: AddressScope,         // Global / Link / Host
}
```

### 4.3 Policy Routing (ip rule)

```rust
pub struct IpRule {
    pub priority: u32,
    pub selector: RuleSelector,
    pub action: RuleAction,
}

pub struct RuleSelector {
    pub from: Option<IpNetwork>,
    pub to: Option<IpNetwork>,
    pub fwmark: Option<u32>,
    pub fwmask: Option<u32>,
    pub iif: Option<String>,
    pub oif: Option<String>,
    pub tos: Option<u8>,
    pub ipproto: Option<u8>,
    pub sport: Option<PortRange>,
    pub dport: Option<PortRange>,
}

pub enum RuleAction {
    Lookup(u32),       // table id
    Blackhole,
    Unreachable,
    Prohibit,
}
```

### 4.4 Routing Table

```rust
pub struct RoutingTable {
    pub id: u32,
    pub name: Option<String>,
    pub routes: Vec<Route>,
}

pub struct Route {
    pub destination: IpNetwork,
    pub gateway: Option<IpAddr>,
    pub dev: Option<String>,
    pub src: Option<IpAddr>,
    pub metric: u32,
    pub scope: RouteScope,
    pub route_type: RouteType,       // Unicast / Local / Broadcast / Blackhole / Unreachable / Prohibit / Throw
    pub mtu: Option<u32>,
}
```

### 4.5 Netfilter (nftables / iptables 통합 IR)

```rust
pub struct NetfilterConfig {
    pub nftables: Option<NftablesRuleset>,
    pub iptables: Option<IptablesRuleset>,
}

pub struct NftablesRuleset {
    pub tables: Vec<NfTable>,
}

pub struct NfTable {
    pub family: NfFamily,            // Ip / Ip6 / Inet / Bridge
    pub name: String,
    pub chains: Vec<NfChain>,
}

pub struct NfChain {
    pub name: String,
    pub chain_type: Option<NfChainType>,  // Filter / Nat / Route / Mangle
    pub hook: Option<NfHook>,             // Prerouting / Input / Forward / Output / Postrouting
    pub priority: Option<i32>,
    pub policy: Option<NfVerdict>,
    pub rules: Vec<NfRule>,
}

pub struct NfRule {
    pub handle: Option<u64>,
    pub comment: Option<String>,
    pub matches: Vec<NfMatch>,
    pub action: NfAction,
}

// NfMatch: IP/Transport/Interface/Meta/Conntrack/Mark 매칭
// NfAction: Verdict/Nat/Mark/Log/Counter/Jump/Goto/Return
```

iptables 규칙은 파서가 동일한 `NfRule` IR로 변환한다.

### 4.6 XDP

```rust
pub struct XdpConfig {
    pub programs: Vec<XdpProgram>,
}

pub struct XdpProgram {
    pub interface: String,
    pub rules: Vec<XdpRule>,
    pub default_action: XdpAction,   // Pass / Drop / Tx / Redirect / Aborted
}
```

XDP는 eBPF 기반이므로 정적 시뮬레이션에서는 간소화된 match-action 규칙으로 모델링한다.

### 4.7 Packet

```rust
pub struct PacketDef {
    pub ingress_interface: String,
    pub ethertype: EtherType,
    pub vlan_id: Option<u16>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: IpProtocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<TcpFlags>,
    pub packet_length: Option<u32>,
    pub ttl: Option<u8>,
    pub initial_mark: u32,
    pub initial_ct_mark: u32,
    pub conntrack_state: ConntrackState,
}

/// 파이프라인 통과 시 변경되는 가변 상태
pub struct PacketState {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: IpProtocol,
    pub mark: u32,
    pub ct_mark: u32,
    pub ct_state: ConntrackState,
    pub ingress_if: String,
    pub egress_if: Option<String>,
    pub ttl: u8,
    pub dscp: u8,
    pub dnat_applied: bool,
    pub snat_applied: bool,
    pub original_dst: Option<(IpAddr, Option<u16>)>,
    pub original_src: Option<(IpAddr, Option<u16>)>,
}
```

### 4.8 Trace / 시뮬레이션 결과

```rust
pub struct SimulationResult {
    pub id: String,
    pub verdict: FinalVerdict,
    pub summary: SimulationSummary,
    pub trace: Vec<TraceStep>,
    pub created_at: String,
}

pub enum FinalVerdict {
    Drop, LocalDelivery, Forwarded, Redirect, Tx, Rejected, Blackhole, Tproxy,
}

pub struct TraceStep {
    pub seq: u32,
    pub stage: PipelineStage,
    pub description: String,
    pub state_before: PacketState,
    pub state_after: PacketState,
    pub state_changes: Vec<StateChange>,
    pub matched_rules: Vec<MatchedRuleRef>,
    pub decision: StageDecision,
    pub explain: String,
}

pub enum PipelineStage {
    Xdp, TcIngress, ConntrackIn, PreRouting,
    RoutingDecision, LocalInput, Forward, PostRouting, ConntrackConfirm,
}
```

---

## 5. 시뮬레이션 파이프라인

Linux 커널 ingress 패킷 처리 경로를 충실히 재현한다.

```
NIC receives packet
      │
 [1]  XDP (per-interface program)
      │  PASS / DROP / TX / REDIRECT / ABORTED
      ▼
 [2]  tc ingress (MVP: pass-through)
      ▼
 [3]  conntrack lookup (nf_conntrack_in)
      │  ct_state: NEW / ESTABLISHED / RELATED / INVALID
      ▼
 [4]  PREROUTING chains (priority 순서):
      │  raw(-300) → mangle(-150) → nat(-100, DNAT/REDIRECT/TPROXY)
      │  nftables: hook=prerouting 체인을 priority 순 정렬
      ▼
 [5]  Routing Decision
      │  a. ip rules를 priority 순으로 순회
      │  b. 매칭 rule의 routing table 선택
      │  c. longest prefix match로 route 선택
      │  d. LOCAL / FORWARD / BLACKHOLE / UNREACHABLE 결정
      ▼
      ├── LOCAL ──────────────────┐
      │                           │
      │  [6a] INPUT chains        │
      │   mangle → filter         │
      │         │                 │
      │         ▼                 │
      │   LOCAL_DELIVERY          │
      │                           │
      └── FORWARD ────────────────┘
                │
         [6b] FORWARD chains
          mangle → filter
                │
                ▼
         [7] POSTROUTING chains
          mangle → nat (SNAT/MASQUERADE)
                │
                ▼
         [8] conntrack confirm
                │
                ▼
          FORWARDED (egress)
```

### 핵심 처리 상세

**Conntrack:**
- 정적 시뮬레이션이므로 사용자가 선언한 conntrack state를 사용
- DNAT/SNAT 적용 시 original tuple을 기록

**체인 우선순위와 정렬:**
- nftables와 iptables의 동일 hook 체인을 병합 후 priority 순 정렬
- iptables 기본 priority: raw=-300, mangle=-150, nat(dnat)=-100, filter=0, nat(snat)=100

**룰 평가:**
- 체인 내 규칙을 순서대로 평가
- 모든 match 조건이 충족되면 action 실행
- jump/goto 서브체인 지원
- 매칭 규칙 없으면 체인 policy 적용

**라우팅 결정:**
1. ip_rules를 priority 오름차순 정렬
2. 각 rule의 selector를 패킷 상태와 매칭
3. 매칭 시 참조 routing table에서 longest prefix match
4. route_type에 따라 결정: Local → LOCAL_DELIVERY, Unicast+gateway → FORWARD
5. Throw → 다음 rule로 계속

**NAT 반영:**
- DNAT: PREROUTING에서 dst_ip/dst_port 변경 (라우팅 전)
- SNAT/MASQUERADE: POSTROUTING에서 src_ip/src_port 변경
- REDIRECT: dst_ip를 수신 인터페이스 주소로 변경
- TPROXY: 헤더 미변경, mark 설정, StageDecision::Stolen

**Mark 처리:**
- skb mark와 ct mark은 별개
- mangle 테이블에서 mark 변경 가능
- PREROUTING mangle의 mark 변경이 라우팅 결정에 영향 (fwmark 기반 정책 라우팅)

---

## 6. 파일 기반 저장소

```
/data/projects/
├── my-project/
│   ├── project.yaml              # 메타데이터 (name, created_at, updated_at)
│   ├── scenario.yaml             # 시나리오 정의
│   ├── imported-config.yaml      # import된 원본 설정 (보존)
│   └── results/
│       └── <uuid>.json           # 시뮬레이션 결과 스냅샷
```

---

## 7. 시스템 설정 파서

각 명령어 출력을 텍스트로 입력받아 IR로 변환한다.

| 명령어 | 파서 파일 | 변환 대상 |
|--------|----------|-----------|
| `ip addr` | ip_addr.rs | `Vec<Interface>` |
| `ip rule` | ip_rule.rs | `Vec<IpRule>` |
| `ip route` | ip_route.rs | `Vec<RoutingTable>` |
| `nft list ruleset` | nft_list.rs | `NftablesRuleset` |
| `iptables-save` | iptables_save.rs | `IptablesRuleset` |

각 파서는 `ValidationReport`를 함께 생성하여 정상/부분/미지원 항목을 구분한다.

```rust
pub struct ParseResult<T> {
    pub data: T,
    pub report: ValidationReport,
}

pub struct ValidationReport {
    pub parsed_ok: Vec<String>,
    pub partial: Vec<String>,
    pub unsupported: Vec<String>,
}
```
