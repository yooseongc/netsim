# netsim 백엔드 설계안

## 1. 개요

netsim 백엔드는 Rust Workspace 구조로 3개의 crate로 구성된다.
리눅스 커널의 ingress/output 패킷 처리 경로를 정적으로 시뮬레이션하는 엔진과,
이를 웹 API로 노출하는 서버, 그리고 시스템 설정 텍스트를 파싱하는 파서로 나뉜다.

---

## 2. 프로젝트 구조

```
netsim/
├── Cargo.toml                        # Workspace root
├── crates/
│   ├── netsim-core/                  # 시뮬레이션 엔진 라이브러리
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs                # 모듈 선언 (model, pipeline, engine, session_engine, trace, matcher, error, flow)
│   │   │   ├── engine.rs             # 시뮬레이션 오케스트레이터 (~596줄, run + run_output)
│   │   │   ├── session_engine.rs     # 세션 단위 시뮬레이션 (TCP handshake, ICMP, UDP)
│   │   │   ├── flow.rs               # TrafficFlow → SimulationRun 확장
│   │   │   ├── trace.rs              # SimulationResult, TraceStep, FinalVerdict(9), PipelineStage(25), StageDecision(8)
│   │   │   ├── matcher.rs            # 공유 룰 매칭 로직 (NfMatch 평가, 26개 단위 테스트)
│   │   │   ├── error.rs              # 에러 타입
│   │   │   ├── model/                # IR 데이터 모델 (13개 파일)
│   │   │   │   ├── mod.rs            # 모듈 선언 + pub use re-exports
│   │   │   │   ├── scenario.rs       # Scenario (최상위 구조체, topology/sysctl 포함)
│   │   │   │   ├── interface.rs      # Interface, InterfaceAddress, InterfaceState, InterfaceKind
│   │   │   │   ├── routing.rs        # RoutingTable, Route, RouteType, RouteScope
│   │   │   │   ├── policy_routing.rs # IpRule, RuleSelector, RuleAction
│   │   │   │   ├── netfilter.rs      # NetfilterConfig, NftablesRuleset, IptablesRuleset, NfTable, NfChain, NfRule, NfMatch, NfAction
│   │   │   │   ├── xdp.rs           # XdpConfig, XdpProgram, XdpRule, XdpAction
│   │   │   │   ├── nat.rs           # NatAction (Dnat, Snat, Masquerade, Redirect, Tproxy)
│   │   │   │   ├── packet.rs        # PacketDef, PacketState, EtherType, IpProtocol, TcpFlags, ArpFields
│   │   │   │   ├── conntrack.rs     # ConntrackState, ConntrackEntry, NatTuple, DnatMapping, SnatMapping
│   │   │   │   ├── sysctl.rs        # SysctlConfig, Ipv4Sysctl, Ipv6Sysctl, InterfaceSysctl, RpFilterMode
│   │   │   │   ├── endpoint.rs      # EndpointRole, Endpoint, TrafficFlow, Topology
│   │   │   │   ├── neighbor.rs     # NeighborEntry, NeighborState (ARP/neighbor 테이블)
│   │   │   │   ├── bridge_fdb.rs   # FdbEntry (Bridge Forwarding Database)
│   │   │   │   └── session.rs       # SessionDef, SessionType, SessionEndpoint, SessionPacket, PacketDirection
│   │   │   └── pipeline/            # 시뮬레이션 파이프라인
│   │   │       ├── mod.rs           # StageResult + re-exports (OrderedChain, chain_eval::*, nat::*)
│   │   │       ├── context.rs       # PipelineContext, RoutingOutcome, StageOutcome
│   │   │       ├── chain_eval.rs    # 체인 수집/평가/Jump/Goto 로직
│   │   │       ├── nat.rs           # apply_nat (DNAT/SNAT/Masquerade/Redirect/Tproxy)
│   │   │       ├── xdp.rs           # XDP 처리
│   │   │       ├── tc_ingress.rs    # tc ingress (현재 pass-through)
│   │   │       ├── prerouting.rs    # PREROUTING 체인 평가
│   │   │       ├── routing.rs       # 라우팅 결정 (ip rule → routing table → longest prefix match)
│   │   │       ├── local_input.rs   # INPUT 체인 평가
│   │   │       ├── forward.rs       # FORWARD 체인 평가
│   │   │       ├── postrouting.rs   # POSTROUTING 체인 평가
│   │   │       └── stages/          # 독립 검증 스테이지
│   │   │           ├── mod.rs
│   │   │           ├── interface_check.rs  # ingress 인터페이스 존재/상태 검증
│   │   │           ├── bridge.rs           # 브릿지 멤버 검사, br_nf_call_iptables 파이프라인
│   │   │           ├── arp.rs              # ARP 처리 (arp_ignore + ARP 해석/시뮬레이션)
│   │   │           ├── l2_rewrite.rs       # L2 헤더 재작성 (src_mac/dst_mac)
│   │   │           ├── sysctl_checks.rs    # rp_filter, route_localnet, ip_forward, icmp_echo_ignore, egress 인터페이스 검증
│   │   │           └── mtu_check.rs        # MTU 검사 (DF flag)
│   │   └── tests/
│   │       ├── integration_test.rs  # 통합 테스트 (66개, FDB/ARP/L2 포함)
│   │       └── session_test.rs      # 세션 테스트 (6개)
│   ├── netsim-parser/               # 시스템 설정 파서
│   │   └── src/
│   │       ├── lib.rs               # parse_system_config, SystemConfigInput, PartialScenario
│   │       ├── ip_addr.rs           # `ip addr` 출력 파서
│   │       ├── ip_rule.rs           # `ip rule` 출력 파서
│   │       ├── ip_route.rs          # `ip route` 출력 파서
│   │       ├── nft_list.rs          # `nft list ruleset` 출력 파서
│   │       ├── iptables_save.rs     # `iptables-save` 출력 파서
│   │       ├── validation.rs        # ValidationReport
│   │       └── error.rs
│   └── netsim-server/               # 웹 계층 (axum)
│       └── src/
│           ├── main.rs
│           ├── app.rs               # 라우터 설정, 정적 파일 서빙
│           ├── api/
│           │   ├── mod.rs           # 라우트 합성
│           │   ├── project.rs       # 프로젝트 CRUD + clone
│           │   ├── simulation.rs    # 시나리오/시뮬레이션 API
│           │   ├── import.rs        # 설정 import/parse/preview
│           │   └── health.rs
│           ├── storage.rs           # ProjectStorage (파일 기반)
│           ├── state.rs             # AppState (storage + 시뮬레이션 캐시)
│           └── error.rs             # ApiError (NotFound, Conflict, BadRequest, Internal)
```

---

## 3. Crate 의존성

### netsim-core
- serde, serde_json, serde_yaml — 직렬화/역직렬화
- uuid — 시뮬레이션 ID 생성
- ipnet — IP 네트워크 표현
- chrono — 타임스탬프
- thiserror — 에러 타입

### netsim-parser
- netsim-core — IR 모델 참조
- nom — 파싱 컴비네이터
- thiserror

### netsim-server
- netsim-core, netsim-parser
- axum — 웹 프레임워크
- tokio — 비동기 런타임
- tower-http — CorsLayer, ServeDir, ServeFile, TraceLayer
- serde, serde_json, serde_yaml
- chrono
- tracing, tracing-subscriber

---

## 4. 핵심 IR 모델

### 4.1 Scenario (최상위, scenario.rs)

```rust
pub struct Scenario {
    pub version: String,             // "1.0" (기본값)
    pub name: String,
    pub description: Option<String>,
    pub interfaces: Vec<Interface>,
    pub routing_tables: Vec<RoutingTable>,
    pub ip_rules: Vec<IpRule>,
    pub netfilter: NetfilterConfig,
    pub xdp: XdpConfig,
    pub sysctl: SysctlConfig,        // 커널 파라미터
    pub packet: PacketDef,
    pub topology: Option<Topology>,  // 엔드포인트 및 트래픽 흐름
}
```

### 4.2 Interface (interface.rs)

```rust
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub mac: Option<String>,
    pub addresses: Vec<InterfaceAddress>,
    pub mtu: u32,                    // 기본값 1500
    pub state: InterfaceState,       // Up / Down
    pub kind: InterfaceKind,         // Physical / Veth / Bridge / Vlan / Loopback / Bond
    pub veth_peer: Option<String>,
    pub bridge_members: Vec<String>,
    pub master: Option<String>,      // 속한 브릿지 이름
    pub vlan_parent: Option<String>,
    pub vlan_id: Option<u16>,
    pub bond_members: Vec<String>,
}
```

### 4.3 PacketDef / PacketState (packet.rs)

`PacketDef`는 사용자 정의 패킷 — `PacketState`는 파이프라인 통과 시 변경되는 가변 상태.

```rust
pub struct PacketDef {
    pub ingress_interface: String,
    pub ethertype: EtherType,        // ipv4/ipv6/arp/stp/lldp/vlan/other
    pub vlan_id: Option<u16>,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub src_ip: Option<IpAddr>,      // L2-only에서는 None
    pub dst_ip: Option<IpAddr>,
    pub protocol: IpProtocol,        // tcp/udp/icmp/icmpv6/vrrp/ospf/gre/esp/ah/sctp/other
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<TcpFlags>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub arp: Option<ArpFields>,
    pub packet_length: Option<u32>,
    pub df_flag: bool,
    pub dscp: Option<u8>,
    pub ttl: Option<u8>,            // 기본값 64
    pub initial_mark: u32,
    pub initial_ct_mark: u32,
    pub conntrack_state: ConntrackState,
}

pub struct PacketState {
    // PacketDef의 대부분 필드 + 가변 상태
    pub mark: u32,
    pub ct_mark: u32,
    pub ct_state: ConntrackState,
    pub egress_if: Option<String>,
    pub dnat_applied: bool,
    pub snat_applied: bool,
    pub tproxy_applied: bool,
    pub original_dst_ip: Option<IpAddr>,
    pub original_dst_port: Option<u16>,
    pub original_src_ip: Option<IpAddr>,
    pub original_src_port: Option<u16>,
    // ... (PacketDef의 L2/L3/L4 필드 포함)
}
```

### 4.4 Conntrack (conntrack.rs)

```rust
pub enum ConntrackState { New, Established, Related, Invalid, Untracked }

pub struct ConntrackEntry {
    pub state: ConntrackState,
    pub nat_tuple: Option<NatTuple>,
}

pub struct NatTuple {
    pub dnat: Option<DnatMapping>,   // original_dst ↔ translated_dst
    pub snat: Option<SnatMapping>,   // original_src ↔ translated_src
}
```

Established/Related 패킷은 저장된 NAT tuple을 자동 적용하고 NAT 체인 평가를 건너뛴다.

### 4.5 Endpoint / Topology (endpoint.rs)

```rust
pub enum EndpointRole {
    LocalClient,    // 로컬 발신 (OUTPUT 경로)
    RemoteClient,   // 외부 수신 (ingress 경로)
    LocalServer,    // 로컬 서비스
    RemoteServer,   // 외부 서비스 (포워딩 대상)
    LocalProxy,     // 일반 프록시 (DNAT → INPUT → OUTPUT)
    LocalTProxy,    // 투명 프록시 (TPROXY → INPUT → OUTPUT)
}

pub struct Topology {
    pub endpoints: Vec<Endpoint>,
    pub flows: Vec<TrafficFlow>,
}
```

### 4.6 SysctlConfig (sysctl.rs)

```rust
pub struct SysctlConfig {
    pub ipv4: Ipv4Sysctl,           // ip_forward, icmp_echo_ignore_all, ...
    pub ipv6: Ipv6Sysctl,           // forwarding
    pub interface_conf: HashMap<String, InterfaceSysctl>,
    pub bridge_nf_call_iptables: bool,
    pub bridge_nf_call_ip6tables: bool,
    pub bridge_nf_call_arptables: bool,
}

pub struct InterfaceSysctl {
    pub forwarding: Option<bool>,
    pub route_localnet: bool,
    pub rp_filter: RpFilterMode,     // Off / Strict / Loose
    pub accept_local: bool,
    pub arp_ignore: u8,              // 0-8
    pub arp_announce: u8,            // 0-2
    // ... (send_redirects, log_martians, proxy_arp 등)
}
```

인터페이스 설정 조회 우선순위: `{iface}` → `"all"` → `"default"` → 기본값.

### 4.7 Netfilter (netfilter.rs)

```rust
pub struct NetfilterConfig {
    pub nftables: Option<NftablesRuleset>,
    pub iptables: Option<IptablesRuleset>,
}

pub enum NfAction {
    Verdict { verdict: NfVerdict },  // Accept/Drop/Reject/Continue/Queue
    Nat { action: NatAction },       // Dnat/Snat/Masquerade/Redirect/Tproxy
    SetMark { value: u32, mask: Option<u32> },
    Log { prefix: Option<String>, level: Option<u8> },
    Counter,
    Jump { target: String },
    Goto { target: String },
    Return,
}
```

### 4.8 Session (session.rs)

```rust
pub enum SessionType {
    TcpHandshake { client, server, include_data, include_close },
    IcmpEcho { source, destination, ipv6 },
    UdpExchange { client, server },
    Custom { packets: Vec<SessionPacket> },
}
```

`SessionDef::expand_to_packets()` — 세션을 `Vec<(String, PacketDef)>` 시퀀스로 확장.

---

## 5. 시뮬레이션 파이프라인

### 5.1 Ingress 경로 (`engine::run`)

```
NIC receives packet
      │
 [0]  InterfaceCheck — 인터페이스 존재/UP 검증
      │
 [1]  XDP — per-interface 프로그램 (PASS/DROP/TX/REDIRECT)
      │
      ├── BridgeCheck — 브릿지 멤버면 L2 포워딩
      │   └── (bridge_nf_call_iptables=true 시 BrNfPrerouting → BrNfForward → BrNfPostrouting)
      │
 [2]  ARP — arp_ignore 처리 (L2-only 패킷은 여기서 종료)
      │
      ├── L2Bypass — ARP/STP/LLDP 패킷은 netfilter/routing 건너뛰기
      │
 [3]  tc ingress (pass-through)
      │
 [4]  PREROUTING
      │  ├── PreRoutingRaw: raw 체인 (priority ≤ -200, conntrack 이전)
      │  ├── ConntrackIn: conntrack lookup (사용자 선언 ct_state)
      │  │   └── Established/Related: 저장된 NAT tuple 자동 적용 → NAT 체인 건너뛰기
      │  └── PreRouting: post-conntrack 체인 (mangle/nat/filter, DNAT/TPROXY 포함)
      │      └── TPROXY: mark 설정 + dst 변경, 패킷은 routing → INPUT으로 계속
      │
 [5]  sysctl 검사
      │  ├── rp_filter (Reverse Path Filtering)
      │  ├── route_localnet (127.0.0.0/8 라우팅 허용, TPROXY 시 건너뛰기)
      │
 [6]  Routing Decision
      │  ├── TPROXY: routing_result 이미 Local로 설정 → 라우팅 건너뛰기
      │  ├── ip rules → routing table → longest prefix match
      │  └── mark/dst 변경 시 Reroute 기록 (fwmark 정책 라우팅 존재 시)
      │
      ├── LOCAL ─────────────────────────────────────────┐
      │  ├── sysctl: icmp_echo_ignore_all                │
      │  ├── INPUT chains (mangle → filter)              │
      │  └── LOCAL_DELIVERY                              │
      │                                                  │
      └── FORWARD ───────────────────────────────────────┘
         ├── sysctl: egress 인터페이스 존재/UP 검증
         ├── sysctl: ip_forward 검사
         ├── FORWARD chains (mangle → filter)
         ├── POSTROUTING chains (mangle → nat/SNAT/MASQUERADE)
         ├── MTU check (DF flag 시 MTU 초과 검사)
         ├── ConntrackConfirm
         └── FORWARDED
```

### 5.2 Output 경로 (`engine::run_output`)

```
Local process sends packet
      │
 [1]  OUTPUT chains
      │  ├── OUTPUT_RAW (priority ≤ -200)
      │  ├── ConntrackIn (output)
      │  └── OUTPUT post-conntrack (mangle/filter/nat)
      │
 [2]  Routing Decision (post-OUTPUT)
      │  ├── LOCAL → LoopbackDelivery → INPUT → LOCAL_DELIVERY
      │  └── FORWARD → continue
      │  └── mark 변경 시 Reroute 기록
      │
 [3]  POSTROUTING chains
      │
 [4]  MTU check (output)
      │
 [5]  ConntrackConfirm
      │
      └── SENT
```

### 5.3 PipelineContext (context.rs)

```rust
pub struct PipelineContext<'a> {
    pub packet: PacketState,
    pub scenario: &'a Scenario,
    pub trace: Vec<TraceStep>,
    pub matched_rules: Vec<MatchedRuleRef>,
    pub seq: u32,
    pub routing_result: Option<RoutingOutcome>,
    pub needs_reroute: bool,
    pub conntrack_entry: Option<ConntrackEntry>,
}
```

주요 메서드:
- `from_scenario()` — Scenario에서 PipelineContext 생성
- `record_step()` — StageResult로 TraceStep 기록 (자동 state diff 계산)
- `record_info_step()` — 정보성 TraceStep 기록
- `finalize()` — SimulationResult 빌드

### 5.4 체인 평가 (chain_eval.rs)

```rust
pub struct OrderedChain {
    pub source: RuleSource,          // Nftables / Iptables
    pub table_name: String,
    pub chain_name: String,
    pub priority: i32,
    pub policy: Option<NfVerdict>,
    pub rules: Vec<NfRule>,
}
```

주요 함수:
- `collect_chains_for_hook()` — nftables + iptables에서 해당 hook의 모든 체인을 수집, priority 정렬
- `collect_all_chains_in_tables()` — Jump/Goto 대상 조회용 전체 체인 목록
- `evaluate_chain_inner()` — 체인 규칙 평가 (재귀, 최대 16단계)
  - Accept/Drop/Reject/Queue → 즉시 반환
  - NAT → `apply_nat()` 호출 후 Accept
  - SetMark → mark 변경, 다음 규칙 계속
  - Jump → 타겟 체인 평가 후 복귀 (Return 시 현재 체인 다음 규칙)
  - Goto → 타겟 체인 평가 후 현재 체인 종료 (Return 시 base chain policy)
- `evaluate_netfilter_hook()` — 특정 hook 전체 평가 (L2-only 건너뛰기)
- `evaluate_chains_subset()` — 사전 필터링된 체인 목록 평가 (PREROUTING raw/post-ct 분리에 사용)

### 5.5 NAT 적용 (nat.rs)

```rust
pub fn apply_nat(nat_action: &NatAction, state: &mut PacketState, interfaces: &[Interface])
```

| NatAction | 동작 |
|-----------|------|
| Dnat | dst_ip/dst_port 변경, original 보존, dnat_applied=true |
| Snat | src_ip/src_port 변경, original 보존, snat_applied=true |
| Masquerade | egress 인터페이스 IP로 src_ip 변경 (address family 매칭) |
| Redirect | ingress 인터페이스 IP로 dst_ip 변경 |
| Tproxy | dst 변경 + mark 설정 + tproxy_applied=true |

ICMP 패킷에는 포트 변경을 적용하지 않는다 (`state.has_ports()` 검사).

### 5.6 Matcher (matcher.rs)

`evaluate_matches(&[NfMatch], &PacketState) -> bool` — 모든 조건 AND 결합.

지원하는 NfMatch 타입:
- **Ip**: saddr/daddr/protocol/version/dscp/ttl (CIDR, comma-separated set 지원)
- **Transport**: sport/dport/flags/icmp_type/icmp_code (프로토콜별 분기)
- **Iif/Oif**: 인터페이스 이름 매칭
- **Meta**: mark/protocol/iifname/oifname/l4proto/nfproto
- **Ct**: state/mark/direction (comma-separated set 지원)
- **Mark**: value/mask 기반 비교

---

## 6. 세션 시뮬레이션 (session_engine.rs)

`run_session()` — 세션을 패킷 시퀀스로 확장 후 순서대로 `engine::run()` 호출.

- 첫 번째 패킷에서 NAT 매핑 추출
- 이후 reply 패킷에 NAT 매핑을 역으로 적용
  - DNAT 역변환: reply의 src를 translated dst로
  - SNAT 역변환: reply의 dst를 translated src로
- 패킷이 드롭되면 세션 즉시 중단 (`SessionVerdict::Failed`)

### SessionVerdict

```rust
pub enum SessionVerdict {
    Established,                     // 모든 패킷 통과
    Failed { failed_at, reason },    // 특정 패킷에서 실패
    Partial { passed, total },       // 부분 성공
}
```

---

## 7. TrafficFlow 확장 (flow.rs)

`expand_flow()` — TrafficFlow와 Topology의 엔드포인트를 기반으로 SimulationRun 생성.

| Source Role → Dest Role | SimulationRun |
|------------------------|---------------|
| RemoteClient → LocalServer/LocalProxy/LocalTProxy | Ingress |
| LocalClient → RemoteServer | Output |
| RemoteClient → RemoteServer | Ingress (forward) |
| LocalProxy/LocalTProxy → RemoteServer | Output (proxy output) |
| LocalServer → RemoteClient | Output (response) |

---

## 8. 파일 기반 저장소 (storage.rs)

```
{data_dir}/
├── {project-name}/
│   ├── project.yaml              # ProjectMeta (YAML, serde_yaml)
│   ├── scenario.json             # Scenario (JSON, serde_json)
│   └── simulations/
│       └── {uuid}.json           # SimulationResult (JSON)
```

`ProjectStorage` 메서드:
- `list_projects()` — 디렉토리 순회, 이름순 정렬
- `create_project()` / `get_project()` / `update_project()` / `delete_project()`
- `clone_project()` — 재귀적 디렉토리 복사 + 메타데이터 갱신
- `get_scenario()` / `save_scenario()` — scenario.json 읽기/쓰기
- `save_simulation_result()` / `find_simulation_result()` — 전체 프로젝트 검색

---

## 9. 시스템 설정 파서 (netsim-parser)

| 명령어 | 파서 파일 | 변환 대상 |
|--------|----------|-----------|
| `ip addr` | ip_addr.rs | `Vec<Interface>` |
| `ip rule` | ip_rule.rs | `Vec<IpRule>` |
| `ip route` | ip_route.rs | `Vec<RoutingTable>` |
| `nft list ruleset` | nft_list.rs | `NftablesRuleset` |
| `iptables-save` | iptables_save.rs | `IptablesRuleset` |

진입점: `parse_system_config(input: &SystemConfigInput) -> ParseResult<PartialScenario>`

```rust
pub struct PartialScenario {
    pub interfaces: Vec<Interface>,
    pub routing_tables: Vec<RoutingTable>,
    pub ip_rules: Vec<IpRule>,
    pub netfilter: NetfilterConfig,
}

pub struct ValidationReport {
    pub parsed_ok: Vec<String>,
    pub partial: Vec<String>,
    pub unsupported: Vec<String>,
}
```
