# netsim 진행 사항

## 현재 단계

**7단계: 프론트엔드 구현** — 진행 중

---

## 진행 이력

### 2026-03-29

- [x] 요구사항 분석 (spec/REQUIREMENT.md, spec/TECH.md)
- [x] 백엔드 설계안 작성 (docs/DESIGN_BACKEND.md)
- [x] 프론트엔드 설계안 작성 (docs/DESIGN_FRONTEND.md)
- [x] API 명세 작성 (docs/API.md)
- [x] 스타일 가이드 작성 (docs/STYLE.md)
- [x] 빌드/실행 가이드 작성 (docs/DEV.md)
- [x] 테스트 정의 작성 (docs/TEST.md)
- [x] Rust workspace 초기화 (3 crates + IR 모델 정의 + 컴파일 확인)
- [x] Frontend scaffold 생성 (React + TypeScript + Vite + Tailwind + 빌드 확인)
- [x] Dockerfile 작성 (멀티스테이지)
- [x] 패킷 모델 보강 (ICMP type/code, ARP, L2 프로토콜, VRRP/OSPF/GRE 등)
- [x] matcher.rs 룰 매칭 엔진 구현 (프로토콜별 L4 분기, 15개 단위 테스트)
- [x] 파이프라인 전 단계 구현 (xdp, tc, prerouting, routing, input, forward, postrouting)
- [x] engine.rs 시뮬레이션 오케스트레이터 구현
- [x] 통합 테스트 13개 시나리오 (TCP/UDP/ICMP/ARP/VRRP, DNAT, SNAT, XDP, 정책라우팅, TTL, blackhole)
- [x] 1차 버그 수정 (메모리 누수, Reject/Drop 구분, XDP TX, next_hop)
- [x] 통합 테스트 26개로 확장 (+Reject, chain policy, iptables, IPv6, ICMPv6, 혼합 규칙)
- [x] 2차 버그 수정 (SCTP has_ports, Masquerade IPv4/6 패밀리, serde 중첩 tag, TTL 순서)
- [x] compute_state_changes NAT/프로토콜 필드 추적 보강
- [x] 세션 모델 구현 (TCP handshake, ICMP echo, UDP exchange, 커스텀)
- [x] 세션 엔진 구현 (NAT 매핑 전파, 방화벽 실패 감지)
- [x] 세션 테스트 6개 (TCP handshake, ICMP ping, DNAT+TCP, 방화벽 차단, UDP DNS, full TCP)
- [x] 3차 버그 수정 (fwmark mask 비교, IpAddr 파싱 복원)
- [x] sysctl 커널 파라미터 모델 (ip_forward, route_localnet, rp_filter, icmp_echo_ignore 등)
- [x] 엔진에 sysctl 통합 (ip_forward, route_localnet, rp_filter, icmp_echo_ignore_all)
- [x] sysctl 테스트 5개 (ip_forward off, route_localnet on/off, icmp_echo_ignore, rp_filter strict)
- [x] 인터페이스 모델 확장 (veth, bridge, VLAN, bond, MTU, df_flag, state 검증)
- [x] ARP sysctl (arp_ignore/announce/filter, proxy_arp, bridge-nf-call)
- [x] 테스트 강화 3회전 실시:
  - R1: MTU trace gap 수정, +11 테스트 (interface down, MTU DF, bridge, ARP, IPv6 masq)
  - R2: ARP→XDP 순서 수정, vlan_id/mac PacketState 추가, egress 존재 검증
  - R3: PipelineStage 라벨 수정 (RpFilter, L2Bypass), compute_state_changes L2 필드 추가
- [x] 총 74개 테스트 통과 (matcher 26 + 통합 42 + 세션 6)
- [x] docs/NETWORK_STACK.md 작성 (전체 파이프라인 다이어그램, 단계별 상세, sysctl, 인터페이스, 세션)
- [x] 5단계: 파서 구현 (5개 파서 + 통합 API + 46개 테스트)
- [x] 엔진 구조 보정 (conntrack/RAW 순서, TPROXY, bridge L2 포워딩, OUTPUT 경로, ingress MTU)
  - PREROUTING을 raw(priority<=-200) → conntrack → mangle/nat으로 분리
  - TPROXY가 stolen 대신 로컬 전달 경로를 따르도록 수정 (tproxy_applied 플래그)
  - Bridge member + bridge_nf_call_iptables=false → L2 브릿지 포워딩 경로 추가
  - Physical NIC ingress 프레임 크기 검사 추가 (가상 인터페이스 제외)
  - run_output() 함수 추가 (로컬 발신 패킷: OUTPUT→routing→POSTROUTING→MTU→SENT)
  - PipelineStage: PreRoutingRaw, BridgeForward, Output 추가
  - FinalVerdict::Sent 추가
  - evaluate_chains_subset() 헬퍼 추가
  - 기존 120개 테스트 전체 통과 유지
- [x] 엔진 Phase 6+7: Bridge NF 파이프라인 + Conntrack/Loopback/NAT 1-time + Endpoint Role Model
  - Phase 6: bridge_nf_call_iptables=true 시 br_nf PREROUTING/FORWARD/POSTROUTING 파이프라인 실행
  - Phase 7: conntrack 엔트리 모델 (NatTuple, DnatMapping, SnatMapping), established 커넥션에 대한 NAT 1-time 적용
  - Phase 7: run_output() 로컬 주소 대상 시 LoopbackDelivery → INPUT → LocalDelivery 경로
  - Endpoint Role Model: EndpointRole (LocalClient/RemoteClient/LocalServer/RemoteServer/LocalProxy/LocalTProxy)
  - Topology + TrafficFlow → SimulationRun 확장 로직 (flow.rs)
  - PipelineStage 추가: BrNfPrerouting, BrNfForward, BrNfPostrouting, LoopbackDelivery
  - conntrack_entry 필드를 PipelineContext에 추가
  - Scenario에 topology 옵션 필드 추가
  - 테스트 4개 추가: bridge_nf_pipeline, conntrack_nat_established, loopback_delivery, flow_remote_to_local
  - 기존 76개 + 신규 4개 = 총 80개 테스트 전체 통과
- [x] 엔진 Phase 4+5: 라우팅 재평가 + TPROXY 로컬 전달
  - Phase 4: PipelineStage::Reroute 추가, run()에서 PREROUTING 후 mark/dst 변경 감지, run_output()에서 OUTPUT mark 변경 시 재라우팅 트레이스 기록
  - Phase 5: TPROXY 적용 시 routing/route_localnet 우회하여 강제 로컬 전달 (skb->sk 소켓 할당 시뮬레이션)
  - has_fwmark_rules() 유틸리티 추가 (fwmark 기반 정책 라우팅 규칙 감지)
  - 테스트 2개 추가: test_tproxy_forces_local_delivery, test_reroute_in_output
  - 기존 74개 + 신규 2개 = 총 76개 테스트 전체 통과
- [x] 엔진 리팩토링 Phase 2+3: 파이프라인 구조 분리
  - Phase 2: engine.rs에서 stage 함수 추출 → pipeline/stages/ 디렉토리
    - interface_check.rs (ingress 인터페이스 검증)
    - bridge.rs (브릿지 멤버 감지, L2 포워딩)
    - arp.rs (arp_ignore 처리)
    - sysctl_checks.rs (rp_filter, route_localnet, icmp_echo_ignore, ip_forward, egress 검증)
    - mtu_check.rs (MTU 초과/DF 플래그 검사)
    - engine.rs → 얇은 오케스트레이터로 축소
  - Phase 3: pipeline/mod.rs에서 chain_eval.rs + nat.rs 분리
    - chain_eval.rs: 체인 수집/평가/헬퍼 함수 전체 이동
    - nat.rs: apply_nat() 이동
    - mod.rs → 모듈 선언 + StageResult + re-export만 유지
  - 외부 API 변경 없음, 120개 테스트 전체 통과
- [x] 7단계: 프론트엔드 MVP 구현
  - TypeScript 타입 정의 (project, scenario, trace — Rust IR 미러)
  - API 클라이언트 (fetch 래퍼, 에러 처리)
  - ProjectListPage (카드 그리드, 생성 다이얼로그, 삭제)
  - ScenarioEditorPage (YAML 텍스트 에디터, Save/Run 버튼)
  - SimulationResultPage (Summary 카드 + Pipeline Flow 타임라인)
  - Trace 시각화 컴포넌트 (PipelineFlow, TraceStepCard, StateDiffView, VerdictBadge)
  - AppShell 레이아웃 (Header + Sidebar + 라우팅)
- [x] Topology/Flow 편집 UI 구현
  - TopologyEditor 컴포넌트 (엔드포인트 카드 그리드 + 트래픽 플로우 목록)
  - EndpointForm 모달 (이름, 역할, IP, 포트, 인터페이스 편집)
  - FlowForm 모달 (이름, 소스/대상 엔드포인트 선택, 프로토콜)
  - ScenarioEditorPage에 YAML/Topology 탭 전환 추가
  - js-yaml 의존성 추가 (YAML ↔ Topology 양방향 동기화)
  - 역할별 아이콘(Lucide) 및 색상 배지 적용
  - SimulationContext (결과 전달용 React Context)
  - lucide-react 아이콘 추가
  - pnpm build 통과 확인
- [x] 시나리오 에디터 고도화 (7탭 폼 에디터)
  - ScenarioEditorPage: YAML/Topology 2탭 → Packet/Interfaces/Routing/Rules/XDP/YAML/Topology 7탭 확장
  - PacketEditor: L2(EtherType, MAC, VLAN) / L3(IP, TTL, DSCP, DF) / L4(포트, TCP flags, ICMP) / Conntrack 폼
  - InterfacesEditor: Interface CRUD + 주소 관리 + 가상 인터페이스(veth, bridge, vlan, bond) 관계 편집
  - RoutingEditor: RoutingTable CRUD(경로 추가/편집/삭제) + IP Rule(정책 라우팅) 편집
  - RulesEditor: nftables 테이블/체인/규칙 3단계 CRUD + NfMatch/NfAction 인라인 편집기
  - XdpEditor: XDP 프로그램 CRUD + 규칙(매치+액션) 편집, redirect 포함
  - YAML ↔ Scenario 양방향 동기화 (탭 전환 시 자동 파싱/직렬화)
  - pnpm build 통과 확인
- [x] Visual Topology Editor 구현 (React Flow 기반)
  - @xyflow/react + @dagrejs/dagre 의존성 추가
  - TopologyCanvas: React Flow 캔버스 (드래그 앤 드롭, 줌/팬, MiniMap)
  - EndpointNode: 역할별 색상/아이콘 커스텀 노드 (6 roles)
  - FlowEdge: 플로우명 + 프로토콜 뱃지 커스텀 엣지
  - TopologyToolbar: Add Endpoint 드롭다운 + Auto Layout (dagre LR)
  - TopologyPropertiesPanel: 선택 노드/엣지 상세 + Edit/Delete
  - 노드 드래그 → position 자동 저장, Handle 드래그 → FlowForm 연결
  - Topology 탭을 메인(첫 번째) 탭으로 승격
  - Endpoint 타입에 position 필드 추가
  - DeviceNode: 중앙 Linux Host 노드 (인터페이스/라우트/규칙 수 표시)
  - InterfaceNode: 네트워크 인터페이스 노드 (이름, IP, MTU, 상태, 종류)
  - Device ↔ Interface 내부 링크 + Endpoint ↔ Interface 외부 링크 자동 생성
  - TopologyCanvas 확장: 장비+인터페이스+엔드포인트 3단계 구조
  - PropertiesPanel: 인터페이스 상세 정보 표시 + 삭제 지원
  - Topology 타입에 node_positions 필드 추가 (device/interface 위치 저장)
  - pnpm build 통과 확인
- [x] 12개 샘플 시나리오 구현 (내장형)
  - 바이너리 내장 (include_str! + 메모리 API, 파일시스템 미사용)
  - GET /api/v1/samples, GET /api/v1/samples/:name, POST /api/v1/samples/:name/simulate
  - basic-forward, dnat-port-forward, snat-masquerade, firewall-drop
  - icmp-ping, policy-routing, xdp-filter, bridge-forward
  - local-delivery, ttl-exceeded, mtu-exceeded, tproxy
- [x] 사이드바 PROJECTS/SAMPLES 구조 개편
  - AppShell 사이드바: PROJECTS (접이식) + SAMPLES (접이식) 2섹션
  - 샘플 클릭 → SampleViewerPage (YAML 읽기전용 + Run + Copy to Project)
- [x] 시뮬레이션 결과 다이얼로그
  - SimulationResultDialog 컴포넌트 (모달, Summary + PipelineFlow)
  - ScenarioEditorPage: navigate 대신 다이얼로그로 결과 표시
  - SampleViewerPage: Run → 다이얼로그로 결과 표시
- [x] 장비 내부/외부 구분
  - Device Boundary: group 노드로 장비 영역 표현 (점선 경계)
  - Local 엔드포인트: parentId로 장비 내부 배치 (extent: parent)
  - Remote 엔드포인트: 장비 외부 배치
  - Toolbar 드롭다운: Inside Device / Outside Device 구분
- [x] 시뮬레이션 리플레이 애니메이션
  - SimulationReplayBar: Play/Pause/Step 컨트롤 + 속도 조절 + 프로그레스 바
  - 단계별 노드/엣지 하이라이트 (ingress=파랑, device=보라, egress=노랑)
  - Drop=빨간 glow, Local Delivery=초록 glow, Forward=노란 glow
  - Run 후 자동 Topology 탭 전환 + 리플레이 시작
- [x] UX 개선
  - 인터페이스 추가 시 랜덤 IP/MAC 초기값 자동 생성
  - forwarded verdict 시 egress interface 헤더에 표시
  - 캔버스 노드 사이즈 축소 (160px endpoint, 140px interface)
  - 세로 스크롤 수정 (AppShell main padding을 페이지 레벨로 이동)
  - 415 에러 수정 (saveScenarioYaml → saveScenario JSON)
- [x] Bridge FDB + ARP 시뮬레이션 + L2 헤더 재작성
  - NeighborEntry (ARP 테이블) + FdbEntry (Bridge FDB) 모델 추가
  - PipelineContext에 arp_table, fdb HashMap 추가
  - PipelineStage: BridgeFdbLookup, ArpResolve, L2Rewrite 3종 추가
  - Bridge FDB: source MAC 동적 학습 + 정적 FDB 조회 + unknown MAC flooding
  - ARP 해석: neighbor 테이블 조회 → 미스 시 ARP request 시뮬레이션 (proxy_arp, arp_filter 반영)
  - L2 재작성: 포워딩 시 src_mac = egress IF MAC, dst_mac = ARP 결과
  - 엔진 통합: routing → egress_check → ARP resolve → L2 rewrite → ip_forward → FORWARD
  - 하위 호환: neighbors 미설정 시 기존 동작 유지
  - 테스트 10개 추가 (FDB 3, ARP 4, L2 rewrite 1, proxy_arp 1, arp_filter 1)
  - 총 144개 테스트 통과 (기존 134 + 신규 10)
- [x] Import UI 페이지 구현
  - ImportPage 컴포넌트 (5개 textarea: ip addr, ip rule, ip route, nft list ruleset, iptables-save)
  - Preview 버튼 → ValidationReport 표시 (parsed_ok/partial/unsupported 구분)
  - Import to Project 버튼 + merge strategy 선택 (replace/merge)
  - 라우트 추가: /projects/:name/import
  - ScenarioEditorPage에 Import 버튼 추가
  - API 클라이언트 타입 강화 (ImportParseRequest, ImportApplyRequest, ImportResponse)
  - pnpm build 통과 확인

---

## 전체 로드맵

| 단계 | 내용 | 상태 |
|------|------|------|
| 1단계 | 설계 문서 작성 | 완료 |
| 2단계 | 프로젝트 초기화 (Rust workspace + Frontend + Docker) | 완료 |
| 3단계 | 코어 모델 구현 (netsim-core IR) | 완료 |
| 4단계 | 시뮬레이션 엔진 구현 | 완료 |
| 5단계 | 파서 구현 (netsim-parser) | 완료 |
| 6단계 | 웹 서버 구현 (netsim-server) | 완료 |
| 7단계 | 프론트엔드 구현 | 완료 |
| 엔진 개편 | Phase 1~7 (PipelineContext, stages, chain_eval, routing 재호출, TPROXY, bridge NF, conntrack, loopback, endpoint roles) | 완료 |
| 8단계 | 프론트엔드 고도화 (Visual Topology, 샘플, 리플레이) | 완료 |
| 9단계 | Docker 빌드 + 통합 배포 | 미진행 |
