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
  - SimulationContext (결과 전달용 React Context)
  - lucide-react 아이콘 추가
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
| 8단계 | 문서 분리 (docs/nstack/) + 통합 배포 | 진행 중 |
