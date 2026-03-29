# netsim 테스트 정의

## 1. 테스트 전략

### 계층별 테스트

| 계층 | 범위 | 도구 |
|------|------|------|
| 단위 테스트 | 개별 함수/모듈 | `cargo test` |
| 통합 테스트 | 전체 시뮬레이션 파이프라인 | `cargo test` (tests/) |
| API 테스트 | HTTP 엔드포인트 | `cargo test -p netsim-server` |
| 프론트엔드 테스트 | 컴포넌트 렌더링 | vitest + React Testing Library |

---

## 2. 백엔드 단위 테스트

### netsim-core

| 모듈 | 테스트 항목 | 상태 |
|------|-----------|------|
| model/ | IR 구조체 YAML/JSON 직렬화/역직렬화 | 대기 |
| matcher.rs | 각 NfMatch 타입별 매칭 로직 | 대기 |
| pipeline/xdp.rs | XDP PASS/DROP/TX/REDIRECT 결정 | 대기 |
| pipeline/prerouting.rs | PREROUTING 체인 순서 평가, DNAT 적용 | 대기 |
| pipeline/routing.rs | ip rule 매칭, longest prefix match, route type 결정 | 대기 |
| pipeline/local_input.rs | INPUT 체인 평가 | 대기 |
| pipeline/forward.rs | FORWARD 체인 평가 | 대기 |
| pipeline/postrouting.rs | POSTROUTING 체인 평가, SNAT 적용 | 대기 |
| engine.rs | 전체 파이프라인 오케스트레이션 | 대기 |
| trace.rs | trace 기록, state diff 계산, explain 생성 | 대기 |

### netsim-parser

| 파서 | 테스트 항목 | 상태 |
|------|-----------|------|
| ip_addr.rs | 단일/복수 인터페이스, IPv4/IPv6, 다양한 상태 | 대기 |
| ip_rule.rs | 기본 rule, fwmark, from/to 매칭 | 대기 |
| ip_route.rs | default route, 다중 테이블, metric, scope | 대기 |
| nft_list.rs | 기본 체인, 다양한 match/action, 테이블 구조 | 대기 |
| iptables_save.rs | filter/nat/mangle 테이블, 기본 규칙 | 대기 |
| validation.rs | ok/partial/unsupported 분류 | 대기 |

---

## 3. 통합 테스트 시나리오

### 시나리오 1: 기본 로컬 패킷 수신
- 패킷: 외부 → 로컬 IP
- 예상 경로: XDP(PASS) → conntrack(NEW) → PREROUTING(ACCEPT) → Routing(LOCAL) → INPUT(ACCEPT) → LOCAL_DELIVERY
- 검증: verdict=LocalDelivery, trace 8단계

### 시나리오 2: 기본 포워딩
- 패킷: eth0 → eth1 (라우팅 테이블에 따라)
- 예상 경로: ... → Routing(FORWARD via eth1) → FORWARD(ACCEPT) → POSTROUTING(ACCEPT) → FORWARDED
- 검증: verdict=Forwarded, egress_if=eth1

### 시나리오 3: DNAT + 포워딩
- PREROUTING nat에서 DNAT 적용
- 예상: dst_ip 변경 후 라우팅, state_changes에 dst_ip diff 기록

### 시나리오 4: SNAT/MASQUERADE
- POSTROUTING에서 SNAT 적용
- 예상: src_ip 변경, state_changes 기록

### 시나리오 5: 방화벽 DROP
- FORWARD 체인에서 DROP
- 예상: verdict=Drop, trace에서 FORWARD 단계에 DROP 결정

### 시나리오 6: 정책 라우팅
- fwmark 기반 다른 라우팅 테이블 선택
- 예상: mangle PREROUTING에서 mark 설정 → 해당 mark의 ip rule 매칭 → 다른 테이블로 라우팅

### 시나리오 7: XDP DROP
- XDP 단계에서 DROP
- 예상: verdict=Drop, trace 1단계만 기록

### 시나리오 8: Blackhole 라우트
- 라우팅 테이블에 blackhole 라우트
- 예상: verdict=Blackhole

---

## 4. API 테스트

| 엔드포인트 | 테스트 항목 | 상태 |
|-----------|-----------|------|
| POST /projects | 생성 성공, 중복 이름 409 | 대기 |
| GET /projects | 빈 목록, 목록 반환 | 대기 |
| GET /projects/:name | 존재, 404 | 대기 |
| DELETE /projects/:name | 삭제 성공, 404 | 대기 |
| PUT /projects/:name/scenario | 저장 성공, 검증 실패 400 | 대기 |
| POST /projects/:name/simulate | 성공 실행, 시나리오 없음 404 | 대기 |
| POST /import/parse | 전체 파싱, 부분 파싱, 빈 입력 | 대기 |

---

## 5. 프론트엔드 테스트

| 컴포넌트 | 테스트 항목 | 상태 |
|---------|-----------|------|
| ProjectListPage | 목록 렌더링, 생성 다이얼로그 | 대기 |
| ScenarioEditorPage | 탭 전환, 폼 입력 | 대기 |
| TraceTimeline | 단계 렌더링, 클릭 선택 | 대기 |
| PacketStateView | state diff 하이라이트 | 대기 |
| ImportForm | 텍스트 입력, 파싱 호출 | 대기 |

---

## 6. 테스트 실행 방법

```bash
# 전체 Rust 테스트
cargo test

# 특정 crate
cargo test -p netsim-core
cargo test -p netsim-parser
cargo test -p netsim-server

# 프론트엔드 테스트
cd frontend && npm test
```
