# netsim API 명세

## 1. 개요

모든 API 엔드포인트는 `/api/v1` prefix 하에 네스팅된다.
Content-Type: `application/json`.
비-`/api` 경로는 프론트엔드 SPA 정적 파일을 서빙한다 (`NETSIM_STATIC_DIR` 환경변수 설정 시).
index.html fallback으로 SPA 라우팅을 지원한다.

### 라우트 구성 (app.rs)

```
/api/v1
├── /health                        (GET)
├── /projects                      (GET, POST)
├── /projects/{name}               (GET, PUT, DELETE)
├── /projects/{name}/clone         (POST)
├── /projects/{name}/scenario      (GET, PUT)
├── /projects/{name}/scenario/validate (POST)
├── /projects/{name}/simulate      (POST)
├── /projects/{name}/import        (POST)
├── /simulations/{id}              (GET)
├── /simulations/{id}/trace        (GET)
├── /import/parse                  (POST)
├── /import/preview                (POST)
├── /samples                       (GET)
├── /samples/{name}                (GET)
└── /samples/{name}/simulate       (POST)
```

미들웨어: `CorsLayer::permissive()`, `TraceLayer`.

---

## 2. 프로젝트 관리

### GET /api/v1/projects

프로젝트 목록 조회. 이름순 정렬.

**Response 200:**
```json
{
  "projects": [
    {
      "name": "my-project",
      "description": "Basic NAT scenario",
      "created_at": "2026-03-29T10:00:00+00:00",
      "updated_at": "2026-03-29T12:00:00+00:00"
    }
  ]
}
```

### POST /api/v1/projects

프로젝트 생성.

**Request:**
```json
{
  "name": "my-project",
  "description": "Basic NAT scenario"   // optional
}
```

**Response 201:** `ProjectMeta` 객체.
```json
{
  "name": "my-project",
  "description": "Basic NAT scenario",
  "created_at": "2026-03-29T10:00:00+00:00",
  "updated_at": "2026-03-29T10:00:00+00:00"
}
```

**Error 409:** `{ "error": { "code": "CONFLICT", "message": "Project 'my-project' already exists" } }`

### GET /api/v1/projects/{name}

프로젝트 상세 조회. `ProjectDetailResponse` 반환.

**Response 200:**
```json
{
  "name": "my-project",
  "description": "Basic NAT scenario",
  "created_at": "2026-03-29T10:00:00+00:00",
  "updated_at": "2026-03-29T12:00:00+00:00",
  "has_scenario": true,
  "has_imported_config": false
}
```

> `has_imported_config`는 현재 항상 `false` (하드코딩).

**Error 404:** 프로젝트 미존재.

### PUT /api/v1/projects/{name}

프로젝트 메타데이터 수정.

**Request:**
```json
{
  "description": "Updated description"   // optional
}
```

**Response 200:** 수정된 `ProjectMeta` 객체. `updated_at` 갱신됨.

### DELETE /api/v1/projects/{name}

프로젝트 삭제 (디렉토리 및 모든 파일 포함).

**Response 204:** No Content (본문 없음).

**Error 404:** 프로젝트 미존재.

### POST /api/v1/projects/{name}/clone

프로젝트 복제. 디렉토리를 재귀적으로 복사하고 메타데이터를 갱신한다.

**Request:**
```json
{
  "new_name": "my-project-copy"
}
```

**Response 201:** 복제된 `ProjectMeta` 객체. `created_at`, `updated_at`이 현재 시각으로 설정.

**Error 404:** 원본 프로젝트 미존재.
**Error 409:** 대상 이름 프로젝트 이미 존재.

---

## 3. 시나리오

### GET /api/v1/projects/{name}/scenario

저장된 시나리오 조회.

**Response 200:** `Scenario` 객체 (JSON).
```json
{
  "version": "1.0",
  "name": "my-project",
  "description": null,
  "interfaces": [...],
  "routing_tables": [...],
  "ip_rules": [...],
  "netfilter": { "nftables": null, "iptables": null },
  "xdp": { "programs": [] },
  "sysctl": { "ipv4": {...}, "ipv6": {...}, "interface_conf": {}, ... },
  "packet": {...},
  "topology": null,
  "neighbors": [
    { "ip": "10.0.0.1", "mac": "02:00:0a:00:00:01", "interface": "eth0", "state": "permanent" }
  ],
  "bridge_fdb": [
    { "mac": "aa:bb:cc:dd:ee:ff", "port": "eth1", "is_static": true }
  ]
}
```

> `sysctl`과 `topology`는 Scenario에 포함된 선택적 필드.

**Error 404:** 시나리오 미존재 또는 프로젝트 미존재.

### PUT /api/v1/projects/{name}/scenario

시나리오 저장/수정. 프로젝트의 `updated_at` 타임스탬프도 갱신.

**Request:** `Scenario` 객체 (JSON).

**Response 200:** 저장된 `Scenario` 객체.

### POST /api/v1/projects/{name}/scenario/validate

시나리오 검증 (시뮬레이션 실행 없이).

**Request:** `Scenario` 객체 (JSON).

**Response 200:**
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "Interface 'eth2' is defined but not referenced in any route"
  ]
}
```

**검증 항목:**
- `interfaces`가 비어있으면 error
- `packet.ingress_interface`가 `interfaces`에 존재하지 않으면 error
- 라우트에서 참조되지 않고 ingress도 아닌 인터페이스가 있으면 warning

---

## 4. 시뮬레이션

### POST /api/v1/projects/{name}/simulate

시뮬레이션 실행. 동기식 — 즉시 결과 반환.

**Request (선택적):**
```json
{
  "scenario_override": null
}
```

- `scenario_override`가 `null` 또는 미제공: 저장된 시나리오 사용.
- `scenario_override`에 `Scenario` 객체 제공: 해당 시나리오로 실행 (저장된 시나리오 무시).

**Response 200:**
```json
{
  "simulation_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "result": { ... }
}
```

`result`는 `SimulationResult` 객체 (아래 참조).

**Error 404:** 프로젝트 미존재 또는 시나리오 미존재 (`scenario_override` 미제공 시).

### GET /api/v1/simulations/{id}

시뮬레이션 결과 조회. 캐시 우선, 미히트 시 전체 프로젝트 디렉토리 검색.

**Response 200:** `SimulationResult` 객체.

### GET /api/v1/simulations/{id}/trace

시뮬레이션 trace만 조회.

**Response 200:**
```json
{
  "trace": [ ... ]
}
```

### SimulationResult 구조

```json
{
  "id": "uuid",
  "verdict": "forwarded",
  "summary": {
    "verdict": "forwarded",
    "egress_interface": "eth1",
    "next_hop": "192.168.1.254",
    "matched_rules": [...],
    "nat_applied": true,
    "total_steps": 8
  },
  "trace": [...],
  "created_at": "2026-03-29T12:30:00+00:00"
}
```

### FinalVerdict (9 variants)

| 값 | serde 직렬화 | 설명 |
|----|-------------|------|
| Drop | `"drop"` | 패킷 드롭 |
| LocalDelivery | `"local_delivery"` | 로컬 프로세스 전달 |
| Forwarded | `"forwarded"` | 포워딩 완료 |
| Redirect | `"redirect"` | XDP REDIRECT |
| Tx | `"tx"` | XDP TX (ingress 인터페이스로 반사) |
| Rejected | `"rejected"` | REJECT (ICMP unreachable 응답) |
| Blackhole | `"blackhole"` | 블랙홀 라우트 |
| Tproxy | `"tproxy"` | TPROXY 로컬 전달 |
| Sent | `"sent"` | 로컬 발신 패킷 전송 완료 (OUTPUT 경로) |

### PipelineStage (22 variants)

| 값 | Display 출력 | 설명 |
|----|-------------|------|
| InterfaceCheck | INTERFACE_CHECK | 인터페이스 검증 (존재, 상태, 브릿지 멤버) |
| ArpProcess | ARP_PROCESS | ARP 처리 (arp_ignore) |
| L2Bypass | L2_BYPASS | L2-only 패킷 바이패스 (ARP, STP) |
| Xdp | XDP | XDP 프로그램 처리 |
| RpFilter | RP_FILTER | Reverse Path Filter (sysctl rp_filter) |
| TcIngress | TC_INGRESS | tc ingress (현재 pass-through) |
| ConntrackIn | CONNTRACK_IN | conntrack lookup |
| PreRoutingRaw | PREROUTING_RAW | PREROUTING RAW 테이블 (conntrack 이전) |
| PreRouting | PREROUTING | PREROUTING 체인 (mangle/nat) |
| RoutingDecision | ROUTING | 라우팅 결정 |
| LocalInput | INPUT | INPUT 체인 |
| Forward | FORWARD | FORWARD 체인 |
| PostRouting | POSTROUTING | POSTROUTING 체인 |
| MtuCheck | MTU_CHECK | MTU 검사 |
| ConntrackConfirm | CONNTRACK_CONFIRM | conntrack confirm |
| BridgeForward | BRIDGE_FORWARD | Bridge L2 포워딩 |
| Output | OUTPUT | OUTPUT 체인 (로컬 발신) |
| Reroute | REROUTE | 라우팅 재평가 (mark/DNAT 변경) |
| BrNfPrerouting | BR_NF_PREROUTING | Bridge NF PREROUTING |
| BrNfForward | BR_NF_FORWARD | Bridge NF FORWARD |
| BrNfPostrouting | BR_NF_POSTROUTING | Bridge NF POSTROUTING |
| LoopbackDelivery | LOOPBACK_DELIVERY | Loopback delivery (output to local) |

### StageDecision (tagged union, `#[serde(tag = "type")]`)

| type 값 | 필드 | 설명 |
|---------|------|------|
| `"continue"` | (없음) | 다음 단계로 계속 |
| `"drop"` | `reason: String` | 패킷 드롭 |
| `"reject"` | `reason: String` | 패킷 거부 (ICMP unreachable) |
| `"accept"` | (없음) | 체인에서 ACCEPT |
| `"stolen"` | (없음) | 패킷 가로챔 (QUEUE/TPROXY) |
| `"redirect"` | `target: String` | 리다이렉트 대상 |
| `"local_delivery"` | (없음) | 로컬 전달 |
| `"forward_to"` | `egress_if: String`, `next_hop: Option<IpAddr>` | 포워딩 |

### TraceStep 구조

```json
{
  "seq": 1,
  "stage": "xdp",
  "description": "XDP",
  "state_before": { ... },
  "state_after": { ... },
  "state_changes": [
    { "field": "dst_ip", "from": "Some(10.0.0.1)", "to": "Some(192.168.1.100)" }
  ],
  "matched_rules": [
    {
      "source": "nftables",
      "table": "nat",
      "chain": "prerouting",
      "rule_index": 0,
      "rule_summary": "1 match(es) -> NAT(Dnat { addr: Some(...), port: Some(8080) })"
    }
  ],
  "decision": { "type": "continue" },
  "explain": "No XDP program attached, packet passes through."
}
```

---

## 5. Import

### POST /api/v1/import/parse

시스템 설정 텍스트를 파싱하여 부분 시나리오로 변환.

**Request:**
```json
{
  "ip_addr": "1: lo: <LOOPBACK,UP,LOWER_UP> ...",
  "ip_rule": "0:\tfrom all lookup local\n...",
  "ip_route": "default via 10.0.0.1 dev eth0\n...",
  "nft_list_ruleset": "table ip filter { ... }",
  "iptables_save": null
}
```

모든 필드는 선택적 (`Option<String>`).

**Response 200:**
```json
{
  "scenario": {
    "interfaces": [...],
    "routing_tables": [...],
    "ip_rules": [...],
    "netfilter": { "nftables": ..., "iptables": ... }
  },
  "validation": {
    "parsed_ok": ["interfaces: 3 parsed"],
    "partial": [],
    "unsupported": []
  }
}
```

### POST /api/v1/import/preview

`parse`와 동일한 동작. 현재 구현상 같은 로직.

### POST /api/v1/projects/{name}/import

파싱 결과를 프로젝트 시나리오에 적용.

**Request:**
```json
{
  "ip_addr": "...",
  "ip_rule": "...",
  "ip_route": "...",
  "nft_list_ruleset": "...",
  "iptables_save": "...",
  "merge_strategy": "replace"
}
```

- `merge_strategy`: `"replace"` (기본값, 새 시나리오 생성) 또는 `"merge"` (기존 시나리오에 병합).

**병합 전략 (`merge`):**
- 인터페이스: 같은 이름이면 교체, 새 이름이면 추가
- 라우팅 테이블: 같은 ID면 교체, 새 ID면 추가
- IP rules: 전체 교체
- netfilter: nftables/iptables 각각 있으면 교체

**교체 전략 (`replace`):**
- 파싱된 데이터로 새 시나리오 생성
- 기본 ingress interface: 파싱된 첫 번째 인터페이스 (없으면 "eth0")
- 기본 packet: 기본값으로 설정

**Response 200:**
```json
{
  "scenario": { ... },
  "validation": { ... }
}
```

---

## 6. Samples (내장)

바이너리에 내장된 샘플 시나리오. 파일시스템 저장 없이 메모리에서 직접 제공.

### GET /api/v1/samples

**Response 200:**
```json
{
  "samples": [
    { "name": "sample-basic-forward", "description": "Basic packet forwarding..." },
    { "name": "sample-dnat-port-forward", "description": "DNAT port forwarding..." }
  ]
}
```

### GET /api/v1/samples/{name}

샘플 시나리오 조회. 응답은 `Scenario` 객체.

**Response 200:** `Scenario` JSON.
**Error 404:** 샘플 미존재.

### POST /api/v1/samples/{name}/simulate

샘플 시나리오로 즉시 시뮬레이션 실행. Request body 불필요.

**Response 200:** `SimulationResult` JSON.
**Error 404:** 샘플 미존재.

### 내장 샘플 목록 (12개)

| 이름 | 설명 | 예상 Verdict |
|------|------|-------------|
| sample-basic-forward | 기본 패킷 포워딩 (ip_forward) | forwarded |
| sample-dnat-port-forward | DNAT :80→192.168.1.100:8080 | forwarded |
| sample-snat-masquerade | 내부→외부 마스커레이드 NAT | forwarded |
| sample-firewall-drop | nftables DROP (SSH만 허용) | drop |
| sample-icmp-ping | ICMP echo request 로컬 수신 | local_delivery |
| sample-policy-routing | fwmark 기반 정책 라우팅 | forwarded |
| sample-xdp-filter | XDP에서 특정 IP 차단 | drop |
| sample-bridge-forward | 브릿지 L2 포워딩 | forwarded |
| sample-local-delivery | TCP 로컬 주소 수신 | local_delivery |
| sample-ttl-exceeded | TTL=1 패킷 폐기 | drop |
| sample-mtu-exceeded | DF+4000B 패킷 MTU 초과 | drop |
| sample-tproxy | 투명 프록시 TPROXY | local_delivery |

---

## 7. Health

### GET /api/v1/health

**Response 200:**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

> `version`은 `CARGO_PKG_VERSION` 매크로로 컴파일 시 결정.

---

## 8. 정적 파일 서빙

환경변수 `NETSIM_STATIC_DIR`이 설정되면, 해당 디렉토리를 fallback 서비스로 마운트한다.
- `/api/v1/*` 이외의 모든 경로에서 정적 파일을 서빙
- 파일이 없으면 `index.html`로 fallback (SPA 라우팅 지원)

---

## 9. 공통 에러 형식

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Project 'unknown' not found"
  }
}
```

| HTTP Status | code | 발생 조건 |
|-------------|------|----------|
| 400 | BAD_REQUEST | 잘못된 요청 (검증 실패) |
| 404 | NOT_FOUND | 리소스 미존재 |
| 409 | CONFLICT | 충돌 (중복 이름) |
| 500 | INTERNAL_ERROR | 내부 서버 에러 |

---

## 10. 저장소 구조

```
{data_dir}/
├── {project-name}/
│   ├── project.yaml              # ProjectMeta (YAML)
│   ├── scenario.json             # Scenario (JSON)
│   └── simulations/
│       └── {uuid}.json           # SimulationResult (JSON)
```

> `data_dir`은 `AppState`에서 설정. 기본값은 `NETSIM_DATA_DIR` 환경변수 또는 `./data`.
