# netsim API 명세

## 1. 개요

모든 API 엔드포인트는 `/api/v1` prefix를 사용한다.
Content-Type: `application/json` (별도 명시가 없는 한).
비-`/api` 경로는 프론트엔드 SPA 정적 파일을 서빙한다 (index.html fallback).

---

## 2. 프로젝트 관리

### GET /api/v1/projects

프로젝트 목록 조회.

**Response 200:**
```json
{
  "projects": [
    {
      "name": "my-project",
      "description": "Basic NAT scenario",
      "created_at": "2026-03-29T10:00:00Z",
      "updated_at": "2026-03-29T12:00:00Z"
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
  "description": "Basic NAT scenario"
}
```

**Response 201:**
```json
{
  "name": "my-project",
  "description": "Basic NAT scenario",
  "created_at": "2026-03-29T10:00:00Z",
  "updated_at": "2026-03-29T10:00:00Z"
}
```

**Error 409:** 동일 이름 프로젝트 존재 시.

### GET /api/v1/projects/:name

프로젝트 상세 조회 (메타데이터 + 시나리오 포함 여부).

**Response 200:**
```json
{
  "name": "my-project",
  "description": "Basic NAT scenario",
  "created_at": "2026-03-29T10:00:00Z",
  "updated_at": "2026-03-29T12:00:00Z",
  "has_scenario": true,
  "has_imported_config": false
}
```

### PUT /api/v1/projects/:name

프로젝트 메타데이터 수정.

**Request:**
```json
{
  "description": "Updated description"
}
```

**Response 200:** 수정된 프로젝트 정보.

### DELETE /api/v1/projects/:name

프로젝트 삭제 (디렉토리 및 모든 파일 포함).

**Response 204:** No Content.

### POST /api/v1/projects/:name/clone

프로젝트 복제.

**Request:**
```json
{
  "new_name": "my-project-copy"
}
```

**Response 201:** 복제된 프로젝트 정보.

---

## 3. 시나리오

### GET /api/v1/projects/:name/scenario

시나리오 조회.

**Query Parameters:**
- `format`: `json` (기본) 또는 `yaml`

**Response 200:**
```json
{
  "version": "1.0",
  "name": "my-project",
  "interfaces": [...],
  "routing_tables": [...],
  "ip_rules": [...],
  "netfilter": {...},
  "xdp": {...},
  "packet": {...}
}
```

**Error 404:** 시나리오 미존재 시.

### PUT /api/v1/projects/:name/scenario

시나리오 저장/수정.

**Request:** Scenario 객체 (JSON).

**Response 200:** 저장된 시나리오.

### POST /api/v1/projects/:name/scenario/validate

시나리오 검증 (시뮬레이션 실행 없이).

**Request:** Scenario 객체 (JSON).

**Response 200:**
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "Interface eth2 is defined but not referenced in any route"
  ]
}
```

---

## 4. 시뮬레이션

### POST /api/v1/projects/:name/simulate

시뮬레이션 실행.

**Request (선택적):**
```json
{
  "scenario_override": null
}
```

`scenario_override`가 null이면 저장된 시나리오 사용. 값이 있으면 해당 시나리오로 실행.

**Response 200:**
```json
{
  "simulation_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "result": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
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
    "created_at": "2026-03-29T12:30:00Z"
  }
}
```

MVP에서는 동기 실행이므로 status는 항상 `"completed"` 또는 `"error"`.

### GET /api/v1/simulations/:id

시뮬레이션 결과 조회.

**Response 200:** 위와 동일한 result 객체.

### GET /api/v1/simulations/:id/trace

전체 trace 조회.

**Response 200:**
```json
{
  "trace": [
    {
      "seq": 1,
      "stage": "xdp",
      "description": "XDP program on eth0",
      "state_before": {...},
      "state_after": {...},
      "state_changes": [],
      "matched_rules": [],
      "decision": { "type": "continue" },
      "explain": "No XDP program attached to eth0, packet passes through."
    },
    {
      "seq": 2,
      "stage": "prerouting",
      "description": "PREROUTING chain evaluation",
      "state_before": {...},
      "state_after": {
        "dst_ip": "10.0.0.100",
        "dst_port": 8080
      },
      "state_changes": [
        { "field": "dst_ip", "from": "10.0.0.1", "to": "10.0.0.100" },
        { "field": "dst_port", "from": "80", "to": "8080" }
      ],
      "matched_rules": [
        {
          "source": "nftables",
          "table": "nat",
          "chain": "prerouting",
          "rule_index": 0,
          "rule_summary": "dnat to 10.0.0.100:8080"
        }
      ],
      "decision": { "type": "continue" },
      "explain": "DNAT rule matched: redirecting traffic to backend server 10.0.0.100:8080"
    }
  ]
}
```

---

## 5. Import

### POST /api/v1/import/parse

시스템 설정 텍스트를 파싱하여 IR로 변환.

**Request:**
```json
{
  "ip_addr": "1: lo: <LOOPBACK,UP,LOWER_UP> ...",
  "ip_rule": "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default",
  "ip_route": "default via 10.0.0.1 dev eth0\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.2",
  "nft_list_ruleset": "table ip filter {\n  chain input {\n    type filter hook input priority 0; policy accept;\n  }\n}",
  "iptables_save": null
}
```

모든 필드는 선택적 (부분 import 지원).

**Response 200:**
```json
{
  "scenario": {
    "interfaces": [...],
    "routing_tables": [...],
    "ip_rules": [...],
    "netfilter": {...}
  },
  "validation": {
    "parsed_ok": [
      "interfaces: 3 parsed",
      "ip_rules: 3 parsed",
      "routes: 5 parsed"
    ],
    "partial": [
      "nftables: chain 'raw' rule 3 has unsupported expression 'ct helper'"
    ],
    "unsupported": [
      "ip6tables rules skipped"
    ]
  }
}
```

### POST /api/v1/import/preview

parse와 동일하지만 검증 리포트를 더 상세하게 반환.

### POST /api/v1/projects/:name/import

파싱 결과를 프로젝트에 적용 (시나리오에 병합).

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

`merge_strategy`: `"replace"` (기존 설정 대체) 또는 `"merge"` (기존 + import 병합).

**Response 200:** 적용된 시나리오 + validation report.

---

## 6. Health

### GET /api/v1/health

**Response 200:**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

---

## 7. 공통 에러 형식

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Project 'unknown' not found"
  }
}
```

HTTP 상태 코드:
- 400: 잘못된 요청 (검증 실패)
- 404: 리소스 미존재
- 409: 충돌 (중복 이름)
- 500: 내부 서버 에러
