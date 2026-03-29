# 07. Routing Decision

IP 라우팅 결정 단계. Policy routing (ip rule) + routing table lookup을 수행한다.

## 코드 참조

- `crates/netsim-core/src/pipeline/routing.rs` - `execute()`, `reverse_path_lookup()`
- `crates/netsim-core/src/engine.rs` - Routing Decision 섹션

## 동작

### Routing 이전 검사

1. **rp_filter** (Reverse Path Filtering): `sysctl_checks::check_rp_filter()`
   - Strict (1): 역경로의 egress가 ingress와 동일해야 함
   - Loose (2): 역경로가 존재하기만 하면 통과
2. **TPROXY Override**: `tproxy_applied=true`이면 routing_result를 `Local`로 강제
3. **route_localnet**: dst가 127.x이고 `route_localnet=0`이면 DROP

### Routing 결정

1. dst_ip가 로컬 인터페이스 주소이면 즉시 `LocalDelivery`
2. `ip_rules`를 priority 오름차순으로 순회
3. 규칙의 selector가 패킷에 매칭되면 action 실행:
   - `Lookup(table_id)`: 해당 라우팅 테이블에서 longest prefix match
   - `Blackhole` / `Unreachable` / `Prohibit`: 즉시 DROP
4. 라우팅 테이블 내 매칭 경로의 `route_type`에 따라 결정:
   - `Local` / `Broadcast` -> LocalDelivery
   - `Unicast` -> ForwardTo (egress_if, next_hop 설정)
   - `Blackhole` / `Unreachable` / `Prohibit` -> DROP
   - `Throw` -> 다음 ip rule로 이동

### Selector 매칭 조건

- `from`: src_ip가 CIDR 범위 내
- `to`: dst_ip가 CIDR 범위 내
- `fwmark`: `(packet_mark & mask) == fwmark`
- `iif`: ingress 인터페이스 이름 일치
- `oif`: egress 인터페이스 이름 일치
- `ipproto`: IP 프로토콜 번호 일치
- `sport` / `dport`: 포트 범위 내

### Reroute 감지

- PREROUTING에서 mark 또는 dst_ip가 변경되고 fwmark 기반 policy rule이 존재하면
  `PipelineStage::Reroute`로 기록
- 실제 재라우팅은 별도 수행하지 않음 (routing이 이미 변경된 상태를 반영)

## sysctl 의존성

| sysctl | 영향 |
|--------|------|
| `conf.{iface}.rp_filter` | Reverse Path Filter 모드 (Off/Strict/Loose) |
| `conf.{iface}.route_localnet` | 127.0.0.0/8 대상 라우팅 허용 |

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `LocalDelivery` | dst가 로컬 주소, local/broadcast route |
| `ForwardTo` | unicast route 매칭 |
| `Drop` | blackhole/unreachable/prohibit, rp_filter 실패, 경로 없음 |

## Trace 출력 예시

```json
{
  "stage": "routing_decision",
  "decision": { "type": "forward_to", "egress_if": "eth1", "next_hop": "10.0.0.1" },
  "explain": "Route 0.0.0.0/0 via 10.0.0.1 dev eth1 in table main"
}
```

```json
{
  "stage": "reroute",
  "description": "mark/dst change detected after PREROUTING",
  "decision": { "type": "continue" },
  "explain": "PREROUTING changed mark (0x0->0x100) or dst. fwmark-based policy routing rules exist; routing decision reflects the updated state."
}
```
