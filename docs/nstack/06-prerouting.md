# 06. PREROUTING

Netfilter PREROUTING hook. raw table, conntrack, mangle/nat/filter 처리를 포함한다.
DNAT, TPROXY, mark 설정이 이 단계에서 수행된다.

## 코드 참조

- `crates/netsim-core/src/engine.rs` - `run()` 내 PREROUTING 섹션
- `crates/netsim-core/src/pipeline/chain_eval.rs` - `evaluate_chains_subset()`
- `crates/netsim-core/src/pipeline/nat.rs` - `apply_nat()`

## 동작

### (a) RAW chains (priority <= -200)

- PREROUTING hook에 등록된 체인 중 priority <= -200인 것만 분리
- Conntrack 이전에 실행 (예: `-t raw -A PREROUTING`)
- NOTRACK 등 conntrack 우회에 사용
- iptables raw table 기본 priority: -300

### (b) Conntrack lookup

- 패킷의 `ct_state`를 기록 (사용자 선언 값)
- PipelineStage: `ConntrackIn`

### (b-1) Conntrack NAT 1-time (established/related)

- `ct_state`가 `Established` 또는 `Related`이고 conntrack entry에 `NatTuple`이 저장되어 있으면:
  - 저장된 DNAT/SNAT 매핑을 패킷에 적용
  - NAT 체인 평가를 건너뜀 (1-time rule)
- 이는 Linux 커널의 conntrack NAT 동작을 시뮬레이션: 첫 패킷에서만 NAT 규칙을 평가하고, 이후 패킷은 conntrack tuple을 사용

### (c) Post-conntrack chains (mangle, nat, filter)

- priority > -200인 체인 평가 (mangle: -150, nat: -100, filter: 0)
- DNAT, Redirect, Tproxy 등의 NAT 액션이 여기서 적용
- TPROXY가 적용되면 `tproxy_applied=true` 설정, 패킷은 계속 진행 (Stolen이 아님)

### NAT 저장

- NAT 체인 평가 후 DNAT/SNAT이 적용되었으면 conntrack entry에 `NatTuple` 저장
- 향후 established 패킷에서 재사용

## sysctl 의존성

없음 (rp_filter, route_localnet 검사는 별도 단계).

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `Continue` | 모든 체인 통과 |
| `Drop` | RAW 또는 post-conntrack 체인에서 DROP/chain policy DROP |
| `Rejected` | 체인에서 REJECT |
| `Tproxy` | TPROXY 또는 QUEUE (Stolen) |

## Trace 출력 예시

```json
{
  "stage": "prerouting_raw",
  "decision": { "type": "continue" },
  "explain": "Accepted by nftables raw/PREROUTING"
}
```

```json
{
  "stage": "conntrack_in",
  "description": "conntrack lookup",
  "decision": { "type": "continue" },
  "explain": "Conntrack lookup: packet classified as ct_state=new (user-declared)"
}
```

```json
{
  "stage": "prerouting",
  "decision": { "type": "continue" },
  "explain": "Accepted by iptables nat/PREROUTING",
  "state_changes": [
    { "field": "dst_ip", "from": "Some(203.0.113.1)", "to": "Some(10.0.0.10)" },
    { "field": "dnat_applied", "from": "false", "to": "true" }
  ]
}
```
