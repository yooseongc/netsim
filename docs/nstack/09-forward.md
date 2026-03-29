# 09. Forward (FORWARD chains)

포워딩 대상 패킷에 대해 TTL 감소 및 netfilter FORWARD hook 체인 평가.

## 코드 참조

- `crates/netsim-core/src/pipeline/forward.rs` - `execute()`
- `crates/netsim-core/src/pipeline/stages/sysctl_checks.rs` - `check_ip_forward()`, `check_egress_interface()`

## 동작

### FORWARD 이전 검사

1. **Egress Interface Check** (`check_egress_interface`):
   - egress 인터페이스가 존재하는지, UP 상태인지 확인
   - 미존재 또는 DOWN이면 DROP

2. **ip_forward Check** (`check_ip_forward`):
   - `is_forwarding_enabled()`: 인터페이스별 `forwarding` 설정 우선, 없으면 전역 `ip_forward`
   - 비활성화이면 DROP

### TTL 처리

- L2-only가 아닌 IP 패킷에 대해 TTL을 1 감소
- TTL이 0이 되면 DROP (실제로는 ICMP Time Exceeded 전송)
- `state.ttl = state.ttl.saturating_sub(1)`

### FORWARD 체인 평가

- TTL 검사 통과 후 netfilter FORWARD hook의 모든 체인 평가
- iptables filter table FORWARD (priority 0) 등

## sysctl 의존성

| sysctl | 영향 |
|--------|------|
| `ipv4.ip_forward` | 전역 IP 포워딩 활성화 (기본: true) |
| `conf.{iface}.forwarding` | 인터페이스별 포워딩 오버라이드 (None이면 전역 사용) |

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `Continue` | TTL > 0, 모든 FORWARD 체인 통과 |
| `Drop` | ip_forward 비활성화 |
| `Drop` | egress 인터페이스 미존재/DOWN |
| `Drop` | TTL expired (TTL=0) |
| `Drop` | FORWARD 체인에서 DROP |
| `Rejected` | FORWARD 체인에서 REJECT |

## Trace 출력 예시

```json
{
  "stage": "forward",
  "description": "FORWARD",
  "decision": { "type": "continue" },
  "explain": "Passed through iptables filter/FORWARD (policy: Some(Accept))",
  "state_changes": [
    { "field": "ttl", "from": "64", "to": "63" }
  ]
}
```

```json
{
  "stage": "forward",
  "description": "ip_forward disabled",
  "decision": { "type": "drop", "reason": "IP forwarding disabled" },
  "explain": "net.ipv4.ip_forward=0 -- packet requires forwarding but forwarding is disabled on eth0"
}
```
