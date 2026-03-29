# 10. POSTROUTING

Netfilter POSTROUTING hook. SNAT/MASQUERADE 처리가 이 단계에서 수행된다.

## 코드 참조

- `crates/netsim-core/src/pipeline/postrouting.rs` - `execute()`
- `crates/netsim-core/src/pipeline/nat.rs` - `apply_nat()` (SNAT, Masquerade 처리)

## 동작

1. POSTROUTING hook에 등록된 모든 체인을 priority 오름차순으로 평가
2. iptables nat table POSTROUTING (priority 100) 등이 여기서 평가됨
3. SNAT/MASQUERADE NAT 액션이 매칭되면 `src_ip`/`src_port` 변경

### SNAT 동작

- `original_src_ip`/`original_src_port`를 저장 (첫 SNAT 적용 시)
- 지정된 `addr`/`port`로 src 변경
- `snat_applied = true`

### Masquerade 동작

- SNAT의 변형: egress 인터페이스의 IP를 자동으로 SNAT 주소로 사용
- `find_interface_ip(interfaces, egress_name, src_ip)`: 패킷의 주소 체계에 맞는 IP 선택
- ICMP 패킷: src_ip만 변경 (포트 없음)

## sysctl 의존성

없음.

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `Continue` | 모든 체인 통과 (NAT 적용 포함) |
| `Drop` | POSTROUTING 체인에서 DROP |
| `Rejected` | POSTROUTING 체인에서 REJECT |

## Conntrack Confirm

POSTROUTING 이후, MTU 검사 이후에 conntrack confirm이 기록된다.
이는 conntrack entry가 확정되었음을 나타낸다.

## Trace 출력 예시

```json
{
  "stage": "postrouting",
  "description": "POSTROUTING",
  "decision": { "type": "continue" },
  "explain": "Accepted by iptables nat/POSTROUTING",
  "state_changes": [
    { "field": "src_ip", "from": "Some(10.0.0.5)", "to": "Some(203.0.113.1)" },
    { "field": "snat_applied", "from": "false", "to": "true" }
  ]
}
```
