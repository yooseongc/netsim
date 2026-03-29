# 08. Local Input (INPUT chains)

로컬 전달로 결정된 패킷에 대해 netfilter INPUT hook의 체인을 평가하는 단계.

## 코드 참조

- `crates/netsim-core/src/pipeline/local_input.rs` - `execute()`
- `crates/netsim-core/src/pipeline/chain_eval.rs` - `evaluate_netfilter_hook()`

## 동작

1. Routing Decision에서 `LocalDelivery`로 판정된 패킷에 대해 실행
2. INPUT hook에 해당하는 모든 체인을 priority 오름차순으로 평가
3. iptables filter table INPUT (priority 0) 등이 여기서 평가됨

### INPUT 이전: icmp_echo_ignore_all 검사

- `icmp_echo_ignore_all=1`이고 ICMP Echo Request이면 즉시 DROP
- IPv4: icmp_type=8, IPv6: icmp_type=128

## sysctl 의존성

| sysctl | 영향 |
|--------|------|
| `ipv4.icmp_echo_ignore_all` | ICMP echo request 전체 무시 |

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `LocalDelivery` | 모든 INPUT 체인 통과 |
| `Drop` | INPUT 체인에서 DROP/chain policy DROP |
| `Rejected` | INPUT 체인에서 REJECT |
| `Drop` | icmp_echo_ignore_all로 ICMP echo 차단 |

## Trace 출력 예시

```json
{
  "stage": "local_input",
  "description": "INPUT",
  "decision": { "type": "continue" },
  "explain": "Accepted by iptables filter/INPUT; Passed through nftables inet/fw/input (policy: Some(Accept))"
}
```

```json
{
  "stage": "local_input",
  "description": "icmp_echo_ignore_all",
  "decision": { "type": "drop", "reason": "ICMP echo ignored by icmp_echo_ignore_all=1" },
  "explain": "net.ipv4.icmp_echo_ignore_all=1 -- all ICMP echo requests silently dropped"
}
```
