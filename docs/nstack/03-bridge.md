# 03. Bridge

브릿지 멤버 감지 및 L2 포워딩 단계. XDP 이후, L3 처리 이전에 실행된다.

## 코드 참조

- `crates/netsim-core/src/pipeline/stages/bridge.rs` - `check_bridge()`, `execute_bridge_nf_pipeline()`

## 동작

### 1단계: 브릿지 멤버 감지 (`check_bridge`)

1. ingress 인터페이스의 `master` 필드 확인
2. `master`가 있으면 브릿지 멤버로 판단
3. `bridge_nf_call_iptables=false`이면 L2 포워딩 (FORWARDED 반환)
4. `bridge_nf_call_iptables=true`이면 Bridge NF Pipeline 실행 후 IP 스택 계속

### 2단계: Bridge NF Pipeline (`execute_bridge_nf_pipeline`)

`bridge_nf_call_iptables=true`일 때 실행:

1. **BrNf PREROUTING**: PREROUTING hook의 모든 체인 평가
2. **Bridge Forwarding Decision**: 다른 브릿지 멤버 포트로 포워딩 결정 (간소화)
3. **BrNf FORWARD**: FORWARD hook의 모든 체인 평가
4. **BrNf POSTROUTING**: POSTROUTING hook의 모든 체인 평가

각 단계에서 DROP/REJECT이 나오면 즉시 Terminal 반환.

## sysctl 의존성

| sysctl | 영향 |
|--------|------|
| `bridge_nf_call_iptables` | `true`: iptables/nftables 체인 통과, `false`: L2만 처리 |

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `Continue` | 브릿지 멤버가 아님, 또는 BrNf Pipeline 통과 |
| `Forwarded` | 브릿지 멤버 + `bridge_nf_call_iptables=false` |
| `Drop/Rejected` | BrNf Pipeline 체인에서 DROP/REJECT |

## Trace 출력 예시

```json
{
  "stage": "bridge_forward",
  "description": "bridge L2 forwarding",
  "decision": { "type": "continue" },
  "explain": "bridge_nf_call_iptables=0: packet forwarded at L2 by bridge 'br0' without passing through IP netfilter stack."
}
```
