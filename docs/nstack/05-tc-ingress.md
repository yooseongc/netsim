# 05. tc ingress

Traffic Control ingress 단계. 현재 MVP 구현으로 pass-through.

## 코드 참조

- `crates/netsim-core/src/pipeline/tc_ingress.rs` - `execute()`

## 동작

현재는 항상 `Continue`를 반환하는 pass-through 구현이다.
향후 tc-bpf, cls_act 등의 시뮬레이션이 추가될 수 있다.

## sysctl 의존성

없음.

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `Continue` | 항상 |

## Trace 출력 예시

```json
{
  "stage": "tc_ingress",
  "description": "TC_INGRESS",
  "decision": { "type": "continue" },
  "explain": "tc ingress on eth0 -- pass-through (MVP)"
}
```
