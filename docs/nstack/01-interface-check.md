# 01. Interface Check

Ingress 인터페이스 검증 단계. 패킷이 파이프라인에 진입하기 전 인터페이스의 존재 여부와 상태를 확인한다.

## 코드 참조

- `crates/netsim-core/src/pipeline/stages/interface_check.rs` - `check_ingress()`

## 동작

1. `ingress_interface` 이름으로 시나리오의 인터페이스 목록에서 검색
2. 인터페이스가 존재하지 않으면 즉시 DROP
3. 인터페이스 상태가 `Down`이면 즉시 DROP
4. Physical NIC인 경우, `packet_length`가 NIC의 수신 프레임 최대 크기를 초과하면 DROP
   - 최대 프레임 크기 = `max(MTU + 18, 9216)` (18 = L2 overhead, 9216 = jumbo frame 최소)

## sysctl 의존성

없음.

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `Continue` | 인터페이스 존재, UP 상태, 프레임 크기 정상 |
| `Drop` | 인터페이스 미존재 |
| `Drop` | 인터페이스 DOWN 상태 |
| `Drop` | Physical NIC에서 프레임 크기 초과 |

## Trace 출력 예시

```json
{
  "stage": "interface_check",
  "description": "ingress interface check",
  "decision": { "type": "drop", "reason": "Unknown ingress interface" },
  "explain": "Ingress interface 'eth99' does not exist in scenario interfaces"
}
```

```json
{
  "stage": "interface_check",
  "description": "physical NIC frame size check",
  "decision": { "type": "drop", "reason": "Frame too large for physical NIC (max=9216)" },
  "explain": "Packet length 10000 exceeds physical NIC 'eth0' max receive frame size 9216 (MTU=1500 + 18 L2 overhead, min 9216 jumbo). Physical NICs drop oversized frames at driver level."
}
```
