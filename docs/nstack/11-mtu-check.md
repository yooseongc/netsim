# 11. MTU Check

Egress 인터페이스의 MTU를 기준으로 패킷 크기를 검사하는 단계.

## 코드 참조

- `crates/netsim-core/src/pipeline/stages/mtu_check.rs` - `check_mtu()`, `check_mtu_output()`

## 동작

1. `egress_if`가 설정되어 있고, 해당 인터페이스가 존재하면 MTU 확인
2. `packet_length`가 MTU를 초과하는 경우:
   - **DF flag=true**: DROP (실제로는 ICMP Fragmentation Needed, Type 3 Code 4 전송)
   - **DF flag=false**: Continue (fragmentation 발생 기록)
3. `packet_length`가 없으면 검사 건너뜀

Ingress 경로에서는 `check_mtu()`, Output 경로에서는 `check_mtu_output()`이 사용된다.
두 함수의 로직은 동일하고 explain 메시지만 다르다.

## sysctl 의존성

없음 (MTU는 인터페이스 속성).

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `Continue` | packet_length <= MTU, 또는 packet_length 미지정 |
| `Continue` | packet_length > MTU 이지만 DF=false (fragmentation) |
| `Drop` | packet_length > MTU 이고 DF=true |

## Trace 출력 예시

```json
{
  "stage": "mtu_check",
  "description": "MTU exceeded with DF flag",
  "decision": { "type": "drop", "reason": "Packet exceeds MTU and DF flag is set (ICMP Fragmentation Needed would be sent)" },
  "explain": "Packet length 1600 exceeds egress interface 'eth1' MTU 1500 and DF (Don't Fragment) flag is set. Kernel would send ICMP Fragmentation Needed (Type 3, Code 4) back to sender."
}
```

```json
{
  "stage": "mtu_check",
  "description": "MTU exceeded, fragmentation needed",
  "decision": { "type": "continue" },
  "explain": "Packet length 1600 exceeds egress interface 'eth1' MTU 1500. Packet would be fragmented before transmission."
}
```
