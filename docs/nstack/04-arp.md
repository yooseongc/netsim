# 04. ARP Processing

ARP 패킷에 대한 `arp_ignore` 검사. XDP 이후, L2 bypass 이전에 실행된다.

## 코드 참조

- `crates/netsim-core/src/pipeline/stages/arp.rs` - `process_arp()`

## 동작

1. `ethertype`이 ARP가 아니면 즉시 Continue
2. ingress 인터페이스의 `arp_ignore` 값 확인 (InterfaceSysctl)
3. `arp_ignore < 1`이면 Continue (기본 동작: 모든 로컬 IP에 대해 ARP 응답)

### arp_ignore >= 1

- ARP 요청의 `target_ip`가 ingress 인터페이스에 설정된 주소인지 확인
- 설정되지 않은 IP면 DROP

### arp_ignore >= 2

- 위 조건에 더해, ARP 요청의 `sender_ip`가 ingress 인터페이스의 주소와 같은 서브넷인지 확인
- 같은 서브넷이 아니면 DROP

## sysctl 의존성

| sysctl | 값 | 영향 |
|--------|---|------|
| `conf.{iface}.arp_ignore` | 0 | 모든 로컬 IP에 대해 ARP 응답 (기본) |
| `conf.{iface}.arp_ignore` | 1 | 수신 인터페이스에 설정된 IP만 응답 |
| `conf.{iface}.arp_ignore` | 2 | 위 + sender가 같은 서브넷일 때만 응답 |

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `Continue` | ARP가 아님, 또는 arp_ignore 조건 통과 |
| `Drop` | arp_ignore 조건 불일치 |

## Trace 출력 예시

```json
{
  "stage": "arp_process",
  "description": "arp_ignore check",
  "decision": { "type": "drop", "reason": "ARP reply suppressed by arp_ignore=1" },
  "explain": "arp_ignore=1: ARP target IP 10.0.0.100 is not configured on ingress interface 'eth1' -- ARP reply suppressed"
}
```
