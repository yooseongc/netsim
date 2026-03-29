# 02. XDP (eXpress Data Path)

NIC 드라이버 레벨에서 동작하는 고성능 패킷 처리 단계. L2 레벨에서 동작하므로 ARP/STP 등 L2-only 패킷도 처리 대상이다.

## 코드 참조

- `crates/netsim-core/src/pipeline/xdp.rs` - `execute()`
- `crates/netsim-core/src/model/xdp.rs` - `XdpConfig`, `XdpProgram`, `XdpRule`, `XdpAction`

## 동작

1. `ingress_if`에 연결된 XDP 프로그램을 검색
2. 프로그램이 없으면 `XDP_PASS` (Continue)
3. 규칙을 순서대로 평가 (NfMatch 공유)
4. 첫 매칭 규칙의 action 적용
5. 매칭 규칙 없으면 `default_action` 적용

## XDP Action 종류

| Action | 결과 | 설명 |
|--------|------|------|
| `Pass` | Continue | 정상 네트워크 스택으로 전달 |
| `Drop` | Drop | 패킷 즉시 폐기 |
| `Tx` | Redirect(self) | 수신 인터페이스로 반송 |
| `Redirect { target_if }` | Redirect(target) | 다른 인터페이스로 전달 |
| `Aborted` | Drop | 에러 경로, 패킷 폐기 |

## XDP Mode

- `Generic` (기본값): 소프트웨어 XDP
- `Native`: 드라이버 레벨 XDP
- `Offload`: NIC 하드웨어 오프로드

## sysctl 의존성

없음. XDP는 커널 네트워크 스택 이전에 실행된다.

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `Continue` | XDP_PASS 또는 프로그램 없음 |
| `Drop` | XDP_DROP 또는 XDP_ABORTED |
| `FinalVerdict::Tx` | XDP_TX (Redirect target == ingress_if) |
| `FinalVerdict::Redirect` | XDP_REDIRECT (target != ingress_if) |

## Trace 출력 예시

```json
{
  "stage": "xdp",
  "decision": { "type": "drop", "reason": "XDP_DROP on interface eth0" },
  "explain": "XDP rule #0 on eth0 matched: XDP_DROP"
}
```
