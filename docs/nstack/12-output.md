# 12. Output (OUTPUT 경로)

로컬 프로세스에서 발신하는 패킷의 처리 경로. `engine::run_output()`으로 실행된다.

## 코드 참조

- `crates/netsim-core/src/engine.rs` - `run_output()`

## 파이프라인

```
Local Process
  -> OUTPUT chains (raw -> conntrack -> mangle/filter/nat)
  -> Routing Decision (post-OUTPUT)
  -> POSTROUTING chains
  -> MTU Check
  -> Conntrack Confirm
  -> SENT
```

## 동작

### 1. OUTPUT chains

PREROUTING과 동일한 split 구조:

1. **RAW chains** (priority <= -200): conntrack 이전
2. **Conntrack lookup**: `ct_state` 기록
3. **Post-conntrack chains** (mangle, filter, nat): mark 설정, DNAT 등

### 2. Routing Decision (post-OUTPUT)

- 라우팅 수행: policy routing + routing table lookup
- **Loopback path**: dst가 로컬 주소이면
  - `LoopbackDelivery` 기록
  - INPUT 체인 실행
  - `LocalDelivery` 반환
- 경로 없음/blackhole -> DROP

### 3. Reroute 감지

- OUTPUT chains에서 mark가 변경되고 fwmark policy rule이 존재하면
  `PipelineStage::Reroute` 기록
- Linux에서는 초기 라우팅 후 mangle OUTPUT에서 mark 변경 시 커널이 재라우팅
- 시뮬레이터에서는 routing이 OUTPUT 이후에 실행되므로 이미 변경된 mark를 반영

### 4. POSTROUTING

- Ingress 경로와 동일한 POSTROUTING 체인 평가
- SNAT/MASQUERADE 적용

### 5. MTU Check

- `check_mtu_output()` 호출
- DF flag + MTU 초과 시 DROP

### 6. Conntrack Confirm

- Conntrack entry 확정 기록

## sysctl 의존성

OUTPUT 경로 자체에는 별도 sysctl 의존성 없음.
Loopback path의 INPUT 체인에서 `icmp_echo_ignore_all` 등이 영향을 줄 수 있다.

## 가능한 결과

| 결과 | 조건 |
|------|------|
| `Sent` | 모든 단계 통과, 패킷 전송 완료 |
| `LocalDelivery` | dst가 로컬 주소 (loopback path) |
| `Drop` | OUTPUT 체인 DROP, 경로 없음, MTU+DF 초과 |
| `Rejected` | OUTPUT 또는 INPUT 체인 REJECT |

## Trace 출력 예시

```json
{
  "stage": "output",
  "description": "OUTPUT",
  "decision": { "type": "continue" },
  "explain": "Passed through iptables filter/OUTPUT (policy: Some(Accept))"
}
```

```json
{
  "stage": "loopback_delivery",
  "description": "loopback delivery",
  "decision": { "type": "continue" },
  "explain": "Output packet destination is a local address -- packet enters loopback path (OUTPUT -> routing -> INPUT -> LOCAL_DELIVERY)."
}
```
