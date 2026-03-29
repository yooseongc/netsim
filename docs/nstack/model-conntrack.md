# Model: Conntrack

Connection Tracking 모델. 패킷의 연결 상태와 NAT 매핑 정보를 관리한다.

## 코드 참조

- `crates/netsim-core/src/model/conntrack.rs` - 데이터 모델
- `crates/netsim-core/src/engine.rs` - `apply_conntrack_nat_if_established()`, `store_nat_to_conntrack()`
- `crates/netsim-core/src/pipeline/nat.rs` - NAT 적용 로직

## ConntrackState

| 상태 | 설명 |
|------|------|
| `New` | 새로운 연결의 첫 패킷 (기본값) |
| `Established` | 양방향 트래픽이 확인된 연결 |
| `Related` | 기존 연결과 관련된 새 연결 (예: FTP data) |
| `Invalid` | 유효하지 않은 상태의 패킷 |
| `Untracked` | conntrack 추적 제외 (raw table NOTRACK) |

시뮬레이션에서는 사용자가 `PacketDef.conntrack_state`로 직접 선언한다.

## ConntrackEntry

파이프라인 컨텍스트에 저장되는 conntrack entry.

```rust
pub struct ConntrackEntry {
    pub state: ConntrackState,
    pub nat_tuple: Option<NatTuple>,
}
```

## NatTuple

DNAT/SNAT 매핑 정보를 저장. Established 패킷에서 NAT 체인 재평가 없이 적용된다.

```rust
pub struct NatTuple {
    pub dnat: Option<DnatMapping>,
    pub snat: Option<SnatMapping>,
}

pub struct DnatMapping {
    pub original_dst_ip: IpAddr,
    pub original_dst_port: Option<u16>,
    pub translated_dst_ip: IpAddr,
    pub translated_dst_port: Option<u16>,
}

pub struct SnatMapping {
    pub original_src_ip: IpAddr,
    pub original_src_port: Option<u16>,
    pub translated_src_ip: IpAddr,
    pub translated_src_port: Option<u16>,
}
```

## NAT 1-time Rule

Linux 커널의 conntrack NAT 동작을 시뮬레이션:

1. **New 패킷**: NAT 체인을 정상 평가, NAT 적용 후 `store_nat_to_conntrack()`으로 NatTuple 저장
2. **Established/Related 패킷**: `apply_conntrack_nat_if_established()`에서 저장된 NatTuple을 직접 적용, NAT 체인 평가 건너뜀

이 메커니즘은 세션 시뮬레이션(`session_engine`)에서 중요하다: 첫 패킷(SYN)에서 DNAT이 적용되면, 이후 패킷(SYN-ACK, ACK)은 conntrack tuple에서 NAT 매핑을 가져온다.

## NatAction 종류

`crates/netsim-core/src/model/nat.rs`에 정의:

| Action | 설명 | 변경 필드 |
|--------|------|-----------|
| `Dnat { addr, port }` | Destination NAT | dst_ip, dst_port |
| `Snat { addr, port }` | Source NAT | src_ip, src_port |
| `Masquerade { port }` | SNAT (egress IF IP 사용) | src_ip, src_port |
| `Redirect { port }` | DNAT (ingress IF IP 사용) | dst_ip, dst_port |
| `Tproxy { addr, port, mark }` | Transparent Proxy | dst_ip, dst_port, mark, tproxy_applied |

### NAT 적용 시 동작

- 첫 NAT 적용 시 원본 주소를 `original_*` 필드에 저장
- ICMP 패킷(`has_ports()=false`)에서는 포트 변경하지 않음
- TPROXY는 `tproxy_applied=true`를 설정하여 routing override를 유발

## Trace 출력 예시

```json
{
  "stage": "prerouting",
  "description": "conntrack NAT tuple (established)",
  "decision": { "type": "continue" },
  "explain": "Applying conntrack NAT tuple for established/related connection -- skipping NAT chain evaluation."
}
```
