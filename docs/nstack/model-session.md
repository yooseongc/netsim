# Model: Session

세션(연결) 단위 시뮬레이션 모델. 단일 패킷이 아닌 관련 패킷 시퀀스를 시뮬레이션한다.

## 코드 참조

- `crates/netsim-core/src/model/session.rs` - 세션 정의 및 패킷 확장
- `crates/netsim-core/src/session_engine.rs` - 세션 시뮬레이션 실행

## SessionDef

```rust
pub struct SessionDef {
    pub session_type: SessionType,
}
```

## SessionType

| 타입 | 설명 | 생성되는 패킷 |
|------|------|--------------|
| `TcpHandshake` | TCP 3-way handshake | SYN, SYN-ACK, ACK + (DATA) + (FIN) |
| `IcmpEcho` | ICMP ping | Echo Request, Echo Reply |
| `UdpExchange` | UDP 요청/응답 | Request, Reply |
| `Custom` | 사용자 정의 | 사용자 지정 패킷 시퀀스 |

### TcpHandshake

```rust
TcpHandshake {
    client: SessionEndpoint,
    server: SessionEndpoint,
    include_data: bool,   // handshake 후 PSH/ACK 데이터 포함
    include_close: bool,  // FIN/FIN-ACK 종료 시퀀스 포함
}
```

패킷 시퀀스:
1. **TCP SYN** (client -> server, ct_state=New, flags: SYN)
2. **TCP SYN-ACK** (server -> client, ct_state=Established, flags: SYN+ACK)
3. **TCP ACK** (client -> server, ct_state=Established, flags: ACK)
4. **(opt) TCP DATA** (client -> server, PSH+ACK)
5. **(opt) TCP DATA** (server -> client, PSH+ACK)
6. **(opt) TCP FIN** (client -> server, FIN+ACK)
7. **(opt) TCP FIN-ACK** (server -> client, FIN+ACK)

### IcmpEcho

```rust
IcmpEcho {
    source: SessionEndpoint,
    destination: SessionEndpoint,
    ipv6: bool,  // ICMPv6 여부
}
```

- IPv4: type 8 (echo request) -> type 0 (echo reply)
- IPv6: type 128 (echo request) -> type 129 (echo reply)

### UdpExchange

```rust
UdpExchange {
    client: SessionEndpoint,
    server: SessionEndpoint,
}
```

- UDP Request (ct_state=New) -> UDP Reply (ct_state=Established)

## SessionEndpoint

```rust
pub struct SessionEndpoint {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub interface: String,
    pub mac: Option<String>,
}
```

## NAT Propagation (세션 엔진)

`session_engine::run_session()`에서 NAT 매핑이 세션 내에서 전파된다.

### 동작 순서

1. 첫 번째 패킷(forward direction) 시뮬레이션
2. 결과에서 NAT 매핑 추출 (`extract_nat_mapping`)
   - `dnat_applied`이면 DNAT 매핑 (original_dst -> translated_dst)
   - `snat_applied`이면 SNAT 매핑 (original_src -> translated_src)
3. 이후 reply 패킷에 NAT 역변환 적용 (`apply_to_reply`)

### NAT 역변환 규칙

Forward: `client(A:a) -> server(B:b)`, DNAT `B->B'`, SNAT `A->A'`
Reply: `server(B':b') -> client(A':a')`

- DNAT 역변환: reply의 `src_ip`가 original dst(B)이면 translated dst(B')로 변경
- SNAT 역변환: reply의 `dst_ip`가 original src(A)이면 translated src(A')로 변경

## SessionResult

```rust
pub struct SessionResult {
    pub packet_results: Vec<PacketSimResult>,
    pub session_verdict: SessionVerdict,
}

pub enum SessionVerdict {
    Established,              // 모든 패킷 성공
    Failed { failed_at, reason }, // 특정 패킷에서 실패
    Partial { passed, total },    // 부분 성공
}
```

### Terminal Verdict

패킷이 `Drop`, `Rejected`, `Blackhole` 중 하나이면 세션 즉시 중단.

## Trace 출력 예시

```json
{
  "session_verdict": "established",
  "packet_results": [
    { "label": "TCP SYN", "result": { "verdict": "forwarded", ... } },
    { "label": "TCP SYN-ACK", "result": { "verdict": "forwarded", ... } },
    { "label": "TCP ACK", "result": { "verdict": "forwarded", ... } }
  ]
}
```
