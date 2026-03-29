# Model: Endpoint

시뮬레이션 참여자(엔드포인트), 트래픽 흐름, 토폴로지 모델.

## 코드 참조

- `crates/netsim-core/src/model/endpoint.rs` - 데이터 모델
- `crates/netsim-core/src/flow.rs` - TrafficFlow -> SimulationRun 확장

## EndpointRole

| 역할 | 설명 | 패킷 경로 |
|------|------|-----------|
| `LocalClient` | 시뮬레이션 호스트에서 외부로 발신 | OUTPUT -> routing -> POSTROUTING |
| `RemoteClient` | 외부에서 호스트로 수신 | Ingress -> PREROUTING -> routing -> INPUT |
| `LocalServer` | 호스트의 로컬 서비스 | 로컬 수신 -> OUTPUT 응답 |
| `RemoteServer` | 외부 서비스 (포워딩 대상) | - |
| `LocalProxy` | 일반 프록시 | DNAT -> INPUT -> app -> OUTPUT -> POSTROUTING |
| `LocalTProxy` | 투명 프록시 | TPROXY -> INPUT -> app -> OUTPUT -> original dst |

## Endpoint

```rust
pub struct Endpoint {
    pub role: EndpointRole,
    pub name: String,          // 참조용 이름
    pub ip: IpAddr,            // 엔드포인트 IP 주소
    pub port: Option<u16>,     // 포트 (TCP/UDP)
    pub interface: Option<String>, // 연결된 인터페이스
}
```

## TrafficFlow

엔드포인트 간 통신 경로를 정의.

```rust
pub struct TrafficFlow {
    pub name: String,              // 흐름 이름
    pub source: String,            // 소스 엔드포인트 이름
    pub destination: String,       // 대상 엔드포인트 이름
    pub protocol: Option<String>,  // tcp, udp, icmp
    pub description: Option<String>,
}
```

## Topology

```rust
pub struct Topology {
    pub endpoints: Vec<Endpoint>,
    pub flows: Vec<TrafficFlow>,
}
```

## Flow Expansion (`flow.rs`)

`expand_flow()`가 TrafficFlow를 구체적인 `SimulationRun`으로 변환한다.

```rust
pub enum SimulationRun {
    Ingress(PacketDef),  // engine::run() 사용
    Output(PacketDef),   // engine::run_output() 사용
}
```

### EndpointRole 조합별 변환

| Source | Destination | SimulationRun | 설명 |
|--------|------------|---------------|------|
| RemoteClient | LocalServer | Ingress | 외부 -> 로컬 |
| RemoteClient | LocalProxy | Ingress | 외부 -> 프록시 |
| RemoteClient | LocalTProxy | Ingress | 외부 -> 투명 프록시 |
| LocalClient | RemoteServer | Output | 로컬 -> 외부 |
| RemoteClient | RemoteServer | Ingress (forward) | 외부 -> 외부 (포워딩) |
| LocalProxy | RemoteServer | Output (proxy output) | 프록시 -> 외부 |
| LocalTProxy | RemoteServer | Output (proxy output) | 투명 프록시 -> 외부 |
| LocalServer | RemoteClient | Output (response) | 로컬 -> 외부 응답 |

### PacketDef 생성

- **Ingress**: `ingress_interface` = source의 interface, src/dst = source/dest의 IP/port
- **Output**: `ingress_interface` = source의 interface (없으면 "lo"), src/dst = source/dest의 IP/port
- protocol은 flow의 `protocol` 필드에서 파싱 (기본: TCP)
