# Model: Packet

패킷 정의(PacketDef)와 파이프라인 처리 중 가변 상태(PacketState)를 정의한다.

## 코드 참조

- `crates/netsim-core/src/model/packet.rs`

## PacketDef

시나리오에서 사용자가 정의하는 패킷 초기 상태.

| 필드 | 타입 | 기본값 | 설명 |
|------|------|--------|------|
| `ingress_interface` | `String` | (필수) | 수신 인터페이스 이름 |
| `ethertype` | `EtherType` | `Ipv4` | L2 프로토콜 |
| `vlan_id` | `Option<u16>` | None | 802.1Q VLAN ID |
| `src_mac` / `dst_mac` | `Option<String>` | None | MAC 주소 |
| `src_ip` / `dst_ip` | `Option<IpAddr>` | None | IP 주소 (L2-only에서는 생략 가능) |
| `protocol` | `IpProtocol` | `Tcp` | IP 프로토콜 |
| `src_port` / `dst_port` | `Option<u16>` | None | TCP/UDP/SCTP 포트 |
| `tcp_flags` | `Option<TcpFlags>` | None | TCP 플래그 (syn, ack, fin, rst, psh, urg) |
| `icmp_type` / `icmp_code` | `Option<u8>` | None | ICMP/ICMPv6 type, code |
| `arp` | `Option<ArpFields>` | None | ARP 패킷 필드 (operation, sender/target) |
| `packet_length` | `Option<u32>` | None | 패킷 전체 길이 (bytes) |
| `df_flag` | `bool` | `false` | Don't Fragment 플래그 |
| `dscp` | `Option<u8>` | None | Differentiated Services Code Point |
| `ttl` | `Option<u8>` | None | Time To Live (기본 64) |
| `initial_mark` | `u32` | `0` | 초기 패킷 mark |
| `initial_ct_mark` | `u32` | `0` | 초기 conntrack mark |
| `conntrack_state` | `ConntrackState` | `New` | 사용자 선언 conntrack 상태 |

## PacketState

파이프라인 통과 중 변경되는 가변 상태. `PacketDef::from_packet_def()`으로 초기화된다.

PacketDef의 필드에 추가로:

| 필드 | 타입 | 초기값 | 설명 |
|------|------|--------|------|
| `mark` | `u32` | `initial_mark` | 현재 패킷 mark (SetMark로 변경) |
| `ct_mark` | `u32` | `initial_ct_mark` | Conntrack mark |
| `ct_state` | `ConntrackState` | `conntrack_state` | 현재 conntrack 상태 |
| `ingress_if` | `String` | `ingress_interface` | 수신 인터페이스 |
| `egress_if` | `Option<String>` | `None` | 송신 인터페이스 (routing에서 설정) |
| `ttl` | `u8` | `ttl.unwrap_or(64)` | 현재 TTL |
| `dscp` | `u8` | `dscp.unwrap_or(0)` | 현재 DSCP |
| `dnat_applied` | `bool` | `false` | DNAT 적용 여부 |
| `snat_applied` | `bool` | `false` | SNAT 적용 여부 |
| `tproxy_applied` | `bool` | `false` | TPROXY 적용 여부 |
| `original_dst_ip` | `Option<IpAddr>` | `None` | DNAT 이전 원본 dst |
| `original_dst_port` | `Option<u16>` | `None` | DNAT 이전 원본 dst port |
| `original_src_ip` | `Option<IpAddr>` | `None` | SNAT 이전 원본 src |
| `original_src_port` | `Option<u16>` | `None` | SNAT 이전 원본 src port |

## EtherType

| 값 | 설명 | `is_l2_only()` |
|----|------|----------------|
| `Ipv4` | IPv4 (기본) | false |
| `Ipv6` | IPv6 | false |
| `Arp` | ARP | true |
| `Vlan` | 802.1Q | false |
| `Stp` | Spanning Tree | true |
| `Lldp` | LLDP | true |
| `Other(u16)` | 기타 | false |

L2-only 패킷(ARP, STP, LLDP)은 XDP 이후 netfilter/routing을 건너뛰고 바로 LOCAL_DELIVERY.

## IpProtocol

| 값 | 번호 | `has_ports()` | `is_icmp()` |
|----|------|---------------|-------------|
| `Tcp` | 6 | true | false |
| `Udp` | 17 | true | false |
| `Sctp` | 132 | true | false |
| `Icmp` | 1 | false | true |
| `Icmpv6` | 58 | false | true |
| `Vrrp` | 112 | false | false |
| `Ospf` | 89 | false | false |
| `Gre` | 47 | false | false |
| `Esp` | 50 | false | false |
| `Ah` | 51 | false | false |
| `Other(u8)` | n | false | false |

## TcpFlags

```rust
pub struct TcpFlags {
    pub syn: bool,   // default: false
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}
```

## ArpFields

```rust
pub struct ArpFields {
    pub operation: u16,          // 1=request, 2=reply
    pub sender_mac: Option<String>,
    pub sender_ip: Option<IpAddr>,
    pub target_mac: Option<String>,
    pub target_ip: Option<IpAddr>,
}
```
