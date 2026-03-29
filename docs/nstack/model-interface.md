# Model: Interface

네트워크 인터페이스 모델. 물리/가상 인터페이스, 브릿지, veth, VLAN 등을 정의한다.

## 코드 참조

- `crates/netsim-core/src/model/interface.rs`

## Interface 구조체

```rust
pub struct Interface {
    pub name: String,                    // 인터페이스 이름
    pub index: u32,                      // 인터페이스 인덱스
    pub mac: Option<String>,             // MAC 주소
    pub addresses: Vec<InterfaceAddress>, // IP 주소 목록
    pub mtu: u32,                        // MTU (기본: 1500)
    pub state: InterfaceState,           // Up/Down (기본: Up)
    pub kind: InterfaceKind,             // 인터페이스 종류

    // 가상 인터페이스 관계
    pub veth_peer: Option<String>,       // veth peer 이름
    pub bridge_members: Vec<String>,     // 브릿지 멤버 목록 (kind=Bridge)
    pub master: Option<String>,          // 소속 브릿지 이름
    pub vlan_parent: Option<String>,     // VLAN 부모 인터페이스
    pub vlan_id: Option<u16>,            // VLAN ID
    pub bond_members: Vec<String>,       // Bond 멤버 목록
}
```

## InterfaceKind

| 종류 | 설명 | 특수 필드 |
|------|------|-----------|
| `Loopback` | lo 인터페이스 | - |
| `Physical` | 물리 NIC (기본값) | NIC frame size 검사 대상 |
| `Veth` | Virtual Ethernet pair | `veth_peer` |
| `Bridge` | Linux bridge | `bridge_members` |
| `Vlan` | 802.1Q VLAN | `vlan_parent`, `vlan_id` |
| `Bond` | Bonding | `bond_members` |
| `Tun` | TUN 장치 | - |
| `Tap` | TAP 장치 | - |
| `Wireguard` | WireGuard VPN | - |
| `Other(String)` | 기타 | - |

## InterfaceAddress

```rust
pub struct InterfaceAddress {
    pub ip: IpAddr,          // IP 주소
    pub prefix_len: u8,      // 서브넷 프리픽스 길이
    pub scope: AddressScope,  // Global/Link/Host (기본: Global)
}
```

## InterfaceState

- `Up` (기본): 활성 상태, 패킷 수신/송신 가능
- `Down`: 비활성 상태, 패킷 수신 불가 (interface_check에서 DROP)

## 헬퍼 함수

| 함수 | 설명 |
|------|------|
| `find_interface(interfaces, name)` | 이름으로 인터페이스 검색 |
| `find_interface_ip(interfaces, name, family_hint)` | 주소 체계에 맞는 IP 반환 (Masquerade/Redirect에서 사용) |
| `is_bridge()` | kind == Bridge |
| `is_bridge_member()` | master.is_some() |
| `is_veth()` | kind == Veth |
| `is_up()` | state == Up |

## 파이프라인에서의 사용

- **Interface Check**: 존재 여부, UP/DOWN, Physical NIC frame size
- **Bridge Check**: `master` 필드로 브릿지 멤버 감지
- **ARP Process**: `addresses`에서 target_ip 존재 확인, 서브넷 비교
- **Routing**: `addresses`에서 로컬 주소 판정, egress 인터페이스 설정
- **NAT**: `find_interface_ip()`로 Masquerade/Redirect 주소 결정
- **MTU Check**: `mtu` 값으로 패킷 크기 검사
- **Egress Check**: egress 인터페이스 존재/UP 확인
