# 리눅스 네트워크 스택 시뮬레이션 구현 명세

> 이 문서는 `netsim-core` 엔진의 **현재 구현**을 기준으로 작성되었습니다.
> 소스 참조: `engine.rs`, `trace.rs`, `pipeline/mod.rs`, `model/sysctl.rs`, `model/interface.rs`, `model/packet.rs`, `session_engine.rs`

---

## 1. 개요

netsim 엔진은 두 가지 패킷 경로를 시뮬레이션한다.

| 경로 | 진입점 | 설명 |
|------|--------|------|
| **Ingress** (`engine::run`) | 외부에서 수신한 패킷 | NIC 수신 → netfilter → 라우팅 → 로컬/포워딩 |
| **Output** (`engine::run_output`) | 로컬에서 발신한 패킷 | OUTPUT chains → 라우팅 → POSTROUTING → 전송 |

두 경로 모두 `PacketState`를 변이(mutate)하면서 각 단계(stage)를 순차적으로 통과하며, 각 단계의 결과를 `TraceStep`으로 기록한다.

---

## 2. Ingress 파이프라인 다이어그램

```
                        패킷 수신 (NIC)
                             |
                    [InterfaceCheck]
                     존재? UP? 브릿지 멤버?
                             |
              +----- 브릿지 멤버? -----+
              |  (master 존재)         |  (아님)
              |                        |
   bridge_nf_call_iptables?            |
      false:                           |
   [BridgeForward]                     |
    L2 포워딩 --> FORWARDED            |
      true:                            |
      계속 v  <------------------------+
              |
   [InterfaceCheck] Physical NIC 수신 프레임 크기
    (Physical NIC만: pkt_len > max(mtu+18, 9216) --> DROP)
              |
           [XDP]
    XDP_PASS / XDP_DROP / XDP_TX / XDP_REDIRECT
              |
        [ArpProcess]  (ARP 패킷만)
         arp_ignore 검사
              |
        [L2Bypass]  (ARP/STP/LLDP 패킷)
         --> LOCAL_DELIVERY (netfilter/routing 건너뜀)
              |
        [TcIngress]
         TC ingress qdisc
              |
      [PreRoutingRaw]
       PREROUTING 체인 중 priority <= -200 (raw 테이블)
              |
       [ConntrackIn]
        conntrack 조회 (ct_state 결정)
              |
       [PreRouting]
        PREROUTING 체인 중 priority > -200
        (mangle -150, dnat -100 등)
        * TPROXY 적용 시 tproxy_applied=true 설정 후 계속 진행
              |
        [RpFilter]
         sysctl rp_filter 검사 (strict/loose)
              |
      route_localnet 검사
       (dst가 127.0.0.0/8이면 route_localnet 필요)
              |
      [RoutingDecision]
       라우팅 테이블 조회 --> local / forward 결정
              |
       +------+------+
       |             |
   LocalDelivery  ForwardTo
       |             |
  icmp_echo_     [InterfaceCheck]
  ignore_all?     egress IF 존재/UP 검사
       |             |
  [LocalInput]   ip_forward 검사
   INPUT chains      |
       |         [Forward]
  LOCAL_DELIVERY  FORWARD chains
                     |
                [PostRouting]
                 POSTROUTING chains (SNAT/MASQ)
                     |
                 [MtuCheck]
                  egress MTU 검사
                  (DF=1 --> DROP, DF=0 --> fragmentation)
                     |
              [ConntrackConfirm]
                     |
                  FORWARDED
```

---

## 2.1. Output 파이프라인 다이어그램

```
              로컬 발신 패킷
                   |
            [Output] RAW
             OUTPUT 체인 중 priority <= -200
                   |
            [ConntrackIn]
             conntrack 조회
                   |
            [Output] post-CT
             OUTPUT 체인 중 priority > -200
             (mangle, filter, nat)
                   |
          [RoutingDecision]
           라우팅 테이블 조회 (egress IF 결정)
                   |
          [PostRouting]
           POSTROUTING chains (SNAT/MASQ)
                   |
           [MtuCheck]
            egress MTU 검사
                   |
        [ConntrackConfirm]
                   |
               SENT
```

---

## 3. 단계별 상세 설명

### 3.1 InterfaceCheck (인터페이스 검증)

`PipelineStage::InterfaceCheck`

Ingress 경로의 첫 번째 단계. 여러 하위 검사를 포함한다.

| 하위 검사 | 조건 | 결과 |
|-----------|------|------|
| (a) 인터페이스 존재 | ingress IF가 시나리오에 없음 | DROP |
| (b) 인터페이스 상태 | ingress IF가 DOWN | DROP |
| (c) 브릿지 멤버 감지 | `iface.master`가 존재 | Continue (정보 기록) |
| (d) Physical NIC 프레임 크기 | `kind=Physical`, `pkt_len > max(mtu+18, 9216)` | DROP |
| (e) Egress IF 검증 (포워딩 시) | egress IF 없음 또는 DOWN | DROP |

**Physical NIC 프레임 크기 검사**: 물리 NIC는 드라이버 수준에서 최대 수신 프레임 크기를 제한한다. `max(mtu + 18, 9216)` 바이트를 초과하면 DROP. 가상 인터페이스(veth, bridge, tun, tap)는 이 검사를 건너뛴다.

### 3.2 BridgeForward (브릿지 L2 포워딩)

`PipelineStage::BridgeForward`

ingress 인터페이스가 브릿지 멤버이고 `sysctl.bridge_nf_call_iptables = false`이면, IP netfilter 스택을 거치지 않고 L2 레벨에서 브릿지가 직접 포워딩한다. 최종 verdict: **Forwarded**.

`bridge_nf_call_iptables = true`이면 이 단계를 건너뛰고 일반 IP 스택 경로를 계속 진행한다.

### 3.3 XDP

`PipelineStage::Xdp`

드라이버 레벨에서 가장 먼저 실행. XDP 프로그램 규칙을 평가한다.

| XDP verdict | 동작 |
|-------------|------|
| XDP_PASS | 다음 단계로 계속 |
| XDP_DROP | DROP |
| XDP_TX | 같은 인터페이스로 반사 --> FinalVerdict::Tx |
| XDP_REDIRECT | 다른 인터페이스로 리다이렉트 --> FinalVerdict::Redirect |

### 3.4 ArpProcess (ARP 처리)

`PipelineStage::ArpProcess`

ARP 패킷(`ethertype = Arp`)에만 적용. `sysctl.arp_ignore` 값에 따라 ARP 응답을 억제한다.

| arp_ignore | 동작 |
|------------|------|
| 0 | 모든 로컬 IP에 대해 응답 (기본값) |
| >= 1 | target IP가 수신 인터페이스에 설정된 경우만 응답 |
| >= 2 | 추가로 sender IP가 같은 서브넷인 경우만 응답 |

### 3.5 L2Bypass (L2 전용 패킷 바이패스)

`PipelineStage::L2Bypass`

`ethertype.is_l2_only()` (ARP, STP, LLDP)인 패킷은 XDP/ARP 처리 이후 netfilter와 라우팅을 건너뛰고 바로 **LOCAL_DELIVERY**로 전달된다.

### 3.6 TcIngress (TC Ingress)

`PipelineStage::TcIngress`

XDP 이후, PREROUTING 이전에 실행. TC ingress qdisc의 필터/액션을 평가한다.
현재 구현에서는 정보 기록(pass-through) 단계.

### 3.7 PreRoutingRaw (PREROUTING RAW)

`PipelineStage::PreRoutingRaw`

PREROUTING 체인 중 **priority <= -200**인 체인만 평가한다. 일반적으로 raw 테이블(priority -300)이 여기에 해당한다. conntrack 이전에 실행되므로 NOTRACK 마킹 등이 가능하다.

RAW 체인이 없으면 이 단계는 건너뛴다.

### 3.8 ConntrackIn (Conntrack 조회)

`PipelineStage::ConntrackIn`

RAW 테이블 이후, mangle/nat 이전에 실행. 패킷의 conntrack 상태(`ct_state`)를 결정한다. 현재 구현에서는 사용자가 선언한 `ct_state` 값을 그대로 사용한다.

### 3.9 PreRouting (PREROUTING)

`PipelineStage::PreRouting`

PREROUTING 체인 중 **priority > -200**인 체인을 평가한다. mangle(-150), DNAT(-100) 등이 여기에 해당한다.

**TPROXY 특수 처리**: TPROXY NAT 액션이 적용되면 `tproxy_applied = true`로 설정하고 패킷을 Stolen으로 처리하지 않는다. 대신 라우팅 --> INPUT 경로를 통해 로컬 전달된다. TPROXY는 mark를 설정하여 policy routing이 local 테이블로 패킷을 전달하도록 한다.

### 3.10 RpFilter (Reverse Path Filter)

`PipelineStage::RpFilter`

PREROUTING 이후, 라우팅 결정 이전에 실행. `sysctl.rp_filter` 값에 따라 source IP의 역방향 라우팅을 검증한다.

| 모드 | 동작 |
|------|------|
| Off (0) | 검사 안 함 |
| Strict (1) | 역라우팅 결과의 egress IF == ingress IF 여야 통과 |
| Loose (2) | 어떤 인터페이스로든 역라우팅 가능하면 통과 |

PREROUTING mangle이 mark를 변경할 수 있고, mark가 policy routing에 영향을 주므로 rp_filter는 PREROUTING 이후에 실행된다.

### 3.11 RoutingDecision (라우팅 결정)

`PipelineStage::RoutingDecision`

ip rule --> routing table 순서로 라우팅 조회를 수행한다.

| 결과 | 의미 |
|------|------|
| LocalDelivery | dst가 로컬 주소 --> INPUT 경로 |
| ForwardTo { egress_if, next_hop } | 포워딩 대상 결정 |
| Drop / Reject | 라우팅 실패 |

추가 검사:
- `route_localnet`: dst가 `127.0.0.0/8`이면 해당 sysctl 활성화 필요 (라우팅 전에 확인)
- `icmp_echo_ignore_all`: 로컬 전달 시 ICMP echo request이면 DROP

### 3.12 LocalInput (INPUT 체인)

`PipelineStage::LocalInput`

로컬 전달 경로. INPUT hook에 등록된 모든 체인을 우선순위 순으로 평가한다.
통과 시 최종 verdict: **LocalDelivery**.

### 3.13 Forward (FORWARD 체인)

`PipelineStage::Forward`

포워딩 경로. 실행 전에 `sysctl.ip_forward` / `sysctl.conf.{iface}.forwarding` 검사를 수행한다. 비활성이면 DROP.

FORWARD hook에 등록된 모든 체인을 우선순위 순으로 평가한다.

### 3.14 PostRouting (POSTROUTING 체인)

`PipelineStage::PostRouting`

POSTROUTING hook에 등록된 체인 평가. SNAT, Masquerade 등이 여기서 적용된다.
Ingress 포워딩 경로와 Output 경로 모두에서 사용된다.

### 3.15 MtuCheck (MTU 검사)

`PipelineStage::MtuCheck`

egress 인터페이스의 MTU와 패킷 크기를 비교한다.

| 조건 | 결과 |
|------|------|
| `pkt_len <= mtu` | 통과 |
| `pkt_len > mtu` && `df_flag = true` | DROP (ICMP Fragmentation Needed 전송) |
| `pkt_len > mtu` && `df_flag = false` | Continue (fragmentation 수행) |
| `packet_length` 미지정 | Continue (검사 건너뜀) |

### 3.16 ConntrackConfirm (Conntrack 확인)

`PipelineStage::ConntrackConfirm`

패킷이 성공적으로 전달/전송될 때 conntrack 엔트리를 확인(confirm)한다. 현재 구현에서는 정보 기록 단계.

### 3.17 Output (OUTPUT 체인)

`PipelineStage::Output`

로컬 발신 패킷 전용. PREROUTING과 동일하게 RAW / post-conntrack으로 분할된다.

- **Output RAW**: priority <= -200인 OUTPUT 체인
- **Output post-CT**: priority > -200인 OUTPUT 체인 (mangle, filter, nat)

---

## 4. Netfilter 체인 평가

### 4.1 체인 수집 (`collect_chains_for_hook`)

지정된 hook(Prerouting, Input, Forward, Output, Postrouting)에 대해:

1. **nftables**: 모든 테이블의 체인 중 `chain.hook == hook`인 것을 수집
2. **iptables**: 모든 테이블의 체인 중 이름이 hook과 일치하는 것을 수집 (테이블별 기본 priority 사용)
3. **priority 오름차순 정렬**

### 4.2 PREROUTING 분할

PREROUTING과 OUTPUT은 conntrack 기준으로 분할된다.

```
모든 체인 수집 (collect_chains_for_hook)
         |
    partition by priority
         |
   +-----+-----+
   |             |
 <= -200       > -200
  (RAW)    (mangle/nat/filter)
   |             |
 평가 후      conntrack
 계속 진행    조회 후 평가
```

| 분류 | priority 범위 | 대표 테이블 |
|------|--------------|------------|
| RAW | <= -200 | raw (-300) |
| post-conntrack | > -200 | mangle (-150), nat (-100), filter (0) |

### 4.3 체인 평가 (`evaluate_chain`)

체인 내 규칙을 순서대로 평가한다.

| 액션 | 동작 | 체인 중단 | 전체 중단 |
|------|------|----------|----------|
| Accept | 수락 | Yes | Yes |
| Drop | 드롭 | Yes | Yes |
| Reject | 거부 (ICMP unreachable) | Yes | Yes |
| Continue | 다음 규칙으로 | No | No |
| Queue | Stolen 처리 | Yes | Yes |
| NAT (Dnat/Snat/Masq/Redirect/Tproxy) | 패킷 상태 변경 후 수락 | Yes | **No** (다음 체인 계속) |
| SetMark | mark 변경 | No | No |
| Log / Counter | 비종료 액션 | No | No |
| Jump / Goto | 현재 구현: continue | No | No |
| Return | 체인 정책으로 복귀 | Yes (규칙 루프) | No |

**체인 정책(policy)**: 규칙에 매칭되지 않으면 체인 policy 적용.
- Accept --> 다음 체인 계속 (전체 중단 아님)
- Drop --> 전체 중단

### 4.4 NAT 액션

| NAT 유형 | 변경 필드 | 플래그 |
|----------|----------|--------|
| Dnat { addr, port } | dst_ip, dst_port | dnat_applied |
| Snat { addr, port } | src_ip, src_port | snat_applied |
| Masquerade { port } | src_ip (egress IF의 IP), src_port | snat_applied |
| Redirect { port } | dst_ip (ingress IF의 IP), dst_port | dnat_applied |
| Tproxy { addr, port, mark } | dst_ip, dst_port, mark | dnat_applied, tproxy_applied |

- NAT 적용 시 `original_dst_ip/port` 또는 `original_src_ip/port`에 원본 값 보존
- ICMP 등 포트가 없는 프로토콜에서는 port 변경을 건너뜀 (`has_ports()` 검사)

---

## 5. sysctl 커널 파라미터

### 5.1 전역 IPv4 파라미터 (`Ipv4Sysctl`)

| 파라미터 | 경로 | 기본값 | 설명 |
|----------|------|--------|------|
| `ip_forward` | `net.ipv4.ip_forward` | `true` | IP 포워딩 활성화 |
| `icmp_echo_ignore_all` | `net.ipv4.icmp_echo_ignore_all` | `false` | 모든 ICMP echo 무시 |
| `icmp_echo_ignore_broadcasts` | `net.ipv4.icmp_echo_ignore_broadcasts` | `true` | 브로드캐스트 ICMP echo 무시 |
| `tcp_syncookies` | `net.ipv4.tcp_syncookies` | `true` | SYN cookies 활성화 |

### 5.2 전역 IPv6 파라미터 (`Ipv6Sysctl`)

| 파라미터 | 경로 | 기본값 | 설명 |
|----------|------|--------|------|
| `forwarding` | `net.ipv6.conf.all.forwarding` | `true` | IPv6 포워딩 |

### 5.3 브릿지 파라미터

| 파라미터 | 경로 | 기본값 | 설명 |
|----------|------|--------|------|
| `bridge_nf_call_iptables` | `net.bridge.bridge-nf-call-iptables` | `false` | 브릿지 패킷에 iptables 적용 |
| `bridge_nf_call_ip6tables` | `net.bridge.bridge-nf-call-ip6tables` | `false` | 브릿지 IPv6 패킷에 ip6tables 적용 |
| `bridge_nf_call_arptables` | `net.bridge.bridge-nf-call-arptables` | `false` | 브릿지 ARP 패킷에 arptables 적용 |

### 5.4 인터페이스별 파라미터 (`InterfaceSysctl`)

조회 순서: `interface_conf[iface]` --> `interface_conf["all"]` --> `interface_conf["default"]` --> 기본값

| 파라미터 | 경로 | 기본값 | 설명 |
|----------|------|--------|------|
| `forwarding` | `conf.{iface}.forwarding` | `None` (전역 사용) | 인터페이스별 포워딩 오버라이드 |
| `route_localnet` | `conf.{iface}.route_localnet` | `false` | 127.0.0.0/8 라우팅 허용 |
| `rp_filter` | `conf.{iface}.rp_filter` | `Strict` | Reverse Path 필터링 (Off/Strict/Loose) |
| `accept_local` | `conf.{iface}.accept_local` | `false` | 로컬 소스 주소 허용 |
| `send_redirects` | `conf.{iface}.send_redirects` | `true` | ICMP redirect 전송 |
| `log_martians` | `conf.{iface}.log_martians` | `false` | 비정상 패킷 로깅 |
| `proxy_arp` | `conf.{iface}.proxy_arp` | `false` | Proxy ARP |
| `proxy_arp_pvlan` | `conf.{iface}.proxy_arp_pvlan` | `false` | Private VLAN proxy ARP |
| `arp_ignore` | `conf.{iface}.arp_ignore` | `0` | ARP 응답 제어 (0~8) |
| `arp_announce` | `conf.{iface}.arp_announce` | `0` | ARP 소스 IP 선택 (0~2) |
| `arp_filter` | `conf.{iface}.arp_filter` | `false` | ARP 필터링 |

### 5.5 RpFilterMode

| 값 | sysctl 값 | 동작 |
|----|----------|------|
| `Off` | 0 | 비활성화 |
| `Strict` | 1 | 역라우팅 결과가 ingress IF와 동일해야 통과 |
| `Loose` | 2 | 어떤 IF로든 역라우팅 가능하면 통과 |

---

## 6. 인터페이스 모델

### 6.1 인터페이스 종류 (`InterfaceKind`)

| 종류 | 설명 | 비고 |
|------|------|------|
| `Loopback` | 루프백 (lo) | |
| `Physical` | 물리 NIC | 프레임 크기 제한 적용 |
| `Veth` | 가상 이더넷 페어 | `veth_peer` 필드로 피어 지정 |
| `Bridge` | 브릿지 | `bridge_members` 필드로 멤버 목록 |
| `Vlan` | VLAN 인터페이스 | `vlan_parent`, `vlan_id` 필드 |
| `Bond` | 본딩 인터페이스 | `bond_members` 필드 |
| `Tun` | TUN 터널 | |
| `Tap` | TAP 터널 | |
| `Wireguard` | WireGuard VPN | |
| `Other(String)` | 기타 | |

### 6.2 인터페이스 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `name` | String | 인터페이스 이름 |
| `index` | u32 | 인터페이스 인덱스 |
| `mac` | Option\<String\> | MAC 주소 |
| `addresses` | Vec\<InterfaceAddress\> | IP 주소 목록 (ip, prefix_len, scope) |
| `mtu` | u32 | MTU (기본: 1500) |
| `state` | InterfaceState | Up / Down |
| `kind` | InterfaceKind | 인터페이스 종류 |
| `veth_peer` | Option\<String\> | veth 피어 이름 |
| `bridge_members` | Vec\<String\> | 브릿지 멤버 목록 |
| `master` | Option\<String\> | 소속 브릿지 이름 |
| `vlan_parent` | Option\<String\> | VLAN 부모 인터페이스 |
| `vlan_id` | Option\<u16\> | VLAN ID |
| `bond_members` | Vec\<String\> | 본딩 멤버 목록 |

### 6.3 주소 스코프 (`AddressScope`)

| 스코프 | 설명 |
|--------|------|
| `Global` | 전역 (기본값) |
| `Link` | 링크 로컬 |
| `Host` | 호스트 로컬 |

---

## 7. 패킷 상태 추적 (`PacketState`)

파이프라인 전체에서 변이되는 가변 상태 구조체.

### 7.1 L2 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `ethertype` | EtherType | 프레임 타입 (Ipv4, Ipv6, Arp, Vlan, Stp, Lldp, Other) |
| `vlan_id` | Option\<u16\> | VLAN ID |
| `src_mac` | Option\<String\> | 출발지 MAC |
| `dst_mac` | Option\<String\> | 목적지 MAC |

### 7.2 L3 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `src_ip` | Option\<IpAddr\> | 출발지 IP |
| `dst_ip` | Option\<IpAddr\> | 목적지 IP |
| `protocol` | IpProtocol | IP 프로토콜 (Tcp, Udp, Icmp, Icmpv6, Vrrp, Ospf, Gre, Esp, Ah, Sctp, Other) |
| `ttl` | u8 | TTL (기본: 64) |
| `dscp` | u8 | DSCP 값 |
| `df_flag` | bool | Don't Fragment 플래그 |
| `packet_length` | Option\<u32\> | 패킷 크기 (바이트) |

### 7.3 L4 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `src_port` | Option\<u16\> | 출발지 포트 (TCP/UDP/SCTP) |
| `dst_port` | Option\<u16\> | 목적지 포트 |
| `tcp_flags` | Option\<TcpFlags\> | TCP 플래그 (syn, ack, fin, rst, psh, urg) |
| `icmp_type` | Option\<u8\> | ICMP 타입 |
| `icmp_code` | Option\<u8\> | ICMP 코드 |
| `arp_op` | Option\<u16\> | ARP operation (1=req, 2=reply) |

### 7.4 메타데이터 / 추적 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `mark` | u32 | 패킷 마크 (fwmark) |
| `ct_mark` | u32 | conntrack 마크 |
| `ct_state` | ConntrackState | conntrack 상태 (New, Established, Related, Invalid, Untracked) |
| `ingress_if` | String | 수신 인터페이스 |
| `egress_if` | Option\<String\> | 송신 인터페이스 (라우팅 후 결정) |

### 7.5 NAT 추적 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `dnat_applied` | bool | DNAT 적용 여부 |
| `snat_applied` | bool | SNAT 적용 여부 |
| `tproxy_applied` | bool | TPROXY 적용 여부 |
| `original_dst_ip` | Option\<IpAddr\> | NAT 이전 원본 목적지 IP |
| `original_dst_port` | Option\<u16\> | NAT 이전 원본 목적지 포트 |
| `original_src_ip` | Option\<IpAddr\> | NAT 이전 원본 출발지 IP |
| `original_src_port` | Option\<u16\> | NAT 이전 원본 출발지 포트 |

---

## 8. 최종 판정 (`FinalVerdict`)

| Verdict | 설명 | 발생 조건 |
|---------|------|----------|
| `Drop` | 패킷 폐기 | 규칙 DROP, 검증 실패, MTU+DF 등 |
| `LocalDelivery` | 로컬 프로세스로 전달 | 라우팅 --> local, INPUT 통과 |
| `Forwarded` | 다른 인터페이스로 포워딩 | FORWARD --> POSTROUTING --> MTU 통과 |
| `Redirect` | XDP REDIRECT로 리다이렉트 | XDP redirect (다른 IF) |
| `Tx` | XDP TX로 반사 | XDP redirect (같은 IF) |
| `Rejected` | 패킷 거부 (ICMP 응답 전송) | 규칙 REJECT |
| `Blackhole` | 블랙홀 라우트 | 라우팅에서 blackhole 매칭 |
| `Tproxy` | TPROXY Stolen | Stolen decision |
| `Sent` | 로컬 발신 패킷 전송 완료 | Output 경로 최종 성공 |

---

## 9. 세션 시뮬레이션 (`session_engine`)

### 9.1 개요

`SessionDef`를 받아 관련 패킷 시퀀스를 생성하고, 각 패킷을 `engine::run()`으로 순차 시뮬레이션한다. NAT 매핑이 reply 패킷에 자동으로 반영된다.

### 9.2 세션 타입 (`SessionType`)

| 타입 | 설명 |
|------|------|
| `TcpHandshake` | TCP 3-way handshake (+선택적 data/close) |
| `IcmpPing` | ICMP echo request/reply |
| `Custom` | 사용자 정의 패킷 시퀀스 |

### 9.3 NAT 매핑

첫 번째 패킷(forward 방향) 시뮬레이션 후 NAT 매핑을 추출한다.

```
Forward: client(A:a) --> server(B:b)
  DNAT 적용 --> B':b'
  SNAT 적용 --> A':a'

Reply: server(B':b') --> client(A':a')  (NAT 역변환 적용)
```

reply 패킷에서는:
- forward의 DNAT 역변환: reply의 `src_ip`가 original dst --> translated dst로 변경
- forward의 SNAT 역변환: reply의 `dst_ip`가 original src --> translated src로 변경

### 9.4 세션 판정 (`SessionVerdict`)

| 판정 | 조건 |
|------|------|
| `Established` | 모든 패킷이 성공 |
| `Failed { failed_at, reason }` | 특정 패킷에서 터미널 verdict (Drop/Rejected/Blackhole) |
| `Partial { passed, total }` | 일부만 통과 |

터미널 verdict(Drop, Rejected, Blackhole) 발생 시 세션 시뮬레이션을 즉시 중단한다.
