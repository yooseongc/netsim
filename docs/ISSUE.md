# netsim 이슈 및 해결 방법

## 개발 중 발견된 문제 사항

(아직 개발 시작 전이므로 이슈 없음)

---

## 설계 단계 결정 사항

### D-001. Conntrack 시뮬레이션 방식

**문제**: 정적 시뮬레이션에서 실제 conntrack 상태를 추적할 수 없음.
**결정**: 사용자가 패킷 정의 시 conntrack state(NEW/ESTABLISHED/RELATED/INVALID)를 직접 선언.
**이유**: 단일 패킷 시뮬레이션이므로 연결 상태 추적이 불가능. 사용자가 시나리오 의도에 맞게 선언하는 것이 합리적.

### D-002. nftables / iptables 통합 IR

**문제**: nftables와 iptables를 별도 IR로 관리할 것인가, 통합할 것인가.
**결정**: 통합 IR (`NfRule`)을 사용하되, 파서 레벨에서 각각의 형식을 통합 IR로 변환.
**이유**: 시뮬레이션 엔진이 단일 로직으로 체인을 평가할 수 있어 복잡도 감소.

### D-003. XDP 모델링

**문제**: XDP는 eBPF 프로그램이므로 완전한 시뮬레이션이 불가능.
**결정**: 간소화된 match-action 규칙으로 모델링. 사용자가 "이 조건이면 DROP" 형태로 정의.
**이유**: 정적 시뮬레이션 목적에 부합. eBPF 바이트코드 해석은 범위 밖.

### D-004. MVP 동기 실행

**문제**: 시뮬레이션을 비동기로 실행할 필요가 있는가.
**결정**: MVP에서는 동기 실행. API 응답에 simulation_id + status 구조는 유지하여 향후 비동기 전환 용이.
**이유**: 단일 패킷 시뮬레이션은 충분히 빠르므로 (< 10ms) 비동기가 불필요.

### D-005. PREROUTING RAW/conntrack 분리

**문제**: PREROUTING을 단일 evaluate_netfilter_hook으로 처리하면 RAW 테이블이 conntrack 이후에 평가됨.
**결정**: collect_chains_for_hook으로 체인을 수집한 후 priority -200 기준으로 raw/post-conntrack 그룹으로 분리. evaluate_chains_subset 헬퍼로 각 그룹을 별도 평가.
**이유**: Linux 커널에서 raw table(-300)은 conntrack 이전에 실행되어 NOTRACK 등을 설정할 수 있어야 함.

### D-006. Physical NIC ingress MTU vs IP MTU

**문제**: ingress MTU 검사에서 interface.mtu를 직접 사용하면 정상적인 포워딩 시나리오가 깨짐 (MTU=1500인 NIC에서 2000바이트 패킷 수신 가능).
**결정**: IP MTU가 아닌 물리적 수신 프레임 크기 상한(max(mtu+18, 9216))으로 비교. 가상 인터페이스는 검사 생략.
**이유**: Linux에서 IP MTU는 송신 측 제약. NIC는 설정된 MTU보다 큰 프레임을 수신할 수 있음 (예: jumbo frame 지원).

### D-007. TPROXY는 stolen이 아닌 로컬 전달

**문제**: TPROXY를 StageDecision::Stolen으로 처리하면 패킷이 INPUT 체인을 거치지 않음.
**결정**: TPROXY 적용 시 tproxy_applied 플래그를 설정하고, stolen 대신 정상 라우팅→INPUT 경로를 따르도록 함.
**이유**: Linux에서 TPROXY는 mark + dst 변경 후 정책 라우팅으로 로컬 테이블에 전달하여 INPUT 체인을 통과함.
