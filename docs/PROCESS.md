# netsim 진행 사항

## 현재 단계

**4단계: 시뮬레이션 엔진 구현** — 완료

---

## 진행 이력

### 2026-03-29

- [x] 요구사항 분석 (spec/REQUIREMENT.md, spec/TECH.md)
- [x] 백엔드 설계안 작성 (docs/DESIGN_BACKEND.md)
- [x] 프론트엔드 설계안 작성 (docs/DESIGN_FRONTEND.md)
- [x] API 명세 작성 (docs/API.md)
- [x] 스타일 가이드 작성 (docs/STYLE.md)
- [x] 빌드/실행 가이드 작성 (docs/DEV.md)
- [x] 테스트 정의 작성 (docs/TEST.md)
- [x] Rust workspace 초기화 (3 crates + IR 모델 정의 + 컴파일 확인)
- [x] Frontend scaffold 생성 (React + TypeScript + Vite + Tailwind + 빌드 확인)
- [x] Dockerfile 작성 (멀티스테이지)
- [x] 패킷 모델 보강 (ICMP type/code, ARP, L2 프로토콜, VRRP/OSPF/GRE 등)
- [x] matcher.rs 룰 매칭 엔진 구현 (프로토콜별 L4 분기, 15개 단위 테스트)
- [x] 파이프라인 전 단계 구현 (xdp, tc, prerouting, routing, input, forward, postrouting)
- [x] engine.rs 시뮬레이션 오케스트레이터 구현
- [x] 통합 테스트 13개 시나리오 (TCP/UDP/ICMP/ARP/VRRP, DNAT, SNAT, XDP, 정책라우팅, TTL, blackhole)
- [x] 1차 버그 수정 (메모리 누수, Reject/Drop 구분, XDP TX, next_hop)
- [x] 통합 테스트 26개로 확장 (+Reject, chain policy, iptables, IPv6, ICMPv6, 혼합 규칙)
- [x] 2차 버그 수정 (SCTP has_ports, Masquerade IPv4/6 패밀리, serde 중첩 tag, TTL 순서)
- [x] compute_state_changes NAT/프로토콜 필드 추적 보강
- [x] 세션 모델 구현 (TCP handshake, ICMP echo, UDP exchange, 커스텀)
- [x] 세션 엔진 구현 (NAT 매핑 전파, 방화벽 실패 감지)
- [x] 세션 테스트 6개 (TCP handshake, ICMP ping, DNAT+TCP, 방화벽 차단, UDP DNS, full TCP)

---

## 전체 로드맵

| 단계 | 내용 | 상태 |
|------|------|------|
| 1단계 | 설계 문서 작성 | 완료 |
| 2단계 | 프로젝트 초기화 (Rust workspace + Frontend + Docker) | 완료 |
| 3단계 | 코어 모델 구현 (netsim-core IR) | 완료 |
| 4단계 | 시뮬레이션 엔진 구현 | 완료 |
| 5단계 | 파서 구현 (netsim-parser) | 대기 |
| 6단계 | 웹 서버 구현 (netsim-server) | 대기 |
| 7단계 | 프론트엔드 구현 | 대기 |
| 8단계 | 통합 및 배포 | 대기 |
