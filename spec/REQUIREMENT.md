# netsim 기능 요구사항 (확장 포함)

## 1. 개요

`netsim`은 Linux 네트워크 패킷의 처리 경로를 정적으로 시뮬레이션하는 도구이다.  
사용자는 Web 기반 UI를 통해 네트워크 설정과 패킷을 정의하고,  
해당 패킷이 시스템 내에서 어떻게 처리되는지를 단계적으로 분석할 수 있어야 한다.

---

## 2. 주요 기능 영역

- 시나리오 기반 패킷 시뮬레이션
- XDP / Netfilter / Routing / NAT 통합 처리
- 단계별 trace 및 explain 기능
- Web 기반 GUI 제공
- 실제 시스템 설정 import 기능

---

## 3. 기능 요구사항

## 3.1 시나리오 입력

(기존과 동일 — 생략)

---

## 3.2 시스템 설정 Import (신규 핵심 기능)

### FR-001. 시스템 설정 수집
시스템은 현재 Linux 시스템의 네트워크 설정을 수집할 수 있어야 한다.

최소 수집 대상:

- `ip addr`
- `ip rule`
- `ip route`
- `nft list ruleset`
- `iptables-save`

---

### FR-002. 설정 파싱 및 변환
시스템은 수집된 설정을 내부 시뮬레이션 모델(IR)로 변환할 수 있어야 한다.

---

### FR-003. 부분 Import 지원
사용자는 전체 설정이 아닌 일부만 선택적으로 import할 수 있어야 한다.

예:
- routing만
- nftables만
- 특정 인터페이스만

---

### FR-004. Import 결과 검증
시스템은 import된 설정 중 다음을 명확히 표시해야 한다.

- 정상적으로 해석된 항목
- 부분적으로 해석된 항목
- 지원하지 않는 항목

---

### FR-005. Import 결과 수정 가능
사용자는 import된 설정을 Web UI 또는 파일에서 수정할 수 있어야 한다.

---

### FR-006. 시스템 의존성 제거
Import된 설정은 실제 시스템과 분리된 독립적인 시뮬레이션 환경으로 사용되어야 한다.

---

## 3.3 Web 기반 GUI (신규 핵심 기능)

### FR-011. Web UI 제공
시스템은 브라우저 기반 Web UI를 제공해야 한다.

---

### FR-012. 시나리오 생성 UI
사용자는 GUI를 통해 다음을 직관적으로 설정할 수 있어야 한다.

- 패킷 속성
- 인터페이스 및 IP
- 라우팅 테이블
- 정책 라우팅
- nftables / iptables 규칙
- XDP 규칙

---

### FR-013. 시뮬레이션 실행 UI
사용자는 GUI에서 시뮬레이션을 실행하고 결과를 즉시 확인할 수 있어야 한다.

---

### FR-014. Trace 시각화
시스템은 패킷 처리 흐름을 시각적으로 표현해야 한다.

예:
- 단계별 타임라인
- flow diagram
- rule hit highlight

---

### FR-015. 상태 변화 시각화
시스템은 다음 항목의 변화를 단계별로 시각화해야 한다.

- IP / port 변경
- mark 변화
- conntrack state
- routing decision

---

### FR-016. Explain 모드 UI
시스템은 "왜 이 경로로 갔는지"를 자연어 또는 구조화된 형태로 설명해야 한다.

---

### FR-017. Import UI
사용자는 GUI에서 다음 기능을 수행할 수 있어야 한다.

- 현재 시스템 설정 import
- 파일 업로드(import)
- import 결과 미리보기

---

### FR-018. 프로젝트/시나리오 관리
사용자는 여러 개의 시나리오를 저장하고 불러올 수 있어야 한다.

---

## 3.4 시뮬레이션 결과 및 분석

(기존 trace/출력 요구사항 유지)

---

## 4. 아키텍처 요구사항 (추가)

### FR-021. Backend 엔진 분리
시뮬레이션 엔진은 Web UI와 분리된 독립 모듈로 동작해야 한다.

---

### FR-022. API 제공
시스템은 Web UI와 통신하기 위한 API를 제공해야 한다.

예:
- 시뮬레이션 실행
- 시나리오 저장/불러오기
- 설정 import

---

### FR-023. 비동기 실행 지원
시뮬레이션은 비동기로 실행될 수 있어야 하며, 진행 상태를 조회할 수 있어야 한다.

---

## 5. MVP 범위 (업데이트)

초기 버전에서는 다음을 포함한다.

### 필수
- YAML 기반 시나리오 입력
- ingress 패킷 시뮬레이션
- XDP 기본 처리
- nftables / iptables 기본 규칙 처리
- 정책 라우팅 및 라우팅
- NAT 반영
- trace 출력 (text/json)
- Web UI 기본 버전
  - 시나리오 입력
  - 실행
  - 텍스트 trace 표시
- 시스템 설정 import (read-only 수준)

---

## 6. 확장 단계

### Phase 2
- Web UI 고도화 (시각화, diff)
- import 결과 편집 기능
- explain 기능 강화

### Phase 3
- tc / eBPF 일부 지원
- bridge / advanced routing
- dead rule 분석

---

# netsim 기능 요구사항

## 1. 개요

`netsim`은 Linux 네트워크 패킷의 처리 경로를 정적으로 시뮬레이션하는 Web 기반 도구이다.  
사용자는 브라우저 UI를 통해 네트워크 설정과 패킷을 정의하고,  
해당 패킷이 시스템 내에서 어떻게 처리되는지를 단계적으로 분석할 수 있어야 한다.

---

## 2. 주요 기능 영역

- 시나리오 기반 패킷 시뮬레이션
- XDP / Netfilter / Routing / NAT 통합 처리
- 단계별 trace 및 explain 기능
- Web 기반 GUI
- 실제 시스템 설정 import

---

## 3. 기능 요구사항

## 3.1 시나리오 입력

### FR-001. 패킷 시나리오 정의
사용자는 시뮬레이션 대상 패킷의 속성을 정의할 수 있어야 한다.

포함 항목:
- ingress interface
- EtherType
- VLAN 태그
- 출발지/목적지 IP
- 프로토콜
- 출발지/목적지 포트
- 패킷 길이
- 초기 `skb mark`
- 초기 `ct mark`
- conntrack state

---

### FR-002. 네트워크 환경 정의
사용자는 시뮬레이션에 필요한 네트워크 환경을 정의할 수 있어야 한다.

포함 항목:
- 인터페이스 및 IP
- 라우팅 테이블
- 정책 라우팅(`ip rule`)
- nftables 규칙
- iptables 규칙
- XDP 규칙
- 로컬 주소 정보

---

### FR-003. 파일 기반 시나리오 입력
시스템은 YAML 또는 JSON 형식으로 시나리오를 입력받을 수 있어야 한다.

---

### FR-004. 입력 검증
시스템은 입력 오류, 누락, 지원하지 않는 표현식을 검출하고 사용자에게 명확히 표시해야 한다.

---

## 3.2 시스템 설정 Import

### FR-010. 시스템 설정 수집
시스템은 현재 Linux 시스템의 네트워크 설정을 수집할 수 있어야 한다.

대상:
- `ip addr`
- `ip rule`
- `ip route`
- `nft list ruleset`
- `iptables-save`

---

### FR-011. 설정 파싱 및 IR 변환
수집된 설정은 내부 시뮬레이션 모델(IR)로 변환되어야 한다.

---

### FR-012. 부분 Import 지원
사용자는 다음과 같이 선택적으로 import할 수 있어야 한다.

- routing만
- nftables만
- 특정 인터페이스만

---

### FR-013. Import 결과 검증
시스템은 import 결과를 다음과 같이 구분하여 표시해야 한다.

- 정상 해석
- 부분 해석
- 미지원 항목

---

### FR-014. Import 결과 수정
사용자는 import된 설정을 UI에서 수정할 수 있어야 한다.

---

### FR-015. 환경 독립성 보장
Import된 설정은 실제 시스템과 분리된 시뮬레이션 환경에서 동작해야 한다.

---

## 3.3 Web 기반 GUI

### FR-020. Web UI 제공
시스템은 브라우저 기반 UI를 제공해야 한다.

---

### FR-021. 시나리오 편집 UI
사용자는 GUI를 통해 다음을 설정할 수 있어야 한다.

- 패킷 속성
- 인터페이스 및 IP
- 라우팅
- 정책 라우팅
- nftables / iptables 규칙
- XDP 규칙

---

### FR-022. 시뮬레이션 실행
사용자는 UI에서 시뮬레이션을 실행할 수 있어야 한다.

---

### FR-023. Trace 시각화
시스템은 패킷 처리 흐름을 시각적으로 표현해야 한다.

예:
- 단계별 타임라인
- flow diagram
- rule hit 강조

---

### FR-024. 상태 변화 시각화
다음 상태 변화를 단계별로 보여줘야 한다.

- IP / port
- mark
- conntrack state
- routing decision

---

### FR-025. Explain 기능
시스템은 패킷 처리 결과에 대한 설명을 제공해야 한다.

예:
- 어떤 rule이 매칭되었는지
- 어떤 routing rule이 선택되었는지
- 왜 특정 인터페이스로 나갔는지

---

### FR-026. Import UI
사용자는 UI에서 다음을 수행할 수 있어야 한다.

- 시스템 설정 import
- 파일 업로드
- import 결과 미리보기

---

### FR-027. 시나리오 관리
사용자는 시나리오를 저장, 불러오기, 복제할 수 있어야 한다.

---

## 3.4 시뮬레이션 엔진

### FR-030. ingress 패킷 처리 시뮬레이션
시스템은 ingress 패킷의 전체 처리 경로를 시뮬레이션할 수 있어야 한다.

---

### FR-031. XDP 처리
시스템은 XDP 단계에서 다음을 처리해야 한다.

- PASS
- DROP
- TX
- REDIRECT
- ABORTED

---

### FR-032. Netfilter 처리
시스템은 nftables 및 iptables 규칙을 평가할 수 있어야 한다.

---

### FR-033. NAT 처리
시스템은 DNAT, SNAT, REDIRECT, TPROXY를 반영할 수 있어야 한다.

---

### FR-034. 정책 라우팅 및 라우팅
시스템은 다음을 수행할 수 있어야 한다.

- ip rule 평가
- routing table 선택
- longest prefix match

---

### FR-035. 최종 결과 산출
시스템은 다음 중 하나의 결과를 산출해야 한다.

- DROP
- LOCAL DELIVERY
- FORWARDED
- REDIRECT
- TX
- REJECTED
- BLACKHOLE
- TPROXY

---

### FR-036. Trace 기록
시스템은 모든 처리 단계를 trace로 기록해야 한다.

---

## 3.5 결과 표현

### FR-040. UI 기반 결과 표시
시스템은 시뮬레이션 결과를 UI에서 표현해야 한다.

---

### FR-041. 단계별 trace 출력
사용자는 각 처리 단계를 순서대로 확인할 수 있어야 한다.

---

### FR-042. 핵심 요약 제공
다음 정보를 요약해서 보여줘야 한다.

- 최종 결과
- 출력 인터페이스
- next-hop
- 주요 매칭 규칙

---

### FR-043. 구조화 데이터 제공
시스템은 내부적으로 JSON 형태의 결과를 생성해야 한다 (API용).

---

## 3.6 아키텍처 요구사항

### FR-050. 엔진-UI 분리
시뮬레이션 엔진은 UI와 분리되어야 한다.

---

### FR-051. API 제공
시스템은 다음 기능을 위한 API를 제공해야 한다.

- 시뮬레이션 실행
- 시나리오 관리
- 설정 import

---

### FR-052. 비동기 처리
시뮬레이션은 비동기로 실행되어야 하며 진행 상태를 조회할 수 있어야 한다.

---

## 4. MVP 범위

### 포함 기능

- YAML/JSON 시나리오 입력
- ingress 패킷 시뮬레이션
- XDP 기본 처리
- nftables / iptables 기본 처리
- 정책 라우팅 및 라우팅
- NAT 반영
- trace 생성
- Web UI 기본 기능
  - 시나리오 입력
  - 실행
  - 텍스트 기반 trace 표시
- 시스템 설정 import (read-only)

---

## 5. 확장 단계

### Phase 2
- 시각화 강화 (flow, timeline)
- explain 기능 고도화
- import 편집 기능
- 결과 비교(diff)

### Phase 3
- tc / eBPF 일부 지원
- bridge / advanced routing
- dead rule 분석
