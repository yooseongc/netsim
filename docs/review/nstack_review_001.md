# netsim 네트워크 스택 설계 검증 결과 001

## 1. 전체 평가

- ✔️ 구조 적합성: 높음 (약 80~90%)
- ✔️ XDP → Netfilter → Routing → INPUT/FORWARD/OUTPUT 흐름: 전반적으로 정확
- ⚠️ 일부 핵심 커널 동작과의 차이 존재
- ❗ 특히 routing, TPROXY, bridge 처리에서 현실과 차이 발생

---

## 2. 핵심 차이 (중요도 높음)

### 2.1 Routing 처리 방식

#### 현재 설계
- PREROUTING 이후 단일 routing 단계 수행

#### 실제 Linux
- routing은 단일 단계가 아님
- 여러 상황에서 재평가됨:
  - DNAT 이후
  - mark 변경 이후 (PBR)
  - TPROXY 적용 시
  - policy routing 변경 시

#### 문제점
- 현재 구조는 routing이 1회만 수행됨
- 이후 상태 변화가 routing에 반영되지 않음

#### 개선 방향
- routing을 “단계(stage)”가 아니라 “재호출 가능한 함수”로 설계

---

### 2.2 TPROXY 처리

#### 현재 설계
- TPROXY 적용 후에도 routing 계속 진행

#### 실제 Linux
- skb->sk 설정
- local delivery 강제
- routing 결과 override

#### 문제점
- 실제보다 정상 패킷처럼 흐름

#### 개선 방향
- TPROXY 적용 시:
  - mark 변경
  - socket assign
  - routing 결과를 LOCAL로 강제 변경

---

### 2.3 Bridge 처리

#### 현재 설계
- bridge_nf_call_iptables=false → L2 forwarding bypass

#### 실제 Linux
- 두 가지 경로 존재

1. 순수 bridge
   - netfilter 미통과

2. bridge-nf enabled
   - 별도의 bridge netfilter hook 사용
   - PREROUTING / FORWARD / POSTROUTING (bridge family)

#### 문제점
- 단순 bypass vs IP stack 이분법 구조

#### 개선 방향
- bridge 전용 pipeline 추가
- bridge netfilter hook 모델링 필요

---

## 3. Netfilter 처리 정확도

### ✔️ 잘 맞는 부분

- raw → conntrack → mangle/nat → filter 흐름 정확
- priority 기반 hook 분리 적절

---

### ⚠️ 보완 필요

#### NAT 처리

현재:
- 지속적으로 NAT 적용 가능

실제:
- DNAT: PREROUTING에서 최초 1회
- SNAT: POSTROUTING에서 최초 1회
- 이후 패킷은 conntrack 기반 처리

---

#### Conntrack 상태

현재:
- 사용자 정의 상태

실제:
- NEW
- ESTABLISHED
- RELATED
- INVALID

추가:
- NAT 상태도 conntrack에 포함

---

## 4. rp_filter

#### 현재 설계
- PREROUTING 이후 수행

#### 실제 Linux
- routing lookup 기반 검증
- fib_validate_source() 내부

#### 평가
- ✔️ 거의 정확
- routing과 결합된 처리임을 반영하면 더 정확

---

## 5. TTL 처리

#### 현재 설계
- FORWARD 단계에서 TTL 감소

#### 실제 Linux
- 동일

#### 누락
- TTL=0 시 ICMP Time Exceeded 생성

---

## 6. MTU 처리

#### 현재 설계
- POSTROUTING 이후 MTU 검사

#### 실제 Linux
- fragmentation은 output path에서 수행
- forwarding 시에도 적용

#### 평가
- ✔️ 큰 문제 없음

---

## 7. OUTPUT 경로

#### 현재 설계
- OUTPUT raw → conntrack → mangle → routing → POSTROUTING

#### 평가
- ✔️ 실제 커널과 거의 동일

---

## 8. 누락된 주요 요소

### 8.1 Loopback 경로

#### 실제 Linux
- OUTPUT → routing → LOCAL → INPUT


#### 문제
- netsim에 해당 경로 없음

---

### 8.2 Mark 기반 재-routing

#### 실제 Linux
- mark 변경 시 routing 재수행 가능

#### 문제
- 현재 단일 routing 구조

---

### 8.3 Socket Lookup

#### 실제 Linux
- sk lookup으로 local delivery 결정
- TPROXY / bind / reuseport 등에 영향

#### 문제
- 해당 레이어 없음

---

### 8.4 TC (Traffic Control)

#### 현재 설계
- ingress pass-through

#### 실제 Linux
- drop / redirect / mirred 가능

---

## 9. 결론

### 👍 강점

- 전체 pipeline 구조 매우 정확
- netfilter hook 모델링 우수
- XDP 통합 구조 적절
- sysctl 반영 설계 현실적
- OUTPUT / FORWARD 분기 정확

---

### ⚠️ 반드시 수정 필요

1. routing을 재호출 가능 구조로 변경
2. TPROXY를 local delivery override로 처리
3. bridge pipeline 분리

---

### ⚠️ 중간 중요도 개선

4. conntrack state 실제처럼 모델링
5. NAT 1회 적용 규칙 반영
6. loopback 경로 추가

---

### ⚠️ 후순위 개선

7. ICMP 생성
8. tc 동작 반영
9. socket lookup 모델링

---

## 10. 최종 평가

> “Linux 네트워크 스택의 구조를 매우 잘 반영한 설계이지만,  
> routing 재평가, TPROXY 처리, bridge 경로에서 커널의 비선형 동작을 추가로 반영해야 완성도에 도달한다.”
