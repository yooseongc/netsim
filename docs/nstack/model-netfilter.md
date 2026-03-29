# Model: Netfilter

nftables 및 iptables 규칙 체계와 체인 평가 로직을 정의한다.

## 코드 참조

- `crates/netsim-core/src/model/netfilter.rs` - 데이터 모델
- `crates/netsim-core/src/pipeline/chain_eval.rs` - 체인 평가 로직

## NetfilterConfig

nftables와 iptables 설정을 통합하는 최상위 구조체.

```rust
pub struct NetfilterConfig {
    pub nftables: Option<NftablesRuleset>,  // nftables 테이블/체인
    pub iptables: Option<IptablesRuleset>,  // iptables 테이블/체인
}
```

두 체계의 체인은 priority 기준으로 통합 정렬되어 평가된다.

## Hook 및 Priority

| Hook | iptables table | iptables priority |
|------|---------------|-------------------|
| Prerouting | raw | -300 |
| Prerouting | mangle | -150 |
| Prerouting | nat | -100 |
| Input | filter | 0 |
| Forward | filter | 0 |
| Output | raw | -300 |
| Output | mangle | -150 |
| Output | nat | -100 |
| Output | filter | 0 |
| Postrouting | nat | 100 |

nftables 체인은 사용자가 priority를 직접 지정한다.

## NfMatch 종류

| 타입 | 설명 | 필드 |
|------|------|------|
| `Ip` | IP 주소/필드 매칭 | field(saddr/daddr/protocol/version/length/dscp/ttl), op, value |
| `Transport` | TCP/UDP/ICMP 필드 | protocol, field(sport/dport/flags/icmp_type/icmp_code), op, value |
| `Iif` | 입력 인터페이스 | name |
| `Oif` | 출력 인터페이스 | name |
| `Meta` | 메타 정보 | key(mark/protocol/length/iifname/oifname/skuid/nfproto/l4proto), op, value |
| `Ct` | conntrack 정보 | key(state/mark/status/direction/expiration), op, value |
| `Mark` | 패킷 mark | op, value, mask(optional) |

## MatchOp (비교 연산자)

`eq`, `neq`, `lt`, `gt`, `lte`, `gte`, `in`

## NfAction 종류

| Action | 동작 | Terminal |
|--------|------|----------|
| `Verdict { Accept }` | 패킷 수용, 이후 체인 중단 | Yes (stop=true) |
| `Verdict { Drop }` | 패킷 폐기 | Yes |
| `Verdict { Reject }` | 패킷 거부 (ICMP 응답) | Yes |
| `Verdict { Continue }` | 다음 규칙으로 | No |
| `Verdict { Queue }` | 패킷 stolen (userspace queue) | Yes |
| `Nat { action }` | NAT 적용 후 Accept (stop=false) | No (다음 체인 계속) |
| `SetMark { value, mask }` | 패킷 mark 설정 | No |
| `Log { prefix, level }` | 로깅 (non-terminating) | No |
| `Counter` | 카운터 (non-terminating) | No |
| `Jump { target }` | 타겟 체인으로 점프 | 타겟에 따라 |
| `Goto { target }` | 타겟 체인으로 이동 | 타겟에 따라 |
| `Return` | 호출 체인으로 복귀 | Break |

## Jump vs Goto

- **Jump**: 타겟 체인 평가 후 Return 시 **현재 체인의 다음 규칙**으로 복귀
- **Goto**: 타겟 체인 평가 후 Return 시 **base chain의 policy**로 (현재 체인 종료)
- 최대 재귀 깊이: 16단계 (`MAX_CHAIN_DEPTH`)

## Chain Policy

체인 내 모든 규칙이 매칭되지 않았을 때:

- `policy: Accept` -> decision=None, stop=false (다른 체인 계속)
- `policy: Drop` -> decision=Drop, stop=true (이후 체인도 중단)

## 체인 평가 흐름

```
collect_chains_for_hook(hook)
  -> priority 오름차순 정렬
  -> 각 체인에 대해 evaluate_chain_inner():
       -> 규칙 순회, matches 평가
       -> 매칭 시 action 실행
       -> terminal decision이면 즉시 반환
       -> 체인 끝까지 도달하면 policy 적용
  -> 모든 체인 통과하면 Continue
```

## Trace 출력 예시

```json
{
  "matched_rules": [
    {
      "source": "iptables",
      "table": "filter",
      "chain": "INPUT",
      "rule_index": 2,
      "rule_summary": "3 match(es) -> Drop /* block ssh */"
    }
  ]
}
```
