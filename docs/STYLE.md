# netsim 스타일 가이드

## 1. 개요

netsim 프론트엔드의 일관된 look & feel을 위한 스타일 가이드.

---

## 2. 기술 스택

- **UI 프레임워크**: shadcn/ui
- **스타일링**: Tailwind CSS
- **아이콘**: Lucide React
- **폰트**: Inter (본문), JetBrains Mono (코드/YAML)

---

## 3. 색상 체계

### 기본 색상 (Tailwind CSS 변수)

shadcn/ui의 기본 테마를 따르되, 시뮬레이션 결과 표현을 위한 시맨틱 색상을 추가한다.

### 시뮬레이션 시맨틱 색상

| 용도 | 색상 | Tailwind Class |
|------|------|----------------|
| PASS / ACCEPT | Green | `text-green-600 bg-green-50` |
| DROP / REJECT | Red | `text-red-600 bg-red-50` |
| NAT 적용 | Amber | `text-amber-600 bg-amber-50` |
| Routing 결정 | Blue | `text-blue-600 bg-blue-50` |
| 상태 변경 | Purple | `text-purple-600 bg-purple-50` |
| PASS-THROUGH | Gray | `text-gray-500 bg-gray-50` |

### PipelineStage 별 색상

| Stage | 색상 |
|-------|------|
| XDP | Indigo |
| tc ingress | Slate |
| conntrack | Cyan |
| PREROUTING | Amber |
| Routing | Blue |
| INPUT | Green |
| FORWARD | Teal |
| POSTROUTING | Orange |

---

## 4. 공통 컴포넌트 (shadcn/ui 기반)

### 사용하는 shadcn/ui 컴포넌트

| 컴포넌트 | 용도 |
|---------|------|
| `Button` | 모든 액션 버튼 |
| `Card` | 프로젝트 카드, 요약 카드, 단계 카드 |
| `Input` | 텍스트 입력 필드 |
| `Select` | 드롭다운 선택 |
| `Table` | 데이터 테이블 (인터페이스, 라우팅, 규칙) |
| `Tabs` | 시나리오 에디터 탭 |
| `Dialog` | 모달 (프로젝트 생성, 확인) |
| `Toast` | 알림 메시지 |
| `Badge` | 상태 뱃지 (verdict, stage) |
| `Textarea` | Import 텍스트 입력 |
| `Separator` | 구분선 |
| `ScrollArea` | 스크롤 영역 |
| `Tooltip` | 도움말 툴팁 |
| `Alert` | 경고/정보 알림 |
| `Collapsible` | 접을 수 있는 섹션 |

---

## 5. 레이아웃 규칙

### 간격
- 페이지 패딩: `p-6`
- 카드 간 간격: `gap-4`
- 섹션 간 간격: `space-y-6`
- 폼 필드 간: `space-y-4`

### 반응형
- 사이드바: 데스크탑에서 고정 `w-64`, 모바일에서 숨김/토글
- 메인 콘텐츠: `flex-1` 남은 공간 채움
- 최소 지원 너비: 1024px

### 테이블
- 헤더: `bg-muted` 배경
- 행: hover 시 `bg-muted/50`
- 액션 버튼: 행 우측에 배치

---

## 6. 타이포그래피

| 요소 | 스타일 |
|------|--------|
| 페이지 제목 | `text-2xl font-bold` |
| 섹션 제목 | `text-lg font-semibold` |
| 카드 제목 | `text-base font-medium` |
| 본문 | `text-sm` |
| 보조 텍스트 | `text-xs text-muted-foreground` |
| 코드/YAML | `font-mono text-sm` |
| 뱃지 텍스트 | `text-xs font-medium` |

---

## 7. Trace 시각화 스타일

### TraceTimeline
- 수직 리스트, 각 단계를 연결하는 선 (`border-l-2`)
- 각 단계: 원형 인디케이터 + 단계명 + 결정 뱃지
- 선택된 단계: 배경 하이라이트 `bg-accent`

### TraceStepCard
- 카드 형태, 좌측에 stage 색상 바 (`border-l-4`)
- 상단: stage 이름 + decision 뱃지
- 중간: state before/after 비교 테이블
- 하단: matched rules + explain

### PacketStateView
- 2열 레이아웃 (Before | After)
- 변경된 필드: `bg-yellow-50 font-semibold`
- 변경 없는 필드: `text-muted-foreground`

### Verdict 뱃지

| Verdict | 스타일 |
|---------|--------|
| `DROP` | `bg-red-100 text-red-800 border-red-200` |
| `LOCAL_DELIVERY` | `bg-green-100 text-green-800 border-green-200` |
| `FORWARDED` | `bg-blue-100 text-blue-800 border-blue-200` |
| `REJECTED` | `bg-red-100 text-red-800 border-red-200` |
| `BLACKHOLE` | `bg-gray-100 text-gray-800 border-gray-200` |
| `TPROXY` | `bg-purple-100 text-purple-800 border-purple-200` |

---

## 8. 코딩 컨벤션

### 파일명
- 컴포넌트: PascalCase (`PacketEditor.tsx`)
- 유틸리티: camelCase (`utils.ts`)
- 타입: camelCase (`scenario.ts`)

### 컴포넌트
- 함수형 컴포넌트 사용 (화살표 함수)
- Props 타입은 컴포넌트와 같은 파일에 정의
- shadcn/ui 컴포넌트를 직접 사용하고, 필요 시 래퍼 컴포넌트 작성

### Tailwind
- 인라인 클래스 사용 (CSS 파일 최소화)
- 반복 패턴은 `cn()` 유틸리티로 조건부 클래스 적용
- 매직 넘버 대신 Tailwind 스케일 사용
