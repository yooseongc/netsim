# netsim 프론트엔드 설계안

## 1. 개요

netsim 프론트엔드는 React + TypeScript + Vite 기반으로 구현하며, shadcn/ui + Tailwind CSS를 사용한다.

---

## 2. 디렉토리 구조

```
frontend/
├── package.json
├── tsconfig.json
├── vite.config.ts
├── tailwind.config.ts
├── postcss.config.js
├── index.html
├── components.json               # shadcn/ui 설정
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── api/                      # API 클라이언트
    │   └── client.ts
    ├── types/                    # TypeScript 타입 (백엔드 IR 미러)
    │   ├── scenario.ts
    │   ├── packet.ts
    │   ├── trace.ts
    │   └── project.ts
    ├── pages/
    │   ├── ProjectListPage.tsx
    │   ├── ScenarioEditorPage.tsx
    │   ├── SimulationResultPage.tsx
    │   └── ImportPage.tsx
    ├── components/
    │   ├── ui/                   # shadcn/ui 프리미티브
    │   ├── layout/
    │   │   ├── AppShell.tsx
    │   │   ├── Sidebar.tsx
    │   │   └── Header.tsx
    │   ├── editor/
    │   │   ├── PacketEditor.tsx
    │   │   ├── InterfaceEditor.tsx
    │   │   ├── RoutingEditor.tsx
    │   │   ├── PolicyRoutingEditor.tsx
    │   │   ├── NftablesEditor.tsx
    │   │   ├── IptablesEditor.tsx
    │   │   ├── XdpEditor.tsx
    │   │   └── YamlEditor.tsx
    │   ├── trace/
    │   │   ├── TraceTimeline.tsx
    │   │   ├── TraceStepCard.tsx
    │   │   ├── PacketStateView.tsx
    │   │   └── ExplainPanel.tsx
    │   └── import/
    │       ├── ImportForm.tsx
    │       ├── ImportPreview.tsx
    │       └── ValidationReport.tsx
    ├── hooks/
    │   ├── useSimulation.ts
    │   ├── useProject.ts
    │   └── useImport.ts
    └── lib/
        └── utils.ts              # 유틸리티 (cn 함수 등)
```

---

## 3. 페이지 구조 및 라우팅

| Route | Page | 설명 |
|-------|------|------|
| `/` | `ProjectListPage` | 프로젝트 목록, 생성, 삭제 |
| `/projects/:name` | `ScenarioEditorPage` | 시나리오 편집 + 시뮬레이션 실행 |
| `/projects/:name/result/:id` | `SimulationResultPage` | trace 결과 시각화 |
| `/projects/:name/import` | `ImportPage` | 시스템 설정 import |

React Router를 사용한다.

---

## 4. 레이아웃

```
┌──────────────────────────────────────────────────┐
│  Header (netsim 로고, 프로젝트 breadcrumb)        │
├──────────┬───────────────────────────────────────┤
│ Sidebar  │  Main Content Area                    │
│          │                                       │
│ • 프로젝트│  (현재 페이지 콘텐츠)                   │
│   목록   │                                       │
│ • 네비   │                                       │
│          │                                       │
├──────────┴───────────────────────────────────────┤
│  (상태바 - 선택적)                                 │
└──────────────────────────────────────────────────┘
```

`AppShell`이 Header, Sidebar, Main Content 영역을 조합한다.

---

## 5. 주요 페이지 상세

### 5.1 ProjectListPage

- 프로젝트 카드 그리드 또는 테이블
- 새 프로젝트 생성 다이얼로그
- 프로젝트 삭제/복제 기능
- 각 카드: 이름, 설명, 최종 수정일, 시뮬레이션 실행 횟수

### 5.2 ScenarioEditorPage

탭 기반 에디터:

```
┌───────────────────────────────────────────────────┐
│ [Packet] [Interfaces] [Routing] [Rules] [XDP] [YAML] │
├───────────────────────────────────────────────────┤
│                                                   │
│  (활성 탭의 에디터 콘텐츠)                          │
│                                                   │
├───────────────────────────────────────────────────┤
│  [Validate]  [Import]  [▶ Run Simulation]         │
└───────────────────────────────────────────────────┘
```

**Packet 탭**: 패킷 속성 폼 (ingress interface, src/dst IP, protocol, port, mark 등)
**Interfaces 탭**: 인터페이스 테이블 (추가/수정/삭제)
**Routing 탭**: ip rule 테이블 + routing table 별 route 테이블
**Rules 탭**: nftables/iptables 규칙 편집 (테이블 → 체인 → 규칙 계층 구조)
**XDP 탭**: 인터페이스별 XDP 프로그램 규칙
**YAML 탭**: 전체 시나리오 raw YAML 편집 (파워 유저용)

### 5.3 SimulationResultPage

```
┌───────────────────────────────────────────────────┐
│  Summary Card                                      │
│  Verdict: FORWARDED │ Egress: eth1                │
│  Next-hop: 192.168.1.254 │ NAT: SNAT applied     │
├───────────────────────────────────────────────────┤
│  Trace Timeline                                    │
│  ┌─[1] XDP ──── PASS ────────────────────┐        │
│  ├─[2] tc ingress ──── PASS ─────────────┤        │
│  ├─[3] conntrack ──── NEW ───────────────┤        │
│  ├─[4] PREROUTING ──── ACCEPT (DNAT) ───┤        │
│  ├─[5] Routing ──── FORWARD via eth1 ───┤        │
│  ├─[6] FORWARD ──── ACCEPT ─────────────┤        │
│  └─[7] POSTROUTING ──── ACCEPT (SNAT) ──┘        │
├───────────────────────────────────────────────────┤
│  Step Detail (선택된 단계)                          │
│  ┌─────────────┬──────────────┐                   │
│  │ State Before│ State After  │                   │
│  │ src: A      │ src: B  (◀) │                   │
│  │ dst: C      │ dst: C      │                   │
│  └─────────────┴──────────────┘                   │
│  Matched Rules: [table:chain rule#3]              │
│  Explain: "SNAT applied because..."               │
└───────────────────────────────────────────────────┘
```

**TraceTimeline**: 수직 스텝 리스트, 단계별 색상 코딩
**TraceStepCard**: 클릭 시 확장되는 상세 뷰
**PacketStateView**: before/after 나란히 표시, 변경된 필드 하이라이트
**ExplainPanel**: 자연어/구조화 설명

### 5.4 ImportPage

```
┌───────────────────────────────────────────────────┐
│  Import System Configuration                       │
├───────────────────────────────────────────────────┤
│  ┌─ ip addr output ────────────────────────┐      │
│  │  (textarea)                              │      │
│  └──────────────────────────────────────────┘      │
│  ┌─ ip rule output ────────────────────────┐      │
│  │  (textarea)                              │      │
│  └──────────────────────────────────────────┘      │
│  ┌─ ip route output ───────────────────────┐      │
│  │  (textarea)                              │      │
│  └──────────────────────────────────────────┘      │
│  ┌─ nft list ruleset ──────────────────────┐      │
│  │  (textarea)                              │      │
│  └──────────────────────────────────────────┘      │
│  ┌─ iptables-save ─────────────────────────┐      │
│  │  (textarea)                              │      │
│  └──────────────────────────────────────────┘      │
│  [Preview]  [Import to Project]                    │
├───────────────────────────────────────────────────┤
│  Validation Report                                 │
│  ✓ OK: 12 items │ ⚠ Partial: 2 │ ✕ Skip: 1      │
│  (상세 항목 리스트)                                 │
└───────────────────────────────────────────────────┘
```

파일 업로드 또는 텍스트 직접 입력 지원.

---

## 6. 컴포넌트 상세

### 6.1 Layout 컴포넌트

| 컴포넌트 | 역할 |
|---------|------|
| `AppShell` | 전체 레이아웃 프레임 (Header + Sidebar + Content) |
| `Header` | 로고, breadcrumb, 테마 토글 |
| `Sidebar` | 프로젝트 목록, 네비게이션 링크 |

### 6.2 Editor 컴포넌트

| 컴포넌트 | 역할 |
|---------|------|
| `PacketEditor` | 패킷 속성 폼 |
| `InterfaceEditor` | 인터페이스 CRUD 테이블 |
| `RoutingEditor` | 라우팅 테이블 관리 |
| `PolicyRoutingEditor` | ip rule CRUD 테이블 |
| `NftablesEditor` | nftables 규칙 계층 편집 |
| `IptablesEditor` | iptables 규칙 편집 |
| `XdpEditor` | XDP 프로그램 규칙 편집 |
| `YamlEditor` | raw YAML 편집 (코드 에디터) |

### 6.3 Trace 컴포넌트

| 컴포넌트 | 역할 |
|---------|------|
| `TraceTimeline` | 단계별 수직 타임라인 |
| `TraceStepCard` | 개별 단계 상세 카드 |
| `PacketStateView` | before/after 상태 비교 |
| `ExplainPanel` | 설명 패널 |

### 6.4 Import 컴포넌트

| 컴포넌트 | 역할 |
|---------|------|
| `ImportForm` | 명령어 출력 입력 폼 |
| `ImportPreview` | 파싱 결과 미리보기 |
| `ValidationReport` | 검증 결과 표시 |

---

## 7. API 클라이언트

`src/api/client.ts`에 fetch 기반 API 클라이언트를 구현한다.

```typescript
const API_BASE = '/api/v1';

export const api = {
  // Projects
  listProjects: () => get('/projects'),
  createProject: (data) => post('/projects', data),
  getProject: (name) => get(`/projects/${name}`),
  deleteProject: (name) => del(`/projects/${name}`),
  cloneProject: (name) => post(`/projects/${name}/clone`),

  // Scenario
  getScenario: (name) => get(`/projects/${name}/scenario`),
  saveScenario: (name, data) => put(`/projects/${name}/scenario`, data),
  validateScenario: (name, data) => post(`/projects/${name}/scenario/validate`, data),

  // Simulation
  runSimulation: (name) => post(`/projects/${name}/simulate`),
  getSimulation: (id) => get(`/simulations/${id}`),
  getTrace: (id) => get(`/simulations/${id}/trace`),

  // Import
  parseImport: (data) => post('/import/parse', data),
  previewImport: (data) => post('/import/preview', data),
  applyImport: (name, data) => post(`/projects/${name}/import`, data),
};
```

---

## 8. 커스텀 Hooks

| Hook | 역할 |
|------|------|
| `useProject` | 프로젝트 CRUD, 시나리오 로드/저장 |
| `useSimulation` | 시뮬레이션 실행, 결과 조회 |
| `useImport` | import 파싱, 미리보기, 적용 |
