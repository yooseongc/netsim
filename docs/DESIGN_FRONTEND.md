# netsim 프론트엔드 설계안

## 1. 개요

netsim 프론트엔드는 React + TypeScript + Vite 기반으로 구현되며, Tailwind CSS + Lucide React 아이콘을 사용한다.
네트워크 토폴로지는 @xyflow/react (React Flow) 캔버스, 자동 레이아웃은 @dagrejs/dagre를 사용한다.
상태 관리는 React hooks + Context API로 처리한다.

---

## 2. 디렉토리 구조

```
frontend/
├── package.json
├── tsconfig.json / tsconfig.app.json / tsconfig.node.json
├── vite.config.ts
├── tailwind.config.ts
├── index.html
└── src/
    ├── main.tsx                   # React 엔트리포인트 (BrowserRouter)
    ├── App.tsx                    # 라우트 정의
    ├── index.css                  # Tailwind 디렉티브
    ├── api/
    │   └── client.ts              # fetch 기반 API 클라이언트 (타입 세이프)
    ├── types/
    │   ├── scenario.ts            # Scenario IR 타입 (Rust serde 미러)
    │   ├── trace.ts               # 시뮬레이션 결과/트레이스 타입
    │   └── project.ts             # 프로젝트 메타데이터 타입
    ├── pages/
    │   ├── ProjectListPage.tsx    # 프로젝트 목록/생성/삭제
    │   ├── ScenarioEditorPage.tsx  # 7탭 시나리오 에디터 + Save/Run
    │   ├── SampleViewerPage.tsx   # 샘플 뷰어 (7탭, 읽기전용 + Run + Copy)
    │   ├── SimulationResultPage.tsx # 트레이스 결과 (레거시, 다이얼로그로 대체)
    │   └── ImportPage.tsx          # 시스템 설정 import
    ├── components/
    │   ├── layout/
    │   │   └── AppShell.tsx        # Header + Sidebar(PROJECTS/SAMPLES) + Content
    │   ├── editors/
    │   │   ├── PacketEditor.tsx    # L2/L3/L4/Conntrack 패킷 속성 폼
    │   │   ├── InterfacesEditor.tsx # Interface CRUD + 주소/가상관계 관리
    │   │   ├── RoutingEditor.tsx   # RoutingTable + Route CRUD + IP Rule 편집
    │   │   ├── RulesEditor.tsx     # nftables 테이블→체인→규칙 3단계 CRUD
    │   │   └── XdpEditor.tsx       # XDP 프로그램 + 규칙(매치+액션) 편집
    │   ├── topology/
    │   │   ├── TopologyEditor.tsx  # TopologyCanvas 래퍼 (props 전달)
    │   │   ├── TopologyCanvas.tsx  # React Flow 캔버스 메인 (노드/엣지/리플레이)
    │   │   ├── TopologyToolbar.tsx # Add Endpoint + Auto Layout 도구
    │   │   ├── TopologyPropertiesPanel.tsx # 선택 노드/엣지 속성 패널
    │   │   ├── SimulationReplayBar.tsx    # 시뮬레이션 리플레이 컨트롤 바
    │   │   ├── useTopologyGraph.ts # Topology ↔ React Flow 변환
    │   │   ├── useAutoLayout.ts   # dagre 자동 레이아웃
    │   │   ├── EndpointForm.tsx    # 엔드포인트 추가/편집 모달
    │   │   ├── FlowForm.tsx        # 트래픽 플로우 추가/편집 모달
    │   │   ├── nodes/
    │   │   │   ├── DeviceNode.tsx  # 장비 경계 group 노드 (Linux Host)
    │   │   │   ├── InterfaceNode.tsx # 인터페이스 노드 (name, IP, MTU, state)
    │   │   │   └── EndpointNode.tsx  # 엔드포인트 노드 (역할별 색상/아이콘)
    │   │   └── edges/
    │   │       └── FlowEdge.tsx    # 트래픽 플로우 엣지 (이름+프로토콜 뱃지)
    │   └── trace/
    │       ├── SimulationResultDialog.tsx # 결과 다이얼로그 (Summary + PipelineFlow)
    │       ├── PipelineFlow.tsx    # 트레이스 수직 타임라인
    │       ├── TraceStepCard.tsx   # 개별 단계 상세 카드
    │       ├── StateDiffView.tsx   # before/after 상태 비교
    │       └── VerdictBadge.tsx    # verdict/decision 색상 뱃지
    ├── contexts/
    │   └── SimulationContext.tsx   # 시뮬레이션 결과 공유용 React Context
    └── lib/
        └── utils.ts               # cn() 유틸리티 (clsx + tailwind-merge)
```

---

## 3. 라우팅

| Route | Page | 설명 |
|-------|------|------|
| `/` | `ProjectListPage` | 프로젝트 목록, 생성, 삭제 |
| `/projects/:name` | `ScenarioEditorPage` | 7탭 시나리오 에디터 + 시뮬레이션 실행 |
| `/projects/:name/result` | `SimulationResultPage` | 트레이스 결과 (레거시) |
| `/projects/:name/import` | `ImportPage` | 시스템 설정 import |
| `/samples/:name` | `SampleViewerPage` | 샘플 뷰어 (읽기전용 7탭) |

React Router v7 (BrowserRouter) 사용.

---

## 4. 레이아웃

```
┌──────────────────────────────────────────────────┐
│  Header (netsim 로고 + breadcrumb)                │
├──────────┬───────────────────────────────────────┤
│ Sidebar  │  Main Content Area                    │
│          │                                       │
│ PROJECTS │  (현재 페이지 콘텐츠)                   │
│  ▾ proj1 │                                       │
│  ▾ proj2 │                                       │
│          │                                       │
│ SAMPLES  │                                       │
│  ▾ basic │                                       │
│  ▾ dnat  │                                       │
└──────────┴───────────────────────────────────────┘
```

- `AppShell`: Header + Sidebar(PROJECTS/SAMPLES 접이식) + Main Content
- Sidebar: 사용자 프로젝트 목록 + 내장 샘플 12개

---

## 5. 주요 페이지 상세

### 5.1 ProjectListPage

- 프로젝트 카드 그리드 레이아웃
- 새 프로젝트 생성 다이얼로그 (이름 + 설명)
- 프로젝트 삭제 기능
- 각 카드 클릭 → ScenarioEditorPage로 이동

### 5.2 ScenarioEditorPage

7개 탭 기반 에디터. Topology 탭이 기본(첫 번째):

```
┌────────────────────────────────────────────────────────────────┐
│ [Topology] [Packet] [Interfaces] [Routing] [Rules] [XDP] [YAML] │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──── Linux Host (Device Boundary) ─────────────────────┐    │
│  │ [eth0: 10.0.0.1/24]      [eth1: 192.168.1.1/24]     │    │
│  │                                                       │    │
│  │  [Local Client]            [Local Server]            │    │
│  └───────────────────────────────────────────────────────┘    │
│  [Remote Client] ──flow──▶              ◀── [Remote Server]  │
│                                                                │
│  ┌─ Replay Bar ──────────────────────────────────────────┐    │
│  │ ◀ ▶ ▶▶ │ 1x │ 3/9 │ PREROUTING │ CONTINUE │ ...     │    │
│  └────────────────────────────────────────────────────────┘    │
├────────────────────────────────────────────────────────────────┤
│  [Save]  [Import]  [▶ Run Simulation]                          │
└────────────────────────────────────────────────────────────────┘
```

**Topology 탭 (React Flow 캔버스):**
- DeviceNode: 장비 경계 (group 노드, 점선 사각형)
- InterfaceNode: 인터페이스 포트 (장비 내부, 상단 배치)
- EndpointNode: Local은 장비 내부, Remote는 장비 외부
- FlowEdge: 트래픽 플로우 (애니메이션 화살표)
- TopologyToolbar: Add Endpoint (Inside/Outside 구분) + Auto Layout
- TopologyPropertiesPanel: 선택 항목 속성 (우측 슬라이드)
- SimulationReplayBar: Play/Pause/Step + 속도 조절 + 단계별 하이라이트

**시뮬레이션 리플레이:**
- Run 후 자동으로 Topology 탭 전환
- 단계별 노드/엣지 하이라이트 (ingress=파랑, device=보라, egress=노랑)
- 최종: Drop=빨강, Local Delivery=초록, Forwarded → egress 표시
- SimulationResultDialog: 다른 탭에서는 모달 다이얼로그로 결과 표시

**나머지 탭:**

| 탭 | 컴포넌트 | 역할 |
|----|---------|------|
| Packet | `PacketEditor` | L2/L3/L4/Conntrack 폼. 프로토콜별 조건부 필드 |
| Interfaces | `InterfacesEditor` | CRUD + 랜덤 IP/MAC 초기값 자동 생성 |
| Routing | `RoutingEditor` | RoutingTable + Route + IP Rule |
| Rules | `RulesEditor` | nftables 테이블→체인→규칙 3단계 |
| XDP | `XdpEditor` | XDP 프로그램 + 규칙 |
| YAML | textarea | raw YAML 편집 (파워 유저) |

### 5.3 SampleViewerPage

- ScenarioEditorPage와 동일한 7탭 UI (읽기전용)
- Save 대신 **Copy to Project** 버튼
- Run → 토폴로지 리플레이 / 다이얼로그 결과

### 5.4 ImportPage

- 5개 textarea (ip addr, ip rule, ip route, nft list ruleset, iptables-save)
- Preview → ValidationReport (parsed_ok/partial/unsupported)
- Import to Project (replace/merge 전략)

---

## 6. 캔버스 노드 타입

### DeviceNode (장비 경계)
- React Flow group 노드, 점선 사각형 경계
- 헤더: 장비명 + 인터페이스/라우트/규칙 수 요약
- 내부에 InterfaceNode, Local EndpointNode 포함 (parentId)
- 크기: 내부 노드 수에 따라 동적 계산

### InterfaceNode (네트워크 인터페이스)
- 140px 너비, indigo 테마
- 이름, IP 주소, MTU, 상태(UP/DN), 종류(veth, bridge 등)
- parentId: DEVICE → 장비 내부, extent: parent

### EndpointNode (엔드포인트)
- 160px 너비, 역할별 색상 6종
- Local roles (local_client/server/proxy/tproxy): parentId: DEVICE → 내부
- Remote roles (remote_client/server): 외부 배치

### FlowEdge (트래픽 플로우)
- 애니메이션 화살표, 프로토콜 뱃지 + 플로우명 라벨
- Endpoint 간 연결

---

## 7. 상태 관리

- `Scenario` 객체를 중앙 상태로 유지 (ScenarioEditorPage)
- 구조화된 탭 → Scenario 업데이트 → YAML 자동 직렬화
- YAML 편집 → 탭 전환 시 파싱 → Scenario 업데이트
- 시뮬레이션 결과는 페이지 내 state로 관리 (다이얼로그/리플레이)
- SimulationContext: 레거시 결과 페이지용 Context

---

## 8. API 클라이언트

```typescript
export const api = {
  // Projects
  listProjects, createProject, getProject, updateProject, deleteProject, cloneProject,
  // Scenario
  getScenario, getScenarioYaml, saveScenario, saveScenarioYaml, validateScenario,
  // Simulation
  runSimulation, getSimulation,
  // Samples (내장, 파일시스템 미사용)
  listSamples, getSample, simulateSample,
  // Import
  parseImport, applyImport,
};
```

---

## 9. 의존성

| 패키지 | 용도 |
|--------|------|
| `react` + `react-dom` | UI 프레임워크 |
| `react-router-dom` | 클라이언트 라우팅 |
| `@xyflow/react` | React Flow 캔버스 (노드/엣지 그래프) |
| `@dagrejs/dagre` | 자동 레이아웃 알고리즘 |
| `js-yaml` | YAML ↔ JSON 양방향 변환 |
| `lucide-react` | 아이콘 |
| `tailwindcss` | 유틸리티 CSS |
| `clsx` + `tailwind-merge` | 조건부 클래스 병합 (`cn()`) |
| `vite` | 빌드 도구 |
| `typescript` | 타입 시스템 |

패키지 매니저: **pnpm**
