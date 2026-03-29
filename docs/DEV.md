# netsim 빌드 및 실행 가이드

## 1. 사전 요구사항

- Rust 1.93+
- Node.js 20+
- ppnpm
- Docker (배포 시)

---

## 2. 프로젝트 구조

```
netsim/
├── Cargo.toml            # Rust workspace
├── crates/
│   ├── netsim-core/      # 시뮬레이션 엔진
│   ├── netsim-parser/    # 설정 파서
│   └── netsim-server/    # 웹 서버
├── frontend/             # React 프론트엔드
├── docs/                 # 설계 문서
└── Dockerfile
```

---

## 3. 로컬 개발

### 백엔드 실행

```bash
# 전체 빌드
cargo build

# 서버 실행 (port 8080)
cargo run -p netsim-server

# 테스트
cargo test

# 특정 crate 테스트
cargo test -p netsim-core
cargo test -p netsim-parser
cargo test -p netsim-server
```

환경 변수:
- `NETSIM_STATIC_DIR`: 프론트엔드 정적 파일 경로 (기본: `./frontend/dist`)
- `NETSIM_DATA_DIR`: 프로젝트 데이터 저장 경로 (기본: `./data/projects`)
- `NETSIM_PORT`: 서버 포트 (기본: `8080`)

### 프론트엔드 실행

```bash
cd frontend

# 의존성 설치
pnpm install

# 개발 서버 실행 (port 5173)
pnpm run dev

# 빌드
pnpm run build

# 린트
pnpm run lint

# 타입 체크
pnpm run typecheck
```

개발 서버는 `/api` 경로를 `http://localhost:8080`으로 프록시한다.

### 동시 실행 (개발)

터미널 1:
```bash
cargo run -p netsim-server
```

터미널 2:
```bash
cd frontend && pnpm run dev
```

브라우저에서 `http://localhost:5173` 접속.

---

## 4. Docker 빌드

```bash
# 이미지 빌드
docker build -t netsim .

# 컨테이너 실행
docker run -p 8080:8080 -v $(pwd)/data:/data netsim

# 브라우저에서 http://localhost:8080 접속
```

### Dockerfile 구조 (멀티스테이지)

1. **Stage 1**: Node.js 환경에서 프론트엔드 빌드
2. **Stage 2**: Rust 환경에서 백엔드 빌드 (musl target)
3. **Stage 3**: Alpine 기반 경량 런타임 이미지

---

## 5. 디렉토리 규칙

### 데이터 저장

```
data/projects/
├── <project-name>/
│   ├── project.yaml          # 프로젝트 메타데이터
│   ├── scenario.yaml         # 시나리오 정의
│   ├── imported-config.yaml  # import된 설정
│   └── results/
│       └── <uuid>.json       # 시뮬레이션 결과
```

Docker 실행 시 `/data` 볼륨 마운트로 데이터 영속화.

---

## 6. Workspace 설정

### Cargo.toml (root)

```toml
[workspace]
resolver = "2"
members = [
    "crates/netsim-core",
    "crates/netsim-parser",
    "crates/netsim-server",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
```

### Vite 설정 (frontend/vite.config.ts)

```typescript
export default defineConfig({
  server: {
    proxy: {
      '/api': 'http://localhost:8080'
    }
  }
})
```
