# Stage 1: Frontend build
FROM node:20-alpine AS frontend-builder
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

# Stage 2: Backend build
FROM rust:1.87-alpine AS backend-builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN cargo build --release --target x86_64-unknown-linux-musl -p netsim-server

# Stage 3: Runtime
FROM alpine:3.20
RUN adduser -D netsim
COPY --from=backend-builder /app/target/x86_64-unknown-linux-musl/release/netsim-server /app/netsim
COPY --from=frontend-builder /app/frontend/dist /app/ui
RUN mkdir -p /data/projects && chown -R netsim:netsim /data /app
USER netsim
EXPOSE 8080
ENV NETSIM_STATIC_DIR=/app/ui
ENV NETSIM_DATA_DIR=/data/projects
CMD ["/app/netsim"]
