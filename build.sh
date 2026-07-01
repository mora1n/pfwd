#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${VERSION:-dev}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"

mkdir -p "$ROOT_DIR/dist"

clang -O2 -g -Wall -Werror -target bpfel -c "$ROOT_DIR/xdp/xdp.bpf.c" -o "$ROOT_DIR/xdp/xdp_bpfel.o"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o "$ROOT_DIR/dist/pfwd-linux-amd64" "$ROOT_DIR/cmd/pfwd"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$LDFLAGS" -o "$ROOT_DIR/dist/pfwd-linux-arm64" "$ROOT_DIR/cmd/pfwd"
