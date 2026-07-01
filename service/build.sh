#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/service"

mkdir -p "$ROOT_DIR/assets"
GOFLAGS="${GOFLAGS:-}" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$ROOT_DIR/assets/pfwd-service-linux-amd64" .
GOFLAGS="${GOFLAGS:-}" CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o "$ROOT_DIR/assets/pfwd-service-linux-arm64" .
