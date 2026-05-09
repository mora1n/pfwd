#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RFWD_DIR="${RFWD_DIR:-$ROOT_DIR/../realm-forward}"

cd "$SCRIPT_DIR"

clang -O2 -g -Wall -Werror -target bpfel -c guard.bpf.c -o guard_bpfel.o

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$ROOT_DIR/assets/pfwd-guard-linux-amd64" .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o "$ROOT_DIR/assets/pfwd-guard-linux-arm64" .

if [ -d "$RFWD_DIR" ]; then
    mkdir -p "$RFWD_DIR/assets"
    install -m 0755 "$ROOT_DIR/assets/pfwd-guard-linux-amd64" "$RFWD_DIR/assets/rfwd-guard-linux-amd64"
    install -m 0755 "$ROOT_DIR/assets/pfwd-guard-linux-arm64" "$RFWD_DIR/assets/rfwd-guard-linux-arm64"
fi
