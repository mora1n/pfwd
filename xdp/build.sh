#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pfwd-xdp-build.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

cd "$SCRIPT_DIR"

install_if_changed() {
    local source="$1"
    local target="$2"
    local mode="$3"
    if [ -f "$target" ] && cmp -s "$source" "$target"; then
        chmod "$mode" "$target"
        return 0
    fi
    install -m "$mode" "$source" "$target"
}

clang -O2 -g -Wall -Werror -target bpfel -c xdp.bpf.c -o "$BUILD_DIR/xdp_bpfel.o"
install_if_changed "$BUILD_DIR/xdp_bpfel.o" xdp_bpfel.o 0644

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -buildid=" -o "$BUILD_DIR/pfwd-xdp-linux-amd64" .
install_if_changed "$BUILD_DIR/pfwd-xdp-linux-amd64" "$ROOT_DIR/assets/pfwd-xdp-linux-amd64" 0755

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -buildid=" -o "$BUILD_DIR/pfwd-xdp-linux-arm64" .
install_if_changed "$BUILD_DIR/pfwd-xdp-linux-arm64" "$ROOT_DIR/assets/pfwd-xdp-linux-arm64" 0755
