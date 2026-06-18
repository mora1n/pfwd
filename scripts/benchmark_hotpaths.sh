#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

export PFWD_ROOT_PREFIX="$TMP_DIR/root"
export PFWD_LIB_DIR="$ROOT_DIR/lib"
export PFWD_ASSETS_DIR="$ROOT_DIR/assets"
export PFWD_SKIP_SHORTCUT=1
export PFWD_TEST_NOW_ISO="2026-06-18T00:00:00Z"

"$ROOT_DIR/pfwd.sh" init >/dev/null

bench_one() {
    local label="$1"
    shift
    local loops="${PFWD_BENCH_LOOPS:-5}"
    local total_ms=0 max_ms=0 run_ms start_ns end_ns i
    for ((i = 1; i <= loops; i++)); do
        start_ns="$(date +%s%N)"
        "$@" >/dev/null
        end_ns="$(date +%s%N)"
        run_ms=$(( (end_ns - start_ns) / 1000000 ))
        total_ms=$((total_ms + run_ms))
        if [ "$run_ms" -gt "$max_ms" ]; then
            max_ms="$run_ms"
        fi
    done
    printf '%s\tavg=%sms\tmax=%sms\tloops=%s\n' "$label" "$((total_ms / loops))" "$max_ms" "$loops"
}

bench_one "hotpath.render_status" "$ROOT_DIR/pfwd.sh" render status
bench_one "hotpath.doctor" "$ROOT_DIR/pfwd.sh" doctor
bench_one "hotpath.doctor_bench" "$ROOT_DIR/pfwd.sh" doctor --bench
bench_one "hotpath.reconcile_reuse" "$ROOT_DIR/pfwd.sh" reconcile
