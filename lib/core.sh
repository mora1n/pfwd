#!/usr/bin/env bash

pfwd_root_prefix() {
    local prefix="${PFWD_ROOT_PREFIX:-/}"
    prefix="${prefix%/}"
    if [ -z "$prefix" ]; then
        echo ""
    else
        echo "$prefix"
    fi
}

pfwd_path() {
    local rel="$1"
    local prefix
    prefix="$(pfwd_root_prefix)"
    if [ -z "$prefix" ]; then
        echo "/$rel"
    else
        echo "$prefix/$rel"
    fi
}

PFWD_ETC_DIR="${PFWD_ETC_DIR:-$(pfwd_path etc/pfwd)}"
PFWD_STATE_DIR="${PFWD_STATE_DIR:-$(pfwd_path var/lib/pfwd)}"
PFWD_RUN_DIR="${PFWD_RUN_DIR:-$(pfwd_path run/pfwd)}"
PFWD_INSTALL_DIR="${PFWD_INSTALL_DIR:-$(pfwd_path usr/local/lib/pfwd)}"
PFWD_BIN_PATH="${PFWD_BIN_PATH:-$(pfwd_path usr/local/bin/pfwd)}"
PFWD_BBR_BIN_PATH="${PFWD_BBR_BIN_PATH:-$(pfwd_path usr/local/bin/bbr.sh)}"
PFWD_BBR_ALIAS_BIN_PATH="${PFWD_BBR_ALIAS_BIN_PATH:-$(pfwd_path usr/local/bin/pfwd-bbr)}"
PFWD_SYSTEMD_DIR="${PFWD_SYSTEMD_DIR:-$(pfwd_path etc/systemd/system)}"
PFWD_CONFIG_FILE="${PFWD_CONFIG_FILE:-$PFWD_ETC_DIR/config.json}"
PFWD_STATS_FILE="${PFWD_STATS_FILE:-$PFWD_STATE_DIR/stats.json}"
PFWD_FORWARDER_RUNTIME_FILE="${PFWD_FORWARDER_RUNTIME_FILE:-$PFWD_RUN_DIR/runtime.json}"
PFWD_FORWARDER_RENDER_FILE="${PFWD_FORWARDER_RENDER_FILE:-$PFWD_RUN_DIR/forwarder.nft}"
PFWD_BBR_STATE_FILE="${PFWD_BBR_STATE_FILE:-$PFWD_STATE_DIR/bbr-state.env}"
PFWD_GUARD_BIN_PATH="${PFWD_GUARD_BIN_PATH:-$PFWD_INSTALL_DIR/bin/pfwd-guard}"
PFWD_GUARD_STATE_DIR="${PFWD_GUARD_STATE_DIR:-$PFWD_STATE_DIR/guard}"
PFWD_GUARD_STATUS_FILE="${PFWD_GUARD_STATUS_FILE:-$PFWD_GUARD_STATE_DIR/status.json}"
PFWD_GUARD_WHITELIST_IPV4_FILE="${PFWD_GUARD_WHITELIST_IPV4_FILE:-$PFWD_GUARD_STATE_DIR/whitelist_ipv4.txt}"
PFWD_GUARD_LINK_INGRESS_PATH="${PFWD_GUARD_LINK_INGRESS_PATH:-/sys/fs/bpf/pfwd_guard_ingress}"
PFWD_GUARD_LINK_EGRESS_PATH="${PFWD_GUARD_LINK_EGRESS_PATH:-/sys/fs/bpf/pfwd_guard_egress}"
PFWD_SCRIPT_NAME="pfwd"

pfwd_die() {
    echo "错误：$*" >&2
    exit 1
}

pfwd_info() {
    echo "$*" >&2
}

pfwd_require_cmd() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || pfwd_die "缺少必需命令：$cmd"
}

pfwd_require_jq() {
    pfwd_require_cmd jq
}

pfwd_now_iso() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

pfwd_today() {
    date '+%Y-%m-%d'
}

pfwd_mkdirs() {
    mkdir -p "$PFWD_ETC_DIR" "$PFWD_STATE_DIR" "$PFWD_RUN_DIR" "$PFWD_GUARD_STATE_DIR"
}

pfwd_write_atomic() {
    local target="$1"
    local tmp
    tmp="$(mktemp "${target}.tmp.XXXXXX")"
    cat > "$tmp"
    mv "$tmp" "$target"
}

pfwd_run() {
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        local line="DRY-RUN:"
        local arg
        for arg in "$@"; do
            printf -v arg ' %q' "$arg"
            line+="$arg"
        done
        ui_emit_dry_run "$line"
        return 0
    fi
    "$@"
}

pfwd_is_root_prefix_real() {
    [ "$(pfwd_root_prefix)" = "" ]
}

pfwd_system_mutation_allowed() {
    [ "${PFWD_DRY_RUN:-0}" = "1" ] || pfwd_is_root_prefix_real
}

pfwd_json_escape() {
    jq -Rn --arg value "$1" '$value'
}

pfwd_id() {
    local prefix="${1:-id}"
    printf '%s-%s-%s\n' "$prefix" "$(date +%s)" "$RANDOM"
}

pfwd_expand_path() {
    local path="$1"
    case "$path" in
        "~")
            printf '%s\n' "${HOME:-$PWD}"
            ;;
        "~/"*)
            printf '%s/%s\n' "${HOME:-$PWD}" "${path#~/}"
            ;;
        *)
            printf '%s\n' "$path"
            ;;
    esac
}

pfwd_default_export_path() {
    local base
    base="$(pfwd_expand_path "${HOME:-$PWD}")"
    printf '%s/pfwd-export-%s.json\n' "${base%/}" "$(date '+%Y%m%d-%H%M%S')"
}

pfwd_file_checksum() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{print $1}'
    else
        cksum "$path" | awk '{print $1 "-" $2}'
    fi
}

pfwd_stdin_checksum() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
    else
        cksum | awk '{print $1 "-" $2}'
    fi
}

pfwd_version_compare() {
    local left="${1#v}"
    local right="${2#v}"
    local IFS=.
    local -a left_parts=() right_parts=()
    local i max left_value right_value

    read -r -a left_parts <<< "$left"
    read -r -a right_parts <<< "$right"
    max="${#left_parts[@]}"
    if [ "${#right_parts[@]}" -gt "$max" ]; then
        max="${#right_parts[@]}"
    fi

    for ((i = 0; i < max; i++)); do
        left_value="${left_parts[$i]:-0}"
        right_value="${right_parts[$i]:-0}"
        ((10#$left_value > 10#$right_value)) && { echo 1; return 0; }
        ((10#$left_value < 10#$right_value)) && { echo -1; return 0; }
    done

    echo 0
}

pfwd_configured_ports() {
    [ -f "$PFWD_CONFIG_FILE" ] || return 0
    jq -r '.forwards[]?.listen_port' "$PFWD_CONFIG_FILE"
}

pfwd_port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -H -tuln 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]$port$"
    else
        return 1
    fi
}

pfwd_pick_random_port() {
    local range="$1"
    local reserved="${2:-}"
    local start="${range%-*}"
    local end="${range#*-}"
    validate_port_range "$range"

    local span=$((end - start + 1))
    local configured
    configured="$(pfwd_configured_ports | tr '\n' ' ')"

    local i candidate
    for ((i = 0; i < span; i++)); do
        candidate=$((start + (RANDOM + i) % span))
        if [[ " $configured " == *" $candidate "* ]]; then
            continue
        fi
        if [[ " $reserved " == *" $candidate "* ]]; then
            continue
        fi
        if pfwd_port_in_use "$candidate"; then
            continue
        fi
        echo "$candidate"
        return 0
    done

    pfwd_die "端口范围内没有可用端口：$range"
}
