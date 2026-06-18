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
PFWD_RUNTIME_LOCK_FILE="${PFWD_RUNTIME_LOCK_FILE:-$PFWD_RUN_DIR/pfwd-runtime.lock}"
PFWD_INSTALL_DIR="${PFWD_INSTALL_DIR:-$(pfwd_path usr/local/lib/pfwd)}"
PFWD_BIN_PATH="${PFWD_BIN_PATH:-$(pfwd_path usr/local/bin/pfwd)}"
PFWD_BBR_BIN_PATH="${PFWD_BBR_BIN_PATH:-$(pfwd_path usr/local/bin/bbr.sh)}"
PFWD_BBR_ALIAS_BIN_PATH="${PFWD_BBR_ALIAS_BIN_PATH:-$(pfwd_path usr/local/bin/pfwd-bbr)}"
PFWD_SYSTEMD_DIR="${PFWD_SYSTEMD_DIR:-$(pfwd_path etc/systemd/system)}"
PFWD_CONFIG_FILE="${PFWD_CONFIG_FILE:-$PFWD_ETC_DIR/config.json}"
PFWD_STATS_FILE="${PFWD_STATS_FILE:-$PFWD_STATE_DIR/stats.json}"
PFWD_FORWARDER_RUNTIME_FILE="${PFWD_FORWARDER_RUNTIME_FILE:-$PFWD_RUN_DIR/runtime.json}"
PFWD_FORWARDER_XDP_RUNTIME_FILE="${PFWD_FORWARDER_XDP_RUNTIME_FILE:-$PFWD_RUN_DIR/runtime.xdp.json}"
PFWD_FORWARDER_NFT_RUNTIME_FILE="${PFWD_FORWARDER_NFT_RUNTIME_FILE:-$PFWD_RUN_DIR/runtime.nft.json}"
PFWD_FORWARDER_NFT_RENDER_FILE="${PFWD_FORWARDER_NFT_RENDER_FILE:-$PFWD_RUN_DIR/forwarder.nft}"
PFWD_FORWARDER_STATUS_FILE="${PFWD_FORWARDER_STATUS_FILE:-$PFWD_STATE_DIR/forwarder/status.json}"
PFWD_XDP_STATUS_FILE="${PFWD_XDP_STATUS_FILE:-$PFWD_STATE_DIR/xdp/status.json}"
PFWD_XDP_INDEX_FILE="${PFWD_XDP_INDEX_FILE:-$PFWD_STATE_DIR/xdp/indexes.json}"
PFWD_BBR_STATE_FILE="${PFWD_BBR_STATE_FILE:-$PFWD_STATE_DIR/bbr-state.env}"
PFWD_XDP_BIN_PATH="${PFWD_XDP_BIN_PATH:-$PFWD_INSTALL_DIR/bin/pfwd-xdp}"
PFWD_DOWNMASK_STATE_DIR="${PFWD_DOWNMASK_STATE_DIR:-$PFWD_STATE_DIR/downmask}"
PFWD_DOWNMASK_STATUS_FILE="${PFWD_DOWNMASK_STATUS_FILE:-$PFWD_DOWNMASK_STATE_DIR/status.json}"
PFWD_DOWNMASK_BIN_PATH="${PFWD_DOWNMASK_BIN_PATH:-$PFWD_INSTALL_DIR/bin/pfwd-downmask}"
if [ -z "${PFWD_ASSETS_DIR:-}" ]; then
    if [ -n "${PFWD_SCRIPT_DIR:-}" ] && [ -d "$PFWD_SCRIPT_DIR/assets" ]; then
        PFWD_ASSETS_DIR="$PFWD_SCRIPT_DIR/assets"
    else
        PFWD_ASSETS_DIR="$PFWD_INSTALL_DIR/assets"
    fi
fi
PFWD_GUARD_STATE_DIR="${PFWD_GUARD_STATE_DIR:-$PFWD_STATE_DIR/guard}"
PFWD_GUARD_STATUS_FILE="${PFWD_GUARD_STATUS_FILE:-$PFWD_GUARD_STATE_DIR/status.json}"
PFWD_XDP_LINK_PIN_PATH="${PFWD_XDP_LINK_PIN_PATH:-/sys/fs/bpf/pfwd_xdp_link}"
PFWD_XDP_INGRESS_PIN_PATH="${PFWD_XDP_INGRESS_PIN_PATH:-/sys/fs/bpf/pfwd_xdp_ingress}"
PFWD_XDP_HOST_EGRESS_PIN_PATH="${PFWD_XDP_HOST_EGRESS_PIN_PATH:-/sys/fs/bpf/pfwd_xdp_host_egress}"
PFWD_XDP_LOOPBACK_PIN_PATH="${PFWD_XDP_LOOPBACK_PIN_PATH:-/sys/fs/bpf/pfwd_xdp_loopback}"
PFWD_XDP_SK_LOOKUP_PIN_PATH="${PFWD_XDP_SK_LOOKUP_PIN_PATH:-/sys/fs/bpf/pfwd_xdp_sk_lookup}"
PFWD_XDP_SETTINGS_PIN_PATH="${PFWD_XDP_SETTINGS_PIN_PATH:-/sys/fs/bpf/pfwd_settings}"
PFWD_XDP_RULES_PIN_PATH="${PFWD_XDP_RULES_PIN_PATH:-/sys/fs/bpf/pfwd_rules}"
PFWD_XDP_CONNECTIONS_PIN_PATH="${PFWD_XDP_CONNECTIONS_PIN_PATH:-/sys/fs/bpf/pfwd_connections}"
PFWD_XDP_REVERSE_PIN_PATH="${PFWD_XDP_REVERSE_PIN_PATH:-/sys/fs/bpf/pfwd_reverse}"
PFWD_XDP_RULE_COUNTER_PIN_PATH="${PFWD_XDP_RULE_COUNTER_PIN_PATH:-/sys/fs/bpf/pfwd_rule_counters}"
PFWD_XDP_USER_COUNTER_PIN_PATH="${PFWD_XDP_USER_COUNTER_PIN_PATH:-/sys/fs/bpf/pfwd_user_counters}"
PFWD_XDP_STATS_PIN_PATH="${PFWD_XDP_STATS_PIN_PATH:-/sys/fs/bpf/pfwd_stats}"
PFWD_TC_INGRESS_PREF="${PFWD_TC_INGRESS_PREF:-20}"
PFWD_TC_BPF_INGRESS_PREF="${PFWD_TC_BPF_INGRESS_PREF:-10}"
PFWD_TC_IFB_DEV="${PFWD_TC_IFB_DEV:-ifb-pfwd0}"
PFWD_TC_STATE_FILE="${PFWD_TC_STATE_FILE:-$PFWD_STATE_DIR/tc.env}"
PFWD_XDP_WHITELIST_V4_PIN_PATH="${PFWD_XDP_WHITELIST_V4_PIN_PATH:-/sys/fs/bpf/pfwd_whitelist_v4}"
PFWD_XDP_WHITELIST_V6_PIN_PATH="${PFWD_XDP_WHITELIST_V6_PIN_PATH:-/sys/fs/bpf/pfwd_whitelist_v6}"
PFWD_XDP_WHITELIST_CACHE_V4_PIN_PATH="${PFWD_XDP_WHITELIST_CACHE_V4_PIN_PATH:-/sys/fs/bpf/pfwd_whitelist_cache_v4}"
PFWD_XDP_WHITELIST_CACHE_V6_PIN_PATH="${PFWD_XDP_WHITELIST_CACHE_V6_PIN_PATH:-/sys/fs/bpf/pfwd_whitelist_cache_v6}"
PFWD_XDP_EGRESS_WHITELIST_V4_PIN_PATH="${PFWD_XDP_EGRESS_WHITELIST_V4_PIN_PATH:-/sys/fs/bpf/pfwd_egress_whitelist_v4}"
PFWD_XDP_EGRESS_WHITELIST_V6_PIN_PATH="${PFWD_XDP_EGRESS_WHITELIST_V6_PIN_PATH:-/sys/fs/bpf/pfwd_egress_whitelist_v6}"
PFWD_XDP_EGRESS_WHITELIST_CACHE_V4_PIN_PATH="${PFWD_XDP_EGRESS_WHITELIST_CACHE_V4_PIN_PATH:-/sys/fs/bpf/pfwd_egress_whitelist_cache_v4}"
PFWD_XDP_EGRESS_WHITELIST_CACHE_V6_PIN_PATH="${PFWD_XDP_EGRESS_WHITELIST_CACHE_V6_PIN_PATH:-/sys/fs/bpf/pfwd_egress_whitelist_cache_v6}"
PFWD_XDP_ALLOWED_FLOWS_PIN_PATH="${PFWD_XDP_ALLOWED_FLOWS_PIN_PATH:-/sys/fs/bpf/pfwd_allowed_flows}"
PFWD_XDP_HOST_EGRESS_FLOWS_PIN_PATH="${PFWD_XDP_HOST_EGRESS_FLOWS_PIN_PATH:-/sys/fs/bpf/pfwd_host_egress_flows}"
PFWD_XDP_GUARD_PREFIXES_PIN_PATH="${PFWD_XDP_GUARD_PREFIXES_PIN_PATH:-/sys/fs/bpf/pfwd_guard_prefixes}"
PFWD_XDP_SKIP_PORTS_PIN_PATH="${PFWD_XDP_SKIP_PORTS_PIN_PATH:-/sys/fs/bpf/pfwd_protocol_skip_ports}"
PFWD_XDP_GEO_BUCKET_V4_PIN_PATH="${PFWD_XDP_GEO_BUCKET_V4_PIN_PATH:-/sys/fs/bpf/pfwd_geo_bucket_v4}"
PFWD_XDP_GEO_BUCKET_V6_PIN_PATH="${PFWD_XDP_GEO_BUCKET_V6_PIN_PATH:-/sys/fs/bpf/pfwd_geo_bucket_v6}"
PFWD_XDP_GEO_SEGMENTS_V4_PIN_PATH="${PFWD_XDP_GEO_SEGMENTS_V4_PIN_PATH:-/sys/fs/bpf/pfwd_geo_segments_v4}"
PFWD_XDP_GEO_SEGMENTS_V6_PIN_PATH="${PFWD_XDP_GEO_SEGMENTS_V6_PIN_PATH:-/sys/fs/bpf/pfwd_geo_segments_v6}"
PFWD_XDP_GEO_PROVINCE_POLICY_PIN_PATH="${PFWD_XDP_GEO_PROVINCE_POLICY_PIN_PATH:-/sys/fs/bpf/pfwd_geo_province_policy}"
PFWD_XDP_INGRESS_GEO_V4_PIN_PATH="${PFWD_XDP_INGRESS_GEO_V4_PIN_PATH:-/sys/fs/bpf/pfwd_ingress_geo_v4}"
PFWD_XDP_INGRESS_GEO_V6_PIN_PATH="${PFWD_XDP_INGRESS_GEO_V6_PIN_PATH:-/sys/fs/bpf/pfwd_ingress_geo_v6}"
PFWD_XDP_INGRESS_CITY_V4_PIN_PATH="${PFWD_XDP_INGRESS_CITY_V4_PIN_PATH:-/sys/fs/bpf/pfwd_ingress_city_v4}"
PFWD_XDP_INGRESS_POLICY_MODES_PIN_PATH="${PFWD_XDP_INGRESS_POLICY_MODES_PIN_PATH:-/sys/fs/bpf/pfwd_ingress_policy_modes}"
PFWD_XDP_INGRESS_POLICY_PROVINCES_PIN_PATH="${PFWD_XDP_INGRESS_POLICY_PROVINCES_PIN_PATH:-/sys/fs/bpf/pfwd_ingress_policy_provinces}"
PFWD_XDP_INGRESS_POLICY_CITIES_PIN_PATH="${PFWD_XDP_INGRESS_POLICY_CITIES_PIN_PATH:-/sys/fs/bpf/pfwd_ingress_policy_cities}"
PFWD_GUARD_XDP_PIN_PATH="${PFWD_GUARD_XDP_PIN_PATH:-$PFWD_XDP_LINK_PIN_PATH}"
PFWD_GUARD_LINK_INGRESS_PATH="${PFWD_GUARD_LINK_INGRESS_PATH:-$PFWD_XDP_INGRESS_PIN_PATH}"
PFWD_WHITELIST_STATE_DIR="${PFWD_WHITELIST_STATE_DIR:-$PFWD_STATE_DIR/whitelist}"
PFWD_WHITELIST_ALLOW_IPV4_FILE="${PFWD_WHITELIST_ALLOW_IPV4_FILE:-$PFWD_WHITELIST_STATE_DIR/allow_ipv4.txt}"
PFWD_WHITELIST_ALLOW_IPV6_FILE="${PFWD_WHITELIST_ALLOW_IPV6_FILE:-$PFWD_WHITELIST_STATE_DIR/allow_ipv6.txt}"
PFWD_WHITELIST_CITY_IPV4_FILE="${PFWD_WHITELIST_CITY_IPV4_FILE:-$PFWD_WHITELIST_STATE_DIR/city_ipv4.tsv}"
PFWD_EGRESS_WHITELIST_STATE_DIR="${PFWD_EGRESS_WHITELIST_STATE_DIR:-$PFWD_STATE_DIR/egress_whitelist}"
PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV4_FILE="${PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV4_FILE:-$PFWD_EGRESS_WHITELIST_STATE_DIR/host_allow_ipv4.txt}"
PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV6_FILE="${PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV6_FILE:-$PFWD_EGRESS_WHITELIST_STATE_DIR/host_allow_ipv6.txt}"
PFWD_SCRIPT_NAME="pfwd"
PFWD_XDP_DATAPLANE_VERSION="${PFWD_XDP_DATAPLANE_VERSION:-2}"
PFWD_XDP_MAP_ABI_VERSION="${PFWD_XDP_MAP_ABI_VERSION:-16}"
PFWD_LEASEWEB_CONFIG_FILE="${PFWD_LEASEWEB_CONFIG_FILE:-$PFWD_ETC_DIR/leaseweb.json}"
PFWD_LEASEWEB_BIN_PATH="${PFWD_LEASEWEB_BIN_PATH:-$PFWD_INSTALL_DIR/bin/pfwd-leaseweb}"
PFWD_LEASEWEB_STATE_DIR="${PFWD_LEASEWEB_STATE_DIR:-$PFWD_STATE_DIR/leaseweb}"
PFWD_WHITELIST_LEASES_FILE="${PFWD_WHITELIST_LEASES_FILE:-$PFWD_WHITELIST_STATE_DIR/leases.json}"
PFWD_WHITELIST_TEMP_ALLOW_IPV4_FILE="${PFWD_WHITELIST_TEMP_ALLOW_IPV4_FILE:-$PFWD_WHITELIST_STATE_DIR/temp_allow_ipv4.txt}"
PFWD_WHITELIST_TEMP_ALLOW_IPV6_FILE="${PFWD_WHITELIST_TEMP_ALLOW_IPV6_FILE:-$PFWD_WHITELIST_STATE_DIR/temp_allow_ipv6.txt}"

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
    if [ -n "${PFWD_TEST_NOW_ISO:-}" ]; then
        printf '%s\n' "$PFWD_TEST_NOW_ISO"
        return 0
    fi
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

pfwd_today() {
    if [ -n "${PFWD_TEST_TODAY:-}" ]; then
        printf '%s\n' "$PFWD_TEST_TODAY"
        return 0
    fi
    if [ -n "${PFWD_TEST_NOW_ISO:-}" ]; then
        printf '%s\n' "${PFWD_TEST_NOW_ISO%%T*}"
        return 0
    fi
    date '+%Y-%m-%d'
}

pfwd_now_minute() {
    if [ -n "${PFWD_TEST_NOW_ISO:-}" ]; then
        date -u -d "$PFWD_TEST_NOW_ISO" '+%Y-%m-%d %H:%M'
        return 0
    fi
    date '+%Y-%m-%d %H:%M'
}

pfwd_now_epoch() {
    if [ -n "${PFWD_TEST_NOW_EPOCH:-}" ]; then
        printf '%s\n' "$PFWD_TEST_NOW_EPOCH"
        return 0
    fi
    if [ -n "${PFWD_TEST_NOW_ISO:-}" ]; then
        date -u -d "$PFWD_TEST_NOW_ISO" '+%s'
        return 0
    fi
    date '+%s'
}

pfwd_parse_duration_seconds() {
    local raw="$1"
    local value unit seconds=0
    raw="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [ -n "$raw" ] || pfwd_die "时长不能为空"
    if [[ "$raw" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$raw"
        return 0
    fi
    if [[ "$raw" =~ ^([0-9]+)(s|m|h|d)$ ]]; then
        value="${BASH_REMATCH[1]}"
        unit="${BASH_REMATCH[2]}"
        case "$unit" in
            s) seconds="$value" ;;
            m) seconds=$((value * 60)) ;;
            h) seconds=$((value * 3600)) ;;
            d) seconds=$((value * 86400)) ;;
            *) pfwd_die "无效时长单位：$raw" ;;
        esac
        [ "$seconds" -ge 1 ] || pfwd_die "时长必须大于 0：$raw"
        printf '%s\n' "$seconds"
        return 0
    fi
    pfwd_die "无效时长：$raw；支持纯秒，或 30m/2h/1d"
}

pfwd_format_duration_seconds() {
    local seconds="$1"
    if [[ -z "$seconds" || ! "$seconds" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "-"
        return 0
    fi
    if [ "$seconds" -gt 0 ] && [ $((seconds % 86400)) -eq 0 ]; then
        printf '%sd\n' $((seconds / 86400))
    elif [ "$seconds" -gt 0 ] && [ $((seconds % 3600)) -eq 0 ]; then
        printf '%sh\n' $((seconds / 3600))
    elif [ "$seconds" -gt 0 ] && [ $((seconds % 60)) -eq 0 ]; then
        printf '%sm\n' $((seconds / 60))
    else
        printf '%ss\n' "$seconds"
    fi
}

pfwd_join_lines() {
    local delimiter="${1:-}"
    awk -v delimiter="$delimiter" '
      NF {
        if (seen) {
          printf "%s", delimiter
        }
        printf "%s", $0
        seen = 1
      }
      END {
        if (seen) {
          printf "\n"
        }
      }
    '
}

pfwd_normalize_minute_value() {
    local value="${1:-}"
    case "$value" in
        ""|"-"|"null") printf '' ;;
        ????-??-??)
            printf '%s 00:00' "$value"
            ;;
        ????/??/??)
            printf '%s 00:00' "${value//\//-}"
            ;;
        ????-??-??\ ??:??)
            printf '%s' "$value"
            ;;
        ????/??/??\ ??:??)
            printf '%s' "${value//\//-}"
            ;;
        ????????????)
            printf '%s-%s-%s %s:%s' "${value:0:4}" "${value:4:2}" "${value:6:2}" "${value:8:2}" "${value:10:2}"
            ;;
        ????????)
            printf '%s-%s-%s 00:00' "${value:0:4}" "${value:4:2}" "${value:6:2}"
            ;;
        *)
            printf '%s' "$value"
            ;;
    esac
}

pfwd_stop_at_expired() {
    local stop_at normalized now_minute
    stop_at="${1:-}"
    normalized="$(pfwd_normalize_minute_value "$stop_at")"
    [ -n "$normalized" ] || return 1
    now_minute="$(pfwd_now_minute)"
    [ "$normalized" \< "$now_minute" ] || [ "$normalized" = "$now_minute" ]
}

pfwd_mkdirs() {
    mkdir -p "$PFWD_ETC_DIR" "$PFWD_STATE_DIR" "$PFWD_RUN_DIR" "$PFWD_GUARD_STATE_DIR" "$(dirname "$PFWD_XDP_STATUS_FILE")" "$(dirname "$PFWD_XDP_INDEX_FILE")" "$(dirname "$PFWD_FORWARDER_STATUS_FILE")" "$PFWD_WHITELIST_STATE_DIR" "$PFWD_LEASEWEB_STATE_DIR" "$PFWD_DOWNMASK_STATE_DIR"
}

forwarder_bin_path() {
    if [ -x "$PFWD_XDP_BIN_PATH" ]; then
        printf '%s\n' "$PFWD_XDP_BIN_PATH"
        return 0
    fi
    local local_asset=""
    case "$(uname -m)" in
        x86_64|amd64) local_asset="$PFWD_ASSETS_DIR/pfwd-xdp-linux-amd64" ;;
        aarch64|arm64) local_asset="$PFWD_ASSETS_DIR/pfwd-xdp-linux-arm64" ;;
    esac
    if [ -n "$local_asset" ] && [ -x "$local_asset" ]; then
        printf '%s\n' "$local_asset"
        return 0
    fi
    printf '%s\n' "$PFWD_XDP_BIN_PATH"
}

pfwd_write_atomic() {
    local target="$1"
    local tmp
    mkdir -p "$(dirname "$target")"
    tmp="$(mktemp "${target}.tmp.XXXXXX")"
    cat > "$tmp"
    mv "$tmp" "$target"
}

pfwd_indexes_to_json() {
    local indexes="${1:-}"
    printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)'
}

pfwd_validate_indexes() {
    local label="$1"
    local indexes="$2"
    local count="$3"
    local raw

    [ -n "$indexes" ] || pfwd_die "缺少${label}序号"
    [ "$count" -gt 0 ] || pfwd_die "暂无${label}"
    while IFS= read -r raw; do
        [ -n "$raw" ] || continue
        [[ "$raw" =~ ^[0-9]+$ ]] || pfwd_die "${label}序号必须是正整数：$raw"
        [ "$raw" -ge 1 ] && [ "$raw" -le "$count" ] || pfwd_die "${label}序号不存在：$raw"
    done <<< "$indexes"
}

pfwd_with_runtime_lock() {
    local mode="${1:-wait}"
    shift || true
    [ "$#" -ge 1 ] || pfwd_die "pfwd_with_runtime_lock 需要命令"
    mkdir -p "$(dirname "$PFWD_RUNTIME_LOCK_FILE")"
    if [ "${PFWD_RUNTIME_LOCK_HELD:-0}" = "1" ]; then
        "$@"
        return
    fi
    case "$mode" in
        wait)
            (
                flock -x 9
                PFWD_RUNTIME_LOCK_HELD=1 "$@"
            ) 9>"$PFWD_RUNTIME_LOCK_FILE"
            ;;
        try)
            local status
            (
                flock -n -x 9 || exit 75
                PFWD_RUNTIME_LOCK_HELD=1 "$@"
            ) 9>"$PFWD_RUNTIME_LOCK_FILE"
            status=$?
            [ "$status" -ne 75 ] || return 75
            return "$status"
            ;;
        *)
            pfwd_die "未知运行态锁模式：$mode"
            ;;
    esac
}

pfwd_require_json_output() {
    local label="$1"
    local payload="${2:-}"
    [ -n "$payload" ] || pfwd_die "$label 未返回 JSON"
    jq -e . >/dev/null 2>&1 <<< "$payload" || pfwd_die "$label 返回非 JSON"
    printf '%s\n' "$payload"
}

pfwd_capture_json_output() {
    local label="$1"
    shift
    local payload=""
    if ! payload="$("$@")"; then
        pfwd_die "$label 失败"
    fi
    pfwd_require_json_output "$label" "$payload"
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

PFWD_DEBUG="${PFWD_DEBUG:-0}"

pfwd_debug() {
    [ "$PFWD_DEBUG" = "1" ] || return 0
    local ts
    ts="$(date '+%H:%M:%S' 2>/dev/null || echo '?')"
    printf '[DEBUG %s] %s\n' "$ts" "$*" >&2
}
