#!/usr/bin/env bash

guard_script_name() {
    if [ -n "${PFWD_SCRIPT_NAME:-}" ]; then
        printf '%s\n' "$PFWD_SCRIPT_NAME"
    else
        printf '%s\n' "${RFWD_SCRIPT_NAME:-guard}"
    fi
}

guard_repo_raw_url() {
    if [ -n "${PFWD_REPO_RAW_URL:-}" ]; then
        printf '%s\n' "$PFWD_REPO_RAW_URL"
    else
        printf '%s\n' "${RFWD_REPO_RAW_URL:-}"
    fi
}

guard_script_dir() {
    if [ -n "${PFWD_SCRIPT_DIR:-}" ]; then
        printf '%s\n' "$PFWD_SCRIPT_DIR"
    else
        printf '%s\n' "${RFWD_SCRIPT_DIR:-}"
    fi
}

guard_die() {
    if command -v pfwd_die >/dev/null 2>&1; then
        pfwd_die "$@"
    else
        rfwd_die "$@"
    fi
}

guard_require_cmd() {
    if command -v pfwd_require_cmd >/dev/null 2>&1; then
        pfwd_require_cmd "$1"
    else
        rfwd_require_cmd "$1"
    fi
}

guard_require_jq() {
    if command -v pfwd_require_jq >/dev/null 2>&1; then
        pfwd_require_jq
    else
        rfwd_require_jq
    fi
}

guard_now_iso() {
    if command -v pfwd_now_iso >/dev/null 2>&1; then
        pfwd_now_iso
    else
        rfwd_now_iso
    fi
}

guard_expand_path() {
    if command -v pfwd_expand_path >/dev/null 2>&1; then
        pfwd_expand_path "$1"
    else
        rfwd_expand_path "$1"
    fi
}

guard_write_atomic() {
    if command -v pfwd_write_atomic >/dev/null 2>&1; then
        pfwd_write_atomic "$1"
    else
        rfwd_write_atomic "$1"
    fi
}

guard_run() {
    if command -v pfwd_run >/dev/null 2>&1; then
        pfwd_run "$@"
    else
        rfwd_run "$@"
    fi
}

guard_mkdirs() {
    if command -v pfwd_mkdirs >/dev/null 2>&1; then
        pfwd_mkdirs
    else
        rfwd_mkdirs
    fi
}

guard_config_file() {
    printf '%s\n' "${PFWD_CONFIG_FILE:-$RFWD_CONFIG_FILE}"
}

guard_bin_path() {
    printf '%s\n' "${PFWD_GUARD_BIN_PATH:-$RFWD_GUARD_BIN_PATH}"
}

guard_status_file() {
    printf '%s\n' "${PFWD_GUARD_STATUS_FILE:-$RFWD_GUARD_STATUS_FILE}"
}

guard_ingress_pin_path() {
    printf '%s\n' "${PFWD_GUARD_LINK_INGRESS_PATH:-$RFWD_GUARD_LINK_INGRESS_PATH}"
}

guard_state_dir() {
    printf '%s\n' "${PFWD_GUARD_STATE_DIR:-$RFWD_GUARD_STATE_DIR}"
}

guard_asset_name() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)
            if [ "$(guard_script_name)" = "pfwd" ]; then
                echo "pfwd-guard-linux-amd64"
            else
                echo "rfwd-guard-linux-amd64"
            fi
            ;;
        aarch64|arm64)
            if [ "$(guard_script_name)" = "pfwd" ]; then
                echo "pfwd-guard-linux-arm64"
            else
                echo "rfwd-guard-linux-arm64"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

guard_local_asset_path() {
    local script_dir asset
    script_dir="$(guard_script_dir)"
    asset="$(guard_asset_name)" || return 1
    printf '%s/assets/%s\n' "$script_dir" "$asset"
}

guard_tc_interface() {
    local iface=""
    iface="$(jq -r '.settings.guard.tc_interface // empty' "$(guard_config_file)")"
    if [ -n "$iface" ] && [ "$iface" != "null" ]; then
        printf '%s\n' "$iface"
        return 0
    fi
    if command -v fw_tc_interface >/dev/null 2>&1; then
        fw_tc_interface
    else
        ip route show default 2>/dev/null | awk '{print $5; exit}'
    fi
}

guard_enabled() {
    jq -r '.settings.guard.enabled // false' "$(guard_config_file)"
}

guard_block_http() {
    jq -r '.settings.guard.block_http // false' "$(guard_config_file)"
}

guard_block_tls() {
    jq -r '.settings.guard.block_tls // false' "$(guard_config_file)"
}

guard_block_socks() {
    jq -r '.settings.guard.block_socks // false' "$(guard_config_file)"
}

guard_protocol_skip_ports_tsv() {
    jq -r '.settings.guard.protocol_skip_ports // [] | .[]' "$(guard_config_file)"
}

guard_protocol_skip_ports_count() {
    jq -r '.settings.guard.protocol_skip_ports // [] | length' "$(guard_config_file)"
}

guard_protocol_skip_ports_display() {
    local ports
    ports="$(guard_protocol_skip_ports_tsv | paste -sd, -)"
    if [ -n "$ports" ]; then
        printf '%s\n' "$ports"
    else
        printf '%s\n' "-"
    fi
}

guard_bool_to_json() {
    case "$1" in
        true) echo true ;;
        false) echo false ;;
        *) guard_die "无效布尔值：$1" ;;
    esac
}

guard_config_set_enabled() {
    validate_bool "$1"
    config_update --argjson enabled "$(guard_bool_to_json "$1")" '
      (.settings.guard //= {})
      | .settings.guard.enabled = $enabled
    '
}

guard_config_set_tc_interface() {
    local iface="$1"
    config_update --arg iface "$iface" '
      (.settings.guard //= {})
      | .settings.guard.tc_interface = $iface
    '
}

guard_config_set_protocols() {
    local http="$1"
    local tls="$2"
    local socks="$3"
    validate_bool "$http"
    validate_bool "$tls"
    validate_bool "$socks"
    config_update \
      --argjson http "$(guard_bool_to_json "$http")" \
      --argjson tls "$(guard_bool_to_json "$tls")" \
      --argjson socks "$(guard_bool_to_json "$socks")" '
      (.settings.guard //= {})
      | .settings.guard.block_http = $http
      | .settings.guard.block_tls = $tls
      | .settings.guard.block_socks = $socks
    '
}

guard_config_set_protocol_skip_ports() {
    local ports_file="$1"
    [ -f "$ports_file" ] || guard_die "协议封锁跳过端口临时文件不存在：$ports_file"
    while IFS= read -r port; do
        [ -n "$port" ] || continue
        validate_port "$port"
    done < "$ports_file"
    config_update --rawfile ports "$ports_file" '
      (.settings.guard //= {})
      | .settings.guard.protocol_skip_ports =
          (($ports
            | split("\n")
            | map(gsub("^\\s+|\\s+$"; ""))
            | map(select(length > 0) | tonumber)
            | unique))
    '
}

guard_active_port_specs() {
    local today
    today="$(pfwd_today)"
    jq -r --arg today "$today" '
      .forwards[]
      | select(.enabled == true and (.stop_at == null or .stop_at > $today))
      | [.listen_port, (.protocol // "tcp_udp")] | @tsv
    ' "$(guard_config_file)"
}

guard_protocol_enforced_port_specs() {
    local -A skipped=()
    local port protocol
    while IFS= read -r port; do
        [ -n "$port" ] || continue
        skipped["$port"]=1
    done < <(guard_protocol_skip_ports_tsv)

    while IFS=$'\t' read -r port protocol; do
        [ -n "$port" ] || continue
        [ -n "${skipped[$port]:-}" ] && continue
        printf '%s\t%s\n' "$port" "$protocol"
    done < <(guard_active_port_specs)
}

guard_binary_exists() {
    [ -x "$(guard_bin_path)" ]
}

guard_apply_runtime() {
    local quiet="${1:-false}"
    config_init >/dev/null
    guard_mkdirs
    guard_binary_exists || guard_die "缺少 guard 预编译二进制：$(guard_bin_path)"

    if [ "$(guard_enabled)" != "true" ]; then
        guard_remove_runtime "$quiet"
        return 0
    fi

    local iface
    iface="$(guard_tc_interface)"
    [ -n "$iface" ] || guard_die "无法确定 guard 网卡，请先设置 tc_interface"

    local ports_arg
    ports_arg="$(guard_protocol_enforced_port_specs)"

    guard_run "$(guard_bin_path)" apply \
      --iface "$iface" \
      --ingress-pin "$(guard_ingress_pin_path)" \
      --status-file "$(guard_status_file)" \
      --whitelist-enabled false \
      --allow-ports "$ports_arg" \
      --block-http "$(guard_block_http)" \
      --block-tls "$(guard_block_tls)" \
      --block-socks "$(guard_block_socks)"

    if [ "$quiet" != "true" ]; then
        printf 'guard 已应用：iface=%s http=%s tls=%s socks=%s\n' \
          "$iface" "$(guard_block_http)" "$(guard_block_tls)" "$(guard_block_socks)"
    fi
}

guard_remove_runtime() {
    local quiet="${1:-false}"
    local egress_pin=""
    if guard_binary_exists; then
        guard_run "$(guard_bin_path)" remove \
          --ingress-pin "$(guard_ingress_pin_path)" \
          --status-file "$(guard_status_file)"
    else
        rm -f "$(guard_status_file)" 2>/dev/null || true
    fi
    egress_pin="${PFWD_GUARD_LINK_EGRESS_PATH:-${RFWD_GUARD_LINK_EGRESS_PATH:-}}"
    rm -f "$(guard_ingress_pin_path)" ${egress_pin:+"$egress_pin"}
    if [ "$quiet" != "true" ]; then
        echo "guard 已移除"
    fi
}

guard_status_json() {
    config_init >/dev/null
    jq -n \
      --arg script "$(guard_script_name)" \
      --arg iface "$(guard_tc_interface)" \
      --arg bin "$(guard_bin_path)" \
      --arg status_file "$(guard_status_file)" \
      --arg ingress_pin "$(guard_ingress_pin_path)" \
      --argjson enabled "$(guard_bool_to_json "$(guard_enabled)")" \
      --argjson block_http "$(guard_bool_to_json "$(guard_block_http)")" \
      --argjson block_tls "$(guard_bool_to_json "$(guard_block_tls)")" \
      --argjson block_socks "$(guard_bool_to_json "$(guard_block_socks)")" \
      --arg protocol_skip_ports "$(guard_protocol_skip_ports_display)" \
      --argjson protocol_skip_ports_count "$(guard_protocol_skip_ports_count)" \
      '{
        script: $script,
        enabled: $enabled,
        iface: $iface,
        block_http: $block_http,
        block_tls: $block_tls,
        block_socks: $block_socks,
        protocol_skip_ports: $protocol_skip_ports,
        protocol_skip_ports_count: $protocol_skip_ports_count,
        guard_binary: $bin,
        status_file: $status_file,
        ingress_pin: $ingress_pin
      }'
}

guard_render_status() {
    local json
    json="$(guard_status_json)"
    jq -r '
      [
        ["启用状态", (if .enabled then "已启用" else "已停用" end)],
        ["绑定网卡", (.iface // "-")],
        ["封锁 HTTP", (if .block_http then "开" else "关" end)],
        ["封锁 TLS", (if .block_tls then "开" else "关" end)],
        ["封锁 SOCKS", (if .block_socks then "开" else "关" end)],
        ["跳过端口", .protocol_skip_ports],
        ["guard 二进制", .guard_binary],
        ["状态文件", .status_file]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}
