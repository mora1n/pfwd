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

if command -v pfwd_die >/dev/null 2>&1; then
    guard_die()          { pfwd_die "$@"; }
    guard_require_cmd()  { pfwd_require_cmd "$@"; }
    guard_require_jq()   { pfwd_require_jq; }
    guard_now_iso()      { pfwd_now_iso; }
    guard_expand_path()  { pfwd_expand_path "$@"; }
    guard_write_atomic() { pfwd_write_atomic "$@"; }
    guard_run()          { pfwd_run "$@"; }
    guard_mkdirs()       { pfwd_mkdirs; }
else
    guard_die()          { rfwd_die "$@"; }
    guard_require_cmd()  { rfwd_require_cmd "$@"; }
    guard_require_jq()   { rfwd_require_jq; }
    guard_now_iso()      { rfwd_now_iso; }
    guard_expand_path()  { rfwd_expand_path "$@"; }
    guard_write_atomic() { rfwd_write_atomic "$@"; }
    guard_run()          { rfwd_run "$@"; }
    guard_mkdirs()       { rfwd_mkdirs; }
fi

guard_config_file() {
    printf '%s\n' "${PFWD_CONFIG_FILE:-$RFWD_CONFIG_FILE}"
}

guard_bin_path() {
    printf '%s\n' "$PFWD_XDP_BIN_PATH"
}

guard_status_file() {
    printf '%s\n' "${PFWD_XDP_STATUS_FILE:-${PFWD_GUARD_STATUS_FILE:-$RFWD_GUARD_STATUS_FILE}}"
}

guard_xdp_pin_path() {
    printf '%s\n' "${PFWD_GUARD_XDP_PIN_PATH:-$RFWD_GUARD_XDP_PIN_PATH}"
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
                echo "pfwd-xdp-linux-amd64"
            else
                echo "rfwd-guard-linux-amd64"
            fi
            ;;
        aarch64|arm64)
            if [ "$(guard_script_name)" = "pfwd" ]; then
                echo "pfwd-xdp-linux-arm64"
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

guard_xdp_mode() {
    jq -r '.settings.xdp.mode // .settings.guard.xdp_mode // "auto"' "$(guard_config_file)"
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

guard_read_settings() {
    jq -r '{enabled: (.settings.guard.enabled // false), xdp_mode: (.settings.xdp.mode // .settings.guard.xdp_mode // "auto"), block_http: (.settings.guard.block_http // false), block_tls: (.settings.guard.block_tls // false), block_socks: (.settings.guard.block_socks // false)}' "$(guard_config_file)"
}

guard_protocol_filters_enabled() {
    local settings
    settings="$(guard_read_settings)"
    if [ "$(jq -r '.block_http' <<< "$settings")" = "true" ] || [ "$(jq -r '.block_tls' <<< "$settings")" = "true" ] || [ "$(jq -r '.block_socks' <<< "$settings")" = "true" ]; then
        printf 'true\n'
    else
        printf 'false\n'
    fi
}

guard_runtime_config_hash() {
    local iface="$1"
    local ports_arg="$2"
    local settings
    settings="$(guard_read_settings)"
    local http tls socks xdp_mode
    xdp_mode="$(jq -r '.xdp_mode' <<< "$settings")"
    http="$(jq -r '.block_http' <<< "$settings")"
    tls="$(jq -r '.block_tls' <<< "$settings")"
    socks="$(jq -r '.block_socks' <<< "$settings")"
    local payload
    payload="$(cat <<EOF
iface=$iface
xdp_mode=$xdp_mode
http=$http
tls=$tls
socks=$socks
ports:
$ports_arg
EOF
)"
    printf '%s' "$payload" | cksum | awk '{print $1}'
}

guard_runtime_status_config_hash() {
    local status_file
    status_file="$(guard_status_file)"
    [ -f "$status_file" ] || return 0
    jq -r '.config_hash // empty' "$status_file" 2>/dev/null || true
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

guard_config_set_xdp_mode() {
    local mode="$1"
    case "$mode" in
        off|auto|force) ;;
        *) guard_die "无效 xdp 模式：$mode" ;;
    esac
    config_update --arg mode "$mode" '
      (.settings.guard //= {})
      | (.settings.xdp //= {})
      | .settings.guard.xdp_mode = $mode
      | .settings.xdp.mode = $mode
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

guard_active_ports_tsv() {
    guard_active_port_specs | cut -f1 | awk 'NF && !seen[$1]++ { print $1 }'
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
    guard_binary_exists || guard_die "缺少 XDP 预编译二进制：$(guard_bin_path)"

    if command -v whitelist_prepare_runtime >/dev/null 2>&1; then
        whitelist_prepare_runtime
    fi

    if [ "$(guard_enabled)" != "true" ]; then
        guard_remove_runtime "$quiet"
        return 0
    fi

    local iface
    iface="$(guard_tc_interface)"
    [ -n "$iface" ] || guard_die "无法确定 guard 网卡，请先设置 tc_interface"

    local ports_arg allow_any_ports config_hash current_hash
    ports_arg="$(guard_protocol_enforced_port_specs)"
    allow_any_ports="$(guard_active_ports_tsv)"
    if [ "$(guard_protocol_filters_enabled)" != "true" ] || [ -z "$ports_arg" ]; then
        guard_remove_runtime true
        if [ "$quiet" != "true" ]; then
            echo "guard 已跳过：当前没有生效的协议封锁端口"
        fi
        return 0
    fi

    config_hash="$(guard_runtime_config_hash "$iface" "$ports_arg")"
    current_hash="$(guard_runtime_status_config_hash)"
    if [ -n "$current_hash" ] && [ "$config_hash" = "$current_hash" ]; then
        if [ "$quiet" != "true" ]; then
            printf 'guard 已应用：iface=%s http=%s tls=%s socks=%s (unchanged)\n' \
              "$iface" "$(guard_block_http)" "$(guard_block_tls)" "$(guard_block_socks)"
        fi
        return 0
    fi

    local whitelist_state="false"
    local whitelist_files=""
    if command -v whitelist_enabled >/dev/null 2>&1; then
        whitelist_state="$(whitelist_enabled)"
    fi
    if [ "$whitelist_state" = "true" ]; then
        local v4_file="${PFWD_WHITELIST_ALLOW_IPV4_FILE:-}"
        local v6_file="${PFWD_WHITELIST_ALLOW_IPV6_FILE:-}"
        if [ -n "$v4_file" ] && [ -f "$v4_file" ]; then
            whitelist_files="$v4_file"
        fi
        if [ -n "$v6_file" ] && [ -f "$v6_file" ]; then
            whitelist_files="${whitelist_files:+$whitelist_files:}$v6_file"
        fi
    fi

    if command -v forwarder_apply_runtime >/dev/null 2>&1; then
        forwarder_apply_runtime
    fi

    if [ "$quiet" != "true" ]; then
        printf 'guard 已应用到 XDP 数据面：iface=%s http=%s tls=%s socks=%s\n' \
          "$iface" "$(guard_block_http)" "$(guard_block_tls)" "$(guard_block_socks)"
    fi
}

guard_remove_runtime() {
    local quiet="${1:-false}"
    if guard_binary_exists; then
        guard_run "$(guard_bin_path)" remove \
          --xdp-pin "$(guard_xdp_pin_path)" \
          --ingress-pin "$(guard_ingress_pin_path)" \
          --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" \
          --user-counter-pin "$PFWD_XDP_USER_COUNTER_PIN_PATH" \
          --stats-pin "$PFWD_XDP_STATS_PIN_PATH" \
          --status-file "$(guard_status_file)"
    else
        rm -f "$(guard_status_file)" 2>/dev/null || true
    fi
    rm -f "$(guard_xdp_pin_path)" "$(guard_ingress_pin_path)"
    if [ "$quiet" != "true" ]; then
        echo "guard 已移除"
    fi
}

guard_status_json() {
    config_init >/dev/null
    local runtime_status xdp_effective xdp_attach_kind xdp_reason
    runtime_status="$(guard_run "$(guard_bin_path)" status --status-file "$(guard_status_file)" 2>/dev/null || true)"
    xdp_effective="$(jq -r '.xdp_effective // "off"' <<< "${runtime_status:-{}}" 2>/dev/null || true)"
    xdp_attach_kind="$(jq -r '.xdp_attach_kind // "-"' <<< "${runtime_status:-{}}" 2>/dev/null || true)"
    xdp_reason="$(jq -r '.xdp_reason // empty' <<< "${runtime_status:-{}}" 2>/dev/null || true)"

    local settings skip_ports skip_count
    settings="$(guard_read_settings)"
    skip_ports="$(guard_protocol_skip_ports_display)"
    skip_count="$(guard_protocol_skip_ports_count)"

    local wl_enabled="false" wl_include_cn="false" wl_entries=0 wl_custom_count=0
    if command -v whitelist_enabled >/dev/null 2>&1; then
        wl_enabled="$(whitelist_enabled)"
        wl_include_cn="$(whitelist_include_cn)"
        wl_entries="$(whitelist_entry_count)"
        wl_custom_count="$(whitelist_custom_cidrs_count)"
    fi

    jq -n \
      --arg script "$(guard_script_name)" \
      --arg iface "$(guard_tc_interface)" \
      --arg bin "$(guard_bin_path)" \
      --arg status_file "$(guard_status_file)" \
      --arg xdp_pin "$(guard_xdp_pin_path)" \
      --arg ingress_pin "$(guard_ingress_pin_path)" \
      --arg xdp_mode "$(jq -r '.xdp_mode' <<< "$settings")" \
      --arg xdp_effective "$xdp_effective" \
      --arg xdp_attach_kind "$xdp_attach_kind" \
      --arg xdp_reason "$xdp_reason" \
      --argjson enabled "$(jq -r '.enabled' <<< "$settings")" \
      --argjson block_http "$(jq -r '.block_http' <<< "$settings")" \
      --argjson block_tls "$(jq -r '.block_tls' <<< "$settings")" \
      --argjson block_socks "$(jq -r '.block_socks' <<< "$settings")" \
      --arg protocol_skip_ports "$skip_ports" \
      --argjson protocol_skip_ports_count "$skip_count" \
      --argjson wl_enabled "$wl_enabled" \
      --argjson wl_include_cn "$wl_include_cn" \
      --argjson wl_entries "$wl_entries" \
      --argjson wl_custom_count "$wl_custom_count" \
      '{
        script: $script,
        enabled: $enabled,
        iface: $iface,
        xdp_mode: $xdp_mode,
        xdp_effective: $xdp_effective,
        xdp_attach_kind: $xdp_attach_kind,
        xdp_reason: $xdp_reason,
        block_http: $block_http,
        block_tls: $block_tls,
        block_socks: $block_socks,
        protocol_skip_ports: $protocol_skip_ports,
        protocol_skip_ports_count: $protocol_skip_ports_count,
        wl_enabled: $wl_enabled,
        wl_include_cn: $wl_include_cn,
        wl_entries: $wl_entries,
        wl_custom_count: $wl_custom_count,
        guard_binary: $bin,
        status_file: $status_file,
        xdp_pin: $xdp_pin,
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
        ["XDP 模式", .xdp_mode],
        ["XDP 实际状态", .xdp_effective],
        ["XDP 挂载", .xdp_attach_kind],
        ["封锁 HTTP", (if .block_http then "开" else "关" end)],
        ["封锁 TLS", (if .block_tls then "开" else "关" end)],
        ["封锁 SOCKS", (if .block_socks then "开" else "关" end)],
        ["跳过端口", .protocol_skip_ports],
        ["启用白名单", (if .wl_enabled then "开" else "关" end)],
        ["包含国内 IP", (if .wl_enabled then (if .wl_include_cn then "开" else "关" end) else "-" end)],
        ["自定义 CIDR", (.wl_custom_count | tostring)],
        ["白名单条目", (.wl_entries | tostring)],
        ["XDP Pin", .xdp_pin],
        ["XDP 二进制", .guard_binary],
        ["状态文件", .status_file]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}
