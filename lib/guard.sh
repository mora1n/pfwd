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

guard_whitelist_file() {
    printf '%s\n' "${PFWD_GUARD_WHITELIST_IPV4_FILE:-$RFWD_GUARD_WHITELIST_IPV4_FILE}"
}

guard_ingress_pin_path() {
    printf '%s\n' "${PFWD_GUARD_LINK_INGRESS_PATH:-$RFWD_GUARD_LINK_INGRESS_PATH}"
}

guard_state_dir() {
    printf '%s\n' "${PFWD_GUARD_STATE_DIR:-$RFWD_GUARD_STATE_DIR}"
}

guard_default_source_url() {
    printf '%s\n' "https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone"
}

guard_validate_whitelist_mode() {
    case "$1" in
        off|cn|custom) ;;
        *) guard_die "无效白名单模式：$1" ;;
    esac
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

guard_fetch_url() {
    local url="$1"
    local target="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 --max-time 300 "$url" -o "$target"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$target" "$url"
    else
        guard_die "需要 curl 或 wget 下载白名单数据"
    fi
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

guard_whitelist_mode() {
    jq -r '.settings.guard.whitelist_mode // "off"' "$(guard_config_file)"
}

guard_whitelist_source_url() {
    jq -r --arg url "$(guard_default_source_url)" '.settings.guard.whitelist_source_url // $url' "$(guard_config_file)"
}

guard_whitelist_custom_file() {
    jq -r '.settings.guard.whitelist_file // ""' "$(guard_config_file)"
}

guard_whitelist_refresh_mode() {
    jq -r '.settings.guard.whitelist_refresh_mode // "manual"' "$(guard_config_file)"
}

guard_bool_to_json() {
    case "$1" in
        true) echo true ;;
        false) echo false ;;
        *) guard_die "无效布尔值：$1" ;;
    esac
}

guard_filter_ipv4_cidrs() {
    awk '
      function valid_octet(v) { return v ~ /^[0-9]+$/ && v >= 0 && v <= 255 }
      function valid_mask(v) { return v ~ /^[0-9]+$/ && v >= 0 && v <= 32 }
      /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ {
        split($0, a, /[.\/]/)
        if (valid_octet(a[1]) && valid_octet(a[2]) && valid_octet(a[3]) && valid_octet(a[4]) && valid_mask(a[5])) {
          print $0
        }
      }
    ' | sort -u
}

guard_store_whitelist_file() {
    local source_file="$1"
    local target_file
    target_file="$(guard_whitelist_file)"
    mkdir -p "$(dirname "$target_file")"
    guard_filter_ipv4_cidrs < "$source_file" | guard_write_atomic "$target_file"
    [ -s "$target_file" ] || guard_die "白名单为空：$source_file"
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

guard_config_set_whitelist() {
    local mode="$1"
    local source_url="$2"
    local file_path="$3"
    local refresh_mode="$4"
    guard_validate_whitelist_mode "$mode"
    [ -n "$source_url" ] || source_url="$(guard_default_source_url)"
    config_update \
      --arg mode "$mode" \
      --arg source_url "$source_url" \
      --arg file_path "$file_path" \
      --arg refresh_mode "$refresh_mode" '
      (.settings.guard //= {})
      | .settings.guard.whitelist_mode = $mode
      | .settings.guard.whitelist_source_url = $source_url
      | .settings.guard.whitelist_file = $file_path
      | .settings.guard.whitelist_refresh_mode = $refresh_mode
    '
}

guard_config_mark_last_good() {
    local source="$1"
    local updated_at="$2"
    config_update --arg source "$source" --arg updated_at "$updated_at" '
      (.settings.guard //= {})
      | .settings.guard.last_good_source = $source
      | .settings.guard.last_good_updated_at = $updated_at
    '
}

guard_refresh_cn_whitelist() {
    local url tmp
    url="$(guard_whitelist_source_url)"
    tmp="$(mktemp)"
    guard_fetch_url "$url" "$tmp"
    guard_store_whitelist_file "$tmp"
    rm -f "$tmp"
    guard_config_mark_last_good "$url" "$(guard_now_iso)"
}

guard_import_custom_whitelist() {
    local file_path="$1"
    [ -f "$file_path" ] || guard_die "白名单文件不存在：$file_path"
    guard_store_whitelist_file "$file_path"
    guard_config_mark_last_good "$file_path" "$(guard_now_iso)"
}

guard_prepare_whitelist() {
    local mode custom_file
    mode="$(guard_whitelist_mode)"
    case "$mode" in
        off)
            return 0
            ;;
        cn)
            if [ ! -s "$(guard_whitelist_file)" ]; then
                guard_refresh_cn_whitelist
            fi
            ;;
        custom)
            custom_file="$(guard_whitelist_custom_file)"
            [ -n "$custom_file" ] || guard_die "自定义白名单模式缺少文件路径"
            if [ ! -s "$(guard_whitelist_file)" ]; then
                guard_import_custom_whitelist "$custom_file"
            fi
            ;;
    esac
}

guard_binary_exists() {
    [ -x "$(guard_bin_path)" ]
}

guard_runtime_enabled() {
    case "$(guard_whitelist_mode)" in
        off) echo false ;;
        *) echo true ;;
    esac
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

    local iface whitelist_enabled
    iface="$(guard_tc_interface)"
    [ -n "$iface" ] || guard_die "无法确定 guard 网卡，请先设置 tc_interface"
    guard_prepare_whitelist
    whitelist_enabled="$(guard_runtime_enabled)"

    guard_run "$(guard_bin_path)" apply \
      --iface "$iface" \
      --ingress-pin "$(guard_ingress_pin_path)" \
      --status-file "$(guard_status_file)" \
      --whitelist-file "$(guard_whitelist_file)" \
      --whitelist-enabled "$whitelist_enabled" \
      --block-http "$(guard_block_http)" \
      --block-tls "$(guard_block_tls)" \
      --block-socks "$(guard_block_socks)"

    if [ "$quiet" != "true" ]; then
        printf 'guard 已应用：iface=%s whitelist=%s http=%s tls=%s socks=%s\n' \
          "$iface" "$whitelist_enabled" "$(guard_block_http)" "$(guard_block_tls)" "$(guard_block_socks)"
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
    rm -f "$(guard_whitelist_file)" 2>/dev/null || true
    if [ "$quiet" != "true" ]; then
        echo "guard 已移除"
    fi
}

guard_whitelist_entry_count() {
    if [ -s "$(guard_whitelist_file)" ]; then
        sed '/^$/d' "$(guard_whitelist_file)" | wc -l | tr -d ' '
    else
        echo 0
    fi
}

guard_status_json() {
    config_init >/dev/null
    jq -n \
      --arg script "$(guard_script_name)" \
      --arg iface "$(guard_tc_interface)" \
      --arg bin "$(guard_bin_path)" \
      --arg mode "$(guard_whitelist_mode)" \
      --arg source_url "$(guard_whitelist_source_url)" \
      --arg custom_file "$(guard_whitelist_custom_file)" \
      --arg refresh_mode "$(guard_whitelist_refresh_mode)" \
      --arg whitelist_file "$(guard_whitelist_file)" \
      --arg status_file "$(guard_status_file)" \
      --arg ingress_pin "$(guard_ingress_pin_path)" \
      --argjson enabled "$(guard_bool_to_json "$(guard_enabled)")" \
      --argjson block_http "$(guard_bool_to_json "$(guard_block_http)")" \
      --argjson block_tls "$(guard_bool_to_json "$(guard_block_tls)")" \
      --argjson block_socks "$(guard_bool_to_json "$(guard_block_socks)")" \
      --argjson whitelist_entries "$(guard_whitelist_entry_count)" \
      '{
        script: $script,
        enabled: $enabled,
        iface: $iface,
        block_http: $block_http,
        block_tls: $block_tls,
        block_socks: $block_socks,
        whitelist_mode: $mode,
        whitelist_source_url: $source_url,
        whitelist_custom_file: $custom_file,
        whitelist_refresh_mode: $refresh_mode,
        whitelist_file: $whitelist_file,
        whitelist_entries: $whitelist_entries,
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
        ["白名单模式", .whitelist_mode],
        ["白名单来源", .whitelist_source_url],
        ["自定义文件", (if .whitelist_custom_file == "" then "-" else .whitelist_custom_file end)],
        ["白名单条目", (.whitelist_entries | tostring)],
        ["guard 二进制", .guard_binary],
        ["状态文件", .status_file]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}
