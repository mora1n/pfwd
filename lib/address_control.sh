#!/usr/bin/env bash

address_control_default_source_url() {
    printf '%s\n' "https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone"
}

address_control_state_dir() {
    printf '%s\n' "$PFWD_ADDRESS_CONTROL_STATE_DIR"
}

address_control_allow_file() {
    printf '%s\n' "$PFWD_ADDRESS_CONTROL_ALLOW_IPV4_FILE"
}

address_control_mode() {
    jq -r '.settings.address_control.mode // "off"' "$PFWD_CONFIG_FILE"
}

address_control_source_url() {
    jq -r --arg url "$(address_control_default_source_url)" '.settings.address_control.source_url // $url' "$PFWD_CONFIG_FILE"
}

address_control_custom_file() {
    jq -r '.settings.address_control.file // ""' "$PFWD_CONFIG_FILE"
}

address_control_entry_count() {
    if [ -s "$(address_control_allow_file)" ]; then
        sed '/^$/d' "$(address_control_allow_file)" | wc -l | tr -d ' '
    else
        echo 0
    fi
}

address_control_filter_ipv4_cidrs() {
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

address_control_write_allow_file() {
    local source_file="$1"
    local target_file
    target_file="$(address_control_allow_file)"
    mkdir -p "$(dirname "$target_file")"
    address_control_filter_ipv4_cidrs < "$source_file" | pfwd_write_atomic "$target_file"
    [ -s "$target_file" ] || pfwd_die "地址访问控制目标集合为空：$source_file"
}

address_control_mark_last_good() {
    local source="$1"
    local updated_at="$2"
    config_update --arg source "$source" --arg updated_at "$updated_at" '
      (.settings.address_control //= {})
      | .settings.address_control.last_good_source = $source
      | .settings.address_control.last_good_updated_at = $updated_at
    '
}

address_control_config_set() {
    local mode="$1"
    local source_url="$2"
    local file_path="$3"
    validate_address_control_mode "$mode"
    [ -n "$source_url" ] || source_url="$(address_control_default_source_url)"
    config_update \
      --arg mode "$mode" \
      --arg source_url "$source_url" \
      --arg file_path "$file_path" '
      (.settings.address_control //= {})
      | .settings.address_control.mode = $mode
      | .settings.address_control.source_url = $source_url
      | .settings.address_control.file = $file_path
    '
}

address_control_refresh_cn() {
    local url tmp
    url="$(address_control_source_url)"
    tmp="$(mktemp)"
    pfwd_bootstrap_download "$url" "$tmp"
    address_control_write_allow_file "$tmp"
    rm -f "$tmp"
    address_control_mark_last_good "$url" "$(pfwd_now_iso)"
}

address_control_import_local_cn_seed() {
    local file_path="$PFWD_INSTALL_DIR/assets/cn-aggregated.zone"
    [ -f "$file_path" ] || return 1
    address_control_write_allow_file "$file_path"
    address_control_mark_last_good "$file_path" "$(pfwd_now_iso)"
}

address_control_sync_cn() {
    if ! address_control_import_local_cn_seed; then
        address_control_refresh_cn
    fi
}

address_control_import_custom() {
    local file_path="$1"
    [ -f "$file_path" ] || pfwd_die "地址访问控制文件不存在：$file_path"
    address_control_write_allow_file "$file_path"
    address_control_mark_last_good "$file_path" "$(pfwd_now_iso)"
}

address_control_sync_lan() {
    local tmp
    tmp="$(mktemp)"
    cat > "$tmp" <<'EOF'
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
EOF
    address_control_write_allow_file "$tmp"
    rm -f "$tmp"
    address_control_mark_last_good "built-in:lan" "$(pfwd_now_iso)"
}

address_control_prepare_runtime() {
    local mode custom_file
    mode="$(address_control_mode)"
    case "$mode" in
        off)
            rm -f "$(address_control_allow_file)" 2>/dev/null || true
            ;;
        lan)
            if [ ! -s "$(address_control_allow_file)" ]; then
                address_control_sync_lan
            fi
            ;;
        cn)
            if [ ! -s "$(address_control_allow_file)" ]; then
                address_control_sync_cn
            fi
            ;;
        custom)
            custom_file="$(address_control_custom_file)"
            [ -n "$custom_file" ] || pfwd_die "自定义地址访问控制模式缺少文件路径"
            if [ ! -s "$(address_control_allow_file)" ]; then
                address_control_import_custom "$custom_file"
            fi
            ;;
    esac
}

address_control_runtime_enabled() {
    [ "$(address_control_mode)" = "off" ] && echo false || echo true
}

address_control_status_json() {
    jq -n \
      --arg mode "$(address_control_mode)" \
      --arg source_url "$(address_control_source_url)" \
      --arg custom_file "$(address_control_custom_file)" \
      --arg allow_file "$(address_control_allow_file)" \
      --argjson entries "$(address_control_entry_count)" \
      '{
        mode: $mode,
        source_url: $source_url,
        custom_file: $custom_file,
        allow_file: $allow_file,
        entries: $entries
      }'
}

address_control_render_status() {
    local json
    json="$(address_control_status_json)"
    jq -r '
      [
        ["地址控制模式", .mode],
        ["地址来源", .source_url],
        ["自定义文件", (if .custom_file == "" then "-" else .custom_file end)],
        ["地址条目", (.entries | tostring)],
        ["运行态文件", .allow_file]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}
