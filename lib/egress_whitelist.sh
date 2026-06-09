#!/usr/bin/env bash

EGRESS_WHITELIST_LAST_ERROR=""

egress_whitelist_state_dir() {
    local state_dir="${1:-$PFWD_EGRESS_WHITELIST_STATE_DIR}"
    printf '%s\n' "$state_dir"
}

egress_whitelist_allow_ipv4_file() {
    local state_dir="${1:-}"
    printf '%s\n' "$(egress_whitelist_state_dir "$state_dir")/allow_ipv4.txt"
}

egress_whitelist_allow_ipv6_file() {
    local state_dir="${1:-}"
    printf '%s\n' "$(egress_whitelist_state_dir "$state_dir")/allow_ipv6.txt"
}

egress_whitelist_host_allow_ipv4_file() {
    local state_dir="${1:-}"
    if [ -n "$state_dir" ]; then
        printf '%s\n' "$(egress_whitelist_state_dir "$state_dir")/host_allow_ipv4.txt"
    else
        printf '%s\n' "$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV4_FILE"
    fi
}

egress_whitelist_host_allow_ipv6_file() {
    local state_dir="${1:-}"
    if [ -n "$state_dir" ]; then
        printf '%s\n' "$(egress_whitelist_state_dir "$state_dir")/host_allow_ipv6.txt"
    else
        printf '%s\n' "$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV6_FILE"
    fi
}

egress_whitelist_enabled() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r '.settings.egress_whitelist.enabled // false' "$config_file"
}

egress_whitelist_include_cn() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r 'if (.settings.egress_whitelist.include_cn? | type) == "boolean" then .settings.egress_whitelist.include_cn else true end' "$config_file"
}

egress_whitelist_cn_mode() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r '
      if ((.settings.egress_whitelist.cn_mode // "") | type) == "string" and (.settings.egress_whitelist.cn_mode | length) > 0 then
        .settings.egress_whitelist.cn_mode
      elif ((.settings.egress_whitelist.include_cn? | type) == "boolean") then
        (if .settings.egress_whitelist.include_cn then "all" else "off" end)
      else
        "all"
      end
    ' "$config_file"
}

egress_whitelist_cn_provinces_json() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -c '.settings.egress_whitelist.cn_provinces // []' "$config_file"
}

egress_whitelist_cn_provinces_tsv() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r '.settings.egress_whitelist.cn_provinces // [] | .[]' "$config_file"
}

egress_whitelist_cn_selection_summary() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    local mode
    mode="$(egress_whitelist_cn_mode "$config_file")"
    case "$mode" in
        all) printf '国内IP' ;;
        provinces)
            local provinces
            provinces="$(egress_whitelist_cn_provinces_tsv "$config_file" | pfwd_join_lines '、')"
            [ -n "$provinces" ] || provinces="未选择"
            printf '省份：%s' "$provinces"
            ;;
        *)
            printf '关闭'
            ;;
    esac
}

egress_whitelist_custom_cidrs_tsv() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r '.settings.egress_whitelist.custom_cidrs // [] | .[]' "$config_file"
}

egress_whitelist_custom_cidrs_count() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r '.settings.egress_whitelist.custom_cidrs // [] | length' "$config_file"
}

egress_whitelist_runtime_hash() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r '.settings.egress_whitelist.runtime_hash // ""' "$config_file"
}

egress_whitelist_require_geo_assets() {
    [ "$(egress_whitelist_cn_mode "${1:-$PFWD_CONFIG_FILE}")" = "off" ] && return 0
    [ -f "$PFWD_ASSETS_DIR/pfwd-geo-meta.json" ] || pfwd_die "缺少 geo 资产：$PFWD_ASSETS_DIR/pfwd-geo-meta.json"
    [ -f "$PFWD_ASSETS_DIR/pfwd-geo-cn-v4.bin" ] || pfwd_die "缺少 geo 资产：$PFWD_ASSETS_DIR/pfwd-geo-cn-v4.bin"
    [ -f "$PFWD_ASSETS_DIR/pfwd-geo-cn-v6.bin" ] || pfwd_die "缺少 geo 资产：$PFWD_ASSETS_DIR/pfwd-geo-cn-v6.bin"
}

egress_whitelist_validate_cn_mode() {
    local mode="$1"
    case "$mode" in
        off|all|provinces) ;;
        *) pfwd_die "无效出口白名单国内模式：$mode" ;;
    esac
}

egress_whitelist_config_set_cn_mode() {
    local mode="$1"
    egress_whitelist_validate_cn_mode "$mode"
    config_update --arg mode "$mode" '
      (.settings.egress_whitelist //= {})
      | .settings.egress_whitelist.cn_mode = $mode
      | .settings.egress_whitelist.include_cn = ($mode != "off")
    '
}

egress_whitelist_config_set_cn_provinces() {
    local provinces_file="$1"
    [ -f "$provinces_file" ] || pfwd_die "出口省份临时文件不存在：$provinces_file"
    whitelist_validate_cn_provinces_file "$provinces_file"
    config_update --rawfile provinces "$provinces_file" '
      (.settings.egress_whitelist //= {})
      | .settings.egress_whitelist.cn_provinces =
          (($provinces
            | split("\n")
            | map(gsub("^\\s+|\\s+$"; ""))
            | map(select(length > 0))
            | reduce .[] as $province ([]; if index($province) then . else . + [$province] end)))
    '
}

egress_whitelist_config_apply_cn_selection() {
    local mode="$1"
    local provinces_file="${2:-}"
    egress_whitelist_validate_cn_mode "$mode"
    case "$mode" in
        off|all)
            config_update --arg mode "$mode" '
              (.settings.egress_whitelist //= {})
              | .settings.egress_whitelist.cn_mode = $mode
              | .settings.egress_whitelist.cn_provinces = []
              | .settings.egress_whitelist.include_cn = ($mode != "off")
            '
            ;;
        provinces)
            [ -n "$provinces_file" ] || pfwd_die "缺少出口省份列表"
            [ -f "$provinces_file" ] || pfwd_die "出口省份临时文件不存在：$provinces_file"
            whitelist_validate_cn_provinces_file "$provinces_file"
            config_update --arg mode "$mode" --rawfile provinces "$provinces_file" '
              (.settings.egress_whitelist //= {})
              | .settings.egress_whitelist.cn_mode = $mode
              | .settings.egress_whitelist.cn_provinces =
                  (($provinces
                    | split("\n")
                    | map(gsub("^\\s+|\\s+$"; ""))
                    | map(select(length > 0))
                    | reduce .[] as $province ([]; if index($province) then . else . + [$province] end)))
              | .settings.egress_whitelist.include_cn = true
            '
            ;;
    esac
}

egress_whitelist_entry_count() {
    local state_dir="${1:-}" total=0
    local ipv4_file ipv6_file
    ipv4_file="$(egress_whitelist_allow_ipv4_file "$state_dir")"
    ipv6_file="$(egress_whitelist_allow_ipv6_file "$state_dir")"
    if [ -s "$ipv4_file" ]; then
        total=$((total + $(sed '/^$/d' "$ipv4_file" | wc -l | tr -d ' ')))
    fi
    if [ -s "$ipv6_file" ]; then
        total=$((total + $(sed '/^$/d' "$ipv6_file" | wc -l | tr -d ' ')))
    fi
    echo "$total"
}

egress_whitelist_host_entry_count() {
    local state_dir="${1:-}" total=0
    local ipv4_file ipv6_file
    ipv4_file="$(egress_whitelist_host_allow_ipv4_file "$state_dir")"
    ipv6_file="$(egress_whitelist_host_allow_ipv6_file "$state_dir")"
    if [ -s "$ipv4_file" ]; then
        total=$((total + $(sed '/^$/d' "$ipv4_file" | wc -l | tr -d ' ')))
    fi
    if [ -s "$ipv6_file" ]; then
        total=$((total + $(sed '/^$/d' "$ipv6_file" | wc -l | tr -d ' ')))
    fi
    echo "$total"
}

egress_whitelist_write_allow_ipv4_file() {
    local source_file="$1"
    local target_file="${2:-$(egress_whitelist_allow_ipv4_file)}"
    mkdir -p "$(dirname "$target_file")"
    whitelist_filter_ipv4_cidrs < "$source_file" | pfwd_write_atomic "$target_file"
}

egress_whitelist_write_allow_ipv6_file() {
    local source_file="$1"
    local target_file="${2:-$(egress_whitelist_allow_ipv6_file)}"
    mkdir -p "$(dirname "$target_file")"
    whitelist_filter_ipv6_cidrs < "$source_file" | pfwd_write_atomic "$target_file"
}

egress_whitelist_write_host_allow_ipv4_file() {
    local source_file="$1"
    local target_file="${2:-$(egress_whitelist_host_allow_ipv4_file)}"
    mkdir -p "$(dirname "$target_file")"
    whitelist_filter_ipv4_cidrs < "$source_file" | pfwd_write_atomic "$target_file"
}

egress_whitelist_write_host_allow_ipv6_file() {
    local source_file="$1"
    local target_file="${2:-$(egress_whitelist_host_allow_ipv6_file)}"
    mkdir -p "$(dirname "$target_file")"
    whitelist_filter_ipv6_cidrs < "$source_file" | pfwd_write_atomic "$target_file"
}

egress_whitelist_special_ipv4_cidrs() {
    cat <<'EOF'
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
224.0.0.0/4
240.0.0.0/4
255.255.255.255/32
EOF
}

egress_whitelist_special_ipv6_cidrs() {
    cat <<'EOF'
::1/128
fe80::/10
fc00::/7
ff00::/8
EOF
}

egress_whitelist_non_loopback_onlink_cidrs() {
    ip -o addr show up scope global 2>/dev/null | awk '
      $2 != "lo" {
        for (i = 1; i <= NF; i++) {
          if ($i == "inet" || $i == "inet6") {
            print $(i + 1)
          }
        }
      }
    '
}

egress_whitelist_default_gateway_ips() {
    {
        ip route show default 2>/dev/null | awk '
          /^default / {
            for (i = 1; i <= NF; i++) {
              if ($i == "via" && (i + 1) <= NF) {
                print $(i + 1)
              }
            }
          }
        '
        ip -6 route show default 2>/dev/null | awk '
          /^default / {
            for (i = 1; i <= NF; i++) {
              if ($i == "via" && (i + 1) <= NF) {
                print $(i + 1)
              }
            }
          }
        '
    } | sed 's/%.*$//'
}

egress_whitelist_host_allow_rows() {
    local state_dir="${1:-$PFWD_EGRESS_WHITELIST_STATE_DIR}"
    local ipv4_file ipv6_file gateway
    ipv4_file="$(egress_whitelist_allow_ipv4_file "$state_dir")"
    ipv6_file="$(egress_whitelist_allow_ipv6_file "$state_dir")"

    egress_whitelist_special_ipv4_cidrs
    egress_whitelist_special_ipv6_cidrs
    egress_whitelist_non_loopback_onlink_cidrs
    while IFS= read -r gateway; do
        [ -n "$gateway" ] || continue
        printf '%s\n' "$gateway"
    done < <(egress_whitelist_default_gateway_ips)
    [ -f "$ipv4_file" ] && cat "$ipv4_file"
    [ -f "$ipv6_file" ] && cat "$ipv6_file"
}

egress_whitelist_prepare_host_runtime() {
    local state_dir="${1:-$PFWD_EGRESS_WHITELIST_STATE_DIR}"
    local tmp_v4 tmp_v6 host_v4_file host_v6_file
    host_v4_file="$(egress_whitelist_host_allow_ipv4_file "$state_dir")"
    host_v6_file="$(egress_whitelist_host_allow_ipv6_file "$state_dir")"
    tmp_v4="$(mktemp)"
    tmp_v6="$(mktemp)"

    egress_whitelist_host_allow_rows "$state_dir" | whitelist_filter_ipv4_cidrs >> "$tmp_v4"
    egress_whitelist_host_allow_rows "$state_dir" | whitelist_filter_ipv6_cidrs >> "$tmp_v6"

    if [ -s "$tmp_v4" ]; then
        egress_whitelist_write_host_allow_ipv4_file "$tmp_v4" "$host_v4_file"
    else
        : > "$host_v4_file"
    fi
    if [ -s "$tmp_v6" ]; then
        egress_whitelist_write_host_allow_ipv6_file "$tmp_v6" "$host_v6_file"
    else
        : > "$host_v6_file"
    fi
    rm -f "$tmp_v4" "$tmp_v6"
}

egress_whitelist_validate_custom_cidrs() {
    local cidr
    while IFS= read -r cidr; do
        cidr="$(printf '%s' "$cidr" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -n "$cidr" ] || continue
        normalize_ip_or_cidr "$cidr"
    done
}

egress_whitelist_config_set_state() {
    local enabled="$1"
    local cn_mode="$2"
    validate_bool "$enabled"
    egress_whitelist_validate_cn_mode "$cn_mode"
    config_update \
      --argjson enabled "$enabled" \
      --arg cn_mode "$cn_mode" '
      (.settings.egress_whitelist //= {})
      | .settings.egress_whitelist.enabled = $enabled
      | .settings.egress_whitelist.cn_mode = $cn_mode
      | .settings.egress_whitelist.include_cn = ($cn_mode != "off")
      | if $cn_mode != "provinces" then .settings.egress_whitelist.cn_provinces = [] else . end
    '
}

egress_whitelist_config_set_custom_cidrs() {
    local cidrs_file="$1"
    local normalized_file
    [ -f "$cidrs_file" ] || pfwd_die "出口白名单自定义 CIDR 临时文件不存在：$cidrs_file"
    normalized_file="$(mktemp)"
    egress_whitelist_validate_custom_cidrs < "$cidrs_file" > "$normalized_file"
    config_update --rawfile cidrs "$normalized_file" '
      (.settings.egress_whitelist //= {})
      | .settings.egress_whitelist.custom_cidrs =
          (($cidrs
            | split("\n")
            | map(gsub("^\\s+|\\s+$"; ""))
            | map(select(length > 0))
            | unique))
    '
    rm -f "$normalized_file"
}

egress_whitelist_append_custom_cidr() {
    local cidr="$1"
    cidr="$(normalize_ip_or_cidr "$cidr")"
    config_update --arg cidr "$cidr" '
      (.settings.egress_whitelist //= {})
      | .settings.egress_whitelist.custom_cidrs =
          (((.settings.egress_whitelist.custom_cidrs // []) + [$cidr]) | unique)
    '
}

egress_whitelist_clear_custom_cidrs() {
    config_update '
      (.settings.egress_whitelist //= {})
      | .settings.egress_whitelist.custom_cidrs = []
    '
}

egress_whitelist_replace_custom_cidr_by_index() {
    local index="$1"
    local cidr="$2"
    cidr="$(normalize_ip_or_cidr "$cidr")"
    [[ "$index" =~ ^[0-9]+$ ]] || pfwd_die "无效出口白名单自定义 CIDR 序号：$index"
    config_update --argjson index "$index" --arg cidr "$cidr" '
      (.settings.egress_whitelist //= {})
      | (.settings.egress_whitelist.custom_cidrs // []) as $items
      | if $index < 1 or $index > ($items | length) then
          error("出口白名单自定义 CIDR 序号超出范围")
        else
          .settings.egress_whitelist.custom_cidrs =
            ([ range(0; $items|length) as $i | if $i == ($index - 1) then $cidr else $items[$i] end ] | unique)
        end
    '
}

egress_whitelist_delete_custom_cidrs_by_indexes() {
    local indexes="$1"
    [ -n "$indexes" ] || pfwd_die "缺少出口白名单自定义 CIDR 序号"
    config_update --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      (.settings.egress_whitelist //= {})
      | (.settings.egress_whitelist.custom_cidrs // []) as $items
      | if ($idxs | length) == 0 then
          error("缺少出口白名单自定义 CIDR 序号")
        elif (($idxs | min) < 1) or (($idxs | max) > ($items | length)) then
          error("出口白名单自定义 CIDR 序号超出范围")
        else
          .settings.egress_whitelist.custom_cidrs =
            [ range(0; $items | length) as $i | select(([$idxs[] - 1] | index($i)) | not) | $items[$i] ]
        end
    '
}

egress_whitelist_custom_cidr_by_index() {
    local index="$1"
    [[ "$index" =~ ^[0-9]+$ ]] || pfwd_die "无效出口白名单自定义 CIDR 序号：$index"
    jq -r --argjson index "$index" '
      (.settings.egress_whitelist.custom_cidrs // [])[($index - 1)] // empty
    ' "$PFWD_CONFIG_FILE"
}

egress_whitelist_prepare_runtime() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    local state_dir="${2:-$PFWD_EGRESS_WHITELIST_STATE_DIR}"
    local ipv4_file ipv6_file host_ipv4_file host_ipv6_file tmp_v4 tmp_v6
    ipv4_file="$(egress_whitelist_allow_ipv4_file "$state_dir")"
    ipv6_file="$(egress_whitelist_allow_ipv6_file "$state_dir")"
    host_ipv4_file="$(egress_whitelist_host_allow_ipv4_file "$state_dir")"
    host_ipv6_file="$(egress_whitelist_host_allow_ipv6_file "$state_dir")"
    mkdir -p "$(dirname "$ipv4_file")"

    if [ "$(egress_whitelist_enabled "$config_file")" != "true" ]; then
        rm -f "$ipv4_file" "$ipv6_file" "$host_ipv4_file" "$host_ipv6_file" "${ipv4_file}.cn" "${ipv6_file}.cn" 2>/dev/null || true
        return 0
    fi

    if [ "$(egress_whitelist_cn_mode "$config_file")" != "off" ]; then
        egress_whitelist_require_geo_assets "$config_file"
    else
        rm -f "${ipv4_file}.cn" "${ipv6_file}.cn" 2>/dev/null || true
    fi

    tmp_v4="$(mktemp)"
    tmp_v6="$(mktemp)"
    egress_whitelist_custom_cidrs_tsv "$config_file" | whitelist_filter_ipv4_cidrs >> "$tmp_v4"
    egress_whitelist_custom_cidrs_tsv "$config_file" | whitelist_filter_ipv6_cidrs >> "$tmp_v6"

    if [ -s "$tmp_v4" ]; then
        egress_whitelist_write_allow_ipv4_file "$tmp_v4" "$ipv4_file"
    else
        : > "$ipv4_file"
    fi
    if [ -s "$tmp_v6" ]; then
        egress_whitelist_write_allow_ipv6_file "$tmp_v6" "$ipv6_file"
    else
        : > "$ipv6_file"
    fi
    rm -f "$tmp_v4" "$tmp_v6"
    egress_whitelist_prepare_host_runtime "$state_dir"
}

egress_whitelist_runtime_hash_compute() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    local state_dir="${2:-$PFWD_EGRESS_WHITELIST_STATE_DIR}"
    local ipv4_file ipv6_file host_ipv4_file host_ipv6_file payload
    ipv4_file="$(egress_whitelist_allow_ipv4_file "$state_dir")"
    ipv6_file="$(egress_whitelist_allow_ipv6_file "$state_dir")"
    host_ipv4_file="$(egress_whitelist_host_allow_ipv4_file "$state_dir")"
    host_ipv6_file="$(egress_whitelist_host_allow_ipv6_file "$state_dir")"
    payload="$(cat <<EOF
enabled=$(egress_whitelist_enabled "$config_file")
cn_mode=$(egress_whitelist_cn_mode "$config_file")
cn_provinces=$(egress_whitelist_cn_provinces_tsv "$config_file" | paste -sd ',' -)
custom:
$(egress_whitelist_custom_cidrs_tsv "$config_file")
ipv4:
$(cat "$ipv4_file" 2>/dev/null || true)
ipv6:
$(cat "$ipv6_file" 2>/dev/null || true)
host_ipv4:
$(cat "$host_ipv4_file" 2>/dev/null || true)
host_ipv6:
$(cat "$host_ipv6_file" 2>/dev/null || true)
EOF
)"
    printf '%s' "$payload" | cksum | awk '{print $1}'
}

egress_whitelist_update_runtime_hash() {
    local runtime_hash="$1"
    config_update --arg runtime_hash "$runtime_hash" '
      (.settings.egress_whitelist //= {})
      | .settings.egress_whitelist.runtime_hash = $runtime_hash
    '
}

egress_whitelist_apply_runtime() {
    local runtime_hash current_hash
    egress_whitelist_prepare_runtime "$PFWD_CONFIG_FILE" "$PFWD_EGRESS_WHITELIST_STATE_DIR"
    runtime_hash="$(egress_whitelist_runtime_hash_compute "$PFWD_CONFIG_FILE" "$PFWD_EGRESS_WHITELIST_STATE_DIR")"
    current_hash="$(egress_whitelist_runtime_hash)"
    [ "$runtime_hash" = "$current_hash" ] || egress_whitelist_update_runtime_hash "$runtime_hash"
}

egress_whitelist_status_json() {
    local enabled cn_provinces entries host_entries custom_cidrs_count
    enabled="$(jq -cn --arg value "$(egress_whitelist_enabled)" '$value == "true"')"
    cn_provinces="$(pfwd_capture_json_output "出口白名单省份配置" egress_whitelist_cn_provinces_json)"
    entries="$(jq -cn --argjson value "$(egress_whitelist_entry_count)" '$value')"
    host_entries="$(jq -cn --argjson value "$(egress_whitelist_host_entry_count)" '$value')"
    custom_cidrs_count="$(jq -cn --argjson value "$(egress_whitelist_custom_cidrs_count)" '$value')"
    jq -n \
      --argjson enabled "$enabled" \
      --arg cn_mode "$(egress_whitelist_cn_mode)" \
      --argjson cn_provinces "$cn_provinces" \
      --arg allow_ipv4_file "$(egress_whitelist_allow_ipv4_file)" \
      --arg allow_ipv6_file "$(egress_whitelist_allow_ipv6_file)" \
      --arg host_allow_ipv4_file "$(egress_whitelist_host_allow_ipv4_file)" \
      --arg host_allow_ipv6_file "$(egress_whitelist_host_allow_ipv6_file)" \
      --argjson entries "$entries" \
      --argjson host_entries "$host_entries" \
      --argjson custom_cidrs_count "$custom_cidrs_count" \
      '{
        enabled: $enabled,
        cn_mode: $cn_mode,
        cn_provinces: $cn_provinces,
        allow_ipv4_file: $allow_ipv4_file,
        allow_ipv6_file: $allow_ipv6_file,
        host_allow_ipv4_file: $host_allow_ipv4_file,
        host_allow_ipv6_file: $host_allow_ipv6_file,
        entries: $entries,
        host_entries: $host_entries,
        custom_cidrs_count: $custom_cidrs_count
      }'
}

egress_whitelist_render_status() {
    local json
    json="$(egress_whitelist_status_json)"
    jq -r '
      [
        ["启用出口白名单", (if .enabled then "开" else "关" end)],
        ["出口国内 IP 策略", (if .enabled then (if .cn_mode == "all" then "国内IP" elif .cn_mode == "provinces" then ("省份：" + ((.cn_provinces // []) | join("、"))) else "关闭" end) else "-" end)],
        ["出口自定义 CIDR", (.custom_cidrs_count | tostring)],
        ["出口白名单条目", (.entries | tostring)],
        ["宿主机出口白名单条目", (.host_entries | tostring)],
        ["出口 IPv4 文件", .allow_ipv4_file],
        ["出口 IPv6 文件", .allow_ipv6_file],
        ["宿主机出口 IPv4 文件", .host_allow_ipv4_file],
        ["宿主机出口 IPv6 文件", .host_allow_ipv6_file]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}

egress_whitelist_assert_target_rows_allowed() {
    local remote_input="$1"
    local target_rows="$2"
    local state_dir="${3:-$PFWD_EGRESS_WHITELIST_STATE_DIR}"
    local config_file="${4:-$PFWD_CONFIG_FILE}"
    local resolved_ip geo_mode provinces_csv asset_dir whitelist_files
    geo_mode="$(egress_whitelist_cn_mode "$config_file")"
    provinces_csv="$(egress_whitelist_cn_provinces_tsv "$config_file" | paste -sd ',' -)"
    asset_dir="$PFWD_ASSETS_DIR"
    whitelist_files="$(egress_whitelist_allow_ipv4_file "$state_dir"):$(egress_whitelist_allow_ipv6_file "$state_dir")"
    while IFS='|' read -r _ _ resolved_ip; do
        [ -n "$resolved_ip" ] || continue
        if ! "$(forwarder_bin_path)" geo-check \
            --asset-dir "$asset_dir" \
            --address "$resolved_ip" \
            --mode "$geo_mode" \
            --provinces "$provinces_csv" \
            --egress-whitelist-file "$whitelist_files" >/dev/null 2>&1; then
            EGRESS_WHITELIST_LAST_ERROR="resolved_ip=${resolved_ip}"
            return 1
        fi
    done <<< "$target_rows"
    return 0
}

egress_whitelist_validate_remote_host() {
    local remote_host="$1"
    local listen_ip="$2"
    local snat_mode="$3"
    local snat_source="$4"
    local forward_id="${5:-}"
    local config_file="${6:-$PFWD_CONFIG_FILE}"
    local state_dir="${7:-$PFWD_EGRESS_WHITELIST_STATE_DIR}"
    local ipver target_rows target_kind resolve_error prefix

    EGRESS_WHITELIST_LAST_ERROR=""
    [ "$(egress_whitelist_enabled "$config_file")" = "true" ] || return 0
    egress_whitelist_prepare_runtime "$config_file" "$state_dir"
    target_kind="$(runtime_target_kind "$remote_host")"
    prefix="出口白名单拒绝目标：remote=${remote_host}"
    [ -n "$forward_id" ] && prefix="出口白名单拒绝转发规则：${forward_id} remote=${remote_host}"

    while IFS= read -r ipver; do
        [ -n "$ipver" ] || continue
        target_rows="$(runtime_resolve_targets "$remote_host" "$ipver" || true)"
        resolve_error="${FORWARDER_LAST_RESOLVE_ERROR:-}"
        if [ -z "$target_rows" ]; then
            if [ "$target_kind" = "domain" ]; then
                EGRESS_WHITELIST_LAST_ERROR="${prefix} 无法解析 IPv${ipver}${resolve_error:+：${resolve_error}}"
                return 1
            fi
            continue
        fi
        if ! egress_whitelist_assert_target_rows_allowed "$remote_host" "$target_rows" "$state_dir" "$config_file"; then
            EGRESS_WHITELIST_LAST_ERROR="${prefix} ${EGRESS_WHITELIST_LAST_ERROR}"
            return 1
        fi
    done < <(runtime_infer_ip_version "$listen_ip" "$snat_mode" "$snat_source")
    return 0
}

egress_whitelist_validate_config_file() {
    local config_file="$1"
    local now_minute tmp_state_dir
    local forward_id remote_host listen_ip snat_mode snat_source

    EGRESS_WHITELIST_LAST_ERROR=""
    [ "$(egress_whitelist_enabled "$config_file")" = "true" ] || return 0
    tmp_state_dir="$(mktemp -d)"
    egress_whitelist_prepare_runtime "$config_file" "$tmp_state_dir"
    now_minute="$(pfwd_now_minute)"

    while IFS=$'\t' read -r forward_id remote_host listen_ip snat_mode snat_source; do
        [ -n "$forward_id" ] || continue
        if ! egress_whitelist_validate_remote_host "$remote_host" "$listen_ip" "$snat_mode" "$snat_source" "$forward_id" "$config_file" "$tmp_state_dir"; then
            rm -rf "$tmp_state_dir"
            return 1
        fi
    done < <(jq -r --arg now "$now_minute" '
      .forwards[]
      | select(.enabled == true and (.stop_at == null or .stop_at > $now))
      | [
          .id,
          .remote_host,
          (.listen_ip // "::"),
          (.net.snat_mode // "masquerade"),
          (.net.snat_source // "")
        ] | @tsv
    ' "$config_file")

    rm -rf "$tmp_state_dir"
    return 0
}
