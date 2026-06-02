#!/usr/bin/env bash

whitelist_state_dir() {
    printf '%s\n' "$PFWD_WHITELIST_STATE_DIR"
}

whitelist_allow_file() {
    printf '%s\n' "$PFWD_WHITELIST_ALLOW_IPV4_FILE"
}

whitelist_allow_ipv4_file() {
    printf '%s\n' "$PFWD_WHITELIST_ALLOW_IPV4_FILE"
}

whitelist_allow_ipv6_file() {
    printf '%s\n' "$PFWD_WHITELIST_ALLOW_IPV6_FILE"
}

whitelist_enabled() {
    jq -r '.settings.whitelist.enabled // false' "$PFWD_CONFIG_FILE"
}

whitelist_include_cn() {
    jq -r 'if (.settings.whitelist.include_cn? | type) == "boolean" then .settings.whitelist.include_cn else true end' "$PFWD_CONFIG_FILE"
}

whitelist_cn_mode() {
    jq -r '
      if ((.settings.whitelist.cn_mode // "") | type) == "string" and (.settings.whitelist.cn_mode | length) > 0 then
        .settings.whitelist.cn_mode
      elif ((.settings.whitelist.include_cn? | type) == "boolean") then
        (if .settings.whitelist.include_cn then "all" else "off" end)
      else
        "all"
      end
    ' "$PFWD_CONFIG_FILE"
}

whitelist_cn_provinces_json() {
    jq -c '.settings.whitelist.cn_provinces // []' "$PFWD_CONFIG_FILE"
}

whitelist_cn_provinces_tsv() {
    jq -r '.settings.whitelist.cn_provinces // [] | .[]' "$PFWD_CONFIG_FILE"
}

whitelist_cn_mode_label() {
    local mode="${1:-$(whitelist_cn_mode)}"
    case "$mode" in
        all) printf '国内IP' ;;
        provinces) printf '省份' ;;
        off) printf '关闭' ;;
        *) printf '%s' "$mode" ;;
    esac
}

whitelist_cn_selection_summary() {
    local mode="${1:-$(whitelist_cn_mode)}"
    case "$mode" in
        all) printf '国内IP' ;;
        provinces)
            local provinces
            provinces="$(whitelist_cn_provinces_tsv | pfwd_join_lines '、')"
            [ -n "$provinces" ] || provinces="未选择"
            printf '省份：%s' "$provinces"
            ;;
        *)
            printf '关闭'
            ;;
    esac
}

whitelist_custom_cidrs_tsv() {
    jq -r '.settings.whitelist.custom_cidrs // [] | .[]' "$PFWD_CONFIG_FILE"
}

whitelist_custom_cidrs_json() {
    jq -c '.settings.whitelist.custom_cidrs // []' "$PFWD_CONFIG_FILE"
}

whitelist_entry_count() {
    local total=0
    if [ -s "$(whitelist_allow_ipv4_file)" ]; then
        total=$((total + $(sed '/^$/d' "$(whitelist_allow_ipv4_file)" | wc -l | tr -d ' ')))
    fi
    if [ -s "$(whitelist_allow_ipv6_file)" ]; then
        total=$((total + $(sed '/^$/d' "$(whitelist_allow_ipv6_file)" | wc -l | tr -d ' ')))
    fi
    echo "$total"
}

whitelist_custom_cidrs_count() {
    jq -r '.settings.whitelist.custom_cidrs // [] | length' "$PFWD_CONFIG_FILE"
}

whitelist_runtime_hash() {
    jq -r '.settings.whitelist.runtime_hash // ""' "$PFWD_CONFIG_FILE"
}

whitelist_geo_asset_dir() {
    printf '%s\n' "$PFWD_ASSETS_DIR"
}

whitelist_geo_meta_file() {
    printf '%s\n' "$(whitelist_geo_asset_dir)/pfwd-geo-meta.json"
}

whitelist_geo_ipv4_asset_file() {
    printf '%s\n' "$(whitelist_geo_asset_dir)/pfwd-geo-cn-v4.bin"
}

whitelist_geo_ipv6_asset_file() {
    printf '%s\n' "$(whitelist_geo_asset_dir)/pfwd-geo-cn-v6.bin"
}

whitelist_require_geo_assets() {
    [ "$(whitelist_cn_mode)" = "off" ] && return 0
    [ -f "$(whitelist_geo_meta_file)" ] || pfwd_die "缺少 geo 资产：$(whitelist_geo_meta_file)"
    [ -f "$(whitelist_geo_ipv4_asset_file)" ] || pfwd_die "缺少 geo 资产：$(whitelist_geo_ipv4_asset_file)"
    [ -f "$(whitelist_geo_ipv6_asset_file)" ] || pfwd_die "缺少 geo 资产：$(whitelist_geo_ipv6_asset_file)"
}

whitelist_geo_province_rows() {
    local meta_file
    meta_file="$(whitelist_geo_meta_file)"
    [ -f "$meta_file" ] || pfwd_die "缺少 geo 省份资产：$meta_file，请先执行 ./xdp/build.sh 或使用完整安装包"
    jq -r '.provinces[]? | [.id, .name] | @tsv' "$meta_file"
}

whitelist_validate_cn_provinces_file() {
    local provinces_file="$1"
    [ -f "$provinces_file" ] || pfwd_die "省份临时文件不存在：$provinces_file"
    whitelist_require_geo_assets
    local known tmp province
    tmp="$(mktemp)"
    whitelist_geo_province_rows | cut -f2 > "$tmp"
    while IFS= read -r province; do
        province="$(printf '%s' "$province" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -n "$province" ] || continue
        grep -Fxq "$province" "$tmp" || { rm -f "$tmp"; pfwd_die "未知省份：$province"; }
    done < "$provinces_file"
    rm -f "$tmp"
}

whitelist_validate_cn_mode() {
    local mode="$1"
    case "$mode" in
        off|all|provinces) ;;
        *) pfwd_die "无效入口白名单国内模式：$mode" ;;
    esac
}

whitelist_config_set_cn_mode() {
    local mode="$1"
    whitelist_validate_cn_mode "$mode"
    config_update --arg mode "$mode" '
      (.settings.whitelist //= {})
      | .settings.whitelist.cn_mode = $mode
      | .settings.whitelist.include_cn = ($mode != "off")
    '
}

whitelist_config_set_cn_provinces() {
    local provinces_file="$1"
    [ -f "$provinces_file" ] || pfwd_die "入口省份临时文件不存在：$provinces_file"
    whitelist_validate_cn_provinces_file "$provinces_file"
    config_update --rawfile provinces "$provinces_file" '
      (.settings.whitelist //= {})
      | .settings.whitelist.cn_provinces =
          (($provinces
            | split("\n")
            | map(gsub("^\\s+|\\s+$"; ""))
            | map(select(length > 0))
            | reduce .[] as $province ([]; if index($province) then . else . + [$province] end)))
    '
}

whitelist_config_apply_cn_selection() {
    local mode="$1"
    local provinces_file="${2:-}"
    whitelist_validate_cn_mode "$mode"
    case "$mode" in
        off|all)
            config_update --arg mode "$mode" '
              (.settings.whitelist //= {})
              | .settings.whitelist.cn_mode = $mode
              | .settings.whitelist.cn_provinces = []
              | .settings.whitelist.include_cn = ($mode != "off")
            '
            ;;
        provinces)
            [ -n "$provinces_file" ] || pfwd_die "缺少入口省份列表"
            [ -f "$provinces_file" ] || pfwd_die "入口省份临时文件不存在：$provinces_file"
            whitelist_validate_cn_provinces_file "$provinces_file"
            config_update --arg mode "$mode" --rawfile provinces "$provinces_file" '
              (.settings.whitelist //= {})
              | .settings.whitelist.cn_mode = $mode
              | .settings.whitelist.cn_provinces =
                  (($provinces
                    | split("\n")
                    | map(gsub("^\\s+|\\s+$"; ""))
                    | map(select(length > 0))
                    | reduce .[] as $province ([]; if index($province) then . else . + [$province] end)))
              | .settings.whitelist.include_cn = true
            '
            ;;
    esac
}

whitelist_filter_ipv4_cidrs() {
    awk '
      function valid_octet(v) { return v ~ /^[0-9]+$/ && v >= 0 && v <= 255 }
      function valid_mask(v) { return v ~ /^[0-9]+$/ && v >= 0 && v <= 32 }
      /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
        split($0, a, /\./)
        if (valid_octet(a[1]) && valid_octet(a[2]) && valid_octet(a[3]) && valid_octet(a[4])) {
          print $0 "/32"
        }
      }
      /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ {
        split($0, a, /[.\/]/)
        if (valid_octet(a[1]) && valid_octet(a[2]) && valid_octet(a[3]) && valid_octet(a[4]) && valid_mask(a[5])) {
          print $0
        }
      }
    ' | sort -u
}

whitelist_filter_ipv6_cidrs() {
    awk '
      function valid_hex(s,    i, c) {
        if (length(s) == 0 || length(s) > 4) return 0
        for (i = 1; i <= length(s); i++) {
          c = tolower(substr(s, i, 1))
          if (!((c >= "0" && c <= "9") || (c >= "a" && c <= "f"))) return 0
        }
        return 1
      }
      /^#/ || /^$/ { next }
      {
        n = split($0, parts, "/")
        if (n == 1) {
          addr = parts[1]
          mask = 128
          normalized = addr "/128"
        } else if (n == 2) {
          addr = parts[1]
          mask = parts[2]
          normalized = $0
          if (mask !~ /^[0-9]+$/ || mask + 0 < 0 || mask + 0 > 128) next
        } else next
        np = split(addr, groups, ":")
        if (np < 2) next
        skip = 0
        for (i = 1; i <= np; i++) {
          if (groups[i] != "" && !valid_hex(groups[i])) { skip = 1; break }
        }
        if (!skip) print normalized
      }
    ' | sort -u
}

whitelist_write_allow_file() {
    local source_file="$1"
    local target_file
    target_file="$(whitelist_allow_ipv4_file)"
    mkdir -p "$(dirname "$target_file")"
    whitelist_filter_ipv4_cidrs < "$source_file" | pfwd_write_atomic "$target_file"
    [ -s "$target_file" ] || pfwd_die "白名单来源 IP 集合为空：$source_file"
}

whitelist_write_allow_ipv6_file() {
    local source_file="$1"
    local target_file
    target_file="$(whitelist_allow_ipv6_file)"
    mkdir -p "$(dirname "$target_file")"
    whitelist_filter_ipv6_cidrs < "$source_file" | pfwd_write_atomic "$target_file"
    [ -s "$target_file" ] || pfwd_die "白名单来源 IPv6 集合为空：$source_file"
}

whitelist_validate_custom_cidrs() {
    local cidr
    while IFS= read -r cidr; do
        cidr="$(printf '%s' "$cidr" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -n "$cidr" ] || continue
        normalize_ip_or_cidr "$cidr"
    done
}

whitelist_config_set_state() {
    local enabled="$1"
    local cn_mode="$2"
    validate_bool "$enabled"
    whitelist_validate_cn_mode "$cn_mode"
    config_update \
      --argjson enabled "$enabled" \
      --arg cn_mode "$cn_mode" '
      (.settings.whitelist //= {})
      | .settings.whitelist.enabled = $enabled
      | .settings.whitelist.cn_mode = $cn_mode
      | .settings.whitelist.include_cn = ($cn_mode != "off")
      | if $cn_mode != "provinces" then .settings.whitelist.cn_provinces = [] else . end
    '
}

whitelist_config_set_custom_cidrs() {
    local cidrs_file="$1"
    local normalized_file
    [ -f "$cidrs_file" ] || pfwd_die "自定义 CIDR 临时文件不存在：$cidrs_file"
    normalized_file="$(mktemp)"
    whitelist_validate_custom_cidrs < "$cidrs_file" > "$normalized_file"
    config_update --rawfile cidrs "$normalized_file" '
      (.settings.whitelist //= {})
      | .settings.whitelist.custom_cidrs =
          (($cidrs
            | split("\n")
            | map(gsub("^\\s+|\\s+$"; ""))
            | map(select(length > 0))
            | unique))
    '
    rm -f "$normalized_file"
}

whitelist_append_custom_cidr() {
    local cidr="$1"
    cidr="$(normalize_ip_or_cidr "$cidr")"
    config_update --arg cidr "$cidr" '
      (.settings.whitelist //= {})
      | .settings.whitelist.custom_cidrs =
          (((.settings.whitelist.custom_cidrs // []) + [$cidr]) | unique)
    '
}

whitelist_clear_custom_cidrs() {
    config_update '
      (.settings.whitelist //= {})
      | .settings.whitelist.custom_cidrs = []
    '
}

whitelist_replace_custom_cidr_by_index() {
    local index="$1"
    local cidr="$2"
    cidr="$(normalize_ip_or_cidr "$cidr")"
    [[ "$index" =~ ^[0-9]+$ ]] || pfwd_die "无效自定义 CIDR 序号：$index"
    config_update --argjson index "$index" --arg cidr "$cidr" '
      (.settings.whitelist //= {})
      | (.settings.whitelist.custom_cidrs // []) as $items
      | if $index < 1 or $index > ($items | length) then
          error("自定义 CIDR 序号超出范围")
        else
          .settings.whitelist.custom_cidrs =
            ([ range(0; $items|length) as $i | if $i == ($index - 1) then $cidr else $items[$i] end ] | unique)
        end
    '
}

whitelist_delete_custom_cidrs_by_indexes() {
    local indexes="$1"
    [ -n "$indexes" ] || pfwd_die "缺少自定义 CIDR 序号"
    config_update --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      (.settings.whitelist //= {})
      | (.settings.whitelist.custom_cidrs // []) as $items
      | if ($idxs | length) == 0 then
          error("缺少自定义 CIDR 序号")
        elif (($idxs | min) < 1) or (($idxs | max) > ($items | length)) then
          error("自定义 CIDR 序号超出范围")
        else
          .settings.whitelist.custom_cidrs =
            [ range(0; $items | length) as $i | select(([$idxs[] - 1] | index($i)) | not) | $items[$i] ]
        end
    '
}

whitelist_custom_cidr_by_index() {
    local index="$1"
    [[ "$index" =~ ^[0-9]+$ ]] || pfwd_die "无效自定义 CIDR 序号：$index"
    jq -r --argjson index "$index" '
      (.settings.whitelist.custom_cidrs // [])[($index - 1)] // empty
    ' "$PFWD_CONFIG_FILE"
}

whitelist_merge_runtime() {
    local tmp_v4 tmp_v6
    tmp_v4="$(mktemp)"
    tmp_v6="$(mktemp)"
    whitelist_custom_cidrs_tsv | whitelist_filter_ipv4_cidrs >> "$tmp_v4"
    whitelist_custom_cidrs_tsv | whitelist_filter_ipv6_cidrs >> "$tmp_v6"

    if [ -s "$tmp_v4" ]; then
        whitelist_write_allow_file "$tmp_v4"
    else
        : > "$(whitelist_allow_ipv4_file)"
    fi
    if [ -s "$tmp_v6" ]; then
        whitelist_write_allow_ipv6_file "$tmp_v6"
    else
        : > "$(whitelist_allow_ipv6_file)"
    fi
    rm -f "$tmp_v4" "$tmp_v6"
}

whitelist_prepare_runtime() {
    if [ "$(whitelist_enabled)" != "true" ]; then
        rm -f "$(whitelist_allow_ipv4_file)" "$(whitelist_allow_ipv6_file)" 2>/dev/null || true
        rm -f "$(whitelist_allow_ipv4_file).cn" "$(whitelist_allow_ipv6_file).cn" 2>/dev/null || true
        return 0
    fi

    if [ "$(whitelist_cn_mode)" != "off" ]; then
        whitelist_require_geo_assets
    else
        rm -f "$(whitelist_allow_ipv4_file).cn" "$(whitelist_allow_ipv6_file).cn" 2>/dev/null || true
    fi

    whitelist_merge_runtime
}

whitelist_runtime_enabled() {
    [ "$(whitelist_enabled)" = "true" ] && echo true || echo false
}

whitelist_runtime_hash_compute() {
    local payload
    payload="$(cat <<EOF
enabled=$(whitelist_enabled)
cn_mode=$(whitelist_cn_mode)
cn_provinces=$(whitelist_cn_provinces_tsv | paste -sd ',' -)
custom:
$(whitelist_custom_cidrs_tsv)
ipv4:
$(cat "$(whitelist_allow_ipv4_file)" 2>/dev/null || true)
ipv6:
$(cat "$(whitelist_allow_ipv6_file)" 2>/dev/null || true)
EOF
)"
    printf '%s' "$payload" | cksum | awk '{print $1}'
}

whitelist_update_runtime_hash() {
    local runtime_hash="$1"
    config_update --arg runtime_hash "$runtime_hash" '
      (.settings.whitelist //= {})
      | .settings.whitelist.runtime_hash = $runtime_hash
    '
}

whitelist_apply_runtime() {
    local runtime_hash current_hash
    whitelist_prepare_runtime
    runtime_hash="$(whitelist_runtime_hash_compute)"
    current_hash="$(whitelist_runtime_hash)"
    if [ "$runtime_hash" = "$current_hash" ]; then
        return 0
    fi
    whitelist_update_runtime_hash "$runtime_hash"
}

whitelist_status_json() {
    jq -n \
      --argjson enabled "$(whitelist_enabled)" \
      --arg cn_mode "$(whitelist_cn_mode)" \
      --argjson cn_provinces "$(whitelist_cn_provinces_json)" \
      --arg allow_ipv4_file "$(whitelist_allow_ipv4_file)" \
      --arg allow_ipv6_file "$(whitelist_allow_ipv6_file)" \
      --argjson entries "$(whitelist_entry_count)" \
      --argjson custom_cidrs_count "$(whitelist_custom_cidrs_count)" \
      '{
        enabled: $enabled,
        cn_mode: $cn_mode,
        cn_provinces: $cn_provinces,
        allow_ipv4_file: $allow_ipv4_file,
        allow_ipv6_file: $allow_ipv6_file,
        entries: $entries,
        custom_cidrs_count: $custom_cidrs_count
      }'
}

whitelist_render_status() {
    local json
    json="$(whitelist_status_json)"
    jq -r '
      [
        ["启用白名单", (if .enabled then "开" else "关" end)],
        ["国内 IP 策略", (if .enabled then (if .cn_mode == "all" then "国内IP" elif .cn_mode == "provinces" then ("省份：" + ((.cn_provinces // []) | join("、"))) else "关闭" end) else "-" end)],
        ["自定义 CIDR", (.custom_cidrs_count | tostring)],
        ["白名单条目", (.entries | tostring)],
        ["IPv4 文件", .allow_ipv4_file],
        ["IPv6 文件", .allow_ipv6_file]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}
