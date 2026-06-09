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

whitelist_city_runtime_ipv4_file() {
    printf '%s\n' "$PFWD_WHITELIST_CITY_IPV4_FILE"
}

whitelist_leases_file() {
    printf '%s\n' "$PFWD_WHITELIST_LEASES_FILE"
}

whitelist_temp_allow_ipv4_file() {
    printf '%s\n' "$PFWD_WHITELIST_TEMP_ALLOW_IPV4_FILE"
}

whitelist_temp_allow_ipv6_file() {
    printf '%s\n' "$PFWD_WHITELIST_TEMP_ALLOW_IPV6_FILE"
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

whitelist_cn_city_codes_json() {
    jq -c '.settings.whitelist.cn_city_codes // []' "$PFWD_CONFIG_FILE"
}

whitelist_cn_city_codes_tsv() {
    jq -r '.settings.whitelist.cn_city_codes // [] | .[]' "$PFWD_CONFIG_FILE"
}

whitelist_port_policies_json() {
    jq -c '.settings.whitelist.port_policies // []' "$PFWD_CONFIG_FILE"
}

whitelist_port_policy_count() {
    jq -r '.settings.whitelist.port_policies // [] | length' "$PFWD_CONFIG_FILE"
}

whitelist_port_policy_json() {
    local listen_port="$1"
    jq -c --argjson port "$listen_port" '
      (.settings.whitelist.port_policies // [])
      | map(select((.listen_port // 0) == $port))
      | first // empty
    ' "$PFWD_CONFIG_FILE"
}

whitelist_port_policy_exists() {
    local listen_port="$1"
    [ -n "$(whitelist_port_policy_json "$listen_port")" ]
}

whitelist_effective_policy_source_for_port() {
    local listen_port="$1"
    if [ -n "$listen_port" ] && whitelist_port_policy_exists "$listen_port"; then
        printf '端口覆盖'
    else
        printf '全局默认'
    fi
}

whitelist_effective_cn_mode_for_port() {
    local listen_port="$1"
    if [ -n "$listen_port" ] && whitelist_port_policy_exists "$listen_port"; then
        jq -r --argjson port "$listen_port" '
          (.settings.whitelist.port_policies // [])
          | map(select((.listen_port // 0) == $port))
          | first
          | .cn_mode // "off"
        ' "$PFWD_CONFIG_FILE"
        return 0
    fi
    whitelist_cn_mode
}

whitelist_effective_cn_provinces_json_for_port() {
    local listen_port="$1"
    if [ -n "$listen_port" ] && whitelist_port_policy_exists "$listen_port"; then
        jq -c --argjson port "$listen_port" '
          (.settings.whitelist.port_policies // [])
          | map(select((.listen_port // 0) == $port))
          | first
          | .cn_provinces // []
        ' "$PFWD_CONFIG_FILE"
        return 0
    fi
    whitelist_cn_provinces_json
}

whitelist_effective_cn_provinces_tsv_for_port() {
    local listen_port="$1"
    whitelist_effective_cn_provinces_json_for_port "$listen_port" | jq -r '.[]'
}

whitelist_effective_cn_city_codes_json_for_port() {
    local listen_port="$1"
    if [ -n "$listen_port" ] && whitelist_port_policy_exists "$listen_port"; then
        jq -c --argjson port "$listen_port" '
          (.settings.whitelist.port_policies // [])
          | map(select((.listen_port // 0) == $port))
          | first
          | .cn_city_codes // []
        ' "$PFWD_CONFIG_FILE"
        return 0
    fi
    whitelist_cn_city_codes_json
}

whitelist_effective_cn_city_codes_tsv_for_port() {
    local listen_port="$1"
    whitelist_effective_cn_city_codes_json_for_port "$listen_port" | jq -r '.[]'
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

whitelist_lease_entries_json() {
    local file
    file="$(whitelist_leases_file)"
    if [ ! -f "$file" ]; then
        printf '[]\n'
        return 0
    fi
    jq -c -s '
      if length == 0 then
        []
      else
        (.[0] | if type == "array" then . else [] end)
      end
    ' "$file" 2>/dev/null || printf '[]\n'
}

whitelist_lease_entries_sorted_json() {
    whitelist_lease_entries_json | jq -c '
      map(
        .address = (.address // "")
        | .cidr = (.cidr // "")
        | .channel = (.channel // "manual")
        | .note = (.note // "")
        | .idle_ttl_sec = ((.idle_ttl_sec // 0) | tonumber)
        | .granted_at = ((.granted_at // 0) | tonumber)
        | .last_seen_at = (if (.last_seen_at // null) == null then null else (.last_seen_at | tonumber) end)
        | .last_active_at = (if (.last_seen_at // null) == null then (.granted_at // 0) else .last_seen_at end)
      )
      | sort_by(.address)
    '
}

whitelist_lease_count() {
    whitelist_lease_entries_json | jq -r 'length'
}

whitelist_lease_custom_cidrs_tsv() {
    whitelist_lease_entries_sorted_json | jq -r '.[] | .cidr // empty'
}

whitelist_lease_find_by_address_json() {
    local address="$1"
    whitelist_lease_entries_json | jq -c --arg address "$address" '
      map(select((.address // "") == $address))
      | first // empty
    '
}

whitelist_nonempty_line_count() {
    local file="$1"
    if [ -s "$file" ]; then
        sed '/^$/d' "$file" | wc -l | tr -d ' '
    else
        echo 0
    fi
}

whitelist_entry_count() {
    local total=0
    total=$((total + $(whitelist_nonempty_line_count "$(whitelist_allow_ipv4_file)")))
    total=$((total + $(whitelist_nonempty_line_count "$(whitelist_allow_ipv6_file)")))
    total=$((total + $(whitelist_nonempty_line_count "$(whitelist_city_runtime_ipv4_file)")))
    total=$((total + $(whitelist_nonempty_line_count "$(whitelist_temp_allow_ipv4_file)")))
    total=$((total + $(whitelist_nonempty_line_count "$(whitelist_temp_allow_ipv6_file)")))
    echo "$total"
}

whitelist_custom_cidrs_count() {
    jq -r '.settings.whitelist.custom_cidrs // [] | length' "$PFWD_CONFIG_FILE"
}

whitelist_city_codes_count() {
    jq -r '.settings.whitelist.cn_city_codes // [] | length' "$PFWD_CONFIG_FILE"
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

whitelist_city_meta_file() {
    printf '%s\n' "$(whitelist_geo_asset_dir)/pfwd-city-cn-meta.json"
}

whitelist_city_ipv4_asset_file() {
    printf '%s\n' "$(whitelist_geo_asset_dir)/pfwd-city-cn-v4.bin"
}

whitelist_any_geo_policy_enabled() {
    jq -r '
      def mode_enabled($mode): ($mode == "all" or $mode == "provinces");
      (.settings.whitelist // {}) as $wl
      | (
          mode_enabled(
            if (($wl.cn_mode // "") | type) == "string" and (($wl.cn_mode // "") | length) > 0 then
              $wl.cn_mode
            elif (($wl.include_cn? | type) == "boolean") then
              (if $wl.include_cn then "all" else "off" end)
            else
              "all"
            end
          )
          or (($wl.port_policies // []) | any(mode_enabled(.cn_mode // "off")))
        )
    ' "$PFWD_CONFIG_FILE"
}

whitelist_any_city_policy_enabled() {
    jq -r '
      (.settings.whitelist // {}) as $wl
      | ((($wl.cn_city_codes // []) | length) > 0
         or (($wl.port_policies // []) | any(((.cn_city_codes // []) | length) > 0)))
    ' "$PFWD_CONFIG_FILE"
}

whitelist_require_geo_assets() {
    [ -f "$(whitelist_geo_meta_file)" ] || pfwd_die "缺少 geo 资产：$(whitelist_geo_meta_file)"
    [ -f "$(whitelist_geo_ipv4_asset_file)" ] || pfwd_die "缺少 geo 资产：$(whitelist_geo_ipv4_asset_file)"
    [ -f "$(whitelist_geo_ipv6_asset_file)" ] || pfwd_die "缺少 geo 资产：$(whitelist_geo_ipv6_asset_file)"
}

whitelist_require_city_assets() {
    [ -f "$(whitelist_city_meta_file)" ] || pfwd_die "缺少市级白名单资产：$(whitelist_city_meta_file)"
    [ -f "$(whitelist_city_ipv4_asset_file)" ] || pfwd_die "缺少市级白名单资产：$(whitelist_city_ipv4_asset_file)"
}

whitelist_geo_province_rows() {
    local meta_file
    meta_file="$(whitelist_city_meta_file)"
    [ -f "$meta_file" ] || pfwd_die "缺少入口省份目录资产：$meta_file，请先执行 ./xdp/build.sh 或使用完整安装包"
    jq -r '
      (.provinces // [])
      | to_entries[]
      | [(.key + 1), .value.name]
      | @tsv
    ' "$meta_file"
}

whitelist_city_available_province_rows() {
    whitelist_require_city_assets
    jq -r '
      [ .provinces[]? | select(((.cities // []) | length) > 0) ]
      | to_entries[]
      | [(.key + 1), (.value.code | tostring), .value.name, ((.value.cities // []) | length)]
      | @tsv
    ' "$(whitelist_city_meta_file)"
}

whitelist_city_rows_by_province_code() {
    local province_code="$1"
    whitelist_require_city_assets
    jq -r --arg code "$province_code" '
      (.provinces[]? | select((.code | tostring) == $code)) as $province
      | ($province.cities // [])
      | to_entries[]
      | [(.key + 1), (.value.code | tostring), .value.name]
      | @tsv
    ' "$(whitelist_city_meta_file)"
}

whitelist_city_selected_rows() {
    whitelist_city_selected_rows_from_codes_json "$(whitelist_cn_city_codes_json)"
}

whitelist_city_selected_rows_from_codes_json() {
    local codes_json="$1"
    [ "$(jq -r 'length' <<< "$codes_json")" -eq 0 ] && return 0
    whitelist_require_city_assets
    jq -r --argjson codes "$codes_json" '
      .provinces[]? as $province
      | ($province.cities // [])[]?
      | (.code | tostring) as $code
      | select($codes | index($code))
      | [$code, $province.name, .name]
      | @tsv
    ' "$(whitelist_city_meta_file)"
}

whitelist_city_province_code_by_selector() {
    local selector="$1"
    whitelist_require_city_assets
    jq -er --arg selector "$selector" '
      def norm:
        gsub("(特别行政区|维吾尔自治区|壮族自治区|回族自治区|自治区|省|市|地区|盟)$"; "");
      [ .provinces[]? | select(((.cities // []) | length) > 0) ] as $items
      | ($selector | gsub("^\\s+|\\s+$"; "")) as $raw
      | ($raw | norm) as $normalized
      | first(
          $items
          | to_entries[]
          | select(
              ((.key + 1) | tostring) == $raw
              or ((.value.code | tostring) == $raw)
              or (.value.name == $raw)
              or ((.value.name | norm) == $normalized)
            )
          | (.value.code | tostring)
        )
    ' "$(whitelist_city_meta_file)" 2>/dev/null || pfwd_die "未找到可选省份：$selector"
}

whitelist_city_code_by_selector() {
    local province_selector="$1"
    local city_selector="$2"
    local province_code
    province_code="$(whitelist_city_province_code_by_selector "$province_selector")"
    jq -er --arg province_code "$province_code" --arg selector "$city_selector" '
      def norm:
        gsub("(特别行政区|维吾尔自治区|壮族自治区|回族自治区|自治区|省|市|地区|盟)$"; "");
      (.provinces[]? | select((.code | tostring) == $province_code)) as $province
      | ($province.cities // []) as $items
      | ($selector | gsub("^\\s+|\\s+$"; "")) as $raw
      | ($raw | norm) as $normalized
      | first(
          $items
          | to_entries[]
          | select(
              ((.key + 1) | tostring) == $raw
              or ((.value.code | tostring) == $raw)
              or (.value.name == $raw)
              or ((.value.name | norm) == $normalized)
            )
          | (.value.code | tostring)
        )
    ' "$(whitelist_city_meta_file)" 2>/dev/null || pfwd_die "未找到城市：$city_selector"
}

whitelist_validate_city_codes_file() {
    local codes_file="$1"
    [ -f "$codes_file" ] || pfwd_die "城市临时文件不存在：$codes_file"
    whitelist_require_city_assets
    local tmp code
    tmp="$(mktemp)"
    whitelist_city_available_codes > "$tmp"
    while IFS= read -r code; do
        code="$(printf '%s' "$code" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -n "$code" ] || continue
        grep -Fxq "$code" "$tmp" || { rm -f "$tmp"; pfwd_die "未知城市 code：$code"; }
    done < "$codes_file"
    rm -f "$tmp"
}

whitelist_city_available_codes() {
    jq -r '.provinces[]? | (.cities // [])[]? | (.code | tostring)' "$(whitelist_city_meta_file)"
}

whitelist_city_selection_summary() {
    whitelist_city_selection_summary_from_codes_json "$(whitelist_cn_city_codes_json)"
}

whitelist_city_selection_summary_from_codes_json() {
    local codes_json="$1"
    local count preview suffix
    local -a rows=() shown=()
    if [ "$(jq -r 'length' <<< "$codes_json")" -eq 0 ]; then
        printf '未选择'
        return 0
    fi
    mapfile -t rows < <(whitelist_city_selected_rows_from_codes_json "$codes_json" | awk -F '\t' '{print $2 "/" $3}')
    count="${#rows[@]}"
    if [ "$count" -eq 0 ]; then
        printf '未选择'
        return 0
    fi
    if [ "$count" -le 2 ]; then
        printf '%s' "$(printf '%s\n' "${rows[@]}" | pfwd_join_lines '、')"
        return 0
    fi
    shown=("${rows[@]:0:3}")
    suffix=""
    [ "$count" -gt 3 ] && suffix="..."
    preview="$(printf '%s\n' "${shown[@]}" | pfwd_join_lines '、')"
    printf '%s 个（%s%s）' "$count" "$preview" "$suffix"
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

whitelist_config_set_city_codes() {
    local codes_file="$1"
    local normalized_file
    [ -f "$codes_file" ] || pfwd_die "城市临时文件不存在：$codes_file"
    whitelist_validate_city_codes_file "$codes_file"
    normalized_file="$(mktemp)"
    awk 'NR == FNR { wanted[$1] = 1; next } ($1 in wanted) { print }' \
      "$codes_file" <(whitelist_city_available_codes) > "$normalized_file"
    config_update --rawfile codes "$normalized_file" '
      (.settings.whitelist //= {})
      | .settings.whitelist.cn_city_codes =
          (($codes
            | split("\n")
            | map(gsub("^\\s+|\\s+$"; ""))
            | map(select(length > 0))
            | reduce .[] as $code ([]; if index($code) then . else . + [$code] end)))
    '
    rm -f "$normalized_file"
}

whitelist_port_policy_base_json() {
    local listen_port="$1"
    local existing
    existing="$(whitelist_port_policy_json "$listen_port")"
    if [ -n "$existing" ]; then
        jq -c --argjson port "$listen_port" '
          .listen_port = $port
          | .cn_mode = (.cn_mode // "off")
          | .cn_provinces = (.cn_provinces // [])
          | .cn_city_codes = (.cn_city_codes // [])
        ' <<< "$existing"
        return 0
    fi
    jq -n \
      --argjson port "$listen_port" \
      --arg mode "$(whitelist_cn_mode)" \
      --argjson provinces "$(whitelist_cn_provinces_json)" \
      --argjson codes "$(whitelist_cn_city_codes_json)" '
      {
        listen_port: $port,
        cn_mode: $mode,
        cn_provinces: $provinces,
        cn_city_codes: $codes
      }
    '
}

whitelist_config_upsert_port_policy_json() {
    local policy_json="$1"
    local listen_port
    listen_port="$(jq -r '.listen_port' <<< "$policy_json")"
    validate_port "$listen_port"
    config_update --argjson policy "$policy_json" '
      (.settings.whitelist //= {})
      | (.settings.whitelist.port_policies //= [])
      | .settings.whitelist.port_policies =
          (
            ((.settings.whitelist.port_policies // [])
             | map(select((.listen_port // 0) != ($policy.listen_port // 0)))) + [$policy]
          )
          | sort_by(.listen_port)
    '
}

whitelist_config_apply_port_cn_selection() {
    local listen_port="$1"
    local mode="$2"
    local provinces_file="${3:-}"
    validate_port "$listen_port"
    whitelist_validate_cn_mode "$mode"
    case "$mode" in
        off|all)
            whitelist_config_upsert_port_policy_json "$(
              whitelist_port_policy_base_json "$listen_port" | jq -c --arg mode "$mode" '
                .cn_mode = $mode
                | .cn_provinces = []
              '
            )"
            ;;
        provinces)
            [ -n "$provinces_file" ] || pfwd_die "缺少入口端口省份列表"
            [ -f "$provinces_file" ] || pfwd_die "入口端口省份临时文件不存在：$provinces_file"
            whitelist_validate_cn_provinces_file "$provinces_file"
            whitelist_config_upsert_port_policy_json "$(
              whitelist_port_policy_base_json "$listen_port" | jq -c --arg mode "$mode" --rawfile provinces "$provinces_file" '
                .cn_mode = $mode
                | .cn_provinces =
                    (($provinces
                      | split("\n")
                      | map(gsub("^\\s+|\\s+$"; ""))
                      | map(select(length > 0))
                      | reduce .[] as $province ([]; if index($province) then . else . + [$province] end)))
              '
            )"
            ;;
    esac
}

whitelist_config_set_port_city_codes() {
    local listen_port="$1"
    local codes_file="$2"
    local normalized_file
    validate_port "$listen_port"
    [ -f "$codes_file" ] || pfwd_die "入口端口城市临时文件不存在：$codes_file"
    whitelist_validate_city_codes_file "$codes_file"
    normalized_file="$(mktemp)"
    awk 'NR == FNR { wanted[$1] = 1; next } ($1 in wanted) { print }' \
      "$codes_file" <(whitelist_city_available_codes) > "$normalized_file"
    whitelist_config_upsert_port_policy_json "$(
      whitelist_port_policy_base_json "$listen_port" | jq -c --rawfile codes "$normalized_file" '
        .cn_city_codes =
          (($codes
            | split("\n")
            | map(gsub("^\\s+|\\s+$"; ""))
            | map(select(length > 0))
            | reduce .[] as $code ([]; if index($code) then . else . + [$code] end)))
      '
    )"
    rm -f "$normalized_file"
}

whitelist_clear_port_city_codes() {
    local listen_port="$1"
    validate_port "$listen_port"
    whitelist_config_upsert_port_policy_json "$(
      whitelist_port_policy_base_json "$listen_port" | jq -c '.cn_city_codes = []'
    )"
}

whitelist_delete_port_city_codes_by_indexes() {
    local listen_port="$1"
    local indexes="$2"
    validate_port "$listen_port"
    [ -n "$indexes" ] || pfwd_die "缺少入口端口市白名单序号"
    whitelist_config_upsert_port_policy_json "$(
      whitelist_port_policy_base_json "$listen_port" \
        | jq -c --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
            (.cn_city_codes // []) as $items
            | if ($idxs | length) == 0 then
                error("缺少入口端口市白名单序号")
              elif (($idxs | min) < 1) or (($idxs | max) > ($items | length)) then
                error("入口端口市白名单序号超出范围")
              else
                .cn_city_codes =
                  [ range(0; $items | length) as $i | select(([$idxs[] - 1] | index($i)) | not) | $items[$i] ]
              end
          '
    )"
}

whitelist_clear_port_policy() {
    local listen_port="$1"
    validate_port "$listen_port"
    config_update --argjson port "$listen_port" '
      (.settings.whitelist //= {})
      | .settings.whitelist.port_policies =
          ((.settings.whitelist.port_policies // []) | map(select((.listen_port // 0) != $port)))
    '
}

whitelist_clear_city_codes() {
    config_update '
      (.settings.whitelist //= {})
      | .settings.whitelist.cn_city_codes = []
    '
}

whitelist_delete_city_codes_by_indexes() {
    local indexes="$1"
    [ -n "$indexes" ] || pfwd_die "缺少市白名单序号"
    config_update --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      (.settings.whitelist //= {})
      | (.settings.whitelist.cn_city_codes // []) as $items
      | if ($idxs | length) == 0 then
          error("缺少市白名单序号")
        elif (($idxs | min) < 1) or (($idxs | max) > ($items | length)) then
          error("市白名单序号超出范围")
        else
          .settings.whitelist.cn_city_codes =
            [ range(0; $items | length) as $i | select(([$idxs[] - 1] | index($i)) | not) | $items[$i] ]
        end
    '
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
    local tmp_v4 tmp_v6 tmp_lease_v4 tmp_lease_v6
    tmp_v4="$(mktemp)"
    tmp_v6="$(mktemp)"
    tmp_lease_v4="$(mktemp)"
    tmp_lease_v6="$(mktemp)"
    whitelist_custom_cidrs_tsv | whitelist_filter_ipv4_cidrs >> "$tmp_v4"
    whitelist_custom_cidrs_tsv | whitelist_filter_ipv6_cidrs >> "$tmp_v6"
    whitelist_lease_custom_cidrs_tsv | whitelist_filter_ipv4_cidrs >> "$tmp_lease_v4"
    whitelist_lease_custom_cidrs_tsv | whitelist_filter_ipv6_cidrs >> "$tmp_lease_v6"
    cat "$tmp_lease_v4" >> "$tmp_v4"
    cat "$tmp_lease_v6" >> "$tmp_v6"
    whitelist_materialize_city_runtime

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
    if [ -s "$tmp_lease_v4" ]; then
        whitelist_write_allow_file "$tmp_lease_v4" > /dev/null 2>&1 || true
        sort -u "$tmp_lease_v4" | pfwd_write_atomic "$(whitelist_temp_allow_ipv4_file)"
    else
        : > "$(whitelist_temp_allow_ipv4_file)"
    fi
    if [ -s "$tmp_lease_v6" ]; then
        sort -u "$tmp_lease_v6" | pfwd_write_atomic "$(whitelist_temp_allow_ipv6_file)"
    else
        : > "$(whitelist_temp_allow_ipv6_file)"
    fi
    rm -f "$tmp_v4" "$tmp_v6" "$tmp_lease_v4" "$tmp_lease_v6"
}

whitelist_materialize_city_runtime() {
    local target tmp_codes
    target="$(whitelist_city_runtime_ipv4_file)"
    mkdir -p "$(dirname "$target")"
    tmp_codes="$(mktemp)"
    whitelist_cn_city_codes_tsv > "$tmp_codes"
    if [ ! -s "$tmp_codes" ]; then
        : > "$target"
        rm -f "$tmp_codes"
        return 0
    fi
    whitelist_require_city_assets
    [ -x "$(forwarder_bin_path)" ] || { rm -f "$tmp_codes"; pfwd_die "缺少 XDP 辅助程序：$(forwarder_bin_path)" ; }
    "$(forwarder_bin_path)" city-export \
      --asset-dir "$(whitelist_geo_asset_dir)" \
      --codes-file "$tmp_codes" | pfwd_write_atomic "$target"
    rm -f "$tmp_codes"
    [ -s "$target" ] || pfwd_die "已选市白名单没有可用 IPv4 CIDR"
}

whitelist_prepare_runtime() {
    if [ "$(whitelist_enabled)" != "true" ]; then
        rm -f "$(whitelist_allow_ipv4_file)" "$(whitelist_allow_ipv6_file)" 2>/dev/null || true
        rm -f "$(whitelist_allow_ipv4_file).cn" "$(whitelist_allow_ipv6_file).cn" 2>/dev/null || true
        rm -f "$(whitelist_city_runtime_ipv4_file)" 2>/dev/null || true
        rm -f "$(whitelist_temp_allow_ipv4_file)" "$(whitelist_temp_allow_ipv6_file)" 2>/dev/null || true
        return 0
    fi

    if [ "$(whitelist_any_geo_policy_enabled)" = "true" ]; then
        whitelist_require_geo_assets
    else
        rm -f "$(whitelist_allow_ipv4_file).cn" "$(whitelist_allow_ipv6_file).cn" 2>/dev/null || true
    fi
    if [ "$(whitelist_any_city_policy_enabled)" = "true" ]; then
        whitelist_require_city_assets
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
cn_city_codes=$(whitelist_cn_city_codes_tsv | paste -sd ',' -)
port_policies=$(whitelist_port_policies_json)
custom:
$(whitelist_custom_cidrs_tsv)
ipv4:
$(cat "$(whitelist_allow_ipv4_file)" 2>/dev/null || true)
ipv6:
$(cat "$(whitelist_allow_ipv6_file)" 2>/dev/null || true)
city_ipv4:
$(cat "$(whitelist_city_runtime_ipv4_file)" 2>/dev/null || true)
temp_ipv4:
$(cat "$(whitelist_temp_allow_ipv4_file)" 2>/dev/null || true)
temp_ipv6:
$(cat "$(whitelist_temp_allow_ipv6_file)" 2>/dev/null || true)
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
    local enabled cn_provinces cn_city_codes port_policies leases entries custom_cidrs_count lease_count city_count port_policy_count
    enabled="$(jq -cn --arg value "$(whitelist_enabled)" '$value == "true"')"
    cn_provinces="$(pfwd_capture_json_output "入口白名单省份配置" whitelist_cn_provinces_json)"
    cn_city_codes="$(pfwd_capture_json_output "入口白名单市配置" whitelist_cn_city_codes_json)"
    port_policies="$(pfwd_capture_json_output "入口白名单端口策略" whitelist_port_policies_json)"
    leases="$(pfwd_capture_json_output "入口白名单临时租约" whitelist_lease_entries_sorted_json)"
    entries="$(jq -cn --argjson value "$(whitelist_entry_count)" '$value')"
    custom_cidrs_count="$(jq -cn --argjson value "$(whitelist_custom_cidrs_count)" '$value')"
    lease_count="$(jq -cn --argjson value "$(whitelist_lease_count)" '$value')"
    city_count="$(jq -cn --argjson value "$(whitelist_city_codes_count)" '$value')"
    port_policy_count="$(jq -cn --argjson value "$(whitelist_port_policy_count)" '$value')"
    jq -n \
      --argjson enabled "$enabled" \
      --arg cn_mode "$(whitelist_cn_mode)" \
      --argjson cn_provinces "$cn_provinces" \
      --argjson cn_city_codes "$cn_city_codes" \
      --argjson port_policies "$port_policies" \
      --arg city_selection "$(whitelist_city_selection_summary)" \
      --arg allow_ipv4_file "$(whitelist_allow_ipv4_file)" \
      --arg allow_ipv6_file "$(whitelist_allow_ipv6_file)" \
      --arg city_ipv4_file "$(whitelist_city_runtime_ipv4_file)" \
      --arg temp_ipv4_file "$(whitelist_temp_allow_ipv4_file)" \
      --arg temp_ipv6_file "$(whitelist_temp_allow_ipv6_file)" \
      --argjson entries "$entries" \
      --argjson custom_cidrs_count "$custom_cidrs_count" \
      --argjson lease_count "$lease_count" \
      --argjson leases "$leases" \
      --argjson city_count "$city_count" \
      --argjson port_policy_count "$port_policy_count" \
      '{
        enabled: $enabled,
        cn_mode: $cn_mode,
        cn_provinces: $cn_provinces,
        cn_city_codes: $cn_city_codes,
        port_policies: $port_policies,
        city_selection: $city_selection,
        allow_ipv4_file: $allow_ipv4_file,
        allow_ipv6_file: $allow_ipv6_file,
        city_ipv4_file: $city_ipv4_file,
        temp_ipv4_file: $temp_ipv4_file,
        temp_ipv6_file: $temp_ipv6_file,
        entries: $entries,
        custom_cidrs_count: $custom_cidrs_count,
        lease_count: $lease_count,
        leases: $leases,
        city_count: $city_count,
        port_policy_count: $port_policy_count
      }'
}

whitelist_effective_cn_selection_summary_for_port() {
    local listen_port="$1"
    local mode provinces
    mode="$(whitelist_effective_cn_mode_for_port "$listen_port")"
    case "$mode" in
        all)
            printf '国内IP'
            ;;
        provinces)
            provinces="$(whitelist_effective_cn_provinces_tsv_for_port "$listen_port" | pfwd_join_lines '、')"
            [ -n "$provinces" ] || provinces="未选择"
            printf '省份：%s' "$provinces"
            ;;
        *)
            printf '关闭'
            ;;
    esac
}

whitelist_effective_city_selection_summary_for_port() {
    local listen_port="$1"
    whitelist_city_selection_summary_from_codes_json "$(whitelist_effective_cn_city_codes_json_for_port "$listen_port")"
}

whitelist_port_policy_rows() {
    local row port mode city source provinces_json codes_json city_summary cn_summary
    while IFS=$'\t' read -r port mode provinces_json codes_json; do
        [ -n "$port" ] || continue
        cn_summary="$(
          case "$mode" in
              all) printf '国内IP' ;;
              provinces)
                  jq -r '.[]' <<< "$provinces_json" | pfwd_join_lines '、' | {
                      IFS= read -r row
                      [ -n "$row" ] || row="未选择"
                      printf '省份：%s' "$row"
                  }
                  ;;
              *) printf '关闭' ;;
          esac
        )"
        city_summary="$(whitelist_city_selection_summary_from_codes_json "$codes_json")"
        source="$(whitelist_effective_policy_source_for_port "$port")"
        printf '%s\t%s\t%s\t%s\n' "$port" "$source" "$cn_summary" "$city_summary"
    done < <(jq -r '
      (.settings.whitelist.port_policies // [])
      | sort_by(.listen_port)
      | .[]
      | [
          (.listen_port | tostring),
          (.cn_mode // "off"),
          ((.cn_provinces // []) | @json),
          ((.cn_city_codes // []) | @json)
        ] | @tsv
    ' "$PFWD_CONFIG_FILE")
}

whitelist_port_policy_status_json() {
    local listen_port="$1"
    validate_port "$listen_port"
    jq -n \
      --argjson listen_port "$listen_port" \
      --arg source "$(whitelist_effective_policy_source_for_port "$listen_port")" \
      --arg mode "$(whitelist_effective_cn_mode_for_port "$listen_port")" \
      --argjson provinces "$(whitelist_effective_cn_provinces_json_for_port "$listen_port")" \
      --argjson city_codes "$(whitelist_effective_cn_city_codes_json_for_port "$listen_port")" \
      --arg cn_summary "$(whitelist_effective_cn_selection_summary_for_port "$listen_port")" \
      --arg city_summary "$(whitelist_effective_city_selection_summary_for_port "$listen_port")" '
      {
        listen_port: $listen_port,
        source: $source,
        cn_mode: $mode,
        cn_provinces: $provinces,
        cn_city_codes: $city_codes,
        cn_summary: $cn_summary,
        city_summary: $city_summary
      }
    '
}

whitelist_runtime_policies_json() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -c '
      def normalized_mode($wl):
        if (($wl.cn_mode // "") | type) == "string" and (($wl.cn_mode // "") | length) > 0 then
          $wl.cn_mode
        elif (($wl.include_cn? | type) == "boolean") then
          (if $wl.include_cn then "all" else "off" end)
        else
          "all"
        end;
      (.settings.whitelist // {}) as $wl
      | (
          [{
            id: 0,
            source: "global",
            cn_mode: normalized_mode($wl),
            cn_provinces: ($wl.cn_provinces // []),
            cn_city_codes: ($wl.cn_city_codes // [])
          }]
          + [
              ($wl.port_policies // [] | sort_by(.listen_port) | to_entries[]) as $entry
              | $entry.value
              | {
                  id: ($entry.key + 1),
                  source: "port",
                  listen_port: (.listen_port | tonumber),
                  cn_mode: (.cn_mode // "off"),
                  cn_provinces: (.cn_provinces // []),
                  cn_city_codes: (.cn_city_codes // [])
                }
            ]
        )
    ' "$config_file"
}

whitelist_render_status() {
    local json
    json="$(whitelist_status_json)"
    jq -r '
      [
        ["启用白名单", (if .enabled then "开" else "关" end)],
        ["国内 IP 策略", (if .enabled then (if .cn_mode == "all" then "国内IP" elif .cn_mode == "provinces" then ("省份：" + ((.cn_provinces // []) | join("、"))) else "关闭" end) else "-" end)],
        ["市白名单", (if .enabled then .city_selection else "-" end)],
        ["端口覆盖", (if .enabled then ((.port_policy_count // 0) | tostring) else "-" end)],
        ["自定义 CIDR", (.custom_cidrs_count | tostring)],
        ["临时白名单", (.lease_count | tostring)],
        ["白名单条目", (.entries | tostring)],
        ["IPv4 文件", .allow_ipv4_file],
        ["临时 IPv4 文件", .temp_ipv4_file],
        ["市级 IPv4 文件", .city_ipv4_file],
        ["IPv6 文件", .allow_ipv6_file],
        ["临时 IPv6 文件", .temp_ipv6_file]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}

whitelist_lease_save_json() {
    local payload="$1"
    mkdir -p "$(dirname "$(whitelist_leases_file)")"
    printf '%s\n' "$payload" | jq '.' | pfwd_write_atomic "$(whitelist_leases_file)"
}

whitelist_lease_upsert() {
    local address="$1"
    local idle_ttl_sec="$2"
    local note="$3"
    local channel="$4"
    local now granted_at
    local cidr payload
    cidr="$(normalize_ip_literal_to_cidr "$address")"
    address="${cidr%/*}"
    now="$(pfwd_now_epoch)"
    payload="$(
      whitelist_lease_entries_json | jq -c \
        --arg address "$address" \
        --arg cidr "$cidr" \
        --arg note "$note" \
        --arg channel "$channel" \
        --argjson idle_ttl_sec "$idle_ttl_sec" \
        --argjson now "$now" '
        (map(select((.address // "") != $address))) as $rest
        | (map(select((.address // "") == $address)) | first // null) as $existing
        | ($existing.last_seen_at // null) as $last_seen
        | $rest + [{
            address: $address,
            cidr: $cidr,
            idle_ttl_sec: $idle_ttl_sec,
            granted_at: $now,
            last_seen_at: $last_seen,
            note: $note,
            channel: $channel
          }]
      '
    )"
    whitelist_lease_save_json "$payload"
}

whitelist_lease_delete_by_address() {
    local address="$1"
    local payload
    address="$(normalize_ip_literal_to_cidr "$address")"
    address="${address%/*}"
    payload="$(whitelist_lease_entries_json | jq -c --arg address "$address" '
      map(select((.address // "") != $address))
    ')"
    whitelist_lease_save_json "$payload"
}

whitelist_lease_clear_all() {
    whitelist_lease_save_json '[]'
}

whitelist_lease_delete_by_indexes() {
    local indexes="$1"
    local payload
    [ -n "$indexes" ] || pfwd_die "缺少临时白名单序号"
    payload="$(whitelist_lease_entries_sorted_json | jq -c --arg raw "$indexes" '
      ($raw | split("\n") | map(select(length > 0) | tonumber)) as $wanted
      | to_entries
      | map(select((($wanted | index(.key + 1)) | not)))
      | map(.value)
    ')"
    whitelist_lease_save_json "$payload"
}

whitelist_lease_list_rows() {
    whitelist_lease_entries_sorted_json | jq -r '
      to_entries[]
      | [
          ((.key + 1) | tostring),
          (.value.address // "-"),
          ((.value.idle_ttl_sec // 0) | tostring),
          (if (.value.last_seen_at // null) == null then "-" else (.value.last_seen_at | tostring) end),
          ((.value.granted_at // 0) | tostring),
          (.value.channel // "-"),
          (.value.note // "-")
        ] | @tsv
    '
}

whitelist_lease_status_json() {
    jq -n \
      --argjson count "$(whitelist_lease_count)" \
      --argjson leases "$(whitelist_lease_entries_sorted_json)" \
      '{
        count: $count,
        leases: $leases
      }'
}

whitelist_lease_materialize_activity_json() {
    local file="${1:-}"
    if [ -n "$file" ] && [ -f "$file" ]; then
        jq -c 'if type == "array" then . else [] end' "$file" 2>/dev/null || printf '[]\n'
    else
        printf '[]\n'
    fi
}

whitelist_lease_reconcile_activity() {
    local activity_json="$1"
    local now payload
    now="$(pfwd_now_epoch)"
    payload="$(
      jq -nc \
        --argjson leases "$(whitelist_lease_entries_json)" \
        --argjson activity "$activity_json" \
        --argjson now "$now" '
        def activity_map:
          reduce $activity[]? as $row ({};
            if (($row.address // "") | length) == 0 then
              .
            else
              .[$row.address] = (($row.last_seen_at // 0) | tonumber)
            end
          );
        (activity_map) as $active
        | ($leases // [])
        | map(
            .address = (.address // "")
            | .idle_ttl_sec = ((.idle_ttl_sec // 0) | tonumber)
            | .granted_at = ((.granted_at // 0) | tonumber)
            | .last_seen_at =
                (if ($active[.address] // 0) > 0 then ($active[.address]) else (.last_seen_at // null) end)
          )
        | map(
            .last_active_at = (if (.last_seen_at // null) == null then .granted_at else .last_seen_at end)
          )
        | map(select((.last_active_at + .idle_ttl_sec) > $now))
        | map(del(.last_active_at))
      '
    )"
    whitelist_lease_save_json "$payload"
}
