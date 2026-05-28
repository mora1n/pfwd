#!/usr/bin/env bash

whitelist_default_source_url() {
    printf '%s\n' "https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone"
}

whitelist_default_ipv6_source_url() {
    printf '%s\n' "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/cn-aggregated.zone"
}

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
    jq -r '.settings.whitelist.include_cn // true' "$PFWD_CONFIG_FILE"
}

whitelist_source_url() {
    jq -r --arg url "$(whitelist_default_source_url)" '.settings.whitelist.source_url // $url' "$PFWD_CONFIG_FILE"
}

whitelist_last_good_source() {
    jq -r '.settings.whitelist.last_good_source // ""' "$PFWD_CONFIG_FILE"
}

whitelist_last_good_updated_at() {
    jq -r '.settings.whitelist.last_good_updated_at // empty' "$PFWD_CONFIG_FILE"
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

whitelist_mark_last_good() {
    local source="$1"
    local updated_at="$2"
    config_update --arg source "$source" --arg updated_at "$updated_at" '
      (.settings.whitelist //= {})
      | .settings.whitelist.last_good_source = $source
      | .settings.whitelist.last_good_updated_at = $updated_at
    '
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
    local include_cn="$2"
    local source_url="$3"
    validate_bool "$enabled"
    validate_bool "$include_cn"
    [ -n "$source_url" ] || source_url="$(whitelist_default_source_url)"
    config_update \
      --argjson enabled "$enabled" \
      --argjson include_cn "$include_cn" \
      --arg source_url "$source_url" '
      (.settings.whitelist //= {})
      | .settings.whitelist.enabled = $enabled
      | .settings.whitelist.include_cn = $include_cn
      | .settings.whitelist.source_url = $source_url
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

whitelist_refresh_cn() {
    local url tmp
    url="$(whitelist_source_url)"
    tmp="$(mktemp)"
    pfwd_bootstrap_download "$url" "$tmp"
    whitelist_write_allow_file "$tmp"
    rm -f "$tmp"
    whitelist_mark_last_good "$url" "$(pfwd_now_iso)"
}

whitelist_refresh_cn_ipv6() {
    local url tmp
    url="$(whitelist_default_ipv6_source_url)"
    tmp="$(mktemp)"
    pfwd_bootstrap_download "$url" "$tmp"
    whitelist_write_allow_ipv6_file "$tmp"
    rm -f "$tmp"
}

whitelist_import_local_cn_seed() {
    local file_path="$PFWD_INSTALL_DIR/assets/cn-aggregated.zone"
    [ -f "$file_path" ] || return 1
    whitelist_write_allow_file "$file_path"
    whitelist_mark_last_good "$file_path" "$(pfwd_now_iso)"
}

whitelist_import_local_cn_seed_ipv6() {
    local file_path="$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone"
    [ -f "$file_path" ] || return 1
    whitelist_write_allow_ipv6_file "$file_path"
}

whitelist_sync_cn() {
    if ! whitelist_import_local_cn_seed; then
        whitelist_refresh_cn
    fi
    if ! whitelist_import_local_cn_seed_ipv6; then
        whitelist_refresh_cn_ipv6
    fi
}

whitelist_merge_runtime() {
    local tmp_v4 tmp_v6
    tmp_v4="$(mktemp)"
    tmp_v6="$(mktemp)"
    if [ "$(whitelist_include_cn)" = "true" ]; then
        if [ -s "$(whitelist_allow_ipv4_file).cn" ]; then
            cat "$(whitelist_allow_ipv4_file).cn" >> "$tmp_v4"
            printf '\n' >> "$tmp_v4"
        fi
        if [ -s "$(whitelist_allow_ipv6_file).cn" ]; then
            cat "$(whitelist_allow_ipv6_file).cn" >> "$tmp_v6"
            printf '\n' >> "$tmp_v6"
        fi
    fi
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
    local cn_tmp
    if [ "$(whitelist_enabled)" != "true" ]; then
        rm -f "$(whitelist_allow_ipv4_file)" "$(whitelist_allow_ipv6_file)" 2>/dev/null || true
        rm -f "$(whitelist_allow_ipv4_file).cn" "$(whitelist_allow_ipv6_file).cn" 2>/dev/null || true
        return 0
    fi

    if [ "$(whitelist_include_cn)" = "true" ]; then
        cn_tmp="$(mktemp)"
        if [ -f "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone" ]; then
            whitelist_filter_ipv4_cidrs < "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone" | pfwd_write_atomic "$cn_tmp"
            whitelist_mark_last_good "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone" "$(pfwd_now_iso)"
        else
            pfwd_bootstrap_download "$(whitelist_source_url)" "$cn_tmp"
            whitelist_filter_ipv4_cidrs < "$cn_tmp" | pfwd_write_atomic "$cn_tmp.filtered"
            mv "$cn_tmp.filtered" "$cn_tmp"
            whitelist_mark_last_good "$(whitelist_source_url)" "$(pfwd_now_iso)"
        fi
        mv "$cn_tmp" "$(whitelist_allow_ipv4_file).cn"

        cn_tmp="$(mktemp)"
        if [ -f "$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone" ]; then
            whitelist_filter_ipv6_cidrs < "$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone" | pfwd_write_atomic "$cn_tmp"
        else
            pfwd_bootstrap_download "$(whitelist_default_ipv6_source_url)" "$cn_tmp"
            whitelist_filter_ipv6_cidrs < "$cn_tmp" | pfwd_write_atomic "$cn_tmp.filtered"
            mv "$cn_tmp.filtered" "$cn_tmp"
        fi
        mv "$cn_tmp" "$(whitelist_allow_ipv6_file).cn"
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
include_cn=$(whitelist_include_cn)
source=$(whitelist_source_url)
last_good_source=$(whitelist_last_good_source)
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
      --argjson include_cn "$(whitelist_include_cn)" \
      --arg source_url "$(whitelist_source_url)" \
      --arg allow_ipv4_file "$(whitelist_allow_ipv4_file)" \
      --arg allow_ipv6_file "$(whitelist_allow_ipv6_file)" \
      --arg last_good_source "$(whitelist_last_good_source)" \
      --arg last_good_updated_at "$(whitelist_last_good_updated_at)" \
      --argjson entries "$(whitelist_entry_count)" \
      --argjson custom_cidrs_count "$(whitelist_custom_cidrs_count)" \
      '{
        enabled: $enabled,
        include_cn: $include_cn,
        source_url: $source_url,
        allow_ipv4_file: $allow_ipv4_file,
        allow_ipv6_file: $allow_ipv6_file,
        last_good_source: $last_good_source,
        last_good_updated_at: (if $last_good_updated_at == "" then null else $last_good_updated_at end),
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
        ["包含国内 IP", (if .enabled then (if .include_cn then "开" else "关" end) else "-" end)],
        ["自定义 CIDR", (.custom_cidrs_count | tostring)],
        ["白名单条目", (.entries | tostring)],
        ["来源地址", (if .last_good_source == "" then .source_url else .last_good_source end)],
        ["IPv4 文件", .allow_ipv4_file],
        ["IPv6 文件", .allow_ipv6_file]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}
