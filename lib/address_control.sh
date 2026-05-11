#!/usr/bin/env bash

address_control_default_source_url() {
    printf '%s\n' "https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone"
}

address_control_default_ipv6_source_url() {
    printf '%s\n' "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/cn-aggregated.zone"
}

address_control_state_dir() {
    printf '%s\n' "$PFWD_ADDRESS_CONTROL_STATE_DIR"
}

address_control_allow_file() {
    printf '%s\n' "$PFWD_ADDRESS_CONTROL_ALLOW_IPV4_FILE"
}

address_control_allow_ipv4_file() {
    printf '%s\n' "$PFWD_ADDRESS_CONTROL_ALLOW_IPV4_FILE"
}

address_control_allow_ipv6_file() {
    printf '%s\n' "$PFWD_ADDRESS_CONTROL_ALLOW_IPV6_FILE"
}

address_control_enabled() {
    jq -r '.settings.address_control.enabled // false' "$PFWD_CONFIG_FILE"
}

address_control_include_cn() {
    jq -r '.settings.address_control.include_cn // true' "$PFWD_CONFIG_FILE"
}

address_control_source_url() {
    jq -r --arg url "$(address_control_default_source_url)" '.settings.address_control.source_url // $url' "$PFWD_CONFIG_FILE"
}

address_control_last_good_source() {
    jq -r '.settings.address_control.last_good_source // ""' "$PFWD_CONFIG_FILE"
}

address_control_last_good_updated_at() {
    jq -r '.settings.address_control.last_good_updated_at // empty' "$PFWD_CONFIG_FILE"
}

address_control_custom_cidrs_tsv() {
    jq -r '.settings.address_control.custom_cidrs // [] | .[]' "$PFWD_CONFIG_FILE"
}

address_control_custom_cidrs_json() {
    jq -c '.settings.address_control.custom_cidrs // []' "$PFWD_CONFIG_FILE"
}

address_control_entry_count() {
    local total=0
    if [ -s "$(address_control_allow_ipv4_file)" ]; then
        total=$((total + $(sed '/^$/d' "$(address_control_allow_ipv4_file)" | wc -l | tr -d ' ')))
    fi
    if [ -s "$(address_control_allow_ipv6_file)" ]; then
        total=$((total + $(sed '/^$/d' "$(address_control_allow_ipv6_file)" | wc -l | tr -d ' ')))
    fi
    echo "$total"
}

address_control_custom_cidrs_count() {
    jq -r '.settings.address_control.custom_cidrs // [] | length' "$PFWD_CONFIG_FILE"
}

address_control_family() {
    printf '%s\n' "$PFWD_ADDRESS_CONTROL_FAMILY"
}

address_control_table() {
    printf '%s\n' "$PFWD_ADDRESS_CONTROL_TABLE"
}

address_control_runtime_hash() {
    jq -r '.settings.address_control.runtime_hash // ""' "$PFWD_CONFIG_FILE"
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

address_control_filter_ipv6_cidrs() {
    python3 -c '
import ipaddress
import sys

items = set()
for raw in sys.stdin:
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    try:
        network = ipaddress.ip_network(line, strict=False)
    except Exception:
        continue
    if network.version != 6:
        continue
    items.add(str(network))

for item in sorted(items):
    print(item)
'
}

address_control_write_allow_file() {
    local source_file="$1"
    local target_file
    target_file="$(address_control_allow_ipv4_file)"
    mkdir -p "$(dirname "$target_file")"
    address_control_filter_ipv4_cidrs < "$source_file" | pfwd_write_atomic "$target_file"
    [ -s "$target_file" ] || pfwd_die "白名单来源 IP 集合为空：$source_file"
}

address_control_write_allow_ipv6_file() {
    local source_file="$1"
    local target_file
    target_file="$(address_control_allow_ipv6_file)"
    mkdir -p "$(dirname "$target_file")"
    address_control_filter_ipv6_cidrs < "$source_file" | pfwd_write_atomic "$target_file"
    [ -s "$target_file" ] || pfwd_die "白名单来源 IPv6 集合为空：$source_file"
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

address_control_validate_custom_cidrs() {
    local cidr
    while IFS= read -r cidr; do
        [ -n "$cidr" ] || continue
        validate_ip_cidr "$cidr"
    done
}

address_control_config_set_state() {
    local enabled="$1"
    local include_cn="$2"
    local source_url="$3"
    validate_bool "$enabled"
    validate_bool "$include_cn"
    [ -n "$source_url" ] || source_url="$(address_control_default_source_url)"
    config_update \
      --argjson enabled "$enabled" \
      --argjson include_cn "$include_cn" \
      --arg source_url "$source_url" '
      (.settings.address_control //= {})
      | .settings.address_control.enabled = $enabled
      | .settings.address_control.include_cn = $include_cn
      | .settings.address_control.source_url = $source_url
    '
}

address_control_config_set_custom_cidrs() {
    local cidrs_file="$1"
    [ -f "$cidrs_file" ] || pfwd_die "自定义 CIDR 临时文件不存在：$cidrs_file"
    address_control_validate_custom_cidrs < "$cidrs_file"
    config_update --rawfile cidrs "$cidrs_file" '
      (.settings.address_control //= {})
      | .settings.address_control.custom_cidrs =
          (($cidrs
            | split("\n")
            | map(gsub("^\\s+|\\s+$"; ""))
            | map(select(length > 0))
            | unique))
    '
}

address_control_append_custom_cidr() {
    local cidr="$1"
    validate_ip_cidr "$cidr"
    config_update --arg cidr "$cidr" '
      (.settings.address_control //= {})
      | .settings.address_control.custom_cidrs =
          (((.settings.address_control.custom_cidrs // []) + [$cidr]) | unique)
    '
}

address_control_clear_custom_cidrs() {
    config_update '
      (.settings.address_control //= {})
      | .settings.address_control.custom_cidrs = []
    '
}

address_control_replace_custom_cidr_by_index() {
    local index="$1"
    local cidr="$2"
    validate_ip_cidr "$cidr"
    [[ "$index" =~ ^[0-9]+$ ]] || pfwd_die "无效自定义 CIDR 序号：$index"
    config_update --argjson index "$index" --arg cidr "$cidr" '
      (.settings.address_control //= {})
      | (.settings.address_control.custom_cidrs // []) as $items
      | if $index < 1 or $index > ($items | length) then
          error("自定义 CIDR 序号超出范围")
        else
          .settings.address_control.custom_cidrs =
            ([ range(0; $items|length) as $i | if $i == ($index - 1) then $cidr else $items[$i] end ] | unique)
        end
    '
}

address_control_delete_custom_cidrs_by_indexes() {
    local indexes="$1"
    [ -n "$indexes" ] || pfwd_die "缺少自定义 CIDR 序号"
    config_update --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      (.settings.address_control //= {})
      | (.settings.address_control.custom_cidrs // []) as $items
      | if ($idxs | length) == 0 then
          error("缺少自定义 CIDR 序号")
        elif (($idxs | min) < 1) or (($idxs | max) > ($items | length)) then
          error("自定义 CIDR 序号超出范围")
        else
          .settings.address_control.custom_cidrs =
            [ range(0; $items | length) as $i | select(([$idxs[] - 1] | index($i)) | not) | $items[$i] ]
        end
    '
}

address_control_custom_cidr_by_index() {
    local index="$1"
    [[ "$index" =~ ^[0-9]+$ ]] || pfwd_die "无效自定义 CIDR 序号：$index"
    jq -r --argjson index "$index" '
      (.settings.address_control.custom_cidrs // [])[($index - 1)] // empty
    ' "$PFWD_CONFIG_FILE"
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

address_control_refresh_cn_ipv6() {
    local url tmp
    url="$(address_control_default_ipv6_source_url)"
    tmp="$(mktemp)"
    pfwd_bootstrap_download "$url" "$tmp"
    address_control_write_allow_ipv6_file "$tmp"
    rm -f "$tmp"
}

address_control_import_local_cn_seed() {
    local file_path="$PFWD_INSTALL_DIR/assets/cn-aggregated.zone"
    [ -f "$file_path" ] || return 1
    address_control_write_allow_file "$file_path"
    address_control_mark_last_good "$file_path" "$(pfwd_now_iso)"
}

address_control_import_local_cn_seed_ipv6() {
    local file_path="$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone"
    [ -f "$file_path" ] || return 1
    address_control_write_allow_ipv6_file "$file_path"
}

address_control_sync_cn() {
    if ! address_control_import_local_cn_seed; then
        address_control_refresh_cn
    fi
    if ! address_control_import_local_cn_seed_ipv6; then
        address_control_refresh_cn_ipv6
    fi
}

address_control_merge_runtime() {
    local tmp_v4 tmp_v6
    tmp_v4="$(mktemp)"
    tmp_v6="$(mktemp)"
    if [ "$(address_control_include_cn)" = "true" ]; then
        if [ -s "$(address_control_allow_ipv4_file).cn" ]; then
            cat "$(address_control_allow_ipv4_file).cn" >> "$tmp_v4"
            printf '\n' >> "$tmp_v4"
        fi
        if [ -s "$(address_control_allow_ipv6_file).cn" ]; then
            cat "$(address_control_allow_ipv6_file).cn" >> "$tmp_v6"
            printf '\n' >> "$tmp_v6"
        fi
    fi
    address_control_custom_cidrs_tsv | address_control_filter_ipv4_cidrs >> "$tmp_v4"
    address_control_custom_cidrs_tsv | address_control_filter_ipv6_cidrs >> "$tmp_v6"

    if [ -s "$tmp_v4" ]; then
        address_control_write_allow_file "$tmp_v4"
    else
        : > "$(address_control_allow_ipv4_file)"
    fi
    if [ -s "$tmp_v6" ]; then
        address_control_write_allow_ipv6_file "$tmp_v6"
    else
        : > "$(address_control_allow_ipv6_file)"
    fi
    rm -f "$tmp_v4" "$tmp_v6"
}

address_control_prepare_runtime() {
    local cn_tmp
    if [ "$(address_control_enabled)" != "true" ]; then
        rm -f "$(address_control_allow_ipv4_file)" "$(address_control_allow_ipv6_file)" 2>/dev/null || true
        rm -f "$(address_control_allow_ipv4_file).cn" "$(address_control_allow_ipv6_file).cn" 2>/dev/null || true
        return 0
    fi

    if [ "$(address_control_include_cn)" = "true" ]; then
        cn_tmp="$(mktemp)"
        if [ -f "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone" ]; then
            address_control_filter_ipv4_cidrs < "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone" | pfwd_write_atomic "$cn_tmp"
            address_control_mark_last_good "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone" "$(pfwd_now_iso)"
        else
            pfwd_bootstrap_download "$(address_control_source_url)" "$cn_tmp"
            address_control_filter_ipv4_cidrs < "$cn_tmp" | pfwd_write_atomic "$cn_tmp.filtered"
            mv "$cn_tmp.filtered" "$cn_tmp"
            address_control_mark_last_good "$(address_control_source_url)" "$(pfwd_now_iso)"
        fi
        mv "$cn_tmp" "$(address_control_allow_ipv4_file).cn"

        cn_tmp="$(mktemp)"
        if [ -f "$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone" ]; then
            address_control_filter_ipv6_cidrs < "$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone" | pfwd_write_atomic "$cn_tmp"
        else
            pfwd_bootstrap_download "$(address_control_default_ipv6_source_url)" "$cn_tmp"
            address_control_filter_ipv6_cidrs < "$cn_tmp" | pfwd_write_atomic "$cn_tmp.filtered"
            mv "$cn_tmp.filtered" "$cn_tmp"
        fi
        mv "$cn_tmp" "$(address_control_allow_ipv6_file).cn"
    else
        rm -f "$(address_control_allow_ipv4_file).cn" "$(address_control_allow_ipv6_file).cn" 2>/dev/null || true
    fi

    address_control_merge_runtime
}

address_control_runtime_enabled() {
    [ "$(address_control_enabled)" = "true" ] && echo true || echo false
}

address_control_runtime_hash_compute() {
    local payload
    payload="$(cat <<EOF
enabled=$(address_control_enabled)
include_cn=$(address_control_include_cn)
source=$(address_control_source_url)
last_good_source=$(address_control_last_good_source)
custom:
$(address_control_custom_cidrs_tsv)
ipv4:
$(cat "$(address_control_allow_ipv4_file)" 2>/dev/null || true)
ipv6:
$(cat "$(address_control_allow_ipv6_file)" 2>/dev/null || true)
EOF
)"
    printf '%s' "$payload" | cksum | awk '{print $1}'
}

address_control_update_runtime_hash() {
    local runtime_hash="$1"
    config_update --arg runtime_hash "$runtime_hash" '
      (.settings.address_control //= {})
      | .settings.address_control.runtime_hash = $runtime_hash
    '
}

address_control_render_nft() {
    local family table
    family="$(address_control_family)"
    table="$(address_control_table)"

    echo "table $family $table {"
    if [ "$(address_control_runtime_enabled)" = "true" ]; then
        if [ -s "$(address_control_allow_ipv4_file)" ]; then
            echo "    set pfwd_addrctl_allow_v4 {"
            echo "        type ipv4_addr"
            echo "        flags interval"
            echo "        elements = {"
            sed 's/^/            /;s/$/,/' "$(address_control_allow_ipv4_file)"
            echo "        }"
            echo "    }"
            echo
        fi
        if [ -s "$(address_control_allow_ipv6_file)" ]; then
            echo "    set pfwd_addrctl_allow_v6 {"
            echo "        type ipv6_addr"
            echo "        flags interval"
            echo "        elements = {"
            sed 's/^/            /;s/$/,/' "$(address_control_allow_ipv6_file)"
            echo "        }"
            echo "    }"
            echo
        fi
    fi
    echo "    chain forward {"
    echo "        type filter hook forward priority 5; policy accept;"
    if [ "$(address_control_runtime_enabled)" = "true" ]; then
        if [ -s "$(address_control_allow_ipv4_file)" ]; then
            echo '        ct status dnat ct state new meta nfproto ipv4 ip saddr != @pfwd_addrctl_allow_v4 drop comment "Inbound whitelist denies unmatched IPv4 sources"'
        fi
        if [ -s "$(address_control_allow_ipv6_file)" ]; then
            echo '        ct status dnat ct state new meta nfproto ipv6 ip6 saddr != @pfwd_addrctl_allow_v6 drop comment "Inbound whitelist denies unmatched IPv6 sources"'
        fi
    fi
    echo "    }"
    echo "}"
}

address_control_table_exists() {
    nft list table "$(address_control_family)" "$(address_control_table)" >/dev/null 2>&1
}

address_control_delete_table() {
    if command -v nft >/dev/null 2>&1 && address_control_table_exists; then
        pfwd_run nft delete table "$(address_control_family)" "$(address_control_table)"
    fi
}

address_control_apply_runtime() {
    local runtime_hash current_hash tmp_render
    address_control_prepare_runtime
    runtime_hash="$(address_control_runtime_hash_compute)"
    current_hash="$(address_control_runtime_hash)"
    if [ "$runtime_hash" = "$current_hash" ] && address_control_table_exists; then
        return 0
    fi

    if [ "$(address_control_runtime_enabled)" != "true" ]; then
        address_control_delete_table
        address_control_update_runtime_hash "$runtime_hash"
        return 0
    fi

    pfwd_require_cmd nft
    tmp_render="$(mktemp "$PFWD_RUN_DIR/address-control.XXXXXX")"
    address_control_render_nft > "$tmp_render"
    pfwd_run nft -f "$tmp_render"
    rm -f "$tmp_render"
    address_control_update_runtime_hash "$runtime_hash"
}

address_control_status_json() {
    jq -n \
      --argjson enabled "$(address_control_enabled)" \
      --argjson include_cn "$(address_control_include_cn)" \
      --arg source_url "$(address_control_source_url)" \
      --arg allow_ipv4_file "$(address_control_allow_ipv4_file)" \
      --arg allow_ipv6_file "$(address_control_allow_ipv6_file)" \
      --arg last_good_source "$(address_control_last_good_source)" \
      --arg last_good_updated_at "$(address_control_last_good_updated_at)" \
      --argjson entries "$(address_control_entry_count)" \
      --argjson custom_cidrs_count "$(address_control_custom_cidrs_count)" \
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

address_control_render_status() {
    local json
    json="$(address_control_status_json)"
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
