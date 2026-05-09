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

address_control_entry_count() {
    if [ -s "$(address_control_allow_file)" ]; then
        sed '/^$/d' "$(address_control_allow_file)" | wc -l | tr -d ' '
    else
        echo 0
    fi
}

address_control_custom_cidrs_count() {
    jq -r '.settings.address_control.custom_cidrs // [] | length' "$PFWD_CONFIG_FILE"
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
    [ -s "$target_file" ] || pfwd_die "白名单来源 IP 集合为空：$source_file"
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
        validate_ipv4_cidr "$cidr"
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

address_control_merge_runtime() {
    local tmp
    tmp="$(mktemp)"
    if [ "$(address_control_include_cn)" = "true" ]; then
        if [ -s "$(address_control_allow_file).cn" ]; then
            cat "$(address_control_allow_file).cn" >> "$tmp"
            printf '\n' >> "$tmp"
        fi
    fi
    address_control_custom_cidrs_tsv >> "$tmp"
    address_control_write_allow_file "$tmp"
    rm -f "$tmp"
}

address_control_prepare_runtime() {
    local cn_tmp
    if [ "$(address_control_enabled)" != "true" ]; then
        rm -f "$(address_control_allow_file)" 2>/dev/null || true
        rm -f "$(address_control_allow_file).cn" 2>/dev/null || true
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
        mv "$cn_tmp" "$(address_control_allow_file).cn"
    else
        rm -f "$(address_control_allow_file).cn" 2>/dev/null || true
    fi

    address_control_merge_runtime
}

address_control_runtime_enabled() {
    [ "$(address_control_enabled)" = "true" ] && echo true || echo false
}

address_control_status_json() {
    jq -n \
      --argjson enabled "$(address_control_enabled)" \
      --argjson include_cn "$(address_control_include_cn)" \
      --arg source_url "$(address_control_source_url)" \
      --arg allow_file "$(address_control_allow_file)" \
      --arg last_good_source "$(address_control_last_good_source)" \
      --arg last_good_updated_at "$(address_control_last_good_updated_at)" \
      --argjson entries "$(address_control_entry_count)" \
      --argjson custom_cidrs_count "$(address_control_custom_cidrs_count)" \
      '{
        enabled: $enabled,
        include_cn: $include_cn,
        source_url: $source_url,
        allow_file: $allow_file,
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
        ["运行态文件", .allow_file]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}
