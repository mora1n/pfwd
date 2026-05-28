#!/usr/bin/env bash

EGRESS_WHITELIST_LAST_ERROR=""

egress_whitelist_default_source_url() {
    printf '%s\n' "https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone"
}

egress_whitelist_default_ipv6_source_url() {
    printf '%s\n' "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/cn-aggregated.zone"
}

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

egress_whitelist_enabled() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r '.settings.egress_whitelist.enabled // false' "$config_file"
}

egress_whitelist_include_cn() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r '.settings.egress_whitelist.include_cn // true' "$config_file"
}

egress_whitelist_source_url() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r --arg url "$(egress_whitelist_default_source_url)" '.settings.egress_whitelist.source_url // $url' "$config_file"
}

egress_whitelist_last_good_source() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r '.settings.egress_whitelist.last_good_source // ""' "$config_file"
}

egress_whitelist_last_good_updated_at() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r '.settings.egress_whitelist.last_good_updated_at // empty' "$config_file"
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

egress_whitelist_mark_last_good() {
    local source="$1"
    local updated_at="$2"
    config_update --arg source "$source" --arg updated_at "$updated_at" '
      (.settings.egress_whitelist //= {})
      | .settings.egress_whitelist.last_good_source = $source
      | .settings.egress_whitelist.last_good_updated_at = $updated_at
    '
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
    local include_cn="$2"
    local source_url="$3"
    validate_bool "$enabled"
    validate_bool "$include_cn"
    [ -n "$source_url" ] || source_url="$(egress_whitelist_default_source_url)"
    config_update \
      --argjson enabled "$enabled" \
      --argjson include_cn "$include_cn" \
      --arg source_url "$source_url" '
      (.settings.egress_whitelist //= {})
      | .settings.egress_whitelist.enabled = $enabled
      | .settings.egress_whitelist.include_cn = $include_cn
      | .settings.egress_whitelist.source_url = $source_url
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
    local ipv4_file ipv6_file cn_tmp tmp_v4 tmp_v6
    ipv4_file="$(egress_whitelist_allow_ipv4_file "$state_dir")"
    ipv6_file="$(egress_whitelist_allow_ipv6_file "$state_dir")"
    mkdir -p "$(dirname "$ipv4_file")"

    if [ "$(egress_whitelist_enabled "$config_file")" != "true" ]; then
        rm -f "$ipv4_file" "$ipv6_file" "${ipv4_file}.cn" "${ipv6_file}.cn" 2>/dev/null || true
        return 0
    fi

    if [ "$(egress_whitelist_include_cn "$config_file")" = "true" ]; then
        cn_tmp="$(mktemp)"
        if [ -f "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone" ]; then
            egress_whitelist_write_allow_ipv4_file "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone" "$cn_tmp"
            [ "$config_file" = "$PFWD_CONFIG_FILE" ] && egress_whitelist_mark_last_good "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone" "$(pfwd_now_iso)"
        else
            pfwd_bootstrap_download "$(egress_whitelist_source_url "$config_file")" "$cn_tmp"
            egress_whitelist_write_allow_ipv4_file "$cn_tmp" "$cn_tmp.filtered"
            mv "$cn_tmp.filtered" "$cn_tmp"
            [ "$config_file" = "$PFWD_CONFIG_FILE" ] && egress_whitelist_mark_last_good "$(egress_whitelist_source_url "$config_file")" "$(pfwd_now_iso)"
        fi
        mv "$cn_tmp" "${ipv4_file}.cn"

        cn_tmp="$(mktemp)"
        if [ -f "$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone" ]; then
            egress_whitelist_write_allow_ipv6_file "$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone" "$cn_tmp"
        else
            pfwd_bootstrap_download "$(egress_whitelist_default_ipv6_source_url)" "$cn_tmp"
            egress_whitelist_write_allow_ipv6_file "$cn_tmp" "$cn_tmp.filtered"
            mv "$cn_tmp.filtered" "$cn_tmp"
        fi
        mv "$cn_tmp" "${ipv6_file}.cn"
    else
        rm -f "${ipv4_file}.cn" "${ipv6_file}.cn" 2>/dev/null || true
    fi

    tmp_v4="$(mktemp)"
    tmp_v6="$(mktemp)"
    if [ -s "${ipv4_file}.cn" ]; then
        cat "${ipv4_file}.cn" >> "$tmp_v4"
        printf '\n' >> "$tmp_v4"
    fi
    if [ -s "${ipv6_file}.cn" ]; then
        cat "${ipv6_file}.cn" >> "$tmp_v6"
        printf '\n' >> "$tmp_v6"
    fi
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
}

egress_whitelist_runtime_hash_compute() {
    local config_file="${1:-$PFWD_CONFIG_FILE}"
    local state_dir="${2:-$PFWD_EGRESS_WHITELIST_STATE_DIR}"
    local ipv4_file ipv6_file payload
    ipv4_file="$(egress_whitelist_allow_ipv4_file "$state_dir")"
    ipv6_file="$(egress_whitelist_allow_ipv6_file "$state_dir")"
    payload="$(cat <<EOF
enabled=$(egress_whitelist_enabled "$config_file")
include_cn=$(egress_whitelist_include_cn "$config_file")
source=$(egress_whitelist_source_url "$config_file")
last_good_source=$(egress_whitelist_last_good_source "$config_file")
custom:
$(egress_whitelist_custom_cidrs_tsv "$config_file")
ipv4:
$(cat "$ipv4_file" 2>/dev/null || true)
ipv6:
$(cat "$ipv6_file" 2>/dev/null || true)
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
    jq -n \
      --argjson enabled "$(egress_whitelist_enabled)" \
      --argjson include_cn "$(egress_whitelist_include_cn)" \
      --arg source_url "$(egress_whitelist_source_url)" \
      --arg allow_ipv4_file "$(egress_whitelist_allow_ipv4_file)" \
      --arg allow_ipv6_file "$(egress_whitelist_allow_ipv6_file)" \
      --arg last_good_source "$(egress_whitelist_last_good_source)" \
      --arg last_good_updated_at "$(egress_whitelist_last_good_updated_at)" \
      --argjson entries "$(egress_whitelist_entry_count)" \
      --argjson custom_cidrs_count "$(egress_whitelist_custom_cidrs_count)" \
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

egress_whitelist_render_status() {
    local json
    json="$(egress_whitelist_status_json)"
    jq -r '
      [
        ["启用出口白名单", (if .enabled then "开" else "关" end)],
        ["出口包含国内 IP", (if .enabled then (if .include_cn then "开" else "关" end) else "-" end)],
        ["出口自定义 CIDR", (.custom_cidrs_count | tostring)],
        ["出口白名单条目", (.entries | tostring)],
        ["出口来源地址", (if .last_good_source == "" then .source_url else .last_good_source end)],
        ["出口 IPv4 文件", .allow_ipv4_file],
        ["出口 IPv6 文件", .allow_ipv6_file]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}

egress_whitelist_assert_target_rows_allowed() {
    local remote_input="$1"
    local target_rows="$2"
    local state_dir="${3:-$PFWD_EGRESS_WHITELIST_STATE_DIR}"
    local tmp_ips blocked_ip ipv4_file ipv6_file
    tmp_ips="$(mktemp)"
    ipv4_file="$(egress_whitelist_allow_ipv4_file "$state_dir")"
    ipv6_file="$(egress_whitelist_allow_ipv6_file "$state_dir")"
    while IFS='|' read -r _ _ resolved_ip; do
        [ -n "$resolved_ip" ] || continue
        printf '%s\n' "$resolved_ip" >> "$tmp_ips"
    done <<< "$target_rows"

    local status=0
    if blocked_ip="$(python3 - "$tmp_ips" "$ipv4_file" "$ipv6_file" <<'PY'
import ipaddress
import pathlib
import sys

addr_file = pathlib.Path(sys.argv[1])
ipv4_file = pathlib.Path(sys.argv[2])
ipv6_file = pathlib.Path(sys.argv[3])

def load_networks(path):
    if not path.exists():
        return []
    items = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        items.append(ipaddress.ip_network(line, strict=False))
    return items

ipv4_networks = load_networks(ipv4_file)
ipv6_networks = load_networks(ipv6_file)

for raw in addr_file.read_text().splitlines():
    value = raw.strip()
    if not value:
        continue
    addr = ipaddress.ip_address(value)
    networks = ipv4_networks if addr.version == 4 else ipv6_networks
    if not any(addr in network for network in networks):
        sys.stdout.write(value)
        sys.exit(1)
PY
    )"; then
        status=0
    else
        status=$?
    fi
    rm -f "$tmp_ips"
    if [ "$status" -ne 0 ] && [ -n "$blocked_ip" ]; then
        EGRESS_WHITELIST_LAST_ERROR="resolved_ip=${blocked_ip}"
        return 1
    fi
    if [ "$status" -ne 0 ]; then
        EGRESS_WHITELIST_LAST_ERROR="remote=${remote_input} 校验失败"
        return 1
    fi
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
        if ! egress_whitelist_assert_target_rows_allowed "$remote_host" "$target_rows" "$state_dir"; then
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
