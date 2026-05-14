#!/usr/bin/env bash

forwarder_table() {
    fw_forward_table
}

forwarder_target_kind() {
    local target="$1"
    if [[ "$target" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
        echo "ipv4"
    elif [[ "$target" == *:* ]]; then
        echo "ipv6"
    else
        echo "domain"
    fi
}

forwarder_infer_ip_version() {
    local listen_ip="$1"
    local snat_mode="$2"
    local snat_source="$3"

    if [ "$snat_mode" = "snat" ] && [ -n "$snat_source" ]; then
        if [[ "$snat_source" == *:* ]]; then
            echo "6"
        else
            echo "4"
        fi
        return 0
    fi

    case "$listen_ip" in
        ""|"::") echo "46" ;;
        "0.0.0.0") echo "4" ;;
        *:*) echo "6" ;;
        *) echo "4" ;;
    esac
}

forwarder_protocol_rows() {
    local protocol="${1:-tcp_udp}"
    case "$protocol" in
        tcp_udp) printf 'tcp\nudp\n' ;;
        tcp|udp) printf '%s\n' "$protocol" ;;
        *) pfwd_die "无效协议：$protocol" ;;
    esac
}

FORWARDER_TSV_FIELDS=()
FORWARDER_LAST_RESOLVE_ERROR=""

forwarder_split_tsv_line() {
    local line="$1"
    local field
    FORWARDER_TSV_FIELDS=()
    while true; do
        if [[ "$line" == *$'\t'* ]]; then
            field="${line%%$'\t'*}"
            FORWARDER_TSV_FIELDS+=("$field")
            line="${line#*$'\t'}"
        else
            FORWARDER_TSV_FIELDS+=("$line")
            break
        fi
    done
}

forwarder_resolve_targets() {
    local target="$1"
    local ip_ver="${2:-46}"
    local target_kind resolved_lines resolved_v4="" resolved_v6=""
    local getent_status=0 getent_output=""

    FORWARDER_LAST_RESOLVE_ERROR=""

    target_kind="$(forwarder_target_kind "$target")"
    case "$target_kind" in
        ipv4)
            [ "$ip_ver" = "6" ] || printf 'ip|4|%s\n' "$target"
            ;;
        ipv6)
            [ "$ip_ver" = "4" ] || printf 'ip6|6|%s\n' "$target"
            ;;
        domain)
            case "${target,,}" in
                localhost|localhost.localdomain|ip6-localhost|ip6-loopback)
                    if [ "$ip_ver" != "6" ]; then
                        printf 'ip|4|127.0.0.1\n'
                    fi
                    if [ "$ip_ver" != "4" ]; then
                        printf 'ip6|6|::1\n'
                    fi
                    return 0
                    ;;
            esac
            getent_output="$(getent ahosts "$target" 2>&1)" || getent_status=$?
            if [ "$getent_status" -ne 0 ]; then
                FORWARDER_LAST_RESOLVE_ERROR="$(printf 'getent ahosts exit=%s: %s' "$getent_status" "$(printf '%s' "$getent_output" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')")"
                pfwd_debug "forwarder_resolve_targets target=$target error=$FORWARDER_LAST_RESOLVE_ERROR"
                resolved_lines=""
            else
                resolved_lines="$getent_output"
            fi
            resolved_v4="$(awk '/STREAM/ && $1 ~ /^[0-9]+\./ { print $1; exit }' <<< "$resolved_lines")"
            resolved_v6="$(awk '/STREAM/ && $1 ~ /:/ { print $1; exit }' <<< "$resolved_lines")"
            if [ -n "$resolved_v4" ] && [ "$ip_ver" != "6" ]; then
                printf 'ip|4|%s\n' "$resolved_v4"
            fi
            if [ -n "$resolved_v6" ] && [ "$ip_ver" != "4" ]; then
                printf 'ip6|6|%s\n' "$resolved_v6"
            fi
            if [ -z "$resolved_v4" ] && [ -z "$resolved_v6" ] && [ -z "$FORWARDER_LAST_RESOLVE_ERROR" ]; then
                FORWARDER_LAST_RESOLVE_ERROR="getent ahosts 未返回可用地址"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

forwarder_iface() {
    local iface
    iface="$(jq -r '.settings.forward.interface // .settings.tc_interface // ""' "$PFWD_CONFIG_FILE")"
    if [ -n "$iface" ]; then
        echo "$iface"
        return
    fi
    ip route show default 2>/dev/null | awk '{print $5; exit}'
}

forwarder_protocol_filters_enabled() {
    if [ "$(jq -r '.settings.guard.enabled // false' "$PFWD_CONFIG_FILE")" != "true" ]; then
        echo false
    elif [ "$(jq -r '.settings.guard.block_http // false' "$PFWD_CONFIG_FILE")" = "true" ] ||
       [ "$(jq -r '.settings.guard.block_tls // false' "$PFWD_CONFIG_FILE")" = "true" ] ||
       [ "$(jq -r '.settings.guard.block_socks // false' "$PFWD_CONFIG_FILE")" = "true" ]; then
        echo true
    else
        echo false
    fi
}

forwarder_guard_ingress_mode() {
    echo tc
}

forwarder_whitelist_files_json() {
    local files=()
    if [ "$(jq -r '.settings.guard.enabled // false' "$PFWD_CONFIG_FILE")" = "true" ] &&
       command -v whitelist_enabled >/dev/null 2>&1 &&
       [ "$(whitelist_enabled)" = "true" ]; then
        if [ -f "$PFWD_WHITELIST_ALLOW_IPV4_FILE" ]; then
            files+=("$PFWD_WHITELIST_ALLOW_IPV4_FILE")
        fi
        if [ -f "$PFWD_WHITELIST_ALLOW_IPV6_FILE" ]; then
            files+=("$PFWD_WHITELIST_ALLOW_IPV6_FILE")
        fi
    fi
    if [ "${#files[@]}" -eq 0 ]; then
        printf '[]\n'
        return 0
    fi
    printf '%s\n' "${files[@]}" | jq -R . | jq -s .
}

forwarder_protocol_skip_ports_json() {
    jq -c '.settings.guard.protocol_skip_ports // []' "$PFWD_CONFIG_FILE"
}

forwarder_render_config() {
    forwarder_runtime_json true | jq '.'
}

forwarder_ensure_ip_forwarding() {
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        ui_emit_dry_run "DRY-RUN: sysctl -w net.ipv4.ip_forward=1"
        ui_emit_dry_run "DRY-RUN: sysctl -w net.ipv6.conf.all.forwarding=1"
        return 0
    fi
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
}

forwarder_runtime_status_json() {
    local backend="$1"
    local runtime_json="$2"
    local xdp_runtime_json="$3"
    local nft_runtime_json="$4"
    local fallback_reason="${5:-}"
    local xdp_error="${6:-}"
    local xdp_applied="${7:-false}"
    local nft_applied="${8:-false}"
    local xdp_status_json="${9:-{}}"
    local xdp_forward_applied="${10:-false}"
    [ -n "$runtime_json" ] || runtime_json='{"rules":[],"settings":{}}'
    [ -n "$xdp_runtime_json" ] || xdp_runtime_json='{"rules":[]}'
    [ -n "$nft_runtime_json" ] || nft_runtime_json='{"rules":[]}'
    if ! jq -e . >/dev/null 2>&1 <<< "$xdp_status_json"; then
        xdp_status_json='{}'
    fi

    jq -n \
      --arg backend "$backend" \
      --arg fallback_reason "$fallback_reason" \
      --arg xdp_error "$xdp_error" \
      --argjson xdp_applied "$xdp_applied" \
      --argjson nft_applied "$nft_applied" \
      --argjson xdp_forward_applied "$xdp_forward_applied" \
      --argjson runtime "$runtime_json" \
      --argjson xdp_runtime "$xdp_runtime_json" \
      --argjson nft_runtime "$nft_runtime_json" \
      --argjson xdp_status "$xdp_status_json" \
      --arg generated_at "$(pfwd_now_iso)" '
      {
        applied: ($xdp_applied or $nft_applied),
        generated_at: $generated_at,
        forwarding_backend: $backend,
        xdp_applied: $xdp_applied,
        xdp_forward_applied: $xdp_forward_applied,
        nft_applied: $nft_applied,
        loopback_via_nft: (($runtime.rules | any(.loopback_local == true)) // false),
        fallback_reason: (if $fallback_reason == "" then null else $fallback_reason end),
        xdp_error: (if $xdp_error == "" then null else $xdp_error end),
        rules: ($runtime.rules | length),
        xdp_candidate_rules_count: ([$runtime.rules[]? | select(.execution_class == "xdp")] | length),
        xdp_rules_count: ($xdp_runtime.rules | length),
        xdp_guard_rules_count: ((if ($runtime.settings.guard_enabled // false) then 1 else 0 end)),
        nft_rules_count: ($nft_runtime.rules | length),
        interface: ($runtime.settings.interface // ""),
        protocol_guard: ($runtime.settings.guard_enabled // false),
        whitelist_enabled: ($runtime.settings.whitelist_enabled // false),
        xdp_status: $xdp_status
      }'
}

forwarder_write_status_file() {
    local status_json="$1"
    printf '%s\n' "$status_json" | jq '.' | pfwd_write_atomic "$PFWD_FORWARDER_STATUS_FILE"
}

forwarder_status_json() {
    if [ -f "$PFWD_FORWARDER_STATUS_FILE" ]; then
        jq '.' "$PFWD_FORWARDER_STATUS_FILE"
    else
    jq -n '
          {
            applied: false,
            forwarding_backend: "none",
            xdp_applied: false,
            xdp_forward_applied: false,
            nft_applied: false,
            loopback_via_nft: false,
            rules: 0,
            xdp_candidate_rules_count: 0,
            xdp_rules_count: 0,
            xdp_guard_rules_count: 0,
            nft_rules_count: 0,
            interface: "",
            protocol_guard: false,
            whitelist_enabled: false
          }'
    fi
}

forwarder_render_status() {
    local json
    json="$(forwarder_status_json)"
    jq -r '
      [
        ["后端", (.forwarding_backend // "none")],
        ["XDP 转发", (if .xdp_applied then "开" else "关" end)],
        ["XDP 正向转发", (if (.xdp_forward_applied // false) then "开" else "关" end)],
        ["nft 转发", (if .nft_applied then "开" else "关" end)],
        ["localhost 走 nft", (if .loopback_via_nft then "是" else "否" end)],
        ["生效规则", (.rules | tostring)],
        ["XDP 候选规则", ((.xdp_candidate_rules_count // 0) | tostring)],
        ["XDP 规则", (.xdp_rules_count | tostring)],
        ["Guard 数据面", (if (.xdp_guard_rules_count // 0) > 0 then "开" else "关" end)],
        ["nft 规则", (.nft_rules_count | tostring)],
        ["绑定网卡", (.interface // "-")],
        ["回退原因", (.fallback_reason // "-")]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}

forwarder_apply_xdp_runtime() {
    runtime_apply_xdp_runtime "$1" || {
        printf '%s' "$RUNTIME_XDP_ERROR" >&2
        return 1
    }
    jq '.' <<< "${RUNTIME_XDP_STATUS_JSON:-{\"applied\":true}}"
}

forwarder_apply_runtime() {
    local runtime_json
    pfwd_debug "forwarder_apply_runtime start"
    config_init >/dev/null
    forwarder_validate_config
    if command -v whitelist_prepare_runtime >/dev/null 2>&1; then
        whitelist_prepare_runtime
    fi

    runtime_json="$(forwarder_runtime_json true)"
    runtime_apply_compiled_runtime "$runtime_json"
}

forwarder_run_maintenance() {
    forwarder_apply_runtime
}

forwarder_stop_runtime() {
    runtime_stop_compiled_runtime
}

forwarder_validate_config() {
    config_init >/dev/null
    jq -e '
      type == "object"
      and (.forwards | type == "array")
      and (.users | type == "array")
    ' "$PFWD_CONFIG_FILE" >/dev/null || pfwd_die "无效 pfwd 配置文件：$PFWD_CONFIG_FILE"
}

forwarder_service_unit() {
    cat <<EOF
[Unit]
Description=pfwd XDP/nft runtime restore
After=network-online.target nftables.service systemd-sysctl.service ufw.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PFWD_BIN_PATH __forward_boot

[Install]
WantedBy=multi-user.target
EOF
}
