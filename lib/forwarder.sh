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

forwarder_domain_target_requires_refresh() {
    local target="${1:-}"
    if [ "$(forwarder_target_kind "$target")" != "domain" ]; then
        return 1
    fi
    case "${target,,}" in
        localhost|localhost.localdomain|ip6-localhost|ip6-loopback) return 1 ;;
    esac
    return 0
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

forwarder_domain_rules_present() {
    config_init >/dev/null
    local remote_host
    while IFS= read -r remote_host; do
        [ -n "$remote_host" ] || continue
        if forwarder_domain_target_requires_refresh "$remote_host"; then
            echo true
            return 0
        fi
    done < <(jq -r '.forwards[]? | select(.enabled == true) | .remote_host' "$PFWD_CONFIG_FILE")
    echo false
}

forwarder_domain_refresh_interval_seconds() {
    config_init >/dev/null
    local raw
    raw="$(jq -r '.settings.domain_refresh_interval // ""' "$PFWD_CONFIG_FILE")"
    [ -n "$raw" ] || {
        echo 0
        return 0
    }
    pfwd_parse_duration_seconds "$raw"
}

forwarder_domain_refresh_status_json() {
    if [ -f "$PFWD_FORWARDER_STATUS_FILE" ]; then
        jq '.' "$PFWD_FORWARDER_STATUS_FILE" 2>/dev/null || printf '{}\n'
    else
        printf '{}\n'
    fi
}

forwarder_domain_refresh_last_checked_at() {
    local status_json value
    status_json="$(forwarder_domain_refresh_status_json)"
    value="$(jq -r '.domain_refresh_checked_at // .generated_at // ""' <<< "$status_json" 2>/dev/null || true)"
    printf '%s\n' "$value"
}

forwarder_domain_refresh_due() {
    local interval_seconds="$1"
    [ -n "$interval_seconds" ] || interval_seconds=0
    [[ "$interval_seconds" =~ ^[0-9]+$ ]] || pfwd_die "domain_refresh_interval 秒数无效：$interval_seconds"
    [ "$interval_seconds" -gt 0 ] || return 1

    local last_checked now_epoch last_epoch
    last_checked="$(forwarder_domain_refresh_last_checked_at)"
    [ -n "$last_checked" ] || return 0

    now_epoch="$(pfwd_now_epoch)"
    last_epoch="$(date -u -d "$last_checked" '+%s' 2>/dev/null || true)"
    [ -n "$last_epoch" ] || return 0
    [ $((now_epoch - last_epoch)) -ge "$interval_seconds" ]
}

forwarder_update_domain_refresh_metadata() {
    local checked_at="$1"
    local interval_seconds="$2"
    local domain_rules_present="$3"
    local status_json

    status_json="$(forwarder_status_json 2>/dev/null || printf '{}\n')"
    status_json="$(jq \
      --arg checked_at "$checked_at" \
      --argjson interval_seconds "$interval_seconds" \
      --argjson domain_rules_present "$domain_rules_present" '
      .domain_refresh_checked_at = $checked_at
      | .domain_refresh_interval_seconds = $interval_seconds
      | .domain_rules_present = $domain_rules_present
    ' <<< "$status_json")"
    forwarder_write_status_file "$status_json"
}

forwarder_domain_refresh_hash_from_runtime_json() {
    local runtime_json="${1:-}"
    jq -c '
      [
        .rules[]?
        | select(
            (.remote_input | type == "string")
            and ((.remote_input | ascii_downcase) != "localhost")
            and ((.remote_input | ascii_downcase) != "localhost.localdomain")
            and ((.remote_input | ascii_downcase) != "ip6-localhost")
            and ((.remote_input | ascii_downcase) != "ip6-loopback")
            and ((.remote_input | test("^[0-9]+(\\.[0-9]+){3}$") | not))
            and ((.remote_input | contains(":")) | not)
          )
        | {
            id,
            listen_ip,
            listen_port,
            protocol,
            remote_input,
            resolved_target,
            remote_port,
            ip_version,
            execution_class,
            snat_mode,
            snat_source,
            mss_mode,
            mss_value,
            traffic_mode,
            traffic_ratio,
            whitelist_policy_id
          }
      ]
      | sort_by(.id, .protocol, .ip_version, .resolved_target)
    ' <<< "$runtime_json" | pfwd_stdin_checksum
}

forwarder_domain_refresh_hash_file() {
    [ -f "$PFWD_FORWARDER_RUNTIME_FILE" ] || return 0
    forwarder_domain_refresh_hash_from_runtime_json "$(jq -c '.' "$PFWD_FORWARDER_RUNTIME_FILE")"
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

forwarder_egress_whitelist_files_json() {
    local files=()
    if command -v egress_whitelist_enabled >/dev/null 2>&1 &&
       [ "$(egress_whitelist_enabled)" = "true" ]; then
        if [ -f "$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV4_FILE" ]; then
            files+=("$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV4_FILE")
        fi
        if [ -f "$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV6_FILE" ]; then
            files+=("$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV6_FILE")
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
    local loopback_split_active="${11:-false}"
    local hybrid_reason="${12:-}"
    [ -n "$runtime_json" ] || runtime_json='{"rules":[],"settings":{}}'
    [ -n "$xdp_runtime_json" ] || xdp_runtime_json='{"rules":[]}'
    [ -n "$nft_runtime_json" ] || nft_runtime_json='{"rules":[]}'
    if ! jq -e . >/dev/null 2>&1 <<< "$xdp_status_json"; then
        xdp_status_json='{}'
    fi
    local runtime_file xdp_runtime_file nft_runtime_file xdp_status_file
    runtime_file="$(pfwd_json_to_temp_file "$runtime_json")" || return 1
    xdp_runtime_file="$(pfwd_json_to_temp_file "$xdp_runtime_json")" || {
        rm -f "$runtime_file"
        return 1
    }
    nft_runtime_file="$(pfwd_json_to_temp_file "$nft_runtime_json")" || {
        rm -f "$runtime_file" "$xdp_runtime_file"
        return 1
    }
    xdp_status_file="$(pfwd_json_to_temp_file "$xdp_status_json")" || {
        rm -f "$runtime_file" "$xdp_runtime_file" "$nft_runtime_file"
        return 1
    }

    jq -n \
      --arg backend "$backend" \
      --arg fallback_reason "$fallback_reason" \
      --arg xdp_error "$xdp_error" \
      --argjson xdp_applied "$xdp_applied" \
      --argjson nft_applied "$nft_applied" \
      --argjson xdp_forward_applied "$xdp_forward_applied" \
      --argjson loopback_split_active "$loopback_split_active" \
      --arg hybrid_reason "$hybrid_reason" \
      --slurpfile runtime "$runtime_file" \
      --slurpfile xdp_runtime "$xdp_runtime_file" \
      --slurpfile nft_runtime "$nft_runtime_file" \
      --slurpfile xdp_status "$xdp_status_file" \
      --arg generated_at "$(pfwd_now_iso)" '
      ($runtime[0]) as $runtime
      | ($xdp_runtime[0]) as $xdp_runtime
      | ($nft_runtime[0]) as $nft_runtime
      | ($xdp_status[0]) as $xdp_status
      |
      {
        applied: ($xdp_applied or $nft_applied),
        generated_at: $generated_at,
        forwarding_backend: $backend,
        xdp_applied: $xdp_applied,
        xdp_forward_applied: $xdp_forward_applied,
        nft_applied: $nft_applied,
        loopback_via_nft: (($runtime.rules | any(.loopback_local == true)) // false),
        loopback_split_active: $loopback_split_active,
        hybrid_reason: (if $hybrid_reason == "" then null else $hybrid_reason end),
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
        egress_whitelist_enabled: ($runtime.settings.egress_whitelist_enabled // false),
        host_egress_enabled: ($runtime.settings.host_egress_enabled // false),
        host_egress_backend: ($runtime.settings.host_egress_backend // "off"),
        dataplane_version: ($runtime.dataplane_version // $xdp_status.dataplane_version // null),
        map_abi_version: ($runtime.map_abi_version // $xdp_status.map_abi_version // null),
        incremental_apply: ($xdp_status.incremental_apply // false),
        preserved_connections: ($xdp_status.preserved_connections // 0),
        invalidated_connections: ($xdp_status.invalidated_connections // 0),
        refresh_report: ($xdp_status.refresh_report // {}),
        profile_counts: ($runtime.summary.profile_counts // $xdp_status.profile_counts // {}),
        xdp_status: $xdp_status
      }'
    local status=$?
    rm -f "$runtime_file" "$xdp_runtime_file" "$nft_runtime_file" "$xdp_status_file"
    return "$status"
}

forwarder_write_status_file() {
    local status_json="$1"
    printf '%s\n' "$status_json" | jq '.' | pfwd_write_atomic "$PFWD_FORWARDER_STATUS_FILE"
}

forwarder_xdp_status_json() {
    if [ -x "$(forwarder_bin_path)" ] && [ -f "$PFWD_XDP_STATUS_FILE" ]; then
        "$(forwarder_bin_path)" status --status-file "$PFWD_XDP_STATUS_FILE" 2>/dev/null && return 0
    fi
    if [ -f "$PFWD_XDP_STATUS_FILE" ]; then
        jq '.' "$PFWD_XDP_STATUS_FILE" 2>/dev/null && return 0
    fi
    printf '{}\n'
}

forwarder_status_json() {
    local base_json xdp_status_json
    if [ -f "$PFWD_FORWARDER_STATUS_FILE" ]; then
        base_json="$(jq '.' "$PFWD_FORWARDER_STATUS_FILE")"
    else
        base_json="$(jq -n '
          {
            applied: false,
            forwarding_backend: "none",
            xdp_applied: false,
            xdp_forward_applied: false,
            nft_applied: false,
            loopback_via_nft: false,
            loopback_split_active: false,
            rules: 0,
            xdp_candidate_rules_count: 0,
            xdp_rules_count: 0,
            xdp_guard_rules_count: 0,
            nft_rules_count: 0,
            interface: "",
            protocol_guard: false,
            whitelist_enabled: false,
            egress_whitelist_enabled: false,
            host_egress_enabled: false,
            host_egress_backend: "off",
            dataplane_version: null,
            map_abi_version: null,
            incremental_apply: false,
            preserved_connections: 0,
            invalidated_connections: 0,
            refresh_report: {},
            profile_counts: {}
          }')"
    fi
    xdp_status_json="$(forwarder_xdp_status_json)"
    local xdp_status_file
    xdp_status_file="$(pfwd_json_to_temp_file "$xdp_status_json")" || return 1
    jq --slurpfile xdp_status "$xdp_status_file" '.xdp_status = $xdp_status[0]' <<< "$base_json"
    local status=$?
    rm -f "$xdp_status_file"
    return "$status"
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
        ["混合原因", (if (.hybrid_reason // "") == "" then "-" elif .hybrid_reason == "loopback-split" then "localhost 分流" else .hybrid_reason end)],
        ["生效规则", (.rules | tostring)],
        ["XDP 候选规则", ((.xdp_candidate_rules_count // 0) | tostring)],
        ["XDP 规则", (.xdp_rules_count | tostring)],
        ["Guard 数据面", (if (.xdp_guard_rules_count // 0) > 0 then "开" else "关" end)],
        ["入口白名单", (if (.whitelist_enabled // false) then "开" else "关" end)],
        ["出口白名单", (if (.egress_whitelist_enabled // false) then "开" else "关" end)],
        ["宿主机出口白名单", (if (.host_egress_enabled // false) then (.host_egress_backend // "开") else "关" end)],
        ["nft 规则", (.nft_rules_count | tostring)],
        ["绑定网卡", (.interface // "-")],
        ["dataplane", ((.dataplane_version // .xdp_status.dataplane_version // "-") | tostring)],
        ["map ABI", ((.map_abi_version // .xdp_status.map_abi_version // "-") | tostring)],
        ["XDP 增量刷新", (if (.xdp_status.incremental_apply // .incremental_apply // false) then "是" else "否" end)],
        ["XDP 保留连接", ((.xdp_status.preserved_connections // .preserved_connections // 0) | tostring)],
        ["XDP 失效连接", ((.xdp_status.invalidated_connections // .invalidated_connections // 0) | tostring)],
        ["XDP refresh", ((.xdp_status.refresh_report.mode // .refresh_report.mode // "-") | tostring)],
	        ["XDP refresh 耗时", (((.xdp_status.refresh_report.total_duration_ms // .refresh_report.total_duration_ms // null) | if . == null then "-" else tostring + " ms" end))],
	        ["XDP aux refresh", (((.xdp_status.refresh_report.aux_actions // []) | map(.component + "=" + .action + (if ((.changed_items // 0) > 0) then "(" + ((.changed_items | tostring)) + ")" else "" end)) | join(", ")) as $actions | if $actions == "" then "-" else $actions end)],
	        ["XDP 规则变更", (((.xdp_status.refresh_report.rules_added // .refresh_report.rules_added // 0) | tostring) + "/" + ((.xdp_status.refresh_report.rules_updated // .refresh_report.rules_updated // 0) | tostring) + "/" + ((.xdp_status.refresh_report.rules_deleted // .refresh_report.rules_deleted // 0) | tostring) + " add/update/delete"],
	        ["XDP 用户变更", (((.xdp_status.refresh_report.users_added // .refresh_report.users_added // 0) | tostring) + "/" + ((.xdp_status.refresh_report.users_updated // .refresh_report.users_updated // 0) | tostring) + "/" + ((.xdp_status.refresh_report.users_deleted // .refresh_report.users_deleted // 0) | tostring) + " add/update/delete"],
	        ["XDP counter 保留", ((.xdp_status.refresh_report.counters_preserved // .refresh_report.counters_preserved // 0) | tostring)],
	        ["XDP counter 重置", ((.xdp_status.refresh_report.counters_reset // .refresh_report.counters_reset // 0) | tostring)],
	        ["XDP reconcile 耗时", (((.xdp_status.refresh_report.reconcile_duration_ms // .refresh_report.reconcile_duration_ms // null) | if . == null then "-" else tostring + " ms" end))],
	        ["XDP attach 耗时", (((.xdp_status.refresh_report.attach_timings // []) | map(.component + "=" + ((.duration_ms | tostring)) + "ms") | join(", ")) as $timings | if $timings == "" then "-" else $timings end)],
	        ["XDP profile", (((.profile_counts // .xdp_status.profile_counts // {}) | to_entries | sort_by(.key) | map("\(.key)=\(.value)") | join(", ")) as $profiles | if $profiles == "" then "-" else $profiles end)],
	        ["XDP 活动连接", ((.xdp_status.active_summary.total // 0) | tostring)],
        ["XDP TCP 预热中", ((.xdp_status.active_summary.tcp_syn_pending // 0) | tostring)],
        ["XDP TCP 已建链", ((.xdp_status.active_summary.tcp_established // 0) | tostring)],
        ["XDP UDP 活动", ((.xdp_status.active_summary.udp // 0) | tostring)],
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
