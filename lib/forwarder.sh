#!/usr/bin/env bash

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
    iface="$(jq -r '.settings.xdp.interface // .settings.tc_interface // ""' "$PFWD_CONFIG_FILE")"
    if [ -n "$iface" ]; then
        echo "$iface"
        return
    fi
    ip route show default 2>/dev/null | awk '{print $5; exit}'
}

forwarder_xdp_mode() {
    jq -r '.settings.xdp.mode // "auto"' "$PFWD_CONFIG_FILE"
}

forwarder_protocol_filters_enabled() {
    if [ "$(jq -r '.settings.guard.block_http // false' "$PFWD_CONFIG_FILE")" = "true" ] ||
       [ "$(jq -r '.settings.guard.block_tls // false' "$PFWD_CONFIG_FILE")" = "true" ] ||
       [ "$(jq -r '.settings.guard.block_socks // false' "$PFWD_CONFIG_FILE")" = "true" ]; then
        echo true
    else
        echo false
    fi
}

forwarder_whitelist_files_json() {
    local files=()
    if command -v whitelist_enabled >/dev/null 2>&1 && [ "$(whitelist_enabled)" = "true" ]; then
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

forwarder_runtime_json() {
    local strict="${1:-true}"
    config_init >/dev/null
    stats_init >/dev/null

    local today rows rules_json="[]" users_json settings_json rule_index_json user_index_json
    today="$(pfwd_today)"
    rows="$(jq -r --arg today "$today" '
      .forwards[]
      | select(.enabled == true and (.stop_at == null or .stop_at > $today))
      | [
          .id,
          .user_id,
          (.listen_ip // "::"),
          (.listen_port | tostring),
          .remote_host,
          (.remote_port | tostring),
          (.protocol // "tcp_udp"),
          (.comment // ""),
          (.xdp.snat_mode // "masquerade"),
          (.xdp.snat_source // ""),
          (.xdp.mss_mode // ""),
          (if (.xdp.mss_value // null) == null then "" else (.xdp.mss_value | tostring) end),
          (.traffic_mode // "two-way"),
          ((.traffic_ratio // 1) | tostring),
          (.limits.traffic_bytes // 0 | tostring)
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE")"

    user_index_json="$(jq -r '
      reduce (.users[]? | .id) as $id ({};
        .[$id] = (keys | length)
      )
    ' "$PFWD_CONFIG_FILE")"
    rule_index_json="$(jq -r '
      reduce (.forwards[]? | .id) as $id ({};
        .[$id] = (keys | length)
      )
    ' "$PFWD_CONFIG_FILE")"

    users_json="$(jq -n \
      --slurpfile cfg "$PFWD_CONFIG_FILE" \
      --slurpfile stats "$PFWD_STATS_FILE" \
      --argjson user_index "$user_index_json" '
      [
        $cfg[0].users[]? |
        {
          id: .id,
          index: ($user_index[.id] // 0),
          traffic_limit_bytes: (.limits.traffic_bytes // 0),
          billing_used_base_bytes: ($stats[0].users[.id].billing_used_bytes // 0)
        }
      ]
    ')"

    if [ -n "$rows" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            forwarder_split_tsv_line "$line"
            local id user_id listen_ip listen_port remote_host remote_port protocol comment snat_mode snat_source mss_mode mss_value traffic_mode traffic_ratio rule_limit
            id="${FORWARDER_TSV_FIELDS[0]:-}"
            user_id="${FORWARDER_TSV_FIELDS[1]:-}"
            listen_ip="${FORWARDER_TSV_FIELDS[2]:-}"
            listen_port="${FORWARDER_TSV_FIELDS[3]:-}"
            remote_host="${FORWARDER_TSV_FIELDS[4]:-}"
            remote_port="${FORWARDER_TSV_FIELDS[5]:-}"
            protocol="${FORWARDER_TSV_FIELDS[6]:-}"
            comment="${FORWARDER_TSV_FIELDS[7]:-}"
            snat_mode="${FORWARDER_TSV_FIELDS[8]:-}"
            snat_source="${FORWARDER_TSV_FIELDS[9]:-}"
            mss_mode="${FORWARDER_TSV_FIELDS[10]:-}"
            mss_value="${FORWARDER_TSV_FIELDS[11]:-}"
            traffic_mode="${FORWARDER_TSV_FIELDS[12]:-two-way}"
            traffic_ratio="${FORWARDER_TSV_FIELDS[13]:-1}"
            rule_limit="${FORWARDER_TSV_FIELDS[14]:-0}"
            [ -n "$listen_port" ] || continue
            local ip_versions target_rows ipver proto family resolved_ip family_ipver user_limit user_index rule_index billing_used user_billing_used
            ip_versions="$(forwarder_infer_ip_version "$listen_ip" "$snat_mode" "$snat_source")"
            user_limit="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | (.limits.traffic_bytes // 0)' "$PFWD_CONFIG_FILE")"
            user_index="$(jq -r --arg id "$user_id" --argjson idx "$user_index_json" '$idx[$id] // 0' <<< '{}')"
            rule_index="$(jq -r --arg id "$id" --argjson idx "$rule_index_json" '$idx[$id] // 0' <<< '{}')"
            billing_used="$(jq -r --arg id "$id" '.forwards[$id].billing_used_bytes // 0' "$PFWD_STATS_FILE")"
            user_billing_used="$(jq -r --arg id "$user_id" '.users[$id].billing_used_bytes // 0' "$PFWD_STATS_FILE")"
            while IFS= read -r ipver; do
                [ -n "$ipver" ] || continue
                target_rows="$(forwarder_resolve_targets "$remote_host" "$ipver" || true)"
                if [ -z "$target_rows" ]; then
                    if [ "$strict" = "true" ] && [ "$(forwarder_target_kind "$remote_host")" = "domain" ]; then
                        pfwd_die "无法解析目标地址：$remote_host (IPv$ipver)${FORWARDER_LAST_RESOLVE_ERROR:+：$FORWARDER_LAST_RESOLVE_ERROR}"
                    fi
                    continue
                fi
                while IFS= read -r proto; do
                    [ -n "$proto" ] || continue
                    while IFS='|' read -r family _ resolved_ip; do
                        [ -n "$resolved_ip" ] || continue
                        if [ "$family" = "ip6" ]; then
                            family_ipver=6
                        else
                            family_ipver=4
                        fi
                        rules_json="$(jq -c \
                          --argjson rules "$rules_json" \
                          --arg id "$id" \
                          --argjson index "$rule_index" \
                          --arg user_id "$user_id" \
                          --argjson user_index "$user_index" \
                          --arg listen_ip "$listen_ip" \
                          --argjson listen_port "$listen_port" \
                          --arg protocol "$proto" \
                          --arg remote_input "$remote_host" \
                          --arg resolved_target "$resolved_ip" \
                          --argjson remote_port "$remote_port" \
                          --argjson ip_version "$family_ipver" \
                          --arg comment "$comment" \
                          --arg snat_mode "$snat_mode" \
                          --arg snat_source "$snat_source" \
                          --arg mss_mode "$mss_mode" \
                          --arg mss_value "$mss_value" \
                          --arg traffic_mode "$traffic_mode" \
                          --arg traffic_ratio "$traffic_ratio" \
                          --argjson rule_limit "$rule_limit" \
                          --argjson user_limit "${user_limit:-0}" \
                          --argjson billing_used "$billing_used" \
                          --argjson user_billing_used "$user_billing_used" '
                          $rules + [{
                            id: $id,
                            index: $index,
                            user_id: $user_id,
                            user_index: $user_index,
                            listen_ip: $listen_ip,
                            listen_port: $listen_port,
                            protocol: $protocol,
                            remote_input: $remote_input,
                            resolved_target: $resolved_target,
                            remote_port: $remote_port,
                            ip_version: $ip_version,
                            comment: (if $comment == "" then null else $comment end),
                            snat_mode: $snat_mode,
                            snat_source: (if $snat_source == "" then null else $snat_source end),
                            mss_mode: (if $mss_mode == "" then null else $mss_mode end),
                            mss_value: (if $mss_value == "" then null else ($mss_value | tonumber) end),
                            traffic_mode: $traffic_mode,
                            traffic_ratio: ($traffic_ratio | tonumber),
                            traffic_limit_bytes: $rule_limit,
                            user_limit_bytes: $user_limit,
                            billing_used_base_bytes: $billing_used,
                            user_billing_used_base_bytes: $user_billing_used
                          }]
                        ' <<< '{}')"
                    done <<< "$target_rows"
                done < <(forwarder_protocol_rows "$protocol")
            done <<< "$ip_versions"
        done <<< "$rows"
    fi

    settings_json="$(jq -n \
      --arg mode "$(forwarder_xdp_mode)" \
      --arg iface "$(forwarder_iface)" \
      --argjson whitelist_enabled "$(command -v whitelist_enabled >/dev/null 2>&1 && whitelist_enabled || echo false)" \
      --argjson block_http "$(jq -r '.settings.guard.block_http // false' "$PFWD_CONFIG_FILE")" \
      --argjson block_tls "$(jq -r '.settings.guard.block_tls // false' "$PFWD_CONFIG_FILE")" \
      --argjson block_socks "$(jq -r '.settings.guard.block_socks // false' "$PFWD_CONFIG_FILE")" \
      --argjson files "$(forwarder_whitelist_files_json)" '
      {
        xdp_mode: $mode,
        interface: $iface,
        whitelist_enabled: $whitelist_enabled,
        block_http: $block_http,
        block_tls: $block_tls,
        block_socks: $block_socks,
        whitelist_files: $files
      }
    ')"

    jq -n \
      --arg generated_at "$(pfwd_now_iso)" \
      --argjson settings "$settings_json" \
      --argjson users "$users_json" \
      --argjson rules "$rules_json" \
      --argjson rule_index "$rule_index_json" \
      --argjson user_index "$user_index_json" '
      {
        generated_at: $generated_at,
        settings: $settings,
        users: $users,
        rules: $rules,
        rule_index: $rule_index,
        user_index: $user_index
      }
    '
}

forwarder_write_runtime_file() {
    local runtime_json="$1"
    printf '%s\n' "$runtime_json" | jq '.' | pfwd_write_atomic "$PFWD_FORWARDER_RUNTIME_FILE"
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

forwarder_apply_runtime() {
    local runtime_json
    pfwd_debug "forwarder_apply_runtime start"
    config_init >/dev/null
    forwarder_validate_config
    if command -v whitelist_prepare_runtime >/dev/null 2>&1; then
        whitelist_prepare_runtime
    fi
    runtime_json="$(forwarder_runtime_json true)"
    forwarder_write_runtime_file "$runtime_json"
    if [ "$(printf '%s\n' "$runtime_json" | jq '.rules | length')" = "0" ]; then
        forwarder_stop_runtime
        return 0
    fi
    pfwd_require_cmd "$(forwarder_bin_path)"
    local iface
    iface="$(forwarder_iface)"
    [ -n "$iface" ] || pfwd_die "无法确定 XDP 网卡，请设置 settings.xdp.interface 或 settings.tc_interface"
    forwarder_ensure_ip_forwarding
    pfwd_run "$(forwarder_bin_path)" apply \
      --runtime-file "$PFWD_FORWARDER_RUNTIME_FILE" \
      --state-file "$PFWD_STATS_FILE" \
      --status-file "$PFWD_XDP_STATUS_FILE" \
      --iface "$iface" \
      --xdp-mode "$(forwarder_xdp_mode)" \
      --xdp-pin "$PFWD_XDP_LINK_PIN_PATH" \
      --ingress-pin "$PFWD_XDP_INGRESS_PIN_PATH" \
      --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" \
      --user-counter-pin "$PFWD_XDP_USER_COUNTER_PIN_PATH" \
      --stats-pin "$PFWD_XDP_STATS_PIN_PATH" \
      --quiet
}

forwarder_run_maintenance() {
    forwarder_apply_runtime
}

forwarder_stop_runtime() {
    if [ -x "$(forwarder_bin_path)" ]; then
        pfwd_run "$(forwarder_bin_path)" remove \
          --status-file "$PFWD_XDP_STATUS_FILE" \
          --xdp-pin "$PFWD_XDP_LINK_PIN_PATH" \
          --ingress-pin "$PFWD_XDP_INGRESS_PIN_PATH" \
          --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" \
          --user-counter-pin "$PFWD_XDP_USER_COUNTER_PIN_PATH" \
          --stats-pin "$PFWD_XDP_STATS_PIN_PATH" || true
    fi
    printf '[]\n' | pfwd_write_atomic "$PFWD_FORWARDER_RUNTIME_FILE"
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
Description=pfwd XDP boot restore
After=network-online.target systemd-sysctl.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PFWD_BIN_PATH __forward_boot

[Install]
WantedBy=multi-user.target
EOF
}
