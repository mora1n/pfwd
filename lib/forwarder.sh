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
    iface="$(jq -r '.settings.xdp.interface // .settings.tc_interface // ""' "$PFWD_CONFIG_FILE")"
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

forwarder_runtime_has_loopback_backend() {
    jq -e '.rules[]? | select(.resolved_target == "127.0.0.1" or .resolved_target == "::1")' >/dev/null
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
        ] | @tsv
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

    local guard_enabled whitelist_state protocol_filters_enabled
    guard_enabled="$(jq -r '.settings.guard.enabled // false' "$PFWD_CONFIG_FILE")"
    whitelist_state="false"
    if [ "$guard_enabled" = "true" ] && command -v whitelist_enabled >/dev/null 2>&1 && [ "$(whitelist_enabled)" = "true" ]; then
        whitelist_state="true"
    fi
    protocol_filters_enabled="$(forwarder_protocol_filters_enabled)"

    settings_json="$(jq -n \
      --arg iface "$(forwarder_iface)" \
      --arg guard_ingress_mode "$(forwarder_guard_ingress_mode)" \
      --argjson guard_enabled "$guard_enabled" \
      --argjson whitelist_enabled "$whitelist_state" \
      --argjson block_http "$(if [ "$protocol_filters_enabled" = "true" ]; then jq -r '.settings.guard.block_http // false' "$PFWD_CONFIG_FILE"; else echo false; fi)" \
      --argjson block_tls "$(if [ "$protocol_filters_enabled" = "true" ]; then jq -r '.settings.guard.block_tls // false' "$PFWD_CONFIG_FILE"; else echo false; fi)" \
      --argjson block_socks "$(if [ "$protocol_filters_enabled" = "true" ]; then jq -r '.settings.guard.block_socks // false' "$PFWD_CONFIG_FILE"; else echo false; fi)" \
      --argjson skip_ports "$(forwarder_protocol_skip_ports_json)" \
      --argjson files "$(forwarder_whitelist_files_json)" '
      {
        interface: $iface,
        guard_ingress_mode: $guard_ingress_mode,
        guard_enabled: $guard_enabled,
        whitelist_enabled: $whitelist_enabled,
        block_http: $block_http,
        block_tls: $block_tls,
        block_socks: $block_socks,
        protocol_skip_ports: $skip_ports,
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

forwarder_runtime_config_hash() {
    jq -S '.' | sha256sum | awk '{print $1}'
}

forwarder_write_runtime_file() {
    local runtime_json="$1"
    printf '%s\n' "$runtime_json" | jq '.' | pfwd_write_atomic "$PFWD_FORWARDER_RUNTIME_FILE"
}

forwarder_write_xdp_runtime_file() {
    local runtime_json="$1"
    printf '%s\n' "$runtime_json" | jq '.' | pfwd_write_atomic "$PFWD_FORWARDER_XDP_RUNTIME_FILE"
}

forwarder_write_nft_runtime_file() {
    local runtime_json="$1"
    printf '%s\n' "$runtime_json" | jq '.' | pfwd_write_atomic "$PFWD_FORWARDER_NFT_RUNTIME_FILE"
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

forwarder_split_runtime_json() {
    local runtime_json="$1"
    local xdp_rules nft_rules xdp_payload nft_payload

    xdp_rules="$(jq '
      [
        .rules[]?
        | if (.resolved_target == "127.0.0.1") or (.resolved_target == "::1") then
            . + {xdp_disabled: true}
          else
            .
          end
      ]
    ' <<< "$runtime_json")"
    nft_rules="$(jq '
      [.rules[]? | select((.resolved_target == "127.0.0.1") or (.resolved_target == "::1"))]
    ' <<< "$runtime_json")"

    xdp_payload="$(jq \
      --argjson rules "$xdp_rules" '
      .rules = $rules
      | .rule_index = (reduce ($rules[]? | .id) as $id ({}; .[$id] = (keys | length)))
    ' <<< "$runtime_json")"
    nft_payload="$(jq \
      --argjson rules "$nft_rules" '
      .rules = $rules
      | .rule_index = (reduce ($rules[]? | .id) as $id ({}; .[$id] = (keys | length)))
    ' <<< "$runtime_json")"

    FORWARDER_SPLIT_XDP_RUNTIME_JSON="$xdp_payload"
    FORWARDER_SPLIT_NFT_RUNTIME_JSON="$nft_payload"
}

forwarder_xdp_guard_required() {
    local runtime_json="$1"
    jq -e '
      (.settings.guard_enabled == true)
      and ((.settings.whitelist_enabled == true) or (.settings.block_http == true) or (.settings.block_tls == true) or (.settings.block_socks == true))
    ' >/dev/null <<< "$runtime_json"
}

forwarder_xdp_forward_rule_count() {
    local runtime_json="$1"
    jq '[.rules[]? | select((.xdp_disabled // false) | not)] | length' <<< "$runtime_json"
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
        applied: ((($runtime.rules | length) > 0) and ($xdp_applied or $nft_applied)),
        generated_at: $generated_at,
        forwarding_backend: $backend,
        xdp_applied: $xdp_applied,
        xdp_forward_applied: $xdp_forward_applied,
        nft_applied: $nft_applied,
        loopback_via_nft: (($nft_runtime.rules | any(.resolved_target == "127.0.0.1" or .resolved_target == "::1")) // false),
        fallback_reason: (if $fallback_reason == "" then null else $fallback_reason end),
        xdp_error: (if $xdp_error == "" then null else $xdp_error end),
        rules: ($runtime.rules | length),
        xdp_rules_count: ([$xdp_runtime.rules[]? | select((.xdp_disabled // false) | not)] | length),
        xdp_guard_rules_count: ([$xdp_runtime.rules[]? | select((.xdp_disabled // false) == true)] | length),
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
        ["XDP 规则", (.xdp_rules_count | tostring)],
        ["XDP Guard 规则", ((.xdp_guard_rules_count // 0) | tostring)],
        ["nft 规则", (.nft_rules_count | tostring)],
        ["绑定网卡", (.interface // "-")],
        ["回退原因", (.fallback_reason // "-")]
      ]
      | map(@tsv)
      | .[]
    ' <<< "$json"
}

forwarder_apply_xdp_runtime() {
    local runtime_json="$1"
    local xdp_status xdp_error="" iface total_rules
    total_rules="$(jq '.rules | length' <<< "$runtime_json")"
    if [ "$total_rules" = "0" ]; then
        if [ -x "$(forwarder_bin_path)" ]; then
            pfwd_run "$(forwarder_bin_path)" remove \
              --status-file "$PFWD_XDP_STATUS_FILE" \
              --xdp-pin "$PFWD_XDP_LINK_PIN_PATH" \
              --ingress-pin "$PFWD_XDP_INGRESS_PIN_PATH" \
              --loopback-pin "$PFWD_XDP_LOOPBACK_PIN_PATH" \
              --sk-lookup-pin "$PFWD_XDP_SK_LOOKUP_PIN_PATH" \
              --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" \
              --user-counter-pin "$PFWD_XDP_USER_COUNTER_PIN_PATH" \
              --stats-pin "$PFWD_XDP_STATS_PIN_PATH" || true
        fi
        jq -n '{applied:false}' 
        return 0
    fi

    iface="$(jq -r '.settings.interface // empty' <<< "$runtime_json")"
    [ -n "$iface" ] || iface="$(forwarder_iface)"
    [ -n "$iface" ] || pfwd_die "无法确定 XDP 网卡，请设置 settings.xdp.interface 或 settings.tc_interface"

    if [ ! -x "$(forwarder_bin_path)" ]; then
        return 1
    fi

    xdp_status="$(
      "$(forwarder_bin_path)" apply \
        --runtime-file "$PFWD_FORWARDER_XDP_RUNTIME_FILE" \
        --state-file "$PFWD_STATS_FILE" \
        --status-file "$PFWD_XDP_STATUS_FILE" \
        --iface "$iface" \
        --xdp-pin "$PFWD_XDP_LINK_PIN_PATH" \
        --ingress-pin "$PFWD_XDP_INGRESS_PIN_PATH" \
        --loopback-pin "$PFWD_XDP_LOOPBACK_PIN_PATH" \
        --sk-lookup-pin "$PFWD_XDP_SK_LOOKUP_PIN_PATH" \
        --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" \
        --user-counter-pin "$PFWD_XDP_USER_COUNTER_PIN_PATH" \
        --stats-pin "$PFWD_XDP_STATS_PIN_PATH" \
        --guard-mode ingress \
        --quiet 2>&1
    )" || {
        xdp_error="$xdp_status"
        pfwd_run "$(forwarder_bin_path)" remove \
          --status-file "$PFWD_XDP_STATUS_FILE" \
          --xdp-pin "$PFWD_XDP_LINK_PIN_PATH" \
          --ingress-pin "$PFWD_XDP_INGRESS_PIN_PATH" \
          --loopback-pin "$PFWD_XDP_LOOPBACK_PIN_PATH" \
          --sk-lookup-pin "$PFWD_XDP_SK_LOOKUP_PIN_PATH" \
          --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" \
          --user-counter-pin "$PFWD_XDP_USER_COUNTER_PIN_PATH" \
          --stats-pin "$PFWD_XDP_STATS_PIN_PATH" || true
        printf '%s' "$xdp_error" >&2
        return 1
    }

    if [ -f "$PFWD_XDP_STATUS_FILE" ]; then
        jq '.' "$PFWD_XDP_STATUS_FILE"
    else
        jq -n '{applied:true}'
    fi
}

forwarder_apply_runtime() {
    local runtime_json xdp_runtime_json nft_runtime_json
    local xdp_status_json="" xdp_error="" backend="none"
    local xdp_applied="false" xdp_forward_applied="false" nft_applied="false"
    local xdp_forward_rules=0 xdp_guard_required="false"
    pfwd_debug "forwarder_apply_runtime start"
    config_init >/dev/null
    forwarder_validate_config
    if command -v whitelist_prepare_runtime >/dev/null 2>&1; then
        whitelist_prepare_runtime
    fi

    runtime_json="$(forwarder_runtime_json true)"
    forwarder_write_runtime_file "$runtime_json"
    forwarder_split_runtime_json "$runtime_json"
    xdp_runtime_json="$FORWARDER_SPLIT_XDP_RUNTIME_JSON"
    nft_runtime_json="$FORWARDER_SPLIT_NFT_RUNTIME_JSON"
    forwarder_write_xdp_runtime_file "$xdp_runtime_json"
    forwarder_write_nft_runtime_file "$nft_runtime_json"
    xdp_forward_rules="$(forwarder_xdp_forward_rule_count "$xdp_runtime_json")"
    if forwarder_xdp_guard_required "$runtime_json"; then
        xdp_guard_required="true"
    fi

    if [ "$(jq '.rules | length' <<< "$runtime_json")" = "0" ]; then
        forwarder_stop_runtime
        return 0
    fi

    forwarder_ensure_ip_forwarding

    if [ "$xdp_forward_rules" -gt 0 ] || [ "$xdp_guard_required" = "true" ]; then
        if xdp_status_json="$(forwarder_apply_xdp_runtime "$xdp_runtime_json" 2>&1)"; then
            xdp_applied="true"
            if [ "$xdp_forward_rules" -gt 0 ]; then
                xdp_forward_applied="true"
            fi
        else
            xdp_error="$xdp_status_json"
            xdp_status_json='{}'
            nft_runtime_json="$(jq \
              --argjson extra "$(jq '[.rules[]? | select((.xdp_disabled // false) | not)]' <<< "$xdp_runtime_json")" \
              '.rules += $extra | .rule_index = (reduce (.rules[]? | .id) as $id ({}; .[$id] = (keys | length)))' <<< "$nft_runtime_json")"
            forwarder_write_nft_runtime_file "$nft_runtime_json"
        fi
    else
        pfwd_run "$(forwarder_bin_path)" remove \
          --status-file "$PFWD_XDP_STATUS_FILE" \
          --xdp-pin "$PFWD_XDP_LINK_PIN_PATH" \
          --ingress-pin "$PFWD_XDP_INGRESS_PIN_PATH" \
          --loopback-pin "$PFWD_XDP_LOOPBACK_PIN_PATH" \
          --sk-lookup-pin "$PFWD_XDP_SK_LOOKUP_PIN_PATH" \
          --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" \
          --user-counter-pin "$PFWD_XDP_USER_COUNTER_PIN_PATH" \
          --stats-pin "$PFWD_XDP_STATS_PIN_PATH" || true
        xdp_status_json='{}'
    fi

    if [ "$(jq '.rules | length' <<< "$nft_runtime_json")" -gt 0 ]; then
        fw_apply_nft_runtime "$nft_runtime_json"
        nft_applied="true"
    else
        fw_delete_forward_table || true
        : > "$PFWD_FORWARDER_NFT_RENDER_FILE"
    fi

    fw_apply_accounting_runtime "$runtime_json"
    fw_apply_tc

    if [ "$xdp_forward_applied" = "true" ] && [ "$nft_applied" = "true" ]; then
        backend="hybrid"
    elif [ "$xdp_forward_applied" = "true" ]; then
        backend="xdp-only"
    elif [ "$nft_applied" = "true" ]; then
        if [ -n "$xdp_error" ]; then
            backend="nft-fallback"
        else
            backend="nft-only"
        fi
    elif [ "$xdp_applied" = "true" ]; then
        backend="guard-only"
    fi

    forwarder_write_status_file "$(forwarder_runtime_status_json "$backend" "$runtime_json" "$xdp_runtime_json" "$nft_runtime_json" "${xdp_error:+XDP 不可用，已自动切换到 nftables}" "$xdp_error" "$xdp_applied" "$nft_applied" "${xdp_status_json:-{}}" "$xdp_forward_applied")"
    fw_cleanup_legacy_nft
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
          --loopback-pin "$PFWD_XDP_LOOPBACK_PIN_PATH" \
          --sk-lookup-pin "$PFWD_XDP_SK_LOOKUP_PIN_PATH" \
          --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" \
          --user-counter-pin "$PFWD_XDP_USER_COUNTER_PIN_PATH" \
          --stats-pin "$PFWD_XDP_STATS_PIN_PATH" || true
    fi
    fw_delete_forward_table || true
    fw_cleanup_legacy_nft || true
    printf '[]\n' | pfwd_write_atomic "$PFWD_FORWARDER_RUNTIME_FILE"
    printf '[]\n' | pfwd_write_atomic "$PFWD_FORWARDER_XDP_RUNTIME_FILE"
    printf '[]\n' | pfwd_write_atomic "$PFWD_FORWARDER_NFT_RUNTIME_FILE"
    : > "$PFWD_FORWARDER_NFT_RENDER_FILE"
    forwarder_write_status_file "$(jq -n '{applied:false,forwarding_backend:"none",xdp_applied:false,xdp_forward_applied:false,nft_applied:false,loopback_via_nft:false,rules:0,xdp_rules_count:0,xdp_guard_rules_count:0,nft_rules_count:0,interface:"",protocol_guard:false,whitelist_enabled:false}')"
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
