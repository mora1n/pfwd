#!/usr/bin/env bash

forwarder_table() {
    if [ -f "$PFWD_CONFIG_FILE" ]; then
        jq -r '.settings.forward_table // "port_forward"' "$PFWD_CONFIG_FILE"
    else
        echo "port_forward"
    fi
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
        ""|"::")
            echo "46"
            ;;
        "0.0.0.0")
            echo "4"
            ;;
        *:*)
            echo "6"
            ;;
        *)
            echo "4"
            ;;
    esac
}

forwarder_protocol_rows() {
    local protocol="${1:-tcp_udp}"
    case "$protocol" in
        tcp_udp)
            printf 'tcp\nudp\n'
            ;;
        tcp|udp)
            printf '%s\n' "$protocol"
            ;;
        *)
            pfwd_die "无效协议：$protocol"
            ;;
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

forwarder_runtime_json() {
    local strict="${1:-true}"
    config_init >/dev/null
    local today rows
    today="$(pfwd_today)"
    rows="$(jq -r --arg today "$today" '
      .forwards[]
      | select(.enabled == true and (.stop_at == null or .stop_at > $today))
      | [
          .id,
          (.listen_ip // "::"),
          (.listen_port | tostring),
          .remote_host,
          (.remote_port | tostring),
          (.protocol // "tcp_udp"),
          (.comment // ""),
          (.nft.snat_mode // "masquerade"),
          (.nft.snat_source // ""),
          (.nft.mss_mode // ""),
          (if (.nft.mss_value // null) == null then "" else (.nft.mss_value | tostring) end)
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE")"

    if [ -z "$rows" ]; then
        printf '[]\n'
        return 0
    fi

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        forwarder_split_tsv_line "$line"
        local id listen_ip listen_port remote_host remote_port protocol comment snat_mode snat_source mss_mode mss_value
        id="${FORWARDER_TSV_FIELDS[0]:-}"
        listen_ip="${FORWARDER_TSV_FIELDS[1]:-}"
        listen_port="${FORWARDER_TSV_FIELDS[2]:-}"
        remote_host="${FORWARDER_TSV_FIELDS[3]:-}"
        remote_port="${FORWARDER_TSV_FIELDS[4]:-}"
        protocol="${FORWARDER_TSV_FIELDS[5]:-}"
        comment="${FORWARDER_TSV_FIELDS[6]:-}"
        snat_mode="${FORWARDER_TSV_FIELDS[7]:-}"
        snat_source="${FORWARDER_TSV_FIELDS[8]:-}"
        mss_mode="${FORWARDER_TSV_FIELDS[9]:-}"
        mss_value="${FORWARDER_TSV_FIELDS[10]:-}"
        [ -n "$listen_port" ] || continue
        local ip_versions target_rows ipver proto family resolved_ip family_ipver
        ip_versions="$(forwarder_infer_ip_version "$listen_ip" "$snat_mode" "$snat_source")"
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
                    jq -cn \
                      --arg id "$id" \
                      --arg listen_ip "$listen_ip" \
                      --argjson listen_port "$listen_port" \
                      --arg protocol "$proto" \
                      --arg remote_input "$remote_host" \
                      --arg resolved_target "$resolved_ip" \
                      --argjson remote_port "$remote_port" \
                      --arg family "$family" \
                      --argjson ip_version "$family_ipver" \
                      --arg comment "$comment" \
                      --arg snat_mode "$snat_mode" \
                      --arg snat_source "$snat_source" \
                      --arg mss_mode "$mss_mode" \
                      --arg mss_value "$mss_value" '
                      {
                        id: $id,
                        listen_ip: $listen_ip,
                        listen_port: $listen_port,
                        protocol: $protocol,
                        remote_input: $remote_input,
                        resolved_target: $resolved_target,
                        remote_port: $remote_port,
                        family: $family,
                        ip_version: $ip_version,
                        comment: (if $comment == "" then null else $comment end),
                        snat_mode: $snat_mode,
                        snat_source: (if $snat_source == "" then null else $snat_source end),
                        mss_mode: (if $mss_mode == "" then null else $mss_mode end),
                        mss_value: (if $mss_value == "" then null else ($mss_value | tonumber) end)
                      }
                    '
                done <<< "$target_rows"
            done < <(forwarder_protocol_rows "$protocol")
        done <<< "$ip_versions"
    done <<< "$rows" | jq -s '.'
}

forwarder_subchain_name() {
    local section="$1"
    local proto="$2"
    local ipver="$3"
    printf 'pfwd_%s_%s%s' "$section" "$proto" "$ipver"
}

forwarder_dispatch_tokens() {
    local proto="$1"
    local ipver="$2"
    if [ "$ipver" = "6" ]; then
        printf 'ip6 nexthdr %s' "$proto"
    else
        printf 'ip protocol %s' "$proto"
    fi
}

forwarder_ports_to_expr() {
    local ports_csv="$1"
    if [[ "$ports_csv" == *,* ]]; then
        printf '{ %s }' "${ports_csv//,/\, }"
    else
        printf '%s' "$ports_csv"
    fi
}

forwarder_render_to_stdout() {
    local runtime_json="$1"
    local table
    table="$(forwarder_table)"

    if [ "$(printf '%s\n' "$runtime_json" | jq 'length')" = "0" ]; then
        return 0
    fi

    declare -A prerouting_ports=()
    declare -A prerouting_seen=()
    declare -A postrouting_keys=()
    declare -A forward_keys=()
    declare -A subchains=()
    local line proto listen_port ipver target_input resolved_target remote_port comment snat_mode snat_source mss_mode mss_value key

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        forwarder_split_tsv_line "$line"
        proto="${FORWARDER_TSV_FIELDS[0]:-}"
        listen_port="${FORWARDER_TSV_FIELDS[1]:-}"
        ipver="${FORWARDER_TSV_FIELDS[2]:-}"
        target_input="${FORWARDER_TSV_FIELDS[3]:-}"
        resolved_target="${FORWARDER_TSV_FIELDS[4]:-}"
        remote_port="${FORWARDER_TSV_FIELDS[5]:-}"
        comment="${FORWARDER_TSV_FIELDS[6]:-}"
        snat_mode="${FORWARDER_TSV_FIELDS[7]:-}"
        snat_source="${FORWARDER_TSV_FIELDS[8]:-}"
        mss_mode="${FORWARDER_TSV_FIELDS[9]:-}"
        mss_value="${FORWARDER_TSV_FIELDS[10]:-}"
        key="${proto}|${ipver}|${resolved_target}|${remote_port}|${snat_mode}|${snat_source}|${mss_mode}|${mss_value}"
        if [ -z "${prerouting_seen["$key|$listen_port"]:-}" ]; then
            if [ -n "${prerouting_ports[$key]:-}" ]; then
                prerouting_ports["$key"]+=",${listen_port}"
            else
                prerouting_ports["$key"]="$listen_port"
            fi
            prerouting_seen["$key|$listen_port"]=1
        fi
        postrouting_keys["$key"]=1
        subchains["prerouting|$ipver|$proto"]=1
        subchains["postrouting|$ipver|$proto"]=1
        if [ "$proto" = "tcp" ] && [ -n "$mss_mode" ]; then
            forward_keys["$key"]=1
            subchains["forward|$ipver|$proto"]=1
        fi
    done < <(
        printf '%s\n' "$runtime_json" | jq -r '
          .[]
          | [
              .protocol,
              (.listen_port | tostring),
              (.ip_version | tostring),
              .remote_input,
              .resolved_target,
              (.remote_port | tostring),
              (.comment // ""),
              (.snat_mode // "masquerade"),
              (.snat_source // ""),
              (.mss_mode // ""),
              (if (.mss_value // null) == null then "" else (.mss_value | tostring) end)
            ]
          | @tsv
        '
    )

    echo "table inet $table {"
    echo "    chain prerouting {"
        echo "        type nat hook prerouting priority dstnat; policy accept;"
    for ipver in 4 6; do
        for proto in tcp udp; do
            [ -n "${subchains["prerouting|$ipver|$proto"]:-}" ] || continue
            echo "        $(forwarder_dispatch_tokens "$proto" "$ipver") jump $(forwarder_subchain_name prerouting "$proto" "$ipver")"
        done
    done
    echo "    }"
    echo

    echo "    chain postrouting {"
    echo "        type nat hook postrouting priority srcnat; policy accept;"
    for ipver in 4 6; do
        for proto in tcp udp; do
            [ -n "${subchains["postrouting|$ipver|$proto"]:-}" ] || continue
            echo "        ct status dnat $(forwarder_dispatch_tokens "$proto" "$ipver") jump $(forwarder_subchain_name postrouting "$proto" "$ipver")"
        done
    done
    echo "    }"
    echo

    echo "    chain forward {"
    echo "        type filter hook forward priority 0; policy accept;"
    echo "        ct state established,related accept"
    for ipver in 4 6; do
        for proto in tcp; do
            [ -n "${subchains["forward|$ipver|$proto"]:-}" ] || continue
            echo "        $(forwarder_dispatch_tokens "$proto" "$ipver") jump $(forwarder_subchain_name forward "$proto" "$ipver")"
        done
    done
    echo "    }"
    echo

    echo "    chain input {"
    echo "        type filter hook input priority filter - 10; policy accept;"
    echo '        ip daddr 127.0.0.0/8 ct status dnat counter accept comment "Allow DNAT to localhost"'
    echo '        ip6 daddr ::1 ct status dnat counter accept comment "Allow DNAT to localhost"'
    echo "    }"
    echo

    for ipver in 4 6; do
        for proto in tcp udp; do
            echo "    chain $(forwarder_subchain_name prerouting "$proto" "$ipver") {"
            while IFS= read -r key; do
                [ -n "$key" ] || continue
                IFS='|' read -r key_proto key_ipver key_target key_remote_port key_snat_mode key_snat_source key_mss_mode key_mss_value <<< "$key"
                [ "$key_proto" = "$proto" ] || continue
                [ "$key_ipver" = "$ipver" ] || continue
                if [ "$ipver" = "6" ]; then
                    echo "        $proto dport $(forwarder_ports_to_expr "${prerouting_ports[$key]}") dnat ip6 to [$key_target]:$key_remote_port"
                else
                    echo "        $proto dport $(forwarder_ports_to_expr "${prerouting_ports[$key]}") dnat ip to $key_target:$key_remote_port"
                fi
            done < <(printf '%s\n' "${!prerouting_ports[@]}" | sort)
            echo "    }"
            echo

            echo "    chain $(forwarder_subchain_name postrouting "$proto" "$ipver") {"
            while IFS= read -r key; do
                [ -n "$key" ] || continue
                IFS='|' read -r key_proto key_ipver key_target key_remote_port key_snat_mode key_snat_source key_mss_mode key_mss_value <<< "$key"
                [ "$key_proto" = "$proto" ] || continue
                [ "$key_ipver" = "$ipver" ] || continue
                if [ "$key_snat_mode" = "snat" ] && [ -n "$key_snat_source" ]; then
                    echo "        ct status dnat $([ "$ipver" = "6" ] && echo ip6 || echo ip) daddr $key_target $proto dport $key_remote_port snat to $key_snat_source"
                else
                    echo "        ct status dnat $([ "$ipver" = "6" ] && echo ip6 || echo ip) daddr $key_target $proto dport $key_remote_port masquerade"
                fi
            done < <(printf '%s\n' "${!postrouting_keys[@]}" | sort)
            echo "    }"
            echo
        done

        echo "    chain $(forwarder_subchain_name forward tcp "$ipver") {"
        while IFS= read -r key; do
            [ -n "$key" ] || continue
            IFS='|' read -r key_proto key_ipver key_target key_remote_port key_snat_mode key_snat_source key_mss_mode key_mss_value <<< "$key"
            [ "$key_proto" = "tcp" ] || continue
            [ "$key_ipver" = "$ipver" ] || continue
            if [ "$key_mss_mode" = "clamp" ]; then
                echo "        $([ "$ipver" = "6" ] && echo ip6 || echo ip) daddr $key_target tcp dport $key_remote_port tcp flags syn / syn,rst tcp option maxseg size set rt mtu"
            elif [ "$key_mss_mode" = "set" ] && [ -n "$key_mss_value" ]; then
                echo "        $([ "$ipver" = "6" ] && echo ip6 || echo ip) daddr $key_target tcp dport $key_remote_port tcp flags syn / syn,rst tcp option maxseg size set $key_mss_value"
            fi
        done < <(printf '%s\n' "${!forward_keys[@]}" | sort)
        echo "    }"
        echo
    done
    echo "}"
}

forwarder_write_runtime_file() {
    local runtime_json="$1"
    printf '%s\n' "$runtime_json" | jq '.' | pfwd_write_atomic "$PFWD_FORWARDER_RUNTIME_FILE"
}

forwarder_write_render_file() {
    local runtime_json="$1"
    local tmp_file
    tmp_file="$(mktemp "${PFWD_FORWARDER_RENDER_FILE}.tmp.XXXXXX")"
    forwarder_render_to_stdout "$runtime_json" > "$tmp_file"
    mv "$tmp_file" "$PFWD_FORWARDER_RENDER_FILE"
}

forwarder_render_matches_runtime() {
    local candidate="$1"
    [ -f "$PFWD_FORWARDER_RENDER_FILE" ] || return 1
    cmp -s "$candidate" "$PFWD_FORWARDER_RENDER_FILE"
}

forwarder_render_config() {
    local runtime_json
    runtime_json="$(forwarder_runtime_json true)"
    forwarder_render_to_stdout "$runtime_json"
}

forwarder_table_exists() {
    local table
    table="$(forwarder_table)"
    nft list table inet "$table" >/dev/null 2>&1
}

forwarder_validate_render_file() {
    local table validate_table validate_file render_file
    table="$(forwarder_table)"
    validate_table="pfwd_validate_$$"
    render_file="$1"
    validate_file="$(mktemp "${render_file}.validate.XXXXXX")"
    sed "s/^table inet $table /table inet $validate_table /" "$render_file" > "$validate_file"
    nft -c -f "$validate_file" >/dev/null 2>&1
    rm -f "$validate_file"
}

forwarder_route_localnet_needed() {
    local runtime_json="$1"
    printf '%s\n' "$runtime_json" | jq -e '.[]? | select(.resolved_target | test("^127\\."))' >/dev/null
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

forwarder_ensure_route_localnet() {
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        ui_emit_dry_run "DRY-RUN: sysctl -w net.ipv4.conf.all.route_localnet=1"
        ui_emit_dry_run "DRY-RUN: sysctl -w net.ipv4.conf.default.route_localnet=1"
        return 0
    fi
    sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.route_localnet=1 >/dev/null 2>&1 || true
}

forwarder_delete_table() {
    local table
    table="$(forwarder_table)"
    if forwarder_table_exists; then
        pfwd_run nft delete table inet "$table"
    fi
}

forwarder_apply_runtime() {
    local runtime_json
    local tmp_render
    pfwd_debug "forwarder_apply_runtime start"
    config_init >/dev/null
    forwarder_validate_config
    runtime_json="$(forwarder_runtime_json true)"
    forwarder_write_runtime_file "$runtime_json"
    if [ "$(printf '%s\n' "$runtime_json" | jq 'length')" = "0" ]; then
        if command -v nft >/dev/null 2>&1; then
            forwarder_delete_table
        fi
        : > "$PFWD_FORWARDER_RENDER_FILE"
        return 0
    fi

    pfwd_require_cmd nft
    tmp_render="$(mktemp "${PFWD_FORWARDER_RENDER_FILE}.tmp.XXXXXX")"
    forwarder_render_to_stdout "$runtime_json" > "$tmp_render"
    forwarder_validate_render_file "$tmp_render" || {
        rm -f "$tmp_render"
        pfwd_die "forwarder nft 配置校验失败：$tmp_render"
    }
    forwarder_ensure_ip_forwarding
    if forwarder_route_localnet_needed "$runtime_json"; then
        forwarder_ensure_route_localnet
    fi
    if forwarder_table_exists && forwarder_render_matches_runtime "$tmp_render"; then
        rm -f "$tmp_render"
        return 0
    fi
    mv "$tmp_render" "$PFWD_FORWARDER_RENDER_FILE"
    forwarder_delete_table
    pfwd_run nft -f "$PFWD_FORWARDER_RENDER_FILE"
}

forwarder_run_maintenance() {
    forwarder_apply_runtime
}

forwarder_stop_runtime() {
    if command -v nft >/dev/null 2>&1; then
        forwarder_delete_table
    fi
    : > "$PFWD_FORWARDER_RENDER_FILE"
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
Description=pfwd boot restore
After=network-online.target nftables.service systemd-sysctl.service ufw.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PFWD_BIN_PATH __forward_boot

[Install]
WantedBy=multi-user.target
EOF
}
