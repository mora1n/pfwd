#!/usr/bin/env bash

fw_table() {
    jq -r '.settings.nft_table // "pfwd"' "$PFWD_CONFIG_FILE"
}

fw_family() {
    jq -r '.settings.nft_family // "inet"' "$PFWD_CONFIG_FILE"
}

FW_NFT_ACCOUNTING_RENDER_FILE="${PFWD_RUN_DIR}/firewall.nft"

fw_forward_table() {
    jq -r '.settings.forward_table // "port_forward"' "$PFWD_CONFIG_FILE"
}

fw_tc_interface() {
    local iface
    iface="$(jq -r '.settings.tc_interface // .settings.forward.interface // ""' "$PFWD_CONFIG_FILE")"
    if [ -n "$iface" ]; then
        echo "$iface"
        return
    fi
    ip route show default 2>/dev/null | awk '{print $5; exit}'
}

fw_cleanup_nft_table() {
    local family="$1"
    local table="$2"
    [ -n "$family" ] || return 0
    [ -n "$table" ] || return 0
    case "$family:$table" in
        ip:filter|ip:nat|ip:mangle|ip6:filter|ip6:nat|ip6:mangle|inet:filter|inet:nat|inet:mangle)
            return 0
            ;;
    esac
    nft list table "$family" "$table" >/dev/null 2>&1 || return 0
    pfwd_run nft delete table "$family" "$table"
}

fw_counter_names() {
    local id="$1"
    local safe="${id//-/_}"
    echo "fwd_${safe}_in fwd_${safe}_out"
}

fw_safe_object_name() {
    local prefix="$1"
    local value="$2"
    local sum safe
    sum="$(printf '%s' "$value" | cksum | awk '{print $1}')"
    safe="$(printf '%s' "$value" | tr -c 'A-Za-z0-9_' '_' | sed 's/^_*//;s/_*$//;s/__*/_/g' | cut -c1-24)"
    [ -n "$safe" ] || safe="id"
    printf '%s_%s_%s' "$prefix" "$sum" "$safe"
}

fw_forward_usage_expr() {
    local mode="$1"
    local ratio="${2:-1}"
    local in_bytes="$3"
    local out_bytes="$4"
    awk -v mode="$mode" -v ratio="$ratio" -v in_bytes="$in_bytes" -v out_bytes="$out_bytes" '
        BEGIN {
            factor = (mode == "one-way") ? 1 : 2
            billed = int(in_bytes * ratio) + int(out_bytes * ratio)
            printf "%.0f\n", billed * factor
        }
    '
}

fw_runtime_rule_rows() {
    local runtime_json="$1"
    jq -r '
      .rules[]? |
      [
        .id,
        .user_id,
        (.listen_ip // "::"),
        (.listen_port | tostring),
        (.protocol // "tcp_udp"),
        (.remote_input // ""),
        .resolved_target,
        (.remote_port | tostring),
        (.ip_version | tostring),
        (.comment // ""),
        (.snat_mode // "masquerade"),
        (.snat_source // ""),
        (.mss_mode // ""),
        (if (.mss_value // null) == null then "" else (.mss_value | tostring) end),
        (.traffic_mode // "two-way"),
        ((.traffic_ratio // 1) | tostring),
        ((.traffic_limit_bytes // 0) | tostring),
        ((.user_limit_bytes // 0) | tostring)
      ] | @tsv
    ' <<< "$runtime_json"
}

fw_ports_to_expr() {
    local ports_csv="$1"
    if [[ "$ports_csv" == *,* ]]; then
        printf '{ %s }' "${ports_csv//,/\, }"
    else
        printf '%s' "$ports_csv"
    fi
}

fw_subchain_name() {
    local section="$1"
    local proto="$2"
    local ipver="$3"
    printf 'pfwd_%s_%s%s' "$section" "$proto" "$ipver"
}

fw_dispatch_tokens() {
    local proto="$1"
    local ipver="$2"
    if [ "$ipver" = "6" ]; then
        printf 'ip6 nexthdr %s' "$proto"
    else
        printf 'ip protocol %s' "$proto"
    fi
}

fw_rule_matches_snapshot() {
    local render_file="$1"
    [ -f "$PFWD_FORWARDER_NFT_RENDER_FILE" ] || return 1
    cmp -s "$render_file" "$PFWD_FORWARDER_NFT_RENDER_FILE"
}

fw_route_localnet_needed() {
    local runtime_json="$1"
    jq -e '.rules[]? | select(.resolved_target | test("^127\\."))' >/dev/null <<< "$runtime_json"
}

fw_ensure_route_localnet() {
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        ui_emit_dry_run "DRY-RUN: sysctl -w net.ipv4.conf.all.route_localnet=1"
        ui_emit_dry_run "DRY-RUN: sysctl -w net.ipv4.conf.default.route_localnet=1"
        return 0
    fi
    sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.route_localnet=1 >/dev/null 2>&1 || true
}

fw_delete_forward_table() {
    local family table
    family="$(fw_family)"
    table="$(fw_forward_table)"
    nft list table "$family" "$table" >/dev/null 2>&1 || return 0
    pfwd_run nft delete table "$family" "$table"
}

fw_forward_table_exists() {
    local family table
    family="$(fw_family)"
    table="$(fw_forward_table)"
    nft list table "$family" "$table" >/dev/null 2>&1
}

fw_accounting_table_exists() {
    local family table
    family="$(fw_family)"
    table="$(fw_table)"
    nft list table "$family" "$table" >/dev/null 2>&1
}

fw_validate_render_file() {
    local render_file="$1"
    local validate_table validate_file table family
    family="$(fw_family)"
    table="$(fw_forward_table)"
    validate_table="pfwd_validate_$$"
    validate_file="$(mktemp "${render_file}.validate.XXXXXX")"
    sed "s/^table $family $table /table $family $validate_table /" "$render_file" > "$validate_file"
    nft -c -f "$validate_file" >/dev/null 2>&1
    rm -f "$validate_file"
}

fw_render_runtime_to_stdout() {
    local runtime_json="$1"
    local table family
    family="$(fw_family)"
    table="$(fw_forward_table)"

    if [ "$(jq '.rules | length' <<< "$runtime_json")" = "0" ]; then
        return 0
    fi

    declare -A prerouting_ports=()
    declare -A prerouting_seen=()
    declare -A postrouting_keys=()
    declare -A forward_keys=()
    declare -A subchains=()
    local line id user_id listen_ip listen_port proto remote_input resolved_target remote_port ipver comment snat_mode snat_source mss_mode mss_value key

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        IFS=$'\t' read -r id user_id listen_ip listen_port proto remote_input resolved_target remote_port ipver comment snat_mode snat_source mss_mode mss_value _traffic_mode _traffic_ratio _rule_limit _user_limit <<< "$line"
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
    done < <(fw_runtime_rule_rows "$runtime_json")

    echo "table $family $table {"
    echo "    chain prerouting {"
    echo "        type nat hook prerouting priority dstnat; policy accept;"
    for ipver in 4 6; do
        for proto in tcp udp; do
            [ -n "${subchains["prerouting|$ipver|$proto"]:-}" ] || continue
            echo "        $(fw_dispatch_tokens "$proto" "$ipver") jump $(fw_subchain_name prerouting "$proto" "$ipver")"
        done
    done
    echo "    }"
    echo

    echo "    chain postrouting {"
    echo "        type nat hook postrouting priority srcnat; policy accept;"
    for ipver in 4 6; do
        for proto in tcp udp; do
            [ -n "${subchains["postrouting|$ipver|$proto"]:-}" ] || continue
            echo "        ct status dnat $(fw_dispatch_tokens "$proto" "$ipver") jump $(fw_subchain_name postrouting "$proto" "$ipver")"
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
            echo "        $(fw_dispatch_tokens "$proto" "$ipver") jump $(fw_subchain_name forward "$proto" "$ipver")"
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
            echo "    chain $(fw_subchain_name prerouting "$proto" "$ipver") {"
            while IFS= read -r key; do
                [ -n "$key" ] || continue
                IFS='|' read -r key_proto key_ipver key_target key_remote_port key_snat_mode key_snat_source key_mss_mode key_mss_value <<< "$key"
                [ "$key_proto" = "$proto" ] || continue
                [ "$key_ipver" = "$ipver" ] || continue
                if [ "$ipver" = "6" ]; then
                    echo "        $proto dport $(fw_ports_to_expr "${prerouting_ports[$key]}") dnat ip6 to [$key_target]:$key_remote_port"
                else
                    echo "        $proto dport $(fw_ports_to_expr "${prerouting_ports[$key]}") dnat ip to $key_target:$key_remote_port"
                fi
            done < <(printf '%s\n' "${!prerouting_ports[@]}" | sort)
            echo "    }"
            echo

            echo "    chain $(fw_subchain_name postrouting "$proto" "$ipver") {"
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

        echo "    chain $(fw_subchain_name forward tcp "$ipver") {"
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

fw_render_nft_objects() {
    local runtime_json="$1"
    local users_json stats_file
    stats_file="$PFWD_STATS_FILE"
    users_json="$(jq -c '.users // []' <<< "$runtime_json")"

    jq -r --argjson users "$users_json" --slurpfile stats "$stats_file" '
      $users[]
      | select((.traffic_limit_bytes // 0) > 0)
      | [.id, (.traffic_limit_bytes // 0), ($stats[0].users[.id].billing_used_bytes // 0)] | @tsv
    ' <<< '{}' |
    while IFS=$'\t' read -r user_id limit used; do
        [ -n "$user_id" ] || continue
        local quota_name
        quota_name="$(fw_safe_object_name user "$user_id")"
        echo "  quota $quota_name { over $limit bytes used ${used:-0} bytes }"
    done

    jq -r --slurpfile stats "$stats_file" '
      .rules | unique_by(.id)[]?
      | [
          .id,
          .user_id,
          ((.traffic_limit_bytes // 0) | tostring),
          ((.user_limit_bytes // 0) | tostring),
          ($stats[0].forwards[.id].billing_used_bytes // 0)
        ] | @tsv
    ' <<< "$runtime_json" |
    while IFS=$'\t' read -r id user_id rule_limit user_limit used; do
        [ -n "$id" ] || continue
        local in_counter out_counter user_quota
        read -r in_counter out_counter < <(fw_counter_names "$id")
        user_quota="$(fw_safe_object_name user "$user_id")"
        echo "  counter $in_counter {}"
        echo "  counter $out_counter {}"
        echo "  chain fwd_${id//-/_}_limit {"
        if [ "${user_limit:-0}" -gt 0 ]; then
            echo "    quota name $user_quota drop"
        fi
        if [ "${rule_limit:-0}" -gt 0 ]; then
            echo "    quota over $rule_limit bytes used ${used:-0} bytes drop"
        fi
        echo "    accept"
        echo "  }"
    done
}

fw_render_prerouting_count_chain() {
    local runtime_json="$1"
    echo "  chain prerouting_count {"
    echo "    type filter hook prerouting priority -10; policy accept;"
    for proto in tcp udp; do
        local entries=()
        while IFS=$'\t' read -r id port protocol; do
            [ -n "$id" ] || continue
            case "${protocol:-tcp_udp}" in
                "$proto"|tcp_udp)
                    entries+=("$port : jump fwd_${id//-/_}_in_count")
                    ;;
            esac
        done < <(jq -r '.rules[]? | [.id, (.listen_port | tostring), (.protocol // "tcp_udp")] | @tsv' <<< "$runtime_json")
        if [ "${#entries[@]}" -gt 0 ]; then
            printf '    ct status dnat ct direction original meta l4proto %s ct original proto-dst vmap { ' "$proto"
            local i
            for i in "${!entries[@]}"; do
                [ "$i" -eq 0 ] || printf ', '
                printf '%s' "${entries[$i]}"
            done
            printf ' }\n'
        fi
    done
    echo "  }"
    jq -r '.rules | unique_by(.id)[]? | [.id] | @tsv' <<< "$runtime_json" |
    while IFS=$'\t' read -r id; do
        [ -n "$id" ] || continue
        local in_counter
        read -r in_counter _ < <(fw_counter_names "$id")
        echo "  chain fwd_${id//-/_}_in_count {"
        echo "    counter name $in_counter jump fwd_${id//-/_}_limit"
        echo "  }"
    done
}

fw_render_postrouting_count_chain() {
    local runtime_json="$1"
    echo "  chain postrouting_count {"
    echo "    type filter hook postrouting priority -10; policy accept;"
    for proto in tcp udp; do
        local entries=()
        while IFS=$'\t' read -r id port protocol; do
            [ -n "$id" ] || continue
            case "${protocol:-tcp_udp}" in
                "$proto"|tcp_udp)
                    entries+=("$port : jump fwd_${id//-/_}_out_count")
                    ;;
            esac
        done < <(jq -r '.rules[]? | [.id, (.listen_port | tostring), (.protocol // "tcp_udp")] | @tsv' <<< "$runtime_json")
        if [ "${#entries[@]}" -gt 0 ]; then
            printf '    ct status dnat ct direction reply meta l4proto %s ct original proto-dst vmap { ' "$proto"
            local i
            for i in "${!entries[@]}"; do
                [ "$i" -eq 0 ] || printf ', '
                printf '%s' "${entries[$i]}"
            done
            printf ' }\n'
        fi
    done
    echo "  }"
    jq -r '.rules | unique_by(.id)[]? | [.id] | @tsv' <<< "$runtime_json" |
    while IFS=$'\t' read -r id; do
        [ -n "$id" ] || continue
        local out_counter
        read -r _ out_counter < <(fw_counter_names "$id")
        echo "  chain fwd_${id//-/_}_out_count {"
        echo "    counter name $out_counter jump fwd_${id//-/_}_limit"
        echo "  }"
    done
}

fw_render_accounting_to_stdout() {
    local runtime_json="$1"
    local family table
    family="$(fw_family)"
    table="$(fw_table)"
    echo "table $family $table {"
    fw_render_nft_objects "$runtime_json"
    fw_render_prerouting_count_chain "$runtime_json"
    fw_render_postrouting_count_chain "$runtime_json"
    echo "}"
}

fw_apply_accounting_runtime() {
    local runtime_json="$1"
    pfwd_require_cmd nft

    local tmp family table
    family="$(fw_family)"
    table="$(fw_table)"
    tmp="$(mktemp "${FW_NFT_ACCOUNTING_RENDER_FILE}.tmp.XXXXXX")"
    fw_render_accounting_to_stdout "$runtime_json" > "$tmp"
    if [ -f "$FW_NFT_ACCOUNTING_RENDER_FILE" ] && cmp -s "$tmp" "$FW_NFT_ACCOUNTING_RENDER_FILE" && fw_accounting_table_exists; then
        rm -f "$tmp"
        return 0
    fi
    if nft list table "$family" "$table" >/dev/null 2>&1; then
        pfwd_run nft delete table "$family" "$table"
    fi
    mv "$tmp" "$FW_NFT_ACCOUNTING_RENDER_FILE"
    pfwd_run nft -f "$FW_NFT_ACCOUNTING_RENDER_FILE"
}

fw_apply_nft_runtime() {
    local runtime_json="$1"
    pfwd_require_cmd nft

    if [ "$(jq '.rules | length' <<< "$runtime_json")" = "0" ]; then
        fw_delete_forward_table || true
        : > "$PFWD_FORWARDER_NFT_RENDER_FILE"
        return 0
    fi

    local tmp_render
    tmp_render="$(mktemp "${PFWD_FORWARDER_NFT_RENDER_FILE}.tmp.XXXXXX")"
    fw_render_runtime_to_stdout "$runtime_json" > "$tmp_render"
    if ! fw_validate_render_file "$tmp_render"; then
        rm -f "$tmp_render"
        pfwd_die "nft 转发配置校验失败"
    fi
    forwarder_ensure_ip_forwarding
    if fw_route_localnet_needed "$runtime_json"; then
        fw_ensure_route_localnet
    fi
    if [ -f "$PFWD_FORWARDER_NFT_RENDER_FILE" ] && fw_rule_matches_snapshot "$tmp_render" && fw_forward_table_exists; then
        rm -f "$tmp_render"
    else
        mv "$tmp_render" "$PFWD_FORWARDER_NFT_RENDER_FILE"
        fw_delete_forward_table || true
        pfwd_run nft -f "$PFWD_FORWARDER_NFT_RENDER_FILE"
    fi
}

fw_render_nft() {
    local runtime_json
    runtime_json="$(forwarder_runtime_json true)"
    runtime_json="$(runtime_backend_json "$runtime_json" nft)"
    fw_render_runtime_to_stdout "$runtime_json"
}

fw_apply_tc() {
    local rate_count iface
    rate_count="$(fw_effective_rate_count)"
    iface="$(fw_tc_interface 2>/dev/null || true)"
    if [ "$rate_count" -le 0 ]; then
        command -v tc >/dev/null 2>&1 || return 0
        [ -n "$iface" ] && fw_reset_tc_runtime "$iface"
        return 0
    fi
    pfwd_require_cmd tc
    [ -n "$iface" ] || pfwd_die "未配置 tc 网卡，且未找到默认路由网卡"
    fw_reset_tc_runtime "$iface"
    fw_ensure_ifb
    fw_render_tc | while IFS= read -r line; do
        [ -n "$line" ] || continue
        # shellcheck disable=SC2086
        pfwd_run $line
    done
    fw_write_tc_state "$iface"
}

fw_effective_rate_count() {
    jq -r '
      . as $cfg
      | [
          .forwards[]
          | . as $f
          | ($cfg.users[]? | select(.id == $f.user_id) | .limits.rate // null) as $user_rate
          | (($f.limits.rate // $user_rate) // null)
          | select(. != null)
        ]
      | length
    ' "$PFWD_CONFIG_FILE"
}

fw_render_tc() {
    config_init >/dev/null
    local rate_count
    rate_count="$(fw_effective_rate_count)"
    [ "$rate_count" -gt 0 ] || return 0

    local iface ifb_dev
    iface="$(fw_tc_interface)"
    [ -n "$iface" ] || pfwd_die "未配置 tc 网卡，且未找到默认路由网卡"
    ifb_dev="$(fw_tc_ifb_name)"

    echo "tc qdisc add dev $iface root handle 1: htb default 999 r2q 100"
    echo "tc class replace dev $iface parent 1: classid 1:999 htb rate 10000mbit ceil 10000mbit quantum 1514"
    echo "tc qdisc replace dev $iface clsact"
    echo "tc qdisc add dev $ifb_dev root handle 1: htb default 999 r2q 100"
    echo "tc class replace dev $ifb_dev parent 1: classid 1:999 htb rate 10000mbit ceil 10000mbit quantum 1514"
    echo "tc filter add dev $iface ingress pref $PFWD_TC_INGRESS_PREF matchall action mirred egress redirect dev $ifb_dev"

    local class_index=10
    fw_effective_rate_rows | while IFS=$'\t' read -r id user_id rate port protocol; do
        [ -n "$id" ] || continue
        fw_render_tc_rule_pair "$iface" "$ifb_dev" "$rate" "$port" "$protocol" "$class_index"
        class_index=$((class_index + 1))
    done
}

fw_effective_rate_rows() {
    jq -r '
      . as $cfg
      | .forwards[]
      | . as $f
      | ($cfg.users[]? | select(.id == $f.user_id) | .limits.rate // null) as $user_rate
      | (($f.limits.rate // $user_rate) // null) as $rate
      | select($rate != null)
      | [$f.id, $f.user_id, $rate, ($f.listen_port | tostring), ($f.protocol // "tcp_udp")] | @tsv
    ' "$PFWD_CONFIG_FILE"
}

fw_tc_ifb_name() {
    printf '%s\n' "$PFWD_TC_IFB_DEV"
}

fw_tc_supports_flower() {
    tc qdisc replace dev lo clsact >/dev/null 2>&1 || return 1
    tc filter add dev lo ingress pref 65534 protocol ip flower ip_proto tcp dst_port 1 action drop >/dev/null 2>&1
    local rc=$?
    tc filter del dev lo ingress pref 65534 >/dev/null 2>&1 || true
    tc qdisc del dev lo clsact >/dev/null 2>&1 || true
    [ "$rc" -eq 0 ]
}

fw_tc_state_read_iface() {
    [ -f "$PFWD_TC_STATE_FILE" ] || return 0
    awk -F= '$1=="TC_IFACE"{print $2}' "$PFWD_TC_STATE_FILE" 2>/dev/null || true
}

fw_write_tc_state() {
    local iface="$1"
    mkdir -p "$(dirname "$PFWD_TC_STATE_FILE")"
    cat > "$PFWD_TC_STATE_FILE" <<EOF
TC_IFACE=$iface
TC_IFB=$(fw_tc_ifb_name)
EOF
}

fw_clear_tc_state() {
    rm -f "$PFWD_TC_STATE_FILE"
}

fw_ensure_ifb() {
    local ifb_dev
    ifb_dev="$(fw_tc_ifb_name)"
    if command -v modprobe >/dev/null 2>&1; then
        pfwd_run modprobe ifb >/dev/null 2>&1 || true
    fi
    ip link show dev "$ifb_dev" >/dev/null 2>&1 || pfwd_run ip link add "$ifb_dev" type ifb
    pfwd_run ip link set dev "$ifb_dev" up
}

fw_remove_ifb() {
    local ifb_dev
    ifb_dev="$(fw_tc_ifb_name)"
    pfwd_run ip link set dev "$ifb_dev" down >/dev/null 2>&1 || true
    pfwd_run ip link del "$ifb_dev" type ifb >/dev/null 2>&1 || true
}

fw_render_tc_rule_pair() {
    local iface="$1"
    local ifb_dev="$2"
    local rate="$3"
    local port="$4"
    local protocol="$5"
    local class_index="$6"
    local classid="1:$class_index"

    echo "tc class replace dev $iface parent 1: classid $classid htb rate $rate ceil $rate quantum 1514"
    echo "tc class replace dev $ifb_dev parent 1: classid $classid htb rate $rate ceil $rate quantum 1514"

    case "$protocol" in
        tcp)
            fw_render_tc_filters "$iface" "$ifb_dev" "$port" tcp "$classid" "$class_index"
            ;;
        udp)
            fw_render_tc_filters "$iface" "$ifb_dev" "$port" udp "$classid" "$class_index"
            ;;
        *)
            fw_render_tc_filters "$iface" "$ifb_dev" "$port" tcp "$classid" "$class_index"
            fw_render_tc_filters "$iface" "$ifb_dev" "$port" udp "$classid" "$class_index"
            ;;
    esac
}

fw_tc_filter_pref() {
    local class_index="$1"
    local l4="$2"
    local family="$3"
    local base=$((1000 + class_index * 10))
    local offset=0
    [ "$l4" = "udp" ] && offset=$((offset + 2))
    [ "$family" = "ipv6" ] && offset=$((offset + 1))
    printf '%s\n' "$((base + offset))"
}

fw_render_tc_filters() {
    if fw_tc_supports_flower; then
        fw_render_tc_flower_filters "$@"
    else
        fw_render_tc_u32_filters "$@"
    fi
}

fw_render_tc_flower_filters() {
    local iface="$1"
    local ifb_dev="$2"
    local port="$3"
    local l4="$4"
    local classid="$5"
    local class_index="$6"
    local pref_ipv4 pref_ipv6
    pref_ipv4="$(fw_tc_filter_pref "$class_index" "$l4" ipv4)"
    pref_ipv6="$(fw_tc_filter_pref "$class_index" "$l4" ipv6)"

    echo "tc filter add dev $iface protocol ip parent 1: pref $pref_ipv4 flower ip_proto $l4 src_port $port flowid $classid"
    echo "tc filter add dev $iface protocol ipv6 parent 1: pref $pref_ipv6 flower ip_proto $l4 src_port $port flowid $classid"
    echo "tc filter add dev $ifb_dev protocol ip parent 1: pref $pref_ipv4 flower ip_proto $l4 dst_port $port flowid $classid"
    echo "tc filter add dev $ifb_dev protocol ipv6 parent 1: pref $pref_ipv6 flower ip_proto $l4 dst_port $port flowid $classid"
}

fw_render_tc_u32_filters() {
    local iface="$1"
    local ifb_dev="$2"
    local port="$3"
    local l4="$4"
    local classid="$5"
    local class_index="$6"
    local ip_proto="6"
    local pref
    [ "$l4" = "udp" ] && ip_proto="17"
    pref="$(fw_tc_filter_pref "$class_index" "$l4" ipv4)"

    echo "tc filter add dev $iface protocol ip parent 1: pref $pref u32 match ip protocol $ip_proto 0xff match ip sport $port 0xffff flowid $classid"
    echo "tc filter add dev $ifb_dev protocol ip parent 1: pref $pref u32 match ip protocol $ip_proto 0xff match ip dport $port 0xffff flowid $classid"
}

fw_reset_tc_root() {
    local iface="$1"
    [ -n "$iface" ] || return 0
    pfwd_run tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
}

fw_reset_tc_ingress() {
    local iface="$1"
    [ -n "$iface" ] || return 0
    pfwd_run tc filter del dev "$iface" ingress pref "$PFWD_TC_INGRESS_PREF" >/dev/null 2>&1 || true
}

fw_reset_tc_ifb() {
    local ifb_dev
    ifb_dev="$(fw_tc_ifb_name)"
    pfwd_run tc qdisc del dev "$ifb_dev" root >/dev/null 2>&1 || true
}

fw_reset_tc_runtime() {
    local iface="${1:-}"
    if [ -z "$iface" ]; then
        iface="$(fw_tc_state_read_iface)"
    fi
    [ -n "$iface" ] || iface="$(fw_tc_interface 2>/dev/null || true)"
    [ -n "$iface" ] && fw_reset_tc_root "$iface"
    [ -n "$iface" ] && fw_reset_tc_ingress "$iface"
    fw_reset_tc_ifb
    fw_remove_ifb
    fw_clear_tc_state
}

fw_read_nft_counters() {
    local table family
    family="$(fw_family)"
    table="$(fw_table)"
    command -v nft >/dev/null 2>&1 || return 1
    nft -j list table "$family" "$table" 2>/dev/null
}

fw_read_counters() {
    stats_init >/dev/null
    stats_usage_json
}
