#!/usr/bin/env bash

fw_table() {
    jq -r '.settings.nft_table // "pfwd"' "$PFWD_CONFIG_FILE"
}

fw_family() {
    jq -r '.settings.nft_family // "inet"' "$PFWD_CONFIG_FILE"
}

fw_tc_interface() {
    local iface
    iface="$(jq -r '.settings.tc_interface // ""' "$PFWD_CONFIG_FILE")"
    if [ -n "$iface" ]; then
        echo "$iface"
        return
    fi
    ip route show default 2>/dev/null | awk '{print $5; exit}'
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

fw_active_forwards_tsv() {
    local fields="$1"
    local extra_filter="${2:-true}"
    local today
    today="$(pfwd_today)"
    jq -r --arg today "$today" --argjson fields "$fields" --arg extra "$extra_filter" '
      .forwards[]
      | select(.enabled == true and (.stop_at == null or .stop_at > $today))
      | select(if $extra == "two-way" then .traffic_mode == "two-way" else true end)
      | [.[ $fields[] ]] | @tsv
    ' "$PFWD_CONFIG_FILE"
}

fw_render_nft_objects() {
    local today
    today="$(pfwd_today)"
    stats_init >/dev/null
    jq -r --arg today "$today" --slurpfile stats "$PFWD_STATS_FILE" '
      .users[]?
      | select((.limits.traffic_bytes // null) != null)
      | [.id, (.limits.traffic_bytes // "null"), ($stats[0].users[.id].billing_used_bytes // 0)] | @tsv
    ' "$PFWD_CONFIG_FILE" |
    while IFS=$'\t' read -r user_id limit used; do
        local quota_name
        quota_name="$(fw_safe_object_name user "$user_id")"
        echo "  quota $quota_name { over $limit bytes used ${used:-0} bytes }"
    done

    jq -r --arg today "$today" --slurpfile stats "$PFWD_STATS_FILE" '
      . as $cfg
      | .forwards[]
      | select(.enabled == true and (.stop_at == null or .stop_at > $today))
      | . as $f
      | ($cfg.users[]? | select(.id == $f.user_id) | (.limits.traffic_bytes // "null")) as $user_limit
      | [
          $f.id,
          $f.user_id,
          ($f.listen_port | tostring),
          ($f.limits.traffic_bytes // "null"),
          ($stats[0].forwards[$f.id].billing_used_bytes // 0),
          ($user_limit // "null")
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE" |
    while IFS=$'\t' read -r id user_id _ limit used user_limit; do
        local in_counter out_counter user_quota
        read -r in_counter out_counter < <(fw_counter_names "$id")
        user_quota="$(fw_safe_object_name user "$user_id")"
        limit="${limit:-null}"
        echo "  counter $in_counter {}"
        echo "  counter $out_counter {}"
        echo "  chain fwd_${id//-/_}_limit {"
        if [ "$user_limit" != "null" ] && [ -n "$user_limit" ]; then
            echo "    quota name $user_quota drop"
        fi
        if [ "$limit" != "null" ] && [ -n "$limit" ]; then
            echo "    quota over $limit bytes used ${used:-0} bytes drop"
        fi
        echo "    accept"
        echo "  }"
    done
}

fw_render_prerouting_chain() {
    echo "  chain prerouting_count {"
    echo "    type filter hook prerouting priority -10; policy accept;"
    fw_active_forwards_tsv '["id","listen_port","protocol"]' |
    while IFS=$'\t' read -r id port protocol; do
        local in_counter
        read -r in_counter _ < <(fw_counter_names "$id")
        case "${protocol:-tcp_udp}" in
            tcp)
                echo "    ct status dnat ct direction original meta l4proto tcp ct original proto-dst $port counter name $in_counter jump fwd_${id//-/_}_limit"
                ;;
            udp)
                echo "    ct status dnat ct direction original meta l4proto udp ct original proto-dst $port counter name $in_counter jump fwd_${id//-/_}_limit"
                ;;
            *)
                echo "    ct status dnat ct direction original meta l4proto tcp ct original proto-dst $port counter name $in_counter jump fwd_${id//-/_}_limit"
                echo "    ct status dnat ct direction original meta l4proto udp ct original proto-dst $port counter name $in_counter jump fwd_${id//-/_}_limit"
                ;;
        esac
    done
    echo "  }"
}

fw_render_postrouting_chain() {
    echo "  chain postrouting_count {"
    echo "    type filter hook postrouting priority -10; policy accept;"
    fw_active_forwards_tsv '["id","listen_port","protocol"]' |
    while IFS=$'\t' read -r id port protocol; do
        local out_counter
        read -r _ out_counter < <(fw_counter_names "$id")
        case "${protocol:-tcp_udp}" in
            tcp)
                echo "    ct status dnat ct direction reply meta l4proto tcp ct original proto-dst $port counter name $out_counter jump fwd_${id//-/_}_limit"
                ;;
            udp)
                echo "    ct status dnat ct direction reply meta l4proto udp ct original proto-dst $port counter name $out_counter jump fwd_${id//-/_}_limit"
                ;;
            *)
                echo "    ct status dnat ct direction reply meta l4proto tcp ct original proto-dst $port counter name $out_counter jump fwd_${id//-/_}_limit"
                echo "    ct status dnat ct direction reply meta l4proto udp ct original proto-dst $port counter name $out_counter jump fwd_${id//-/_}_limit"
                ;;
        esac
    done
    echo "  }"
}

fw_render_nft() {
    config_init >/dev/null
    local family table
    family="$(fw_family)"
    table="$(fw_table)"

    echo "table $family $table {"
    fw_render_nft_objects
    fw_render_prerouting_chain
    fw_render_postrouting_chain
    echo "}"
}

FW_NFT_RENDER_FILE="${PFWD_RUN_DIR}/firewall.nft"

fw_apply_nft() {
    pfwd_require_cmd nft
    local tmp
    tmp="$(mktemp "$PFWD_RUN_DIR/nft.XXXXXX")"
    fw_render_nft > "$tmp"
    if [ -f "$FW_NFT_RENDER_FILE" ] && cmp -s "$tmp" "$FW_NFT_RENDER_FILE"; then
        rm -f "$tmp"
        return 0
    fi
    local family table
    family="$(fw_family)"
    table="$(fw_table)"
    if nft list table "$family" "$table" >/dev/null 2>&1; then
        pfwd_run nft delete table "$family" "$table"
    fi
    mv "$tmp" "$FW_NFT_RENDER_FILE"
    pfwd_run nft -f "$FW_NFT_RENDER_FILE"
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

    local iface
    iface="$(fw_tc_interface)"
    [ -n "$iface" ] || pfwd_die "未配置 tc 网卡，且未找到默认路由网卡"
    echo "tc qdisc add dev $iface root handle 1: htb default 999 r2q 100"
    echo "tc class add dev $iface parent 1: classid 1:999 htb rate 10000mbit ceil 10000mbit quantum 1514"

    local class_index=10
    jq -r '
      . as $cfg
      | .forwards[]
      | . as $f
      | ($cfg.users[]? | select(.id == $f.user_id) | .limits.rate // null) as $user_rate
      | (($f.limits.rate // $user_rate) // null) as $rate
      | select($rate != null)
      | [$f.id, $rate, ($f.listen_port | tostring)] | @tsv
    ' "$PFWD_CONFIG_FILE" | while IFS=$'\t' read -r id rate port; do
        echo "tc class add dev $iface parent 1: classid 1:$class_index htb rate $rate ceil $rate quantum 1514"
        echo "tc filter add dev $iface protocol ip parent 1: prio $class_index u32 match ip sport $port 0xffff flowid 1:$class_index"
        class_index=$((class_index + 1))
    done
}

fw_reset_tc_root() {
    local iface="$1"
    [ -n "$iface" ] || return 0
    pfwd_run tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
}

fw_apply_tc() {
    pfwd_require_cmd tc
    local rate_count iface
    rate_count="$(fw_effective_rate_count)"
    [ "$rate_count" -gt 0 ] || return 0
    iface="$(fw_tc_interface)"
    [ -n "$iface" ] || pfwd_die "未配置 tc 网卡，且未找到默认路由网卡"
    fw_reset_tc_root "$iface"
    fw_render_tc | while IFS= read -r line; do
        [ -n "$line" ] || continue
        # shellcheck disable=SC2086
        pfwd_run $line
    done
}

fw_read_counters() {
    stats_init >/dev/null
    stats_usage_json
}
