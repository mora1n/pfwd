#!/usr/bin/env bash

fw_tc_interface() {
    local iface
    iface="$(jq -r '.settings.tc_interface // .settings.xdp.interface // ""' "$PFWD_CONFIG_FILE")"
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
