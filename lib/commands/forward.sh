#!/usr/bin/env bash

cmd_format_remote() {
    local host="$1"
    local port="$2"
    if [[ "$host" == *:* ]]; then
        printf '[%s]:%s' "$host" "$port"
    else
        printf '%s:%s' "$host" "$port"
    fi
}


cmd_protocol_label() {
    case "${1:-tcp_udp}" in
        tcp) printf 'TCP' ;;
        udp) printf 'UDP' ;;
        *) printf 'TCP+UDP' ;;
    esac
}


cmd_forward_state_label() {
    local enabled="$1"
    local stop_at="${2:-}"
    if [ "$enabled" = "true" ]; then
        printf '启用'
        return 0
    fi
    if pfwd_stop_at_expired "$stop_at"; then
        printf '停止'
        return 0
    fi
    printf '停用'
}


cmd_add() {
    local user_id="" remote="" listen_ip="" listen_port="" random_range="" stop_at="" protocol="tcp_udp" traffic_mode="two-way"
    local traffic_ratio="1.0" comment="" mss_mode="" mss_value="" snat_mode="masquerade" snat_source=""
    local stop_at_explicit="false" traffic_mode_explicit="false"
    config_init >/dev/null
    listen_ip="$(jq -r '.settings.default_listen_ip // "::"' "$PFWD_CONFIG_FILE")"

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            --remote) remote="${2:-}"; shift 2 ;;
            --listen-ip) listen_ip="${2:-}"; shift 2 ;;
            --listen-port) listen_port="${2:-}"; shift 2 ;;
            --random-port) random_range="${2:-}"; shift 2 ;;
            --stop-at) stop_at="${2:-}"; stop_at_explicit="true"; shift 2 ;;
            --protocol) protocol="${2:-}"; shift 2 ;;
            --traffic-mode) traffic_mode="${2:-}"; traffic_mode_explicit="true"; shift 2 ;;
            --traffic-ratio) traffic_ratio="${2:-}"; shift 2 ;;
            --comment) comment="${2:-}"; shift 2 ;;
            --mss-clamp) mss_mode="clamp"; mss_value=""; shift ;;
            --mss) mss_mode="set"; mss_value="${2:-}"; shift 2 ;;
            --snat-source) snat_mode="snat"; snat_source="${2:-}"; shift 2 ;;
            --masquerade) snat_mode="masquerade"; snat_source=""; shift ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done

    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    [ -n "$remote" ] || pfwd_die "必须提供 --remote"

    local user_defaults default_rate="" default_stop_at="" default_traffic_mode=""
    user_defaults="$(config_user_forward_defaults_json "$user_id")"
    default_rate="$(jq -r '.rate // ""' <<< "$user_defaults")"
    default_stop_at="$(jq -r '.stop_at // ""' <<< "$user_defaults")"
    default_traffic_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$user_defaults")"

    if [ "$traffic_mode_explicit" != "true" ] && [ -n "$default_traffic_mode" ]; then
        traffic_mode="$default_traffic_mode"
    fi
    if [ "$stop_at_explicit" = "true" ] && [ "$stop_at" = "-" ]; then
        stop_at=""
    elif [ "$stop_at_explicit" != "true" ] && [ -n "$default_stop_at" ]; then
        stop_at="$default_stop_at"
    fi

    local parsed remote_host remote_ports listen_ports reserved="" port forward_ids count
    parsed="$(parse_host_port_spec "$remote")"
    remote_host="${parsed%	*}"
    remote_ports="$(expand_port_spec "${parsed##*	}")"

    if [ -z "$listen_port" ]; then
        [ -n "$random_range" ] || pfwd_die "必须提供 --listen-port 或 --random-port"
        validate_port_range "$random_range"
        listen_ports=""
        while IFS= read -r port; do
            [ -n "$port" ] || continue
            local picked
            picked="$(pfwd_pick_random_port "$random_range" "$reserved")"
            reserved="$reserved $picked"
            listen_ports="${listen_ports}${picked}"$'\n'
        done <<< "$remote_ports"
        listen_ports="${listen_ports%$'\n'}"
    else
        listen_ports="$(expand_port_spec "$listen_port")"
    fi

    forward_ids="$(config_add_forward_batch "$user_id" "$listen_ip" "$listen_ports" "$remote_host" "$remote_ports" "$stop_at" "$traffic_mode" "$protocol" "$traffic_ratio" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$default_rate")"
    count="$(printf '%s\n' "$forward_ids" | sed '/^$/d' | wc -l | tr -d ' ')"
    echo "转发已添加：$count 条"
    printf '%s\n' "$forward_ids" | sed '/^$/d' | sed 's/^/  /'
    stats_rollup_current
    cmd_apply_forwarding_bundle
}


cmd_list() {
    local user_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    config_init >/dev/null
    if [ -n "$user_id" ]; then
        jq -r --arg id "$user_id" '
          def hostport($host; $port):
            if ($host | contains(":")) then "[" + $host + "]:" + ($port | tostring)
            else $host + ":" + ($port | tostring)
            end;
          .forwards[]?
          | select(.user_id == $id)
          | (.net.snat_source // "") as $snat_source
          | [.id,.user_id,.enabled,.listen_port,hostport(.remote_host; .remote_port),(.protocol // "tcp_udp"),(.stop_at // "-"),.traffic_mode,((.traffic_ratio // 1) | tostring),(.net.mss_mode // "-"),(if $snat_source == "" then (.net.snat_mode // "masquerade") else $snat_source end)]
          | @tsv
        ' "$PFWD_CONFIG_FILE"
    else
        jq -r '
          def hostport($host; $port):
            if ($host | contains(":")) then "[" + $host + "]:" + ($port | tostring)
            else $host + ":" + ($port | tostring)
            end;
          .forwards[]?
          | (.net.snat_source // "") as $snat_source
          | [.id,.user_id,.enabled,.listen_port,hostport(.remote_host; .remote_port),(.protocol // "tcp_udp"),(.stop_at // "-"),.traffic_mode,((.traffic_ratio // 1) | tostring),(.net.mss_mode // "-"),(if $snat_source == "" then (.net.snat_mode // "masquerade") else $snat_source end)]
          | @tsv
        ' "$PFWD_CONFIG_FILE"
    fi
}


cmd_toggle_forward() {
    local enabled="$1"
    shift
    [ "$#" -eq 1 ] || pfwd_die "用法：pfwd start|stop <forward_id>"
    config_set_forward_enabled "$1" "$enabled"
    echo "转发状态已更新：$1 enabled=$enabled"
    stats_rollup_current
    cmd_apply_forwarding_bundle
}


cmd_delete() {
    [ "$#" -eq 1 ] || pfwd_die "用法：pfwd delete <forward_id>"
    config_delete_forward "$1"
    echo "转发已删除：$1"
    stats_rollup_current
    cmd_apply_forwarding_bundle
}


cmd_expire() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        set)
            local id="${1:-}" stop_at=""
            shift || true
            [ -n "$id" ] || pfwd_die "必须提供转发 id"
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --stop-at) stop_at="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$stop_at" ] || pfwd_die "必须提供 --stop-at"
            config_set_forward_expire "$id" "$stop_at"
            stop_at="$(jq -r --arg id "$id" '.forwards[] | select(.id == $id) | .stop_at' "$PFWD_CONFIG_FILE")"
            echo "转发到期时间已更新：$id stop_at=$stop_at"
            stats_rollup_current
            cmd_apply_forwarding_bundle
            ;;
        clear)
            local id="${1:-}"
            [ -n "$id" ] || pfwd_die "必须提供转发 id"
            config_clear_forward_expire "$id"
            echo "转发到期时间已清空：$id"
            stats_rollup_current
            cmd_apply_forwarding_bundle
            ;;
        user-set)
            local user_id="" stop_at=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --user-id) user_id="${2:-}"; shift 2 ;;
                    --stop-at) stop_at="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
            [ -n "$stop_at" ] || pfwd_die "必须提供 --stop-at"
            config_set_user_forwards_expire "$user_id" "$stop_at"
            echo "用户全部转发到期时间已更新：$(normalize_user_id "$user_id")"
            stats_rollup_current
            cmd_apply_forwarding_bundle
            ;;
        user-clear)
            local user_id=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --user-id) user_id="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
            config_clear_user_forwards_expire "$user_id"
            echo "用户全部转发到期时间已清空：$(normalize_user_id "$user_id")"
            stats_rollup_current
            cmd_apply_forwarding_bundle
            ;;
        *)
            pfwd_die "用法：pfwd expire set|clear|user-set|user-clear"
            ;;
    esac
}


cmd_limit() {
    local sub="${1:-}"
    shift || true
    [ "$sub" = "set" ] || pfwd_die "用法：pfwd limit set --forward-id ID|--user-id ID"
    local forward_id="" user_id="" traffic="" rate="" mode=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --forward-id) forward_id="${2:-}"; shift 2 ;;
            --user-id) user_id="${2:-}"; shift 2 ;;
            --traffic) traffic="${2:-}"; shift 2 ;;
            --rate) rate="${2:-}"; shift 2 ;;
            --traffic-mode) mode="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    local traffic_bytes="__KEEP__" normalized_rate="__KEEP__"
    [ -z "$traffic" ] || traffic_bytes="$(parse_size_bytes "$traffic")"
    [ -z "$rate" ] || normalized_rate="$(normalize_rate "$rate")"
    if [ -n "$forward_id" ] && [ -z "$user_id" ]; then
        stats_rollup_current
        if [ -n "$mode" ]; then
            cmd_rollup_before_traffic_semantics_change
        fi
        config_set_forward_limit "$forward_id" "$traffic_bytes" "$normalized_rate" "$mode"
        echo "转发限制已更新：$forward_id"
        cmd_apply_firewall_tc_runtime
    elif [ -n "$user_id" ] && [ -z "$forward_id" ]; then
        stats_rollup_current
        config_set_user_limit "$user_id" "$traffic_bytes" "$normalized_rate" "$mode"
        echo "用户限制已更新：$user_id"
        cmd_apply_firewall_tc_runtime
    else
        pfwd_die "只能设置 --forward-id 或 --user-id 其中一个"
    fi
}


cmd_forward() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        update) cmd_forward_update "$@" ;;
        *) pfwd_die "用法：pfwd forward update --forward-id ID [--listen-ip IP] [--listen-port PORT] [--remote-host HOST] [--remote-port PORT] [--stop-at YYYYMMDD[ HH:MM]|YYYY-MM-DD[ HH:MM]|YYYY/MM/DD[ HH:MM]|+7|7d|--clear-stop-at] [--protocol tcp|udp|tcp_udp] [--traffic-mode one-way|two-way] [--traffic-ratio 1.0] [--comment TEXT|--clear-comment] [--mss-clamp|--mss VALUE|--clear-mss] [--masquerade|--snat-source IP]" ;;
    esac
}


cmd_forward_update() {
    local forward_id=""
    local before current_comment current_listen_ip current_listen_port current_remote_host current_remote_port current_stop_at current_protocol current_traffic_mode current_traffic_ratio current_mss_mode current_mss_value current_snat_mode current_snat_source
    local after updated_comment updated_listen_ip updated_listen_port updated_remote_host updated_remote_port updated_stop_at updated_protocol updated_traffic_mode updated_traffic_ratio updated_mss_mode updated_mss_value updated_snat_mode updated_snat_source
    local changed_forwarding="false" changed_stats="false" changed_comment="false"
    local listen_ip="__KEEP__" listen_port="__KEEP__" remote_host="__KEEP__" remote_port="__KEEP__"
    local stop_at="__KEEP__" protocol="__KEEP__" traffic_mode="__KEEP__"
    local traffic_ratio="__KEEP__" comment="__KEEP__" mss_mode="__KEEP__" mss_value="__KEEP__" snat_mode="__KEEP__" snat_source="__KEEP__"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --forward-id) forward_id="${2:-}"; shift 2 ;;
            --listen-ip) listen_ip="${2:-}"; shift 2 ;;
            --listen-port) listen_port="${2:-}"; shift 2 ;;
            --remote-host) remote_host="${2:-}"; shift 2 ;;
            --remote-port) remote_port="${2:-}"; shift 2 ;;
            --stop-at) stop_at="${2:-}"; shift 2 ;;
            --clear-stop-at) stop_at="__CLEAR__"; shift ;;
            --protocol) protocol="${2:-}"; shift 2 ;;
            --traffic-mode) traffic_mode="${2:-}"; shift 2 ;;
            --traffic-ratio) traffic_ratio="${2:-}"; shift 2 ;;
            --comment) comment="${2:-}"; shift 2 ;;
            --clear-comment) comment="__CLEAR__"; shift ;;
            --mss-clamp) mss_mode="clamp"; mss_value="__CLEAR__"; shift ;;
            --mss) mss_mode="set"; mss_value="${2:-}"; shift 2 ;;
            --clear-mss) mss_mode="__CLEAR__"; mss_value="__CLEAR__"; shift ;;
            --snat-source) snat_mode="snat"; snat_source="${2:-}"; shift 2 ;;
            --masquerade) snat_mode="masquerade"; snat_source="__CLEAR__"; shift ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -n "$forward_id" ] || pfwd_die "必须提供 --forward-id"
    before="$(jq -c --arg id "$forward_id" '.forwards[] | select(.id == $id)' "$PFWD_CONFIG_FILE")"
    current_comment="$(jq -r '.comment // ""' <<< "$before")"
    current_listen_ip="$(jq -r '.listen_ip // ""' <<< "$before")"
    current_listen_port="$(jq -r '.listen_port | tostring' <<< "$before")"
    current_remote_host="$(jq -r '.remote_host' <<< "$before")"
    current_remote_port="$(jq -r '.remote_port | tostring' <<< "$before")"
    current_stop_at="$(jq -r '.stop_at // ""' <<< "$before")"
    current_protocol="$(jq -r '.protocol // "tcp_udp"' <<< "$before")"
    current_traffic_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$before")"
    current_traffic_ratio="$(jq -r '(.traffic_ratio // 1) | tostring' <<< "$before")"
    current_mss_mode="$(jq -r '.net.mss_mode // ""' <<< "$before")"
    current_mss_value="$(jq -r 'if (.net.mss_value // null) == null then "" else (.net.mss_value | tostring) end' <<< "$before")"
    current_snat_mode="$(jq -r '.net.snat_mode // "masquerade"' <<< "$before")"
    current_snat_source="$(jq -r '.net.snat_source // ""' <<< "$before")"
    if [ "$traffic_mode" != "__KEEP__" ] || [ "$traffic_ratio" != "__KEEP__" ]; then
        cmd_rollup_before_traffic_semantics_change
    fi
    config_update_forward "$forward_id" "$listen_ip" "$listen_port" "$remote_host" "$remote_port" "$stop_at" "$protocol" "$traffic_mode" "$traffic_ratio" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source"
    after="$(jq -c --arg id "$forward_id" '.forwards[] | select(.id == $id)' "$PFWD_CONFIG_FILE")"
    updated_comment="$(jq -r '.comment // ""' <<< "$after")"
    updated_listen_ip="$(jq -r '.listen_ip // ""' <<< "$after")"
    updated_listen_port="$(jq -r '.listen_port | tostring' <<< "$after")"
    updated_remote_host="$(jq -r '.remote_host' <<< "$after")"
    updated_remote_port="$(jq -r '.remote_port | tostring' <<< "$after")"
    updated_stop_at="$(jq -r '.stop_at // ""' <<< "$after")"
    updated_protocol="$(jq -r '.protocol // "tcp_udp"' <<< "$after")"
    updated_traffic_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$after")"
    updated_traffic_ratio="$(jq -r '(.traffic_ratio // 1) | tostring' <<< "$after")"
    updated_mss_mode="$(jq -r '.net.mss_mode // ""' <<< "$after")"
    updated_mss_value="$(jq -r 'if (.net.mss_value // null) == null then "" else (.net.mss_value | tostring) end' <<< "$after")"
    updated_snat_mode="$(jq -r '.net.snat_mode // "masquerade"' <<< "$after")"
    updated_snat_source="$(jq -r '.net.snat_source // ""' <<< "$after")"
    if [ "$current_comment" != "$updated_comment" ]; then
        changed_comment="true"
    fi
    if [ "$current_traffic_mode" != "$updated_traffic_mode" ] || [ "$current_traffic_ratio" != "$updated_traffic_ratio" ]; then
        changed_stats="true"
    fi
    if [ "$current_listen_ip" != "$updated_listen_ip" ] || [ "$current_listen_port" != "$updated_listen_port" ] || [ "$current_remote_host" != "$updated_remote_host" ] || [ "$current_remote_port" != "$updated_remote_port" ] || [ "$current_stop_at" != "$updated_stop_at" ] || [ "$current_protocol" != "$updated_protocol" ] || [ "$current_mss_mode" != "$updated_mss_mode" ] || [ "$current_mss_value" != "$updated_mss_value" ] || [ "$current_snat_mode" != "$updated_snat_mode" ] || [ "$current_snat_source" != "$updated_snat_source" ]; then
        changed_forwarding="true"
    fi
    echo "转发已更新：$forward_id"
    if [ "$changed_forwarding" = "true" ]; then
        stats_rollup_current
        cmd_apply_forwarding_bundle
    elif [ "$changed_stats" = "true" ]; then
        cmd_apply_firewall_runtime
    elif [ "$changed_comment" = "true" ]; then
        :
    fi
}


cmd_user_forwards_traffic_mode() {
    local user_id="" traffic_mode=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            --traffic-mode) traffic_mode="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    [ -n "$traffic_mode" ] || pfwd_die "必须提供 --traffic-mode"
    cmd_rollup_before_traffic_semantics_change
    config_set_user_forwards_traffic_mode "$user_id" "$traffic_mode"
    echo "用户全部转发流量模式已更新：$(normalize_user_id "$user_id") mode=$traffic_mode"
    cmd_apply_firewall_runtime
}


cmd_user_forwards_limit() {
    local user_id="" traffic="__KEEP__" rate="__KEEP__" mode="__KEEP__"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            --traffic) traffic="${2:-}"; shift 2 ;;
            --rate) rate="${2:-}"; shift 2 ;;
            --traffic-mode) mode="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    user_id="$(normalize_user_id "$user_id")"
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"

    local traffic_bytes="__KEEP__" normalized_rate="__KEEP__"
    [ "$traffic" = "__KEEP__" ] || traffic_bytes="$(parse_size_bytes "$traffic")"
    [ "$rate" = "__KEEP__" ] || normalized_rate="$(normalize_rate "$rate")"

    if [ "$mode" != "__KEEP__" ]; then
        cmd_rollup_before_traffic_semantics_change
    fi
    config_set_user_forward_limits "$user_id" "$traffic_bytes" "$normalized_rate" "$mode"
    echo "用户全部转发限制已更新：$user_id"
    stats_rollup_current
    cmd_apply_firewall_tc_runtime
}


cmd_traffic() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        used)
            local scope="${1:-}"
            shift || true
            [ "$scope" = "set" ] || pfwd_die "用法：pfwd traffic used set --user-id ID|--forward-id ID --used 100GB"
            local user_id="" forward_id="" used=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --user-id) user_id="${2:-}"; shift 2 ;;
                    --forward-id) forward_id="${2:-}"; shift 2 ;;
                    --used) used="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$used" ] || pfwd_die "必须提供 --used"
            local used_bytes
            used_bytes="$(parse_size_bytes "$used")"
            if [ -n "$user_id" ] && [ -z "$forward_id" ]; then
                stats_set_user_used "$user_id" "$used_bytes"
                echo "用户已用流量已更新：$(normalize_user_id "$user_id")"
            elif [ -n "$forward_id" ] && [ -z "$user_id" ]; then
                stats_set_forward_used "$forward_id" "$used_bytes"
                echo "转发已用流量已更新：$forward_id"
            else
                pfwd_die "只能设置 --user-id 或 --forward-id 其中一个"
            fi
            cmd_apply_firewall_runtime
            ;;
        reset-day)
            local scope="${1:-}"
            shift || true
            [ "$scope" = "set" ] || pfwd_die "用法：pfwd traffic reset-day set --user-id ID|--forward-id ID --day 0|15|15T09:30|'15 09:30'"
            local user_id="" forward_id="" day=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --user-id) user_id="${2:-}"; shift 2 ;;
                    --forward-id) forward_id="${2:-}"; shift 2 ;;
                    --day) day="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$day" ] || pfwd_die "必须提供 --day"
            if [ -n "$user_id" ] && [ -z "$forward_id" ]; then
                stats_set_user_reset_day "$user_id" "$day"
                echo "用户流量重置日已更新：$(normalize_user_id "$user_id") day=$day"
            elif [ -n "$forward_id" ] && [ -z "$user_id" ]; then
                stats_set_forward_reset_day "$forward_id" "$day"
                echo "转发流量重置日已更新：$forward_id day=$day"
            else
                pfwd_die "只能设置 --user-id 或 --forward-id 其中一个"
            fi
            ;;
        reset-now)
            local user_id="" forward_id=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --user-id) user_id="${2:-}"; shift 2 ;;
                    --forward-id) forward_id="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            if [ -n "$user_id" ] && [ -z "$forward_id" ]; then
                stats_reset_user_cycle "$user_id"
                echo "用户流量已重置：$(normalize_user_id "$user_id")"
            elif [ -n "$forward_id" ] && [ -z "$user_id" ]; then
                stats_reset_forward_cycle "$forward_id"
                echo "转发流量已重置：$forward_id"
            else
                pfwd_die "只能设置 --user-id 或 --forward-id 其中一个"
            fi
            cmd_apply_firewall_runtime
            ;;
        *) pfwd_die "用法：pfwd traffic used|reset-day|reset-now" ;;
    esac
}


stats_json() {
    local user_id="$1"
    local forward_id="$2"
    local counters
    counters="$(stats_usage_json)"
    jq --arg user "$user_id" --arg fwd "$forward_id" '
      .forwards |= map(select(($user == "" or .user_id == $user) and ($fwd == "" or .id == $fwd)))
      | .total_bytes = ([.forwards[].total_bytes] | add // 0)
    ' <<< "$counters"
}


cmd_stats() {
    local user_id="" forward_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            --forward-id) forward_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    stats_json "$user_id" "$forward_id" | jq '.'
}
