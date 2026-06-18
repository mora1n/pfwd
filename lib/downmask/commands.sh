#!/usr/bin/env bash

cmd_downmask() {
    config_init >/dev/null
    local sub="${1:-status}"
    shift || true
    case "$sub" in
        status) downmask_status_json | jq '.' ;;
        policy) cmd_downmask_policy "$@" ;;
        public) cmd_downmask_public "$@" ;;
        ab-pull) cmd_downmask_ab_pull "$@" ;;
        ab-feed) cmd_downmask_ab_feed "$@" ;;
        seed) cmd_downmask_seed "$@" ;;
        help|-h|--help)
            cat <<'EOF'
用法：
  pfwd downmask status
  pfwd downmask policy [--pull-mode off|public|ab] [--min-ratio N] [--max-ratio N] [--time-window-start HH:MM|empty=all-day] [--time-window-end HH:MM|empty=all-day] [--max-jitter SEC] [--min-deficit-bytes 20MB] [--max-bytes-per-run 800MB] [--iface NAME]
  pfwd downmask public [--active-source NAME(cloudflare_dynamic|linode_tokyo_100mb|cachefly_100mb)] [--speed-limit 4M(default, bytes/s; also 32Mbps/4MB/s)]
  pfwd downmask public custom add --name NAME --kind query|range --url URL(query 用 {bytes} 占位；range 需支持 Range 请求)
  pfwd downmask public custom delete --name NAME
  pfwd downmask public custom list
  pfwd downmask public custom clear
  pfwd downmask ab-pull [--protocol tcp|udp] [--protocol-mode single|parallel] [--tcp-enabled true|false] [--udp-enabled true|false] [--remote-host HOST(IP)] [--remote-port PORT] [--local-ip IP] [--token TOKEN(openssl rand -hex 16)] [--speed-limit 4M(default, bytes/s; also 32Mbps/4MB/s)] [--timeout SEC] [--parallel-limit N] [--speed-jitter-percent 12] [--bytes-jitter-percent 18]
  pfwd downmask ab-pull targets list|add|update|delete|clear ...
  pfwd downmask ab-feed [--tcp-enabled true|false] [--udp-enabled true|false] [--bind-ip IP] [--tcp-port PORT] [--udp-port PORT] [--token TOKEN(openssl rand -hex 16)] [--seed-file PATH] [--udp-payload-bytes 1200|1.2KB]
  pfwd downmask seed generate [--path PATH] [--size 1GB]   # 推荐 256MB-4GB
EOF
            ;;
        *) pfwd_die "未知 downmask 子命令：$sub" ;;
    esac
}


cmd_downmask_policy() {
    local pull_mode="" min_ratio="" max_ratio="" tws="" twe="" jitter="" mindef="" maxrun="" iface=""
    local tws_set=0 twe_set=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --pull-mode) pull_mode="$2"; shift 2 ;;
            --min-ratio) min_ratio="$2"; shift 2 ;;
            --max-ratio) max_ratio="$2"; shift 2 ;;
            --time-window-start) tws="$2"; tws_set=1; shift 2 ;;
            --time-window-end) twe="$2"; twe_set=1; shift 2 ;;
            --max-jitter) jitter="$2"; shift 2 ;;
            --min-deficit-bytes) mindef="$2"; shift 2 ;;
            --max-bytes-per-run) maxrun="$2"; shift 2 ;;
            --iface) iface="$2"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -z "$pull_mode" ] || validate_downmask_pull_mode "$pull_mode"
    [ -z "$min_ratio" ] || validate_downmask_ratio "$min_ratio"
    [ -z "$max_ratio" ] || validate_downmask_ratio "$max_ratio"
    [ -z "$tws" ] || validate_downmask_time_window "$tws"
    [ -z "$twe" ] || validate_downmask_time_window "$twe"
    [ -z "$jitter" ] || [[ "$jitter" =~ ^[0-9]+$ ]] || pfwd_die "max-jitter 必须是非负整数"
    [ -z "$mindef" ] || mindef="$(parse_downmask_size_bytes "$mindef")"
    [ -z "$maxrun" ] || maxrun="$(parse_downmask_size_bytes "$maxrun")"
    config_update \
        --arg pull_mode "$pull_mode" \
        --arg min_ratio "$min_ratio" \
        --arg max_ratio "$max_ratio" \
        --arg tws "$tws" \
        --arg twe "$twe" \
        --argjson tws_set "$tws_set" \
        --argjson twe_set "$twe_set" \
        --arg jitter "$jitter" \
        --arg mindef "$mindef" \
        --arg maxrun "$maxrun" \
        --arg iface "$iface" '
        .settings.downmask |= (
            (if $pull_mode == "" then . else .pull_mode = $pull_mode end)
            | (if $min_ratio == "" then . else .min_ratio = ($min_ratio | tonumber) end)
            | (if $max_ratio == "" then . else .max_ratio = ($max_ratio | tonumber) end)
            | (if $tws_set == 1 then .time_window_start = $tws else . end)
            | (if $twe_set == 1 then .time_window_end = $twe else . end)
            | (if $jitter == "" then . else .max_jitter_seconds = ($jitter | tonumber) end)
            | (if $mindef == "" then . else .min_deficit_bytes = ($mindef | tonumber) end)
            | (if $maxrun == "" then . else .max_bytes_per_run = ($maxrun | tonumber) end)
            | (if $iface == "" then . else .iface = $iface end)
        )'
    echo "已更新 downmask 策略"
}


cmd_downmask_public() {
    if [ "${1:-}" = "custom" ]; then
        shift
        cmd_downmask_public_custom "$@"
        return
    fi
    local active="" speed=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --active-source) active="$2"; shift 2 ;;
            --speed-limit) speed="$2"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -z "$active" ] || validate_downmask_public_source_name "$active"
    [ -z "$speed" ] || validate_downmask_speed_limit "$speed"
    config_update \
        --arg active "$active" \
        --arg speed "$speed" '
        .settings.downmask.public |= (
            (if $active == "" then . else .active_source = $active end)
            | (if $speed == "" then . else .speed_limit = $speed end)
        )'
    echo "已更新公网拉流配置"
}


cmd_downmask_public_custom() {
    local sub="${1:-list}"
    shift || true
    case "$sub" in
        list)
            jq -r '.settings.downmask.public.custom_sources[]? | "\(.name)\t\(.kind)\t\(.url)"' "$PFWD_CONFIG_FILE"
            ;;
        clear)
            config_update '.settings.downmask.public.custom_sources = []'
            echo "已清空自定义公网源"
            ;;
        add)
            local name="" kind="" url=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --name) name="$2"; shift 2 ;;
                    --kind) kind="$2"; shift 2 ;;
                    --url) url="$2"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$name" ] && [ -n "$url" ] || pfwd_die "--name 与 --url 必填"
            case "$kind" in query|range) ;; *) pfwd_die "--kind 必须是 query 或 range" ;; esac
            config_update --arg name "$name" --arg kind "$kind" --arg url "$url" '
                .settings.downmask.public.custom_sources |=
                  ((. // []) | map(select(.name != $name)) + [{name: $name, kind: $kind, url: $url}])
            '
            echo "已添加自定义源：$name"
            ;;
        delete)
            local name=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --name) name="$2"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$name" ] || pfwd_die "--name 必填"
            config_update --arg name "$name" '
                .settings.downmask.public.custom_sources |= ((. // []) | map(select(.name != $name)))
            '
            echo "已删除自定义源：$name"
            ;;
        *) pfwd_die "用法：pfwd downmask public custom list|clear|add|delete" ;;
    esac
}


cmd_downmask_ab_pull() {
    if [ "${1:-}" = "targets" ]; then
        shift
        local sub="${1:-list}"
        shift || true
        case "$sub" in
            list)
                downmask_ab_pull_targets_list
                ;;
            clear)
                downmask_ab_pull_targets_clear
                echo "已清空 AB 拉流 B机池"
                ;;
            add|update)
                local host="" port="" local_ip="" token="" weight="" tcp_enabled="" udp_enabled=""
                while [ "$#" -gt 0 ]; do
                    case "$1" in
                        --host) host="$2"; shift 2 ;;
                        --port) port="$2"; shift 2 ;;
                        --local-ip) local_ip="$2"; shift 2 ;;
                        --token) token="$2"; shift 2 ;;
                        --weight) weight="$2"; shift 2 ;;
                        --tcp-enabled) tcp_enabled="$2"; shift 2 ;;
                        --udp-enabled) udp_enabled="$2"; shift 2 ;;
                        *) pfwd_die "未知选项：$1" ;;
                    esac
                done
                downmask_ab_pull_target_update "$host" "$port" "$token" "$local_ip" "$weight" "$tcp_enabled" "$udp_enabled"
                echo "已更新 AB 拉流 B机：$host"
                ;;
            delete)
                local host=""
                while [ "$#" -gt 0 ]; do
                    case "$1" in
                        --host) host="$2"; shift 2 ;;
                        *) pfwd_die "未知选项：$1" ;;
                    esac
                done
                downmask_ab_pull_target_delete "$host"
                echo "已删除 AB 拉流 B机：$host"
                ;;
            *)
                pfwd_die "用法：pfwd downmask ab-pull targets list|add|update|delete|clear"
                ;;
        esac
        return 0
    fi

    local protocol="" protocol_mode="" tcp_enabled="" udp_enabled="" remote_host="" remote_port="" local_ip="" token="" speed="" timeout="" parallel_limit="" speed_jitter="" bytes_jitter=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --protocol) protocol="$2"; shift 2 ;;
            --protocol-mode) protocol_mode="$2"; shift 2 ;;
            --tcp-enabled) tcp_enabled="$2"; shift 2 ;;
            --udp-enabled) udp_enabled="$2"; shift 2 ;;
            --remote-host) remote_host="$2"; shift 2 ;;
            --remote-port) remote_port="$2"; shift 2 ;;
            --local-ip) local_ip="$2"; shift 2 ;;
            --token) token="$2"; shift 2 ;;
            --speed-limit) speed="$2"; shift 2 ;;
            --timeout) timeout="$2"; shift 2 ;;
            --parallel-limit) parallel_limit="$2"; shift 2 ;;
            --speed-jitter-percent) speed_jitter="$2"; shift 2 ;;
            --bytes-jitter-percent) bytes_jitter="$2"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -z "$protocol" ] || validate_downmask_protocol "$protocol"
    [ -z "$protocol_mode" ] || validate_downmask_protocol_mode "$protocol_mode"
    [ -z "$tcp_enabled" ] || validate_bool "$tcp_enabled"
    [ -z "$udp_enabled" ] || validate_bool "$udp_enabled"
    [ -z "$remote_host" ] || validate_downmask_target_host "$remote_host"
    [ -z "$remote_port" ] || validate_port "$remote_port"
    [ -z "$local_ip" ] || validate_downmask_local_ip "$local_ip"
    [ -z "$token" ] || validate_downmask_token "$token"
    [ -z "$speed" ] || validate_downmask_speed_limit "$speed"
    [ -z "$timeout" ] || [[ "$timeout" =~ ^[0-9]+$ ]] || pfwd_die "timeout 必须是非负整数"
    [ -z "$parallel_limit" ] || validate_downmask_parallel_limit "$parallel_limit"
    [ -z "$speed_jitter" ] || validate_downmask_percent "speed-jitter-percent" "$speed_jitter"
    [ -z "$bytes_jitter" ] || validate_downmask_percent "bytes-jitter-percent" "$bytes_jitter"
    config_update \
        --arg protocol "$protocol" \
        --arg protocol_mode "$protocol_mode" \
        --arg tcp_enabled "$tcp_enabled" \
        --arg udp_enabled "$udp_enabled" \
        --arg remote_host "$remote_host" \
        --arg remote_port "$remote_port" \
        --arg local_ip "$local_ip" \
        --arg token "$token" \
        --arg speed "$speed" \
        --arg timeout "$timeout" \
        --arg parallel_limit "$parallel_limit" \
        --arg speed_jitter "$speed_jitter" \
        --arg bytes_jitter "$bytes_jitter" '
        .settings.downmask.ab_pull |= (
            (if $protocol == "" then . else .protocol = $protocol end)
            | (if $protocol_mode == "" then . else .protocol_mode = $protocol_mode end)
            | (if $tcp_enabled == "" then . else .tcp_enabled = ($tcp_enabled == "true") end)
            | (if $udp_enabled == "" then . else .udp_enabled = ($udp_enabled == "true") end)
            | (if $remote_host == "" then . else .remote_host = $remote_host end)
            | (if $remote_port == "" then . else .remote_port = ($remote_port | tonumber) end)
            | (if $local_ip == "" then . else .local_ip = $local_ip end)
            | (if $token == "" then . else .token = $token end)
            | (if $speed == "" then . else .speed_limit = $speed end)
            | (if $timeout == "" then . else .timeout_seconds = ($timeout | tonumber) end)
            | (if $parallel_limit == "" then . else .parallel_limit = ($parallel_limit | tonumber) end)
            | (if $speed_jitter == "" then . else .speed_jitter_percent = ($speed_jitter | tonumber) end)
            | (if $bytes_jitter == "" then . else .bytes_jitter_percent = ($bytes_jitter | tonumber) end)
        )'
    echo "已更新 AB 拉流配置"
}


cmd_downmask_ab_feed() {
    local tcp="" udp="" bind="" tcp_port="" udp_port="" token="" seed_file="" payload=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --tcp-enabled) tcp="$2"; shift 2 ;;
            --udp-enabled) udp="$2"; shift 2 ;;
            --bind-ip) bind="$2"; shift 2 ;;
            --tcp-port) tcp_port="$2"; shift 2 ;;
            --udp-port) udp_port="$2"; shift 2 ;;
            --token) token="$2"; shift 2 ;;
            --seed-file) seed_file="$2"; shift 2 ;;
            --udp-payload-bytes) payload="$2"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -z "$tcp" ] || validate_bool "$tcp"
    [ -z "$udp" ] || validate_bool "$udp"
    [ -z "$bind" ] || validate_downmask_bind_ip "$bind"
    [ -z "$tcp_port" ] || validate_port "$tcp_port"
    [ -z "$udp_port" ] || validate_port "$udp_port"
    if [ -n "$payload" ]; then
        payload="$(parse_downmask_size_bytes "$payload")"
        validate_downmask_udp_payload_bytes "$payload"
    fi

    local cur_tcp cur_udp cur_tcp_port cur_udp_port cur_token
    cur_tcp="$(downmask_config_get '.ab_feed.tcp_enabled')"
    cur_udp="$(downmask_config_get '.ab_feed.udp_enabled')"
    cur_tcp_port="$(downmask_config_get '.ab_feed.tcp_port')"
    cur_udp_port="$(downmask_config_get '.ab_feed.udp_port')"
    cur_token="$(downmask_config_get '.ab_feed.token')"
    local eff_tcp eff_udp eff_tcp_port eff_udp_port eff_token
    eff_tcp="${tcp:-$cur_tcp}"
    eff_udp="${udp:-$cur_udp}"
    eff_tcp_port="${tcp_port:-$cur_tcp_port}"
    eff_udp_port="${udp_port:-$cur_udp_port}"
    eff_token="${token:-$cur_token}"

    if [ "$eff_tcp" = "true" ] && { [ -z "$eff_tcp_port" ] || [ "$eff_tcp_port" = "0" ]; }; then
        pfwd_die "启用 TCP 喂流必须设置有效的 --tcp-port"
    fi
    if [ "$eff_udp" = "true" ] && { [ -z "$eff_udp_port" ] || [ "$eff_udp_port" = "0" ]; }; then
        pfwd_die "启用 UDP 喂流必须设置有效的 --udp-port"
    fi

    if [ "$eff_tcp" = "true" ] || [ "$eff_udp" = "true" ]; then
        if [ -z "$eff_token" ]; then
            pfwd_die "启用 ab-feed 必须设置 --token"
        fi
    fi

    config_update \
        --arg tcp "$tcp" \
        --arg udp "$udp" \
        --arg bind "$bind" \
        --arg tcp_port "$tcp_port" \
        --arg udp_port "$udp_port" \
        --arg token "$token" \
        --arg seed_file "$seed_file" \
        --arg payload "$payload" '
        .settings.downmask.ab_feed |= (
            (if $tcp == "" then . else .tcp_enabled = ($tcp == "true") end)
            | (if $udp == "" then . else .udp_enabled = ($udp == "true") end)
            | (if $bind == "" then . else .bind_ip = $bind end)
            | (if $tcp_port == "" then . else .tcp_port = ($tcp_port | tonumber) end)
            | (if $udp_port == "" then . else .udp_port = ($udp_port | tonumber) end)
            | (if $token == "" then . else .token = $token end)
            | (if $seed_file == "" then . else .seed_file = $seed_file end)
            | (if $payload == "" then . else .udp_payload_bytes = ($payload | tonumber) end)
        )'
    downmask_reload_feed_service
    echo "已更新 AB 喂流配置"
}


cmd_downmask_seed() {
    local sub="${1:-generate}"
    shift || true
    [ "$sub" = "generate" ] || pfwd_die "用法：pfwd downmask seed generate [--path PATH] [--size 1GB]"
    local path="" size=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --path) path="$2"; shift 2 ;;
            --size) size="$2"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -x "$PFWD_DOWNMASK_BIN_PATH" ] || pfwd_die "pfwd-downmask 二进制不存在：$PFWD_DOWNMASK_BIN_PATH"
    [ -z "$size" ] || size="$(parse_downmask_size_bytes "$size")"
    local args=("seed" "generate")
    [ -z "$path" ] || args+=("--path" "$path")
    [ -z "$size" ] || args+=("--size" "$size")
    "$PFWD_DOWNMASK_BIN_PATH" "${args[@]}"
}
