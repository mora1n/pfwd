#!/usr/bin/env bash

DOWNMASK_BUILTIN_SOURCES="cloudflare_dynamic cachefly_100mb digitalocean_100mb aliyun_ubuntu_iso"

downmask_config_get() {
    local subpath="$1"
    config_init >/dev/null
    jq -r ".settings.downmask$subpath // empty" "$PFWD_CONFIG_FILE"
}

downmask_config_get_raw() {
    local subpath="$1"
    config_init >/dev/null
    jq -c ".settings.downmask$subpath" "$PFWD_CONFIG_FILE"
}

downmask_iface() {
    local iface
    iface="$(downmask_config_get '.iface')"
    if [ -n "$iface" ]; then
        echo "$iface"
        return
    fi
    forwarder_iface
}

downmask_read_iface_bytes() {
    local iface="$1"
    local rx tx
    rx="$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo 0)"
    tx="$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo 0)"
    printf '%s\t%s\n' "$rx" "$tx"
}

downmask_state_file() {
    echo "$PFWD_DOWNMASK_STATE_DIR/day_state.json"
}

downmask_load_day_state() {
    local file
    file="$(downmask_state_file)"
    if [ -f "$file" ]; then
        cat "$file"
    else
        echo '{}'
    fi
}

downmask_save_day_state() {
    local payload="$1"
    local file
    file="$(downmask_state_file)"
    mkdir -p "$(dirname "$file")"
    printf '%s\n' "$payload" | jq '.' | pfwd_write_atomic "$file"
}

downmask_random_ratio() {
    local min="$1"
    local max="$2"
    awk -v min="$min" -v max="$max" -v seed="$RANDOM$$" 'BEGIN { srand(seed); printf "%.4f", min + rand() * (max - min) }'
}

downmask_in_time_window() {
    local now start end
    now="$(date '+%H:%M')"
    start="$(downmask_config_get '.time_window_start')"
    end="$(downmask_config_get '.time_window_end')"
    [ -n "$start" ] && [ -n "$end" ] || return 0
    if [[ "$start" < "$end" || "$start" == "$end" ]]; then
        [[ "$now" > "$start" || "$now" == "$start" ]] && [[ "$now" < "$end" ]]
    else
        [[ "$now" > "$start" || "$now" == "$start" ]] || [[ "$now" < "$end" ]]
    fi
}

downmask_now_epoch() {
    date '+%s'
}

downmask_random_jitter_until() {
    local max_jitter="$1"
    local base
    base="$(downmask_now_epoch)"
    [ "$max_jitter" -gt 0 ] || { echo "$base"; return; }
    local offset=$((RANDOM % max_jitter))
    echo $((base + offset))
}

downmask_public_source_url() {
    local name="$1"
    local bytes="$2"
    case "$name" in
        cloudflare_dynamic)
            printf 'query|https://speed.cloudflare.com/__down?bytes=%s\n' "$bytes"
            ;;
        cachefly_100mb)
            printf 'range|http://cachefly.cachefly.net/100mb.test\n'
            ;;
        digitalocean_100mb)
            printf 'range|https://speedtest-sgp1.digitalocean.com/100mb.test\n'
            ;;
        aliyun_ubuntu_iso)
            printf 'range|https://mirrors.aliyun.com/ubuntu-releases/24.04/ubuntu-24.04.2-desktop-amd64.iso\n'
            ;;
        *)
            return 1
            ;;
    esac
}

downmask_resolve_active_source() {
    local active bytes
    active="$(downmask_config_get '.public.active_source')"
    bytes="$1"
    [ -n "$active" ] || active="cloudflare_dynamic"
    if downmask_public_source_url "$active" "$bytes" 2>/dev/null; then
        return 0
    fi
    local custom
    custom="$(jq -r --arg name "$active" '.settings.downmask.public.custom_sources[]? | select(.name == $name) | "\(.kind)|\(.url)"' "$PFWD_CONFIG_FILE" | head -n1)"
    if [ -n "$custom" ]; then
        local kind url
        kind="${custom%%|*}"
        url="${custom#*|}"
        case "$kind" in
            query)
                printf 'query|%s\n' "${url//\{bytes\}/$bytes}"
                return 0
                ;;
            range|*)
                printf 'range|%s\n' "$url"
                return 0
                ;;
        esac
    fi
    downmask_public_source_url "cloudflare_dynamic" "$bytes"
}

downmask_pull_public() {
    local planned="$1"
    local resolved kind url speed_limit
    speed_limit="$(downmask_config_get '.public.speed_limit')"
    [ -n "$speed_limit" ] || speed_limit="4M"
    resolved="$(downmask_resolve_active_source "$planned")" || return 1
    kind="${resolved%%|*}"
    url="${resolved#*|}"
    [ -n "$url" ] || return 1
    command -v curl >/dev/null 2>&1 || { echo 0; return 0; }
    local actual=0
    case "$kind" in
        query)
            actual="$(curl -fsSL --max-time 1800 --limit-rate "$speed_limit" -o /dev/null -w '%{size_download}' "$url" 2>/dev/null || echo 0)"
            ;;
        range)
            local end=$((planned - 1))
            actual="$(curl -fsSL --max-time 1800 --limit-rate "$speed_limit" -r "0-$end" -o /dev/null -w '%{size_download}' "$url" 2>/dev/null || echo 0)"
            ;;
    esac
    [[ "$actual" =~ ^[0-9]+$ ]] || actual=0
    echo "$actual"
}

downmask_pull_ab() {
    local planned="$1"
    local protocol remote_host remote_port local_ip token speed_limit timeout
    protocol="$(downmask_config_get '.ab_pull.protocol')"
    remote_host="$(downmask_config_get '.ab_pull.remote_host')"
    remote_port="$(downmask_config_get '.ab_pull.remote_port')"
    local_ip="$(downmask_config_get '.ab_pull.local_ip')"
    token="$(downmask_config_get '.ab_pull.token')"
    speed_limit="$(downmask_config_get '.ab_pull.speed_limit')"
    timeout="$(downmask_config_get '.ab_pull.timeout_seconds')"
    [ -n "$remote_host" ] && [ -n "$remote_port" ] && [ "$remote_port" != "0" ] || return 1
    [ -n "$token" ] || return 1
    [ -x "$PFWD_DOWNMASK_BIN_PATH" ] || { echo 0; return 0; }

    local rate_bps=0
    if [ -n "$speed_limit" ]; then
        rate_bps="$(downmask_speed_to_bps "$speed_limit")"
    fi
    [ -n "$timeout" ] && [ "$timeout" -gt 0 ] || timeout=1200

    local -a cmd
    cmd=(
        "$PFWD_DOWNMASK_BIN_PATH"
        pull
        --protocol "$protocol"
        --remote-host "$remote_host"
        --remote-port "$remote_port"
        --token "$token"
        --wanted-bytes "$planned"
        --speed-limit "$rate_bps"
        --timeout "$timeout"
    )
    if [ -n "$local_ip" ]; then
        cmd+=(--local-ip "$local_ip")
    fi

    local out
    out="$("${cmd[@]}" 2>/dev/null || true)"
    local actual
    actual="$(echo "$out" | jq -r '.actual_bytes // 0' 2>/dev/null || echo 0)"
    [[ "$actual" =~ ^[0-9]+$ ]] || actual=0
    echo "$actual"
}

downmask_speed_to_bps() {
    local raw="$1"
    [[ "$raw" =~ ^([0-9]+([.][0-9]+)?)([KkMmGg]?)$ ]] || { echo 0; return; }
    local value="${BASH_REMATCH[1]}"
    local unit="${BASH_REMATCH[3]}"
    awk -v value="$value" -v unit="$unit" 'BEGIN {
        scale = 1
        if (unit == "K" || unit == "k") scale = 1024
        else if (unit == "M" || unit == "m") scale = 1024 * 1024
        else if (unit == "G" || unit == "g") scale = 1024 * 1024 * 1024
        printf "%.0f\n", value * scale
    }'
}

downmask_systemd_quote_arg() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//%/%%}"
    printf '"%s"' "$value"
}

downmask_systemd_join_exec() {
    local out="" arg
    for arg in "$@"; do
        out+=" $(downmask_systemd_quote_arg "$arg")"
    done
    printf '%s\n' "${out# }"
}

downmask_config_section() {
    local path="$1"
    jq -c "$path // {}" "$PFWD_CONFIG_FILE"
}

downmask_state_get_fields() {
    local state_json="$1"
    jq -r '[
        (.date // ""),
        (if .target_ratio == null then "" else (.target_ratio | tostring) end),
        (.rx_accum // 0),
        (.tx_accum // 0),
        (.last_rx_raw // 0),
        (.last_tx_raw // 0),
        (.next_eligible_at // 0)
    ] | @tsv' <<< "$state_json"
}

downmask_reconcile_pull() {
    config_init >/dev/null
    local downmask_cfg pull_mode iface today state
    downmask_cfg="$(downmask_config_section '.settings.downmask')"
    pull_mode="$(jq -r '.pull_mode // "off"' <<< "$downmask_cfg")"
    [ -n "$pull_mode" ] && [ "$pull_mode" != "off" ] || return 0
    iface="$(downmask_iface)"
    [ -n "$iface" ] || return 0
    [ -d "/sys/class/net/$iface" ] || return 0

    today="$(pfwd_today)"
    state="$(downmask_load_day_state)"

    local raw_rx_tx raw_rx raw_tx
    raw_rx_tx="$(downmask_read_iface_bytes "$iface")"
    raw_rx="${raw_rx_tx%%$'\t'*}"
    raw_tx="${raw_rx_tx##*$'\t'}"

    local state_fields state_date target_ratio rx_accum tx_accum last_rx last_tx next_eligible
    state_fields="$(downmask_state_get_fields "$state")"
    IFS=$'\t' read -r state_date target_ratio rx_accum tx_accum last_rx last_tx next_eligible <<< "$state_fields"

    if [ "$state_date" != "$today" ] || [ -z "$target_ratio" ]; then
        local min_r max_r
        min_r="$(jq -r '.min_ratio // 1.5' <<< "$downmask_cfg")"
        max_r="$(jq -r '.max_ratio // 2.8' <<< "$downmask_cfg")"
        target_ratio="$(downmask_random_ratio "$min_r" "$max_r")"
        rx_accum=0
        tx_accum=0
        last_rx="$raw_rx"
        last_tx="$raw_tx"
        next_eligible=0
        state_date="$today"
    else
        local delta_rx delta_tx
        if [ "$raw_rx" -ge "$last_rx" ]; then
            delta_rx=$((raw_rx - last_rx))
        else
            delta_rx="$raw_rx"
        fi
        if [ "$raw_tx" -ge "$last_tx" ]; then
            delta_tx=$((raw_tx - last_tx))
        else
            delta_tx="$raw_tx"
        fi
        rx_accum=$((rx_accum + delta_rx))
        tx_accum=$((tx_accum + delta_tx))
        last_rx="$raw_rx"
        last_tx="$raw_tx"
    fi

    local now_epoch action="skip" reason="" actual=0 planned=0
    now_epoch="$(downmask_now_epoch)"

    local commit_state
    commit_state() {
        local last_action="${1:-$action}"
        local last_actual="${2:-$actual}"
        local last_planned="${3:-$planned}"
        local last_error="${4:-$reason}"
        local payload
        payload="$(jq -n \
            --arg date "$state_date" \
            --arg iface "$iface" \
            --arg target_ratio "$target_ratio" \
            --argjson rx_accum "$rx_accum" \
            --argjson tx_accum "$tx_accum" \
            --argjson last_rx_raw "$last_rx" \
            --argjson last_tx_raw "$last_tx" \
            --argjson next_eligible_at "$next_eligible" \
            --arg last_action "$last_action" \
            --argjson last_actual "$last_actual" \
            --argjson last_planned "$last_planned" \
            --arg last_error "$last_error" \
            --arg updated_at "$(pfwd_now_iso)" '
            {
                date: $date,
                iface: $iface,
                target_ratio: ($target_ratio | tonumber),
                rx_accum: $rx_accum,
                tx_accum: $tx_accum,
                last_rx_raw: $last_rx_raw,
                last_tx_raw: $last_tx_raw,
                next_eligible_at: $next_eligible_at,
                last_action: $last_action,
                last_actual_bytes: $last_actual,
                last_planned_bytes: $last_planned,
                last_error: $last_error,
                updated_at: $updated_at
            }')"
        downmask_save_day_state "$payload"
    }

    if ! downmask_in_time_window; then
        reason="out_of_window"
        commit_state
        return 0
    fi

    if [ "$now_epoch" -lt "$next_eligible" ]; then
        reason="waiting_jitter"
        commit_state
        return 0
    fi

    local debt
    debt="$(awk -v r="$target_ratio" -v tx="$tx_accum" -v rx="$rx_accum" 'BEGIN { d = (r * tx) - rx; if (d < 0) d = 0; printf "%.0f", d }')"

    local min_deficit max_per_run
    min_deficit="$(jq -r '.min_deficit_bytes // 0' <<< "$downmask_cfg")"
    max_per_run="$(jq -r '.max_bytes_per_run // 0' <<< "$downmask_cfg")"

    if [ "$debt" -lt "$min_deficit" ]; then
        reason="below_min_deficit"
        commit_state
        return 0
    fi

    planned="$debt"
    if [ "$max_per_run" -gt 0 ] && [ "$planned" -gt "$max_per_run" ]; then
        planned="$max_per_run"
    fi

    case "$pull_mode" in
        public)
            actual="$(downmask_pull_public "$planned" 2>/dev/null || echo 0)"
            action="public"
            ;;
        ab)
            actual="$(downmask_pull_ab "$planned" 2>/dev/null || echo 0)"
            action="ab"
            ;;
        *)
            reason="invalid_pull_mode"
            commit_state
            return 0
            ;;
    esac
    [[ "$actual" =~ ^[0-9]+$ ]] || actual=0

    if [ "$actual" -eq 0 ]; then
        reason="pull_failed"
    fi

    local jitter
    jitter="$(jq -r '.max_jitter_seconds // 0' <<< "$downmask_cfg")"
    next_eligible="$(downmask_random_jitter_until "$jitter")"

    commit_state
}

downmask_feed_unit_path() {
    echo "$PFWD_SYSTEMD_DIR/pfwd-downmask-feed.service"
}

downmask_write_feed_unit_if_needed() {
    config_init >/dev/null
    local tcp_enabled udp_enabled
    tcp_enabled="$(downmask_config_get '.ab_feed.tcp_enabled')"
    udp_enabled="$(downmask_config_get '.ab_feed.udp_enabled')"
    local unit_path
    unit_path="$(downmask_feed_unit_path)"

    if [ "$tcp_enabled" != "true" ] && [ "$udp_enabled" != "true" ]; then
        rm -f "$unit_path"
        return 0
    fi

    local bind_ip tcp_port udp_port token seed_file payload max_rate
    bind_ip="$(downmask_config_get '.ab_feed.bind_ip')"
    tcp_port="$(downmask_config_get '.ab_feed.tcp_port')"
    udp_port="$(downmask_config_get '.ab_feed.udp_port')"
    token="$(downmask_config_get '.ab_feed.token')"
    seed_file="$(downmask_config_get '.ab_feed.seed_file')"
    payload="$(downmask_config_get '.ab_feed.udp_payload_bytes')"
    max_rate=0

    [ -n "$bind_ip" ] || bind_ip="0.0.0.0"
    [ -n "$payload" ] || payload=1200

    local addr_prefix
    case "$bind_ip" in
        *:*) addr_prefix="[$bind_ip]" ;;
        *)   addr_prefix="$bind_ip" ;;
    esac
    local -a exec_args
    exec_args=(
        "$PFWD_DOWNMASK_BIN_PATH"
        "serve"
        "--token" "$token"
        "--status-file" "$PFWD_DOWNMASK_STATUS_FILE"
        "--max-rate" "$max_rate"
        "--udp-payload-bytes" "$payload"
    )
    if [ -n "$seed_file" ]; then
        exec_args+=("--seed-file" "$seed_file")
    fi
    if [ "$tcp_enabled" = "true" ] && [ -n "$tcp_port" ] && [ "$tcp_port" != "0" ]; then
        exec_args+=("--tcp-addr" "$addr_prefix:$tcp_port")
    fi
    if [ "$udp_enabled" = "true" ] && [ -n "$udp_port" ] && [ "$udp_port" != "0" ]; then
        exec_args+=("--udp-addr" "$addr_prefix:$udp_port")
    fi
    local exec_line
    exec_line="$(downmask_systemd_join_exec "${exec_args[@]}")"

    mkdir -p "$PFWD_SYSTEMD_DIR" "$PFWD_DOWNMASK_STATE_DIR"
    cat > "$unit_path" <<EOF
[Unit]
Description=pfwd downmask feeder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$exec_line
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

downmask_reload_feed_service() {
    command -v systemctl >/dev/null 2>&1 || return 0
    downmask_write_feed_unit_if_needed
    pfwd_run systemctl daemon-reload
    local tcp_enabled udp_enabled
    tcp_enabled="$(downmask_config_get '.ab_feed.tcp_enabled')"
    udp_enabled="$(downmask_config_get '.ab_feed.udp_enabled')"
    if [ "$tcp_enabled" = "true" ] || [ "$udp_enabled" = "true" ]; then
        pfwd_run systemctl enable pfwd-downmask-feed.service
        pfwd_run systemctl restart pfwd-downmask-feed.service
    else
        pfwd_run systemctl stop pfwd-downmask-feed.service || true
        pfwd_run systemctl disable pfwd-downmask-feed.service || true
        rm -f "$PFWD_DOWNMASK_STATUS_FILE"
    fi
}

downmask_status_json() {
    config_init >/dev/null
    local cfg state feed
    cfg="$(jq -c '.settings.downmask // {}' "$PFWD_CONFIG_FILE")"
    state="$(downmask_load_day_state)"
    if [ -f "$PFWD_DOWNMASK_STATUS_FILE" ]; then
        feed="$(cat "$PFWD_DOWNMASK_STATUS_FILE" 2>/dev/null || echo '{}')"
    else
        feed='{}'
    fi
    jq -n \
        --argjson config "$cfg" \
        --argjson state "$state" \
        --argjson feed "$feed" '
        {
            config: $config,
            day_state: $state,
            feed: $feed
        }'
}

downmask_render_status() {
    local json pull_mode iface ratio rx tx debt action feed_tcp feed_udp
    json="$(downmask_status_json)"
    pull_mode="$(jq -r '.config.pull_mode // "off"' <<< "$json")"
    iface="$(jq -r '.day_state.iface // .config.iface // "-"' <<< "$json")"
    ratio="$(jq -r '.day_state.target_ratio // "-"' <<< "$json")"
    rx="$(jq -r '.day_state.rx_accum // 0' <<< "$json")"
    tx="$(jq -r '.day_state.tx_accum // 0' <<< "$json")"
    action="$(jq -r '.day_state.last_action // "-"' <<< "$json")"
    feed_tcp="$(jq -r '.feed.tcp_listening // false' <<< "$json")"
    feed_udp="$(jq -r '.feed.udp_listening // false' <<< "$json")"
    debt="$(awk -v r="$ratio" -v tx="$tx" -v rx="$rx" 'BEGIN { if (r == "-") { print "-" } else { d = (r * tx) - rx; if (d < 0) d = 0; printf "%.0f", d } }')"

    printf 'pull_mode\t%s\n' "$pull_mode"
    printf 'iface\t%s\n' "$iface"
    printf 'target_ratio\t%s\n' "$ratio"
    printf 'rx_accum\t%s\n' "$rx"
    printf 'tx_accum\t%s\n' "$tx"
    printf 'debt\t%s\n' "$debt"
    printf 'last_action\t%s\n' "$action"
    printf 'feed_tcp\t%s\n' "$feed_tcp"
    printf 'feed_udp\t%s\n' "$feed_udp"
}

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
  pfwd downmask policy [--pull-mode off|public|ab] [--min-ratio N] [--max-ratio N] [--time-window-start HH:MM] [--time-window-end HH:MM] [--max-jitter SEC] [--min-deficit-bytes 20MB] [--max-bytes-per-run 800MB] [--iface NAME]
  pfwd downmask public [--active-source NAME(cloudflare_dynamic|cachefly_100mb|digitalocean_100mb|aliyun_ubuntu_iso)] [--speed-limit 4M(default, bytes/s)]
  pfwd downmask public custom add --name NAME --kind query|range --url URL(query 用 {bytes} 占位；range 需支持 Range 请求)
  pfwd downmask public custom delete --name NAME
  pfwd downmask public custom list
  pfwd downmask public custom clear
  pfwd downmask ab-pull [--protocol tcp|udp] [--remote-host HOST(IP)] [--remote-port PORT] [--local-ip IP] [--token TOKEN(openssl rand -hex 16)] [--speed-limit 4M(default, bytes/s)] [--timeout SEC]
  pfwd downmask ab-feed [--tcp-enabled true|false] [--udp-enabled true|false] [--bind-ip IP] [--tcp-port PORT] [--udp-port PORT] [--token TOKEN(openssl rand -hex 16)] [--seed-file PATH] [--udp-payload-bytes 1200|1.2KB]
  pfwd downmask seed generate [--path PATH] [--size 64MB]
EOF
            ;;
        *) pfwd_die "未知 downmask 子命令：$sub" ;;
    esac
}

cmd_downmask_policy() {
    local pull_mode="" min_ratio="" max_ratio="" tws="" twe="" jitter="" mindef="" maxrun="" iface=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --pull-mode) pull_mode="$2"; shift 2 ;;
            --min-ratio) min_ratio="$2"; shift 2 ;;
            --max-ratio) max_ratio="$2"; shift 2 ;;
            --time-window-start) tws="$2"; shift 2 ;;
            --time-window-end) twe="$2"; shift 2 ;;
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
        --arg jitter "$jitter" \
        --arg mindef "$mindef" \
        --arg maxrun "$maxrun" \
        --arg iface "$iface" '
        .settings.downmask |= (
            (if $pull_mode == "" then . else .pull_mode = $pull_mode end)
            | (if $min_ratio == "" then . else .min_ratio = ($min_ratio | tonumber) end)
            | (if $max_ratio == "" then . else .max_ratio = ($max_ratio | tonumber) end)
            | (if $tws == "" then . else .time_window_start = $tws end)
            | (if $twe == "" then . else .time_window_end = $twe end)
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
    local protocol="" remote_host="" remote_port="" local_ip="" token="" speed="" timeout=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --protocol) protocol="$2"; shift 2 ;;
            --remote-host) remote_host="$2"; shift 2 ;;
            --remote-port) remote_port="$2"; shift 2 ;;
            --local-ip) local_ip="$2"; shift 2 ;;
            --token) token="$2"; shift 2 ;;
            --speed-limit) speed="$2"; shift 2 ;;
            --timeout) timeout="$2"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -z "$protocol" ] || validate_downmask_protocol "$protocol"
    [ -z "$remote_port" ] || validate_port "$remote_port"
    [ -z "$local_ip" ] || validate_downmask_local_ip "$local_ip"
    [ -z "$speed" ] || validate_downmask_speed_limit "$speed"
    [ -z "$timeout" ] || [[ "$timeout" =~ ^[0-9]+$ ]] || pfwd_die "timeout 必须是非负整数"
    config_update \
        --arg protocol "$protocol" \
        --arg remote_host "$remote_host" \
        --arg remote_port "$remote_port" \
        --arg local_ip "$local_ip" \
        --arg token "$token" \
        --arg speed "$speed" \
        --arg timeout "$timeout" '
        .settings.downmask.ab_pull |= (
            (if $protocol == "" then . else .protocol = $protocol end)
            | (if $remote_host == "" then . else .remote_host = $remote_host end)
            | (if $remote_port == "" then . else .remote_port = ($remote_port | tonumber) end)
            | (if $local_ip == "" then . else .local_ip = $local_ip end)
            | (if $token == "" then . else .token = $token end)
            | (if $speed == "" then . else .speed_limit = $speed end)
            | (if $timeout == "" then . else .timeout_seconds = ($timeout | tonumber) end)
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
    [ "$sub" = "generate" ] || pfwd_die "用法：pfwd downmask seed generate [--path PATH] [--size 64MB]"
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
