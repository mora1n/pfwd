#!/usr/bin/env bash

downmask_reconcile_pull() {
    config_init >/dev/null
    downmask_validate_configured_active_source
    local downmask_cfg pull_mode iface state
    downmask_cfg="$(downmask_config_section '.settings.downmask')"
    pull_mode="$(jq -r '.pull_mode // "off"' <<< "$downmask_cfg")"
    [ -n "$pull_mode" ] && [ "$pull_mode" != "off" ] || return 0
    iface="$(downmask_iface)"
    [ -n "$iface" ] || return 0
    [ -d "/sys/class/net/$iface" ] || return 0

    state="$(downmask_prepare_day_state)" || return 1
    iface="$(jq -r '.iface // ""' <<< "$state")"
    [ -n "$iface" ] || return 0

    local state_fields state_date target_ratio rx_accum tx_accum last_rx last_tx next_eligible
    state_fields="$(downmask_state_get_fields "$state")" || return 1
    IFS=$'\x1f' read -r state_date target_ratio rx_accum tx_accum last_rx last_tx next_eligible <<< "$state_fields"

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
            --argjson previous "$state" \
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
            ($previous // {})
            + {
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
            }
            | .generated_at //= $updated_at
            | .generation_source //= "fresh_init"')" || return 1
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
    downmask_validate_configured_active_source
    local cfg state feed ab_targets pull_mode iface
    cfg="$(jq -c '.settings.downmask // {}' "$PFWD_CONFIG_FILE")"
    pull_mode="$(jq -r '.pull_mode // "off"' <<< "$cfg")"
    if [ -n "$pull_mode" ] && [ "$pull_mode" != "off" ]; then
        iface="$(downmask_iface)"
        if [ -n "$iface" ] && [ -d "/sys/class/net/$iface" ]; then
            state="$(downmask_prepare_day_state)" || return 1
        else
            state='{}'
        fi
    else
        state='{}'
    fi
    ab_targets="$(downmask_ab_pull_targets_json)"
    if [ -f "$PFWD_DOWNMASK_STATUS_FILE" ]; then
        feed="$(cat "$PFWD_DOWNMASK_STATUS_FILE" 2>/dev/null || echo '{}')"
    else
        feed='{}'
    fi
    jq -n \
        --argjson config "$cfg" \
        --argjson state "$state" \
        --argjson ab_targets "$ab_targets" \
        --argjson feed "$feed" '
        {
            config: $config,
            day_state: $state,
            ab_targets: $ab_targets,
            feed: $feed
        }'
}


downmask_render_status() {
    local json downmask_fields pull_mode iface date ratio rx tx debt action feed_tcp feed_udp ab_targets protocol_mode
    local previous_date previous_ratio generated_at generation_source
    downmask_validate_configured_active_source
    json="$(downmask_status_json)"
    downmask_fields="$(jq -r '
      [
        (.config.pull_mode // "off"),
        (.day_state.iface // .config.iface // "-"),
        (.day_state.date // "-"),
        (.day_state.target_ratio // "-"),
        (.day_state.previous_date // "-"),
        (.day_state.previous_target_ratio // "-"),
        (.day_state.generated_at // "-"),
        (.day_state.generation_source // "-"),
        (.day_state.rx_accum // 0),
        (.day_state.tx_accum // 0),
        (.day_state.last_action // "-"),
        (.feed.tcp_listening // false),
        (.feed.udp_listening // false),
        ((.ab_targets // []) | length),
        (.config.ab_pull.protocol_mode // "single")
      ] | map(tostring) | join("\u001f")
    ' <<< "$json")"
    IFS=$'\037' read -r pull_mode iface date ratio previous_date previous_ratio generated_at generation_source rx tx action feed_tcp feed_udp ab_targets protocol_mode <<< "$downmask_fields"
    debt="$(awk -v r="$ratio" -v tx="$tx" -v rx="$rx" 'BEGIN { if (r == "-") { print "-" } else { d = (r * tx) - rx; if (d < 0) d = 0; printf "%.0f", d } }')"

    printf 'pull_mode\t%s\n' "$pull_mode"
    printf 'iface\t%s\n' "$iface"
    printf 'date\t%s\n' "$date"
    printf 'target_ratio\t%s\n' "$ratio"
    printf 'previous_date\t%s\n' "$previous_date"
    printf 'previous_target_ratio\t%s\n' "$previous_ratio"
    printf 'generated_at\t%s\n' "$generated_at"
    printf 'generation_source\t%s\n' "$generation_source"
    printf 'rx_accum\t%s\n' "$rx"
    printf 'tx_accum\t%s\n' "$tx"
    printf 'debt\t%s\n' "$debt"
    printf 'last_action\t%s\n' "$action"
    printf 'ab_protocol_mode\t%s\n' "$protocol_mode"
    printf 'ab_targets\t%s\n' "$ab_targets"
    printf 'feed_tcp\t%s\n' "$feed_tcp"
    printf 'feed_udp\t%s\n' "$feed_udp"
}
