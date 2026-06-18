#!/usr/bin/env bash

downmask_state_file() {
    echo "$PFWD_DOWNMASK_STATE_DIR/day_state.json"
}


downmask_ratio_history_file() {
    echo "$PFWD_DOWNMASK_STATE_DIR/ratio_history.json"
}


downmask_load_day_state() {
    local file
    file="$(downmask_state_file)"
    if [ -f "$file" ]; then
        jq -c '.' "$file" || pfwd_die "无效 downmask 日状态文件：$file"
    else
        echo '{}'
    fi
}


downmask_load_ratio_history() {
    local file
    file="$(downmask_ratio_history_file)"
    if [ -f "$file" ]; then
        jq -c 'if type == "array" then . else error("not array") end' "$file" ||
            pfwd_die "无效 downmask 比例历史文件：$file"
    else
        echo '[]'
    fi
}


downmask_save_day_state() {
    local payload="$1"
    local file
    file="$(downmask_state_file)"
    mkdir -p "$(dirname "$file")"
    printf '%s\n' "$payload" | jq '.' | pfwd_write_atomic "$file"
}


downmask_save_ratio_history() {
    local payload="$1"
    local file
    file="$(downmask_ratio_history_file)"
    mkdir -p "$(dirname "$file")"
    printf '%s\n' "$payload" | jq '.' | pfwd_write_atomic "$file"
}


downmask_history_entry_for_date() {
    local history_json="$1"
    local date="$2"
    jq -c --arg date "$date" '[.[] | select((.date // "") == $date)] | last // {}' <<< "$history_json"
}


downmask_history_latest_entry_before() {
    local history_json="$1"
    local date="$2"
    jq -c --arg date "$date" '[.[] | select((.date // "") < $date)] | last // {}' <<< "$history_json"
}


downmask_history_upsert_entry() {
    local history_json="$1"
    local entry_json="$2"
    jq -c \
        --argjson entry "$entry_json" '
        ([.[] | select((.date // "") != ($entry.date // ""))] + [$entry]
            | sort_by(.date)
            | reverse
            | .[:32]
            | reverse)' <<< "$history_json"
}


downmask_record_ratio_history_entry() {
    local entry_json="$1"
    local history_json updated
    history_json="$(downmask_load_ratio_history)" || return 1
    updated="$(downmask_history_upsert_entry "$history_json" "$entry_json")" || return 1
    downmask_save_ratio_history "$updated"
}


downmask_history_entry_from_state() {
    local state_json="$1"
    jq -c '{
        date: (.date // ""),
        target_ratio: (.target_ratio // 0),
        previous_date: (.previous_date // ""),
        previous_target_ratio: (.previous_target_ratio // null),
        generation_source: (.generation_source // "fresh_init"),
        generated_at: (.generated_at // .updated_at // "")
    }' <<< "$state_json"
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
    ] | join("\u001f")' <<< "$state_json"
}


downmask_prepare_day_state() {
    config_init >/dev/null
    downmask_validate_configured_active_source
    local downmask_cfg pull_mode iface today state history_json today_history_json
    downmask_cfg="$(downmask_config_section '.settings.downmask')"
    pull_mode="$(jq -r '.pull_mode // "off"' <<< "$downmask_cfg")"
    [ -n "$pull_mode" ] && [ "$pull_mode" != "off" ] || return 1
    iface="$(downmask_iface)"
    [ -n "$iface" ] || return 1
    [ -d "/sys/class/net/$iface" ] || return 1

    today="$(pfwd_today)"
    state="$(downmask_load_day_state)" || return 1
    history_json="$(downmask_load_ratio_history)" || return 1
    today_history_json="$(downmask_history_entry_for_date "$history_json" "$today")" || return 1

    local raw_rx_tx raw_rx raw_tx
    raw_rx_tx="$(downmask_read_iface_bytes "$iface")"
    raw_rx="${raw_rx_tx%%$'\t'*}"
    raw_tx="${raw_rx_tx##*$'\t'}"
    [[ "$raw_rx" =~ ^[0-9]+$ ]] || raw_rx=0
    [[ "$raw_tx" =~ ^[0-9]+$ ]] || raw_tx=0

    local state_fields state_date target_ratio rx_accum tx_accum last_rx last_tx next_eligible
    state_fields="$(downmask_state_get_fields "$state")" || return 1
    IFS=$'\x1f' read -r state_date target_ratio rx_accum tx_accum last_rx last_tx next_eligible <<< "$state_fields"
    [[ "$rx_accum" =~ ^[0-9]+$ ]] || rx_accum=0
    [[ "$tx_accum" =~ ^[0-9]+$ ]] || tx_accum=0
    [[ "$last_rx" =~ ^[0-9]+$ ]] || last_rx=0
    [[ "$last_tx" =~ ^[0-9]+$ ]] || last_tx=0
    [[ "$next_eligible" =~ ^[0-9]+$ ]] || next_eligible=0

    local payload now_iso
    now_iso="$(pfwd_now_iso)"
    if [ "$state_date" != "$today" ] || [ -z "$target_ratio" ]; then
        local history_today_date history_today_ratio
        history_today_date="$(jq -r '.date // empty' <<< "$today_history_json")"
        history_today_ratio="$(jq -r 'if .target_ratio == null then "" else (.target_ratio | tostring) end' <<< "$today_history_json")"
        if [ "$history_today_date" = "$today" ] && [ -n "$history_today_ratio" ]; then
            target_ratio="$history_today_ratio"
            state_date="$today"
            rx_accum=0
            tx_accum=0
            last_rx="$raw_rx"
            last_tx="$raw_tx"
            next_eligible=0
            payload="$(jq -n \
                --argjson history "$today_history_json" \
                --arg date "$state_date" \
                --arg iface "$iface" \
                --arg target_ratio "$target_ratio" \
                --argjson rx_accum "$rx_accum" \
                --argjson tx_accum "$tx_accum" \
                --argjson last_rx_raw "$last_rx" \
                --argjson last_tx_raw "$last_tx" \
                --argjson next_eligible_at "$next_eligible" \
                --arg updated_at "$now_iso" '
                ($history // {})
                + {
                    date: $date,
                    iface: $iface,
                    target_ratio: ($target_ratio | tonumber),
                    rx_accum: $rx_accum,
                    tx_accum: $tx_accum,
                    last_rx_raw: $last_rx_raw,
                    last_tx_raw: $last_tx_raw,
                    next_eligible_at: $next_eligible_at,
                    last_action: "state_restore",
                    last_actual_bytes: 0,
                    last_planned_bytes: 0,
                    last_error: "",
                    updated_at: $updated_at
                }
                | .generated_at //= $updated_at
                | .generation_source //= "rollover_history_fallback"')" || return 1
        else
            local min_r max_r previous_date previous_target_ratio generation_source previous_entry_json
            min_r="$(jq -r '.min_ratio // 1.5' <<< "$downmask_cfg")"
            max_r="$(jq -r '.max_ratio // 2.8' <<< "$downmask_cfg")"
            generation_source="fresh_init"
            previous_date=""
            previous_target_ratio=""
            if [ -n "$state_date" ] && [ -n "$target_ratio" ]; then
                previous_date="$state_date"
                previous_target_ratio="$target_ratio"
                generation_source="rollover_state"
            else
                previous_entry_json="$(downmask_history_latest_entry_before "$history_json" "$today")" || return 1
                previous_date="$(jq -r '.date // empty' <<< "$previous_entry_json")"
                previous_target_ratio="$(jq -r 'if .target_ratio == null then "" else (.target_ratio | tostring) end' <<< "$previous_entry_json")"
                if [ -n "$previous_date" ] && [ -n "$previous_target_ratio" ]; then
                    generation_source="rollover_history_fallback"
                fi
            fi
            target_ratio="$(downmask_next_day_ratio "$min_r" "$max_r" "$previous_target_ratio")"
            rx_accum=0
            tx_accum=0
            last_rx="$raw_rx"
            last_tx="$raw_tx"
            next_eligible=0
            state_date="$today"
            payload="$(jq -n \
                --arg date "$state_date" \
                --arg iface "$iface" \
                --arg target_ratio "$target_ratio" \
                --argjson rx_accum "$rx_accum" \
                --argjson tx_accum "$tx_accum" \
                --argjson last_rx_raw "$last_rx" \
                --argjson last_tx_raw "$last_tx" \
                --argjson next_eligible_at "$next_eligible" \
                --arg previous_date "$previous_date" \
                --arg previous_target_ratio "$previous_target_ratio" \
                --arg generation_source "$generation_source" \
                --arg updated_at "$now_iso" '
                {
                    date: $date,
                    iface: $iface,
                    target_ratio: ($target_ratio | tonumber),
                    rx_accum: $rx_accum,
                    tx_accum: $tx_accum,
                    last_rx_raw: $last_rx_raw,
                    last_tx_raw: $last_tx_raw,
                    next_eligible_at: $next_eligible_at,
                    last_action: "new_day",
                    last_actual_bytes: 0,
                    last_planned_bytes: 0,
                    last_error: "",
                    generated_at: $updated_at,
                    updated_at: $updated_at,
                    generation_source: $generation_source
                }
                | if $previous_date == "" then . else .previous_date = $previous_date end
                | if $previous_target_ratio == "" then . else .previous_target_ratio = ($previous_target_ratio | tonumber) end')" || return 1
            downmask_record_ratio_history_entry "$(downmask_history_entry_from_state "$payload")" || return 1
        fi
    else
        local delta_rx delta_tx base_state
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
        base_state="$state"
        if [ -n "$(jq -r '.date // empty' <<< "$today_history_json")" ]; then
            base_state="$(jq -cn --argjson history "$today_history_json" --argjson state "$state" '$history + $state')"
        fi
        payload="$(jq -n \
            --argjson previous "$base_state" \
            --arg date "$state_date" \
            --arg iface "$iface" \
            --arg target_ratio "$target_ratio" \
            --argjson rx_accum "$rx_accum" \
            --argjson tx_accum "$tx_accum" \
            --argjson last_rx_raw "$last_rx" \
            --argjson last_tx_raw "$last_tx" \
            --argjson next_eligible_at "$next_eligible" \
            --arg updated_at "$now_iso" '
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
                updated_at: $updated_at
            }
            | .last_action //= "skip"
            | .last_actual_bytes //= 0
            | .last_planned_bytes //= 0
            | .last_error //= ""
            | .generated_at //= $updated_at
            | .generation_source //= "fresh_init"')" || return 1
        if [ -z "$(jq -r '.date // empty' <<< "$today_history_json")" ]; then
            downmask_record_ratio_history_entry "$(downmask_history_entry_from_state "$payload")" || return 1
        fi
    fi
    downmask_save_day_state "$payload"
    printf '%s\n' "$payload"
}
