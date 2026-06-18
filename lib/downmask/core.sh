#!/usr/bin/env bash

DOWNMASK_BUILTIN_SOURCES="cloudflare_dynamic linode_tokyo_100mb cachefly_100mb"
DOWNMASK_QUERY_PULL_CHUNK_BYTES=$((32 * 1024 * 1024))
DOWNMASK_QUERY_LARGE_PULL_RANGE_SOURCE="linode_tokyo_100mb"
DOWNMASK_RANGE_PULL_CHUNK_BYTES=$((32 * 1024 * 1024))

downmask_is_builtin_public_source() {
    local name="$1"
    case "$name" in
        cloudflare_dynamic|linode_tokyo_100mb|cachefly_100mb) return 0 ;;
        *) return 1 ;;
    esac
}


validate_downmask_public_source_name() {
    local value="$1"
    [ -n "$value" ] || pfwd_die "active_source 不能为空"
    downmask_is_builtin_public_source "$value" && return 0
    case "$value" in
        digitalocean_100mb|aliyun_ubuntu_iso)
            pfwd_die "内置公网源已移除：$value；请改用 cloudflare_dynamic、linode_tokyo_100mb、cachefly_100mb，或使用 public custom 自定义源"
            ;;
        *)
            pfwd_die "未知内置公网源：$value；请改用 cloudflare_dynamic、linode_tokyo_100mb、cachefly_100mb，或使用 public custom 自定义源"
            ;;
    esac
}


downmask_validate_configured_active_source() {
    local active custom
    active="$(downmask_config_get '.public.active_source')"
    [ -n "$active" ] || return 0
    if downmask_is_builtin_public_source "$active"; then
        return 0
    fi
    custom="$(jq -r --arg name "$active" '.settings.downmask.public.custom_sources[]? | select(.name == $name) | .name' "$PFWD_CONFIG_FILE" | head -n1)"
    [ -n "$custom" ] && return 0
    validate_downmask_public_source_name "$active"
}


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


downmask_random_percent_factor() {
    local percent="$1"
    awk -v percent="$percent" -v seed="$RANDOM$$" '
    BEGIN {
        srand(seed)
        if (percent <= 0) {
            printf "1.000000"
            exit
        }
        span = percent / 100.0
        min = 1.0 - span
        max = 1.0 + span
        if (min < 0.05) min = 0.05
        printf "%.6f", min + rand() * (max - min)
    }'
}


downmask_apply_percent_jitter() {
    local base="$1"
    local percent="$2"
    awk -v base="$base" -v factor="$(downmask_random_percent_factor "$percent")" '
    BEGIN {
        value = base * factor
        if (value < 1) value = 1
        printf "%.0f", value
    }'
}


downmask_random_ratio() {
    local min="$1"
    local max="$2"
    if [ -n "${PFWD_TEST_DOWNMASK_RANDOM_RATIO:-}" ]; then
        printf '%.4f\n' "$PFWD_TEST_DOWNMASK_RANDOM_RATIO"
        return 0
    fi
    awk -v min="$min" -v max="$max" -v seed="$RANDOM$$" 'BEGIN { srand(seed); printf "%.4f", min + rand() * (max - min) }'
}


downmask_next_day_ratio() {
    local min="$1"
    local max="$2"
    local previous="${3:-}"
    local candidate
    candidate="$(downmask_random_ratio "$min" "$max")"
    if [ -n "$previous" ] && [ "$candidate" = "$previous" ]; then
        candidate="$(awk -v min="$min" -v max="$max" -v previous="$previous" 'BEGIN {
            adjusted = previous + 0.0001
            if (adjusted > max) {
                adjusted = previous - 0.0001
            }
            if (adjusted < min || adjusted > max) {
                adjusted = previous
            }
            printf "%.4f", adjusted
        }')"
    fi
    printf '%s\n' "$candidate"
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
    pfwd_now_epoch
}


downmask_random_jitter_until() {
    local max_jitter="$1"
    local base
    base="$(downmask_now_epoch)"
    [ "$max_jitter" -gt 0 ] || { echo "$base"; return; }
    local offset=$((RANDOM % max_jitter))
    echo $((base + offset))
}


downmask_speed_to_bps() {
    downmask_rate_to_bytes_per_second "$1" 2>/dev/null || echo 0
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
