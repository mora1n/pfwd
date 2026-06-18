#!/usr/bin/env bash

ui_forward_state_text() {
    case "$1" in
        active|true|启用|已启用) printf '●' ;;
        mixed|混合|部分启用) printf '◐' ;;
        paused|false|停用|暂停|已停用) printf '◉' ;;
        stopped|停止) printf '○' ;;
        *) printf '○' ;;
    esac
}


ui_forward_state_color() {
    case "$1" in
        active|true|启用|已启用) echo "$UI_C_ACTIVE" ;;
        mixed|混合|部分启用) echo "$UI_C_MIXED" ;;
        paused|false|停用|暂停|已停用) echo "$UI_C_PAUSED" ;;
        stopped|停止) echo "$UI_C_STOPPED" ;;
        *) echo "$UI_C_PAUSED" ;;
    esac
}


ui_forward_state_name() {
    case "$1" in
        active|true|启用|已启用|●) printf 'active' ;;
        mixed|混合|部分启用|◐) printf 'mixed' ;;
        paused|false|停用|暂停|已停用|◉|■) printf 'paused' ;;
        stopped|停止|○) printf 'stopped' ;;
        *) printf '' ;;
    esac
}


ui_forward_display_state() {
    local enabled="$1"
    local stop_at="${2:-}"
    local normalized

    normalized="$(ui_forward_state_name "$enabled")"
    if [ "$normalized" = "active" ] || [ "$normalized" = "mixed" ] || [ "$normalized" = "stopped" ]; then
        printf '%s' "$normalized"
        return 0
    fi

    if pfwd_stop_at_expired "$stop_at"; then
        printf 'stopped'
        return 0
    fi

    if [ "$normalized" = "paused" ]; then
        printf 'paused'
        return 0
    fi

    printf 'paused'
}


ui_forward_aggregate_state() {
    local user_id="$1"
    local state_count=0
    local seen_active=0
    local seen_mixed=0
    local seen_paused=0
    local seen_stopped=0
    local _listen_port _remote_host _remote_port _protocol enabled stop_at display_state

    while IFS=$'\t' read -r _listen_port _remote_host _remote_port _protocol enabled stop_at; do
        [ -n "$enabled" ] || continue
        display_state="$(ui_forward_display_state "$enabled" "$stop_at")"
        case "$display_state" in
            active) seen_active=1 ;;
            mixed) seen_mixed=1 ;;
            paused) seen_paused=1 ;;
            stopped) seen_stopped=1 ;;
        esac
    done < <(config_user_forward_summary_tsv "$user_id")

    state_count=$((seen_active + seen_mixed + seen_paused + seen_stopped))
    if [ "$state_count" -eq 0 ]; then
        printf 'paused'
    elif [ "$seen_mixed" -eq 1 ] || [ "$state_count" -gt 1 ]; then
        printf 'mixed'
    elif [ "$seen_active" -eq 1 ]; then
        printf 'active'
    elif [ "$seen_stopped" -eq 1 ]; then
        printf 'stopped'
    else
        printf 'paused'
    fi
}


ui_forward_state_cell() {
    local enabled="$1"
    local stop_at="${2:-}"
    local display_state state_text state_color
    display_state="$(ui_forward_display_state "$enabled" "$stop_at")"
    state_text="$(ui_forward_state_text "$display_state")"
    state_color="$(ui_forward_state_color "$display_state")"
    ui_color "$state_color" "$state_text"
}


ui_guard_summary_state() {
    local item="$1"
    local value="$2"
    case "$item" in
        "启用状态")
            case "$value" in
                已启用|启用|开启|开|true|active|●) printf 'active' ;;
                已停用|停用|关闭|关|false|paused|■) printf 'paused' ;;
            esac
            ;;
        "启用入口白名单"|"启用出口白名单"|"封锁 HTTP"|"封锁 TLS"|"封锁 SOCKS")
            case "$value" in
                开|开启|启用|已启用|true|active|●) printf 'active' ;;
                关|关闭|停用|已停用|false|paused|■) printf 'paused' ;;
            esac
            ;;
    esac
}


ui_guard_summary_rows() {
    local rows line item value guard_state
    rows="$(guard_render_status)"
    while IFS=$'\t' read -r item value; do
        [ -n "$item" ] || continue
        guard_state="$(ui_guard_summary_state "$item" "$value")"
        if [ -n "$guard_state" ]; then
            value="$(ui_forward_state_text "$guard_state")"
        fi
        printf '%s\t%s\n' "$item" "$value"
    done <<< "$rows"
}


ui_whitelist_summary_rows() {
    local rows item value
    rows="$(whitelist_render_status)"
    while IFS=$'\t' read -r item value; do
        [ -n "$item" ] || continue
        case "$item" in
            "启用白名单") item="启用入口白名单" ;;
            "国内 IP 策略")
                item="入口国内 IP 策略"
                [ "$value" != "-" ] && value="$(ui_guard_cn_compact_summary ingress)"
                ;;
            "市白名单") item="入口市白名单" ;;
            "自定义 CIDR") item="入口自定义 CIDR" ;;
            "白名单条目") item="入口白名单条目" ;;
            "IPv4 文件") item="入口 IPv4 文件" ;;
            "市级 IPv4 文件") item="入口市级 IPv4 文件" ;;
            "IPv6 文件") item="入口 IPv6 文件" ;;
        esac
        printf '%s\t%s\n' "$item" "$value"
    done <<< "$rows"
}


ui_egress_whitelist_summary_rows() {
    local rows item value
    rows="$(egress_whitelist_render_status)"
    while IFS=$'\t' read -r item value; do
        [ -n "$item" ] || continue
        case "$item" in
            "出口国内 IP 策略")
                [ "$value" != "-" ] && value="$(ui_guard_cn_compact_summary egress)"
                ;;
        esac
        printf '%s\t%s\n' "$item" "$value"
    done <<< "$rows"
}


ui_forward_line() {
    local enabled="$1"
    local body="$2"
    local stop_at="${3:-}"
    local display_state state_text state_color
    display_state="$(ui_forward_display_state "$enabled" "$stop_at")"
    state_text="$(ui_forward_state_text "$display_state")"
    state_color="$(ui_forward_state_color "$display_state")"
    ui_color "$state_color" "$state_text"
    printf ' %s\n' "$body"
}
