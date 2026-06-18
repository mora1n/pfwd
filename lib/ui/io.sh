#!/usr/bin/env bash

ui_maybe_pause() {
    local mode="${1:-status}"
    case "$mode" in
        success)
            [ "$UI_STATUS" -eq 0 ] || ui_pause
            ;;
        always)
            ui_pause
            ;;
        *)
            [ "$UI_STATUS" -eq 0 ] || ui_pause
            ;;
    esac
}


ui_header() {
    printf '\n'
    ui_color "$UI_C_HEADER" "== $* =="
    printf '\n'
}


ui_main_title_meta_tsv() {
    local backend="none"
    local pull_mode="off"
    local feed_tcp="false"
    local feed_udp="false"
    if [ -f "$PFWD_FORWARDER_STATUS_FILE" ]; then
        backend="$(jq -r '.forwarding_backend // "none"' "$PFWD_FORWARDER_STATUS_FILE" 2>/dev/null || echo none)"
    fi
    if command -v downmask_config_get >/dev/null 2>&1; then
        pull_mode="$(downmask_config_get '.pull_mode' 2>/dev/null || echo off)"
        feed_tcp="$(downmask_config_get '.ab_feed.tcp_enabled' 2>/dev/null || echo false)"
        feed_udp="$(downmask_config_get '.ab_feed.udp_enabled' 2>/dev/null || echo false)"
    fi
    jq -r --arg backend "$backend" --arg pull_mode "$pull_mode" --arg feed_tcp "$feed_tcp" --arg feed_udp "$feed_udp" '
      [
        (.users | length),
        ([.forwards[]? | select(.enabled == true)] | length),
        $backend,
        $pull_mode,
        $feed_tcp,
        $feed_udp
      ] | @tsv
    ' "$PFWD_CONFIG_FILE"
}


ui_main_title_downmask_status() {
    local pull_mode="${1:-off}"
    local feed_tcp="${2:-false}"
    local feed_udp="${3:-false}"
    local tcp_flag="off" udp_flag="off"

    case "$feed_tcp" in
        true|1|yes|on) tcp_flag="on" ;;
    esac
    case "$feed_udp" in
        true|1|yes|on) udp_flag="on" ;;
    esac
    [ -n "$pull_mode" ] || pull_mode="off"
    printf 'downmask: %s | feed tcp=%s udp=%s' "$pull_mode" "$tcp_flag" "$udp_flag"
}


ui_title() {
    local guard_status="" downmask_status="" title_meta user_count forward_count backend pull_mode feed_tcp feed_udp
    title_meta="$(ui_cached_data "main_title_meta_tsv" ui_main_title_meta_tsv)"
    IFS=$'\t' read -r user_count forward_count backend pull_mode feed_tcp feed_udp <<< "$title_meta"
    if command -v guard_enabled >/dev/null 2>&1; then
        if [ "$(guard_enabled)" = "true" ]; then
            guard_status="guard: ${backend:-none}"
        else
            guard_status="guard: off"
        fi
    fi
    downmask_status="$(ui_main_title_downmask_status "$pull_mode" "$feed_tcp" "$feed_udp")"
    printf '\n'
    ui_color "$UI_C_TITLE" "pfwd v${PFWD_VERSION:-}"
    printf '  '
    ui_color "$UI_C_DIM" "用户: $user_count  转发: $forward_count"
    if [ -n "$guard_status" ]; then
        printf '  '
        ui_color "$UI_C_DIM_CYAN" "$guard_status"
    fi
    if [ -n "$downmask_status" ]; then
        printf '  '
        ui_color "$UI_C_DIM_CYAN" "$downmask_status"
    fi
    printf '\n'
    ui_print_line "操作流程：用户 → 添加转发 → 流量管理" "$UI_C_ACCENT"
    ui_rule "-" "$UI_C_DIM"
}


ui_menu_item() {
    local number="$1"
    local label="$2"
    ui_color "$UI_C_MENU_NUM" "$number."
    printf ' %s\n' "$label"
}


ui_success() {
    ui_color "$UI_C_MENU_NUM" "$*"
    printf '\n'
}


ui_warn() {
    ui_color "$UI_C_WARN" "$*"
    printf '\n'
}


ui_error() {
    ui_color "$UI_C_ERROR" "$*"
    printf '\n'
}


ui_read() {
    local prompt="$1"
    local default="${2:-}"
    UI_REPLY=""
    if [ "$UI_PAGE_ACTIVE" = "1" ] && [ -t 0 ] && [ -t 1 ]; then
        ui_page_read_line "$prompt" "" "$default"
        return $?
    fi
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$prompt" "$default"
    else
        printf '%s: ' "$prompt"
    fi
    if ! IFS= read -r UI_REPLY; then
        UI_REPLY=""
        return 1
    fi
    [ -n "$UI_REPLY" ] || UI_REPLY="$default"
    return 0
}


ui_read_timed() {
    local prompt="$1"
    local timeout_seconds="${2:-1}"
    local default="${3:-}"
    UI_REPLY=""

    if [ ! -t 0 ]; then
        ui_read "$prompt" "$default"
        return $?
    fi

    if [ "$UI_PAGE_ACTIVE" = "1" ] && [ -t 1 ]; then
        ui_page_read_line "$prompt" "$timeout_seconds" "$default"
        return $?
    fi

    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$prompt" "$default"
    else
        printf '%s: ' "$prompt"
    fi

    if IFS= read -r -t "$timeout_seconds" UI_REPLY; then
        [ -n "$UI_REPLY" ] || UI_REPLY="$default"
        return 0
    fi

    UI_REPLY=""
    return 124
}


ui_edit_read() {
    local prompt="$1"
    local default="${2:-}"
    UI_EDIT_ABORTED=0
    ui_read "$prompt" "$default" || return 1
    if [ "$UI_REPLY" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi
    return 0
}
