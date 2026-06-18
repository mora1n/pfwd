#!/usr/bin/env bash

ui_config_value() {
    local filter="$1"
    config_init >/dev/null
    jq -r "$filter" "$PFWD_CONFIG_FILE"
}


ui_format_remote() {
    local host="$1"
    local port="$2"
    if [[ "$host" == *:* ]]; then
        printf '[%s]:%s' "$host" "$port"
    else
        printf '%s:%s' "$host" "$port"
    fi
}


ui_format_listen() {
    ui_format_remote "$1" "$2"
}


ui_format_listen_compact() {
    local host="$1"
    local port="$2"
    case "$host" in
        ""|"::"|"0.0.0.0") printf '%s' "$port" ;;
        *) ui_format_listen "$host" "$port" ;;
    esac
}


ui_join_remote() {
    local host="$1"
    local port="$2"
    ui_format_remote "$host" "$port"
}


ui_protocol_label() {
    case "${1:-tcp_udp}" in
        tcp) echo "TCP" ;;
        udp) echo "UDP" ;;
        *) echo "TCP+UDP" ;;
    esac
}


ui_select_protocol() {
    local prompt="$1"
    local current_protocol="${2:-tcp_udp}"
    local allow_clear="${3:-false}"
    UI_EDIT_ABORTED=0
    UI_REPLY=""
    case "$current_protocol" in
        tcp) ui_form_select_read "$prompt" "1" "1) TCP" "2) UDP" "3) TCP+UDP" || return 1 ;;
        udp) ui_form_select_read "$prompt" "2" "1) TCP" "2) UDP" "3) TCP+UDP" || return 1 ;;
        *) ui_form_select_read "$prompt" "3" "1) TCP" "2) UDP" "3) TCP+UDP" || return 1 ;;
    esac
    case "$UI_REPLY" in
        0)
            if [ "$allow_clear" = "true" ]; then
                UI_EDIT_ABORTED=1
                return 0
            fi
            ui_warn "无效选择，已使用 TCP+UDP"
            UI_REPLY="tcp_udp"
            ;;
        "")
            if [ "$allow_clear" = "true" ]; then
                UI_REPLY=""
            else
                UI_REPLY="tcp_udp"
            fi
            ;;
        1) UI_REPLY="tcp" ;;
        2) UI_REPLY="udp" ;;
        3) UI_REPLY="tcp_udp" ;;
        *) ui_warn "无效选择，已使用 TCP+UDP"; UI_REPLY="tcp_udp" ;;
    esac
}


ui_select_protocol_edit() {
    ui_select_protocol "$1" "${2:-tcp_udp}" true
}


ui_select_traffic_mode() {
    local prompt="$1"
    local allow_empty="${2:-false}"
    local current_mode="${3:-}"
    local allow_clear="${4:-false}"
    UI_TRAFFIC_MODE=""
    UI_EDIT_ABORTED=0
    case "$current_mode" in
        one-way) ui_form_select_read "$prompt" "1" "1) 单向计费" "   按 (上行+下行) x 倍率 计费；适合一倍总流量结算。" "2) 双向计费" "   按 (上行+下行) x 倍率 x 2 计费；适合双倍流量结算。" || return 1 ;;
        two-way) ui_form_select_read "$prompt" "2" "1) 单向计费" "   按 (上行+下行) x 倍率 计费；适合一倍总流量结算。" "2) 双向计费" "   按 (上行+下行) x 倍率 x 2 计费；适合双倍流量结算。" || return 1 ;;
        *) ui_form_select_read "$prompt" "2" "1) 单向计费" "   按 (上行+下行) x 倍率 计费；适合一倍总流量结算。" "2) 双向计费" "   按 (上行+下行) x 倍率 x 2 计费；适合双倍流量结算。" || return 1 ;;
    esac
    if [ "$allow_clear" = "true" ] && [ "$UI_REPLY" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi
    if [ -z "$UI_REPLY" ]; then
        if [ "$allow_clear" = "true" ] || [ "$allow_empty" = "true" ]; then
            UI_TRAFFIC_MODE=""
        else
            UI_TRAFFIC_MODE="two-way"
        fi
        return 0
    fi
    case "$UI_REPLY" in
        1) UI_TRAFFIC_MODE="one-way" ;;
        2) UI_TRAFFIC_MODE="two-way" ;;
        *) ui_warn "无效选择，已使用双向"; UI_TRAFFIC_MODE="two-way" ;;
    esac
}


ui_select_traffic_mode_edit() {
    ui_select_traffic_mode "$1" false "${2:-}" true
}


ui_read_traffic_ratio() {
    local prompt="$1"
    local default="${2:-1.0}"
    local allow_clear="${3:-false}"
    UI_TRAFFIC_RATIO=""
    UI_EDIT_ABORTED=0
    if [ "$allow_clear" = "true" ]; then
        ui_form_edit_read "$prompt" "$default" || return 1
        [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    else
        ui_form_read "$prompt" "$default" || return 1
    fi
    UI_TRAFFIC_RATIO="$(normalize_traffic_ratio_input "$UI_REPLY")"
}


ui_read_traffic_ratio_edit() {
    ui_read_traffic_ratio "$1" "${2:-1.0}" true
}
