#!/usr/bin/env bash

cmd_notify_schedule() {
    local user_id="" interval_minutes="__KEEP__" daily_time="__KEEP__"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            --interval-minutes) interval_minutes="${2:-}"; shift 2 ;;
            --daily-time) daily_time="${2:-}"; shift 2 ;;
            --clear-interval) interval_minutes=""; shift ;;
            --clear-daily) daily_time=""; shift ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    user_id="$(normalize_user_id "$user_id")"
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    if [ "$interval_minutes" = "__KEEP__" ] && [ "$daily_time" = "__KEEP__" ]; then
        pfwd_die "至少提供一个定时发送设置"
    fi
    config_set_user_telegram_schedule "$user_id" "$interval_minutes" "$daily_time"
    if { [ "$interval_minutes" != "__KEEP__" ] && [ -n "$interval_minutes" ]; } || { [ "$daily_time" != "__KEEP__" ] && [ -n "$daily_time" ]; }; then
        config_enable_user_telegram "$user_id"
    fi
    echo "Telegram 定时发送已更新：$user_id"
}


cmd_notify_enable() {
    local user_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    user_id="$(normalize_user_id "$user_id")"
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    config_enable_user_telegram "$user_id"
    echo "Telegram 通知已启用：$user_id"
}


cmd_notify_disable() {
    local user_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    user_id="$(normalize_user_id "$user_id")"
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    config_disable_user_telegram "$user_id"
    echo "Telegram 通知已停用：$user_id"
}


cmd_notify_delete() {
    local user_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    user_id="$(normalize_user_id "$user_id")"
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    config_delete_user_telegram "$user_id"
    echo "Telegram 配置已删除：$user_id"
}


cmd_notify_test() {
    local user_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    notify_send_telegram "$user_id" "$(notify_status_message "$user_id")" "false"
    echo "通知已发送：$user_id"
}
