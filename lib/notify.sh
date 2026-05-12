#!/usr/bin/env bash

notify_user_config() {
    local user_id="$1"
    jq -c --arg id "$user_id" '.users[]? | select(.id == $id) | .telegram' "$PFWD_CONFIG_FILE"
}

notify_html_escape() {
    printf '%s' "$1" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g'
}

notify_send_telegram() {
    local user_id="$1"
    local message="$2"
    local require_enabled="${3:-true}"
    config_init >/dev/null
    local tg enabled token chat_id
    tg="$(notify_user_config "$user_id")"
    [ -n "$tg" ] && [ "$tg" != "null" ] || pfwd_die "未找到该用户的 Telegram 配置：$user_id"
    enabled="$(echo "$tg" | jq -r '.enabled // false')"
    if [ "$require_enabled" = "true" ]; then
        [ "$enabled" = "true" ] || pfwd_die "该用户的 Telegram 通知未启用：$user_id"
    fi
    token="$(echo "$tg" | jq -r '.bot_token // ""')"
    chat_id="$(echo "$tg" | jq -r '.chat_id // ""')"
    [ -n "$token" ] || pfwd_die "该用户的 Telegram bot token 为空：$user_id"
    [ -n "$chat_id" ] || pfwd_die "该用户的 Telegram chat id 为空：$user_id"

    pfwd_require_cmd curl
    local response
    response="$(curl -fsS --connect-timeout 5 --max-time 15 \
        -X POST "https://api.telegram.org/bot${token}/sendMessage" \
        --data-urlencode "chat_id=${chat_id}" \
        --data-urlencode "text=${message}" \
        --data-urlencode "parse_mode=HTML")" || pfwd_die "Telegram 请求失败"
    echo "$response" | jq -e '.ok == true' >/dev/null || pfwd_die "Telegram API 返回失败：$response"
}

notify_status_icon() {
    if [ "$1" = "true" ]; then
        echo "🟢"
    else
        echo "🟡"
    fi
}

notify_rate_text() {
    local rate="$1"
    if [ -z "$rate" ] || [ "$rate" = "null" ]; then
        echo "不限"
    else
        echo "$rate"
    fi
}

notify_user_summary_json() {
    local user_id="$1"
    local stats
    stats="$(stats_usage_json)"
    jq -c --arg user "$user_id" '
      .users[]? | select(.id == $user)
    ' <<< "$stats"
}

notify_status_message() {
    local user_id="$1"
    local tg stats user_json server_name reset_day total_limit user_name user_rate
    tg="$(notify_user_config "$user_id")"
    [ -n "$tg" ] && [ "$tg" != "null" ] || pfwd_die "未找到该用户的 Telegram 配置：$user_id"
    stats="$(stats_json "$user_id" "")"
    user_json="$(notify_user_summary_json "$user_id")"
    [ -n "$user_json" ] && [ "$user_json" != "null" ] || pfwd_die "未找到该用户统计信息：$user_id"

    server_name="$(echo "$tg" | jq -r '.server_name // ""')"
    [ -n "$server_name" ] || server_name="$(hostname 2>/dev/null || echo pfwd)"
    reset_day="$(echo "$user_json" | jq -r '.reset_day // "未设置"')"
    total_limit="$(echo "$user_json" | jq -r '.limits.traffic_bytes // "null"')"
    user_rate="$(echo "$user_json" | jq -r '.limits.rate // "null"')"
    user_name="$(notify_html_escape "$user_id")"

    {
        printf '<b>%s</b>\n' "$(notify_html_escape "$server_name")"
        printf '用户：<b>%s</b>\n' "$user_name"
        printf '转发数：%s\n' "$(echo "$stats" | jq -r '.forwards | length')"
        printf '计费用量：%s\n' "$(format_bytes "$(echo "$user_json" | jq -r '.billing_used_bytes // 0')")"
        printf '双向计费：%s\n' "$(format_bytes "$(echo "$user_json" | jq -r '.two_way_bytes // 0')")"
        printf '单向计费：%s\n' "$(format_bytes "$(echo "$user_json" | jq -r '.one_way_bytes // 0')")"
        printf '总流量限制：%s\n' "$(ui_format_limit "$total_limit")"
        printf '重置日：%s\n' "$reset_day"
        printf '\n<b>端口明细</b>\n'
        if jq -e '.forwards | length > 0' <<< "$stats" >/dev/null; then
            jq -c '.forwards[]' <<< "$stats" | while IFS= read -r row; do
                local enabled listen_port input_bytes output_bytes total_bytes limit rate stop_at status_text ratio
                local protocol
                enabled="$(echo "$row" | jq -r '.enabled')"
                listen_port="$(echo "$row" | jq -r '.listen_port')"
                protocol="$(echo "$row" | jq -r '.protocol // "tcp_udp"')"
                input_bytes="$(echo "$row" | jq -r '.input_bytes // 0')"
                output_bytes="$(echo "$row" | jq -r '.output_bytes // 0')"
                total_bytes="$(echo "$row" | jq -r '.total_bytes // 0')"
                ratio="$(echo "$row" | jq -r '(.traffic_ratio // 1) | tostring')"
                limit="$(echo "$row" | jq -r '.limits.traffic_bytes // "null"')"
                rate="$(echo "$row" | jq -r '.limits.rate // "null"')"
                if [ -z "$rate" ] || [ "$rate" = "null" ]; then
                    rate="$user_rate"
                fi
                stop_at="$(echo "$row" | jq -r '.stop_at // "不限"')"
                if [ "$enabled" = "true" ]; then
                    status_text="开启"
                else
                    status_text="暂停"
                fi
                printf '%s 端口 <b>%s</b> | 协议 %s | 状态 %s | 计费总量 %s | 上行 %s | 下行 %s | 倍率 %s | 速率 %s | 限额 %s | 到期 %s\n' \
                    "$(notify_status_icon "$enabled")" \
                    "$listen_port" \
                    "$(ui_protocol_label "$protocol")" \
                    "$status_text" \
                    "$(format_bytes "$total_bytes")" \
                    "$(format_bytes "$input_bytes")" \
                    "$(format_bytes "$output_bytes")" \
                    "$(format_ratio "$ratio")" \
                    "$(notify_rate_text "$rate")" \
                    "$(ui_format_limit "$limit")" \
                    "$stop_at"
            done
        else
            printf '暂无转发\n'
        fi
    }
}

notify_interval_due() {
    local interval_minutes="$1"
    local last_sent_at="$2"
    [ -n "$interval_minutes" ] && [ "$interval_minutes" != "null" ] || return 1

    local now_epoch last_epoch
    now_epoch="$(date +%s)"
    if [ -z "$last_sent_at" ] || [ "$last_sent_at" = "null" ]; then
        return 0
    fi
    last_epoch="$(date -d "$last_sent_at" +%s 2>/dev/null)" || return 0
    [ $((now_epoch - last_epoch)) -ge $((interval_minutes * 60)) ]
}

notify_daily_due() {
    local daily_time="$1"
    local last_sent_date="$2"
    [ -n "$daily_time" ] && [ "$daily_time" != "null" ] || return 1

    local today current_minutes target_minutes hh mm
    today="$(date '+%Y-%m-%d')"
    [ "$last_sent_date" != "$today" ] || return 1

    hh="${daily_time%:*}"
    mm="${daily_time#*:}"
    target_minutes=$((10#$hh * 60 + 10#$mm))
    current_minutes=$((10#$(date '+%H') * 60 + 10#$(date '+%M')))
    [ "$current_minutes" -ge "$target_minutes" ]
}

notify_send_scheduled_for_user() {
    local user_id="$1"
    local tg enabled interval_minutes daily_time last_interval last_daily due_interval=false due_daily=false
    tg="$(notify_user_config "$user_id")"
    [ -n "$tg" ] && [ "$tg" != "null" ] || pfwd_die "未找到该用户的 Telegram 配置：$user_id"

    enabled="$(echo "$tg" | jq -r '.enabled // false')"
    [ "$enabled" = "true" ] || return 1
    interval_minutes="$(echo "$tg" | jq -r '.schedule_interval_minutes // "null"')"
    daily_time="$(echo "$tg" | jq -r '.schedule_daily_time // "null"')"
    last_interval="$(echo "$tg" | jq -r '.last_interval_sent_at // "null"')"
    last_daily="$(echo "$tg" | jq -r '.last_daily_sent_date // "null"')"

    if notify_interval_due "$interval_minutes" "$last_interval"; then
        due_interval=true
    fi
    if notify_daily_due "$daily_time" "$last_daily"; then
        due_daily=true
    fi

    [ "$due_interval" = "true" ] || [ "$due_daily" = "true" ] || return 1

    notify_send_telegram "$user_id" "$(notify_status_message "$user_id")"
    if [ "$due_interval" = "true" ]; then
        config_mark_user_telegram_interval_sent "$user_id" "$(pfwd_now_iso)"
    fi
    if [ "$due_daily" = "true" ]; then
        config_mark_user_telegram_daily_sent "$user_id" "$(pfwd_today)"
    fi
    return 0
}

notify_reconcile_schedules() {
    config_init >/dev/null
    local user_id sent=0
    while IFS= read -r user_id; do
        [ -n "$user_id" ] || continue
        if notify_send_scheduled_for_user "$user_id"; then
            sent=$((sent + 1))
        fi
    done < <(jq -r '.users[]?.id' "$PFWD_CONFIG_FILE")
    echo "$sent"
}

notify_expired_message() {
    local forward_id="$1"
    local user_id="$2"
    echo "pfwd：用户 $user_id 的转发 $forward_id 已到期并停止"
}
