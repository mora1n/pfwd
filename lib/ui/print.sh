#!/usr/bin/env bash

ui_print_user_delete_preview() {
    local user_ids="$1"
    local has_forwards="false"
    local user_id count

    ui_print_line "将删除以下用户：" "$UI_C_WARN"
    while IFS= read -r user_id; do
        [ -n "$user_id" ] || continue
        printf '%s\n' "$user_id"
    done <<< "$user_ids"

    while IFS= read -r user_id; do
        [ -n "$user_id" ] || continue
        count="$(config_user_forward_count "$user_id")"
        [ "$count" -gt 0 ] || continue
        has_forwards="true"
        printf '\n'
        ui_print_line "用户：$user_id（以下转发将一并删除）" "$UI_C_WARN"
        ui_table_render $'监听\t目标\t协议\t状态' "$(ui_user_delete_forward_rows "$user_id")" "2,4"
    done <<< "$user_ids"

    if [ "$has_forwards" = "true" ]; then
        printf '\n'
        ui_print_line "以上关联转发会随用户一起删除。" "$UI_C_WARN"
    fi

    UI_REPLY="$has_forwards"
}


ui_print_user_traffic_summary() {
    local user_id="$1"
    local data total_limit used one_way two_way reset_day forward_count rate rows="" config_tsv=""
    data="$(ui_main_usage_json)"
    config_tsv="$(ui_load_user_config_tsv "$user_id")"
    total_limit="${config_tsv%%$'\t'*}"
    config_tsv="${config_tsv#*$'\t'}"
    rate="${config_tsv%%$'\t'*}"
    used="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .billing_used_bytes // 0' <<< "$data")"
    one_way="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .one_way_bytes // 0' <<< "$data")"
    two_way="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .two_way_bytes // 0' <<< "$data")"
    reset_day="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .reset_day // "-"' <<< "$data")"
    forward_count="$(ui_user_forward_count "$user_id")"
    rows+="用户名"$'\t'"$user_id"$'\n'
    rows+="转发数"$'\t'"${forward_count} 个"$'\n'
    rows+="重置日"$'\t'"$(ui_format_reset_day "$reset_day")"$'\n'
    rows+="总限额"$'\t'"$(ui_format_limit "$total_limit")"$'\n'
    rows+="每端口速率"$'\t'"$(ui_format_rate "$rate")"$'\n'
    rows+="计费用量"$'\t'"$(format_bytes "$used")"$'\n'
    rows+="双向计费"$'\t'"$(format_bytes "$two_way")"$'\n'
    rows+="单向计费"$'\t'"$(format_bytes "$one_way")"
    ui_table_render $'项目\t值' "$rows" "2"
}


ui_print_main_user_summary() {
    local data="$1"
    local rows=""
    ui_print_line "用户状态" "$UI_C_HEADER"

    if ! jq -e '.users | length > 0' <<< "$data" >/dev/null; then
        ui_print_line "$(ui_empty_users_text)"
        return
    fi

    while IFS=$'\t' read -r user count used two_way one_way limit reset_day; do
        rows+="$user"$'\t'"$count"$'\t'"$(format_bytes "$used")"$'\t'"$(ui_progress_bar "$used" "$limit")"$'\t'"$(format_bytes "$two_way")"$'\t'"$(format_bytes "$one_way")"$'\t'"$(ui_format_limit "$limit")"$'\t'"$(ui_format_reset_day "$reset_day")"$'\n'
    done < <(ui_main_user_rows "$data")
    rows="${rows%$'\n'}"
    ui_table_render $'用户名\t转发数\t计费用量\t用量进度\t双向计费\t单向计费\t总限额\t重置日' "$rows" "1,6,7"
}


ui_render_forward_groups() {
    local rows="$1"
    local headers_tsv="$2"
    local shrink_csv="$3"
    local empty_text="$4"

    if [ -z "$rows" ]; then
        ui_print_line "$empty_text"
        return 0
    fi
    ui_table_render "$headers_tsv" "$rows" "$shrink_csv"
}


ui_print_main_forward_summary() {
    local data="$1"
    local rows="" limit total shown
    ui_print_line "当前转发" "$UI_C_HEADER"

    if ! jq -e '.forwards | length > 0' <<< "$data" >/dev/null; then
        ui_print_line "$(ui_empty_forwards_text)"
        return
    fi

    limit="${UI_MAIN_FORWARD_SUMMARY_LIMIT:-40}"
    [[ "$limit" =~ ^[0-9]+$ ]] || limit=40
    total="$(ui_main_forward_count "$data")"
    while IFS=$'\t' read -r enabled user listen_ip listen_port remote_host remote_port input_bytes output_bytes stop_at ratio rate comment; do
        local remote_text listen_text
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        listen_text="$(ui_format_listen_compact "$listen_ip" "$listen_port")"
        rows+="$enabled"$'\t'"$user"$'\t'"$listen_text"$'\t'"$remote_text"$'\t'"$(ui_format_bytes_or_dash "$input_bytes")"$'\t'"$(ui_format_bytes_or_dash "$output_bytes")"$'\t'"$(ui_display_or_dash "$stop_at")"$'\t'"$(format_ratio "$ratio")"$'\t'"$(ui_format_rate "$rate")"$'\t'"$(ui_display_or_dash "$comment")"$'\n'
    done < <(ui_main_forward_rows "$data" "$limit")
    rows="${rows%$'\n'}"
    ui_render_forward_groups "$rows" $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注' "4,10,2,7,3" "$(ui_empty_forwards_text)"
    if [ "$limit" -gt 0 ] && [ "$total" -gt "$limit" ]; then
        shown="$limit"
        ui_print_line "已显示 $shown/$total 条；进入转发管理查看完整列表。" "$UI_C_DIM"
    fi
}


ui_print_main_forwards() {
    config_init >/dev/null
    config_snapshot_load
    local data
    data="$(ui_main_usage_json)"
    ui_print_main_user_summary "$data"
    ui_rule "-" "$UI_C_DIM"
    ui_print_main_forward_summary "$data"
    ui_rule "-" "$UI_C_DIM"
}


ui_print_forward_list() {
    config_init >/dev/null
    if ! jq -e '.forwards | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_empty_forwards_text
        return
    fi
    ui_render_forward_groups "$(ui_forward_list_rows)" $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\t倍率\tMSS\tSNAT\t备注' "4,12,2,7,8,10,3" "$(ui_empty_forwards_text)"
}


ui_print_user_forward_summary() {
    local user_id="$1"
    config_init >/dev/null
    if ! jq -e --arg id "$user_id" '[.forwards[]? | select(.user_id == $id)] | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_print_line "$(ui_empty_forwards_text)"
        return
    fi
    ui_table_render $'监听\t目标\t协议\t状态\t到期' "$(ui_user_forward_summary_rows "$user_id")" "2,5"
}


ui_print_user_list() {
    local allow_zero="${1:-false}"
    config_init >/dev/null
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_empty_users_text
        return
    fi
    ui_table_render $'序号\t用户名' "$(ui_user_list_rows "$allow_zero")" "2"
}
