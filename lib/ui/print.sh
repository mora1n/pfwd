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
    local empty_text="$4"
    local current_user="" line user first_group=true
    local enabled="" col3="" col4="" col5="" col6="" col7="" col8="" col9="" col10="" col11="" col12=""
    local group_rows="" group_headers="" group_shrink="" row_buffer=""

    if [ -z "$rows" ]; then
        ui_print_line "$empty_text"
        return 0
    fi

    ui_render_forward_group_block() {
        local block_user="$1"
        local block_rows="$2"
        local block_headers="$3"
        local block_shrink="$4"
        local block_line="" block_enabled="" block_user_id=""
        local block_col3="" block_col4="" block_col5="" block_col6="" block_col7="" block_col8="" block_col9="" block_col10="" block_col11="" block_col12=""
        local block_display_state=""
        local render_rows=""

        [ -n "$block_rows" ] || return 0
        ui_print_line "用户：$block_user" "$UI_C_HEADER"
        while IFS= read -r block_line; do
            [ -n "$block_line" ] || continue
            IFS=$'\t' read -r block_enabled block_user_id block_col3 block_col4 block_col5 block_col6 block_col7 block_col8 block_col9 block_col10 block_col11 block_col12 <<< "$block_line"
            case "$headers_tsv" in
                $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t备注')
                    render_rows+="$block_enabled"$'\t'"$block_col3"$'\t'"$block_col4"$'\t'"$block_col5"$'\t'"$block_col6"$'\t'"$block_col7"$'\t'"$(format_ratio "$block_col8")"$'\t'"$(ui_display_or_dash "$block_col9")"$'\n'
                    ;;
                $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注')
                    render_rows+="$block_enabled"$'\t'"$block_col3"$'\t'"$block_col4"$'\t'"$block_col5"$'\t'"$block_col6"$'\t'"$block_col7"$'\t'"$(format_ratio "$block_col8")"$'\t'"$(ui_format_rate "$block_col9")"$'\t'"$(ui_display_or_dash "$block_col10")"$'\n'
                    ;;
                $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\t倍率\tMSS\tSNAT\t备注')
                    render_rows+="#$block_enabled"$'\t'"$block_col6"$'\t'"$block_col3"$'\t'"$block_col4"$'\t'"$block_col5"$'\t'"$block_col7"$'\t'"$block_col8"$'\t'"$(format_ratio "$block_col9")"$'\t'"$block_col10"$'\t'"$block_col11"$'\t'"$(ui_display_or_dash "$block_col12")"$'\n'
                    ;;
                $'序号\t用户\t监听\t目标\t协议\t状态\t到期')
                    render_rows+="#$block_enabled"$'\t'"$block_col6"$'\t'"$block_col3"$'\t'"$block_col4"$'\t'"$block_col5"$'\t'"$block_col7"$'\n'
                    ;;
                *)
                    ui_forward_line "$block_enabled" "$block_line" "$col7"
                    continue
                    ;;
            esac
        done <<< "$block_rows"
        render_rows="${render_rows%$'\n'}"
        ui_table_render "$block_headers" "$render_rows" "$block_shrink"
    }

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        IFS=$'\t' read -r _ user _ <<< "$line"
        if [ -z "$current_user" ] || [ "$user" != "$current_user" ]; then
            if [ "$first_group" = "false" ]; then
                case "$headers_tsv" in
                    $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t备注')
                        group_headers=$'状态\t监听\t目标\t上行\t下行\t到期\t倍率\t备注'
                        group_shrink="2,3,4,5,6,7,8"
                        ;;
                    $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注')
                        group_headers=$'状态\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注'
                        group_shrink="2,3,4,5,6,7,8,9"
                        ;;
                    $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\t倍率\tMSS\tSNAT\t备注')
                        group_headers=$'序号\t状态\t监听\t目标\t协议\t到期\t模式\t倍率\tMSS\tSNAT\t备注'
                        group_shrink="3,4,6,7,8,9,10,11"
                        ;;
                    $'序号\t用户\t监听\t目标\t协议\t状态\t到期')
                        group_headers=$'序号\t状态\t监听\t目标\t协议\t到期'
                        group_shrink="3,4,6"
                        ;;
                    *)
                        group_headers=""
                        group_shrink=""
                        ;;
                esac
                ui_render_forward_group_block "$current_user" "$group_rows" "$group_headers" "$group_shrink"
                printf '\n'
            fi
            current_user="$user"
            first_group=false
            group_rows=""
        fi
        group_rows+="$line"$'\n'
    done <<< "$rows"

    group_rows="${group_rows%$'\n'}"
    case "$headers_tsv" in
        $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t备注')
            group_headers=$'状态\t监听\t目标\t上行\t下行\t到期\t倍率\t备注'
            group_shrink="2,3,4,5,6,7,8"
            ;;
        $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注')
            group_headers=$'状态\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注'
            group_shrink="2,3,4,5,6,7,8,9"
            ;;
        $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\t倍率\tMSS\tSNAT\t备注')
            group_headers=$'序号\t状态\t监听\t目标\t协议\t到期\t模式\t倍率\tMSS\tSNAT\t备注'
            group_shrink="3,4,6,7,8,9,10,11"
            ;;
        $'序号\t用户\t监听\t目标\t协议\t状态\t到期')
            group_headers=$'序号\t状态\t监听\t目标\t协议\t到期'
            group_shrink="3,4,6"
            ;;
        *)
            group_headers=""
            group_shrink=""
            ;;
    esac
    ui_render_forward_group_block "$current_user" "$group_rows" "$group_headers" "$group_shrink"
}


ui_print_main_forward_summary() {
    local data="$1"
    local rows=""
    ui_print_line "当前转发" "$UI_C_HEADER"

    if ! jq -e '.forwards | length > 0' <<< "$data" >/dev/null; then
        ui_print_line "$(ui_empty_forwards_text)"
        return
    fi

    while IFS=$'\t' read -r enabled user listen_ip listen_port remote_host remote_port input_bytes output_bytes stop_at ratio rate comment; do
        local remote_text listen_text
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        listen_text="$(ui_format_listen_compact "$listen_ip" "$listen_port")"
        rows+="$enabled"$'\t'"$user"$'\t'"$listen_text"$'\t'"$remote_text"$'\t'"$(ui_format_bytes_or_dash "$input_bytes")"$'\t'"$(ui_format_bytes_or_dash "$output_bytes")"$'\t'"$(ui_display_or_dash "$stop_at")"$'\t'"$(format_ratio "$ratio")"$'\t'"$(ui_format_rate "$rate")"$'\t'"$(ui_display_or_dash "$comment")"$'\n'
    done < <(ui_main_forward_rows "$data")
    rows="${rows%$'\n'}"
    ui_render_forward_groups "$rows" $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注' "4,10,2,7,3" "$(ui_empty_forwards_text)"
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
