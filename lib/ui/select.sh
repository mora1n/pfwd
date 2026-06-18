#!/usr/bin/env bash

ui_select_user() {
    local allow_zero="${1:-false}"
    UI_EDIT_ABORTED=0
    config_init >/dev/null
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_users_text)"
        return 1
    fi
    ui_render_page ui_render_user_select_page "$allow_zero"
    ui_read "选择用户序号" || return 1
    if [ "$allow_zero" = "true" ] && [ "$UI_REPLY" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi
    [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; return 1; }
    local user_id
    user_id="$(jq -r --argjson idx "$UI_REPLY" '.users[$idx - 1].id // ""' "$PFWD_CONFIG_FILE")"
    [ -n "$user_id" ] || { ui_warn "用户序号不存在"; return 1; }
    UI_REPLY="$user_id"
}


ui_render_user_select_page() {
    local allow_zero="${1:-false}"
    ui_header "选择用户"
    ui_notice_render
    ui_print_user_list "$allow_zero"
}


ui_select_user_for_telegram_config() {
    config_init >/dev/null
    local rows=$'0\t返回\n1\t所有用户'
    local index=2 user_id
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_users_text)"
        return 1
    fi
    while IFS= read -r user_id; do
        rows+=$'\n'"$index"$'\t'"$user_id"
        index=$((index + 1))
    done < <(jq -r '.users[]?.id' "$PFWD_CONFIG_FILE")
    ui_render_page ui_render_telegram_user_select_page "$rows"
    ui_read "选择用户序号" || return 1
    [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; return 1; }
    case "$UI_REPLY" in
        0)
            UI_EDIT_ABORTED=1
            return 0
            ;;
        1)
            UI_REPLY="__ALL_USERS__"
            return 0
            ;;
    esac
    local user_id
    user_id="$(jq -r --argjson idx "$UI_REPLY" '.users[$idx - 2].id // ""' "$PFWD_CONFIG_FILE")"
    [ -n "$user_id" ] || { ui_warn "用户序号不存在"; return 1; }
    UI_REPLY="$user_id"
}


ui_select_users_for_telegram_config_multi() {
    config_init >/dev/null
    UI_EDIT_ABORTED=0
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_users_text)"
        return 1
    fi
    local rows=$'0\t返回\n1\t所有用户'
    local user_count index raw indexes selected_count user_ids
    local user_id
    user_count="$(jq '.users | length' "$PFWD_CONFIG_FILE")"
    index=2
    while IFS= read -r user_id; do
        rows+=$'\n'"$index"$'\t'"$user_id"
        index=$((index + 1))
    done < <(jq -r '.users[]?.id' "$PFWD_CONFIG_FILE")

    ui_render_page ui_render_telegram_user_select_page_config "$rows"
    ui_read "选择用户序号，可多选：2,4,6 或 2-5；1 表示所有用户" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$((user_count + 1))" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    selected_count="$(printf '%s\n' "$indexes" | sed '/^$/d' | wc -l | tr -d ' ')"
    if printf '%s\n' "$indexes" | grep -qx '1'; then
        [ "$selected_count" = "1" ] || { ui_warn "“所有用户”只能单独选择"; return 1; }
        UI_REPLY="__ALL_USERS__"
        return 0
    fi
    user_ids="$(jq -r --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      [ .users[]?.id ] as $ids
      | $idxs[]
      | $ids[. - 2] // empty
    ' "$PFWD_CONFIG_FILE")"
    [ -n "$user_ids" ] || { ui_warn "用户序号不存在"; return 1; }
    UI_REPLY="$user_ids"
}


ui_render_telegram_user_select_page() {
    local rows="$1"
    ui_header "选择用户"
    ui_notice_render
    ui_table_render $'序号\t用户' "$rows" "2"
}


ui_render_telegram_user_select_page_config() {
    local rows="$1"
    ui_header "选择用户"
    ui_notice_render
    ui_print_line "1 表示所有用户；也支持多选具体用户。" "$UI_C_ACCENT"
    ui_table_render $'序号\t用户' "$rows" "2"
}


ui_telegram_configured_user_select_rows() {
    local rows=""
    local index=1 user status schedule
    while IFS=$'\t' read -r user status schedule; do
        [ -n "$user" ] || continue
        rows+="$index"$'\t'"$user"$'\t'"$status"$'\t'"$schedule"$'\n'
        index=$((index + 1))
    done < <(ui_telegram_configured_user_rows)
    printf '%s' "${rows%$'\n'}"
}


ui_render_telegram_user_select_page_configured() {
    local rows="$1"
    local empty="${2:-false}"
    ui_header "选择已配置用户"
    ui_notice_render
    if [ "$empty" = "true" ]; then
        ui_warn "暂无已配置用户，请先配置 Telegram。"
        ui_table_render $'序号\t操作' "$rows" "2"
    else
        ui_print_line "支持多选：1,3,5 或 1-3" "$UI_C_ACCENT"
        ui_table_render $'序号\t用户\t状态\t定时发送' "$rows" "2,4"
    fi
}


ui_select_configured_users_multi() {
    config_init >/dev/null
    UI_EDIT_ABORTED=0
    local configured_count rows raw indexes user_ids
    configured_count="$(jq '[.users[]? | select((.telegram.bot_token // "") != "" and (.telegram.chat_id // "") != "")] | length' "$PFWD_CONFIG_FILE")"
    if [ "$configured_count" -eq 0 ]; then
        rows=$'0\t返回'
        ui_render_page ui_render_telegram_user_select_page_configured "$rows" "true"
        ui_read "选择 0 返回" || return 1
        if [ "$UI_REPLY" = "0" ]; then
            UI_EDIT_ABORTED=1
            return 0
        fi
        ui_warn "暂无已配置用户，请先配置 Telegram。"
        return 1
    fi

    rows="$(ui_telegram_configured_user_select_rows)"
    ui_render_page ui_render_telegram_user_select_page_configured "$rows" "false"
    ui_read "选择已配置用户序号，可多选：1,3,5 或 1-3" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$configured_count" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    user_ids="$(jq -r --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      [
        .users[]?
        | select((.telegram.bot_token // "") != "" and (.telegram.chat_id // "") != "")
        | .id
      ] as $ids
      | $idxs[]
      | $ids[. - 1] // empty
    ' "$PFWD_CONFIG_FILE")"
    [ -n "$user_ids" ] || { ui_warn "用户序号不存在"; return 1; }
    UI_REPLY="$user_ids"
}


ui_multiselect_normalize_tokens() {
    local raw="$1"
    raw="${raw// /}"
    raw="${raw#,}"
    raw="${raw%,}"
    printf '%s' "$raw"
}


ui_multiselect_parse_indexes() {
    local raw="$1"
    local max_index="$2"
    local allow_zero="${3:-false}"
    local normalized token start end value
    local -A seen=()
    local values=()

    UI_EDIT_ABORTED=0
    UI_REPLY=""
    normalized="$(ui_multiselect_normalize_tokens "$raw")"
    [ -n "$normalized" ] || { ui_warn "请选择至少一个序号"; return 1; }

    if [ "$allow_zero" = "true" ] && [ "$normalized" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi

    while IFS= read -r token; do
        [ -n "$token" ] || { ui_warn "多选格式无效"; return 1; }
        if [[ "$token" =~ ^[0-9]+$ ]]; then
            value="$token"
            if [ "$allow_zero" = "true" ] && [ "$value" = "0" ]; then
                ui_warn "0 只能单独输入表示返回"
                return 1
            fi
            if [ "$value" -lt 1 ] || [ "$value" -gt "$max_index" ]; then
                ui_warn "序号超出范围：$value"
                return 1
            fi
            seen["$value"]=1
        elif [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start="${BASH_REMATCH[1]}"
            end="${BASH_REMATCH[2]}"
            if [ "$start" -gt "$end" ]; then
                ui_warn "范围无效：$token"
                return 1
            fi
            if [ "$start" -lt 1 ] || [ "$end" -gt "$max_index" ]; then
                ui_warn "序号超出范围：$token"
                return 1
            fi
            for ((value = start; value <= end; value++)); do
                seen["$value"]=1
            done
        else
            ui_warn "多选格式无效：$token"
            return 1
        fi
    done < <(printf '%s\n' "$normalized" | tr ',' '\n')

    for ((value = 1; value <= max_index; value++)); do
        if [ -n "${seen[$value]:-}" ]; then
            values+=("$value")
        fi
    done
    [ "${#values[@]}" -gt 0 ] || { ui_warn "请选择至少一个序号"; return 1; }
    UI_REPLY="$(printf '%s\n' "${values[@]}")"
}


ui_resolve_user_ids_by_indexes() {
    local indexes="$1"
    jq -r --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      [ .users[]?.id ] as $ids
      | $idxs[]
      | $ids[. - 1] // empty
    ' "$PFWD_CONFIG_FILE"
}


ui_resolve_forward_ids_by_indexes() {
    local indexes="$1"
    jq -r --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      [ .forwards[]? | { id, user_id, listen_port, sort_id: .id } ]
      | sort_by(.user_id, .listen_port, .sort_id)
      | map(.id) as $ids
      | $idxs[]
      | $ids[. - 1] // empty
    ' "$PFWD_CONFIG_FILE"
}


ui_resolve_user_forward_ids_by_indexes() {
    local user_id="$1"
    local indexes="$2"
    jq -r --arg id "$user_id" --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      [ .forwards[] | select(.user_id == $id) | { id, listen_port, sort_id: .id } ]
      | sort_by(.listen_port, .sort_id)
      | map(.id) as $ids
      | $idxs[]
      | $ids[. - 1] // empty
    ' "$PFWD_CONFIG_FILE"
}


ui_select_users_multi() {
    local allow_zero="${1:-false}"
    UI_EDIT_ABORTED=0
    config_init >/dev/null
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_users_text)"
        return 1
    fi
    local count raw indexes user_ids
    count="$(jq '.users | length' "$PFWD_CONFIG_FILE")"
    ui_render_page ui_render_user_select_page "$allow_zero"
    ui_read "选择用户序号，可多选：1,3,5 或 1-3" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$count" "$allow_zero" || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    user_ids="$(ui_resolve_user_ids_by_indexes "$indexes")"
    [ -n "$user_ids" ] || { ui_warn "用户序号不存在"; return 1; }
    UI_REPLY="$user_ids"
}


ui_select_forwards_multi() {
    local allow_zero="${1:-false}"
    UI_EDIT_ABORTED=0
    config_init >/dev/null
    if ! jq -e '.forwards | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_forwards_text)"
        return 1
    fi
    local count raw indexes forward_ids
    count="$(jq '.forwards | length' "$PFWD_CONFIG_FILE")"
    ui_render_page ui_render_forward_select_page "$allow_zero"
    ui_read "选择转发序号，可多选：1,3,5 或 1-3" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$count" "$allow_zero" || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    forward_ids="$(ui_resolve_forward_ids_by_indexes "$indexes")"
    [ -n "$forward_ids" ] || { ui_warn "转发序号不存在"; return 1; }
    UI_REPLY="$forward_ids"
}


ui_render_forward_scope_page() {
    local title="${1:-选择转发范围}"
    ui_header "$title"
    ui_notice_render
    ui_menu_item 0 "返回上级菜单"
    ui_menu_item 1 "全部转发"
    ui_menu_item 2 "按用户选择"
}


ui_select_forward_scoped() {
    local allow_zero="${1:-false}"
    local scope_title="${2:-选择转发范围}"
    UI_EDIT_ABORTED=0

    while true; do
        ui_render_page ui_render_forward_scope_page "$scope_title" || return 1
        ui_read "选择范围" || return 1
        case "$UI_REPLY" in
            0)
                if [ "$allow_zero" = "true" ]; then
                    UI_EDIT_ABORTED=1
                    return 0
                fi
                ui_warn "无效选择"
                ;;
            1)
                ui_select_forward "$allow_zero" || return 1
                return 0
                ;;
            2)
                ui_select_user true || return 1
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local user_id="$UI_REPLY"
                ui_select_user_forward "$user_id" true || return 1
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                return 0
                ;;
            *)
                ui_warn "无效选择"
                ;;
        esac
    done
}


ui_select_forwards_multi_scoped() {
    local allow_zero="${1:-false}"
    local scope_title="${2:-选择转发范围}"
    UI_EDIT_ABORTED=0

    while true; do
        ui_render_page ui_render_forward_scope_page "$scope_title" || return 1
        ui_read "选择范围" || return 1
        case "$UI_REPLY" in
            0)
                if [ "$allow_zero" = "true" ]; then
                    UI_EDIT_ABORTED=1
                    return 0
                fi
                ui_warn "无效选择"
                ;;
            1)
                ui_select_forwards_multi "$allow_zero" || return 1
                return 0
                ;;
            2)
                ui_select_user true || return 1
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local user_id="$UI_REPLY"
                ui_select_user_forwards_multi "$user_id" true || return 1
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                return 0
                ;;
            *)
                ui_warn "无效选择"
                ;;
        esac
    done
}


ui_batch_print_result() {
    local ok="$1"
    local fail="$2"
    ui_print_line "完成：成功 $ok 项，失败 $fail 项" "$UI_C_ACCENT"
}


ui_select_user_forwards_multi() {
    local user_id="$1"
    local allow_zero="${2:-false}"
    UI_EDIT_ABORTED=0
    config_init >/dev/null
    if ! jq -e --arg id "$user_id" '[.forwards[]? | select(.user_id == $id)] | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "该用户暂无转发"
        return 1
    fi
    local count raw indexes forward_ids index_count
    count="$(jq -r --arg id "$user_id" '[.forwards[] | select(.user_id == $id)] | length' "$PFWD_CONFIG_FILE")"
    ui_render_page ui_render_user_forward_select_page "$user_id" "$allow_zero" "true"
    ui_read "选择转发序号，可多选：1,3,5 或 1-3" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$((count + 1))" "$allow_zero" || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    if printf '%s\n' "$indexes" | grep -qx '1'; then
        index_count="$(printf '%s\n' "$indexes" | sed '/^$/d' | wc -l | tr -d ' ')"
        if [ "$index_count" != "1" ]; then
            ui_warn "选择全部端口时不能和其他序号混合选择"
            return 1
        fi
        forward_ids="$(jq -r --arg id "$user_id" '
          [.forwards[] | select(.user_id == $id) | { id, listen_port, sort_id: .id }]
          | sort_by(.listen_port, .sort_id)
          | .[].id
        ' "$PFWD_CONFIG_FILE")"
    else
        forward_ids="$(ui_resolve_user_forward_ids_by_indexes "$user_id" "$(printf '%s\n' "$indexes" | awk '$1 > 1 { print $1 - 1 }')")"
    fi
    [ -n "$forward_ids" ] || { ui_warn "转发序号不存在"; return 1; }
    UI_REPLY="$forward_ids"
}


ui_resolve_listen_ports_by_forward_ids() {
    local forward_ids="$1"
    jq -r --argjson ids "$(printf '%s\n' "$forward_ids" | jq -Rcs 'split("\n") | map(select(length > 0))')" '
      [ .forwards[] | select(.id as $id | $ids | index($id)) | .listen_port ]
      | unique
      | .[]
    ' "$PFWD_CONFIG_FILE"
}
