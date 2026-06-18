#!/usr/bin/env bash

ui_print_guard_skip_ports() {
    local ports
    ports="$(guard_protocol_skip_ports_display)"
    if [ "$ports" != "-" ]; then
        ui_print_line "当前入口防护跳过端口：$ports" "$UI_C_ACCENT"
    else
        ui_print_line "当前入口防护跳过端口：-" "$UI_C_DIM"
    fi
    ui_print_line "说明：按公网监听端口匹配；命中后跳过入口白名单和协议封锁，不影响出口白名单。" "$UI_C_DIM"
}


ui_guard_skip_port_rows() {
    local start_index="${1:-1}"
    local idx="$start_index"
    while IFS= read -r port; do
        [ -n "$port" ] || continue
        printf '%s\t%s\n' "$idx" "$port"
        idx=$((idx + 1))
    done < <(guard_protocol_skip_ports_tsv)
}


ui_print_guard_skip_port_list() {
    local start_index="${1:-1}"
    ui_table_render $'序号\t端口' "$(ui_guard_skip_port_rows "$start_index")" "2"
}


ui_render_guard_skip_ports_menu_page() {
    ui_header "入口防护跳过端口"
    ui_notice_render
    ui_print_guard_skip_ports
    echo
    ui_menu_item 1 "增加端口"
    ui_menu_item 2 "删除端口"
    ui_menu_item 3 "修改端口"
    ui_menu_item 0 "返回"
}


ui_render_guard_skip_ports_delete_page() {
    ui_header "删除入口防护跳过端口"
    ui_notice_render
    ui_print_guard_skip_ports
    echo
    ui_menu_item 0 "返回"
    ui_menu_item 1 "所有端口"
    ui_print_guard_skip_port_list 2
}


ui_render_guard_skip_ports_update_page() {
    ui_header "修改入口防护跳过端口"
    ui_notice_render
    ui_print_guard_skip_ports
    echo
    ui_menu_item 0 "返回"
    ui_print_guard_skip_port_list
}


ui_guard_skip_ports_apply_list() {
    local ports="$1"
    local cmd=()
    local port
    if [ -z "$ports" ]; then
        ui_run cmd_guard protocols --clear-skip-ports
        return 0
    fi
    cmd=(cmd_guard protocols --replace-skip-ports)
    while IFS= read -r port; do
        [ -n "$port" ] || continue
        cmd+=(--skip-port "$port")
    done <<< "$ports"
    ui_run "${cmd[@]}"
    [ "$UI_STATUS" -eq 0 ] || return 1
}


ui_guard_skip_ports_expand_spec() {
    local spec="$1"
    ui_try_cmd expand_port_spec "$spec" || return 1
    printf '%s\n' "$UI_REPLY"
}


ui_guard_skip_ports_prompt_spec() {
    local title="$1"
    local prompt="$2"
    local default_value="${3:-}"
    local raw_spec expanded_ports
    ui_form_set "$title" "$prompt"
    ui_form_read "端口规格" "$default_value" || { ui_form_reset; return 1; }
    if [ "$UI_EDIT_ABORTED" = "1" ]; then
        ui_form_reset
        return 1
    fi
    if [ -z "$UI_REPLY" ]; then
        ui_form_reset
        ui_warn "必须提供端口规格"
        return 1
    fi
    raw_spec="$UI_REPLY"
    if ! ui_try_cmd expand_port_spec "$raw_spec"; then
        ui_form_reset
        ui_error_from_reply "端口规格无效"
        return 1
    fi
    expanded_ports="$(printf '%s\n' "$UI_REPLY" | awk '!seen[$0]++')"
    ui_form_reset
    [ -n "$expanded_ports" ] || { ui_warn "未解析到有效端口"; return 1; }
    UI_REPLY="$expanded_ports"
    return 0
}


ui_menu_guard_skip_ports_delete() {
    local count raw indexes delete_indexes remaining_ports port idx delete_all
    count="$(guard_protocol_skip_ports_count)"
    if [ "$count" -eq 0 ]; then
        ui_warn "当前没有入口防护跳过端口"
        ui_pause
        return 0
    fi
    while true; do
        ui_render_page ui_render_guard_skip_ports_delete_page
        ui_read "选择端口序号，可单/多/连续选择；0) 返回，1) 删除全部" || return 1
        raw="$UI_REPLY"
        ui_multiselect_parse_indexes "$raw" "$((count + 1))" true || return 1
        [ "$UI_EDIT_ABORTED" = "1" ] && return 0
        indexes="$UI_REPLY"
        delete_all=0
        if printf '%s\n' "$indexes" | grep -qx '1'; then
            if [ "$(printf '%s\n' "$indexes" | sed '/^$/d' | wc -l | tr -d ' ')" != "1" ]; then
                ui_warn "删除全部时不能和其他序号混合选择"
                ui_pause
                continue
            fi
            delete_all=1
        fi
        if [ "$delete_all" -eq 1 ]; then
            ui_run cmd_guard protocols --clear-skip-ports
            if [ "$UI_STATUS" -eq 0 ]; then
                ui_notice_set "入口防护跳过端口已清空" "$UI_C_MENU_NUM"
                ui_pause
            fi
            return 0
        fi
        delete_indexes="$(printf '%s\n' "$indexes" | awk '$1 > 1 { print $1 - 1 }')"
        [ -n "$delete_indexes" ] || { ui_warn "请选择要删除的端口"; ui_pause; continue; }
        remaining_ports=""
        idx=1
        while IFS= read -r port; do
            [ -n "$port" ] || continue
            if ! printf '%s\n' "$delete_indexes" | grep -qx "$idx"; then
                remaining_ports="${remaining_ports}${remaining_ports:+$'\n'}$port"
            fi
            idx=$((idx + 1))
        done < <(guard_protocol_skip_ports_tsv)
        ui_guard_skip_ports_apply_list "$remaining_ports"
        if [ "$UI_STATUS" -eq 0 ]; then
            ui_notice_set "入口防护跳过端口已删除" "$UI_C_MENU_NUM"
            ui_pause
        fi
        return 0
    done
}


ui_menu_guard_skip_ports_add() {
    local new_ports merged_ports
    while true; do
        if ! ui_guard_skip_ports_prompt_spec "增加入口防护跳过端口" "输入公网监听端口规格，支持单端口、逗号多端口和连续范围。0) 返回。" ""; then
            [ "$UI_EDIT_ABORTED" = "1" ] && return 0
            ui_pause
            continue
        fi
        new_ports="$UI_REPLY"
        merged_ports="$(printf '%s\n%s\n' "$(guard_protocol_skip_ports_tsv)" "$new_ports" | sed '/^$/d' | awk '!seen[$0]++')"
        ui_guard_skip_ports_apply_list "$merged_ports"
        if [ "$UI_STATUS" -eq 0 ]; then
            ui_notice_set "入口防护跳过端口已更新" "$UI_C_MENU_NUM"
            ui_pause
        fi
        return 0
    done
}


ui_menu_guard_skip_ports_update() {
    local count raw indexes selected_indexes selected_ports new_ports updated_ports port idx
    count="$(guard_protocol_skip_ports_count)"
    if [ "$count" -eq 0 ]; then
        ui_warn "当前没有入口防护跳过端口"
        ui_pause
        return 0
    fi
    while true; do
        ui_render_page ui_render_guard_skip_ports_update_page
        ui_read "选择要修改的端口序号，可单/多/连续选择；0) 返回" || return 1
        raw="$UI_REPLY"
        ui_multiselect_parse_indexes "$raw" "$count" true || return 1
        [ "$UI_EDIT_ABORTED" = "1" ] && return 0
        selected_indexes="$UI_REPLY"
        [ -n "$selected_indexes" ] || { ui_warn "请选择要修改的端口"; ui_pause; continue; }
        selected_ports=""
        while IFS= read -r idx; do
            [ -n "$idx" ] || continue
            port="$(guard_protocol_skip_ports_tsv | sed -n "${idx}p")"
            [ -n "$port" ] || continue
            selected_ports="${selected_ports}${selected_ports:+,}$port"
        done <<< "$selected_indexes"
        if ! ui_guard_skip_ports_prompt_spec "修改入口防护跳过端口" "输入新的公网监听端口规格；会替换所选端口。0) 返回。" "$selected_ports"; then
            [ "$UI_EDIT_ABORTED" = "1" ] && return 0
            ui_pause
            continue
        fi
        new_ports="$UI_REPLY"
        updated_ports=""
        idx=1
        while IFS= read -r port; do
            [ -n "$port" ] || continue
            if ! printf '%s\n' "$selected_indexes" | grep -qx "$idx"; then
                updated_ports="${updated_ports}${updated_ports:+$'\n'}$port"
            fi
            idx=$((idx + 1))
        done < <(guard_protocol_skip_ports_tsv)
        updated_ports="$(printf '%s\n%s\n' "$updated_ports" "$new_ports" | sed '/^$/d' | awk '!seen[$0]++')"
        ui_guard_skip_ports_apply_list "$updated_ports"
        if [ "$UI_STATUS" -eq 0 ]; then
            ui_notice_set "入口防护跳过端口已更新" "$UI_C_MENU_NUM"
            ui_pause
        fi
        return 0
    done
}


ui_menu_guard_skip_ports() {
    while true; do
        ui_render_page ui_render_guard_skip_ports_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1) ui_menu_guard_skip_ports_add; ui_maybe_pause success ;;
            2)
                ui_menu_guard_skip_ports_delete
                ui_maybe_pause success
                ;;
            3)
                ui_menu_guard_skip_ports_update
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}
