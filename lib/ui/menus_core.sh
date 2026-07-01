#!/usr/bin/env bash

ui_user_telegram_config() {
    local user_id="$1"
    config_init >/dev/null
    jq -c --arg id "$user_id" '.users[]? | select(.id == $id) | .telegram // {}' "$PFWD_CONFIG_FILE"
}


ui_user_telegram_server_name_default() {
    local current="$1"
    if [ -n "$current" ] && [ "$current" != "null" ]; then
        echo "$current"
    else
        hostname 2>/dev/null || echo pfwd
    fi
}


ui_print_telegram_configured_users() {
    config_init >/dev/null
    ui_print_line "已配置用户" "$UI_C_HEADER"
    if ! jq -e '[.users[]? | select((.telegram.bot_token // "") != "" and (.telegram.chat_id // "") != "")] | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_print_line "暂无已配置用户，请先配置 Telegram。"
        return
    fi
    ui_table_render $'用户\t状态\t定时发送' "$(ui_telegram_configured_user_rows)" "1,3"
}


ui_print_export_import_summary() {
    local rows=""
    rows+="SQLite"$'\t'"$PFWD_DB_FILE"$'\n'
    rows+="配置 cache"$'\t'"$PFWD_CONFIG_FILE"$'\n'
    rows+="状态 cache"$'\t'"$PFWD_STATS_FILE"$'\n'
    rows+="说明"$'\t'"导出会包含主配置和流量状态；导入会覆盖当前内容。"
    ui_table_render $'项目\t值' "$rows" "2"
}


ui_select_forward_table() {
    local allow_zero="${1:-false}"
    config_init >/dev/null
    if ! jq -e '.forwards | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_forwards_text)"
        return 1
    fi
    ui_render_forward_groups "$(ui_forward_select_rows "$allow_zero")" $'序号\t用户\t监听\t目标\t协议\t状态\t到期' "4,2,7,3" "$(ui_empty_forwards_text)"
}


ui_render_forward_select_page() {
    local allow_zero="${1:-false}"
    ui_header "选择转发"
    ui_notice_render
    if [ "$allow_zero" = "true" ]; then
        ui_print_line "0) 返回上级菜单" "$UI_C_ACCENT"
    fi
    ui_select_forward_table false
}


ui_select_forward() {
    local allow_zero="${1:-false}"
    UI_EDIT_ABORTED=0
    ui_render_page ui_render_forward_select_page "$allow_zero" || return 1
    ui_read "选择转发序号" || return 1
    if [ "$allow_zero" = "true" ] && [ "$UI_REPLY" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi
    [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; return 1; }
    local forward_id
    forward_id="$(jq -r --argjson idx "$UI_REPLY" '
      [ .forwards[]? | { id, user_id, listen_port, sort_id: .id } ]
      | sort_by(.user_id, .listen_port, .sort_id)
      | .[$idx - 1].id // ""
    ' "$PFWD_CONFIG_FILE")"
    [ -n "$forward_id" ] || { ui_warn "转发序号不存在"; return 1; }
    UI_REPLY="$forward_id"
}


ui_select_user_forward_table() {
    local user_id="$1"
    local allow_zero="${2:-false}"
    config_init >/dev/null
    if ! jq -e --arg id "$user_id" '[.forwards[]? | select(.user_id == $id)] | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "该用户暂无转发"
        return 1
    fi
    ui_table_render $'序号\t监听\t目标\t协议\t状态\t到期' "$(ui_user_forward_select_rows "$user_id" "$allow_zero")" "3,6,2"
}


ui_render_user_forward_select_page() {
    local user_id="$1"
    local allow_zero="${2:-false}"
    local include_all="${3:-false}"
    ui_header "选择转发"
    ui_notice_render
    if [ "$allow_zero" = "true" ]; then
        ui_print_line "0) 返回上级菜单" "$UI_C_ACCENT"
    fi
    ui_print_line "用户：$user_id" "$UI_C_HEADER"
    ui_table_render $'序号\t监听\t目标\t协议\t状态\t到期' "$(ui_user_forward_select_rows "$user_id" false "$include_all")" "3,6,2"
}


ui_select_user_forward() {
    local user_id="$1"
    local allow_zero="${2:-false}"
    UI_EDIT_ABORTED=0
    ui_render_page ui_render_user_forward_select_page "$user_id" "$allow_zero" || return 1
    ui_read "选择转发序号" || return 1
    if [ "$allow_zero" = "true" ] && [ "$UI_REPLY" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi
    [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; return 1; }
    local forward_id
    forward_id="$(jq -r --arg id "$user_id" --argjson idx "$UI_REPLY" '
      [ .forwards[] | select(.user_id == $id) | { id, listen_port, sort_id: .id } ]
      | sort_by(.listen_port, .sort_id)
      | .[$idx - 1].id // ""
    ' "$PFWD_CONFIG_FILE")"
    [ -n "$forward_id" ] || { ui_warn "转发序号不存在"; return 1; }
    UI_REPLY="$forward_id"
}


ui_select_traffic_scope() {
    local user_id="$1"
    UI_EDIT_ABORTED=0
    echo "0) 返回上级菜单"
    echo "1) 用户所有端口"
    echo "2) 选择端口，可多选"
    ui_read "作用范围" "1" || return 1
    case "$UI_REPLY" in
        0)
            UI_EDIT_ABORTED=1
            return 0
            ;;
        1|"") UI_REPLY="user:$user_id" ;;
        2)
            ui_select_user_forwards_multi "$user_id" true || return 1
            [ "$UI_EDIT_ABORTED" = "1" ] && return 0
            UI_REPLY="forward-list:$UI_REPLY"
            ;;
        *) ui_warn "无效选择"; return 1 ;;
    esac
}


ui_menu_users() {
    while true; do
        ui_render_page ui_render_users_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_read "用户名" || continue
                UI_REPLY="$(normalize_user_id "$UI_REPLY")"
                [ -n "$UI_REPLY" ] || { ui_warn "用户名不能为空"; ui_pause; continue; }
                ui_run cmd_user add "$UI_REPLY"
                if [ "$UI_STATUS" -eq 0 ]; then
                    ui_notice_set "用户已添加：$UI_REPLY" "$UI_C_MENU_NUM"
                fi
                ui_maybe_pause success
                ;;
            2)
                ui_select_users_multi true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local user_ids="$UI_REPLY" has_forwards="" confirm_prompt=""
                ui_print_user_delete_preview "$user_ids"
                has_forwards="$UI_REPLY"
                if [ "$has_forwards" = "true" ]; then
                    confirm_prompt="输入 delete 确认删除用户及其关联转发"
                else
                    confirm_prompt="输入 delete 确认批量删除"
                fi
                if ui_confirm_text "delete" "$confirm_prompt"; then
                    local ok=0 fail=0
                    while IFS= read -r user_id; do
                        [ -n "$user_id" ] || continue
                        ui_run_capture cmd_user delete "$user_id" --cascade
                        if [ "$UI_STATUS" -eq 0 ]; then
                            ok=$((ok + 1))
                        else
                            fail=$((fail + 1))
                            if [ -n "$UI_REPLY" ]; then
                                ui_error "$UI_REPLY"
                            else
                                ui_error "删除失败：$user_id"
                            fi
                        fi
                    done <<< "$user_ids"
                    ui_batch_print_result "$ok" "$fail"
                    ui_notice_set "批量删除用户完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                else
                    ui_warn "已取消"
                fi
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_menu_add_forward() {
    local preset_user_id="${1:-}"
    local user_id remote_host remote_port remote listen_ip listen_port random_range stop_at protocol traffic_mode traffic_ratio comment args=()
    local user_defaults="" default_rate="" default_stop_at="" default_traffic_mode="" stop_prompt=""
    ui_form_set "添加转发" "端口支持单端口、逗号分隔多端口如 443,553，或连续范围如 1000-1005；监听端口和目标端口数量需一致。输入 0 返回上级菜单。"
    if [ -n "$preset_user_id" ]; then
        user_id="$preset_user_id"
    else
        ui_select_user true || return 0
        [ "$UI_EDIT_ABORTED" = "1" ] && return 0
        user_id="$UI_REPLY"
    fi
    user_defaults="$(config_user_forward_defaults_json "$user_id")"
    default_rate="$(jq -r '.rate // ""' <<< "$user_defaults")"
    default_stop_at="$(jq -r '.stop_at // ""' <<< "$user_defaults")"
    default_traffic_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$user_defaults")"
    ui_form_add_kv "用户" "$user_id"
    [ -z "$default_rate" ] || ui_form_add_kv "默认端口速率" "$default_rate"
    ui_form_read "目标 IP/域名" || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    remote_host="$UI_REPLY"
    ui_form_add_kv "目标 IP/域名" "$remote_host"
    ui_form_read "目标端口，支持 443,553 或 1000-1005" || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    remote_port="$UI_REPLY"
    remote="$(ui_join_remote "$remote_host" "$remote_port")"
    ui_form_add_kv "目标端口" "$remote_port"
    ui_form_read "监听 IP，留空默认双栈" "$(ui_config_value '.settings.default_listen_ip // "::"')" || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    listen_ip="$UI_REPLY"
    ui_form_add_kv "监听 IP" "$listen_ip"
    ui_form_read "固定监听端口，支持 443,553 或 1000-1005；留空则使用随机端口" || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    listen_port="$UI_REPLY"
    if [ -z "$listen_port" ]; then
        ui_form_add_kv "监听端口" "随机"
        ui_form_read "随机端口范围" "$(ui_config_value '.settings.default_random_port_range // "20000-30000"')" || { ui_form_reset; return 0; }
        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
        random_range="$UI_REPLY"
    else
        random_range=""
        ui_form_add_kv "监听端口" "$listen_port"
    fi
    [ -z "$random_range" ] || ui_form_add_kv "随机端口范围" "$random_range"
    if [ -n "$default_stop_at" ]; then
        stop_prompt="到期日期 YYYYMMDD，支持 +7/7d；回车继承默认值，输入 - 不限期"
    else
        stop_prompt="到期日期 YYYYMMDD，支持 +7/7d，留空不限期"
    fi
    ui_form_read "$stop_prompt" "$default_stop_at" || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    stop_at="$UI_REPLY"
    ui_form_add_kv "到期日期" "$stop_at"
    ui_select_protocol "转发协议" || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    protocol="$UI_REPLY"
    ui_form_add_kv "转发协议" "$(ui_protocol_label "$protocol")"
    ui_select_traffic_mode "计费模式" false "$default_traffic_mode" true || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    traffic_mode="$UI_TRAFFIC_MODE"
    ui_form_add_kv "计费模式" "$( [ "$traffic_mode" = "one-way" ] && echo "单向计费" || echo "双向计费" )"
    ui_read_traffic_ratio "流量倍率，默认 1.0" "1.0" true || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    traffic_ratio="$UI_TRAFFIC_RATIO"
    ui_form_add_kv "倍率" "$(format_ratio "$traffic_ratio")"
    ui_form_read "备注，留空不设置" || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    comment="$UI_REPLY"
    ui_form_add_kv "备注" "$comment"
    ui_select_mss_mode "MSS 处理方式" "$remote_host" "" "" true || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    case "$UI_MSS_MODE" in
        clamp) ui_form_add_kv "MSS" "Clamp" ;;
        set) ui_form_add_kv "MSS" "$UI_MSS_VALUE" ;;
        *) ui_form_add_kv "MSS" "-" ;;
    esac
    ui_select_snat_mode "SNAT 处理方式" "masquerade" "" true || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    if [ "$UI_SNAT_MODE" = "snat" ]; then
        ui_form_add_kv "SNAT" "$UI_SNAT_SOURCE"
    else
        ui_form_add_kv "SNAT" "masquerade"
    fi

    args=(--user-id "$user_id" --remote "$remote" --listen-ip "$listen_ip" --protocol "$protocol" --traffic-mode "$traffic_mode" --traffic-ratio "$traffic_ratio")
    if [ -n "$listen_port" ]; then
        args+=(--listen-port "$listen_port")
    else
        args+=(--random-port "$random_range")
    fi
    [ -z "$stop_at" ] || args+=(--stop-at "$stop_at")
    case "$UI_MSS_MODE" in
        clamp) args+=(--mss-clamp) ;;
        set) args+=(--mss "$UI_MSS_VALUE") ;;
    esac
    if [ "$UI_SNAT_MODE" = "snat" ]; then
        args+=(--snat-source "$UI_SNAT_SOURCE")
    else
        args+=(--masquerade)
    fi
    [ -z "$comment" ] || args+=(--comment "$comment")

    ui_form_reset
    ui_run cmd_add "${args[@]}"
}


ui_menu_forwards() {
    local user_id=""
    while true; do
        if [ -z "$user_id" ]; then
            ui_render_page ui_render_forwards_select_user_page
            ui_read "选择用户序号" || return 0
            if ! ui_has_users; then
                case "$UI_REPLY" in
                    0) return 0 ;;
                    *) ui_require_users; ui_pause; continue ;;
                esac
            fi
            case "$UI_REPLY" in
                0) return 0 ;;
                '') ui_warn "无效序号"; ui_pause; continue ;;
            esac
            [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; ui_pause; continue; }
            user_id="$(jq -r --argjson idx "$UI_REPLY" '.users[$idx - 1].id // ""' "$PFWD_CONFIG_FILE")"
            [ -n "$user_id" ] || { ui_warn "用户序号不存在"; ui_pause; user_id=""; continue; }
        fi

        while true; do
            ui_render_page ui_render_forwards_menu_page "$user_id"
            ui_read "选择" || return 0
            case "$UI_REPLY" in
                1)
                    ui_menu_add_forward "$user_id"
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "转发已添加" "$UI_C_MENU_NUM"
                    ui_maybe_pause success
                    ;;
                2)
                    ui_select_user_forward "$user_id" true || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    local forward_id="$UI_REPLY" current="" current_listen_ip="" current_listen_port="" current_remote_host="" current_remote_port="" current_stop_at="" current_protocol="" current_mode="" current_ratio="" current_comment=""
                    local current_mss_mode="" current_mss_value="" current_snat_mode="" current_snat_source=""
                    local listen_ip="" listen_port="" remote_host="" remote_port="" stop_at="" protocol="" traffic_mode="" traffic_ratio="" comment="" args=()
                    current="$(jq -c --arg id "$forward_id" '.forwards[] | select(.id == $id)' "$PFWD_CONFIG_FILE")"
                    current_listen_ip="$(jq -r '.listen_ip // "::"' <<< "$current")"
                    current_listen_port="$(jq -r '.listen_port' <<< "$current")"
                    current_remote_host="$(jq -r '.remote_host' <<< "$current")"
                    current_remote_port="$(jq -r '.remote_port' <<< "$current")"
                    current_stop_at="$(jq -r '.stop_at // ""' <<< "$current")"
                    current_protocol="$(jq -r '.protocol // "tcp_udp"' <<< "$current")"
                    current_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$current")"
                    current_ratio="$(jq -r '(.traffic_ratio // 1) | tostring' <<< "$current")"
                    current_comment="$(jq -r '.comment // ""' <<< "$current")"
                    current_mss_mode="$(jq -r '.net.mss_mode // ""' <<< "$current")"
                    current_mss_value="$(jq -r '.net.mss_value // ""' <<< "$current")"
                    current_snat_mode="$(jq -r '.net.snat_mode // "masquerade"' <<< "$current")"
                    current_snat_source="$(jq -r '.net.snat_source // ""' <<< "$current")"

                    ui_form_set "修改转发" "回车保留当前值，0 返回上级；端口支持单端口、逗号分隔多端口如 443,553，或连续范围如 1000-1005；监听端口和目标端口数量需一致；转发到期日输入 - 清空为不限期，备注输入 - 清空。"
                    ui_form_add_kv "用户" "$user_id"
                    ui_form_add_kv "转发 ID" "$forward_id"
                    ui_form_add_kv "当前监听 IP" "$current_listen_ip"
                    ui_form_add_kv "当前监听端口" "$current_listen_port"
                    ui_form_add_kv "当前目标 IP/域名" "$current_remote_host"
                    ui_form_add_kv "当前目标端口" "$current_remote_port"
                    ui_form_add_kv "当前协议" "$(ui_protocol_label "$current_protocol")"
                    ui_form_add_kv "当前计费模式" "$( [ "$current_mode" = "one-way" ] && echo "单向计费" || echo "双向计费" )"
                    ui_form_add_kv "当前倍率" "$(format_ratio "$current_ratio")"
                    ui_form_add_kv "当前到期日" "${current_stop_at:-}"
                    ui_form_add_kv "当前备注" "$current_comment"

                    ui_form_edit_read "监听 IP" "$current_listen_ip" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    listen_ip="$UI_REPLY"
                    ui_form_add_kv "新监听 IP" "$listen_ip"

                    ui_form_edit_read "监听端口，支持 443,553 或 1000-1005" "$current_listen_port" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    listen_port="$UI_REPLY"
                    ui_form_add_kv "新监听端口" "$listen_port"

                    ui_form_edit_read "目标 IP/域名" "$current_remote_host" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    remote_host="$UI_REPLY"
                    ui_form_add_kv "新目标 IP/域名" "$remote_host"

                    ui_form_edit_read "目标端口，支持 443,553 或 1000-1005" "$current_remote_port" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    remote_port="$UI_REPLY"
                    ui_form_add_kv "新目标端口" "$remote_port"

                    ui_form_edit_read "转发到期日 YYYYMMDD，支持 +7/7d" "${current_stop_at:-}" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    stop_at="$UI_REPLY"
                    ui_form_add_kv "新到期日" "$stop_at"

                    ui_select_protocol_edit "转发协议" "$current_protocol" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    protocol="$UI_REPLY"
                    [ -z "$protocol" ] || ui_form_add_kv "新协议" "$(ui_protocol_label "$protocol")"

                    ui_select_traffic_mode_edit "计费模式" "$current_mode" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    traffic_mode="$UI_TRAFFIC_MODE"
                    [ -z "$traffic_mode" ] || ui_form_add_kv "新计费模式" "$( [ "$traffic_mode" = "one-way" ] && echo "单向计费" || echo "双向计费" )"

                    ui_read_traffic_ratio_edit "流量倍率" "$current_ratio" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    traffic_ratio="$UI_TRAFFIC_RATIO"
                    ui_form_add_kv "新倍率" "$(format_ratio "$traffic_ratio")"

                    ui_form_edit_read "备注" "$current_comment" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    comment="$UI_REPLY"
                    ui_form_add_kv "新备注" "$comment"

                    ui_select_mss_mode_edit "MSS 处理方式" "$current_mss_mode" "$current_mss_value" "$remote_host" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    case "$UI_MSS_MODE" in
                        clamp) ui_form_add_kv "新 MSS" "Clamp" ;;
                        set) ui_form_add_kv "新 MSS" "$UI_MSS_VALUE" ;;
                        __CLEAR__) ui_form_add_kv "新 MSS" "清空" ;;
                    esac
                    ui_select_snat_mode_edit "SNAT 处理方式" "$current_snat_mode" "$current_snat_source" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    case "$UI_SNAT_MODE" in
                        snat) ui_form_add_kv "新 SNAT" "$UI_SNAT_SOURCE" ;;
                        masquerade) ui_form_add_kv "新 SNAT" "masquerade" ;;
                    esac

                    args=(--forward-id "$forward_id")
                    [ "$listen_ip" = "$current_listen_ip" ] || args+=(--listen-ip "$listen_ip")
                    [ "$listen_port" = "$current_listen_port" ] || args+=(--listen-port "$listen_port")
                    [ "$remote_host" = "$current_remote_host" ] || args+=(--remote-host "$remote_host")
                    [ "$remote_port" = "$current_remote_port" ] || args+=(--remote-port "$remote_port")
                    if [ "$stop_at" = "-" ]; then
                        [ -n "$current_stop_at" ] && args+=(--clear-stop-at)
                    elif [ "$stop_at" != "$current_stop_at" ]; then
                        [ -n "$stop_at" ] && args+=(--stop-at "$stop_at")
                    fi
                    [ -z "$protocol" ] || [ "$protocol" = "$current_protocol" ] || args+=(--protocol "$protocol")
                    [ -z "$traffic_mode" ] || [ "$traffic_mode" = "$current_mode" ] || args+=(--traffic-mode "$traffic_mode")
                    [ -z "$traffic_ratio" ] || [ "$traffic_ratio" = "$current_ratio" ] || args+=(--traffic-ratio "$traffic_ratio")
                    if [ "$comment" = "-" ]; then
                        [ -n "$current_comment" ] && args+=(--clear-comment)
                    elif [ "$comment" != "$current_comment" ]; then
                        args+=(--comment "$comment")
                    fi
                    case "$UI_MSS_MODE" in
                        clamp)
                            if [ "$current_mss_mode" != "clamp" ]; then
                                args+=(--mss-clamp)
                            fi
                            ;;
                        set)
                            if [ "$current_mss_mode" != "set" ] || [ "$UI_MSS_VALUE" != "$current_mss_value" ]; then
                                args+=(--mss "$UI_MSS_VALUE")
                            fi
                            ;;
                        __CLEAR__)
                            if [ -n "$current_mss_mode" ] || [ -n "$current_mss_value" ]; then
                                args+=(--clear-mss)
                            fi
                            ;;
                    esac
                    case "$UI_SNAT_MODE" in
                        snat)
                            if [ "$current_snat_mode" != "snat" ] || [ "$UI_SNAT_SOURCE" != "$current_snat_source" ]; then
                                args+=(--snat-source "$UI_SNAT_SOURCE")
                            fi
                            ;;
                        masquerade)
                            if [ "$current_snat_mode" != "masquerade" ] || [ -n "$current_snat_source" ]; then
                                args+=(--masquerade)
                            fi
                            ;;
                    esac

                    if [ "${#args[@]}" -eq 2 ]; then
                        ui_warn "未修改"
                    else
                        ui_form_reset
                        ui_run cmd_forward_update "${args[@]}"
                        [ "$UI_STATUS" -eq 0 ] && ui_notice_set "转发已更新：$forward_id" "$UI_C_MENU_NUM"
                    fi
                    ui_form_reset
                    ui_maybe_pause success
                    ;;
                3)
                    ui_select_user_forwards_multi "$user_id" true || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    local stop_ids="$UI_REPLY" ok=0 fail=0
                    while IFS= read -r forward_id; do
                        [ -n "$forward_id" ] || continue
                        if ui_try_cmd cmd_toggle_forward false "$forward_id"; then
                            ok=$((ok + 1))
                        else
                            fail=$((fail + 1))
                            ui_error_from_reply "暂停失败：$forward_id"
                        fi
                    done <<< "$stop_ids"
                    ui_batch_print_result "$ok" "$fail"
                    ui_notice_set "批量暂停完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                    ;;
                4)
                    ui_select_user_forwards_multi "$user_id" true || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    local start_ids="$UI_REPLY" ok=0 fail=0
                    while IFS= read -r forward_id; do
                        [ -n "$forward_id" ] || continue
                        if ui_try_cmd cmd_toggle_forward true "$forward_id"; then
                            ok=$((ok + 1))
                        else
                            fail=$((fail + 1))
                            ui_error_from_reply "恢复失败：$forward_id"
                        fi
                    done <<< "$start_ids"
                    ui_batch_print_result "$ok" "$fail"
                    ui_notice_set "批量恢复完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                    ;;
                5)
                    ui_select_user_forwards_multi "$user_id" true || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    local delete_ids="$UI_REPLY" summary=""
                    while IFS= read -r forward_id; do
                        [ -n "$forward_id" ] || continue
                        summary+="$(
                            jq -r --arg id "$forward_id" '
                              .forwards[] | select(.id == $id) |
                              "\(.id)  监听:\(.listen_port)"
                            ' "$PFWD_CONFIG_FILE"
                        )"$'\n'
                    done <<< "$delete_ids"
                    summary="${summary%$'\n'}"
                    ui_print_line "将删除以下转发：" "$UI_C_WARN"
                    printf '%s\n' "$summary"
                    if ui_confirm_text "delete" "输入 delete 确认批量删除"; then
                        local ok=0 fail=0
                        while IFS= read -r forward_id; do
                            [ -n "$forward_id" ] || continue
                            if ui_try_cmd cmd_delete "$forward_id"; then
                                ok=$((ok + 1))
                            else
                                fail=$((fail + 1))
                                ui_error_from_reply "删除失败：$forward_id"
                            fi
                        done <<< "$delete_ids"
                        ui_batch_print_result "$ok" "$fail"
                        ui_notice_set "批量删除转发完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                    else
                        ui_warn "已取消"
                    fi
                    ;;
                0)
                    user_id=""
                    break
                    ;;
                *)
                    ui_warn "无效选择"
                    ui_pause
                    ;;
            esac
        done
    done
}


ui_menu_expire_limit() {
    local user_id=""
    while true; do
        if [ -z "$user_id" ]; then
            ui_render_page ui_render_traffic_select_user_page
            ui_read "选择用户序号" || return 0
            if ! ui_has_users; then
                case "$UI_REPLY" in
                    0) return 0 ;;
                    *) ui_require_users; ui_pause; continue ;;
                esac
            fi
            case "$UI_REPLY" in
                0) return 0 ;;
                '')
                    ui_warn "无效序号"
                    ui_pause
                    continue
                    ;;
            esac
            [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; ui_pause; continue; }
            user_id="$(jq -r --argjson idx "$UI_REPLY" '.users[$idx - 1].id // ""' "$PFWD_CONFIG_FILE")"
            [ -n "$user_id" ] || { ui_warn "用户序号不存在"; ui_pause; user_id=""; continue; }
        fi

        while true; do
            ui_render_page ui_render_traffic_user_menu_page "$user_id"
            ui_read "选择" || return 0
            case "$UI_REPLY" in
                1)
                    local scope="" current_stop_at=""
                    ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    scope="$UI_REPLY"
                    ui_form_set "流量管理" "修改转发到期日。支持 YYYYMMDD 或 YYYY-MM-DD HH:MM；仅日期默认 00:00。输入 - 清空，0 返回上级。"
                    ui_form_add_kv "用户" "$user_id"
                    ui_form_add_kv "作用范围" "$scope"
                    if [[ "$scope" == user:* ]]; then
                        ui_form_edit_read "转发到期日，支持 YYYYMMDD[ HH:MM]、+7/7d，输入 - 清空" || { ui_form_reset; ui_pause; continue; }
                        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                        if [ -z "$UI_REPLY" ]; then
                            ui_warn "未修改"
                        elif [ "$UI_REPLY" = "-" ]; then
                            ui_run cmd_expire user-clear --user-id "${scope#user:}"
                        else
                            ui_run cmd_expire user-set --user-id "${scope#user:}" --stop-at "$UI_REPLY"
                        fi
                    else
                        ui_form_edit_read "转发到期日，支持 YYYYMMDD[ HH:MM]、+7/7d，输入 - 清空" || { ui_form_reset; ui_pause; continue; }
                        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                        local stop_value="$UI_REPLY" ok=0 fail=0
                        if [ -z "$stop_value" ]; then
                            ui_warn "未修改"
                        else
                            while IFS= read -r forward_id; do
                                [ -n "$forward_id" ] || continue
                                current_stop_at="$(jq -r --arg id "$forward_id" '.forwards[] | select(.id == $id) | (.stop_at // "")' "$PFWD_CONFIG_FILE")"
                                if [ "$stop_value" = "$current_stop_at" ]; then
                                    continue
                                elif [ "$stop_value" = "-" ]; then
                                    if ui_try_cmd cmd_expire clear "$forward_id"; then
                                        ok=$((ok + 1))
                                    else
                                        fail=$((fail + 1))
                                        ui_error_from_reply "清除到期失败：$forward_id"
                                    fi
                                else
                                    if ui_try_cmd cmd_expire set "$forward_id" --stop-at "$stop_value"; then
                                        ok=$((ok + 1))
                                    else
                                        fail=$((fail + 1))
                                        ui_error_from_reply "设置到期失败：$forward_id"
                                    fi
                                fi
                            done <<< "${scope#forward-list:}"
                            ui_batch_print_result "$ok" "$fail"
                        fi
                    fi
                    ui_form_reset
                    ui_maybe_pause success
                    ;;
                2)
                    local scope="" traffic="" rate="" args=() current_mode="" traffic_mode="" current_scope_mode=""
                    ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    scope="$UI_REPLY"
                    ui_form_set "流量管理" "修改流量配额、速率和统计模式。留空不改，0 返回上级。"
                    ui_form_add_kv "用户" "$user_id"
                    ui_form_add_kv "作用范围" "$scope"
                    if [[ "$scope" == user:* ]]; then
                        ui_form_read_allow_zero_value "用户总流量，数字默认 GB；例如 100 / 1.5GB / 512MB；0 清除，留空不改" || { ui_form_reset; continue; }
                    else
                        ui_form_read_allow_zero_value "总流量，数字默认 GB；例如 100 / 1.5GB / 512MB；0 清除，留空不改" || { ui_form_reset; continue; }
                    fi
                    traffic="$UI_REPLY"
                    ui_form_add_kv "总流量" "$traffic"
                    if [[ "$scope" == user:* ]]; then
                        ui_form_read_allow_zero_value "每个端口速率，数字默认 Mbps；例如 50 / 12.5Mbps / 1.2Gbps；0 清除，留空不改" || { ui_form_reset; continue; }
                    else
                        ui_form_read_allow_zero_value "速率，数字默认 Mbps；例如 50 / 12.5Mbps / 1.2Gbps；0 清除，留空不改" || { ui_form_reset; continue; }
                    fi
                    rate="$UI_REPLY"
                    ui_form_add_kv "速率" "$rate"
                    if [[ "$scope" == user:* ]]; then
                        current_scope_mode="$(jq -r --arg id "${scope#user:}" '
                          [ .forwards[] | select(.user_id == $id) | (.traffic_mode // "two-way") ]
                          | unique
                          | if length == 1 then .[0] else "" end
                        ' "$PFWD_CONFIG_FILE")"
                        current_mode="$current_scope_mode"
                    else
                        current_scope_mode="$(jq -r --argjson ids "$(printf '%s\n' "${scope#forward-list:}" | jq -Rcs 'split("\n") | map(select(length > 0))')" '
                          [ .forwards[] | select(.id as $id | $ids | index($id)) | (.traffic_mode // "two-way") ]
                          | unique
                          | if length == 1 then .[0] else "" end
                        ' "$PFWD_CONFIG_FILE")"
                        current_mode="$current_scope_mode"
                    fi
                    ui_select_traffic_mode_edit "流量模式，回车不改，0 返回" "$current_mode" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                    traffic_mode="$UI_TRAFFIC_MODE"
                    [ -z "$traffic_mode" ] || ui_form_add_kv "流量模式" "$( [ "$traffic_mode" = "one-way" ] && echo "单向" || echo "双向" )"
                    [ -z "$traffic" ] || traffic="$(normalize_ui_traffic_input "$traffic")"
                    [ -z "$rate" ] || rate="$(normalize_ui_rate_input "$rate")"
                    if [[ "$scope" == user:* ]]; then
                        args=(set --user-id "${scope#user:}")
                    else
                        args=(set --forward-id "${scope#forward:}")
                    fi
                    if [[ "$scope" == user:* ]]; then
                        local changed="false" user_limit_args=()
                        if [ -n "$traffic" ]; then
                            user_limit_args=(set --user-id "${scope#user:}" --traffic "$traffic")
                            ui_run cmd_limit "${user_limit_args[@]}"
                            changed="true"
                        fi
                        if [ -n "$rate" ] || [ -n "$traffic_mode" ]; then
                            args=(--user-id "${scope#user:}")
                            [ -n "$rate" ] && args+=(--rate "$rate")
                            [ -n "$traffic_mode" ] && args+=(--traffic-mode "$traffic_mode")
                            ui_run cmd_user_forwards_limit "${args[@]}"
                            changed="true"
                        fi
                        if [ "$changed" = "false" ]; then
                            ui_warn "未修改"
                        fi
                    else
                        if [ -n "$traffic" ] || [ -n "$rate" ] || [ -n "$traffic_mode" ]; then
                            local ok=0 fail=0
                            while IFS= read -r forward_id; do
                                [ -n "$forward_id" ] || continue
                                args=(set --forward-id "$forward_id")
                                [ -z "$traffic" ] || args+=(--traffic "$traffic")
                                [ -z "$rate" ] || args+=(--rate "$rate")
                                [ -z "$traffic_mode" ] || args+=(--traffic-mode "$traffic_mode")
                                if ui_try_cmd cmd_limit "${args[@]}"; then
                                    ok=$((ok + 1))
                                else
                                    fail=$((fail + 1))
                                    ui_error_from_reply "端口设置失败：$forward_id"
                                fi
                            done <<< "${scope#forward-list:}"
                            ui_batch_print_result "$ok" "$fail"
                        else
                            ui_warn "未修改"
                        fi
                    fi
                    ui_form_reset
                    ui_maybe_pause success
                    ;;
                3)
                    ui_form_set "流量管理" "重置统计或设置重置日。重置日支持 15 或 15 09:30；仅日期默认 00:00，0 关闭。"
                    ui_form_add_kv "用户" "$user_id"
                    ui_form_select_read "选择" "" "1) 立即重置" "2) 设置每月重置日" "0) 返回" || { ui_form_reset; continue; }
                    local reset_action="$UI_REPLY" scope="" args=()
                    case "$reset_action" in
                        1)
                            ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                            [ "$UI_EDIT_ABORTED" = "1" ] && continue
                            scope="$UI_REPLY"
                            if [[ "$scope" == user:* ]]; then
                                args=(--user-id "${scope#user:}")
                            else
                                local ok=0 fail=0
                                while IFS= read -r forward_id; do
                                    [ -n "$forward_id" ] || continue
                                    if ui_try_cmd cmd_traffic reset-now --forward-id "$forward_id"; then
                                        ok=$((ok + 1))
                                    else
                                        fail=$((fail + 1))
                                        ui_error_from_reply "立即重置失败：$forward_id"
                                    fi
                                done <<< "${scope#forward-list:}"
                                ui_batch_print_result "$ok" "$fail"
                                ui_form_reset
                                ui_pause
                                continue
                            fi
                            ui_run cmd_traffic reset-now "${args[@]}"
                            ;;
                        2)
                            ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                            [ "$UI_EDIT_ABORTED" = "1" ] && continue
                            scope="$UI_REPLY"
                            ui_form_add_kv "作用范围" "$scope"
                            ui_form_read_allow_zero_value "每月重置日，支持 15 或 15 09:30；0 关闭自动重置" || { ui_form_reset; continue; }
                            local day="$UI_REPLY"
                            if [ -z "$day" ]; then
                                ui_warn "未修改"
                                ui_form_reset
                                ui_pause
                                continue
                            fi
                            if [[ "$scope" == user:* ]]; then
                                args=(set --user-id "${scope#user:}" --day "$day")
                            else
                                local ok=0 fail=0
                                while IFS= read -r forward_id; do
                                    [ -n "$forward_id" ] || continue
                                    if ui_try_cmd cmd_traffic reset-day set --forward-id "$forward_id" --day "$day"; then
                                        ok=$((ok + 1))
                                    else
                                        fail=$((fail + 1))
                                        ui_error_from_reply "设置重置日失败：$forward_id"
                                    fi
                                done <<< "${scope#forward-list:}"
                                ui_batch_print_result "$ok" "$fail"
                                ui_form_reset
                                ui_pause
                                continue
                            fi
                            ui_run cmd_traffic reset-day "${args[@]}"
                            ;;
                        0)
                            ui_form_reset
                            continue
                            ;;
                        *) ui_warn "无效选择" ;;
                    esac
                    ui_form_reset
                    ui_maybe_pause success
                    ;;
                4)
                    local scope="" used="" args=()
                    ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    scope="$UI_REPLY"
                    ui_form_set "流量管理" "设置计费用量。输入 0 返回上级。"
                    ui_form_add_kv "用户" "$user_id"
                    ui_form_add_kv "作用范围" "$scope"
                    ui_form_edit_read "已用流量，数字默认 GB；例如 100 / 100GB / 512MB" || { ui_form_reset; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    used="$UI_REPLY"
                    if [ -z "$used" ]; then
                        ui_warn "未修改"
                        ui_form_reset
                        ui_pause
                        continue
                    fi
                    used="$(normalize_ui_traffic_input "$used")"
                    if [[ "$scope" == user:* ]]; then
                        args=(used set --user-id "${scope#user:}" --used "$used")
                    else
                        local ok=0 fail=0
                        while IFS= read -r forward_id; do
                            [ -n "$forward_id" ] || continue
                            if ui_try_cmd cmd_traffic used set --forward-id "$forward_id" --used "$used"; then
                                ok=$((ok + 1))
                            else
                                fail=$((fail + 1))
                                ui_error_from_reply "设置已用流量失败：$forward_id"
                            fi
                        done <<< "${scope#forward-list:}"
                        ui_batch_print_result "$ok" "$fail"
                        ui_form_reset
                        ui_pause
                        continue
                    fi
                    ui_run cmd_traffic "${args[@]}"
                    ui_form_reset
                    ui_maybe_pause success
                    ;;
                0)
                    user_id=""
                    break
                    ;;
                *) ui_warn "无效选择"; ui_pause ;;
            esac
        done
    done
}


ui_menu_telegram() {
    while true; do
        ui_render_page ui_render_telegram_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                UI_EDIT_ABORTED=0
                ui_select_users_for_telegram_config_multi || { ui_pause; continue; }
                [ "${UI_EDIT_ABORTED:-0}" = "1" ] && continue
                local user_id="$UI_REPLY" token="" chat_id="" server_name="" enabled="" tg="" token_default="" chat_id_default="" server_name_default=""
                local selected_users="$UI_REPLY" selected_count target_user ok=0 fail=0
                selected_count="$(printf '%s\n' "$selected_users" | sed '/^$/d' | wc -l | tr -d ' ')"
                if [ "$user_id" = "__ALL_USERS__" ]; then
                    token_default=""
                    chat_id_default=""
                    server_name_default="$(hostname 2>/dev/null || echo pfwd)"
                    enabled="__KEEP__"
                elif [ "$selected_count" = "1" ]; then
                    target_user="$(printf '%s\n' "$selected_users" | sed -n '1p')"
                    tg="$(ui_user_telegram_config "$target_user")"
                    enabled="$(jq -r '.enabled // false' <<< "$tg")"
                    token_default="$(jq -r '.bot_token // ""' <<< "$tg")"
                    chat_id_default="$(jq -r '.chat_id // ""' <<< "$tg")"
                    server_name_default="$(ui_user_telegram_server_name_default "$(jq -r '.server_name // ""' <<< "$tg")")"
                else
                    token_default=""
                    chat_id_default=""
                    server_name_default="$(hostname 2>/dev/null || echo pfwd)"
                    enabled="__KEEP__"
                fi
                ui_form_set "Telegram 通知" "配置 Bot Token、Chat ID 和服务器名称。回车保留默认值，输入 0 返回上级菜单。"
                if [ "$user_id" = "__ALL_USERS__" ]; then
                    ui_form_add_kv "目标用户" "所有用户"
                else
                    ui_form_add_kv "目标用户" "$(printf '%s\n' "$selected_users" | jq -Rrsc 'split("\n") | map(select(length > 0)) | join(", ")')"
                fi
                ui_form_read "Bot Token，例如 123456789:AA..." "$token_default" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                token="$UI_REPLY"
                if [ -z "$token" ]; then
                    ui_form_reset
                    ui_notice_set "Bot Token 不能为空，请填写或输入 0 返回。" "$UI_C_WARN"
                    continue
                fi
                ui_form_add_kv "Bot Token" "$token"
                ui_form_read "Chat ID，例如 123456789 或 -1001234567890" "$chat_id_default" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                chat_id="$UI_REPLY"
                if [ -z "$chat_id" ]; then
                    ui_form_reset
                    ui_notice_set "Chat ID 不能为空，请填写或输入 0 返回。" "$UI_C_WARN"
                    continue
                fi
                ui_form_add_kv "Chat ID" "$chat_id"
                ui_form_read "服务器名称" "$server_name_default" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                server_name="$UI_REPLY"
                ui_form_add_kv "服务器名称" "$server_name"
                if [ "$user_id" = "__ALL_USERS__" ]; then
                    if ! ui_try_cmd cmd_user telegram --all --bot-token "$token" --chat-id "$chat_id" --server-name "$server_name"; then
                        ui_error_from_reply "更新 Telegram 配置失败：全部用户"
                    fi
                else
                    while IFS= read -r target_user; do
                        [ -n "$target_user" ] || continue
                        tg="$(ui_user_telegram_config "$target_user")"
                        enabled="$(jq -r '.enabled // false' <<< "$tg")"
                        if ui_try_cmd cmd_user telegram "$target_user" --bot-token "$token" --chat-id "$chat_id" --server-name "$server_name" --enabled "$enabled"; then
                            ok=$((ok + 1))
                        else
                            fail=$((fail + 1))
                            ui_error_from_reply "更新 Telegram 配置失败：$target_user"
                        fi
                    done <<< "$selected_users"
                    UI_STATUS=0
                    [ "$fail" -eq 0 ] || UI_STATUS=1
                    ui_batch_print_result "$ok" "$fail"
                fi
                ui_form_reset
                if [ "$user_id" = "__ALL_USERS__" ]; then
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "Telegram 配置已更新：全部用户" "$UI_C_MENU_NUM"
                else
                    ui_notice_set "Telegram 配置更新完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                fi
                ui_maybe_pause success
                ;;
            2)
                ui_select_user true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local schedule_user="$UI_REPLY" interval_choice="" interval_value="" daily_time=""
                ui_form_set "Telegram 通知" "留空表示不修改；输入 - 清空对应定时；输入 0 返回上级菜单。"
                ui_form_add_kv "目标用户" "$schedule_user"
                ui_form_read "间隔发送，单位分钟；例如 60" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                interval_choice="$UI_REPLY"
                ui_form_add_kv "间隔发送" "$interval_choice"
                ui_form_read "每日发送时间 HH:MM；例如 09:30" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                daily_time="$UI_REPLY"
                ui_form_add_kv "每日发送时间" "$daily_time"
                if [ "$interval_choice" = "-" ]; then
                    interval_value=""
                else
                    interval_value="${interval_choice:-__KEEP__}"
                fi
                if [ "$daily_time" = "-" ]; then
                    daily_time=""
                elif [ -z "$daily_time" ]; then
                    daily_time="__KEEP__"
                fi
                ui_run cmd_notify_schedule --user-id "$schedule_user" --interval-minutes "$interval_value" --daily-time "$daily_time"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "定时发送已更新：$schedule_user" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_select_configured_users_multi || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local test_ids="$UI_REPLY" ok=0 fail=0
                while IFS= read -r user_id; do
                    [ -n "$user_id" ] || continue
                    if ui_try_cmd cmd_notify_test --user-id "$user_id"; then
                        ok=$((ok + 1))
                    else
                        fail=$((fail + 1))
                        ui_error_from_reply "测试通知失败：$user_id"
                    fi
                done <<< "$test_ids"
                ui_batch_print_result "$ok" "$fail"
                ui_notice_set "测试通知完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                ui_maybe_pause success
                ;;
            4)
                ui_select_users_multi true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local enable_ids="$UI_REPLY" ok=0 fail=0
                while IFS= read -r user_id; do
                    [ -n "$user_id" ] || continue
                    if ui_try_cmd cmd_notify_enable --user-id "$user_id"; then
                        ok=$((ok + 1))
                    else
                        fail=$((fail + 1))
                        ui_error_from_reply "恢复通知失败：$user_id"
                    fi
                done <<< "$enable_ids"
                ui_batch_print_result "$ok" "$fail"
                ui_notice_set "恢复通知完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                ui_maybe_pause success
                ;;
            5)
                ui_select_users_multi true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local disable_ids="$UI_REPLY" ok=0 fail=0
                while IFS= read -r user_id; do
                    [ -n "$user_id" ] || continue
                    if ui_try_cmd cmd_notify_disable --user-id "$user_id"; then
                        ok=$((ok + 1))
                    else
                        fail=$((fail + 1))
                        ui_error_from_reply "暂停通知失败：$user_id"
                    fi
                done <<< "$disable_ids"
                ui_batch_print_result "$ok" "$fail"
                ui_notice_set "暂停通知完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                ui_maybe_pause success
                ;;
            6)
                ui_select_users_multi true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local delete_ids="$UI_REPLY"
                ui_print_line "将删除以下通知配置（Bot Token、Chat ID、服务器名称、间隔/定时设置）：" "$UI_C_WARN"
                printf '%s\n' "$delete_ids"
                if ui_confirm_text "delete" "输入 delete 确认批量删除"; then
                    local ok=0 fail=0
                    while IFS= read -r user_id; do
                        [ -n "$user_id" ] || continue
                        if ui_try_cmd cmd_notify_delete --user-id "$user_id"; then
                            ok=$((ok + 1))
                        else
                            fail=$((fail + 1))
                            ui_error_from_reply "删除通知失败：$user_id"
                        fi
                    done <<< "$delete_ids"
                    ui_batch_print_result "$ok" "$fail"
                    ui_notice_set "删除通知完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                else
                    ui_warn "已取消"
                fi
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_menu_export_import() {
    while true; do
        ui_render_page ui_render_export_import_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_edit_read "导出文件路径" "$(pfwd_default_export_path)" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                ui_run cmd_export "$UI_REPLY"
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "配置已导出：$UI_REPLY" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_edit_read "导入文件路径" "" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                if [ -z "$UI_REPLY" ]; then
                    ui_warn "未修改"
                    ui_pause
                    continue
                fi
                local import_path="$UI_REPLY"
                if ui_confirm_text "import" "输入 import 确认覆盖当前配置"; then
                    ui_run cmd_import "$import_path"
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "配置已导入：$import_path" "$UI_C_MENU_NUM"
                else
                    ui_warn "已取消"
                fi
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_menu_update() {
    ui_clear_screen
    ui_header "更新"
    echo "将检查远端版本，并在确认后更新 pfwd 脚本和服务文件。"
    echo
    if ! service_installation_present; then
        ui_warn "未检测到已安装的 pfwd，请先执行安装。"
        ui_pause
        return 0
    fi
    ui_run cmd_update
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "pfwd 已更新" "$UI_C_MENU_NUM"
    ui_maybe_pause success
}


ui_menu_restart_runtime() {
    ui_clear_screen
    ui_header "重启服务"
    echo "将先停止当前 pfwd 的 XDP/nft/tc 运行态，再按当前配置重新应用。"
    echo "这会短暂中断当前转发。"
    echo
    if ! service_runtime_installed; then
        ui_warn "未检测到已安装的运行态，请先执行安装。"
        ui_pause
        return 0
    fi
    if ui_confirm_text "restart" "输入 restart 确认重启运行态"; then
        ui_run cmd_restart
        [ "$UI_STATUS" -eq 0 ] && ui_notice_set "pfwd 运行态已重启" "$UI_C_MENU_NUM"
    else
        ui_warn "已取消"
    fi
    ui_maybe_pause success
}
