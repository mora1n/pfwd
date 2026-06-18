#!/usr/bin/env bash

ui_leaseweb_status_rows() {
    leaseweb_status_rows
}


ui_print_leaseweb_summary() {
    local rows
    if ! rows="$(ui_leaseweb_status_rows 2>&1)"; then
        ui_error "$rows"
        return 1
    fi
    ui_table_render $'项目\t值' "$rows" "2"
}


ui_leaseweb_trusted_proxy_rows() {
    leaseweb_trusted_proxy_list
}


ui_print_leaseweb_trusted_proxy_list() {
    local rows
    if ! rows="$(ui_leaseweb_trusted_proxy_rows 2>&1)"; then
        ui_error "$rows"
        return 1
    fi
    ui_table_render $'序号\t可信反代 CIDR' "$rows" "2"
}


ui_leaseweb_route_rows() {
    leaseweb_route_ui_rows
}


ui_print_leaseweb_route_list() {
    local rows
    if ! rows="$(ui_leaseweb_route_rows 2>&1)"; then
        ui_error "$rows"
        return 1
    fi
    ui_table_render $'序号\t标签\tsecret\tSSH 目标\tSSH 端口\t放行范围\t空闲 TTL\tSSH 选项' "$rows" "2,4,6,8"
}


ui_render_leaseweb_menu_page() {
    ui_header "leaseweb"
    ui_notice_render
    ui_print_leaseweb_summary
    echo
    ui_menu_item 1 "服务状态"
    ui_menu_item 2 "监听配置"
    ui_menu_item 3 "可信反代 CIDR"
    ui_menu_item 4 "规则列表"
    ui_menu_item 5 "新增规则"
    ui_menu_item 6 "修改规则"
    ui_menu_item 7 "删除规则"
    ui_menu_item 8 "服务启停"
    ui_menu_item 0 "返回"
}


ui_menu_leaseweb_service_status() {
    ui_clear_screen
    ui_header "leaseweb - 服务状态"
    ui_notice_render
    ui_print_leaseweb_summary
    echo
    ui_run cmd_leaseweb service status
    ui_pause
}


ui_menu_leaseweb_listener() {
    local config_json current_host current_port current_timeout
    if ! config_json="$(leaseweb_config_json 2>&1)"; then
        ui_error "$config_json"
        ui_pause
        return 0
    fi
    current_host="$(jq -r '.listen_host // "127.0.0.1"' <<< "$config_json")"
    current_port="$(jq -r '.listen_port // 18080' <<< "$config_json")"
    current_timeout="$(jq -r '.request_timeout_sec // 10' <<< "$config_json")"

    ui_form_set "临时白名单 Web - 监听配置" "可信反代 CIDR：只有来自这些反代 IP/CIDR 的请求，才信任 X-Real-IP / X-Forwarded-For；否则只认直连来源 IP。输入 0 返回上级菜单。"
    ui_form_add_kv "当前监听地址" "$current_host:$current_port"
    ui_form_add_kv "当前请求超时" "${current_timeout}s"
    ui_form_read "监听地址" "$current_host" || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    local listen_host="$UI_REPLY"
    ui_form_add_kv "监听地址" "$listen_host"
    ui_form_read "监听端口" "$current_port" || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    local listen_port="$UI_REPLY"
    ui_form_add_kv "监听端口" "$listen_port"
    ui_form_read "请求超时（秒，例如 30）" "$current_timeout" || { ui_form_reset; return 0; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 0; }
    local request_timeout="$UI_REPLY"
    ui_run cmd_leaseweb config set --listen-host "$listen_host" --listen-port "$listen_port" --request-timeout-sec "$request_timeout"
    ui_form_reset
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "临时白名单 Web 监听配置已更新" "$UI_C_MENU_NUM"
    ui_maybe_pause success
}


ui_render_leaseweb_trusted_proxy_menu_page() {
    ui_header "临时白名单 Web - 可信反代 CIDR"
    ui_notice_render
    ui_print_leaseweb_trusted_proxy_list
    echo "说明：只有来自这些反代 IP/CIDR 的请求，才信任 X-Real-IP / X-Forwarded-For；否则只认直连来源 IP。"
    echo
    ui_menu_item 1 "添加 CIDR"
    ui_menu_item 2 "删除 CIDR"
    ui_menu_item 3 "清空 CIDR"
    ui_menu_item 0 "返回"
}


ui_menu_leaseweb_trusted_proxy() {
    local count
    while true; do
        ui_render_page ui_render_leaseweb_trusted_proxy_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_form_set "添加可信反代 CIDR" "输入一个 IPv4/IPv6 CIDR，或单个 IP。输入 0 返回上级菜单。"
                ui_form_read "CIDR" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                [ -n "$UI_REPLY" ] || { ui_form_reset; ui_warn "必须提供 CIDR 或单个 IP"; ui_pause; continue; }
                ui_run cmd_leaseweb trusted-proxy add "$UI_REPLY"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "可信反代 CIDR 已添加" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                count="$(leaseweb_trusted_proxy_list | sed '/^$/d' | wc -l | tr -d ' ')"
                if [ "$count" -eq 0 ]; then
                    ui_warn "暂无可信反代 CIDR"
                    ui_pause
                    continue
                fi
                ui_render_page ui_render_leaseweb_trusted_proxy_menu_page
                ui_read "选择要删除的序号，可单/多/连续选择" || return 0
                ui_multiselect_parse_indexes "$UI_REPLY" "$count" false || { ui_pause; continue; }
                ui_run cmd_leaseweb trusted-proxy delete $UI_REPLY
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "可信反代 CIDR 已删除" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_run cmd_leaseweb trusted-proxy clear
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "可信反代 CIDR 已清空" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_render_leaseweb_routes_page() {
    ui_header "临时白名单 Web - 规则列表"
    ui_notice_render
    ui_print_leaseweb_route_list
    echo "说明：label 会同时用于界面展示、HTTP 返回和目标机临时白名单备注；放行范围表示“当前访问来源 IP”会被扩成的实际 CIDR。"
}


ui_menu_leaseweb_routes() {
    if ! leaseweb_route_count >/dev/null 2>&1; then
        ui_error "错误：$(leaseweb_config_json 2>&1)"
        ui_pause
        return 0
    fi
    ui_render_page ui_render_leaseweb_routes_page
    ui_pause
}


ui_leaseweb_route_form() {
    local title="$1" mode="$2" index="${3:-}"
    local current_secret="" current_label="" current_target="" current_port="" current_ttl="" current_opts="" current_ipv4_prefix="" current_ipv6_prefix=""
    local defaults_label="当前"
    if [ -n "$index" ]; then
        current_secret="$(leaseweb_route_field "$index" secret)"
        current_label="$(leaseweb_route_field "$index" label)"
        current_target="$(leaseweb_route_field "$index" ssh_target)"
        current_port="$(leaseweb_route_ssh_port "$index")"
        current_ttl="$(leaseweb_route_field "$index" idle_ttl)"
        current_opts="$(leaseweb_route_ssh_options_text_without_port "$index")"
        current_ipv4_prefix="$(leaseweb_route_ipv4_prefix_len "$index")"
        current_ipv6_prefix="$(leaseweb_route_ipv6_prefix_len "$index")"
        [ -n "$current_secret$current_label$current_target$current_ttl$current_opts$current_port$current_ipv4_prefix$current_ipv6_prefix" ] || { ui_warn "规则序号不存在"; ui_pause; return 1; }
    elif [ "$(leaseweb_route_count)" -gt 0 ]; then
        defaults_label="默认"
        current_target="$(leaseweb_route_field 1 ssh_target)"
        current_port="$(leaseweb_route_ssh_port 1)"
        current_opts="$(leaseweb_route_ssh_options_text_without_port 1)"
        current_ipv4_prefix="$(leaseweb_route_ipv4_prefix_len 1)"
        current_ipv6_prefix="$(leaseweb_route_ipv6_prefix_len 1)"
    else
        defaults_label="默认"
        current_opts="$(leaseweb_recommended_ssh_options_text)"
        current_ipv4_prefix="24"
        current_ipv6_prefix="128"
    fi
    local secret="$current_secret" label="$current_label" ssh_target="$current_target"
    local ssh_port="$current_port" idle_ttl="${current_ttl:-2h}" ssh_options="$current_opts"
    local ipv4_prefix_len="${current_ipv4_prefix:-24}" ipv6_prefix_len="${current_ipv6_prefix:-128}"
    local error_notice=""

    while true; do
        ui_form_set "$title" "label 会写入目标机临时白名单备注；放行范围会基于当前访问来源 IP 按 IPv4/IPv6 前缀扩成 CIDR。SSH 权限边界建议配合受限命令脚本。SSH 目标建议填写 user@host；如果只填 IP/域名，将使用控制机当前系统用户。目标机首次接入前，还需先让控制机信任对应 host key。回车保留默认值；SSH 端口/SSH 选项输入 - 清空。若两者都为空，将直接依赖系统 ssh 默认行为，请自行在外部配置好 SSH 连通。输入 0 返回上级菜单。"
        [ -n "$error_notice" ] && ui_notice_set "$error_notice" "$UI_C_ERROR"
        [ -z "$index" ] || ui_form_add_kv "当前规则序号" "$index"
        [ -z "$current_secret" ] || ui_form_add_kv "当前 secret" "$current_secret"
        [ -z "$current_label" ] || ui_form_add_kv "当前标签" "$current_label"
        [ -z "$current_target" ] || ui_form_add_kv "$defaults_label SSH 目标" "$current_target"
        [ -z "$current_port" ] || ui_form_add_kv "$defaults_label SSH 端口" "$current_port"
        [ -z "$current_ipv4_prefix" ] || ui_form_add_kv "$defaults_label IPv4 前缀" "/$current_ipv4_prefix"
        [ -z "$current_ipv6_prefix" ] || ui_form_add_kv "$defaults_label IPv6 前缀" "/$current_ipv6_prefix"
        [ -z "$current_ttl" ] || ui_form_add_kv "当前空闲 TTL" "$current_ttl"
        [ -z "$current_opts" ] || ui_form_add_kv "$defaults_label SSH 选项" "$current_opts"
        ui_form_read "secret" "$secret" || { ui_form_reset; return 1; }
        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 1; }
        secret="$UI_REPLY"
        ui_form_add_kv "secret" "$secret"
        ui_form_read "标签" "$label" || { ui_form_reset; return 1; }
        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 1; }
        label="$UI_REPLY"
        ui_form_add_kv "标签" "$label"
        ui_form_read "SSH 目标（建议 user@host）" "$ssh_target" || { ui_form_reset; return 1; }
        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 1; }
        ssh_target="$UI_REPLY"
        ui_form_add_kv "SSH 目标" "$ssh_target"
        ui_form_read "SSH 端口（输入 - 清空）" "$ssh_port" || { ui_form_reset; return 1; }
        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 1; }
        ssh_port="$UI_REPLY"
        [ "$ssh_port" = "-" ] && ssh_port=""
        ui_form_add_kv "SSH 端口" "$ssh_port"
        ui_form_read "IPv4 前缀长度（0-32；常用 24）" "$ipv4_prefix_len" || { ui_form_reset; return 1; }
        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 1; }
        ipv4_prefix_len="$UI_REPLY"
        ui_form_add_kv "IPv4 前缀长度" "/$ipv4_prefix_len"
        ui_form_read "IPv6 前缀长度（0-128；常用 128）" "$ipv6_prefix_len" || { ui_form_reset; return 1; }
        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 1; }
        ipv6_prefix_len="$UI_REPLY"
        ui_form_add_kv "IPv6 前缀长度" "/$ipv6_prefix_len"
        ui_form_read "空闲 TTL（例如 30m / 2h / 1d）" "$idle_ttl" || { ui_form_reset; return 1; }
        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 1; }
        idle_ttl="$UI_REPLY"
        ui_form_add_kv "空闲 TTL" "$idle_ttl"
        ui_form_read "SSH 选项（空格分隔；输入 - 清空）" "$ssh_options" || { ui_form_reset; return 1; }
        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return 1; }
        ssh_options="$UI_REPLY"
        [ "$ssh_options" = "-" ] && ssh_options=""

        if [ "$mode" = "add" ]; then
            ui_run_capture cmd_leaseweb route add --secret "$secret" --label "$label" --ssh-target "$ssh_target" --ssh-port "$ssh_port" --ipv4-prefix-len "$ipv4_prefix_len" --ipv6-prefix-len "$ipv6_prefix_len" --idle-ttl "$idle_ttl" --ssh-options "$ssh_options"
        else
            ui_run_capture cmd_leaseweb route update --index "$index" --secret "$secret" --label "$label" --ssh-target "$ssh_target" --ssh-port "$ssh_port" --ipv4-prefix-len "$ipv4_prefix_len" --ipv6-prefix-len "$ipv6_prefix_len" --idle-ttl "$idle_ttl" --ssh-options "$ssh_options"
        fi
        if [ "$UI_STATUS" -eq 0 ]; then
            ui_form_reset
            return 0
        fi
        error_notice="操作失败：${UI_REPLY%%$'\n'*}"
    done
}


ui_menu_leaseweb_route_add() {
    ui_leaseweb_route_form "新增 leaseweb 规则" "add" || return 0
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "临时白名单 Web 规则已添加" "$UI_C_MENU_NUM"
    ui_maybe_pause success
}


ui_menu_leaseweb_route_update() {
    local count
    if ! count="$(leaseweb_route_count 2>/dev/null)"; then
        ui_error "错误：$(leaseweb_config_json 2>&1)"
        ui_pause
        return 0
    fi
    if [ "$count" -eq 0 ]; then
        ui_warn "暂无规则"
        ui_pause
        return 0
    fi
    ui_render_page ui_render_leaseweb_routes_page
    ui_read "选择要修改的规则序号（1-$count）" || return 0
    [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; ui_pause; return 0; }
    [ "$UI_REPLY" -ge 1 ] && [ "$UI_REPLY" -le "$count" ] || { ui_warn "序号超出范围"; ui_pause; return 0; }
    ui_leaseweb_route_form "修改 leaseweb 规则" "update" "$UI_REPLY" || return 0
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "临时白名单 Web 规则已更新" "$UI_C_MENU_NUM"
    ui_maybe_pause success
}


ui_menu_leaseweb_route_delete() {
    local count
    if ! count="$(leaseweb_route_count 2>/dev/null)"; then
        ui_error "错误：$(leaseweb_config_json 2>&1)"
        ui_pause
        return 0
    fi
    if [ "$count" -eq 0 ]; then
        ui_warn "暂无规则"
        ui_pause
        return 0
    fi
    ui_render_page ui_render_leaseweb_routes_page
    ui_read "选择要删除的规则序号，可单/多/连续选择" || return 0
    ui_multiselect_parse_indexes "$UI_REPLY" "$count" false || { ui_pause; return 0; }
    ui_run_capture cmd_leaseweb route delete $UI_REPLY
    if [ "$UI_STATUS" -eq 0 ]; then
        ui_notice_set "临时白名单 Web 规则已删除" "$UI_C_MENU_NUM"
    elif [ -n "$UI_REPLY" ]; then
        ui_error_from_reply "删除临时白名单 Web 规则失败"
    fi
    ui_maybe_pause success
}


ui_render_leaseweb_service_menu_page() {
    ui_header "临时白名单 Web - 服务启停"
    ui_notice_render
    ui_print_leaseweb_summary
    echo
    ui_menu_item 1 "启动服务"
    ui_menu_item 2 "停止服务"
    ui_menu_item 3 "重启服务"
    ui_menu_item 4 "开启自启"
    ui_menu_item 5 "关闭自启"
    ui_menu_item 0 "返回"
}


ui_menu_leaseweb_service() {
    while true; do
        ui_render_page ui_render_leaseweb_service_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_run cmd_leaseweb service start
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "临时白名单 Web 服务已启动" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_run cmd_leaseweb service stop
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "临时白名单 Web 服务已停止" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_run cmd_leaseweb service restart
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "临时白名单 Web 服务已重启" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            4)
                ui_run cmd_leaseweb service enable
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "临时白名单 Web 服务已设为开机自启" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            5)
                ui_run cmd_leaseweb service disable
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "临时白名单 Web 服务已取消开机自启" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_menu_leaseweb() {
    leaseweb_init_config_if_missing
    while true; do
        ui_render_page ui_render_leaseweb_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1) ui_menu_leaseweb_service_status ;;
            2) ui_menu_leaseweb_listener ;;
            3) ui_menu_leaseweb_trusted_proxy ;;
            4) ui_menu_leaseweb_routes ;;
            5) ui_menu_leaseweb_route_add ;;
            6) ui_menu_leaseweb_route_update ;;
            7) ui_menu_leaseweb_route_delete ;;
            8) ui_menu_leaseweb_service ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}
