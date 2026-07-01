#!/usr/bin/env bash

ui_render_main_menu_page() {
    ui_title
    ui_notice_render
    ui_print_main_forwards
    echo
    ui_menu_item 1 "用户管理"
    ui_menu_item 2 "转发管理"
    ui_menu_item 3 "流量管理"
    ui_menu_item 4 "Telegram 通知"
    ui_menu_item 5 "配置导入导出"
    ui_menu_item 6 "更新"
    ui_menu_item 7 "重启服务"
    ui_menu_item u "卸载"
    ui_menu_item 0 "退出"
}


ui_render_users_menu_page() {
    ui_header "用户管理"
    ui_notice_render
    ui_print_user_list
    echo
    ui_menu_item 1 "添加用户"
    ui_menu_item 2 "删除用户"
    ui_menu_item 0 "返回上级菜单"
}


ui_render_forwards_menu_page() {
    local user_id="$1"
    ui_header "转发管理"
    ui_notice_render
    ui_print_user_traffic_summary "$user_id"
    echo
    ui_print_line "当前用户端口" "$UI_C_HEADER"
    ui_print_user_forward_summary "$user_id"
    echo
    ui_menu_item 1 "添加转发"
    ui_menu_item 2 "修改转发"
    ui_menu_item 3 "暂停转发"
    ui_menu_item 4 "恢复转发"
    ui_menu_item 5 "删除转发"
    ui_menu_item 0 "返回上级菜单"
}


ui_render_forwards_select_user_page() {
    ui_header "转发管理"
    ui_notice_render
    ui_print_user_list true
    if ! ui_has_users; then
        echo
        ui_menu_item 0 "返回上级菜单"
    fi
}


ui_render_traffic_user_menu_page() {
    local user_id="$1"
    ui_header "流量管理"
    ui_notice_render
    ui_print_user_traffic_summary "$user_id"
    echo
    ui_menu_item 1 "转发到期日"
    ui_menu_item 2 "端口设置"
    ui_menu_item 3 "流量重置日"
    ui_menu_item 4 "设置已用流量"
    ui_menu_item 0 "返回上级菜单"
}


ui_render_traffic_select_user_page() {
    ui_header "流量管理"
    ui_notice_render
    ui_print_user_list true
    if ! ui_has_users; then
        echo
        ui_menu_item 0 "返回上级菜单"
    fi
}


ui_render_telegram_menu_page() {
    ui_header "Telegram 通知"
    ui_notice_render
    ui_print_telegram_configured_users
    echo
    ui_menu_item 1 "配置用户 Telegram"
    ui_menu_item 2 "设置定时发送"
    ui_menu_item 3 "发送测试通知"
    ui_menu_item 4 "恢复通知"
    ui_menu_item 5 "暂停通知"
    ui_menu_item 6 "删除通知"
    ui_menu_item 0 "返回上级菜单"
}


ui_render_export_import_menu_page() {
    ui_header "配置导入导出"
    ui_notice_render
    ui_print_export_import_summary
    echo
    ui_menu_item 1 "导出配置"
    ui_menu_item 2 "导入配置"
    ui_menu_item 0 "返回上级菜单"
}


ui_menu_uninstall() {
    ui_clear_screen
    ui_header "卸载"
    echo "步骤 1：停用 pfwd.service。"
    if ui_confirm_text "yes" "输入 yes 确认停用 pfwd.service，留空跳过"; then
        ui_run service_disable_forwarder
    else
        ui_warn "已跳过停用 pfwd.service"
    fi
    echo
    echo "步骤 2：完整卸载 pfwd 脚本、systemd、XDP 状态、配置和状态。"
    if ui_confirm_text "uninstall" "输入 uninstall 确认完整卸载"; then
        ui_run cmd_uninstall
    else
        ui_warn "已跳过完整卸载"
    fi
    ui_pause
}


cmd_menu() {
    ui_dependency_preflight
    config_init >/dev/null
    ui_runtime_install_preflight
    ui_detect_color_support
    ui_screen_enter
    trap ui_menu_cleanup EXIT INT TERM
    while true; do
        ui_render_page ui_render_main_menu_page
        if ui_read_timed "选择" "$UI_REFRESH_INTERVAL"; then
            :
        else
            case "$?" in
                124) continue ;;
                *) break ;;
            esac
        fi
        case "$UI_REPLY" in
            1) ui_menu_users ;;
            2) ui_menu_forwards ;;
            3) ui_menu_expire_limit ;;
            4) ui_menu_telegram ;;
            5) ui_menu_export_import ;;
            6) ui_menu_update ;;
            7) ui_menu_restart_runtime ;;
            u) ui_menu_uninstall ;;
            0) break ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
    ui_menu_cleanup
}
