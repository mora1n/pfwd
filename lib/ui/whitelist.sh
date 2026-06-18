#!/usr/bin/env bash

ui_whitelist_lease_rows() {
    whitelist_lease_list_rows | while IFS=$'\t' read -r idx address cidr ttl last_seen granted channel note; do
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$idx" "$address" "$cidr" "$(pfwd_format_duration_seconds "$ttl")" "$last_seen" "$granted" "$channel" "$note"
    done
}


ui_print_whitelist_lease_list() {
    ui_table_render $'序号\t最近地址\tCIDR\t空闲TTL\t最近命中(epoch)\t授权(epoch)\t来源\t备注' "$(ui_whitelist_lease_rows)" "2,3,4,5,6,7,8"
}


ui_render_whitelist_lease_menu_page() {
    ui_header "入口临时白名单"
    ui_notice_render
    ui_print_whitelist_lease_list
    echo
    ui_menu_item 1 "添加"
    ui_menu_item 2 "删除"
    ui_menu_item 3 "清空"
    ui_menu_item 0 "返回"
}


ui_menu_whitelist_leases() {
    local count
    while true; do
        ui_render_page ui_render_whitelist_lease_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_form_set "添加临时白名单" "输入公网 IP 和空闲 TTL（例如 30m / 2h / 1d）；该临时白名单对所有启用入口白名单的端口统一生效。"
                ui_form_read "IP 地址" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                local lease_ip="$UI_REPLY"
                ui_form_add_kv "IP 地址" "$lease_ip"
                ui_form_read "空闲 TTL（例如 30m / 2h / 1d）" "30m" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                local lease_ttl="$UI_REPLY"
                ui_form_add_kv "空闲 TTL" "$lease_ttl"
                ui_form_read "备注" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                ui_run cmd_guard_whitelist_lease add --address "$lease_ip" --idle-ttl "$lease_ttl" --channel manual --note "$UI_REPLY"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口临时白名单已添加" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                count="$(whitelist_lease_count)"
                if [ "$count" -eq 0 ]; then
                    ui_warn "暂无入口临时白名单"
                    ui_pause
                    continue
                fi
                ui_render_page ui_render_whitelist_lease_menu_page
                ui_read "选择要删除的序号，可单/多/连续选择" || return 0
                ui_multiselect_parse_indexes "$UI_REPLY" "$count" false || { ui_pause; continue; }
                ui_run cmd_guard_whitelist_lease delete $UI_REPLY
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口临时白名单已删除" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_run cmd_guard_whitelist_lease clear
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口临时白名单已清空" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_render_whitelist_cidrs_menu_page() {
    ui_header "入口自定义 CIDR"
    ui_notice_render
    ui_print_custom_cidr_list
    echo
    ui_menu_item 1 "删除所有入口自定义 CIDR"
    ui_menu_item 2 "增加 CIDR"
    ui_menu_item 3 "删除 CIDR"
    ui_menu_item 4 "修改 CIDR"
    ui_menu_item 0 "返回"
}


ui_menu_whitelist_cidrs() {
    local count selected display_index real_index current_cidr
    while true; do
        ui_render_page ui_render_whitelist_cidrs_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_run cmd_guard_whitelist_custom clear
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单自定义 CIDR 已清空" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_form_set "增加入口自定义 CIDR" "输入一个 IPv4 或 IPv6 CIDR，或单个 IP；会和国内 IP 配置共同组成入口白名单。输入 0 返回上级菜单。"
                ui_form_read "CIDR" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                [ -n "$UI_REPLY" ] || { ui_form_reset; ui_warn "必须提供 CIDR 或单个 IP"; ui_pause; continue; }
                ui_run cmd_guard_whitelist_custom add "$UI_REPLY"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单自定义 CIDR 已添加" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_menu_whitelist_cidrs_delete
                ui_maybe_pause success
                ;;
            4)
                count="$(whitelist_custom_cidrs_count)"
                if [ "$count" -eq 0 ]; then
                    ui_warn "暂无入口白名单自定义 CIDR"
                    ui_pause
                    continue
                fi
                ui_render_page ui_render_whitelist_cidrs_menu_page
                ui_read "选择要修改的 CIDR 序号（1-$count）" || return 0
                [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; ui_pause; continue; }
                display_index="$UI_REPLY"
                [ "$display_index" -ge 1 ] && [ "$display_index" -le "$count" ] || { ui_warn "序号超出范围"; ui_pause; continue; }
                real_index="$display_index"
                current_cidr="$(whitelist_custom_cidr_by_index "$real_index")"
                [ -n "$current_cidr" ] || { ui_warn "入口白名单自定义 CIDR 序号不存在"; ui_pause; continue; }
                ui_form_set "修改入口自定义 CIDR" "输入新的 IPv4 或 IPv6 CIDR，或单个 IP。输入 0 返回上级菜单。"
                ui_form_add_kv "当前 CIDR" "$current_cidr"
                ui_form_read "新 CIDR" "$current_cidr" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                [ -n "$UI_REPLY" ] || { ui_form_reset; ui_warn "必须提供 CIDR 或单个 IP"; ui_pause; continue; }
                ui_run cmd_guard_whitelist_custom update "$real_index" "$UI_REPLY"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单自定义 CIDR 已更新" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_egress_custom_cidr_rows() {
    local idx=1 cidr
    while IFS= read -r cidr; do
        [ -n "$cidr" ] || continue
        printf '%s\t%s\n' "$idx" "$cidr"
        idx=$((idx + 1))
    done < <(egress_whitelist_custom_cidrs_tsv)
}


ui_print_egress_custom_cidr_list() {
    ui_table_render $'序号\t出口自定义 CIDR' "$(ui_egress_custom_cidr_rows)" "2"
}


ui_menu_egress_whitelist_cidrs_delete() {
    local count raw indexes
    count="$(egress_whitelist_custom_cidrs_count)"
    if [ "$count" -eq 0 ]; then
        ui_warn "暂无出口自定义 CIDR"
        ui_pause
        return 0
    fi
    ui_render_page ui_render_egress_whitelist_cidrs_menu_page
    ui_read "选择 CIDR 序号，可单/多/连续选择" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$count" false || return 1
    indexes="$UI_REPLY"
    ui_run cmd_guard_egress_whitelist_custom delete $indexes
    if [ "$UI_STATUS" -eq 0 ]; then
        ui_notice_set "出口白名单自定义 CIDR 已删除" "$UI_C_MENU_NUM"
        ui_pause
    fi
}


ui_render_egress_whitelist_cidrs_menu_page() {
    ui_header "出口自定义 CIDR"
    ui_notice_render
    ui_print_egress_custom_cidr_list
    echo
    ui_menu_item 1 "删除所有出口自定义 CIDR"
    ui_menu_item 2 "增加 CIDR"
    ui_menu_item 3 "删除 CIDR"
    ui_menu_item 4 "修改 CIDR"
    ui_menu_item 0 "返回"
}


ui_menu_egress_whitelist_cidrs() {
    local count display_index real_index current_cidr
    while true; do
        ui_render_page ui_render_egress_whitelist_cidrs_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_run cmd_guard_egress_whitelist_custom clear
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "出口白名单自定义 CIDR 已清空" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_form_set "增加出口自定义 CIDR" "输入一个 IPv4 或 IPv6 CIDR，或单个 IP；会和国内 IP 配置共同组成出口白名单。输入 0 返回上级菜单。"
                ui_form_read "CIDR" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                [ -n "$UI_REPLY" ] || { ui_form_reset; ui_warn "必须提供 CIDR 或单个 IP"; ui_pause; continue; }
                ui_run cmd_guard_egress_whitelist_custom add "$UI_REPLY"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "出口白名单自定义 CIDR 已添加" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_menu_egress_whitelist_cidrs_delete
                ui_maybe_pause success
                ;;
            4)
                count="$(egress_whitelist_custom_cidrs_count)"
                if [ "$count" -eq 0 ]; then
                    ui_warn "暂无出口自定义 CIDR"
                    ui_pause
                    continue
                fi
                ui_render_page ui_render_egress_whitelist_cidrs_menu_page
                ui_read "选择要修改的 CIDR 序号（1-$count）" || return 0
                [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; ui_pause; continue; }
                display_index="$UI_REPLY"
                [ "$display_index" -ge 1 ] && [ "$display_index" -le "$count" ] || { ui_warn "序号超出范围"; ui_pause; continue; }
                real_index="$display_index"
                current_cidr="$(egress_whitelist_custom_cidr_by_index "$real_index")"
                [ -n "$current_cidr" ] || { ui_warn "出口自定义 CIDR 序号不存在"; ui_pause; continue; }
                ui_form_set "修改出口自定义 CIDR" "输入新的 IPv4 或 IPv6 CIDR，或单个 IP。输入 0 返回上级菜单。"
                ui_form_add_kv "当前 CIDR" "$current_cidr"
                ui_form_read "新 CIDR" "$current_cidr" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                [ -n "$UI_REPLY" ] || { ui_form_reset; ui_warn "必须提供 CIDR 或单个 IP"; ui_pause; continue; }
                ui_run cmd_guard_egress_whitelist_custom update "$real_index" "$UI_REPLY"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "出口白名单自定义 CIDR 已更新" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_render_egress_whitelist_menu_page() {
    ui_header "出口白名单"
    ui_notice_render
    ui_print_egress_whitelist_summary
    echo
    ui_menu_item 1 "启用出口白名单"
    ui_menu_item 2 "关闭出口白名单"
    ui_menu_item 3 "国内IP/省份"
    ui_menu_item 4 "出口自定义 CIDR"
    ui_menu_item 0 "返回"
}


ui_menu_egress_whitelist() {
    while true; do
        ui_render_page ui_render_egress_whitelist_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_run cmd_guard_egress_whitelist --enabled true
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "出口白名单已启用" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_run cmd_guard_egress_whitelist --enabled false
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "出口白名单已停用" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_menu_guard_cn_selection egress
                ui_maybe_pause success
                ;;
            4)
                ui_menu_egress_whitelist_cidrs
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}
