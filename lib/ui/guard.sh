#!/usr/bin/env bash

ui_print_guard_summary() {
    ui_table_render $'项目\t值' "$(ui_guard_summary_rows)" "2"
}


ui_menu_guard() {
    while true; do
        ui_render_page ui_render_guard_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_run cmd_guard enable
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "guard 已启用" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_run cmd_guard disable
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "guard 已停用" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_form_set "协议封锁" "HTTPS 会同时开启 HTTP 和 TLS 封锁；仅覆盖 TCP 首包。"
                ui_form_select_read "HTTP" "1" "0) 返回" "1) 关闭" "2) 开启" || { ui_form_reset; continue; }
                local block_http="false" block_tls="false" block_socks="false"
                [ "$UI_REPLY" = "0" ] && { ui_form_reset; continue; }
                [ "$UI_REPLY" = "2" ] && block_http="true"
                ui_form_add_kv "HTTP" "$( [ "$block_http" = "true" ] && echo 开启 || echo 关闭 )"
                ui_form_select_read "TLS" "1" "0) 返回" "1) 关闭" "2) 开启" || { ui_form_reset; continue; }
                [ "$UI_REPLY" = "0" ] && { ui_form_reset; continue; }
                [ "$UI_REPLY" = "2" ] && block_tls="true"
                ui_form_add_kv "TLS" "$( [ "$block_tls" = "true" ] && echo 开启 || echo 关闭 )"
                ui_form_select_read "SOCKS" "1" "0) 返回" "1) 关闭" "2) 开启" || { ui_form_reset; continue; }
                [ "$UI_REPLY" = "0" ] && { ui_form_reset; continue; }
                [ "$UI_REPLY" = "2" ] && block_socks="true"
                ui_form_add_kv "SOCKS" "$( [ "$block_socks" = "true" ] && echo 开启 || echo 关闭 )"
                ui_run cmd_guard protocols --http "$block_http" --tls "$block_tls" --socks "$block_socks"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "guard 协议封锁已更新" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            4)
                ui_menu_guard_skip_ports
                ;;
            5)
                ui_menu_ingress_whitelist
                ;;
            6)
                ui_menu_egress_whitelist
                ;;
            7)
                ui_menu_leaseweb
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_print_whitelist_summary() {
    ui_table_render $'项目\t值' "$(ui_whitelist_summary_rows)" "2"
}


ui_print_egress_whitelist_summary() {
    ui_table_render $'项目\t值' "$(ui_egress_whitelist_summary_rows)" "2"
}


ui_custom_cidr_rows() {
    local idx=1 cidr
    while IFS= read -r cidr; do
        [ -n "$cidr" ] || continue
        printf '%s\t%s\n' "$idx" "$cidr"
        idx=$((idx + 1))
    done < <(whitelist_custom_cidrs_tsv)
}


ui_print_custom_cidr_list() {
    ui_table_render $'序号\t自定义 CIDR' "$(ui_custom_cidr_rows)" "2"
}


ui_menu_whitelist_cidrs_delete() {
    local count raw indexes
    count="$(whitelist_custom_cidrs_count)"
    if [ "$count" -eq 0 ]; then
        ui_warn "暂无自定义 CIDR"
        ui_pause
        return 0
    fi
    ui_render_page ui_render_whitelist_cidrs_menu_page
    ui_read "选择 CIDR 序号，可单/多/连续选择" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$count" false || return 1
    indexes="$UI_REPLY"
    ui_run cmd_guard_whitelist_custom delete $indexes
    if [ "$UI_STATUS" -eq 0 ]; then
        ui_notice_set "入口白名单自定义 CIDR 已删除" "$UI_C_MENU_NUM"
        ui_pause
    fi
}


ui_guard_cn_kind_title() {
    case "$1" in
        ingress) printf '入口省白名单' ;;
        egress) printf '出口国内 IP/省份' ;;
        *) printf '国内 IP/省份' ;;
    esac
}


ui_guard_cn_kind_prefix() {
    case "$1" in
        ingress) printf '入口' ;;
        egress) printf '出口' ;;
        *) printf '' ;;
    esac
}


ui_guard_cn_current_mode() {
    case "$1" in
        ingress) whitelist_cn_mode ;;
        egress) egress_whitelist_cn_mode ;;
    esac
}


ui_guard_cn_current_provinces() {
    case "$1" in
        ingress) whitelist_cn_provinces_tsv ;;
        egress) egress_whitelist_cn_provinces_tsv ;;
    esac
}


ui_guard_cn_compact_summary() {
    local kind="$1"
    local mode count preview suffix
    local -a provinces=() shown=()
    mode="$(ui_guard_cn_current_mode "$kind")"
    case "$mode" in
        all)
            printf '国内IP'
            ;;
        provinces)
            mapfile -t provinces < <(ui_guard_cn_current_provinces "$kind")
            count="${#provinces[@]}"
            if [ "$count" -eq 0 ]; then
                printf '省份：未选择'
                return 0
            fi
            if [ "$count" -le 2 ]; then
                printf '省份：%s' "$(printf '%s\n' "${provinces[@]}" | pfwd_join_lines '、')"
                return 0
            fi
            shown=("${provinces[@]:0:3}")
            suffix=""
            [ "$count" -gt 3 ] && suffix="..."
            preview="$(printf '%s\n' "${shown[@]}" | pfwd_join_lines '、')"
            printf '省份：%s 个（%s%s）' "$count" "$preview" "$suffix"
            ;;
        *)
            printf '关闭'
            ;;
    esac
}


ui_guard_cn_all_provinces() {
    whitelist_geo_province_rows | cut -f2
}


ui_guard_cn_all_province_count() {
    ui_guard_cn_all_provinces | sed '/^$/d' | wc -l | tr -d ' '
}


ui_guard_cn_all_province_rows() {
    local kind="$1"
    local idx=1 province
    local -A selected=()
    while IFS= read -r province; do
        [ -n "$province" ] || continue
        selected["$province"]=1
    done < <(ui_guard_cn_current_provinces "$kind")

    while IFS= read -r province; do
        [ -n "$province" ] || continue
        if [ -n "${selected[$province]:-}" ]; then
            printf '%s\t%s\t已选\n' "$idx" "$province"
        else
            printf '%s\t%s\t\n' "$idx" "$province"
        fi
        idx=$((idx + 1))
    done < <(ui_guard_cn_all_provinces)
}


ui_guard_port_province_rows() {
    local listen_port="$1"
    local idx=1 province
    local -A selected=()
    while IFS= read -r province; do
        [ -n "$province" ] || continue
        selected["$province"]=1
    done < <(whitelist_effective_cn_provinces_tsv_for_port "$listen_port")

    while IFS= read -r province; do
        [ -n "$province" ] || continue
        if [ -n "${selected[$province]:-}" ]; then
            printf '%s\t%s\t已选\n' "$idx" "$province"
        else
            printf '%s\t%s\t\n' "$idx" "$province"
        fi
        idx=$((idx + 1))
    done < <(ui_guard_cn_all_provinces)
}


ui_guard_cn_selected_province_rows() {
    local kind="$1"
    local idx=1 province
    while IFS= read -r province; do
        [ -n "$province" ] || continue
        printf '%s\t%s\n' "$idx" "$province"
        idx=$((idx + 1))
    done < <(ui_guard_cn_current_provinces "$kind")
}


ui_guard_cn_apply_all() {
    case "$1" in
        ingress) ui_run cmd_guard_whitelist_cn all ;;
        egress) ui_run cmd_guard_egress_whitelist_cn all ;;
    esac
}


ui_guard_cn_apply_off() {
    case "$1" in
        ingress) ui_run cmd_guard_whitelist_cn off ;;
        egress) ui_run cmd_guard_egress_whitelist_cn off ;;
    esac
}


ui_guard_cn_apply_provinces() {
    local kind="$1"
    shift
    if [ "$kind" = "ingress" ]; then
        ui_run cmd_guard_whitelist_cn select "$@"
    else
        ui_run cmd_guard_egress_whitelist_cn select "$@"
    fi
}


ui_guard_cn_provinces_from_indexes() {
    local indexes="$1"
    local -a all=() names=()
    local idx
    mapfile -t all < <(ui_guard_cn_all_provinces)
    while IFS= read -r idx; do
        [ -n "$idx" ] || continue
        names+=("${all[$((idx - 1))]:-}")
    done <<< "$indexes"
    printf '%s\n' "${names[@]}" | sed '/^$/d'
}


ui_guard_cn_merge_with_current() {
    local kind="$1"
    local added="$2"
    local province
    local -A selected=()
    while IFS= read -r province; do
        [ -n "$province" ] || continue
        selected["$province"]=1
    done < <(ui_guard_cn_current_provinces "$kind")
    while IFS= read -r province; do
        [ -n "$province" ] || continue
        selected["$province"]=1
    done <<< "$added"

    while IFS= read -r province; do
        [ -n "$province" ] || continue
        [ -n "${selected[$province]:-}" ] || continue
        printf '%s\n' "$province"
    done < <(ui_guard_cn_all_provinces)
}


ui_render_guard_cn_menu_page() {
    local kind="$1"
    ui_header "$(ui_guard_cn_kind_title "$kind")"
    ui_notice_render
    printf '当前策略：%s\n' "$(ui_guard_cn_compact_summary "$kind")"
    printf '说明：添加/删除省份支持单序号、多序号和连续范围，例如 3、3,5、3-6。\n'
    printf '\n'
    ui_menu_item 1 "允许全部国内IP"
    ui_menu_item 2 "关闭国内IP/省份"
    ui_menu_item 3 "添加省份"
    ui_menu_item 4 "删除省份"
    ui_menu_item 0 "返回"
}


ui_render_guard_cn_add_page() {
    local kind="$1"
    ui_header "$(ui_guard_cn_kind_title "$kind") - 添加省份"
    ui_notice_render
    printf '当前策略：%s\n' "$(ui_guard_cn_compact_summary "$kind")"
    printf '说明：选择要加入白名单的省份；已选省份会保留。\n'
    printf '\n'
    ui_table_render $'序号\t省份\t当前' "$(ui_guard_cn_all_province_rows "$kind")" "2"
}


ui_render_guard_cn_delete_page() {
    local kind="$1"
    ui_header "$(ui_guard_cn_kind_title "$kind") - 删除省份"
    ui_notice_render
    printf '当前策略：%s\n' "$(ui_guard_cn_compact_summary "$kind")"
    printf '说明：删除后如果没有剩余省份，将切换为关闭国内IP/省份。\n'
    printf '\n'
    ui_table_render $'序号\t省份' "$(ui_guard_cn_selected_province_rows "$kind")" "2"
}


ui_menu_guard_cn_add_provinces() {
    local kind="$1"
    local raw parsed total added merged prefix
    local -a names=()
    total="$(ui_guard_cn_all_province_count)"
    [ "$total" -gt 0 ] || { ui_warn "暂无省份资产"; return 1; }
    ui_render_page ui_render_guard_cn_add_page "$kind"
    ui_read "选择省份序号，可单/多/连续；0 返回" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$total" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    parsed="$UI_REPLY"
    added="$(ui_guard_cn_provinces_from_indexes "$parsed")"
    merged="$(ui_guard_cn_merge_with_current "$kind" "$added")"
    mapfile -t names < <(printf '%s\n' "$merged" | sed '/^$/d')
    if [ "${#names[@]}" -eq 0 ]; then
        ui_warn "未解析到省份"
        return 1
    fi
    ui_guard_cn_apply_provinces "$kind" "${names[@]}"
    prefix="$(ui_guard_cn_kind_prefix "$kind")"
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "${prefix}国内 IP/省份已添加省份" "$UI_C_MENU_NUM"
}


ui_menu_guard_cn_delete_provinces() {
    local kind="$1"
    local count raw parsed idx prefix
    local -a current=() remaining=()
    mapfile -t current < <(ui_guard_cn_current_provinces "$kind")
    count="${#current[@]}"
    if [ "$count" -eq 0 ]; then
        ui_warn "当前没有已选省份"
        return 1
    fi
    ui_render_page ui_render_guard_cn_delete_page "$kind"
    ui_read "选择要删除的省份序号，可单/多/连续；0 返回" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$count" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    parsed="$UI_REPLY"
    for idx in "${!current[@]}"; do
        if printf '%s\n' "$parsed" | grep -qx "$((idx + 1))"; then
            continue
        fi
        remaining+=("${current[$idx]}")
    done
    prefix="$(ui_guard_cn_kind_prefix "$kind")"
    if [ "${#remaining[@]}" -eq 0 ]; then
        ui_guard_cn_apply_off "$kind"
        [ "$UI_STATUS" -eq 0 ] && ui_notice_set "${prefix}国内 IP/省份已关闭" "$UI_C_MENU_NUM"
        return 0
    fi
    ui_guard_cn_apply_provinces "$kind" "${remaining[@]}"
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "${prefix}国内 IP/省份已删除省份" "$UI_C_MENU_NUM"
}


ui_menu_guard_cn_selection() {
    local kind="$1"
    local prefix
    while true; do
        ui_render_page ui_render_guard_cn_menu_page "$kind"
        ui_read "选择" || return 0
        prefix="$(ui_guard_cn_kind_prefix "$kind")"
        case "$UI_REPLY" in
            1)
                ui_guard_cn_apply_all "$kind"
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "${prefix}国内 IP/省份已设为国内IP" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_guard_cn_apply_off "$kind"
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "${prefix}国内 IP/省份已关闭" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_menu_guard_cn_add_provinces "$kind"
                ui_maybe_pause success
                ;;
            4)
                ui_menu_guard_cn_delete_provinces "$kind"
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_guard_city_compact_summary() {
    whitelist_city_selection_summary
}


ui_guard_city_province_count() {
    whitelist_city_available_province_rows | sed '/^$/d' | wc -l | tr -d ' '
}


ui_guard_city_province_rows() {
    whitelist_city_available_province_rows | awk -F '\t' '{printf "%s\t%s\t%s\n", $1, $3, $4}'
}


ui_guard_city_province_code_by_index() {
    local index="$1"
    whitelist_city_available_province_rows | awk -F '\t' -v idx="$index" '$1 == idx {print $2; exit}'
}


ui_guard_city_city_count() {
    local province_code="$1"
    whitelist_city_rows_by_province_code "$province_code" | sed '/^$/d' | wc -l | tr -d ' '
}


ui_guard_city_rows() {
    local province_code="$1"
    local idx code city
    local -A selected=()
    while IFS= read -r code; do
        [ -n "$code" ] || continue
        selected["$code"]=1
    done < <(whitelist_cn_city_codes_tsv)

    while IFS=$'\t' read -r idx code city; do
        [ -n "$idx" ] || continue
        if [ -n "${selected[$code]:-}" ]; then
            printf '%s\t%s\t%s\t已选\n' "$idx" "$code" "$city"
        else
            printf '%s\t%s\t%s\t\n' "$idx" "$code" "$city"
        fi
    done < <(whitelist_city_rows_by_province_code "$province_code")
}


ui_guard_city_codes_from_indexes() {
    local province_code="$1"
    local indexes="$2"
    local -a cities=()
    local idx
    mapfile -t cities < <(whitelist_city_rows_by_province_code "$province_code" | cut -f2)
    while IFS= read -r idx; do
        [ -n "$idx" ] || continue
        printf '%s\n' "${cities[$((idx - 1))]:-}"
    done <<< "$indexes" | sed '/^$/d'
}


ui_guard_city_selected_rows() {
    local idx=1 code province city
    while IFS=$'\t' read -r code province city; do
        [ -n "$code" ] || continue
        printf '%s\t%s\t%s\t%s\n' "$idx" "$code" "$province" "$city"
        idx=$((idx + 1))
    done < <(whitelist_city_selected_rows)
}


ui_render_guard_city_menu_page() {
    ui_header "入口市白名单"
    ui_notice_render
    printf '当前市白名单：%s\n' "$(ui_guard_city_compact_summary)"
    printf '说明：市白名单当前仅覆盖 IPv4；和省白名单不互斥，最终取并集。\n'
    printf '\n'
    ui_menu_item 1 "添加城市"
    ui_menu_item 2 "删除城市"
    ui_menu_item 3 "清空城市"
    ui_menu_item 0 "返回"
}


ui_render_guard_city_province_page() {
    ui_header "入口市白名单 - 选择省份"
    ui_notice_render
    printf '当前市白名单：%s\n' "$(ui_guard_city_compact_summary)"
    printf '说明：先选择省份，再选择城市；输入 0 返回。\n'
    printf '\n'
    ui_table_render $'序号\t省份\t城市数' "$(ui_guard_city_province_rows)" "2"
}


ui_render_guard_city_add_page() {
    local province_code="$1"
    ui_header "入口市白名单 - 添加城市"
    ui_notice_render
    printf '当前市白名单：%s\n' "$(ui_guard_city_compact_summary)"
    printf '说明：支持单序号、多序号和连续范围，多个选择用 , 分隔，例如 1,3,5-8；输入 0 返回。\n'
    printf '\n'
    ui_table_render $'序号\tcode\t城市\t当前' "$(ui_guard_city_rows "$province_code")" "2"
}


ui_render_guard_city_delete_page() {
    ui_header "入口市白名单 - 删除城市"
    ui_notice_render
    printf '当前市白名单：%s\n' "$(ui_guard_city_compact_summary)"
    printf '说明：支持单序号、多序号和连续范围，多个选择用 , 分隔，例如 1,3,5-8；输入 0 返回。\n'
    printf '\n'
    ui_table_render $'序号\tcode\t省份\t城市' "$(ui_guard_city_selected_rows)" "2"
}


ui_menu_guard_city_add() {
    local province_count raw parsed province_code city_count codes
    local -a city_codes=()
    province_count="$(ui_guard_city_province_count)"
    [ "$province_count" -gt 0 ] || { ui_warn "暂无市级白名单资产"; return 1; }
    ui_render_page ui_render_guard_city_province_page
    ui_read "选择省份序号；0 返回" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$province_count" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    parsed="$(printf '%s\n' "$UI_REPLY" | head -n1)"
    province_code="$(ui_guard_city_province_code_by_index "$parsed")"
    [ -n "$province_code" ] || { ui_warn "省份序号不存在"; return 1; }

    city_count="$(ui_guard_city_city_count "$province_code")"
    [ "$city_count" -gt 0 ] || { ui_warn "该省份暂无市级细分"; return 1; }
    ui_render_page ui_render_guard_city_add_page "$province_code"
    ui_read "选择城市序号，可单/多/连续；0 返回" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$city_count" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    codes="$(ui_guard_city_codes_from_indexes "$province_code" "$UI_REPLY")"
    mapfile -t city_codes < <(printf '%s\n' "$codes" | sed '/^$/d')
    [ "${#city_codes[@]}" -gt 0 ] || { ui_warn "未解析到城市"; return 1; }
    ui_run cmd_guard_whitelist_city add "$province_code" "${city_codes[@]}"
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口市白名单已添加城市" "$UI_C_MENU_NUM"
}


ui_menu_guard_city_delete() {
    local count raw parsed
    count="$(whitelist_city_codes_count)"
    if [ "$count" -eq 0 ]; then
        ui_warn "当前没有已选城市"
        return 1
    fi
    ui_render_page ui_render_guard_city_delete_page
    ui_read "选择要删除的城市序号，可单/多/连续；0 返回" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$count" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    parsed="$UI_REPLY"
    ui_run cmd_guard_whitelist_city delete $parsed
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口市白名单已删除城市" "$UI_C_MENU_NUM"
}


ui_menu_guard_city_selection() {
    while true; do
        ui_render_page ui_render_guard_city_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_menu_guard_city_add
                ui_maybe_pause success
                ;;
            2)
                ui_menu_guard_city_delete
                ui_maybe_pause success
                ;;
            3)
                ui_run cmd_guard_whitelist_city clear
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口市白名单已清空" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_guard_port_selected_summary_rows() {
    local listen_port="$1"
    whitelist_port_policy_status_json "$listen_port" | jq -r '
      [
        ["监听端口", (.listen_port | tostring)],
        ["策略来源", .source],
        ["国内 IP 策略", .cn_summary],
        ["市白名单", .city_summary]
      ] | map(@tsv) | .[]
    '
}


ui_select_listen_port_from_forward() {
    local forward_id listen_port
    ui_select_forward true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    forward_id="$UI_REPLY"
    listen_port="$(jq -r --arg id "$forward_id" '.forwards[]? | select(.id == $id) | .listen_port // empty' "$PFWD_CONFIG_FILE")"
    [ -n "$listen_port" ] || { ui_warn "未找到转发监听端口"; return 1; }
    UI_REPLY="$listen_port"
}


ui_render_guard_port_whitelist_page() {
    local listen_port="$1"
    ui_header "入口白名单 - 按端口配置"
    ui_notice_render
    if [ -z "$listen_port" ]; then
        ui_print_line "当前端口：未选择" "$UI_C_WARN"
    else
        ui_table_render $'项目\t值' "$(ui_guard_port_selected_summary_rows "$listen_port")" "2"
    fi
    echo
    ui_menu_item 1 "选择监听端口"
    ui_menu_item 2 "允许全部国内IP"
    ui_menu_item 3 "关闭国内IP/省份"
    ui_menu_item 4 "选择省份"
    ui_menu_item 5 "添加城市"
    ui_menu_item 6 "删除城市"
    ui_menu_item 7 "清空城市"
    ui_menu_item 8 "清除端口覆盖"
    ui_menu_item 0 "返回"
}


ui_guard_port_city_rows() {
    local listen_port="$1"
    local province_code="$2"
    local idx code city
    local -A selected=()
    while IFS= read -r code; do
        [ -n "$code" ] || continue
        selected["$code"]=1
    done < <(whitelist_effective_cn_city_codes_tsv_for_port "$listen_port")

    while IFS=$'\t' read -r idx code city; do
        [ -n "$idx" ] || continue
        if [ -n "${selected[$code]:-}" ]; then
            printf '%s\t%s\t%s\t已选\n' "$idx" "$code" "$city"
        else
            printf '%s\t%s\t%s\t\n' "$idx" "$code" "$city"
        fi
    done < <(whitelist_city_rows_by_province_code "$province_code")
}


ui_guard_port_city_selected_rows() {
    local listen_port="$1"
    local idx=1 code province city
    while IFS=$'\t' read -r code province city; do
        [ -n "$code" ] || continue
        printf '%s\t%s\t%s\t%s\n' "$idx" "$code" "$province" "$city"
        idx=$((idx + 1))
    done < <(whitelist_city_selected_rows_from_codes_json "$(whitelist_effective_cn_city_codes_json_for_port "$listen_port")")
}


ui_menu_guard_port_select_provinces() {
    local listen_port="$1"
    local total raw parsed provinces
    local -a names=()
    total="$(ui_guard_cn_all_province_count)"
    [ "$total" -gt 0 ] || { ui_warn "暂无省份资产"; return 1; }
    ui_clear_screen
    ui_header "入口白名单 - 端口 $listen_port - 选择省份"
    ui_table_render $'序号\t省份\t当前' "$(ui_guard_port_province_rows "$listen_port")" "2"
    ui_read "选择省份序号，可单/多/连续；0 返回" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$total" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    parsed="$UI_REPLY"
    provinces="$(ui_guard_cn_provinces_from_indexes "$parsed")"
    mapfile -t names < <(printf '%s\n' "$provinces" | sed '/^$/d')
    [ "${#names[@]}" -gt 0 ] || { ui_warn "未解析到省份"; return 1; }
    ui_run cmd_guard_whitelist_port_cn --listen-port "$listen_port" select "${names[@]}"
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单端口 $listen_port 已设置省份" "$UI_C_MENU_NUM"
}


ui_menu_guard_port_city_add() {
    local listen_port="$1"
    local province_count raw parsed province_code city_count codes
    local -a city_codes=()
    province_count="$(ui_guard_city_province_count)"
    [ "$province_count" -gt 0 ] || { ui_warn "暂无市级白名单资产"; return 1; }
    ui_render_page ui_render_guard_city_province_page
    ui_read "选择省份序号；0 返回" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$province_count" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    parsed="$(printf '%s\n' "$UI_REPLY" | head -n1)"
    province_code="$(ui_guard_city_province_code_by_index "$parsed")"
    [ -n "$province_code" ] || { ui_warn "省份序号不存在"; return 1; }

    city_count="$(ui_guard_city_city_count "$province_code")"
    [ "$city_count" -gt 0 ] || { ui_warn "该省份暂无市级细分"; return 1; }
    ui_clear_screen
    ui_header "入口白名单 - 端口 $listen_port - 添加城市"
    ui_table_render $'序号\tcode\t城市\t当前' "$(ui_guard_port_city_rows "$listen_port" "$province_code")" "2"
    ui_read "选择城市序号，可单/多/连续；0 返回" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$city_count" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    codes="$(ui_guard_city_codes_from_indexes "$province_code" "$UI_REPLY")"
    mapfile -t city_codes < <(printf '%s\n' "$codes" | sed '/^$/d')
    [ "${#city_codes[@]}" -gt 0 ] || { ui_warn "未解析到城市"; return 1; }
    ui_run cmd_guard_whitelist_port_city --listen-port "$listen_port" add "$province_code" "${city_codes[@]}"
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单端口 $listen_port 已添加城市" "$UI_C_MENU_NUM"
}


ui_menu_guard_port_city_delete() {
    local listen_port="$1"
    local count raw parsed
    count="$(whitelist_effective_cn_city_codes_tsv_for_port "$listen_port" | sed '/^$/d' | wc -l | tr -d ' ')"
    if [ "$count" -eq 0 ]; then
        ui_warn "当前端口没有已选城市"
        return 1
    fi
    ui_clear_screen
    ui_header "入口白名单 - 端口 $listen_port - 删除城市"
    ui_table_render $'序号\tcode\t省份\t城市' "$(ui_guard_port_city_selected_rows "$listen_port")" "2"
    ui_read "选择要删除的城市序号，可单/多/连续；0 返回" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$count" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    parsed="$UI_REPLY"
    ui_run cmd_guard_whitelist_port_city --listen-port "$listen_port" delete $parsed
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单端口 $listen_port 已删除城市" "$UI_C_MENU_NUM"
}


ui_menu_guard_port_whitelist() {
    local listen_port=""
    while true; do
        ui_render_page ui_render_guard_port_whitelist_page "$listen_port"
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_select_listen_port_from_forward || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                listen_port="$UI_REPLY"
                ui_notice_set "已选择端口：$listen_port" "$UI_C_MENU_NUM"
                ;;
            2)
                [ -n "$listen_port" ] || { ui_warn "请先选择监听端口"; ui_pause; continue; }
                ui_run cmd_guard_whitelist_port_cn --listen-port "$listen_port" all
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单端口 $listen_port 已允许国内IP" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                [ -n "$listen_port" ] || { ui_warn "请先选择监听端口"; ui_pause; continue; }
                ui_run cmd_guard_whitelist_port_cn --listen-port "$listen_port" off
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单端口 $listen_port 已关闭国内IP/省份" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            4)
                [ -n "$listen_port" ] || { ui_warn "请先选择监听端口"; ui_pause; continue; }
                ui_menu_guard_port_select_provinces "$listen_port"
                ui_maybe_pause success
                ;;
            5)
                [ -n "$listen_port" ] || { ui_warn "请先选择监听端口"; ui_pause; continue; }
                ui_menu_guard_port_city_add "$listen_port"
                ui_maybe_pause success
                ;;
            6)
                [ -n "$listen_port" ] || { ui_warn "请先选择监听端口"; ui_pause; continue; }
                ui_menu_guard_port_city_delete "$listen_port"
                ui_maybe_pause success
                ;;
            7)
                [ -n "$listen_port" ] || { ui_warn "请先选择监听端口"; ui_pause; continue; }
                ui_run cmd_guard_whitelist_port_city --listen-port "$listen_port" clear
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单端口 $listen_port 市白名单已清空" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            8)
                [ -n "$listen_port" ] || { ui_warn "请先选择监听端口"; ui_pause; continue; }
                ui_run cmd_guard_whitelist_port clear --listen-port "$listen_port"
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单端口 $listen_port 覆盖已清除" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_render_ingress_whitelist_menu_page() {
    ui_header "入口白名单"
    ui_notice_render
    ui_print_whitelist_summary
    echo
    ui_menu_item 1 "启用入口白名单"
    ui_menu_item 2 "关闭入口白名单"
    ui_menu_item 3 "省白名单"
    ui_menu_item 4 "市白名单"
    ui_menu_item 5 "按端口配置"
    ui_menu_item 6 "入口自定义 CIDR"
    ui_menu_item 7 "临时白名单"
    ui_menu_item 0 "返回"
}


ui_menu_ingress_whitelist() {
    while true; do
        ui_render_page ui_render_ingress_whitelist_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_run cmd_guard_whitelist --enabled true
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单已启用" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_run cmd_guard_whitelist --enabled false
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "入口白名单已停用" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_menu_guard_cn_selection ingress
                ui_maybe_pause success
                ;;
            4)
                ui_menu_guard_city_selection
                ui_maybe_pause success
                ;;
            5)
                ui_menu_guard_port_whitelist
                ;;
            6)
                ui_menu_whitelist_cidrs
                ;;
            7)
                ui_menu_whitelist_leases
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}
