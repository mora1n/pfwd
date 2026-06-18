#!/usr/bin/env bash

ui_print_downmask_summary() {
    local json pull_mode iface date ratio action ab_targets ab_mode
    local previous_date previous_ratio generated_at generation_source
    if ! json="$(downmask_status_json 2>&1)"; then
        printf '  下行伪装状态读取失败：%s\n' "$json"
        return 0
    fi
    pull_mode="$(jq -r '.config.pull_mode // "off"' <<< "$json" 2>/dev/null || echo off)"
    iface="$(jq -r '.day_state.iface // .config.iface // "-"' <<< "$json" 2>/dev/null || echo -)"
    date="$(jq -r '.day_state.date // "-"' <<< "$json" 2>/dev/null || echo -)"
    ratio="$(jq -r '.day_state.target_ratio // "-"' <<< "$json" 2>/dev/null || echo -)"
    action="$(jq -r '.day_state.last_action // "-"' <<< "$json" 2>/dev/null || echo -)"
    previous_date="$(jq -r '.day_state.previous_date // "-"' <<< "$json" 2>/dev/null || echo -)"
    previous_ratio="$(jq -r '.day_state.previous_target_ratio // "-"' <<< "$json" 2>/dev/null || echo -)"
    generated_at="$(jq -r '.day_state.generated_at // "-"' <<< "$json" 2>/dev/null || echo -)"
    generation_source="$(jq -r '.day_state.generation_source // "-"' <<< "$json" 2>/dev/null || echo -)"
    ab_targets="$(jq -r '.ab_targets | length' <<< "$json" 2>/dev/null || echo 0)"
    ab_mode="$(jq -r '.config.ab_pull.protocol_mode // "single"' <<< "$json" 2>/dev/null || echo single)"
    local tws twe window_text
    tws="$(jq -r '.config.time_window_start // ""' <<< "$json" 2>/dev/null || true)"
    twe="$(jq -r '.config.time_window_end // ""' <<< "$json" 2>/dev/null || true)"
    if [ -z "$tws" ] || [ -z "$twe" ]; then
        window_text="全天"
    else
        window_text="${tws}-${twe}"
    fi
    local rx tx
    rx="$(jq -r '.day_state.rx_accum // 0' <<< "$json" 2>/dev/null || echo 0)"
    tx="$(jq -r '.day_state.tx_accum // 0' <<< "$json" 2>/dev/null || echo 0)"
    local feed_tcp feed_udp
    feed_tcp="$(jq -r '.config.ab_feed.tcp_enabled // false' <<< "$json" 2>/dev/null || echo false)"
    feed_udp="$(jq -r '.config.ab_feed.udp_enabled // false' <<< "$json" 2>/dev/null || echo false)"
    printf '  拉流模式：%s  接口：%s  生效时段：%s  日期：%s  今日目标比例：%s  动作：%s\n' "$pull_mode" "$iface" "$window_text" "$date" "$ratio" "$action"
    printf '  上一日：%s  上一日比例：%s  生成来源：%s  生成于：%s\n' "$previous_date" "$previous_ratio" "$generation_source" "$generated_at"
    printf '  今日入站：%s  今日出站：%s\n' "$(format_bytes "$rx")" "$(format_bytes "$tx")"
    printf '  A机拉流：模式=%s  B机池=%s 台\n' "$ab_mode" "$ab_targets"
    printf '  B机喂流 TCP：%s  UDP：%s\n' "$feed_tcp" "$feed_udp"
}


ui_print_downmask_ab_pull_target_summary() {
    local count last_action last_actual last_planned last_error default_port default_local_ip default_token
    count="$(downmask_ab_pull_target_count 2>/dev/null || echo 0)"
    default_port="$(downmask_config_get '.ab_pull.remote_port' 2>/dev/null || echo 0)"
    default_local_ip="$(downmask_config_get '.ab_pull.local_ip' 2>/dev/null || echo "")"
    default_token="$(downmask_config_get '.ab_pull.token' 2>/dev/null || echo "")"
    if [ -z "$default_port" ] || [ "$default_port" = "0" ]; then
        default_port="未设置"
    fi
    [ -n "$default_local_ip" ] || default_local_ip="未设置"
    [ -n "$default_token" ] || default_token="未设置"
    printf '  默认端口：%s  默认本地源IP：%s  默认共享Token：%s\n' "$default_port" "$default_local_ip" "$( [ "$default_token" = "未设置" ] && echo 未设置 || echo set )"
    if [ "${count:-0}" -eq 0 ]; then
        echo "  B机状态：暂无已配置 B机"
    else
        echo "  B机状态："
        echo "  说明：以下端口/本地源IP/Token 为实际生效值；带“默认”表示当前继承默认拉流参数。"
        ui_table_render $'序号\tB机\t端口\t权重\tTCP\tUDP\t本地源IP\tToken' "$(ui_downmask_ab_pull_target_table_rows)" "2,7"
    fi
    last_action="$(jq -r '.last_action // "-"' "$(downmask_state_file)" 2>/dev/null || echo -)"
    last_actual="$(jq -r '.last_actual_bytes // 0' "$(downmask_state_file)" 2>/dev/null || echo 0)"
    last_planned="$(jq -r '.last_planned_bytes // 0' "$(downmask_state_file)" 2>/dev/null || echo 0)"
    last_error="$(jq -r '.last_error // ""' "$(downmask_state_file)" 2>/dev/null || echo "")"
    printf '  最近拉流：动作=%s  实际=%s  计划=%s' "$last_action" "$(format_bytes "$last_actual")" "$(format_bytes "$last_planned")"
    if [ -n "$last_error" ]; then
        printf '  结果=%s' "$last_error"
    fi
    printf '\n'
}


ui_render_downmask_menu_page() {
    ui_header "下行伪装"
    ui_notice_render
    ui_print_downmask_summary
    echo
    ui_menu_item 1 "对冲策略"
    ui_menu_item 2 "公网下载源"
    ui_menu_item 3 "A机拉流"
    ui_menu_item 4 "B机喂流"
    ui_menu_item 5 "生成随机种子文件"
    ui_menu_item 0 "返回"
}


ui_menu_downmask() {
    while true; do
        ui_render_page ui_render_downmask_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1) ui_menu_downmask_policy ;;
            2) ui_menu_downmask_public ;;
            3) ui_menu_downmask_ab_pull ;;
            4) ui_menu_downmask_ab_feed ;;
            5) ui_menu_downmask_seed ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_menu_downmask_policy() {
    ui_form_set "对冲策略" "设置下行伪装的拉流模式与参数。输入 0 返回上级菜单。"
    local pull_mode min_r max_r tws twe jitter mindef maxrun pull_mode_default

    pull_mode_default="1"
    case "$(downmask_config_get '.pull_mode' 2>/dev/null || echo off)" in
        public) pull_mode_default="2" ;;
        ab) pull_mode_default="3" ;;
        *) pull_mode_default="1" ;;
    esac
    ui_form_select_read "拉流模式" "$pull_mode_default" "0) 返回" "1) off（关闭）" "2) public（公网）" "3) ab（A/B 拉流）" || { ui_form_reset; return; }
    [ "$UI_REPLY" = "0" ] && { ui_form_reset; return; }
    case "$UI_REPLY" in 1) pull_mode="off" ;; 2) pull_mode="public" ;; 3) pull_mode="ab" ;; esac
    ui_form_add_kv "拉流模式" "$pull_mode"
    if [ "$pull_mode" = "off" ]; then
        ui_run cmd_downmask_policy --pull-mode off
        ui_form_reset
        [ "$UI_STATUS" -eq 0 ] && ui_notice_set "策略已更新" "$UI_C_MENU_NUM"
        ui_maybe_pause success
        return
    fi

    ui_form_edit_read "最小比例（如 1.5）" "$(downmask_config_get '.min_ratio')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    min_r="$UI_REPLY"
    ui_form_add_kv "最小比例" "$min_r"
    ui_form_edit_read "最大比例（如 2.8）" "$(downmask_config_get '.max_ratio')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    max_r="$UI_REPLY"
    ui_form_add_kv "最大比例" "$max_r"
    ui_form_edit_read "时间窗口开始（HH:MM；回车保留，空格回车=全天）" "$(downmask_config_get '.time_window_start')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    tws="$UI_REPLY"
    if [ -n "$tws" ] && [ -z "$(ui_trim_whitespace "$tws")" ]; then
        tws=""
    fi
    ui_form_add_kv "窗口开始" "$tws"
    ui_form_edit_read "时间窗口结束（HH:MM；回车保留，空格回车=全天）" "$(downmask_config_get '.time_window_end')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    twe="$UI_REPLY"
    if [ -n "$twe" ] && [ -z "$(ui_trim_whitespace "$twe")" ]; then
        twe=""
    fi
    ui_form_add_kv "窗口结束" "$twe"
    ui_form_edit_read "最大随机延迟（秒）" "$(downmask_config_get '.max_jitter_seconds')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    jitter="$UI_REPLY"
    ui_form_edit_read "最小触发缺口（支持 20MB、1GB；裸数字按字节）" "$(downmask_config_get '.min_deficit_bytes')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    mindef="$(normalize_ui_downmask_size_input "$UI_REPLY")"
    ui_form_edit_read "单次最大补流（支持 500MB、2GB；裸数字按字节）" "$(downmask_config_get '.max_bytes_per_run')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    maxrun="$(normalize_ui_downmask_size_input "$UI_REPLY")"

    local args=()
    [ -z "$pull_mode" ] || args+=(--pull-mode "$pull_mode")
    [ -z "$min_r" ] || args+=(--min-ratio "$min_r")
    [ -z "$max_r" ] || args+=(--max-ratio "$max_r")
    args+=(--time-window-start "$tws")
    args+=(--time-window-end "$twe")
    [ -z "$jitter" ] || args+=(--max-jitter "$jitter")
    [ -z "$mindef" ] || args+=(--min-deficit-bytes "$mindef")
    [ -z "$maxrun" ] || args+=(--max-bytes-per-run "$maxrun")
    if [ "${#args[@]}" -gt 0 ]; then
        ui_run cmd_downmask_policy "${args[@]}"
    fi
    ui_form_reset
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "策略已更新" "$UI_C_MENU_NUM"
    ui_maybe_pause success
}


ui_menu_downmask_public() {
    ui_form_set "公网下载源" "选择活跃源并设置限速；默认优先 cloudflare_dynamic，固定文件源请以本机实测可达性为准。输入 0 返回上级菜单。"
    local active speed
    ui_form_select_read "选择源" "1" "0) 返回" "1) cloudflare_dynamic（推荐，按字节动态下载）" "2) linode_tokyo_100mb（推荐备选，固定 100MB 文件）" "3) cachefly_100mb（备选，需确认返回真实文件）" || { ui_form_reset; return; }
    [ "$UI_REPLY" = "0" ] && { ui_form_reset; return; }
    case "$UI_REPLY" in 1) active="cloudflare_dynamic" ;; 2) active="linode_tokyo_100mb" ;; 3) active="cachefly_100mb" ;; esac
    ui_form_add_kv "活跃源" "$active"
    ui_form_edit_read "限速（默认 $(format_downmask_speed_hint "4M")；支持 4M、4MB/s、32Mbps）" "$(downmask_config_get '.public.speed_limit')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    speed="$UI_REPLY"
    local args=(--active-source "$active")
    [ -z "$speed" ] || args+=(--speed-limit "$speed")
    ui_run cmd_downmask_public "${args[@]}"
    ui_form_reset
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "公网源已更新" "$UI_C_MENU_NUM"
    ui_maybe_pause success
}


ui_downmask_ab_target_selection_rows() {
    local rows=$'0\t返回\n1\t所有B机'
    local row
    while IFS= read -r row; do
        [ -n "$row" ] || continue
        rows+=$'\n'"$(awk -F $'\t' '{print $1 + 1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6 "\t" $7 "\t" $8}' <<< "$row")"
    done < <(ui_downmask_ab_pull_target_table_rows)
    printf '%s\n' "$rows"
}


ui_render_downmask_ab_target_selection_page() {
    local title="$1"
    local rows="$2"
    ui_header "$title"
    ui_notice_render
    ui_table_render $'序号\tB机\t端口\t权重\tTCP\tUDP\t本地源IP\tToken' "$rows" "2,7"
}


ui_select_downmask_ab_targets_multi() {
    local title="$1"
    local prompt="$2"
    local count rows raw indexes selected_count
    UI_EDIT_ABORTED=0
    count="$(downmask_ab_pull_target_count 2>/dev/null || echo 0)"
    if [ "${count:-0}" -eq 0 ]; then
        ui_warn "当前没有已配置 B机"
        return 1
    fi
    rows="$(ui_downmask_ab_target_selection_rows)"
    ui_render_page ui_render_downmask_ab_target_selection_page "$title" "$rows"
    ui_read "$prompt" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$((count + 1))" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    selected_count="$(printf '%s\n' "$indexes" | sed '/^$/d' | wc -l | tr -d ' ')"
    if printf '%s\n' "$indexes" | grep -qx '1'; then
        [ "$selected_count" = "1" ] || { ui_warn "所有B机不能和其他序号混合选择"; return 1; }
        UI_REPLY="$(seq 1 "$count")"
        return 0
    fi
    UI_REPLY="$(printf '%s\n' "$indexes" | awk '$1 > 1 { print $1 - 1 }')"
    [ -n "$UI_REPLY" ] || { ui_warn "请选择至少一个 B机"; return 1; }
}


ui_downmask_ab_pull_display_port() {
    local value="$1"
    local source="$2"
    case "$source" in
        override) printf '%s' "$value" ;;
        default) printf '%s（默认）' "$value" ;;
        *) printf '未设置' ;;
    esac
}


ui_downmask_ab_pull_display_local_ip() {
    local value="$1"
    local source="$2"
    case "$source" in
        override) printf '%s' "$value" ;;
        default) printf '%s（默认）' "$value" ;;
        *) printf '-' ;;
    esac
}


ui_downmask_ab_pull_display_token() {
    local source="$1"
    case "$source" in
        override) printf 'set（单独）' ;;
        default) printf 'set（默认）' ;;
        *) printf '未设置' ;;
    esac
}


ui_downmask_ab_pull_target_table_rows() {
    local target_json resolved_json idx host weight tcp udp effective_port effective_port_source effective_local_ip effective_local_ip_source effective_token_source
    idx=1
    while IFS= read -r target_json; do
        [ -n "$target_json" ] || continue
        resolved_json="$(downmask_ab_pull_effective_target_json "$target_json")"
        host="$(jq -r '.host // ""' <<< "$target_json")"
        weight="$(jq -r '.weight // 1' <<< "$target_json")"
        tcp="$(jq -r 'if has("tcp_enabled") then (if .tcp_enabled then "true" else "false" end) else "true" end' <<< "$target_json")"
        udp="$(jq -r 'if has("udp_enabled") then (if .udp_enabled then "true" else "false" end) else "true" end' <<< "$target_json")"
        effective_port="$(jq -r '.effective_port // ""' <<< "$resolved_json")"
        effective_port_source="$(jq -r '.effective_port_source // "unset"' <<< "$resolved_json")"
        effective_local_ip="$(jq -r '.effective_local_ip // ""' <<< "$resolved_json")"
        effective_local_ip_source="$(jq -r '.effective_local_ip_source // "unset"' <<< "$resolved_json")"
        effective_token_source="$(jq -r '.effective_token_source // "unset"' <<< "$resolved_json")"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$idx" \
            "$host" \
            "$(ui_downmask_ab_pull_display_port "$effective_port" "$effective_port_source")" \
            "$weight" \
            "$tcp" \
            "$udp" \
            "$(ui_downmask_ab_pull_display_local_ip "$effective_local_ip" "$effective_local_ip_source")" \
            "$(ui_downmask_ab_pull_display_token "$effective_token_source")"
        idx=$((idx + 1))
    done < <(jq -c '.[]' <<< "$(downmask_ab_pull_targets_json_list)")
}


ui_render_downmask_ab_pull_menu_page() {
    ui_header "A机拉流"
    ui_notice_render
    printf '当前 B机池：%s 台\n' "$(downmask_ab_target_count 2>/dev/null || echo 0)"
    printf '当前协议模式：%s\n' "$(downmask_config_get '.ab_pull.protocol_mode' 2>/dev/null || echo single)"
    printf '当前共享端口：%s\n' "$(downmask_config_get '.ab_pull.remote_port' 2>/dev/null || echo 0)"
    printf '当前共享限速：%s\n' "$(downmask_config_get '.ab_pull.speed_limit' 2>/dev/null || echo 4M)"
    echo
    ui_print_downmask_ab_pull_target_summary
    echo
    ui_menu_item 1 "默认拉流参数"
    ui_menu_item 2 "增加 B机"
    ui_menu_item 3 "修改 B机"
    ui_menu_item 4 "移除 B机"
    ui_menu_item 0 "返回上级菜单"
}


ui_menu_downmask_ab_pull() {
    while true; do
        ui_render_page ui_render_downmask_ab_pull_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_form_set "默认拉流参数" "默认双开 TCP+UDP 拉流。输入 0 返回。"
                local protocol protocol_mode tcp_enabled udp_enabled port local_ip token speed timeout parallel_limit speed_jitter bytes_jitter
                protocol=""
                protocol_mode="parallel"
                tcp_enabled="true"
                udp_enabled="true"
                ui_form_edit_read "默认远端端口（B机可单独覆盖）" "$(downmask_config_get '.ab_pull.remote_port')" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                port="$UI_REPLY"
                ui_form_edit_read "A机默认本地源 IP（可留空；B机可覆盖）" "$(downmask_config_get '.ab_pull.local_ip')" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                local_ip="$UI_REPLY"
                ui_form_edit_read "默认 Token（可留空；B机可覆盖；例如 openssl rand -hex 16）" "$(downmask_config_get '.ab_pull.token')" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                token="$UI_REPLY"
                ui_form_edit_read "默认限速（默认 $(format_downmask_speed_hint "4M")）" "$(downmask_config_get '.ab_pull.speed_limit')" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                speed="$UI_REPLY"
                ui_form_edit_read "超时秒数" "$(downmask_config_get '.ab_pull.timeout_seconds')" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                timeout="$UI_REPLY"
                ui_form_edit_read "并行上限（建议 2）" "$(downmask_config_get '.ab_pull.parallel_limit')" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                parallel_limit="$UI_REPLY"
                ui_form_read_allow_zero_value "限速抖动百分比（0-100，例如 12；默认 $(downmask_config_get '.ab_pull.speed_jitter_percent' 2>/dev/null || echo 12)）" "$(downmask_config_get '.ab_pull.speed_jitter_percent')" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                speed_jitter="$UI_REPLY"
                ui_form_read_allow_zero_value "单次字节抖动百分比（0-100，例如 18；默认 $(downmask_config_get '.ab_pull.bytes_jitter_percent' 2>/dev/null || echo 18)）" "$(downmask_config_get '.ab_pull.bytes_jitter_percent')" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                bytes_jitter="$UI_REPLY"

                local args=()
                [ -z "$protocol_mode" ] || args+=(--protocol-mode "$protocol_mode")
                [ -z "$protocol" ] || args+=(--protocol "$protocol")
                [ -z "$tcp_enabled" ] || args+=(--tcp-enabled "$tcp_enabled")
                [ -z "$udp_enabled" ] || args+=(--udp-enabled "$udp_enabled")
                [ -z "$port" ] || args+=(--remote-port "$port")
                [ -z "$local_ip" ] || args+=(--local-ip "$local_ip")
                [ -z "$token" ] || args+=(--token "$token")
                [ -z "$speed" ] || args+=(--speed-limit "$speed")
                [ -z "$timeout" ] || args+=(--timeout "$timeout")
                [ -z "$parallel_limit" ] || args+=(--parallel-limit "$parallel_limit")
                [ -z "$speed_jitter" ] || args+=(--speed-jitter-percent "$speed_jitter")
                [ -z "$bytes_jitter" ] || args+=(--bytes-jitter-percent "$bytes_jitter")
                ui_run cmd_downmask_ab_pull "${args[@]}"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "默认拉流参数已更新" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_form_set "增加 B机" "按 host 作为唯一键；再次添加同 host 会覆盖。输入 0 返回。"
                local host item_port item_local_ip item_token weight item_tcp item_udp default_port default_local_ip default_token default_port_hint default_local_ip_hint default_token_hint
                default_port="$(downmask_config_get '.ab_pull.remote_port')"
                default_local_ip="$(downmask_config_get '.ab_pull.local_ip')"
                default_token="$(downmask_config_get '.ab_pull.token')"
                if [ -n "$default_port" ] && [ "$default_port" != "0" ]; then
                    default_port_hint="留空=用默认端口 $default_port"
                else
                    default_port_hint="留空=当前无默认端口"
                fi
                if [ -n "$default_local_ip" ]; then
                    default_local_ip_hint="留空=用默认本地源IP $default_local_ip"
                else
                    default_local_ip_hint="留空=当前无默认本地源IP"
                fi
                if [ -n "$default_token" ]; then
                    default_token_hint="留空=用默认Token set"
                else
                    default_token_hint="留空=当前无默认Token"
                fi
                ui_form_edit_read "B机 IP/主机（建议直填 IPv4/IPv6）" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                host="$UI_REPLY"
                ui_form_edit_read "B机端口（$default_port_hint）" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                item_port="$UI_REPLY"
                ui_form_edit_read "B机本地源 IP（$default_local_ip_hint）" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                item_local_ip="$UI_REPLY"
                ui_form_edit_read "B机 Token（$default_token_hint）" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                item_token="$UI_REPLY"
                ui_form_edit_read "权重（默认 1）" "1" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                weight="$UI_REPLY"
                ui_form_select_read "允许 TCP" "2" "0) 返回" "1) 关闭" "2) 开启" || { ui_form_reset; continue; }
                [ "$UI_REPLY" = "0" ] && { ui_form_reset; continue; }
                case "$UI_REPLY" in 1) item_tcp="false" ;; 2) item_tcp="true" ;; esac
                ui_form_select_read "允许 UDP" "2" "0) 返回" "1) 关闭" "2) 开启" || { ui_form_reset; continue; }
                [ "$UI_REPLY" = "0" ] && { ui_form_reset; continue; }
                case "$UI_REPLY" in 1) item_udp="false" ;; 2) item_udp="true" ;; esac
                local target_args=(targets add --host "$host" --tcp-enabled "$item_tcp" --udp-enabled "$item_udp")
                [ -z "$item_port" ] || target_args+=(--port "$item_port")
                [ -z "$item_local_ip" ] || target_args+=(--local-ip "$item_local_ip")
                [ -z "$item_token" ] || target_args+=(--token "$item_token")
                [ -z "$weight" ] || target_args+=(--weight "$weight")
                ui_run cmd_downmask_ab_pull "${target_args[@]}"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "B机已增加" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                local selected_indexes selected_index selected_host current_target effective_target current_port current_local_ip current_token current_weight current_tcp current_udp effective_port effective_port_source effective_local_ip effective_local_ip_source effective_token_source
                ui_select_downmask_ab_targets_multi "修改 B机" "选择 B机 序号，可单/多/连续选择；1 表示所有B机" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                selected_indexes="$UI_REPLY"
                current_target="$(downmask_ab_pull_target_by_index "$(printf '%s\n' "$selected_indexes" | head -n1)")"
                effective_target="$(downmask_ab_pull_effective_target_json "$current_target")"
                current_port="$(jq -r '.port // ""' <<< "$current_target")"
                current_local_ip="$(jq -r '.local_ip // ""' <<< "$current_target")"
                current_token="$(jq -r '.token // ""' <<< "$current_target")"
                current_weight="$(jq -r '.weight // 1' <<< "$current_target")"
                current_tcp="$(jq -r 'if has("tcp_enabled") then (if .tcp_enabled then "true" else "false" end) else "true" end' <<< "$current_target")"
                current_udp="$(jq -r 'if has("udp_enabled") then (if .udp_enabled then "true" else "false" end) else "true" end' <<< "$current_target")"
                effective_port="$(jq -r '.effective_port // ""' <<< "$effective_target")"
                effective_port_source="$(jq -r '.effective_port_source // "unset"' <<< "$effective_target")"
                effective_local_ip="$(jq -r '.effective_local_ip // ""' <<< "$effective_target")"
                effective_local_ip_source="$(jq -r '.effective_local_ip_source // "unset"' <<< "$effective_target")"
                effective_token_source="$(jq -r '.effective_token_source // "unset"' <<< "$effective_target")"
                ui_form_set "修改 B机" "回车表示保留当前覆盖配置。以下“生效”值会参与实际拉流；带“默认”表示当前继承默认拉流参数。输入 0 返回。"
                local new_port new_local_ip new_token new_weight new_tcp new_udp
                ui_form_edit_read "B机端口（回车=保留；覆盖=${current_port:--}；生效=$(ui_downmask_ab_pull_display_port "$effective_port" "$effective_port_source")）" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                new_port="$UI_REPLY"
                ui_form_edit_read "B机本地源 IP（回车=保留；覆盖=${current_local_ip:--}；生效=$(ui_downmask_ab_pull_display_local_ip "$effective_local_ip" "$effective_local_ip_source")）" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                new_local_ip="$UI_REPLY"
                ui_form_edit_read "B机 Token（回车=保留；覆盖=$( [ -n "$current_token" ] && echo set || echo - )；生效=$(ui_downmask_ab_pull_display_token "$effective_token_source")）" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                new_token="$UI_REPLY"
                ui_form_edit_read "权重（回车=保留；当前 $current_weight）" "" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                new_weight="$UI_REPLY"
                ui_form_select_read "允许 TCP（当前 $current_tcp）" "0" "0) 保留" "1) 关闭" "2) 开启" || { ui_form_reset; continue; }
                case "$UI_REPLY" in 0) new_tcp="" ;; 1) new_tcp="false" ;; 2) new_tcp="true" ;; esac
                ui_form_select_read "允许 UDP（当前 $current_udp）" "0" "0) 保留" "1) 关闭" "2) 开启" || { ui_form_reset; continue; }
                case "$UI_REPLY" in 0) new_udp="" ;; 1) new_udp="false" ;; 2) new_udp="true" ;; esac
                local update_ok=0 update_fail=0 update_args
                while IFS= read -r selected_index; do
                    [ -n "$selected_index" ] || continue
                    selected_host="$(downmask_ab_pull_target_field_by_index "$selected_index" "host")"
                    [ -n "$selected_host" ] || { update_fail=$((update_fail + 1)); continue; }
                    update_args=(targets update --host "$selected_host" --tcp-enabled "$new_tcp" --udp-enabled "$new_udp")
                    [ -z "$new_port" ] || update_args+=(--port "$new_port")
                    [ -z "$new_local_ip" ] || update_args+=(--local-ip "$new_local_ip")
                    [ -z "$new_token" ] || update_args+=(--token "$new_token")
                    [ -z "$new_weight" ] || update_args+=(--weight "$new_weight")
                    if ui_try_cmd cmd_downmask_ab_pull "${update_args[@]}"; then
                        update_ok=$((update_ok + 1))
                    else
                        update_fail=$((update_fail + 1))
                        ui_error_from_reply "修改 B机失败：$selected_host"
                    fi
                done <<< "$selected_indexes"
                ui_form_reset
                UI_STATUS=$([ "$update_fail" -eq 0 ] && echo 0 || echo 1)
                if [ "$update_ok" -gt 0 ]; then
                    ui_notice_set "B机修改完成：成功 $update_ok 台，失败 $update_fail 台" "$UI_C_MENU_NUM"
                fi
                ui_maybe_pause always
                ;;
            4)
                local selected_indexes selected_index selected_host delete_ok delete_fail total_count
                ui_select_downmask_ab_targets_multi "移除 B机" "选择 B机 序号，可单/多/连续选择；1 表示移除所有" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                selected_indexes="$UI_REPLY"
                total_count="$(downmask_ab_pull_target_count 2>/dev/null || echo 0)"
                if [ "$(printf '%s\n' "$selected_indexes" | sed '/^$/d' | wc -l | tr -d ' ')" = "${total_count:-0}" ]; then
                    if ui_confirm_text "yes" "输入 yes 确认移除全部 B机"; then
                        ui_run cmd_downmask_ab_pull targets clear
                        [ "$UI_STATUS" -eq 0 ] && ui_notice_set "B机已全部移除" "$UI_C_MENU_NUM"
                        ui_maybe_pause success
                    else
                        ui_warn "已跳过"
                        ui_pause
                    fi
                    continue
                fi
                if ! ui_confirm_text "yes" "输入 yes 确认移除选中的 B机"; then
                    ui_warn "已跳过"
                    ui_pause
                    continue
                fi
                delete_ok=0
                delete_fail=0
                while IFS= read -r selected_index; do
                    [ -n "$selected_index" ] || continue
                    selected_host="$(downmask_ab_pull_target_field_by_index "$selected_index" "host")"
                    [ -n "$selected_host" ] || { delete_fail=$((delete_fail + 1)); continue; }
                    if ui_try_cmd cmd_downmask_ab_pull targets delete --host "$selected_host"; then
                        delete_ok=$((delete_ok + 1))
                    else
                        delete_fail=$((delete_fail + 1))
                        ui_error_from_reply "移除 B机失败：$selected_host"
                    fi
                done <<< "$(printf '%s\n' "$selected_indexes" | sort -rn)"
                UI_STATUS=$([ "$delete_fail" -eq 0 ] && echo 0 || echo 1)
                if [ "$delete_ok" -gt 0 ]; then
                    ui_notice_set "B机移除完成：成功 $delete_ok 台，失败 $delete_fail 台" "$UI_C_MENU_NUM"
                fi
                ui_maybe_pause always
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}


ui_menu_downmask_ab_feed() {
    ui_form_set "B机喂流" "配置 B 机 TCP/UDP 喂流服务。TCP/UDP 共用一套预共享 Token 与返回 IP。输入 0 返回上级菜单。"
    local tcp udp bind tcp_port udp_port token seed_file payload
    local seed_default="/var/lib/pfwd/downmask/seed.bin"

    ui_form_select_read "TCP 喂流" "2" "0) 返回" "1) 关闭" "2) 开启" || { ui_form_reset; return; }
    [ "$UI_REPLY" = "0" ] && { ui_form_reset; return; }
    case "$UI_REPLY" in 1) tcp="false" ;; 2) tcp="true" ;; esac
    ui_form_add_kv "TCP" "$tcp"
    ui_form_select_read "UDP 喂流" "2" "0) 返回" "1) 关闭" "2) 开启" || { ui_form_reset; return; }
    [ "$UI_REPLY" = "0" ] && { ui_form_reset; return; }
    case "$UI_REPLY" in 1) udp="false" ;; 2) udp="true" ;; esac
    ui_form_add_kv "UDP" "$udp"
    if [ "$tcp" = "false" ] && [ "$udp" = "false" ]; then
        ui_run cmd_downmask_ab_feed --tcp-enabled false --udp-enabled false
        ui_form_reset
        [ "$UI_STATUS" -eq 0 ] && ui_notice_set "B机喂流已更新" "$UI_C_MENU_NUM"
        ui_maybe_pause success
        return
    fi
    ui_form_edit_read "B机返回/监听 IP（填本机用于返回内容的 IP）" "$(downmask_config_get '.ab_feed.bind_ip')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    bind="$UI_REPLY"
    ui_form_add_kv "B机返回/监听 IP" "$bind"
    ui_form_edit_read "TCP 端口" "$(downmask_config_get '.ab_feed.tcp_port')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    tcp_port="$UI_REPLY"
    ui_form_edit_read "UDP 端口" "$(downmask_config_get '.ab_feed.udp_port')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    udp_port="$UI_REPLY"
    ui_form_edit_read "预共享 Token（TCP/UDP 共用；A/B 两端一致；可用 openssl rand -hex 16 生成）" "$(downmask_config_get '.ab_feed.token')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    token="$UI_REPLY"
    seed_file="$(downmask_config_get '.ab_feed.seed_file')"
    [ -n "$seed_file" ] || seed_file="$seed_default"
    ui_form_edit_read "种子文件路径（默认 $seed_default）" "$seed_file" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    seed_file="$UI_REPLY"
    ui_form_edit_read "UDP 包大小（支持 1200、1.2KB；范围 17-65507 字节，过小无意义，过大超出单个 UDP 载荷上限）" "$(downmask_config_get '.ab_feed.udp_payload_bytes')" || { ui_form_reset; return; }
    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; return; }
    payload="$UI_REPLY"

    local args=()
    args+=(--tcp-enabled "$tcp" --udp-enabled "$udp")
    [ -z "$bind" ] || args+=(--bind-ip "$bind")
    [ -z "$tcp_port" ] || args+=(--tcp-port "$tcp_port")
    [ -z "$udp_port" ] || args+=(--udp-port "$udp_port")
    [ -z "$token" ] || args+=(--token "$token")
    [ -z "$seed_file" ] || args+=(--seed-file "$seed_file")
    [ -z "$payload" ] || args+=(--udp-payload-bytes "$payload")
    ui_run cmd_downmask_ab_feed "${args[@]}"
    ui_form_reset
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "B机喂流已更新" "$UI_C_MENU_NUM"
    ui_maybe_pause success
}


ui_render_downmask_seed_menu_page() {
    ui_header "生成随机种子文件"
    ui_notice_render
    echo "默认生成 1GB 高熵文件到 /var/lib/pfwd/downmask/seed.bin"
    echo "推荐大小：256MB-4GB；更小随机性收益有限，更大更占磁盘且生成更慢。"
    echo
    ui_menu_item 1 "生成默认种子文件"
    ui_menu_item 2 "自定义大小生成"
    ui_menu_item 0 "返回上级菜单"
}


ui_menu_downmask_seed() {
    local size_input size_normalized
    while true; do
        ui_render_page ui_render_downmask_seed_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                if ui_confirm_text "yes" "输入 yes 确认生成"; then
                    ui_run cmd_downmask_seed generate
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "默认种子文件已生成" "$UI_C_MENU_NUM"
                    ui_maybe_pause success
                else
                    ui_warn "已跳过"
                    ui_pause
                fi
                ;;
            2)
                ui_form_set "自定义大小生成" "输入 0 返回。推荐 256MB-4GB；支持 256MB、1GB、2.5GB，裸数字按字节。"
                ui_form_edit_read "种子文件大小" "1GB" || { ui_form_reset; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_form_reset; continue; }
                size_input="$UI_REPLY"
                size_normalized="$(normalize_ui_downmask_size_input "$size_input")"
                ui_form_reset
                if ui_confirm_text "yes" "输入 yes 确认生成"; then
                    ui_run cmd_downmask_seed generate --size "$size_normalized"
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "自定义大小种子文件已生成" "$UI_C_MENU_NUM"
                    ui_maybe_pause success
                else
                    ui_warn "已跳过"
                    ui_pause
                fi
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}
