#!/usr/bin/env bash

cmd_init() {
    config_init
    echo "已初始化：$PFWD_CONFIG_FILE"
}

cmd_runtime_skip_notice() {
    echo "配置已保存；未检测到已安装运行态，跳过应用，请先执行 pfwd install"
}

cmd_runtime_ready() {
    if ! service_runtime_installed; then
        cmd_runtime_skip_notice
        return 1
    fi
    return 0
}

cmd_apply_forwarding_bundle() {
    config_init >/dev/null
    forwarder_validate_config
    stats_runtime_cache_clear
    cmd_runtime_ready || return 0
    forwarder_apply_runtime
    fw_apply_tc
    stats_runtime_cache_clear
}

cmd_apply_forwarder_runtime() {
    config_init >/dev/null
    forwarder_validate_config
    stats_runtime_cache_clear
    cmd_runtime_ready || return 0
    forwarder_apply_runtime
    stats_runtime_cache_clear
}

cmd_apply_firewall_runtime() {
    config_init >/dev/null
    stats_runtime_cache_clear
    cmd_runtime_ready || return 0
    forwarder_apply_runtime
    stats_runtime_cache_clear
}

cmd_apply_firewall_tc_runtime() {
    config_init >/dev/null
    stats_runtime_cache_clear
    cmd_runtime_ready || return 0
    forwarder_apply_runtime
    fw_apply_tc
    stats_runtime_cache_clear
}

cmd_apply_guard_runtime() {
    config_init >/dev/null
    stats_runtime_cache_clear
    cmd_runtime_ready || return 0
    forwarder_apply_runtime
    stats_runtime_cache_clear
}

cmd_refresh_after_change() {
    stats_rollup_current
    cmd_apply_forwarding_bundle
}

cmd_rollup_before_traffic_semantics_change() {
    stats_rollup_current
}

cmd_export() {
    [ "$#" -le 1 ] || pfwd_die "用法：pfwd export [file]"
    local file_path="${1:-$(pfwd_default_export_path)}"
    file_path="$(pfwd_expand_path "$file_path")"

    stats_rollup_current
    mkdir -p "$(dirname "$file_path")"
    config_export_bundle | pfwd_write_atomic "$file_path"
    echo "配置已导出：$file_path"
}

cmd_import() {
    [ "$#" -eq 1 ] || pfwd_die "用法：pfwd import <file>"
    local file_path="$1"
    file_path="$(pfwd_expand_path "$file_path")"

    config_import_bundle "$file_path"
    echo "配置已导入：$file_path"
    cmd_apply_runtime
}

cmd_update_check() {
    local work_dir="$1"
    local staged_dir="$work_dir/staged"
    local local_version remote_version local_digest remote_digest cmp

    local_version="$(service_installed_version 2>/dev/null || echo "$PFWD_VERSION")"
    remote_version="$(service_read_version_from_file "$staged_dir/pfwd.sh")"
    [ -n "$remote_version" ] || pfwd_die "无法解析远端版本号"

    local_digest="$(service_update_bundle_digest "$PFWD_INSTALL_DIR" install)"
    remote_digest="$(service_update_bundle_digest "$staged_dir" staged)"
    cmp="$(pfwd_version_compare "$remote_version" "$local_version")"

    echo "当前版本：$local_version"
    echo "远端版本：$remote_version"
    echo "更新源：$PFWD_REPO_RAW_URL"

    if [ "$cmp" -lt 0 ]; then
        echo "远端版本低于当前版本，已跳过"
        return 10
    fi
    if [ "$cmp" -eq 0 ] && [ "$local_digest" = "$remote_digest" ]; then
        echo "已是最新版本"
        return 10
    fi

    return 0
}

cmd_update_finalize_recover() {
    local work_dir="$1"
    local runtime_enabled="$2"
    local timer_enabled="$3"
    local guard_enabled="$4"
    local error_message="$5"

    service_update_rollback "$work_dir" || true
    service_update_restore_enabled_state "$runtime_enabled" "$timer_enabled" "$guard_enabled" || true
    pfwd_die "$error_message；已回滚；临时目录保留：$work_dir"
}

cmd_update_finalize() {
    local work_dir="" runtime_enabled="" timer_enabled="" guard_enabled="" from_version="" to_version=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --work-dir) work_dir="${2:-}"; shift 2 ;;
            --runtime-enabled) runtime_enabled="${2:-}"; shift 2 ;;
            --timer-enabled) timer_enabled="${2:-}"; shift 2 ;;
            --guard-enabled) guard_enabled="${2:-}"; shift 2 ;;
            --from-version) from_version="${2:-}"; shift 2 ;;
            --to-version) to_version="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done

    [ -n "$work_dir" ] || pfwd_die "缺少更新工作目录"

    if ! service_write_unit_files; then
        cmd_update_finalize_recover "$work_dir" "$runtime_enabled" "$timer_enabled" "$guard_enabled" "同步 systemd unit 失败"
    fi
    if ! service_update_restore_enabled_state "$runtime_enabled" "$timer_enabled" "$guard_enabled"; then
        cmd_update_finalize_recover "$work_dir" "$runtime_enabled" "$timer_enabled" "$guard_enabled" "恢复服务启用状态失败"
    fi
    if ! cmd_apply_runtime; then
        cmd_update_finalize_recover "$work_dir" "$runtime_enabled" "$timer_enabled" "$guard_enabled" "应用更新后的运行态失败"
    fi

    if ! service_update_cleanup "$work_dir"; then
        cmd_update_finalize_recover "$work_dir" "$runtime_enabled" "$timer_enabled" "$guard_enabled" "更新已完成，但清理临时文件失败"
    fi

    echo "更新完成：$from_version -> $to_version"
}

cmd_update() {
    local check_only="false"
    local auto_yes="false"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --check) check_only="true"; shift ;;
            --yes) auto_yes="true"; shift ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done

    service_installation_present || pfwd_die "未检测到已安装的 pfwd，请先执行 pfwd install"
    local work_dir staged_dir local_version remote_version runtime_enabled timer_enabled guard_enabled
    work_dir="$(service_update_create_workdir)"
    staged_dir="$work_dir/staged"

    if ! service_update_download_bundle "$work_dir"; then
        pfwd_die "下载更新包失败；请确认更新源包含必需的 pfwd-xdp/pfwd-downmask 预编译资产。临时目录保留：$work_dir"
    fi
    if ! service_update_validate_bundle "$staged_dir"; then
        pfwd_die "更新包校验失败；临时目录保留：$work_dir"
    fi
    if ! cmd_update_check "$work_dir"; then
        local check_status="$?"
        if [ "$check_status" = "10" ]; then
            service_update_cleanup "$work_dir" >/dev/null 2>&1 || true
            return 0
        fi
        pfwd_die "更新检查失败"
    fi

    if [ "$check_only" = "true" ]; then
        service_update_cleanup "$work_dir" >/dev/null 2>&1 || true
        return 0
    fi

    if [ "$auto_yes" != "true" ]; then
        if [ ! -t 0 ]; then
            pfwd_die "非交互环境请使用 pfwd update --yes"
        fi
        if ! ui_yes "检测到新版本，是否立即更新？"; then
            service_update_cleanup "$work_dir" >/dev/null 2>&1 || true
            echo "已取消"
            return 0
        fi
    fi

    local_version="$(service_installed_version)"
    remote_version="$(service_read_version_from_file "$staged_dir/pfwd.sh")"
    runtime_enabled="$(service_update_capture_enabled_state "$(service_primary_runtime_unit)")"
    timer_enabled="$(service_update_capture_enabled_state "$(service_timer_unit_name)")"
    guard_enabled="$(service_update_capture_enabled_state "$(service_guard_unit_name)")"

    service_update_backup_current "$work_dir"
    if ! service_update_apply_staged "$work_dir"; then
        service_update_rollback "$work_dir" || true
        pfwd_die "更新失败，已回滚；临时目录保留：$work_dir"
    fi

    if ! exec "$PFWD_INSTALL_DIR/pfwd.sh" __update_finalize \
        --work-dir "$work_dir" \
        --runtime-enabled "$runtime_enabled" \
        --timer-enabled "$timer_enabled" \
        --guard-enabled "$guard_enabled" \
        --from-version "$local_version" \
        --to-version "$remote_version"; then
        service_update_rollback "$work_dir" || true
        pfwd_die "更新收尾启动失败，已回滚；临时目录保留：$work_dir"
    fi
}

cmd_user() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        add)
            [ "$#" -eq 1 ] || pfwd_die "用法：pfwd user add <username>"
            local user_id
            user_id="$(normalize_user_id "$1")"
            config_add_user "$user_id"
            echo "用户已添加：$user_id"
            ;;
        list)
            config_init >/dev/null
            jq -r '.users[]?.id' "$PFWD_CONFIG_FILE"
            ;;
        delete)
            cmd_user_delete "$@"
            ;;
        telegram)
            cmd_user_telegram "$@"
            ;;
        *) pfwd_die "用法：pfwd user add|list|delete|telegram" ;;
    esac
}

cmd_format_remote() {
    local host="$1"
    local port="$2"
    if [[ "$host" == *:* ]]; then
        printf '[%s]:%s' "$host" "$port"
    else
        printf '%s:%s' "$host" "$port"
    fi
}

cmd_protocol_label() {
    case "${1:-tcp_udp}" in
        tcp) printf 'TCP' ;;
        udp) printf 'UDP' ;;
        *) printf 'TCP+UDP' ;;
    esac
}

cmd_forward_state_label() {
    local enabled="$1"
    local stop_at="${2:-}"
    if [ "$enabled" = "true" ]; then
        printf '启用'
        return 0
    fi
    if pfwd_stop_at_expired "$stop_at"; then
        printf '停止'
        return 0
    fi
    printf '停用'
}

cmd_print_user_forward_summary() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local listen_port remote_host remote_port protocol enabled stop_at remote_text state_text
    while IFS=$'\t' read -r listen_port remote_host remote_port protocol enabled stop_at; do
        [ -n "$listen_port" ] || continue
        remote_text="$(cmd_format_remote "$remote_host" "$remote_port")"
        state_text="$(cmd_forward_state_label "$enabled" "$stop_at")"
        printf '  %s -> %s  %s  %s\n' "$listen_port" "$remote_text" "$(cmd_protocol_label "$protocol")" "$state_text"
    done < <(config_user_forward_summary_tsv "$user_id")
}

cmd_user_delete() {
    [ "$#" -ge 1 ] || pfwd_die "用法：pfwd user delete <username> [--cascade]"
    local user_id cascade="false"
    user_id="$(normalize_user_id "$1")"
    shift || true
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --cascade) cascade="true"; shift ;;
            *) pfwd_die "用法：pfwd user delete <username> [--cascade]" ;;
        esac
    done
    [ -n "$user_id" ] || pfwd_die "用法：pfwd user delete <username> [--cascade]"

    local forward_count deleted_ports
    forward_count="$(config_user_forward_count "$user_id")"
    if [ "$forward_count" -gt 0 ] && [ "$cascade" != "true" ]; then
        echo "用户 $user_id 仍有关联转发："
        cmd_print_user_forward_summary "$user_id"
        pfwd_die "如需连带删除上述端口，请使用：pfwd user delete $user_id --cascade"
    fi

    if [ "$forward_count" -gt 0 ]; then
        deleted_ports="$(config_user_forward_summary_tsv "$user_id" | awk -F $'\t' 'NF {print $1}' | paste -sd, -)"
        config_delete_user_cascade "$user_id"
        echo "用户已删除：$user_id（同时删除 $forward_count 条转发：$deleted_ports）"
        stats_rollup_current
        cmd_apply_forwarding_bundle
        return 0
    fi

    config_delete_user "$user_id"
    echo "用户已删除：$user_id"
}

cmd_user_telegram() {
    local user_id="${1:-}"
    local token="" chat_id="" server_name="" enabled="true" has_server_name="false"
    local apply_all="false"
    if [ "$user_id" = "--all" ]; then
        apply_all="true"
        user_id=""
    else
        shift || true
        user_id="$(normalize_user_id "$user_id")"
        [ -n "$user_id" ] || pfwd_die "用法：pfwd user telegram <username>|--all --bot-token TOKEN --chat-id CHAT_ID"
    fi
    if [ "$apply_all" = "true" ]; then
        shift || true
    fi
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --bot-token) token="${2:-}"; shift 2 ;;
            --chat-id) chat_id="${2:-}"; shift 2 ;;
            --server-name) server_name="${2:-}"; has_server_name="true"; shift 2 ;;
            --enabled) enabled="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -n "$token" ] || pfwd_die "必须提供 --bot-token"
    [ -n "$chat_id" ] || pfwd_die "必须提供 --chat-id"
    if [ "$has_server_name" != "true" ]; then
        server_name="$(hostname 2>/dev/null || echo pfwd)"
    fi
    if [ "$apply_all" = "true" ]; then
        config_set_all_users_telegram "$token" "$chat_id" "$server_name" "__KEEP__"
        echo "Telegram 配置已批量更新：全部用户"
    else
        config_set_user_telegram "$user_id" "$token" "$chat_id" "$server_name" "$enabled"
        echo "Telegram 配置已更新：$user_id"
    fi
}

cmd_notify_schedule() {
    local user_id="" interval_minutes="__KEEP__" daily_time="__KEEP__"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            --interval-minutes) interval_minutes="${2:-}"; shift 2 ;;
            --daily-time) daily_time="${2:-}"; shift 2 ;;
            --clear-interval) interval_minutes=""; shift ;;
            --clear-daily) daily_time=""; shift ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    user_id="$(normalize_user_id "$user_id")"
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    if [ "$interval_minutes" = "__KEEP__" ] && [ "$daily_time" = "__KEEP__" ]; then
        pfwd_die "至少提供一个定时发送设置"
    fi
    config_set_user_telegram_schedule "$user_id" "$interval_minutes" "$daily_time"
    if { [ "$interval_minutes" != "__KEEP__" ] && [ -n "$interval_minutes" ]; } || { [ "$daily_time" != "__KEEP__" ] && [ -n "$daily_time" ]; }; then
        config_enable_user_telegram "$user_id"
    fi
    echo "Telegram 定时发送已更新：$user_id"
}

cmd_notify_enable() {
    local user_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    user_id="$(normalize_user_id "$user_id")"
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    config_enable_user_telegram "$user_id"
    echo "Telegram 通知已启用：$user_id"
}

cmd_notify_disable() {
    local user_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    user_id="$(normalize_user_id "$user_id")"
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    config_disable_user_telegram "$user_id"
    echo "Telegram 通知已停用：$user_id"
}

cmd_notify_delete() {
    local user_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    user_id="$(normalize_user_id "$user_id")"
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    config_delete_user_telegram "$user_id"
    echo "Telegram 配置已删除：$user_id"
}

cmd_add() {
    local user_id="" remote="" listen_ip="" listen_port="" random_range="" stop_at="" protocol="tcp_udp" traffic_mode="two-way"
    local traffic_ratio="1.0" comment="" mss_mode="" mss_value="" snat_mode="masquerade" snat_source=""
    local stop_at_explicit="false" traffic_mode_explicit="false"
    config_init >/dev/null
    listen_ip="$(jq -r '.settings.default_listen_ip // "::"' "$PFWD_CONFIG_FILE")"

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            --remote) remote="${2:-}"; shift 2 ;;
            --listen-ip) listen_ip="${2:-}"; shift 2 ;;
            --listen-port) listen_port="${2:-}"; shift 2 ;;
            --random-port) random_range="${2:-}"; shift 2 ;;
            --stop-at) stop_at="${2:-}"; stop_at_explicit="true"; shift 2 ;;
            --protocol) protocol="${2:-}"; shift 2 ;;
            --traffic-mode) traffic_mode="${2:-}"; traffic_mode_explicit="true"; shift 2 ;;
            --traffic-ratio) traffic_ratio="${2:-}"; shift 2 ;;
            --comment) comment="${2:-}"; shift 2 ;;
            --mss-clamp) mss_mode="clamp"; mss_value=""; shift ;;
            --mss) mss_mode="set"; mss_value="${2:-}"; shift 2 ;;
            --snat-source) snat_mode="snat"; snat_source="${2:-}"; shift 2 ;;
            --masquerade) snat_mode="masquerade"; snat_source=""; shift ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done

    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    [ -n "$remote" ] || pfwd_die "必须提供 --remote"

    local user_defaults default_rate="" default_stop_at="" default_traffic_mode=""
    user_defaults="$(config_user_forward_defaults_json "$user_id")"
    default_rate="$(jq -r '.rate // ""' <<< "$user_defaults")"
    default_stop_at="$(jq -r '.stop_at // ""' <<< "$user_defaults")"
    default_traffic_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$user_defaults")"

    if [ "$traffic_mode_explicit" != "true" ] && [ -n "$default_traffic_mode" ]; then
        traffic_mode="$default_traffic_mode"
    fi
    if [ "$stop_at_explicit" = "true" ] && [ "$stop_at" = "-" ]; then
        stop_at=""
    elif [ "$stop_at_explicit" != "true" ] && [ -n "$default_stop_at" ]; then
        stop_at="$default_stop_at"
    fi

    local parsed remote_host remote_ports listen_ports reserved="" port forward_ids count
    parsed="$(parse_host_port_spec "$remote")"
    remote_host="${parsed%	*}"
    remote_ports="$(expand_port_spec "${parsed##*	}")"

    if [ -z "$listen_port" ]; then
        [ -n "$random_range" ] || pfwd_die "必须提供 --listen-port 或 --random-port"
        validate_port_range "$random_range"
        listen_ports=""
        while IFS= read -r port; do
            [ -n "$port" ] || continue
            local picked
            picked="$(pfwd_pick_random_port "$random_range" "$reserved")"
            reserved="$reserved $picked"
            listen_ports="${listen_ports}${picked}"$'\n'
        done <<< "$remote_ports"
        listen_ports="${listen_ports%$'\n'}"
    else
        listen_ports="$(expand_port_spec "$listen_port")"
    fi

    forward_ids="$(config_add_forward_batch "$user_id" "$listen_ip" "$listen_ports" "$remote_host" "$remote_ports" "$stop_at" "$traffic_mode" "$protocol" "$traffic_ratio" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$default_rate")"
    count="$(printf '%s\n' "$forward_ids" | sed '/^$/d' | wc -l | tr -d ' ')"
    echo "转发已添加：$count 条"
    printf '%s\n' "$forward_ids" | sed '/^$/d' | sed 's/^/  /'
    stats_rollup_current
    cmd_apply_forwarding_bundle
}

cmd_list() {
    local user_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    config_init >/dev/null
    if [ -n "$user_id" ]; then
        jq -r --arg id "$user_id" '
          def hostport($host; $port):
            if ($host | contains(":")) then "[" + $host + "]:" + ($port | tostring)
            else $host + ":" + ($port | tostring)
            end;
          .forwards[]?
          | select(.user_id == $id)
          | (.net.snat_source // "") as $snat_source
          | [.id,.user_id,.enabled,.listen_port,hostport(.remote_host; .remote_port),(.protocol // "tcp_udp"),(.stop_at // "-"),.traffic_mode,((.traffic_ratio // 1) | tostring),(.net.mss_mode // "-"),(if $snat_source == "" then (.net.snat_mode // "masquerade") else $snat_source end)]
          | @tsv
        ' "$PFWD_CONFIG_FILE"
    else
        jq -r '
          def hostport($host; $port):
            if ($host | contains(":")) then "[" + $host + "]:" + ($port | tostring)
            else $host + ":" + ($port | tostring)
            end;
          .forwards[]?
          | (.net.snat_source // "") as $snat_source
          | [.id,.user_id,.enabled,.listen_port,hostport(.remote_host; .remote_port),(.protocol // "tcp_udp"),(.stop_at // "-"),.traffic_mode,((.traffic_ratio // 1) | tostring),(.net.mss_mode // "-"),(if $snat_source == "" then (.net.snat_mode // "masquerade") else $snat_source end)]
          | @tsv
        ' "$PFWD_CONFIG_FILE"
    fi
}

cmd_toggle_forward() {
    local enabled="$1"
    shift
    [ "$#" -eq 1 ] || pfwd_die "用法：pfwd start|stop <forward_id>"
    config_set_forward_enabled "$1" "$enabled"
    echo "转发状态已更新：$1 enabled=$enabled"
    stats_rollup_current
    cmd_apply_forwarding_bundle
}

cmd_delete() {
    [ "$#" -eq 1 ] || pfwd_die "用法：pfwd delete <forward_id>"
    config_delete_forward "$1"
    echo "转发已删除：$1"
    stats_rollup_current
    cmd_apply_forwarding_bundle
}

cmd_expire() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        set)
            local id="${1:-}" stop_at=""
            shift || true
            [ -n "$id" ] || pfwd_die "必须提供转发 id"
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --stop-at) stop_at="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$stop_at" ] || pfwd_die "必须提供 --stop-at"
            config_set_forward_expire "$id" "$stop_at"
            stop_at="$(jq -r --arg id "$id" '.forwards[] | select(.id == $id) | .stop_at' "$PFWD_CONFIG_FILE")"
            echo "转发到期时间已更新：$id stop_at=$stop_at"
            stats_rollup_current
            cmd_apply_forwarding_bundle
            ;;
        clear)
            local id="${1:-}"
            [ -n "$id" ] || pfwd_die "必须提供转发 id"
            config_clear_forward_expire "$id"
            echo "转发到期时间已清空：$id"
            stats_rollup_current
            cmd_apply_forwarding_bundle
            ;;
        user-set)
            local user_id="" stop_at=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --user-id) user_id="${2:-}"; shift 2 ;;
                    --stop-at) stop_at="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
            [ -n "$stop_at" ] || pfwd_die "必须提供 --stop-at"
            config_set_user_forwards_expire "$user_id" "$stop_at"
            echo "用户全部转发到期时间已更新：$(normalize_user_id "$user_id")"
            stats_rollup_current
            cmd_apply_forwarding_bundle
            ;;
        user-clear)
            local user_id=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --user-id) user_id="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
            config_clear_user_forwards_expire "$user_id"
            echo "用户全部转发到期时间已清空：$(normalize_user_id "$user_id")"
            stats_rollup_current
            cmd_apply_forwarding_bundle
            ;;
        *)
            pfwd_die "用法：pfwd expire set|clear|user-set|user-clear"
            ;;
    esac
}

cmd_limit() {
    local sub="${1:-}"
    shift || true
    [ "$sub" = "set" ] || pfwd_die "用法：pfwd limit set --forward-id ID|--user-id ID"
    local forward_id="" user_id="" traffic="" rate="" mode=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --forward-id) forward_id="${2:-}"; shift 2 ;;
            --user-id) user_id="${2:-}"; shift 2 ;;
            --traffic) traffic="${2:-}"; shift 2 ;;
            --rate) rate="${2:-}"; shift 2 ;;
            --traffic-mode) mode="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    local traffic_bytes="__KEEP__" normalized_rate="__KEEP__"
    [ -z "$traffic" ] || traffic_bytes="$(parse_size_bytes "$traffic")"
    [ -z "$rate" ] || normalized_rate="$(normalize_rate "$rate")"
    if [ -n "$forward_id" ] && [ -z "$user_id" ]; then
        stats_rollup_current
        if [ -n "$mode" ]; then
            cmd_rollup_before_traffic_semantics_change
        fi
        config_set_forward_limit "$forward_id" "$traffic_bytes" "$normalized_rate" "$mode"
        echo "转发限制已更新：$forward_id"
        cmd_apply_firewall_tc_runtime
    elif [ -n "$user_id" ] && [ -z "$forward_id" ]; then
        stats_rollup_current
        config_set_user_limit "$user_id" "$traffic_bytes" "$normalized_rate" "$mode"
        echo "用户限制已更新：$user_id"
        cmd_apply_firewall_tc_runtime
    else
        pfwd_die "只能设置 --forward-id 或 --user-id 其中一个"
    fi
}

cmd_forward() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        update) cmd_forward_update "$@" ;;
        *) pfwd_die "用法：pfwd forward update --forward-id ID [--listen-ip IP] [--listen-port PORT] [--remote-host HOST] [--remote-port PORT] [--stop-at YYYYMMDD[ HH:MM]|YYYY-MM-DD[ HH:MM]|YYYY/MM/DD[ HH:MM]|+7|7d|--clear-stop-at] [--protocol tcp|udp|tcp_udp] [--traffic-mode one-way|two-way] [--traffic-ratio 1.0] [--comment TEXT|--clear-comment] [--mss-clamp|--mss VALUE|--clear-mss] [--masquerade|--snat-source IP]" ;;
    esac
}

cmd_forward_update() {
    local forward_id=""
    local before current_comment current_listen_ip current_listen_port current_remote_host current_remote_port current_stop_at current_protocol current_traffic_mode current_traffic_ratio current_mss_mode current_mss_value current_snat_mode current_snat_source
    local after updated_comment updated_listen_ip updated_listen_port updated_remote_host updated_remote_port updated_stop_at updated_protocol updated_traffic_mode updated_traffic_ratio updated_mss_mode updated_mss_value updated_snat_mode updated_snat_source
    local changed_forwarding="false" changed_stats="false" changed_comment="false"
    local listen_ip="__KEEP__" listen_port="__KEEP__" remote_host="__KEEP__" remote_port="__KEEP__"
    local stop_at="__KEEP__" protocol="__KEEP__" traffic_mode="__KEEP__"
    local traffic_ratio="__KEEP__" comment="__KEEP__" mss_mode="__KEEP__" mss_value="__KEEP__" snat_mode="__KEEP__" snat_source="__KEEP__"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --forward-id) forward_id="${2:-}"; shift 2 ;;
            --listen-ip) listen_ip="${2:-}"; shift 2 ;;
            --listen-port) listen_port="${2:-}"; shift 2 ;;
            --remote-host) remote_host="${2:-}"; shift 2 ;;
            --remote-port) remote_port="${2:-}"; shift 2 ;;
            --stop-at) stop_at="${2:-}"; shift 2 ;;
            --clear-stop-at) stop_at="__CLEAR__"; shift ;;
            --protocol) protocol="${2:-}"; shift 2 ;;
            --traffic-mode) traffic_mode="${2:-}"; shift 2 ;;
            --traffic-ratio) traffic_ratio="${2:-}"; shift 2 ;;
            --comment) comment="${2:-}"; shift 2 ;;
            --clear-comment) comment="__CLEAR__"; shift ;;
            --mss-clamp) mss_mode="clamp"; mss_value="__CLEAR__"; shift ;;
            --mss) mss_mode="set"; mss_value="${2:-}"; shift 2 ;;
            --clear-mss) mss_mode="__CLEAR__"; mss_value="__CLEAR__"; shift ;;
            --snat-source) snat_mode="snat"; snat_source="${2:-}"; shift 2 ;;
            --masquerade) snat_mode="masquerade"; snat_source="__CLEAR__"; shift ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -n "$forward_id" ] || pfwd_die "必须提供 --forward-id"
    before="$(jq -c --arg id "$forward_id" '.forwards[] | select(.id == $id)' "$PFWD_CONFIG_FILE")"
    current_comment="$(jq -r '.comment // ""' <<< "$before")"
    current_listen_ip="$(jq -r '.listen_ip // ""' <<< "$before")"
    current_listen_port="$(jq -r '.listen_port | tostring' <<< "$before")"
    current_remote_host="$(jq -r '.remote_host' <<< "$before")"
    current_remote_port="$(jq -r '.remote_port | tostring' <<< "$before")"
    current_stop_at="$(jq -r '.stop_at // ""' <<< "$before")"
    current_protocol="$(jq -r '.protocol // "tcp_udp"' <<< "$before")"
    current_traffic_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$before")"
    current_traffic_ratio="$(jq -r '(.traffic_ratio // 1) | tostring' <<< "$before")"
    current_mss_mode="$(jq -r '.net.mss_mode // ""' <<< "$before")"
    current_mss_value="$(jq -r 'if (.net.mss_value // null) == null then "" else (.net.mss_value | tostring) end' <<< "$before")"
    current_snat_mode="$(jq -r '.net.snat_mode // "masquerade"' <<< "$before")"
    current_snat_source="$(jq -r '.net.snat_source // ""' <<< "$before")"
    if [ "$traffic_mode" != "__KEEP__" ] || [ "$traffic_ratio" != "__KEEP__" ]; then
        cmd_rollup_before_traffic_semantics_change
    fi
    config_update_forward "$forward_id" "$listen_ip" "$listen_port" "$remote_host" "$remote_port" "$stop_at" "$protocol" "$traffic_mode" "$traffic_ratio" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source"
    after="$(jq -c --arg id "$forward_id" '.forwards[] | select(.id == $id)' "$PFWD_CONFIG_FILE")"
    updated_comment="$(jq -r '.comment // ""' <<< "$after")"
    updated_listen_ip="$(jq -r '.listen_ip // ""' <<< "$after")"
    updated_listen_port="$(jq -r '.listen_port | tostring' <<< "$after")"
    updated_remote_host="$(jq -r '.remote_host' <<< "$after")"
    updated_remote_port="$(jq -r '.remote_port | tostring' <<< "$after")"
    updated_stop_at="$(jq -r '.stop_at // ""' <<< "$after")"
    updated_protocol="$(jq -r '.protocol // "tcp_udp"' <<< "$after")"
    updated_traffic_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$after")"
    updated_traffic_ratio="$(jq -r '(.traffic_ratio // 1) | tostring' <<< "$after")"
    updated_mss_mode="$(jq -r '.net.mss_mode // ""' <<< "$after")"
    updated_mss_value="$(jq -r 'if (.net.mss_value // null) == null then "" else (.net.mss_value | tostring) end' <<< "$after")"
    updated_snat_mode="$(jq -r '.net.snat_mode // "masquerade"' <<< "$after")"
    updated_snat_source="$(jq -r '.net.snat_source // ""' <<< "$after")"
    if [ "$current_comment" != "$updated_comment" ]; then
        changed_comment="true"
    fi
    if [ "$current_traffic_mode" != "$updated_traffic_mode" ] || [ "$current_traffic_ratio" != "$updated_traffic_ratio" ]; then
        changed_stats="true"
    fi
    if [ "$current_listen_ip" != "$updated_listen_ip" ] || [ "$current_listen_port" != "$updated_listen_port" ] || [ "$current_remote_host" != "$updated_remote_host" ] || [ "$current_remote_port" != "$updated_remote_port" ] || [ "$current_stop_at" != "$updated_stop_at" ] || [ "$current_protocol" != "$updated_protocol" ] || [ "$current_mss_mode" != "$updated_mss_mode" ] || [ "$current_mss_value" != "$updated_mss_value" ] || [ "$current_snat_mode" != "$updated_snat_mode" ] || [ "$current_snat_source" != "$updated_snat_source" ]; then
        changed_forwarding="true"
    fi
    echo "转发已更新：$forward_id"
    if [ "$changed_forwarding" = "true" ]; then
        stats_rollup_current
        cmd_apply_forwarding_bundle
    elif [ "$changed_stats" = "true" ]; then
        cmd_apply_firewall_runtime
    elif [ "$changed_comment" = "true" ]; then
        :
    fi
}

cmd_user_forwards_traffic_mode() {
    local user_id="" traffic_mode=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            --traffic-mode) traffic_mode="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    [ -n "$traffic_mode" ] || pfwd_die "必须提供 --traffic-mode"
    cmd_rollup_before_traffic_semantics_change
    config_set_user_forwards_traffic_mode "$user_id" "$traffic_mode"
    echo "用户全部转发流量模式已更新：$(normalize_user_id "$user_id") mode=$traffic_mode"
    cmd_apply_firewall_runtime
}

cmd_user_forwards_limit() {
    local user_id="" traffic="__KEEP__" rate="__KEEP__" mode="__KEEP__"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            --traffic) traffic="${2:-}"; shift 2 ;;
            --rate) rate="${2:-}"; shift 2 ;;
            --traffic-mode) mode="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    user_id="$(normalize_user_id "$user_id")"
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"

    local traffic_bytes="__KEEP__" normalized_rate="__KEEP__"
    [ "$traffic" = "__KEEP__" ] || traffic_bytes="$(parse_size_bytes "$traffic")"
    [ "$rate" = "__KEEP__" ] || normalized_rate="$(normalize_rate "$rate")"

    if [ "$mode" != "__KEEP__" ]; then
        cmd_rollup_before_traffic_semantics_change
    fi
    config_set_user_forward_limits "$user_id" "$traffic_bytes" "$normalized_rate" "$mode"
    echo "用户全部转发限制已更新：$user_id"
    stats_rollup_current
    cmd_apply_firewall_tc_runtime
}

cmd_traffic() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        used)
            local scope="${1:-}"
            shift || true
            [ "$scope" = "set" ] || pfwd_die "用法：pfwd traffic used set --user-id ID|--forward-id ID --used 100GB"
            local user_id="" forward_id="" used=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --user-id) user_id="${2:-}"; shift 2 ;;
                    --forward-id) forward_id="${2:-}"; shift 2 ;;
                    --used) used="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$used" ] || pfwd_die "必须提供 --used"
            local used_bytes
            used_bytes="$(parse_size_bytes "$used")"
            if [ -n "$user_id" ] && [ -z "$forward_id" ]; then
                stats_set_user_used "$user_id" "$used_bytes"
                echo "用户已用流量已更新：$(normalize_user_id "$user_id")"
            elif [ -n "$forward_id" ] && [ -z "$user_id" ]; then
                stats_set_forward_used "$forward_id" "$used_bytes"
                echo "转发已用流量已更新：$forward_id"
            else
                pfwd_die "只能设置 --user-id 或 --forward-id 其中一个"
            fi
            cmd_apply_firewall_runtime
            ;;
        reset-day)
            local scope="${1:-}"
            shift || true
            [ "$scope" = "set" ] || pfwd_die "用法：pfwd traffic reset-day set --user-id ID|--forward-id ID --day 0|15|15T09:30|'15 09:30'"
            local user_id="" forward_id="" day=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --user-id) user_id="${2:-}"; shift 2 ;;
                    --forward-id) forward_id="${2:-}"; shift 2 ;;
                    --day) day="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$day" ] || pfwd_die "必须提供 --day"
            if [ -n "$user_id" ] && [ -z "$forward_id" ]; then
                stats_set_user_reset_day "$user_id" "$day"
                echo "用户流量重置日已更新：$(normalize_user_id "$user_id") day=$day"
            elif [ -n "$forward_id" ] && [ -z "$user_id" ]; then
                stats_set_forward_reset_day "$forward_id" "$day"
                echo "转发流量重置日已更新：$forward_id day=$day"
            else
                pfwd_die "只能设置 --user-id 或 --forward-id 其中一个"
            fi
            ;;
        reset-now)
            local user_id="" forward_id=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --user-id) user_id="${2:-}"; shift 2 ;;
                    --forward-id) forward_id="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            if [ -n "$user_id" ] && [ -z "$forward_id" ]; then
                stats_reset_user_cycle "$user_id"
                echo "用户流量已重置：$(normalize_user_id "$user_id")"
            elif [ -n "$forward_id" ] && [ -z "$user_id" ]; then
                stats_reset_forward_cycle "$forward_id"
                echo "转发流量已重置：$forward_id"
            else
                pfwd_die "只能设置 --user-id 或 --forward-id 其中一个"
            fi
            cmd_apply_firewall_runtime
            ;;
        *) pfwd_die "用法：pfwd traffic used|reset-day|reset-now" ;;
    esac
}

stats_json() {
    local user_id="$1"
    local forward_id="$2"
    local counters
    counters="$(stats_usage_json)"
    jq --arg user "$user_id" --arg fwd "$forward_id" '
      .forwards |= map(select(($user == "" or .user_id == $user) and ($fwd == "" or .id == $fwd)))
      | .total_bytes = ([.forwards[].total_bytes] | add // 0)
    ' <<< "$counters"
}

cmd_stats() {
    local user_id="" forward_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            --forward-id) forward_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    stats_json "$user_id" "$forward_id" | jq '.'
}

cmd_doctor_benchmark() {
    local label="$1"
    local command="$2"
    local loops="${3:-3}"
    local start_ns end_ns elapsed_ms total_ms=0 max_ms=0 run_ms loop
    for ((loop = 1; loop <= loops; loop++)); do
        start_ns="$(date +%s%N 2>/dev/null || true)"
        bash -lc "$command" >/dev/null 2>&1 || {
            echo "$label：n/a"
            return 0
        }
        end_ns="$(date +%s%N 2>/dev/null || true)"
        if [[ ! "$start_ns" =~ ^[0-9]+$ ]] || [[ ! "$end_ns" =~ ^[0-9]+$ ]]; then
            echo "$label：ok"
            return 0
        fi
        run_ms=$(( (end_ns - start_ns) / 1000000 ))
        total_ms=$((total_ms + run_ms))
        if [ "$run_ms" -gt "$max_ms" ]; then
            max_ms="$run_ms"
        fi
    done
    elapsed_ms=$(( total_ms / loops ))
    echo "$label：avg=${elapsed_ms}ms max=${max_ms}ms loops=${loops}"
}

cmd_doctor_runner() {
    local body="$1"
    local script_dir script_path
    script_dir="$(printf '%q' "$PFWD_SCRIPT_DIR")"
    script_path="$(printf '%q' "$PFWD_SCRIPT_DIR/pfwd.sh")"
    printf 'cd %s && tmp_root="$(mktemp -d /tmp/pfwd-bench.XXXXXX)" && trap '\''rm -rf "$tmp_root"'\'' EXIT && export PFWD_ROOT_PREFIX="$tmp_root" PFWD_SKIP_SHORTCUT=1 && { source %s help >/dev/null 2>&1 || true; config_init >/dev/null 2>&1; %s; }' "$script_dir" "$script_path" "$body"
}

cmd_doctor_benchmarks() {
    cmd_doctor_benchmark "benchmark.stats_current_snapshot" "$(cmd_doctor_runner 'stats_current_snapshot >/dev/null')"
    cmd_doctor_benchmark "benchmark.stats_rollup_current" "$(cmd_doctor_runner 'stats_rollup_current >/dev/null')"
    cmd_doctor_benchmark "benchmark.xdp_read_counters" "$(cmd_doctor_runner 'fw_read_counters >/dev/null')"
    cmd_doctor_benchmark "benchmark.xdp_runtime_json" "$(cmd_doctor_runner 'forwarder_runtime_json true >/dev/null')"
    cmd_doctor_benchmark "benchmark.ui_main_usage_json" "$(cmd_doctor_runner 'UI_COLOR_ENABLED=0; ui_main_usage_json >/dev/null')"
    cmd_doctor_benchmark "benchmark.main_page" "$(cmd_doctor_runner 'UI_COLOR_ENABLED=0; ui_render_main_menu_page >/dev/null')"
    cmd_doctor_benchmark "benchmark.forward_list" "$(cmd_doctor_runner 'UI_COLOR_ENABLED=0; ui_print_forward_list >/dev/null')"
}

cmd_doctor_usage() {
    cat <<'EOF'
用法：pfwd doctor [--bench]
EOF
}

cmd_render() {
    local target="${1:-forwarder}"
    case "$target" in
        status) forwarder_status_json | jq '.' ;;
        xdp) forwarder_render_xdp_config ;;
        forwarder) forwarder_render_config ;;
        nft) fw_render_nft ;;
        tc) fw_render_tc ;;
        guard) guard_render_status ;;
        downmask) downmask_status_json | jq '.' ;;
        units)
            echo "# pfwd.service"
            service_manager_unit
            echo "# pfwd.timer"
            service_timer_unit
            echo "# pfwd-bbr.service"
            bbr_service_unit
            echo "# pfwd-xdp.service"
            guard_service_unit
            if [ -f "$(downmask_feed_unit_path)" ]; then
                echo "# pfwd-downmask-feed.service"
                cat "$(downmask_feed_unit_path)"
            fi
            ;;
        *) pfwd_die "用法：pfwd render [forwarder|status|nft|tc|guard|downmask|units]" ;;
    esac
}

cmd_apply_runtime() {
    cmd_apply_forwarding_bundle
    echo "已刷新"
}

cmd_refresh() {
    config_init >/dev/null
    stats_rollup_current
    cmd_apply_forwarding_bundle
    downmask_reload_feed_service 2>/dev/null || true
    echo "已刷新"
}

cmd_restart() {
    [ "$#" -eq 0 ] || pfwd_die "用法：pfwd restart"
    config_init >/dev/null
    stats_rollup_current
    cmd_runtime_ready || return 0
    forwarder_stop_runtime
    cmd_apply_forwarding_bundle
    downmask_reload_feed_service 2>/dev/null || true
    echo "已重启运行态"
}

cmd_reconcile() {
    config_init >/dev/null
    local before after now_minute need_refresh=false sent
    if stats_apply_due_resets; then
        need_refresh=true
    fi
    now_minute="$(pfwd_now_minute)"
    before="$(jq '[.forwards[]? | select(.enabled == true)] | length' "$PFWD_CONFIG_FILE")"
    config_disable_expired "$now_minute"
    config_disable_telegram_for_expired_users "$now_minute"
    after="$(jq '[.forwards[]? | select(.enabled == true)] | length' "$PFWD_CONFIG_FILE")"
    if [ "$before" != "$after" ]; then
        need_refresh=true
    fi
    if [ "$need_refresh" = "true" ]; then
        stats_rollup_current
        cmd_apply_forwarding_bundle
    fi
    sent="$(notify_reconcile_schedules)"
    downmask_reconcile_pull 2>/dev/null || true
    echo "已同步：active_before=$before active_after=$after notify_sent=$sent"
}

cmd_notify_test() {
    local user_id=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --user-id) user_id="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -n "$user_id" ] || pfwd_die "必须提供 --user-id"
    notify_send_telegram "$user_id" "$(notify_status_message "$user_id")" "false"
    echo "通知已发送：$user_id"
}

cmd_doctor() {
    local include_bench="false"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --bench) include_bench="true"; shift ;;
            help|-h|--help)
                cmd_doctor_usage
                return 0
                ;;
            *)
                cmd_doctor_usage >&2
                pfwd_die "未知选项：$1"
                ;;
        esac
    done
    config_init >/dev/null
    local forwarder_status xdp_status backend fallback_reason hybrid_reason tc_iface tc_ifb tc_mode xdp_active_total xdp_tcp_prewarmed xdp_tcp_established xdp_udp_active
    local dataplane_version map_abi_version incremental_apply preserved_connections invalidated_connections profile_counts
    local refresh_mode refresh_total_ms refresh_reconcile_ms refresh_map_load_ms refresh_aux_actions refresh_attach_timings
    local refresh_rules_added refresh_rules_updated refresh_rules_deleted refresh_users_added refresh_users_updated refresh_users_deleted
    local refresh_counters_preserved refresh_counters_reset
    stats_runtime_cache_clear
    forwarder_status="$(forwarder_status_json)"
    xdp_status="$(forwarder_xdp_status_json)"
    backend="$(jq -r '.forwarding_backend // "none"' <<< "$forwarder_status")"
    fallback_reason="$(jq -r '.fallback_reason // empty' <<< "$forwarder_status")"
    hybrid_reason="$(jq -r '.hybrid_reason // empty' <<< "$forwarder_status")"
    xdp_active_total="$(jq -r '.active_summary.total // 0' <<< "$xdp_status")"
    xdp_tcp_prewarmed="$(jq -r '.active_summary.tcp_syn_pending // 0' <<< "$xdp_status")"
    xdp_tcp_established="$(jq -r '.active_summary.tcp_established // 0' <<< "$xdp_status")"
    xdp_udp_active="$(jq -r '.active_summary.udp // 0' <<< "$xdp_status")"
    dataplane_version="$(jq -r '.dataplane_version // .xdp_status.dataplane_version // "-" ' <<< "$forwarder_status")"
    map_abi_version="$(jq -r '.map_abi_version // .xdp_status.map_abi_version // "-" ' <<< "$forwarder_status")"
    incremental_apply="$(jq -r '.xdp_status.incremental_apply // .incremental_apply // false' <<< "$forwarder_status")"
    preserved_connections="$(jq -r '.xdp_status.preserved_connections // .preserved_connections // 0' <<< "$forwarder_status")"
    invalidated_connections="$(jq -r '.xdp_status.invalidated_connections // .invalidated_connections // 0' <<< "$forwarder_status")"
    profile_counts="$(jq -r '((.profile_counts // .xdp_status.profile_counts // {}) | to_entries | sort_by(.key) | map("\(.key)=\(.value)") | join(", ")) as $profiles | if $profiles == "" then "-" else $profiles end' <<< "$forwarder_status")"
    refresh_mode="$(jq -r '.xdp_status.refresh_report.mode // .refresh_report.mode // "-"' <<< "$forwarder_status")"
    refresh_total_ms="$(jq -r '.xdp_status.refresh_report.total_duration_ms // .refresh_report.total_duration_ms // "-"' <<< "$forwarder_status")"
    refresh_reconcile_ms="$(jq -r '.xdp_status.refresh_report.reconcile_duration_ms // .refresh_report.reconcile_duration_ms // "-"' <<< "$forwarder_status")"
    refresh_map_load_ms="$(jq -r '.xdp_status.refresh_report.map_load_duration_ms // .refresh_report.map_load_duration_ms // "-"' <<< "$forwarder_status")"
    refresh_aux_actions="$(jq -r '((.xdp_status.refresh_report.aux_actions // []) | map(.component + "=" + .action + (if ((.changed_items // 0) > 0) then "(" + ((.changed_items | tostring)) + ")" else "" end)) | join(", ")) as $actions | if $actions == "" then "-" else $actions end' <<< "$forwarder_status")"
    refresh_attach_timings="$(jq -r '((.xdp_status.refresh_report.attach_timings // []) | map(.component + "=" + ((.duration_ms | tostring)) + "ms") | join(", ")) as $timings | if $timings == "" then "-" else $timings end' <<< "$forwarder_status")"
    refresh_rules_added="$(jq -r '.xdp_status.refresh_report.rules_added // .refresh_report.rules_added // 0' <<< "$forwarder_status")"
    refresh_rules_updated="$(jq -r '.xdp_status.refresh_report.rules_updated // .refresh_report.rules_updated // 0' <<< "$forwarder_status")"
    refresh_rules_deleted="$(jq -r '.xdp_status.refresh_report.rules_deleted // .refresh_report.rules_deleted // 0' <<< "$forwarder_status")"
    refresh_users_added="$(jq -r '.xdp_status.refresh_report.users_added // .refresh_report.users_added // 0' <<< "$forwarder_status")"
    refresh_users_updated="$(jq -r '.xdp_status.refresh_report.users_updated // .refresh_report.users_updated // 0' <<< "$forwarder_status")"
    refresh_users_deleted="$(jq -r '.xdp_status.refresh_report.users_deleted // .refresh_report.users_deleted // 0' <<< "$forwarder_status")"
    refresh_counters_preserved="$(jq -r '.xdp_status.refresh_report.counters_preserved // .refresh_report.counters_preserved // 0' <<< "$forwarder_status")"
    refresh_counters_reset="$(jq -r '.xdp_status.refresh_report.counters_reset // .refresh_report.counters_reset // 0' <<< "$forwarder_status")"
    tc_iface="$(fw_tc_state_read_iface 2>/dev/null || true)"
    tc_ifb="$(fw_tc_ifb_name 2>/dev/null || true)"
    if [ -n "$tc_iface" ]; then
        tc_mode="bidirectional-ifb"
    elif [ "$(fw_effective_rate_count 2>/dev/null || echo 0)" -gt 0 ]; then
        tc_mode="configured-no-runtime"
    else
        tc_mode="disabled"
    fi
    echo "配置文件：$PFWD_CONFIG_FILE"
    jq -e . "$PFWD_CONFIG_FILE" >/dev/null && echo "配置 JSON：正常"
    echo "数据面：$backend"
    if [ -n "$fallback_reason" ]; then
        echo "回退原因：$fallback_reason"
    elif [ "$hybrid_reason" = "loopback-split" ]; then
        echo "混合原因：localhost 分流"
    fi
    echo "dataplane.version：$dataplane_version"
    echo "dataplane.map_abi：$map_abi_version"
    echo "xdp.incremental_apply：$incremental_apply"
    echo "xdp.preserved_connections：$preserved_connections"
    echo "xdp.invalidated_connections：$invalidated_connections"
    echo "xdp.refresh_mode：$refresh_mode"
    echo "xdp.refresh_total_ms：$refresh_total_ms"
    echo "xdp.refresh_map_load_ms：$refresh_map_load_ms"
    echo "xdp.refresh_reconcile_ms：$refresh_reconcile_ms"
    echo "xdp.refresh_aux_actions：$refresh_aux_actions"
    echo "xdp.refresh_attach_timings：$refresh_attach_timings"
    echo "xdp.rules_added：$refresh_rules_added"
    echo "xdp.rules_updated：$refresh_rules_updated"
    echo "xdp.rules_deleted：$refresh_rules_deleted"
    echo "xdp.users_added：$refresh_users_added"
    echo "xdp.users_updated：$refresh_users_updated"
    echo "xdp.users_deleted：$refresh_users_deleted"
    echo "xdp.counters_preserved：$refresh_counters_preserved"
    echo "xdp.counters_reset：$refresh_counters_reset"
    echo "xdp.profile_counts：${profile_counts:-"-"}"
    echo "运行态文件：$PFWD_FORWARDER_RUNTIME_FILE"
    if [ -x "$(forwarder_bin_path)" ]; then echo "pfwd-xdp：$(forwarder_bin_path)"; else echo "pfwd-xdp：缺失"; fi
    if command -v tc >/dev/null 2>&1; then echo "tc：$(command -v tc)"; else echo "tc：缺失"; fi
    echo "xdp.active_total：$xdp_active_total"
    echo "xdp.tcp_syn_pending：$xdp_tcp_prewarmed"
    echo "xdp.tcp_established：$xdp_tcp_established"
    echo "xdp.udp_active：$xdp_udp_active"
    echo "tc.mode：$tc_mode"
    if [ -n "$tc_iface" ]; then echo "tc.iface：$tc_iface"; fi
    if [ -n "$tc_ifb" ] && [ "$tc_mode" = "bidirectional-ifb" ]; then echo "tc.ifb：$tc_ifb"; fi
    if command -v systemctl >/dev/null 2>&1; then echo "systemctl：正常"; else echo "systemctl：缺失"; fi
    if guard_binary_exists; then echo "guard：$(guard_bin_path)"; else echo "guard：缺失"; fi
    echo "运行态安装：$(service_runtime_status_label)"
    if service_unit_exists pfwd.timer; then echo "pfwd.timer：已安装"; else echo "pfwd.timer：未安装"; fi
    if service_unit_exists pfwd-bbr.service; then echo "pfwd-bbr.service：已安装"; else echo "pfwd-bbr.service：未安装"; fi
    if service_unit_exists pfwd-xdp.service; then echo "pfwd-xdp.service：已安装"; else echo "pfwd-xdp.service：未安装"; fi
    if service_unit_exists pfwd-downmask-feed.service; then echo "pfwd-downmask-feed.service：已安装"; else echo "pfwd-downmask-feed.service：未安装"; fi
    if [ -x "$PFWD_DOWNMASK_BIN_PATH" ]; then echo "pfwd-downmask：$PFWD_DOWNMASK_BIN_PATH"; else echo "pfwd-downmask：缺失"; fi
    echo "转发数量：$(jq '.forwards | length' "$PFWD_CONFIG_FILE")"
    echo "用户数量：$(jq '.users | length' "$PFWD_CONFIG_FILE")"
    guard_render_status | while IFS=$'\t' read -r key value; do
        printf 'guard.%s：%s\n' "$key" "$value"
    done
    whitelist_render_status | while IFS=$'\t' read -r key value; do
        printf 'guard_whitelist.%s：%s\n' "$key" "$value"
    done
    egress_whitelist_render_status | while IFS=$'\t' read -r key value; do
        printf 'guard_egress_whitelist.%s：%s\n' "$key" "$value"
    done
    downmask_render_status | while IFS=$'\t' read -r key value; do
        printf 'downmask.%s：%s\n' "$key" "$value"
    done
    if [ "$include_bench" = "true" ]; then
        cmd_doctor_benchmarks
    else
        echo "benchmark：已省略（使用 pfwd doctor --bench 查看）"
    fi
}

cmd_install() {
    config_init
    service_install_files
    service_enable
    cmd_apply_runtime
    echo "已安装：$PFWD_BIN_PATH"
    echo "BBR 管理入口：$PFWD_BBR_ALIAS_BIN_PATH"
}

cmd_forward_boot() {
    config_init >/dev/null
    forwarder_validate_config
    cmd_apply_forwarding_bundle
    echo "boot restore complete"
}

cmd_guard() {
    config_init >/dev/null
    local sub="${1:-status}"
    shift || true
    case "$sub" in
        enable)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard enable"
            guard_config_set_enabled true
            cmd_apply_guard_runtime
            echo "guard 已启用"
            ;;
        disable)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard disable"
            guard_config_set_enabled false
            cmd_apply_guard_runtime
            echo "guard 已停用"
            ;;
        apply)
            local quiet="false"
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --quiet) quiet="true"; shift ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            cmd_apply_guard_runtime
            ;;
        remove)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard remove"
            guard_config_set_enabled false
            cmd_apply_guard_runtime
            echo "guard 已移除"
            ;;
        status)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard status"
            guard_render_status
            ;;
        protocols)
            local http="__KEEP__" https="__KEEP__" tls="__KEEP__" socks="__KEEP__"
            local skip_port="" replace_skip_ports="false" clear_skip_ports="false" tmp_ports skip_ports_input=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --http) http="${2:-}"; shift 2 ;;
                    --https) https="${2:-}"; shift 2 ;;
                    --tls) tls="${2:-}"; shift 2 ;;
                    --socks) socks="${2:-}"; shift 2 ;;
                    --skip-port)
                        skip_port="${2:-}"
                        shift 2
                        [ -n "$skip_port" ] || pfwd_die "缺少 --skip-port 值"
                        skip_ports_input+=$'\n'"$skip_port"
                        ;;
                    --replace-skip-ports) replace_skip_ports="true"; shift ;;
                    --clear-skip-ports) clear_skip_ports="true"; shift ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ "$http" = "__KEEP__" ] || validate_bool "$http"
            [ "$https" = "__KEEP__" ] || validate_bool "$https"
            [ "$tls" = "__KEEP__" ] || validate_bool "$tls"
            [ "$socks" = "__KEEP__" ] || validate_bool "$socks"
            if [ -n "$skip_ports_input" ]; then
                while IFS= read -r skip_port; do
                    [ -n "$skip_port" ] || continue
                    while IFS= read -r expanded_port; do
                        [ -n "$expanded_port" ] || continue
                        validate_port "$expanded_port"
                    done < <(expand_port_spec "$skip_port")
                done <<< "$skip_ports_input"
            fi
            if [ "$https" != "__KEEP__" ]; then
                http="$https"
                tls="$https"
            fi
            [ "$http" = "__KEEP__" ] && http="$(guard_block_http)"
            [ "$tls" = "__KEEP__" ] && tls="$(guard_block_tls)"
            [ "$socks" = "__KEEP__" ] && socks="$(guard_block_socks)"
            guard_config_set_protocols "$http" "$tls" "$socks"
            tmp_ports="$(mktemp)"
            if [ "$clear_skip_ports" != "true" ]; then
                if [ "$replace_skip_ports" != "true" ]; then
                    guard_protocol_skip_ports_tsv > "$tmp_ports"
                fi
                if [ -n "$skip_ports_input" ]; then
                    while IFS= read -r skip_port; do
                        [ -n "$skip_port" ] || continue
                        expand_port_spec "$skip_port" >> "$tmp_ports"
                    done <<< "$skip_ports_input"
                fi
            fi
            guard_config_set_protocol_skip_ports "$tmp_ports"
            rm -f "$tmp_ports"
            cmd_apply_guard_runtime
            echo "guard 配置已更新"
            ;;
        whitelist)
            cmd_guard_whitelist "$@"
            ;;
        whitelist-cn)
            cmd_guard_whitelist_cn "$@"
            ;;
        whitelist-custom)
            cmd_guard_whitelist_custom "$@"
            ;;
        egress-whitelist)
            cmd_guard_egress_whitelist "$@"
            ;;
        egress-whitelist-cn)
            cmd_guard_egress_whitelist_cn "$@"
            ;;
        egress-whitelist-custom)
            cmd_guard_egress_whitelist_custom "$@"
            ;;
        *)
            pfwd_die "用法：pfwd guard enable|disable|status|apply|remove|protocols|whitelist|whitelist-cn|whitelist-custom|egress-whitelist|egress-whitelist-cn|egress-whitelist-custom"
            ;;
    esac
}

cmd_guard_whitelist() {
    config_init >/dev/null
    local enabled="__KEEP__" include_cn="__KEEP__" cidr="" replace_custom="false" clear_custom="false"
    local cn_mode="__KEEP__"
    local status_requested="false"
    local tmp_cidrs current_cidrs

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --enabled) enabled="${2:-}"; shift 2 ;;
            --include-cn) include_cn="${2:-}"; shift 2 ;;
            --cn-mode) cn_mode="${2:-}"; shift 2 ;;
            --cidr) cidr="${2:-}"; shift 2 ;;
            --replace-custom) replace_custom="true"; shift ;;
            --clear-custom) clear_custom="true"; shift ;;
            status) status_requested="true"; shift ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done

    if [ "$status_requested" = "true" ] && [ "$enabled" = "__KEEP__" ] && [ "$include_cn" = "__KEEP__" ] && [ "$cn_mode" = "__KEEP__" ] && [ -z "$cidr" ] && [ "$clear_custom" = "false" ]; then
        whitelist_render_status
        return 0
    fi

    [ "$enabled" = "__KEEP__" ] || validate_bool "$enabled"
    [ "$include_cn" = "__KEEP__" ] || validate_bool "$include_cn"
    if [ "$cn_mode" != "__KEEP__" ]; then
        whitelist_validate_cn_mode "$cn_mode"
    fi
    if [ -n "$cidr" ]; then
        cidr="$(normalize_ip_or_cidr "$cidr")"
    fi

    if [ "$enabled" = "__KEEP__" ]; then
        enabled="$(whitelist_enabled)"
    fi
    if [ "$include_cn" = "__KEEP__" ]; then
        :
    elif [ "$cn_mode" = "__KEEP__" ]; then
        if [ "$include_cn" = "true" ]; then
            cn_mode="all"
        else
            cn_mode="off"
        fi
    fi
    if [ "$cn_mode" = "__KEEP__" ]; then
        cn_mode="$(whitelist_cn_mode)"
    fi
    whitelist_config_set_state "$enabled" "$cn_mode"

    tmp_cidrs="$(mktemp)"
    if [ "$clear_custom" != "true" ]; then
        if [ "$replace_custom" != "true" ]; then
            whitelist_custom_cidrs_tsv > "$tmp_cidrs"
        fi
        if [ -n "$cidr" ]; then
            printf '%s\n' "$cidr" >> "$tmp_cidrs"
        fi
    fi
    whitelist_config_set_custom_cidrs "$tmp_cidrs"
    rm -f "$tmp_cidrs"

    whitelist_apply_runtime
    cmd_apply_guard_runtime
    echo "协议封锁 / 入口白名单已更新"
}

cmd_guard_whitelist_custom() {
    config_init >/dev/null
    local sub="${1:-}"
    shift || true
    case "$sub" in
        list)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-custom list"
            whitelist_custom_cidrs_tsv
            ;;
        add)
            local cidr="${1:-}"
            [ -n "$cidr" ] || pfwd_die "用法：pfwd guard whitelist-custom add <IPv4/IPv6 CIDR 或单个 IP>"
            cidr="$(normalize_ip_or_cidr "$cidr")"
            whitelist_append_custom_cidr "$cidr"
            whitelist_apply_runtime
            cmd_apply_guard_runtime
            echo "入口白名单自定义 CIDR 已添加：$cidr"
            ;;
        clear)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-custom clear"
            whitelist_clear_custom_cidrs
            whitelist_apply_runtime
            cmd_apply_guard_runtime
            echo "入口白名单自定义 CIDR 已清空"
            ;;
        delete)
            [ "$#" -ge 1 ] || pfwd_die "用法：pfwd guard whitelist-custom delete <index...>"
            whitelist_delete_custom_cidrs_by_indexes "$(printf '%s\n' "$@")"
            whitelist_apply_runtime
            cmd_apply_guard_runtime
            echo "入口白名单自定义 CIDR 已删除"
            ;;
        update)
            local index="${1:-}" cidr="${2:-}"
            [ -n "$index" ] && [ -n "$cidr" ] || pfwd_die "用法：pfwd guard whitelist-custom update <index> <IPv4/IPv6 CIDR 或单个 IP>"
            cidr="$(normalize_ip_or_cidr "$cidr")"
            whitelist_replace_custom_cidr_by_index "$index" "$cidr"
            whitelist_apply_runtime
            cmd_apply_guard_runtime
            echo "入口白名单自定义 CIDR 已更新：$index -> $cidr"
            ;;
        *)
            pfwd_die "用法：pfwd guard whitelist-custom list|add|clear|delete|update"
            ;;
    esac
}

cmd_guard_egress_whitelist() {
    config_init >/dev/null
    local enabled="__KEEP__" include_cn="__KEEP__" cidr="" replace_custom="false" clear_custom="false"
    local cn_mode="__KEEP__"
    local status_requested="false"
    local tmp_cidrs

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --enabled) enabled="${2:-}"; shift 2 ;;
            --include-cn) include_cn="${2:-}"; shift 2 ;;
            --cn-mode) cn_mode="${2:-}"; shift 2 ;;
            --cidr) cidr="${2:-}"; shift 2 ;;
            --replace-custom) replace_custom="true"; shift ;;
            --clear-custom) clear_custom="true"; shift ;;
            status) status_requested="true"; shift ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done

    if [ "$status_requested" = "true" ] && [ "$enabled" = "__KEEP__" ] && [ "$include_cn" = "__KEEP__" ] && [ "$cn_mode" = "__KEEP__" ] && [ -z "$cidr" ] && [ "$clear_custom" = "false" ]; then
        egress_whitelist_render_status
        return 0
    fi

    [ "$enabled" = "__KEEP__" ] || validate_bool "$enabled"
    [ "$include_cn" = "__KEEP__" ] || validate_bool "$include_cn"
    if [ "$cn_mode" != "__KEEP__" ]; then
        egress_whitelist_validate_cn_mode "$cn_mode"
    fi
    if [ -n "$cidr" ]; then
        cidr="$(normalize_ip_or_cidr "$cidr")"
    fi

    if [ "$enabled" = "__KEEP__" ]; then
        enabled="$(egress_whitelist_enabled)"
    fi
    if [ "$include_cn" = "__KEEP__" ]; then
        :
    elif [ "$cn_mode" = "__KEEP__" ]; then
        if [ "$include_cn" = "true" ]; then
            cn_mode="all"
        else
            cn_mode="off"
        fi
    fi
    if [ "$cn_mode" = "__KEEP__" ]; then
        cn_mode="$(egress_whitelist_cn_mode)"
    fi
    egress_whitelist_config_set_state "$enabled" "$cn_mode"

    tmp_cidrs="$(mktemp)"
    if [ "$clear_custom" != "true" ]; then
        if [ "$replace_custom" != "true" ]; then
            egress_whitelist_custom_cidrs_tsv > "$tmp_cidrs"
        fi
        if [ -n "$cidr" ]; then
            printf '%s\n' "$cidr" >> "$tmp_cidrs"
        fi
    fi
    egress_whitelist_config_set_custom_cidrs "$tmp_cidrs"
    rm -f "$tmp_cidrs"

    egress_whitelist_apply_runtime
    if ! egress_whitelist_validate_config_file "$PFWD_CONFIG_FILE"; then
        pfwd_die "$EGRESS_WHITELIST_LAST_ERROR"
    fi
    cmd_apply_guard_runtime
    echo "出口白名单已更新"
}

cmd_guard_whitelist_cn() {
    config_init >/dev/null
    local sub="${1:-status}"
    shift || true
    case "$sub" in
        list)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-cn list"
            whitelist_geo_province_rows
            ;;
        status)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-cn status"
            printf 'mode=%s\n' "$(whitelist_cn_mode)"
            printf 'selection=%s\n' "$(whitelist_cn_selection_summary)"
            ;;
        all)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-cn all"
            whitelist_config_apply_cn_selection all
            whitelist_apply_runtime
            cmd_apply_guard_runtime
            echo "入口白名单国内策略已更新为：国内IP"
            ;;
        off)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-cn off"
            whitelist_config_apply_cn_selection off
            whitelist_apply_runtime
            cmd_apply_guard_runtime
            echo "入口白名单国内策略已关闭"
            ;;
        select)
            [ "$#" -ge 1 ] || pfwd_die "用法：pfwd guard whitelist-cn select <省份...>"
            local tmp
            tmp="$(mktemp)"
            printf '%s\n' "$@" > "$tmp"
            whitelist_config_apply_cn_selection provinces "$tmp"
            rm -f "$tmp"
            whitelist_apply_runtime
            cmd_apply_guard_runtime
            echo "入口白名单国内策略已更新为省份选择"
            ;;
        *)
            pfwd_die "用法：pfwd guard whitelist-cn list|status|all|off|select"
            ;;
    esac
}

cmd_guard_egress_whitelist_cn() {
    config_init >/dev/null
    local sub="${1:-status}"
    shift || true
    case "$sub" in
        list)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-cn list"
            whitelist_geo_province_rows
            ;;
        status)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-cn status"
            printf 'mode=%s\n' "$(egress_whitelist_cn_mode)"
            printf 'selection=%s\n' "$(egress_whitelist_cn_selection_summary)"
            ;;
        all)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-cn all"
            egress_whitelist_config_apply_cn_selection all
            egress_whitelist_apply_runtime
            if ! egress_whitelist_validate_config_file "$PFWD_CONFIG_FILE"; then
                pfwd_die "$EGRESS_WHITELIST_LAST_ERROR"
            fi
            cmd_apply_guard_runtime
            echo "出口白名单国内策略已更新为：国内IP"
            ;;
        off)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-cn off"
            egress_whitelist_config_apply_cn_selection off
            egress_whitelist_apply_runtime
            if ! egress_whitelist_validate_config_file "$PFWD_CONFIG_FILE"; then
                pfwd_die "$EGRESS_WHITELIST_LAST_ERROR"
            fi
            cmd_apply_guard_runtime
            echo "出口白名单国内策略已关闭"
            ;;
        select)
            [ "$#" -ge 1 ] || pfwd_die "用法：pfwd guard egress-whitelist-cn select <省份...>"
            local tmp
            tmp="$(mktemp)"
            printf '%s\n' "$@" > "$tmp"
            egress_whitelist_config_apply_cn_selection provinces "$tmp"
            rm -f "$tmp"
            egress_whitelist_apply_runtime
            if ! egress_whitelist_validate_config_file "$PFWD_CONFIG_FILE"; then
                pfwd_die "$EGRESS_WHITELIST_LAST_ERROR"
            fi
            cmd_apply_guard_runtime
            echo "出口白名单国内策略已更新为省份选择"
            ;;
        *)
            pfwd_die "用法：pfwd guard egress-whitelist-cn list|status|all|off|select"
            ;;
    esac
}

cmd_guard_egress_whitelist_custom() {
    config_init >/dev/null
    local sub="${1:-}"
    shift || true
    case "$sub" in
        list)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-custom list"
            egress_whitelist_custom_cidrs_tsv
            ;;
        add)
            local cidr="${1:-}"
            [ -n "$cidr" ] || pfwd_die "用法：pfwd guard egress-whitelist-custom add <IPv4/IPv6 CIDR 或单个 IP>"
            cidr="$(normalize_ip_or_cidr "$cidr")"
            egress_whitelist_append_custom_cidr "$cidr"
            egress_whitelist_apply_runtime
            if ! egress_whitelist_validate_config_file "$PFWD_CONFIG_FILE"; then
                pfwd_die "$EGRESS_WHITELIST_LAST_ERROR"
            fi
            cmd_apply_guard_runtime
            echo "出口白名单自定义 CIDR 已添加：$cidr"
            ;;
        clear)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-custom clear"
            egress_whitelist_clear_custom_cidrs
            egress_whitelist_apply_runtime
            if ! egress_whitelist_validate_config_file "$PFWD_CONFIG_FILE"; then
                pfwd_die "$EGRESS_WHITELIST_LAST_ERROR"
            fi
            cmd_apply_guard_runtime
            echo "出口白名单自定义 CIDR 已清空"
            ;;
        delete)
            [ "$#" -ge 1 ] || pfwd_die "用法：pfwd guard egress-whitelist-custom delete <index...>"
            egress_whitelist_delete_custom_cidrs_by_indexes "$(printf '%s\n' "$@")"
            egress_whitelist_apply_runtime
            if ! egress_whitelist_validate_config_file "$PFWD_CONFIG_FILE"; then
                pfwd_die "$EGRESS_WHITELIST_LAST_ERROR"
            fi
            cmd_apply_guard_runtime
            echo "出口白名单自定义 CIDR 已删除"
            ;;
        update)
            local index="${1:-}" cidr="${2:-}"
            [ -n "$index" ] && [ -n "$cidr" ] || pfwd_die "用法：pfwd guard egress-whitelist-custom update <index> <IPv4/IPv6 CIDR 或单个 IP>"
            cidr="$(normalize_ip_or_cidr "$cidr")"
            egress_whitelist_replace_custom_cidr_by_index "$index" "$cidr"
            egress_whitelist_apply_runtime
            if ! egress_whitelist_validate_config_file "$PFWD_CONFIG_FILE"; then
                pfwd_die "$EGRESS_WHITELIST_LAST_ERROR"
            fi
            cmd_apply_guard_runtime
            echo "出口白名单自定义 CIDR 已更新：$index -> $cidr"
            ;;
        *)
            pfwd_die "用法：pfwd guard egress-whitelist-custom list|add|clear|delete|update"
            ;;
    esac
}

cmd_uninstall() {
    local uninstall_status=0
    while [ "$#" -gt 0 ]; do
        pfwd_die "未知选项：$1"
    done
    service_uninstall_files || uninstall_status=1
    config_snapshot_invalidate
    service_purge_state || uninstall_status=1
    service_verify_removed || uninstall_status=1
    [ "$uninstall_status" -eq 0 ] || return "$uninstall_status"
    echo "已卸载 pfwd；若需卸载 BBR 调优，请另外执行：$PFWD_BBR_ALIAS_BIN_PATH uninstall"
}
