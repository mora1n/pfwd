#!/usr/bin/env bash

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
