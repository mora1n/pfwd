#!/usr/bin/env bash

cmd_init() {
    config_init
    stats_init
    echo "已初始化：$PFWD_DB_FILE"
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


cmd_render() {
    local target="${1:-forwarder}"
    case "$target" in
        status) forwarder_status_json | jq '.' ;;
        xdp) forwarder_render_xdp_config ;;
        forwarder) forwarder_render_config ;;
        nft) fw_render_nft ;;
        tc) fw_render_tc ;;
        units)
            echo "# pfwd.service"
            service_manager_unit
            ;;
        *) pfwd_die "用法：pfwd render [forwarder|status|xdp|nft|tc|units]" ;;
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
    echo "已刷新"
}


cmd_restart() {
    [ "$#" -eq 0 ] || pfwd_die "用法：pfwd restart"
    config_init >/dev/null
    stats_rollup_current
    cmd_runtime_ready || return 0
    forwarder_stop_runtime
    cmd_apply_forwarding_bundle
    echo "已重启运行态"
}


cmd_service() {
    local action="${1:-}"
    [ -n "$action" ] || pfwd_die "用法：pfwd service status|reload|daemon [--socket PATH] [--db PATH] [--pfwd-bin PATH]"
    shift || true

    local socket_path="$PFWD_SERVICE_SOCKET"
    local db_path="$PFWD_DB_FILE"
    local pfwd_bin_path="$PFWD_BIN_PATH"
    local passthrough=()
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --socket)
                [ "$#" -ge 2 ] || pfwd_die "--socket 需要路径"
                socket_path="$2"
                shift 2
                ;;
            --db)
                [ "$#" -ge 2 ] || pfwd_die "--db 需要路径"
                db_path="$2"
                shift 2
                ;;
            --pfwd-bin)
                [ "$#" -ge 2 ] || pfwd_die "--pfwd-bin 需要路径"
                pfwd_bin_path="$2"
                shift 2
                ;;
            *)
                passthrough+=("$1")
                shift
                ;;
        esac
    done
    [ "${#passthrough[@]}" -eq 0 ] || pfwd_die "未知 service 参数：${passthrough[*]}"

    local bin_path
    bin_path="$(service_bin_path)"
    [ -x "$bin_path" ] || pfwd_die "pfwd-service 不可执行：$bin_path；请先执行 ./service/build.sh 或 pfwd install"

    case "$action" in
        daemon)
            exec "$bin_path" daemon --socket "$socket_path" --db "$db_path" --pfwd-bin "$pfwd_bin_path"
            ;;
        status)
            "$bin_path" status --socket "$socket_path"
            ;;
        reload)
            "$bin_path" reload --socket "$socket_path"
            ;;
        *)
            pfwd_die "用法：pfwd service status|reload|daemon [--socket PATH] [--db PATH] [--pfwd-bin PATH]"
            ;;
    esac
}
