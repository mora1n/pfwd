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
