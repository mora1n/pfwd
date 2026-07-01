#!/usr/bin/env bash

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
    echo "源码更新源：$PFWD_REPO_RAW_URL"
    echo "产物更新源：$PFWD_RELEASE_ASSET_BASE_URL"

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
    local service_states_json="${2:-}"
    local error_message="${3:-更新失败}"

    service_update_rollback "$work_dir" || true
    if [ -n "$service_states_json" ] && [ "$service_states_json" != "[]" ]; then
        service_update_restore_service_states "$service_states_json" || true
    fi
    pfwd_die "$error_message；已回滚；临时目录保留：$work_dir"
}


cmd_update_finalize() {
    local work_dir="" service_states_json="" from_version="" to_version=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --work-dir) work_dir="${2:-}"; shift 2 ;;
            --service-states-json) service_states_json="${2:-}"; shift 2 ;;
            --from-version) from_version="${2:-}"; shift 2 ;;
            --to-version) to_version="${2:-}"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done

    [ -n "$work_dir" ] || pfwd_die "缺少更新工作目录"
    if [ -n "$service_states_json" ]; then
        service_states_json="$(pfwd_require_json_output "update 服务状态" "$service_states_json")"
    else
        service_states_json="[]"
    fi
    if ! service_write_unit_files; then
        cmd_update_finalize_recover "$work_dir" "$service_states_json" "同步 systemd unit 失败"
    fi
    if ! service_update_restore_service_states "$service_states_json"; then
        cmd_update_finalize_recover "$work_dir" "$service_states_json" "恢复服务状态失败"
    fi
    if ! cmd_apply_runtime; then
        cmd_update_finalize_recover "$work_dir" "$service_states_json" "应用更新后的运行态失败"
    fi

    if ! service_update_cleanup "$work_dir"; then
        cmd_update_finalize_recover "$work_dir" "$service_states_json" "更新已完成，但清理临时文件失败"
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
    local work_dir staged_dir local_version remote_version service_states_json
    work_dir="$(service_update_create_workdir)"
    staged_dir="$work_dir/staged"

    if ! service_update_download_bundle "$work_dir"; then
        pfwd_die "下载更新包失败；请确认更新源包含必需的 pfwd-xdp/pfwd-service 预编译资产。临时目录保留：$work_dir"
    fi
    if ! service_update_validate_bundle "$staged_dir"; then
        pfwd_die "更新包校验失败；临时目录保留：$work_dir"
    fi
    cmd_update_check "$work_dir"
    local check_status="$?"
    if [ "$check_status" -ne 0 ]; then
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

    if ! service_update_preflight_space "$work_dir"; then
        pfwd_die "更新工作目录空间不足；未应用更新；临时目录保留：$work_dir"
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
    service_states_json="$(service_update_capture_service_states_json)"

    if ! service_update_backup_current "$work_dir"; then
        pfwd_die "备份当前安装失败；未应用更新；临时目录保留：$work_dir"
    fi
    if ! service_update_apply_staged "$work_dir" "$service_states_json"; then
        service_update_rollback "$work_dir" || true
        pfwd_die "更新失败，已回滚；临时目录保留：$work_dir"
    fi

    if ! exec "$PFWD_INSTALL_DIR/pfwd.sh" __update_finalize \
        --work-dir "$work_dir" \
        --service-states-json "$service_states_json" \
        --from-version "$local_version" \
        --to-version "$remote_version"; then
        service_update_rollback "$work_dir" || true
        pfwd_die "更新收尾启动失败，已回滚；临时目录保留：$work_dir"
    fi
}


cmd_install() {
    config_init
    service_install_files
    service_enable
    cmd_apply_runtime
    echo "已安装：$PFWD_BIN_PATH"
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
    echo "已卸载 pfwd"
}
