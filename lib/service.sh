#!/usr/bin/env bash

service_manager_unit() {
    cat <<EOF
[Unit]
Description=pfwd 到期检查与状态同步
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PFWD_BIN_PATH reconcile
EOF
}

service_installation_present() {
    [ -f "$PFWD_INSTALL_DIR/pfwd.sh" ] || return 1
    [ -f "$PFWD_INSTALL_DIR/bbr.sh" ] || return 1
    [ -x "$PFWD_GUARD_BIN_PATH" ] || return 1
    [ -d "$PFWD_INSTALL_DIR/lib" ] || return 1
    local lib
    for lib in "${PFWD_LIB_FILES[@]}"; do
        [ -f "$PFWD_INSTALL_DIR/lib/$lib.sh" ] || return 1
    done
}

service_timer_unit() {
    cat <<'EOF'
[Unit]
Description=定期执行 pfwd 状态同步

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
Unit=pfwd.service

[Install]
WantedBy=timers.target
EOF
}

bbr_service_unit() {
    cat <<EOF
[Unit]
Description=pfwd bbr runtime restore
After=network-online.target systemd-sysctl.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PFWD_BBR_BIN_PATH __restore

[Install]
WantedBy=multi-user.target
EOF
}

guard_service_unit() {
    cat <<EOF
[Unit]
Description=pfwd guard runtime restore
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PFWD_BIN_PATH guard apply --quiet

[Install]
WantedBy=multi-user.target
EOF
}

service_install_files() {
    pfwd_mkdirs
    mkdir -p "$PFWD_INSTALL_DIR/lib" "$PFWD_INSTALL_DIR/assets" "$(dirname "$PFWD_BIN_PATH")" "$(dirname "$PFWD_BBR_BIN_PATH")" "$(dirname "$PFWD_BBR_ALIAS_BIN_PATH")" "$(dirname "$PFWD_GUARD_BIN_PATH")" "$PFWD_SYSTEMD_DIR"
    [ -f "$PFWD_SCRIPT_DIR/pfwd.sh" ] || pfwd_die "安装包不完整：缺少 pfwd.sh ($PFWD_SCRIPT_DIR/pfwd.sh)"
    [ -f "$PFWD_SCRIPT_DIR/bbr.sh" ] || pfwd_die "安装包不完整：缺少 bbr.sh ($PFWD_SCRIPT_DIR/bbr.sh)"
    [ -f "$PFWD_SCRIPT_DIR/assets/cn-aggregated.zone" ] || pfwd_die "安装包不完整：缺少国内 IPv4 白名单种子 ($PFWD_SCRIPT_DIR/assets/cn-aggregated.zone)。离线手工安装时请先执行：install -d $PFWD_INSTALL_DIR/assets && install -m 644 assets/cn-aggregated.zone $PFWD_INSTALL_DIR/assets/cn-aggregated.zone"
    [ -f "$PFWD_SCRIPT_DIR/assets/cn-aggregated-v6.zone" ] || pfwd_die "安装包不完整：缺少国内 IPv6 白名单种子 ($PFWD_SCRIPT_DIR/assets/cn-aggregated-v6.zone)。离线手工安装时请先执行：install -d $PFWD_INSTALL_DIR/assets && install -m 644 assets/cn-aggregated-v6.zone $PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone"
    if [ "$PFWD_SCRIPT_DIR/pfwd.sh" != "$PFWD_INSTALL_DIR/pfwd.sh" ]; then
        cp "$PFWD_SCRIPT_DIR/pfwd.sh" "$PFWD_INSTALL_DIR/pfwd.sh"
    fi
    if [ "$PFWD_SCRIPT_DIR/bbr.sh" != "$PFWD_INSTALL_DIR/bbr.sh" ]; then
        cp "$PFWD_SCRIPT_DIR/bbr.sh" "$PFWD_INSTALL_DIR/bbr.sh"
    fi
    if [ "$PFWD_SCRIPT_DIR/lib" != "$PFWD_INSTALL_DIR/lib" ]; then
        cp "$PFWD_SCRIPT_DIR/lib/"*.sh "$PFWD_INSTALL_DIR/lib/"
    fi
    if [ "$PFWD_SCRIPT_DIR/assets/cn-aggregated.zone" != "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone" ]; then
        cp "$PFWD_SCRIPT_DIR/assets/cn-aggregated.zone" "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone"
    fi
    if [ "$PFWD_SCRIPT_DIR/assets/cn-aggregated-v6.zone" != "$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone" ]; then
        cp "$PFWD_SCRIPT_DIR/assets/cn-aggregated-v6.zone" "$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone"
    fi
    if [ -x "$PFWD_SCRIPT_DIR/assets/$(guard_asset_name)" ]; then
        if [ "$PFWD_SCRIPT_DIR/assets/$(guard_asset_name)" != "$PFWD_GUARD_BIN_PATH" ]; then
            cp "$PFWD_SCRIPT_DIR/assets/$(guard_asset_name)" "$PFWD_GUARD_BIN_PATH"
        fi
    elif [ ! -x "$PFWD_GUARD_BIN_PATH" ]; then
        pfwd_die "安装包不完整：缺少 guard 预编译二进制 ($PFWD_SCRIPT_DIR/assets/$(guard_asset_name))"
    fi
    chmod +x "$PFWD_INSTALL_DIR/pfwd.sh"
    chmod +x "$PFWD_INSTALL_DIR/bbr.sh"
    chmod +x "$PFWD_GUARD_BIN_PATH"
    ln -sf "$PFWD_INSTALL_DIR/pfwd.sh" "$PFWD_BIN_PATH"
    ln -sf "$PFWD_INSTALL_DIR/bbr.sh" "$PFWD_BBR_BIN_PATH"
    ln -sf "$PFWD_INSTALL_DIR/bbr.sh" "$PFWD_BBR_ALIAS_BIN_PATH"
    forwarder_service_unit > "$PFWD_SYSTEMD_DIR/pfwd-forward.service"
    service_manager_unit > "$PFWD_SYSTEMD_DIR/pfwd.service"
    service_timer_unit > "$PFWD_SYSTEMD_DIR/pfwd.timer"
    bbr_service_unit > "$PFWD_SYSTEMD_DIR/pfwd-bbr.service"
    guard_service_unit > "$PFWD_SYSTEMD_DIR/pfwd-guard.service"
}

service_ensure_shortcut() {
    [ "${PFWD_SKIP_SHORTCUT:-0}" != "1" ] || return 0
    [ "$(basename "$PFWD_SCRIPT_PATH")" = "pfwd.sh" ] || return 0
    [ "$PFWD_SCRIPT_PATH" != "$PFWD_BIN_PATH" ] || return 0
    if [ -z "${PFWD_ROOT_PREFIX:-}" ] && [ "${PFWD_DRY_RUN:-0}" != "1" ] && [ "${EUID:-$(id -u)}" -ne 0 ]; then
        return 0
    fi

    mkdir -p "$(dirname "$PFWD_BIN_PATH")"
    ln -sf "$PFWD_SCRIPT_PATH" "$PFWD_BIN_PATH"
}

service_enable() {
    command -v systemctl >/dev/null 2>&1 || pfwd_die "需要 systemctl"
    pfwd_run systemctl daemon-reload
    pfwd_run systemctl enable pfwd-forward.service pfwd.timer
    pfwd_run systemctl start pfwd.timer
}

service_unit_exists() {
    local unit="$1"
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl cat "$unit" >/dev/null 2>&1
}

service_runtime_installed() {
    service_unit_exists pfwd-forward.service && service_unit_exists pfwd.timer
}

service_primary_runtime_unit() {
    echo "pfwd-forward.service"
}

service_timer_unit_name() {
    echo "pfwd.timer"
}

service_guard_unit_name() {
    echo "pfwd-guard.service"
}

service_runtime_status_label() {
    if service_runtime_installed; then
        echo "已安装"
    else
        echo "未安装"
    fi
}

service_disable() {
    if command -v systemctl >/dev/null 2>&1; then
        pfwd_run systemctl stop pfwd.timer pfwd.service pfwd-forward.service pfwd-guard.service || true
        pfwd_run systemctl disable pfwd.timer pfwd.service pfwd-forward.service pfwd-guard.service || true
        pfwd_run systemctl daemon-reload
    fi
}

service_disable_forwarder() {
    if command -v systemctl >/dev/null 2>&1; then
        pfwd_run systemctl stop "$(service_primary_runtime_unit)" || true
        pfwd_run systemctl disable "$(service_primary_runtime_unit)" || true
        pfwd_run systemctl daemon-reload
    fi
}

service_config_value_or_default() {
    local filter="$1"
    local default_value="$2"
    local value=""
    value="$(jq -r "$filter // empty" "$PFWD_CONFIG_FILE" 2>/dev/null || true)"
    if [ -n "$value" ] && [ "$value" != "null" ]; then
        printf '%s\n' "$value"
    else
        printf '%s\n' "$default_value"
    fi
}

service_forward_table_name() {
    service_config_value_or_default '.settings.forward_table' "port_forward"
}

service_firewall_family() {
    service_config_value_or_default '.settings.nft_family' "inet"
}

service_firewall_table_name() {
    service_config_value_or_default '.settings.nft_table' "pfwd"
}

service_delete_nft_table() {
    local family="$1"
    local table="$2"
    [ -n "$table" ] || return 0
    pfwd_run nft delete table "$family" "$table" 2>/dev/null || true
}

service_cleanup_nft_tables() {
    local forward_table firewall_family firewall_table
    forward_table="$(service_forward_table_name)"
    firewall_family="$(service_firewall_family)"
    firewall_table="$(service_firewall_table_name)"

    command -v nft >/dev/null 2>&1 || return 0
    service_delete_nft_table "inet" "$forward_table"
    service_delete_nft_table "$firewall_family" "$firewall_table"
}

service_cleanup_pfwd_tc() {
    local iface
    iface="$(fw_tc_interface 2>/dev/null || true)"
    command -v tc >/dev/null 2>&1 || return 0
    [ -n "$iface" ] || return 0
    pfwd_run tc qdisc del dev "$iface" root 2>/dev/null || true
}

service_uninstall_files() {
    service_disable
    service_cleanup_nft_tables
    service_cleanup_pfwd_tc
    guard_remove_runtime true || true
    rm -f "$PFWD_SYSTEMD_DIR/pfwd-forward.service" \
          "$PFWD_SYSTEMD_DIR/pfwd.service" \
          "$PFWD_SYSTEMD_DIR/pfwd.timer" \
          "$PFWD_SYSTEMD_DIR/pfwd-guard.service"
    rm -f "$PFWD_BIN_PATH"
    rm -f "$PFWD_INSTALL_DIR/pfwd.sh"
    rm -f "$PFWD_GUARD_BIN_PATH"
    rm -rf "$PFWD_GUARD_STATE_DIR"
    rm -rf "$PFWD_ADDRESS_CONTROL_STATE_DIR"
    rm -rf "$PFWD_INSTALL_DIR/lib"
    rmdir "$PFWD_INSTALL_DIR/bin" 2>/dev/null || true
}

service_purge_state() {
    rm -rf "$PFWD_ETC_DIR" "$PFWD_STATE_DIR" "$PFWD_RUN_DIR"
}

service_verify_removed() {
    local leftovers=()
    for path in "$PFWD_BIN_PATH" "$PFWD_INSTALL_DIR/pfwd.sh" "$PFWD_INSTALL_DIR/lib" "$PFWD_INSTALL_DIR/bin" "$PFWD_GUARD_BIN_PATH" \
        "$PFWD_GUARD_STATE_DIR" "$PFWD_GUARD_STATUS_FILE" "$PFWD_GUARD_LINK_INGRESS_PATH" "$PFWD_GUARD_LINK_EGRESS_PATH" \
        "$PFWD_ADDRESS_CONTROL_STATE_DIR" "$PFWD_ADDRESS_CONTROL_ALLOW_IPV4_FILE" \
        "$PFWD_ETC_DIR" "$PFWD_STATE_DIR" "$PFWD_RUN_DIR" \
        "$PFWD_SYSTEMD_DIR/pfwd-forward.service" "$PFWD_SYSTEMD_DIR/pfwd.service" "$PFWD_SYSTEMD_DIR/pfwd.timer" "$PFWD_SYSTEMD_DIR/pfwd-guard.service"; do
        [ ! -e "$path" ] || leftovers+=("$path")
    done
    if [ "${#leftovers[@]}" -gt 0 ]; then
        printf 'leftover path: %s\n' "${leftovers[@]}" >&2
        return 1
    fi
}

service_read_version_from_file() {
    local file="$1"
    [ -f "$file" ] || return 1
    awk -F'"' '/^PFWD_VERSION=/{print $2; exit}' "$file"
}

service_installed_version() {
    service_installation_present || return 1
    service_read_version_from_file "$PFWD_INSTALL_DIR/pfwd.sh"
}

service_update_create_workdir() {
    pfwd_mkdirs
    mktemp -d "${PFWD_RUN_DIR}/update.XXXXXX"
}

service_update_download_bundle() {
    local work_dir="$1"
    local staged_dir="$work_dir/staged"
    local lib

    mkdir -p "$staged_dir/lib" "$staged_dir/assets"
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/pfwd.sh" "$staged_dir/pfwd.sh" || return 1
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/bbr.sh" "$staged_dir/bbr.sh" || return 1
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/assets/$(guard_asset_name)" "$staged_dir/assets/$(guard_asset_name)" || return 1
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/assets/cn-aggregated.zone" "$staged_dir/assets/cn-aggregated.zone" || return 1
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/assets/cn-aggregated-v6.zone" "$staged_dir/assets/cn-aggregated-v6.zone" || return 1
    for lib in "${PFWD_LIB_FILES[@]}"; do
        pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/lib/$lib.sh" "$staged_dir/lib/$lib.sh" || return 1
    done
}

service_update_validate_bundle() {
    local dir="$1"
    local lib

    [ -f "$dir/pfwd.sh" ] || {
        echo "更新包缺少 pfwd.sh" >&2
        return 1
    }
    [ -f "$dir/bbr.sh" ] || {
        echo "更新包缺少 bbr.sh" >&2
        return 1
    }
    [ -f "$dir/assets/$(guard_asset_name)" ] || {
        echo "更新包缺少 assets/$(guard_asset_name)" >&2
        return 1
    }
    [ -f "$dir/assets/cn-aggregated.zone" ] || {
        echo "更新包缺少 assets/cn-aggregated.zone" >&2
        return 1
    }
    [ -f "$dir/assets/cn-aggregated-v6.zone" ] || {
        echo "更新包缺少 assets/cn-aggregated-v6.zone" >&2
        return 1
    }
    bash -n "$dir/pfwd.sh" || return 1
    bash -n "$dir/bbr.sh" || return 1
    for lib in "${PFWD_LIB_FILES[@]}"; do
        [ -f "$dir/lib/$lib.sh" ] || {
            echo "更新包缺少 lib/$lib.sh" >&2
            return 1
        }
        bash -n "$dir/lib/$lib.sh" || return 1
    done
}

service_update_bundle_digest() {
    local dir="$1"
    local payload="" lib
    local guard_file=""

    if [ -f "$dir/assets/$(guard_asset_name)" ]; then
        guard_file="$dir/assets/$(guard_asset_name)"
    elif [ -f "$dir/bin/pfwd-guard" ]; then
        guard_file="$dir/bin/pfwd-guard"
    else
        pfwd_die "缺少 guard 二进制用于生成摘要：$dir"
    fi

    payload="pfwd.sh $(pfwd_file_checksum "$dir/pfwd.sh")"$'\n'
    payload="${payload}bbr.sh $(pfwd_file_checksum "$dir/bbr.sh")"$'\n'
    payload="${payload}guard $(pfwd_file_checksum "$guard_file")"$'\n'
    payload="${payload}assets/cn-aggregated.zone $(pfwd_file_checksum "$dir/assets/cn-aggregated.zone")"$'\n'
    payload="${payload}assets/cn-aggregated-v6.zone $(pfwd_file_checksum "$dir/assets/cn-aggregated-v6.zone")"$'\n'
    for lib in "${PFWD_LIB_FILES[@]}"; do
        payload="${payload}lib/$lib.sh $(pfwd_file_checksum "$dir/lib/$lib.sh")"$'\n'
    done
    printf '%s' "$payload" | pfwd_stdin_checksum
}

service_update_capture_enabled_state() {
    local unit="$1"
    if ! command -v systemctl >/dev/null 2>&1; then
        echo false
        return 0
    fi
    if systemctl is-enabled "$unit" >/dev/null 2>&1; then
        echo true
    else
        echo false
    fi
}

service_update_restore_enabled_state() {
    local runtime_enabled="$1"
    local timer_enabled="$2"
    local guard_enabled="${3:-false}"

    if ! command -v systemctl >/dev/null 2>&1; then
        return 0
    fi

    pfwd_run systemctl daemon-reload
    if [ "$runtime_enabled" = "true" ]; then
        pfwd_run systemctl enable "$(service_primary_runtime_unit)"
    else
        pfwd_run systemctl disable "$(service_primary_runtime_unit)" || true
    fi
    if [ "$timer_enabled" = "true" ]; then
        pfwd_run systemctl enable "$(service_timer_unit_name)"
        pfwd_run systemctl start "$(service_timer_unit_name)"
    else
        pfwd_run systemctl stop "$(service_timer_unit_name)" || true
        pfwd_run systemctl disable "$(service_timer_unit_name)" || true
    fi
    if [ "$guard_enabled" = "true" ]; then
        pfwd_run systemctl enable "$(service_guard_unit_name)"
    else
        pfwd_run systemctl stop "$(service_guard_unit_name)" || true
        pfwd_run systemctl disable "$(service_guard_unit_name)" || true
    fi
}

service_update_backup_current() {
    local work_dir="$1"
    local backup_dir="$work_dir/backup"
    local unit

    mkdir -p "$backup_dir/install" "$backup_dir/systemd" "$backup_dir/bin"
    cp -a "$PFWD_INSTALL_DIR/." "$backup_dir/install/"
    if [ -e "$PFWD_BIN_PATH" ]; then
        cp -a "$PFWD_BIN_PATH" "$backup_dir/bin/pfwd"
    fi
    if [ -e "$PFWD_BBR_BIN_PATH" ]; then
        cp -a "$PFWD_BBR_BIN_PATH" "$backup_dir/bin/bbr.sh"
    fi
    if [ -e "$PFWD_BBR_ALIAS_BIN_PATH" ]; then
        cp -a "$PFWD_BBR_ALIAS_BIN_PATH" "$backup_dir/bin/pfwd-bbr"
    fi
    if [ -e "$PFWD_GUARD_BIN_PATH" ]; then
        cp -a "$PFWD_GUARD_BIN_PATH" "$backup_dir/bin/pfwd-guard"
    fi
    for unit in pfwd-forward.service pfwd.service pfwd.timer pfwd-bbr.service pfwd-guard.service; do
        if [ -e "$PFWD_SYSTEMD_DIR/$unit" ]; then
            cp -a "$PFWD_SYSTEMD_DIR/$unit" "$backup_dir/systemd/$unit"
        fi
    done
}

service_update_apply_staged() {
    local work_dir="$1"
    local staged_dir="$work_dir/staged"
    local lib

    mkdir -p "$PFWD_INSTALL_DIR/lib" "$PFWD_INSTALL_DIR/assets" "$(dirname "$PFWD_BIN_PATH")" "$(dirname "$PFWD_BBR_BIN_PATH")" "$(dirname "$PFWD_BBR_ALIAS_BIN_PATH")" "$(dirname "$PFWD_GUARD_BIN_PATH")"
    install -m 0755 "$staged_dir/pfwd.sh" "$PFWD_INSTALL_DIR/pfwd.sh"
    install -m 0755 "$staged_dir/bbr.sh" "$PFWD_INSTALL_DIR/bbr.sh"
    install -m 0755 "$staged_dir/assets/$(guard_asset_name)" "$PFWD_GUARD_BIN_PATH"
    install -m 0644 "$staged_dir/assets/cn-aggregated.zone" "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone"
    install -m 0644 "$staged_dir/assets/cn-aggregated-v6.zone" "$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone"
    for lib in "${PFWD_LIB_FILES[@]}"; do
        install -m 0644 "$staged_dir/lib/$lib.sh" "$PFWD_INSTALL_DIR/lib/$lib.sh"
    done
    ln -sf "$PFWD_INSTALL_DIR/pfwd.sh" "$PFWD_BIN_PATH"
    ln -sf "$PFWD_INSTALL_DIR/bbr.sh" "$PFWD_BBR_BIN_PATH"
    ln -sf "$PFWD_INSTALL_DIR/bbr.sh" "$PFWD_BBR_ALIAS_BIN_PATH"
}

service_update_rollback() {
    local work_dir="$1"
    local backup_dir="$work_dir/backup"
    local unit

    [ -d "$backup_dir/install" ] || return 1

    rm -rf "$PFWD_INSTALL_DIR"
    mkdir -p "$PFWD_INSTALL_DIR"
    cp -a "$backup_dir/install/." "$PFWD_INSTALL_DIR/"

    if [ -e "$backup_dir/bin/pfwd" ]; then
        mkdir -p "$(dirname "$PFWD_BIN_PATH")"
        rm -f "$PFWD_BIN_PATH"
        cp -a "$backup_dir/bin/pfwd" "$PFWD_BIN_PATH"
    fi
    if [ -e "$backup_dir/bin/bbr.sh" ]; then
        mkdir -p "$(dirname "$PFWD_BBR_BIN_PATH")"
        rm -f "$PFWD_BBR_BIN_PATH"
        cp -a "$backup_dir/bin/bbr.sh" "$PFWD_BBR_BIN_PATH"
    fi
    if [ -e "$backup_dir/bin/pfwd-bbr" ]; then
        mkdir -p "$(dirname "$PFWD_BBR_ALIAS_BIN_PATH")"
        rm -f "$PFWD_BBR_ALIAS_BIN_PATH"
        cp -a "$backup_dir/bin/pfwd-bbr" "$PFWD_BBR_ALIAS_BIN_PATH"
    fi
    if [ -e "$backup_dir/bin/pfwd-guard" ]; then
        mkdir -p "$(dirname "$PFWD_GUARD_BIN_PATH")"
        rm -f "$PFWD_GUARD_BIN_PATH"
        cp -a "$backup_dir/bin/pfwd-guard" "$PFWD_GUARD_BIN_PATH"
    fi

    mkdir -p "$PFWD_SYSTEMD_DIR"
    rm -f "$PFWD_SYSTEMD_DIR/pfwd-forward.service" \
          "$PFWD_SYSTEMD_DIR/pfwd.service" \
          "$PFWD_SYSTEMD_DIR/pfwd.timer" \
          "$PFWD_SYSTEMD_DIR/pfwd-bbr.service" \
          "$PFWD_SYSTEMD_DIR/pfwd-guard.service"
    for unit in pfwd-forward.service pfwd.service pfwd.timer pfwd-bbr.service pfwd-guard.service; do
        if [ -e "$backup_dir/systemd/$unit" ]; then
            cp -a "$backup_dir/systemd/$unit" "$PFWD_SYSTEMD_DIR/$unit"
        fi
    done

    if command -v systemctl >/dev/null 2>&1; then
        pfwd_run systemctl daemon-reload || true
    fi
}

service_update_cleanup() {
    local work_dir="$1"
    rm -rf "$work_dir"
    [ ! -e "$work_dir" ]
}
