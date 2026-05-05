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

service_install_files() {
    pfwd_mkdirs
    mkdir -p "$PFWD_INSTALL_DIR/lib" "$(dirname "$PFWD_BIN_PATH")" "$(dirname "$PFWD_BBR_BIN_PATH")" "$PFWD_SYSTEMD_DIR"
    if [ "$PFWD_SCRIPT_DIR/pfwd.sh" != "$PFWD_INSTALL_DIR/pfwd.sh" ]; then
        cp "$PFWD_SCRIPT_DIR/pfwd.sh" "$PFWD_INSTALL_DIR/pfwd.sh"
    fi
    if [ "$PFWD_SCRIPT_DIR/bbr.sh" != "$PFWD_INSTALL_DIR/bbr.sh" ]; then
        cp "$PFWD_SCRIPT_DIR/bbr.sh" "$PFWD_INSTALL_DIR/bbr.sh"
    fi
    if [ "$PFWD_SCRIPT_DIR/lib" != "$PFWD_INSTALL_DIR/lib" ]; then
        cp "$PFWD_SCRIPT_DIR/lib/"*.sh "$PFWD_INSTALL_DIR/lib/"
    fi
    chmod +x "$PFWD_INSTALL_DIR/pfwd.sh"
    chmod +x "$PFWD_INSTALL_DIR/bbr.sh"
    ln -sf "$PFWD_INSTALL_DIR/pfwd.sh" "$PFWD_BIN_PATH"
    ln -sf "$PFWD_INSTALL_DIR/bbr.sh" "$PFWD_BBR_BIN_PATH"
    forwarder_service_unit > "$PFWD_SYSTEMD_DIR/pfwd-forward.service"
    service_manager_unit > "$PFWD_SYSTEMD_DIR/pfwd.service"
    service_timer_unit > "$PFWD_SYSTEMD_DIR/pfwd.timer"
    bbr_service_unit > "$PFWD_SYSTEMD_DIR/pfwd-bbr.service"
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
    if [ -f "$PFWD_BBR_STATE_FILE" ]; then
        pfwd_run systemctl enable pfwd-bbr.service
    fi
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

service_runtime_status_label() {
    if service_runtime_installed; then
        echo "已安装"
    else
        echo "未安装"
    fi
}

service_disable() {
    if command -v systemctl >/dev/null 2>&1; then
        pfwd_run systemctl stop pfwd-bbr.service pfwd.timer pfwd.service pfwd-forward.service || true
        pfwd_run systemctl disable pfwd-bbr.service pfwd.timer pfwd.service pfwd-forward.service || true
        pfwd_run systemctl daemon-reload
    fi
}

service_disable_forwarder() {
    if command -v systemctl >/dev/null 2>&1; then
        pfwd_run systemctl stop pfwd-forward.service || true
        pfwd_run systemctl disable pfwd-forward.service || true
        pfwd_run systemctl daemon-reload
    fi
}

service_uninstall_files() {
    local family table iface
    family="$(jq -r '.settings.nft_family // "inet"' "$PFWD_CONFIG_FILE" 2>/dev/null || echo inet)"
    table="$(jq -r '.settings.nft_table // "pfwd"' "$PFWD_CONFIG_FILE" 2>/dev/null || echo pfwd)"
    iface="$(fw_tc_interface 2>/dev/null || true)"

    service_disable
    if command -v nft >/dev/null 2>&1; then
        forwarder_stop_runtime || pfwd_run nft delete table "$family" "$table" 2>/dev/null || true
    fi
    if command -v tc >/dev/null 2>&1 && [ -n "$iface" ]; then
        pfwd_run tc qdisc del dev "$iface" root 2>/dev/null || true
    fi
    rm -f "$PFWD_SYSTEMD_DIR/pfwd-forward.service" \
          "$PFWD_SYSTEMD_DIR/pfwd-bbr.service" \
          "$PFWD_SYSTEMD_DIR/pfwd.service" \
          "$PFWD_SYSTEMD_DIR/pfwd.timer"
    rm -f "$PFWD_BIN_PATH" "$PFWD_BBR_BIN_PATH"
    rm -rf "$PFWD_INSTALL_DIR"
}

service_purge_state() {
    rm -rf "$PFWD_ETC_DIR" "$PFWD_STATE_DIR" "$PFWD_RUN_DIR"
}

service_verify_removed() {
    local leftovers=()
    for path in "$PFWD_BIN_PATH" "$PFWD_INSTALL_DIR" "$PFWD_ETC_DIR" "$PFWD_STATE_DIR" "$PFWD_RUN_DIR" \
        "$PFWD_BBR_BIN_PATH" \
        "$PFWD_SYSTEMD_DIR/pfwd-forward.service" "$PFWD_SYSTEMD_DIR/pfwd-bbr.service" "$PFWD_SYSTEMD_DIR/pfwd.service" "$PFWD_SYSTEMD_DIR/pfwd.timer"; do
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

    mkdir -p "$staged_dir/lib"
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/pfwd.sh" "$staged_dir/pfwd.sh" || return 1
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/bbr.sh" "$staged_dir/bbr.sh" || return 1
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

    payload="pfwd.sh $(pfwd_file_checksum "$dir/pfwd.sh")"$'\n'
    payload="${payload}bbr.sh $(pfwd_file_checksum "$dir/bbr.sh")"$'\n'
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
    local forwarder_enabled="$1"
    local timer_enabled="$2"
    local bbr_enabled="${3:-false}"

    if ! command -v systemctl >/dev/null 2>&1; then
        return 0
    fi

    pfwd_run systemctl daemon-reload
    if [ "$forwarder_enabled" = "true" ]; then
        pfwd_run systemctl enable pfwd-forward.service
    else
        pfwd_run systemctl disable pfwd-forward.service || true
    fi
    if [ "$timer_enabled" = "true" ]; then
        pfwd_run systemctl enable pfwd.timer
        pfwd_run systemctl start pfwd.timer
    else
        pfwd_run systemctl stop pfwd.timer || true
        pfwd_run systemctl disable pfwd.timer || true
    fi
    if [ "$bbr_enabled" = "true" ]; then
        pfwd_run systemctl enable pfwd-bbr.service
    else
        pfwd_run systemctl disable pfwd-bbr.service || true
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
    for unit in pfwd-forward.service pfwd-bbr.service pfwd.service pfwd.timer; do
        if [ -e "$PFWD_SYSTEMD_DIR/$unit" ]; then
            cp -a "$PFWD_SYSTEMD_DIR/$unit" "$backup_dir/systemd/$unit"
        fi
    done
}

service_update_apply_staged() {
    local work_dir="$1"
    local staged_dir="$work_dir/staged"
    local lib

    mkdir -p "$PFWD_INSTALL_DIR/lib" "$(dirname "$PFWD_BIN_PATH")" "$(dirname "$PFWD_BBR_BIN_PATH")"
    install -m 0755 "$staged_dir/pfwd.sh" "$PFWD_INSTALL_DIR/pfwd.sh"
    install -m 0755 "$staged_dir/bbr.sh" "$PFWD_INSTALL_DIR/bbr.sh"
    for lib in "${PFWD_LIB_FILES[@]}"; do
        install -m 0644 "$staged_dir/lib/$lib.sh" "$PFWD_INSTALL_DIR/lib/$lib.sh"
    done
    ln -sf "$PFWD_INSTALL_DIR/pfwd.sh" "$PFWD_BIN_PATH"
    ln -sf "$PFWD_INSTALL_DIR/bbr.sh" "$PFWD_BBR_BIN_PATH"
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

    mkdir -p "$PFWD_SYSTEMD_DIR"
    rm -f "$PFWD_SYSTEMD_DIR/pfwd-forward.service" \
          "$PFWD_SYSTEMD_DIR/pfwd-bbr.service" \
          "$PFWD_SYSTEMD_DIR/pfwd.service" \
          "$PFWD_SYSTEMD_DIR/pfwd.timer"
    for unit in pfwd-forward.service pfwd-bbr.service pfwd.service pfwd.timer; do
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
