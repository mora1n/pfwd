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
    [ -x "$PFWD_XDP_BIN_PATH" ] || return 1
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

xdp_service_unit() {
    cat <<EOF
[Unit]
Description=pfwd XDP runtime restore
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PFWD_BIN_PATH refresh

[Install]
WantedBy=multi-user.target
EOF
}

guard_service_unit() {
    xdp_service_unit
}

downmask_asset_name() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "pfwd-downmask-linux-amd64" ;;
        aarch64|arm64) echo "pfwd-downmask-linux-arm64" ;;
        *) return 1 ;;
    esac
}

service_unit_names() {
    cat <<'EOF'
pfwd-forward.service
pfwd.service
pfwd.timer
pfwd-bbr.service
pfwd-xdp.service
pfwd-downmask-feed.service
pfwd-whitelist-web.service
EOF
}

service_update_managed_unit_rows() {
    cat <<'EOF'
pfwd.service	runtime-manager
pfwd.timer	runtime-timer
pfwd-forward.service	forward-runtime
pfwd-bbr.service	bbr-runtime
pfwd-xdp.service	xdp-runtime
pfwd-downmask-feed.service	downmask-feed
pfwd-whitelist-web.service	whitelist-web
EOF
}

service_update_optional_bundle_rows() {
    local web_asset=""
    web_asset="assets/$(whitelist_web_asset_name 2>/dev/null || true)"
    if [ -n "$web_asset" ]; then
        printf '0755\t%s\tbin/pfwd-whitelist-web\twhitelist-web\n' "$web_asset"
    fi
}

service_shortcut_rows() {
    printf '%s\t%s\t%s\n' "$PFWD_INSTALL_DIR/pfwd.sh" "$PFWD_BIN_PATH" "pfwd"
    printf '%s\t%s\t%s\n' "$PFWD_INSTALL_DIR/bbr.sh" "$PFWD_BBR_BIN_PATH" "bbr.sh"
    printf '%s\t%s\t%s\n' "$PFWD_INSTALL_DIR/bbr.sh" "$PFWD_BBR_ALIAS_BIN_PATH" "pfwd-bbr"
}

service_bundle_rows() {
    local asset_rel="assets/$(guard_asset_name)"
    local downmask_rel="assets/$(downmask_asset_name 2>/dev/null || echo pfwd-downmask-linux-amd64)"
    local lib

    printf '0755\tpfwd.sh\tpfwd.sh\tpfwd.sh\n'
    printf '0755\tbbr.sh\tbbr.sh\tbbr.sh\n'
    printf '0755\tscripts/pfwd_whitelist_lease_command.sh\tbin/%s\twhitelist-lease-command\n' "$(whitelist_web_restricted_command_script_name)"
    printf '0755\t%s\tbin/pfwd-xdp\txdp\n' "$asset_rel"
    printf '0755\t%s\tbin/pfwd-downmask\tdownmask\n' "$downmask_rel"
    printf '0644\tassets/pfwd-geo-cn-v4.bin\tassets/pfwd-geo-cn-v4.bin\tassets/pfwd-geo-cn-v4.bin\n'
    printf '0644\tassets/pfwd-geo-cn-v6.bin\tassets/pfwd-geo-cn-v6.bin\tassets/pfwd-geo-cn-v6.bin\n'
    printf '0644\tassets/pfwd-geo-meta.json\tassets/pfwd-geo-meta.json\tassets/pfwd-geo-meta.json\n'
    printf '0644\tassets/pfwd-city-cn-meta.json\tassets/pfwd-city-cn-meta.json\tassets/pfwd-city-cn-meta.json\n'
    printf '0644\tassets/pfwd-city-cn-v4.bin\tassets/pfwd-city-cn-v4.bin\tassets/pfwd-city-cn-v4.bin\n'
    for lib in "${PFWD_LIB_FILES[@]}"; do
        printf '0644\tlib/%s.sh\tlib/%s.sh\tlib/%s.sh\n' "$lib" "$lib" "$lib"
    done
}

service_missing_bundle_hint() {
    local source_path="$1"
    case "$source_path" in
        */assets/pfwd-downmask-linux-*)
            printf '请先执行 ./downmask/build.sh 生成预编译资产，或使用包含 pfwd-downmask 资产的完整源码/发布包。\n'
            ;;
        */assets/pfwd-xdp-linux-*)
            printf '请先执行 ./xdp/build.sh 生成预编译资产，或使用包含 pfwd-xdp 资产的完整源码/发布包。\n'
            ;;
        */assets/pfwd-city-cn-*)
            printf '请使用包含 city 资产的完整安装包，或使用已更新 bootstrap 的版本重新安装。\n'
            ;;
        */assets/pfwd-whitelist-web-linux-*)
            printf '请先构建 pfwd-whitelist-web 预编译资产，或使用包含该可选组件的完整源码/发布包。\n'
            ;;
        *)
            return 0
            ;;
    esac
}

service_install_target_path() {
    printf '%s/%s\n' "$PFWD_INSTALL_DIR" "$1"
}

service_prepare_install_dirs() {
    mkdir -p "$PFWD_INSTALL_DIR/lib" \
        "$PFWD_INSTALL_DIR/assets" \
        "$PFWD_INSTALL_DIR/bin" \
        "$(dirname "$PFWD_BIN_PATH")" \
        "$(dirname "$PFWD_BBR_BIN_PATH")" \
        "$(dirname "$PFWD_BBR_ALIAS_BIN_PATH")" \
        "$(dirname "$PFWD_XDP_BIN_PATH")" \
        "$(dirname "$PFWD_DOWNMASK_BIN_PATH")" \
        "$(dirname "$PFWD_WHITELIST_WEB_BIN_PATH")" \
        "$PFWD_DOWNMASK_STATE_DIR" \
        "$PFWD_WHITELIST_WEB_STATE_DIR" \
        "$PFWD_SYSTEMD_DIR"
}

service_write_shortcuts() {
    local target link_path _
    while IFS=$'\t' read -r target link_path _; do
        target="$(readlink -f "$target" 2>/dev/null || realpath "$target" 2>/dev/null || printf '%s' "$target")"
        ln -sf "$target" "$link_path"
    done < <(service_shortcut_rows)
}

service_remove_shortcuts() {
    local _ link_path __
    while IFS=$'\t' read -r _ link_path __; do
        rm -f "$link_path"
    done < <(service_shortcut_rows)
}

service_backup_shortcuts() {
    local backup_dir="$1"
    local _ link_path backup_name

    mkdir -p "$backup_dir"
    while IFS=$'\t' read -r _ link_path backup_name; do
        if [ -L "$link_path" ] || [ -e "$link_path" ]; then
            cp -a "$link_path" "$backup_dir/$backup_name" || return 1
        fi
    done < <(service_shortcut_rows)
}

service_restore_shortcuts() {
    local backup_dir="$1"
    local _ link_path backup_name

    while IFS=$'\t' read -r _ link_path backup_name; do
        mkdir -p "$(dirname "$link_path")"
        rm -f "$link_path"
        if [ -L "$backup_dir/$backup_name" ] || [ -e "$backup_dir/$backup_name" ]; then
            cp -a "$backup_dir/$backup_name" "$link_path"
        fi
    done < <(service_shortcut_rows)
}

service_backup_unit_files() {
    local backup_dir="$1"
    local unit

    mkdir -p "$backup_dir"
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        if [ -e "$PFWD_SYSTEMD_DIR/$unit" ]; then
            cp -a "$PFWD_SYSTEMD_DIR/$unit" "$backup_dir/$unit" || return 1
        fi
    done < <(service_unit_names)
}

service_restore_unit_files() {
    local backup_dir="$1"
    local unit

    mkdir -p "$PFWD_SYSTEMD_DIR"
    service_remove_unit_files
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        if [ -e "$backup_dir/$unit" ]; then
            cp -a "$backup_dir/$unit" "$PFWD_SYSTEMD_DIR/$unit"
        fi
    done < <(service_unit_names)
}

service_copy_bundle_from_dir() {
    local source_root="$1"
    local mode source_rel install_rel _
    local source_path target_path

    while IFS=$'\t' read -r mode source_rel install_rel _; do
        source_path="${source_root%/}/$source_rel"
        target_path="$(service_install_target_path "$install_rel")"

        if [ ! -f "$source_path" ]; then
            {
                printf '安装包不完整：缺少 %s\n' "$source_path"
                service_missing_bundle_hint "$source_path"
            } >&2
            exit 1
        fi
        if [ "$source_path" != "$target_path" ]; then
            install -m "$mode" "$source_path" "$target_path"
        else
            chmod "$mode" "$target_path"
        fi
    done < <(service_bundle_rows)
}

service_copy_optional_whitelist_web_from_dir() {
    local source_root="$1"
    local asset_rel target_path source_path
    asset_rel="assets/$(whitelist_web_asset_name 2>/dev/null || true)"
    [ -n "$asset_rel" ] || return 0
    source_path="${source_root%/}/$asset_rel"
    [ -f "$source_path" ] || return 0
    target_path="$(service_install_target_path "bin/pfwd-whitelist-web")"
    install -m 0755 "$source_path" "$target_path"
}

service_update_installed_optional_rows() {
    local mode source_rel install_rel digest_label target_path unit_name
    while IFS=$'\t' read -r mode source_rel install_rel digest_label; do
        [ -n "$source_rel" ] || continue
        target_path="$(service_install_target_path "$install_rel")"
        unit_name=""
        case "$digest_label" in
            whitelist-web) unit_name="pfwd-whitelist-web.service" ;;
        esac
        if [ -f "$target_path" ] || { [ -n "$unit_name" ] && service_unit_exists "$unit_name"; }; then
            printf '%s\t%s\t%s\t%s\n' "$mode" "$source_rel" "$install_rel" "$digest_label"
        fi
    done < <(service_update_optional_bundle_rows)
}

service_update_bundle_rows() {
    service_bundle_rows
    service_update_installed_optional_rows
}

service_cleanup_legacy_install_artifacts() {
    rm -f "$PFWD_INSTALL_DIR/assets/cn-aggregated.zone" \
          "$PFWD_INSTALL_DIR/assets/cn-aggregated-v6.zone"
}

service_verify_bundle_from_dir() {
    local source_root="$1"
    local _ source_rel __ ___
    local source_path

    while IFS=$'\t' read -r _ source_rel __ ___; do
        source_path="${source_root%/}/$source_rel"
        if [ ! -f "$source_path" ]; then
            {
                printf '安装包不完整：缺少 %s\n' "$source_path"
                service_missing_bundle_hint "$source_path"
            } >&2
            exit 1
        fi
    done < <(service_bundle_rows)
}

service_write_unit_files() {
    mkdir -p "$PFWD_SYSTEMD_DIR"
    service_manager_unit > "$PFWD_SYSTEMD_DIR/pfwd.service"
    service_timer_unit > "$PFWD_SYSTEMD_DIR/pfwd.timer"
    bbr_service_unit > "$PFWD_SYSTEMD_DIR/pfwd-bbr.service"
    xdp_service_unit > "$PFWD_SYSTEMD_DIR/pfwd-xdp.service"
    whitelist_web_service_unit > "$PFWD_SYSTEMD_DIR/pfwd-whitelist-web.service"
    if command -v downmask_write_feed_unit_if_needed >/dev/null 2>&1; then
        downmask_write_feed_unit_if_needed || true
    fi
}

service_install_files() {
    pfwd_mkdirs
    service_prepare_install_dirs
    service_verify_bundle_from_dir "$PFWD_SCRIPT_DIR"
    service_copy_bundle_from_dir "$PFWD_SCRIPT_DIR"
    service_copy_optional_whitelist_web_from_dir "$PFWD_SCRIPT_DIR"
    service_cleanup_legacy_install_artifacts
    service_write_shortcuts
    service_write_unit_files
}

service_ensure_shortcut() {
    [ "${PFWD_SKIP_SHORTCUT:-0}" != "1" ] || return 0
    [ "$(basename "$PFWD_SCRIPT_PATH")" = "pfwd.sh" ] || return 0
    [ "$PFWD_SCRIPT_PATH" != "$PFWD_BIN_PATH" ] || return 0
    [ "$PFWD_SCRIPT_PATH" = "$PFWD_INSTALL_DIR/pfwd.sh" ] || return 0
    if [ -z "${PFWD_ROOT_PREFIX:-}" ] && [ "${PFWD_DRY_RUN:-0}" != "1" ] && [ "${EUID:-$(id -u)}" -ne 0 ]; then
        return 0
    fi

    mkdir -p "$(dirname "$PFWD_BIN_PATH")"
    ln -sf "$PFWD_SCRIPT_PATH" "$PFWD_BIN_PATH"
}

service_enable() {
    command -v systemctl >/dev/null 2>&1 || pfwd_die "需要 systemctl"
    pfwd_run systemctl daemon-reload
    pfwd_run systemctl enable pfwd-xdp.service pfwd.timer
    pfwd_run systemctl start pfwd.timer
    if [ -f "$PFWD_WHITELIST_WEB_CONFIG_FILE" ]; then
        pfwd_run systemctl enable pfwd-whitelist-web.service || true
    fi
}

service_unit_exists() {
    local unit="$1"
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl cat "$unit" >/dev/null 2>&1
}

service_runtime_installed() {
    service_unit_exists pfwd-xdp.service && service_unit_exists pfwd.timer
}

service_primary_runtime_unit() {
    echo "pfwd-xdp.service"
}

service_timer_unit_name() {
    echo "pfwd.timer"
}

service_guard_unit_name() {
    echo "pfwd-xdp.service"
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
        pfwd_run systemctl stop pfwd.timer pfwd.service pfwd-forward.service pfwd-bbr.service pfwd-xdp.service pfwd-downmask-feed.service pfwd-whitelist-web.service || true
        pfwd_run systemctl disable pfwd.timer pfwd.service pfwd-forward.service pfwd-bbr.service pfwd-xdp.service pfwd-downmask-feed.service pfwd-whitelist-web.service || true
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

service_cleanup_pfwd_tc() {
    local iface
    iface="$(fw_tc_state_read_iface 2>/dev/null || true)"
    [ -n "$iface" ] || iface="$(fw_tc_interface 2>/dev/null || true)"
    command -v tc >/dev/null 2>&1 || return 0
    fw_reset_tc_runtime "$iface"
}

service_remove_unit_files() {
    local unit
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        rm -f "$PFWD_SYSTEMD_DIR/$unit"
    done < <(service_unit_names)
}

service_remove_binary_artifacts() {
    local mode source_rel install_rel digest_label
    service_remove_shortcuts
    while IFS=$'\t' read -r mode source_rel install_rel digest_label; do
        rm -f "$(service_install_target_path "$install_rel")"
    done < <(service_bundle_rows)
    rm -f "$PFWD_WHITELIST_WEB_BIN_PATH"
}

service_remove_asset_artifacts() {
    rm -rf "$PFWD_INSTALL_DIR/assets"
}

service_remove_installation_artifacts() {
    service_remove_unit_files
    service_remove_binary_artifacts
    service_remove_asset_artifacts
    rm -rf "$PFWD_INSTALL_DIR"
}

service_uninstall_files() {
    local status=0

    service_disable || status=1
    service_cleanup_pfwd_tc || status=1
    guard_remove_runtime true || status=1
    runtime_clear_accounting_runtime || status=1
    runtime_remove_runtime_artifacts || status=1
    runtime_remove_whitelist_runtime_files || status=1
    runtime_remove_runtime_state_dirs || status=1
    service_remove_installation_artifacts || status=1

    return "$status"
}

service_purge_state() {
    rm -rf "$PFWD_ETC_DIR" "$PFWD_STATE_DIR" "$PFWD_RUN_DIR" "$PFWD_DOWNMASK_STATE_DIR"
}

service_verify_removed() {
    local leftovers=()
    local path _ source_rel install_rel __
    for path in "$PFWD_INSTALL_DIR/lib" "$PFWD_INSTALL_DIR/bin" "$PFWD_INSTALL_DIR/assets" \
        "$PFWD_GUARD_STATE_DIR" "$PFWD_GUARD_STATUS_FILE" "$PFWD_GUARD_LINK_INGRESS_PATH" \
        "$PFWD_DOWNMASK_STATE_DIR" "$PFWD_DOWNMASK_STATUS_FILE" "$PFWD_DOWNMASK_BIN_PATH" \
        "$PFWD_WHITELIST_WEB_CONFIG_FILE" "$PFWD_WHITELIST_WEB_BIN_PATH" "$PFWD_WHITELIST_WEB_STATE_DIR" \
        "$PFWD_FORWARDER_RUNTIME_FILE" "$PFWD_FORWARDER_XDP_RUNTIME_FILE" "$PFWD_FORWARDER_NFT_RUNTIME_FILE" "$PFWD_FORWARDER_NFT_RENDER_FILE" "$PFWD_FORWARDER_STATUS_FILE" \
        "$PFWD_XDP_STATUS_FILE" "$PFWD_XDP_LINK_PIN_PATH" "$PFWD_XDP_INGRESS_PIN_PATH" "$PFWD_XDP_HOST_EGRESS_PIN_PATH" "$PFWD_XDP_LOOPBACK_PIN_PATH" \
        "$PFWD_XDP_SK_LOOKUP_PIN_PATH" "$PFWD_XDP_SETTINGS_PIN_PATH" "$PFWD_XDP_RULES_PIN_PATH" "$PFWD_XDP_CONNECTIONS_PIN_PATH" \
        "$PFWD_XDP_REVERSE_PIN_PATH" "$PFWD_XDP_WHITELIST_V4_PIN_PATH" "$PFWD_XDP_WHITELIST_V6_PIN_PATH" \
        "$PFWD_XDP_WHITELIST_CACHE_V4_PIN_PATH" "$PFWD_XDP_WHITELIST_CACHE_V6_PIN_PATH" \
        "$PFWD_XDP_EGRESS_WHITELIST_V4_PIN_PATH" "$PFWD_XDP_EGRESS_WHITELIST_V6_PIN_PATH" \
        "$PFWD_XDP_EGRESS_WHITELIST_CACHE_V4_PIN_PATH" "$PFWD_XDP_EGRESS_WHITELIST_CACHE_V6_PIN_PATH" \
        "$PFWD_XDP_ALLOWED_FLOWS_PIN_PATH" "$PFWD_XDP_HOST_EGRESS_FLOWS_PIN_PATH" "$PFWD_XDP_GUARD_PREFIXES_PIN_PATH" "$PFWD_XDP_SKIP_PORTS_PIN_PATH" \
        "$PFWD_XDP_GEO_BUCKET_V4_PIN_PATH" "$PFWD_XDP_GEO_BUCKET_V6_PIN_PATH" "$PFWD_XDP_GEO_SEGMENTS_V4_PIN_PATH" \
        "$PFWD_XDP_GEO_SEGMENTS_V6_PIN_PATH" "$PFWD_XDP_GEO_PROVINCE_POLICY_PIN_PATH" \
        "$PFWD_XDP_INGRESS_GEO_V4_PIN_PATH" "$PFWD_XDP_INGRESS_GEO_V6_PIN_PATH" "$PFWD_XDP_INGRESS_CITY_V4_PIN_PATH" \
        "$PFWD_XDP_INGRESS_POLICY_MODES_PIN_PATH" "$PFWD_XDP_INGRESS_POLICY_PROVINCES_PIN_PATH" "$PFWD_XDP_INGRESS_POLICY_CITIES_PIN_PATH" \
        "$PFWD_XDP_RULE_COUNTER_PIN_PATH" "$PFWD_XDP_USER_COUNTER_PIN_PATH" "$PFWD_XDP_STATS_PIN_PATH" \
        "$PFWD_WHITELIST_STATE_DIR" "$PFWD_WHITELIST_ALLOW_IPV4_FILE" "$PFWD_WHITELIST_ALLOW_IPV6_FILE" "$PFWD_WHITELIST_CITY_IPV4_FILE" \
        "$PFWD_WHITELIST_LEASES_FILE" "$PFWD_WHITELIST_TEMP_ALLOW_IPV4_FILE" "$PFWD_WHITELIST_TEMP_ALLOW_IPV6_FILE" \
        "${PFWD_WHITELIST_ALLOW_IPV4_FILE}.cn" "${PFWD_WHITELIST_ALLOW_IPV6_FILE}.cn" \
        "$PFWD_ETC_DIR" "$PFWD_STATE_DIR" "$PFWD_RUN_DIR"; do
        [ ! -e "$path" ] || leftovers+=("$path")
    done
    while IFS=$'\t' read -r _ path __; do
        [ ! -e "$path" ] || leftovers+=("$path")
    done < <(service_shortcut_rows)
    while IFS=$'\t' read -r _ source_rel install_rel __; do
        path="$(service_install_target_path "$install_rel")"
        [ ! -e "$path" ] || leftovers+=("$path")
    done < <(service_bundle_rows)
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        path="$PFWD_SYSTEMD_DIR/$path"
        [ ! -e "$path" ] || leftovers+=("$path")
    done < <(service_unit_names)
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
    mktemp -d "${PFWD_STATE_DIR}/update.XXXXXX"
}

service_update_path_size_kb() {
    local path="$1"
    if [ ! -e "$path" ]; then
        echo 0
        return 0
    fi
    du -sk "$path" | awk 'NR == 1 {print $1}'
}

service_update_available_kb() {
    local path="$1"
    df -Pk "$path" | awk 'NR == 2 {print $4}'
}

service_update_download_bundle() {
    local work_dir="$1"
    local staged_dir="$work_dir/staged"

    mkdir -p "$staged_dir/lib" "$staged_dir/assets" "$staged_dir/scripts"
    local _ source_rel __ ___
    while IFS=$'\t' read -r _ source_rel __ ___; do
        pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/$source_rel" "$staged_dir/$source_rel" || return 1
    done < <(service_update_bundle_rows)
}

service_update_validate_bundle() {
    local dir="$1"
    local _ source_rel __ ___
    while IFS=$'\t' read -r _ source_rel __ ___; do
        [ -f "$dir/$source_rel" ] || {
            echo "更新包不完整：缺少 $source_rel" >&2
            service_missing_bundle_hint "$dir/$source_rel" >&2 || true
            return 1
        }
        case "$source_rel" in
            *.sh) bash -n "$dir/$source_rel" || return 1 ;;
        esac
    done < <(service_update_bundle_rows)
}

service_update_bundle_digest() {
    local dir="$1"
    local layout="${2:-staged}"
    local payload="" mode source_rel install_rel digest_label
    local digest_path=""

    while IFS=$'\t' read -r mode source_rel install_rel digest_label; do
        case "$layout" in
            install) digest_path="$dir/$install_rel" ;;
            staged) digest_path="$dir/$source_rel" ;;
            *) pfwd_die "未知更新包布局：$layout" ;;
        esac
        [ -f "$digest_path" ] || pfwd_die "缺少更新产物用于生成摘要：$digest_path"
        payload="${payload}${digest_label} $(pfwd_file_checksum "$digest_path")"$'\n'
    done < <(service_update_bundle_rows)
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

service_update_capture_active_state() {
    local unit="$1"
    if ! command -v systemctl >/dev/null 2>&1; then
        echo false
        return 0
    fi
    if systemctl is-active "$unit" >/dev/null 2>&1; then
        echo true
    else
        echo false
    fi
}

service_update_capture_service_states_json() {
    if ! command -v systemctl >/dev/null 2>&1; then
        printf '[]\n'
        return 0
    fi
    local unit label enabled active
    {
        while IFS=$'\t' read -r unit label; do
            [ -n "$unit" ] || continue
            service_unit_exists "$unit" || continue
            enabled="$(service_update_capture_enabled_state "$unit")"
            active="$(service_update_capture_active_state "$unit")"
            printf '%s\t%s\t%s\t%s\n' "$unit" "$label" "$enabled" "$active"
        done < <(service_update_managed_unit_rows)
    } | jq -Rsc '
      split("\n")
      | map(select(length > 0) | split("\t"))
      | map({
          unit: .[0],
          label: .[1],
          enabled: (.[2] == "true"),
          active: (.[3] == "true")
        })
    '
}

service_update_legacy_service_states_json() {
    local runtime_enabled="${1:-false}"
    local timer_enabled="${2:-false}"
    local guard_enabled="${3:-false}"
    local xdp_enabled="false"

    if [ "$runtime_enabled" = "true" ] || [ "$guard_enabled" = "true" ]; then
        xdp_enabled="true"
    fi

    jq -cn \
      --argjson xdp_enabled "$xdp_enabled" \
      --argjson timer_enabled "$timer_enabled" '
      [
        {
          unit: "pfwd-xdp.service",
          label: "legacy-xdp-runtime",
          enabled: $xdp_enabled,
          active: false
        },
        {
          unit: "pfwd.timer",
          label: "legacy-runtime-timer",
          enabled: $timer_enabled,
          active: $timer_enabled
        }
      ]
    '
}

service_update_restore_service_states() {
    local states_json="$1"

    if ! command -v systemctl >/dev/null 2>&1; then
        return 0
    fi

    pfwd_run systemctl daemon-reload
    jq -r '.[] | [.unit, (if .enabled then "true" else "false" end)] | @tsv' <<< "$states_json" |
    while IFS=$'\t' read -r unit enabled; do
        [ -n "$unit" ] || continue
        if [ "$enabled" = "true" ]; then
            pfwd_run systemctl enable "$unit"
        else
            pfwd_run systemctl disable "$unit" || true
        fi
    done
    jq -r '.[] | [.unit, (if .active then "true" else "false" end)] | @tsv' <<< "$states_json" |
    while IFS=$'\t' read -r unit active; do
        [ -n "$unit" ] || continue
        if [ "$active" = "true" ]; then
            case "$unit" in
                *.timer) pfwd_run systemctl start "$unit" ;;
                *) pfwd_run systemctl restart "$unit" ;;
            esac
        else
            pfwd_run systemctl stop "$unit" || true
        fi
    done
}

service_update_stop_active_services() {
    local states_json="$1"
    if ! command -v systemctl >/dev/null 2>&1; then
        return 0
    fi
    jq -r '
      map(select(.active == true))
      | sort_by(
          if .unit == "pfwd.timer" then 0
          elif .unit == "pfwd.service" then 1
          elif .unit == "pfwd-forward.service" then 2
          elif .unit == "pfwd-bbr.service" then 3
          elif .unit == "pfwd-xdp.service" then 4
          elif .unit == "pfwd-downmask-feed.service" then 5
          elif .unit == "pfwd-whitelist-web.service" then 6
          else 99 end
        )
      | .[].unit
    ' <<< "$states_json" |
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        pfwd_run systemctl stop "$unit" || true
    done
}

service_update_backup_current() {
    local work_dir="$1"
    local backup_dir="$work_dir/backup"

    mkdir -p "$backup_dir/install" "$backup_dir/systemd" "$backup_dir/bin"
    cp -a "$PFWD_INSTALL_DIR/." "$backup_dir/install/" || return 1
    service_backup_shortcuts "$backup_dir/bin" || return 1
    service_backup_unit_files "$backup_dir/systemd" || return 1
}

service_update_preflight_space() {
    local work_dir="$1"
    local staged_dir="$work_dir/staged"
    local installed_kb staged_kb available_kb required_kb safety_kb

    installed_kb="$(service_update_path_size_kb "$PFWD_INSTALL_DIR")" || return 1
    staged_kb="$(service_update_path_size_kb "$staged_dir")" || return 1
    available_kb="$(service_update_available_kb "$work_dir")" || return 1
    safety_kb=16384
    required_kb=$((installed_kb + staged_kb + safety_kb))

    if [ "$available_kb" -lt "$required_kb" ]; then
        {
            printf '更新工作目录空间不足：%s\n' "$work_dir"
            printf '可用空间：%sKB；预计需要：%sKB（当前安装：%sKB，更新包：%sKB，安全余量：%sKB）\n' \
                "$available_kb" "$required_kb" "$installed_kb" "$staged_kb" "$safety_kb"
        } >&2
        return 1
    fi
}

service_update_apply_staged() {
    local work_dir="$1"
    local states_json="${2:-[]}"
    local staged_dir="$work_dir/staged"

    service_update_stop_active_services "$states_json"
    service_prepare_install_dirs
    service_copy_bundle_from_dir "$staged_dir"
    service_copy_optional_whitelist_web_from_dir "$staged_dir"
    service_cleanup_legacy_install_artifacts
    service_write_shortcuts
}

service_update_rollback() {
    local work_dir="$1"
    local backup_dir="$work_dir/backup"

    [ -d "$backup_dir/install" ] || return 1

    rm -rf "$PFWD_INSTALL_DIR"
    mkdir -p "$PFWD_INSTALL_DIR"
    cp -a "$backup_dir/install/." "$PFWD_INSTALL_DIR/"

    service_restore_shortcuts "$backup_dir/bin"
    service_restore_unit_files "$backup_dir/systemd"

    if command -v systemctl >/dev/null 2>&1; then
        pfwd_run systemctl daemon-reload || true
    fi
}

service_update_cleanup() {
    local work_dir="$1"
    rm -rf "$work_dir"
    [ ! -e "$work_dir" ]
}
