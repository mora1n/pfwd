#!/usr/bin/env bash

service_manager_unit() {
    cat <<EOF
[Unit]
Description=pfwd local daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PFWD_SERVICE_BIN_PATH daemon --socket $PFWD_SERVICE_SOCKET --db $PFWD_DB_FILE --pfwd-bin $PFWD_BIN_PATH
Restart=on-failure
RestartSec=2s
RuntimeDirectory=pfwd
RuntimeDirectoryMode=0750
StateDirectory=pfwd
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
}

service_installation_present() {
    [ -f "$PFWD_INSTALL_DIR/pfwd.sh" ] || return 1
    [ -x "$PFWD_XDP_BIN_PATH" ] || return 1
    [ -x "$PFWD_SERVICE_BIN_PATH" ] || return 1
    [ -d "$PFWD_INSTALL_DIR/lib" ] || return 1
    local lib
    for lib in "${PFWD_LIB_FILES[@]}"; do
        [ -f "$PFWD_INSTALL_DIR/$(pfwd_lib_rel_path "$lib")" ] || return 1
    done
}

service_asset_name() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "pfwd-service-linux-amd64" ;;
        aarch64|arm64) echo "pfwd-service-linux-arm64" ;;
        *) return 1 ;;
    esac
}

service_xdp_asset_name() {
    pfwd_bootstrap_xdp_asset_name
}

service_release_asset_url() {
    printf '%s/%s\n' "${PFWD_RELEASE_ASSET_BASE_URL%/}" "$1"
}

service_unit_names() {
    cat <<'EOF'
pfwd.service
EOF
}

service_update_managed_unit_rows() {
    cat <<'EOF'
pfwd.service	local-daemon	true
EOF
}

service_shortcut_rows() {
    printf '%s\t%s\t%s\n' "$PFWD_INSTALL_DIR/pfwd.sh" "$PFWD_BIN_PATH" "pfwd"
}

service_bundle_rows() {
    local lib

    printf 'source\t0755\tpfwd.sh\tpfwd.sh\tpfwd.sh\n'
    printf 'release\t0755\t%s\tbin/pfwd-xdp\txdp\n' "$(service_xdp_asset_name)"
    printf 'release\t0755\t%s\tbin/pfwd-service\tservice\n' "$(service_asset_name)"
    for lib in "${PFWD_LIB_FILES[@]}"; do
        printf 'source\t0644\t%s\t%s\t%s\n' "$(pfwd_lib_rel_path "$lib")" "$(pfwd_lib_rel_path "$lib")" "$(pfwd_lib_rel_path "$lib")"
    done
}

service_missing_bundle_hint() {
    local source_path="$1"
    case "$source_path" in
        */pfwd-xdp-linux-*)
            printf '请确认 GitHub Release 已发布对应架构的 pfwd-xdp 资产，或设置 PFWD_RELEASE_ASSET_DIR 指向本地 dist 目录。\n'
            ;;
        */pfwd-service-linux-*)
            printf '请确认 GitHub Release 已发布对应架构的 pfwd-service 资产，或设置 PFWD_RELEASE_ASSET_DIR 指向本地 dist 目录。\n'
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
        "$PFWD_INSTALL_DIR/bin" \
        "$(dirname "$PFWD_BIN_PATH")" \
        "$(dirname "$PFWD_XDP_BIN_PATH")" \
        "$(dirname "$PFWD_SERVICE_BIN_PATH")" \
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
    local kind mode source_rel install_rel _
    local source_path target_path

    while IFS=$'\t' read -r kind mode source_rel install_rel _; do
        if [ "$kind" = "release" ]; then
            source_path="${PFWD_RELEASE_ASSET_DIR%/}/$source_rel"
        else
            source_path="${source_root%/}/$source_rel"
        fi
        target_path="$(service_install_target_path "$install_rel")"

        if [ ! -f "$source_path" ]; then
            {
                printf '安装包不完整：缺少 %s\n' "$source_path"
                service_missing_bundle_hint "$source_path"
            } >&2
            exit 1
        fi
        if [ "$source_path" != "$target_path" ]; then
            mkdir -p "$(dirname "$target_path")"
            install -m "$mode" "$source_path" "$target_path"
        else
            chmod "$mode" "$target_path"
        fi
    done < <(service_bundle_rows)
}

service_update_bundle_rows() {
    service_bundle_rows
}

service_verify_bundle_from_dir() {
    local source_root="$1"
    local kind _ source_rel __ ___
    local source_path

    while IFS=$'\t' read -r kind _ source_rel __ ___; do
        if [ "$kind" = "release" ]; then
            source_path="${PFWD_RELEASE_ASSET_DIR%/}/$source_rel"
        else
            source_path="${source_root%/}/$source_rel"
        fi
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
}

service_install_files() {
    pfwd_mkdirs
    service_prepare_install_dirs
    service_verify_bundle_from_dir "$PFWD_SCRIPT_DIR"
    service_copy_bundle_from_dir "$PFWD_SCRIPT_DIR"
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
    pfwd_run systemctl enable --now pfwd.service
}

service_unit_exists() {
    local unit="$1"
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl cat "$unit" >/dev/null 2>&1
}

service_runtime_installed() {
    service_unit_exists pfwd.service
}

service_primary_runtime_unit() {
    echo "pfwd.service"
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
        pfwd_run systemctl stop pfwd.service || true
        pfwd_run systemctl disable pfwd.service || true
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
    local kind mode source_rel install_rel digest_label
    service_remove_shortcuts
    while IFS=$'\t' read -r kind mode source_rel install_rel digest_label; do
        rm -f "$(service_install_target_path "$install_rel")"
    done < <(service_bundle_rows)
}

service_remove_installation_artifacts() {
    service_remove_unit_files
    service_remove_binary_artifacts
    rm -rf "$PFWD_INSTALL_DIR"
}

service_uninstall_files() {
    local status=0

    service_disable || status=1
    service_cleanup_pfwd_tc || status=1
    runtime_clear_accounting_runtime || status=1
    runtime_remove_runtime_artifacts || status=1
    runtime_remove_runtime_state_dirs || status=1
    service_remove_installation_artifacts || status=1

    return "$status"
}

service_purge_state() {
    rm -rf "$PFWD_ETC_DIR" "$PFWD_STATE_DIR" "$PFWD_RUN_DIR"
}

service_verify_removed() {
    local leftovers=()
    local path _ source_rel install_rel __
    for path in "$PFWD_INSTALL_DIR/lib" "$PFWD_INSTALL_DIR/bin" \
        "$PFWD_SERVICE_BIN_PATH" "$PFWD_DB_FILE" "$PFWD_SERVICE_SOCKET" \
        "$PFWD_FORWARDER_RUNTIME_FILE" "$PFWD_FORWARDER_XDP_RUNTIME_FILE" "$PFWD_FORWARDER_NFT_RUNTIME_FILE" "$PFWD_FORWARDER_NFT_RENDER_FILE" "$PFWD_FORWARDER_STATUS_FILE" \
        "$PFWD_XDP_STATUS_FILE" "$PFWD_XDP_LINK_PIN_PATH" "$PFWD_XDP_LOOPBACK_PIN_PATH" \
        "$PFWD_XDP_SK_LOOKUP_PIN_PATH" "$PFWD_XDP_SETTINGS_PIN_PATH" "$PFWD_XDP_RULES_PIN_PATH" "$PFWD_XDP_CONNECTIONS_PIN_PATH" \
        "$PFWD_XDP_REVERSE_PIN_PATH" \
        "$PFWD_XDP_RULE_COUNTER_PIN_PATH" "$PFWD_XDP_USER_COUNTER_PIN_PATH" "$PFWD_XDP_STATS_PIN_PATH" \
        "$PFWD_ETC_DIR" "$PFWD_STATE_DIR" "$PFWD_RUN_DIR"; do
        [ ! -e "$path" ] || leftovers+=("$path")
    done
    while IFS=$'\t' read -r _ path __; do
        [ ! -e "$path" ] || leftovers+=("$path")
    done < <(service_shortcut_rows)
    while IFS=$'\t' read -r _ __ source_rel install_rel ___; do
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

    mkdir -p "$staged_dir/lib" "$staged_dir/release"
    local kind _ source_rel __ ___ url target_rel
    while IFS=$'\t' read -r kind _ source_rel __ ___; do
        if [ "$kind" = "release" ]; then
            url="$(service_release_asset_url "$source_rel")"
            target_rel="release/$source_rel"
        else
            url="$PFWD_REPO_RAW_URL/$source_rel"
            target_rel="$source_rel"
        fi
        mkdir -p "$(dirname "$staged_dir/$target_rel")"
        pfwd_bootstrap_download "$url" "$staged_dir/$target_rel" || return 1
    done < <(service_update_bundle_rows)
}

service_update_validate_bundle() {
    local dir="$1"
    local kind _ source_rel __ ___ path
    while IFS=$'\t' read -r kind _ source_rel __ ___; do
        if [ "$kind" = "release" ]; then
            path="$dir/release/$source_rel"
        else
            path="$dir/$source_rel"
        fi
        [ -f "$path" ] || {
            echo "更新包不完整：缺少 $source_rel" >&2
            service_missing_bundle_hint "$path" >&2 || true
            return 1
        }
        case "$source_rel" in
            *.sh) bash -n "$path" || return 1 ;;
        esac
    done < <(service_update_bundle_rows)
}

service_update_bundle_digest() {
    local dir="$1"
    local layout="${2:-staged}"
    local payload="" kind mode source_rel install_rel digest_label
    local digest_path=""

    while IFS=$'\t' read -r kind mode source_rel install_rel digest_label; do
        case "$layout" in
            install) digest_path="$dir/$install_rel" ;;
            staged)
                if [ "$kind" = "release" ]; then
                    digest_path="$dir/release/$source_rel"
                else
                    digest_path="$dir/$source_rel"
                fi
                ;;
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
    local unit label enable_capable enabled active
    {
        while IFS=$'\t' read -r unit label enable_capable; do
            [ -n "$unit" ] || continue
            service_unit_exists "$unit" || continue
            enabled="$(service_update_capture_enabled_state "$unit")"
            active="$(service_update_capture_active_state "$unit")"
            printf '%s\t%s\t%s\t%s\t%s\n' "$unit" "$label" "$enable_capable" "$enabled" "$active"
        done < <(service_update_managed_unit_rows)
    } | jq -Rsc '
      split("\n")
      | map(select(length > 0) | split("\t"))
      | map({
          unit: .[0],
          label: .[1],
          enable_capable: (.[2] == "true"),
          enabled: (.[3] == "true"),
          active: (.[4] == "true")
        })
    '
}

service_update_restore_service_states() {
    local states_json="$1"

    if ! command -v systemctl >/dev/null 2>&1; then
        return 0
    fi

    pfwd_run systemctl daemon-reload
    jq -r '.[] | select((.enable_capable // false) == true) | [.unit, (if .enabled then "true" else "false" end)] | @tsv' <<< "$states_json" |
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
    PFWD_RELEASE_ASSET_DIR="$staged_dir/release" service_copy_bundle_from_dir "$staged_dir"
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
