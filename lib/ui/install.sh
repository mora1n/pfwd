#!/usr/bin/env bash

ui_missing_dependencies() {
    local missing=()
    command -v jq >/dev/null 2>&1 || missing+=(jq)
    command -v tc >/dev/null 2>&1 || missing+=(tc)
    command -v systemctl >/dev/null 2>&1 || missing+=(systemctl)
    printf '%s\n' "${missing[@]}"
}


ui_detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo apt-get
    elif command -v dnf >/dev/null 2>&1; then
        echo dnf
    elif command -v yum >/dev/null 2>&1; then
        echo yum
    elif command -v pacman >/dev/null 2>&1; then
        echo pacman
    elif command -v apk >/dev/null 2>&1; then
        echo apk
    else
        echo ""
    fi
}


ui_install_system_dependencies() {
    local pm="$1"
    case "$pm" in
        apt-get)
            pfwd_run apt-get update
            pfwd_run apt-get install -y jq iproute2 systemd curl tar
            ;;
        dnf)
            pfwd_run dnf install -y jq iproute systemd curl tar
            ;;
        yum)
            pfwd_run yum install -y jq iproute systemd curl tar
            ;;
        pacman)
            pfwd_run pacman -Sy --noconfirm jq iproute2 systemd curl tar
            ;;
        apk)
            pfwd_run apk add jq iproute2 curl tar
            ui_warn "Alpine 默认不提供 systemd/systemctl，pfwd 的服务管理需要 systemd。"
            ;;
        *)
            ui_warn "未识别包管理器，请手动安装 jq、iproute2、systemd、curl、tar。"
            return 1
            ;;
    esac
}


ui_install_forwarder() {
    ui_info "pfwd 已内置 XDP 数据面 helper；无需额外安装转发内核。"
}


ui_install_missing_dependencies() {
    if [ "${PFWD_DRY_RUN:-0}" = "1" ] && [ "$UI_ALT_SCREEN_ACTIVE" = "1" ]; then
        ui_dry_run_reset
    fi
    if [ "$(id -u)" -ne 0 ] && [ "${PFWD_DRY_RUN:-0}" != "1" ]; then
        ui_error "安装依赖需要 root 权限，请使用 sudo pfwd。"
        return 1
    fi

    local pm
    pm="$(ui_detect_package_manager)"
    ui_install_system_dependencies "$pm" || true
    ui_install_forwarder || true
}


ui_dependency_preflight() {
    local missing="" dep
    while IFS= read -r dep; do
        [ -n "$dep" ] || continue
        if [ -z "$missing" ]; then
            missing="$dep"
        else
            missing="$missing $dep"
        fi
    done < <(ui_missing_dependencies)
    [ -n "$missing" ] || return 0

    ui_warn "检测到缺失依赖：$missing"
    if ui_yes "是否安装缺失依赖？"; then
        ui_install_missing_dependencies
        missing=""
        while IFS= read -r dep; do
            [ -n "$dep" ] || continue
            if [ -z "$missing" ]; then
                missing="$dep"
            else
                missing="$missing $dep"
            fi
        done < <(ui_missing_dependencies)
        if [ -n "$missing" ]; then
            ui_warn "仍有缺失依赖：$missing"
        fi
    fi

    if ! command -v jq >/dev/null 2>&1; then
        pfwd_die "jq 是读取配置必需依赖，请安装 jq 后重新运行。"
    fi
}


ui_runtime_install_preflight() {
    if service_runtime_installed; then
        return 0
    fi

    ui_warn "检测到 pfwd 运行态尚未安装，当前修改仅保存配置。"
    if ui_yes "是否现在执行安装？"; then
        ui_run cmd_install
    fi
}
