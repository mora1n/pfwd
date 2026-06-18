#!/usr/bin/env bash

ui_pause() {
    [ -t 0 ] || return 0
    printf '按回车继续...'
    IFS= read -r _ || true
}


ui_run() {
    if [ "${PFWD_DRY_RUN:-0}" = "1" ] && [ "$UI_ALT_SCREEN_ACTIVE" = "1" ]; then
        ui_dry_run_reset
    fi
    if ( "$@" ); then
        UI_STATUS=0
        return 0
    fi
    UI_STATUS=1
    ui_error "操作失败"
    return 0
}


ui_try_cmd() {
    local output="" status=0
    if [ "${PFWD_DRY_RUN:-0}" = "1" ] && [ "$UI_ALT_SCREEN_ACTIVE" = "1" ]; then
        ui_dry_run_reset
    fi
    UI_REPLY=""
    output="$( ( "$@" ) 2>&1 )" || status=$?
    UI_REPLY="$output"
    if [ "$status" -eq 0 ]; then
        UI_STATUS=0
        return 0
    fi
    UI_STATUS=1
    return "$status"
}


ui_error_from_reply() {
    local message="$1"
    if [ -n "$UI_REPLY" ]; then
        ui_error "$message：$UI_REPLY"
    else
        ui_error "$message"
    fi
}


ui_run_capture() {
    local output="" status=0
    if [ "${PFWD_DRY_RUN:-0}" = "1" ] && [ "$UI_ALT_SCREEN_ACTIVE" = "1" ]; then
        ui_dry_run_reset
    fi
    UI_REPLY=""
    output="$( ( "$@" ) 2>&1 )" || status=$?
    UI_REPLY="$output"
    if [ "$status" -eq 0 ]; then
        UI_STATUS=0
    else
        UI_STATUS=1
    fi
    return 0
}


ui_confirm_text() {
    local expected="$1"
    local prompt="$2"
    ui_read "$prompt" || return 1
    [ "$UI_REPLY" = "$expected" ]
}


ui_yes() {
    local prompt="$1"
    ui_read "$prompt" "y/N" || return 1
    case "$UI_REPLY" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}


ui_is_ipv4_literal() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}


ui_is_ipv6_literal() {
    local value="$1"
    [[ "$value" == *:* ]]
}


ui_probe_route_mtu() {
    local family="$1"
    local target="$2"
    local route_cmd_output="" mtu="" iface=""

    if [ "$family" = "6" ]; then
        route_cmd_output="$(ip -6 route get "$target" 2>/dev/null | head -n1 || true)"
    else
        route_cmd_output="$(ip route get "$target" 2>/dev/null | head -n1 || true)"
    fi

    if [[ "$route_cmd_output" =~ [[:space:]]mtu[[:space:]]+([0-9]+) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi

    if [[ "$route_cmd_output" =~ [[:space:]]dev[[:space:]]+([^[:space:]]+) ]]; then
        iface="${BASH_REMATCH[1]}"
        if [ -n "$iface" ] && [ -r "/sys/class/net/$iface/mtu" ]; then
            mtu="$(tr -d '[:space:]' < "/sys/class/net/$iface/mtu" 2>/dev/null || true)"
            if [[ "$mtu" =~ ^[0-9]+$ ]]; then
                printf '%s\n' "$mtu"
                return 0
            fi
        fi
    fi

    return 1
}


ui_recommended_mss_value() {
    local remote_host="$1"
    local rows="" family ipver resolved_ip candidate mtu mss best="" fallback="1460"
    UI_MSS_RECOMMENDED=""
    UI_MSS_RECOMMEND_SOURCE=""

    if ui_is_ipv4_literal "$remote_host"; then
        rows="ip|4|$remote_host"
    elif ui_is_ipv6_literal "$remote_host"; then
        rows="ip6|6|$remote_host"
        fallback="1440"
    else
        rows="$(forwarder_resolve_targets "$remote_host" "46" || true)"
    fi

    if [ -z "$rows" ]; then
        UI_MSS_RECOMMENDED="$fallback"
        UI_MSS_RECOMMEND_SOURCE="fallback"
        return 0
    fi

    while IFS='|' read -r family ipver resolved_ip; do
        [ -n "$resolved_ip" ] || continue
        if mtu="$(ui_probe_route_mtu "$ipver" "$resolved_ip" 2>/dev/null)"; then
            if [ "$ipver" = "6" ]; then
                mss=$((mtu - 60))
            else
                mss=$((mtu - 40))
            fi
            if [ "$mss" -lt 536 ]; then
                mss=536
            fi
            if [ -z "$best" ] || [ "$mss" -lt "$best" ]; then
                best="$mss"
            fi
        elif [ "$ipver" = "6" ] && [ "$fallback" -gt 1440 ]; then
            fallback="1440"
        fi
    done <<< "$rows"

    if [ -n "$best" ]; then
        UI_MSS_RECOMMENDED="$best"
        UI_MSS_RECOMMEND_SOURCE="probed"
        return 0
    fi

    UI_MSS_RECOMMENDED="$fallback"
    UI_MSS_RECOMMEND_SOURCE="fallback"
}


ui_select_mss_mode() {
    local prompt="$1"
    local remote_host="${2:-}"
    local current_mode="${3:-}"
    local current_value="${4:-}"
    local allow_clear="${5:-false}"
    local recommended=""
    local source="fallback"
    local fixed_default=""
    local default_choice="1"

    UI_MSS_MODE=""
    UI_MSS_VALUE=""
    UI_EDIT_ABORTED=0

    if [ -n "$remote_host" ]; then
        ui_recommended_mss_value "$remote_host"
        recommended="$UI_MSS_RECOMMENDED"
        source="$UI_MSS_RECOMMEND_SOURCE"
    fi

    case "$current_mode" in
        clamp) default_choice="2" ;;
        set) default_choice="3" ;;
    esac

    ui_form_select_read "$prompt" "$default_choice" \
        "1) 不设置" \
        "   默认值，不主动改 TCP MSS；适合常规公网转发、大多数直连链路。" \
        "2) MSS Clamp" \
        "   按路径 MTU 自动调整 TCP MSS；适合 PPPoE、VPN、隧道、跨境链路。" \
        "3) 固定 MSS" \
        "   手动写死 TCP MSS；适合已知链路 MTU、上游有统一要求或 clamp 效果不稳定。" || return 1
    case "$UI_REPLY" in
        "")
            UI_MSS_MODE=""
            UI_MSS_VALUE=""
            ;;
        1)
            if [ "$allow_clear" = "true" ]; then
                UI_MSS_MODE="__CLEAR__"
                UI_MSS_VALUE="__CLEAR__"
            else
                UI_MSS_MODE=""
                UI_MSS_VALUE=""
            fi
            ;;
        0)
            if [ "$allow_clear" = "true" ]; then
                UI_EDIT_ABORTED=1
                return 0
            fi
            ui_warn "无效选择，已使用不设置"
            UI_MSS_MODE=""
            UI_MSS_VALUE=""
            ;;
        2)
            UI_MSS_MODE="clamp"
            if [ "$allow_clear" = "true" ]; then
                UI_MSS_VALUE="__CLEAR__"
            else
                UI_MSS_VALUE=""
            fi
            ;;
        3)
            UI_MSS_MODE="set"
            if [ -n "$current_value" ]; then
                fixed_default="$current_value"
                if [ -n "$recommended" ] && [ "$recommended" != "$current_value" ]; then
                    ui_print_line "当前固定 MSS：$current_value；推荐值：$recommended" "$UI_C_ACCENT"
                fi
            else
                fixed_default="$recommended"
                if [ -n "$recommended" ]; then
                    if [ "$source" = "fallback" ]; then
                        ui_warn "未探测到链路 MTU，已使用通用推荐值：$recommended"
                    else
                        ui_print_line "固定 MSS 推荐值：$recommended" "$UI_C_ACCENT"
                    fi
                fi
            fi
            if [ "$allow_clear" = "true" ]; then
                ui_form_edit_read "固定 MSS 值" "$fixed_default" || return 1
                [ "$UI_EDIT_ABORTED" = "1" ] && return 0
            else
                ui_form_read "固定 MSS 值" "$fixed_default" || return 1
            fi
            local mss_value="$UI_REPLY"
            if [ -z "$mss_value" ]; then
                ui_warn "固定 MSS 模式必须提供 MSS 值"
                return 1
            fi
            if ! ui_try_cmd validate_mss_value "$mss_value"; then
                ui_error_from_reply "固定 MSS 值无效"
                return 1
            fi
            UI_MSS_VALUE="$mss_value"
            ;;
        *)
            ui_warn "无效选择，已使用不设置"
            UI_MSS_MODE=""
            UI_MSS_VALUE=""
            ;;
    esac
}


ui_select_mss_mode_edit() {
    ui_select_mss_mode "$1" "${4:-}" "$2" "$3" true
}


ui_select_snat_mode() {
    local prompt="$1"
    local current_mode="${2:-masquerade}"
    local current_source="${3:-}"
    local allow_clear="${4:-false}"

    UI_SNAT_MODE="masquerade"
    UI_SNAT_SOURCE=""
    UI_EDIT_ABORTED=0

    if [ "$current_mode" = "snat" ]; then
        ui_form_select_read "$prompt" "2" \
            "1) Masquerade" \
            "   默认值，出站源地址跟随本机出口地址；适合动态公网 IP、普通单出口转发。" \
            "2) 固定 SNAT 源地址" \
            "   把出站源地址固定改写为指定 IP；适合本机有额外内网 IP、多地址出口、后端白名单来源 IP。" || return 1
    else
        ui_form_select_read "$prompt" "1" \
            "1) Masquerade" \
            "   默认值，出站源地址跟随本机出口地址；适合动态公网 IP、普通单出口转发。" \
            "2) 固定 SNAT 源地址" \
            "   把出站源地址固定改写为指定 IP；适合本机有额外内网 IP、多地址出口、后端白名单来源 IP。" || return 1
    fi
    case "$UI_REPLY" in
        "")
            UI_SNAT_MODE="$current_mode"
            if [ "$allow_clear" = "true" ]; then
                UI_SNAT_SOURCE=""
            else
                UI_SNAT_SOURCE="$current_source"
            fi
            ;;
        0)
            if [ "$allow_clear" = "true" ]; then
                UI_EDIT_ABORTED=1
                return 0
            fi
            ui_warn "无效选择，已使用 masquerade"
            UI_SNAT_MODE="masquerade"
            UI_SNAT_SOURCE=""
            ;;
        1)
            UI_SNAT_MODE="masquerade"
            if [ "$allow_clear" = "true" ]; then
                UI_SNAT_SOURCE="__CLEAR__"
            else
                UI_SNAT_SOURCE=""
            fi
            ;;
        2)
            UI_SNAT_MODE="snat"
            if [ "$allow_clear" = "true" ]; then
                ui_form_edit_read "固定 SNAT 源地址（必须是显式 IP，例如内网 IP）" "$current_source" || return 1
                [ "$UI_EDIT_ABORTED" = "1" ] && return 0
            else
                ui_form_read "固定 SNAT 源地址（必须是显式 IP，例如内网 IP）" || return 1
            fi
            local snat_source="$UI_REPLY"
            if [ -z "$snat_source" ]; then
                ui_warn "固定 SNAT 模式必须提供源地址"
                return 1
            fi
            if ! ui_try_cmd validate_ip_literal "$snat_source"; then
                ui_error_from_reply "固定 SNAT 源地址无效"
                return 1
            fi
            UI_SNAT_SOURCE="$snat_source"
            ;;
        *)
            ui_warn "无效选择，已使用 masquerade"
            UI_SNAT_MODE="masquerade"
            UI_SNAT_SOURCE=""
            ;;
    esac
}


ui_select_snat_mode_edit() {
    ui_select_snat_mode "$1" "$2" "$3" true
}
