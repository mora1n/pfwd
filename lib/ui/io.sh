#!/usr/bin/env bash

ui_maybe_pause() {
    local mode="${1:-status}"
    case "$mode" in
        success)
            [ "$UI_STATUS" -eq 0 ] || ui_pause
            ;;
        always)
            ui_pause
            ;;
        *)
            [ "$UI_STATUS" -eq 0 ] || ui_pause
            ;;
    esac
}


ui_header() {
    printf '\n'
    ui_color "$UI_C_HEADER" "== $* =="
    printf '\n'
}


ui_main_title_meta_tsv() {
    local backend="none"
    if [ -f "$PFWD_FORWARDER_STATUS_FILE" ]; then
        backend="$(jq -r '.forwarding_backend // "none"' "$PFWD_FORWARDER_STATUS_FILE" 2>/dev/null || echo none)"
    fi
    jq -r --arg backend "$backend" '
      [
        (.users | length),
        ([.forwards[]? | select(.enabled == true)] | length),
        $backend
      ] | @tsv
    ' "$PFWD_CONFIG_FILE"
}


ui_title() {
    local title_meta user_count forward_count backend
    title_meta="$(ui_cached_data "main_title_meta_tsv" ui_main_title_meta_tsv)"
    IFS=$'\t' read -r user_count forward_count backend <<< "$title_meta"
    printf '\n'
    ui_color "$UI_C_TITLE" "pfwd v${PFWD_VERSION:-}"
    printf '  '
    ui_color "$UI_C_DIM" "用户: $user_count  转发: $forward_count"
    if [ -n "${backend:-}" ] && [ "$backend" != "none" ]; then
        printf '  '
        ui_color "$UI_C_DIM_CYAN" "后端: $backend"
    fi
    printf '\n'
    ui_print_line "操作流程：用户 → 添加转发 → 流量管理" "$UI_C_ACCENT"
    ui_rule "-" "$UI_C_DIM"
}


ui_menu_item() {
    local number="$1"
    local label="$2"
    ui_color "$UI_C_MENU_NUM" "$number."
    printf ' %s\n' "$label"
}


ui_success() {
    ui_color "$UI_C_MENU_NUM" "$*"
    printf '\n'
}


ui_warn() {
    ui_color "$UI_C_WARN" "$*"
    printf '\n'
}


ui_error() {
    ui_color "$UI_C_ERROR" "$*"
    printf '\n'
}


ui_read() {
    local prompt="$1"
    local default="${2:-}"
    UI_REPLY=""
    if [ "$UI_PAGE_ACTIVE" = "1" ] && [ -t 0 ] && [ -t 1 ]; then
        ui_page_read_line "$prompt" "" "$default"
        return $?
    fi
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$prompt" "$default"
    else
        printf '%s: ' "$prompt"
    fi
    if ! IFS= read -r UI_REPLY; then
        UI_REPLY=""
        return 1
    fi
    [ -n "$UI_REPLY" ] || UI_REPLY="$default"
    return 0
}


ui_read_timed() {
    local prompt="$1"
    local timeout_seconds="${2:-1}"
    local default="${3:-}"
    UI_REPLY=""

    if [ ! -t 0 ]; then
        ui_read "$prompt" "$default"
        return $?
    fi

    if [ "$UI_PAGE_ACTIVE" = "1" ] && [ -t 1 ]; then
        ui_page_read_line "$prompt" "$timeout_seconds" "$default"
        return $?
    fi

    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$prompt" "$default"
    else
        printf '%s: ' "$prompt"
    fi

    if IFS= read -r -t "$timeout_seconds" UI_REPLY; then
        [ -n "$UI_REPLY" ] || UI_REPLY="$default"
        return 0
    fi

    UI_REPLY=""
    return 124
}


ui_edit_read() {
    local prompt="$1"
    local default="${2:-}"
    UI_EDIT_ABORTED=0
    ui_read "$prompt" "$default" || return 1
    if [ "$UI_REPLY" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi
    return 0
}
