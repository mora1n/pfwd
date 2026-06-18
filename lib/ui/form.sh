#!/usr/bin/env bash

ui_form_reset() {
    UI_FORM_TITLE=""
    UI_FORM_HINT=""
    UI_FORM_LINES=()
    UI_FORM_OPTION_LINES=()
}


ui_form_set() {
    local title="$1"
    local hint="${2:-}"
    UI_FORM_TITLE="$title"
    UI_FORM_HINT="$hint"
    UI_FORM_LINES=()
    UI_FORM_OPTION_LINES=()
}


ui_form_add_line() {
    UI_FORM_LINES+=("$1")
}


ui_form_add_kv() {
    local label="$1"
    local value="$2"
    ui_form_add_line "$label：$(ui_display_or_dash "$value")"
}


ui_render_form_page() {
    local title="$1"
    local hint="${2:-}"
    shift 2 || true
    ui_header "$title"
    [ -n "$hint" ] && ui_print_line "$hint" "$UI_C_DIM"
    if [ -n "$UI_NOTICE_TEXT" ]; then
        printf '\n'
        ui_print_line "$UI_NOTICE_TEXT" "${UI_NOTICE_COLOR:-36}"
    fi
    if [ -n "$hint" ] && { [ "${#UI_FORM_LINES[@]}" -gt 0 ] || [ "${#UI_FORM_OPTION_LINES[@]}" -gt 0 ]; }; then
        printf '\n'
    fi
    if [ "${#UI_FORM_LINES[@]}" -gt 0 ]; then
        printf '%s\n' "${UI_FORM_LINES[@]}"
    fi
    if [ "${#UI_FORM_OPTION_LINES[@]}" -gt 0 ]; then
        [ "${#UI_FORM_LINES[@]}" -eq 0 ] || printf '\n'
        printf '%s\n' "${UI_FORM_OPTION_LINES[@]}"
    fi
    if [ "${#UI_DRY_RUN_LINES[@]}" -gt 0 ]; then
        printf '\n'
        ui_print_line "最近 dry-run：" "$UI_C_DIM"
        printf '%s\n' "${UI_DRY_RUN_LINES[@]}"
    fi
}


ui_form_refresh() {
    [ -n "$UI_FORM_TITLE" ] || return 1
    ui_render_page ui_render_form_page "$UI_FORM_TITLE" "$UI_FORM_HINT"
}


ui_form_read() {
    local prompt="$1"
    local default="${2:-}"
    UI_EDIT_ABORTED=0
    if [ -n "$UI_FORM_TITLE" ]; then
        ui_form_refresh
    fi
    ui_read "$prompt" "$default"
    if [ "$UI_REPLY" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi
}


ui_form_edit_read() {
    local prompt="$1"
    local default="${2:-}"
    if [ -n "$UI_FORM_TITLE" ]; then
        ui_form_refresh
    fi
    ui_edit_read "$prompt" "$default"
}


ui_trim_whitespace() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s\n' "$value"
}


ui_form_read_allow_zero_value() {
    local prompt="$1"
    local default="${2:-}"
    UI_EDIT_ABORTED=0
    if [ -n "$UI_FORM_TITLE" ]; then
        ui_form_refresh
    fi
    ui_read "$prompt" "$default"
}


ui_form_select_has_choice() {
    local selected="$1"
    shift || true
    local line
    for line in "$@"; do
        if [[ "$line" =~ ^([0-9]+)\) ]]; then
            [ "$selected" = "${BASH_REMATCH[1]}" ] && return 0
        fi
    done
    return 1
}


ui_form_select_read() {
    local prompt="$1"
    local default="${2:-}"
    shift 2 || true
    local options=("$@")
    local line status

    while true; do
        status=0
        if [ -n "$UI_FORM_TITLE" ]; then
            UI_FORM_OPTION_LINES=("${options[@]}")
            ui_form_refresh
            ui_read "$prompt" "$default" || status=$?
            UI_FORM_OPTION_LINES=()
        else
            for line in "${options[@]}"; do
                printf '%s\n' "$line"
            done
            ui_read "$prompt" "$default" || status=$?
        fi

        [ "$status" -eq 0 ] || return "$status"
        if [ -z "$UI_REPLY" ] || ui_form_select_has_choice "$UI_REPLY" "${options[@]}"; then
            return 0
        fi

        if [ -n "$UI_FORM_TITLE" ]; then
            ui_notice_set "无效选择，请重新输入。" "$UI_C_WARN"
        else
            ui_warn "无效选择，请重新输入。"
        fi
    done
}
