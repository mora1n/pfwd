#!/usr/bin/env bash


UI_REPLY=""
UI_STATUS=0
UI_TRAFFIC_MODE=""
UI_EDIT_ABORTED=0
UI_REFRESH_INTERVAL="${UI_REFRESH_INTERVAL:-10}"
UI_TERM_WIDTH_CACHE=""
UI_WIDTH_RESULT=0
UI_TEXT_RESULT=""
UI_CELL_COLOR=""
UI_MSS_MODE=""
UI_MSS_VALUE=""
UI_SNAT_MODE="masquerade"
UI_SNAT_SOURCE=""
UI_MSS_RECOMMENDED=""
UI_MSS_RECOMMEND_SOURCE=""
UI_NOTICE_TEXT=""
UI_NOTICE_COLOR=""
UI_COLOR_ENABLED="${UI_COLOR_ENABLED:-auto}"
UI_ALT_SCREEN_ACTIVE=0
UI_TERM_HEIGHT_CACHE=""
UI_PAGE_ACTIVE=0
UI_PAGE_SCROLLABLE=0
UI_PAGE_OFFSET=0
UI_PAGE_LINE_COUNT=0
UI_PAGE_RENDERER_KEY=""
UI_WHEEL_STEP="${UI_WHEEL_STEP:-4}"
UI_FORM_TITLE=""
UI_FORM_HINT=""
declare -ag UI_FORM_LINES=()
declare -ag UI_FORM_OPTION_LINES=()
declare -ag UI_PAGE_LINES=()
declare -ag UI_PAGE_PREV_LINES=()
UI_PAGE_PREV_OFFSET=0
declare -ag UI_DRY_RUN_LINES=()
declare -Ag UI_DATA_CACHE_VALUES=()

# Color theme
UI_C_TITLE="1;96"
UI_C_HEADER="1;36"
UI_C_DIM="2;37"
UI_C_DIM_CYAN="2;36"
UI_C_ACCENT="36"
UI_C_MENU_NUM="32"
UI_C_MENU_LABEL="36"
UI_C_SUCCESS="1;32"
UI_C_ACTIVE="1;32"
UI_C_MIXED="1;36"
UI_C_PAUSED="1;33"
UI_C_WARN="33"
UI_C_ERROR="31"
UI_C_STOPPED="1;31"
UI_C_BRIGHT="1;37"


ui_main_status_title() {
    ui_color "$UI_C_TITLE" "端口转发"
}


ui_use_color() {
    case "${UI_COLOR_ENABLED:-auto}" in
        1|true|yes) [ -z "${NO_COLOR:-}" ] ;;
        0|false|no) return 1 ;;
        *)
            [ -t 1 ] && [ -z "${NO_COLOR:-}" ]
            ;;
    esac
}


ui_detect_color_support() {
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        UI_COLOR_ENABLED=1
    else
        UI_COLOR_ENABLED=0
    fi
}


ui_color() {
    local code="$1"
    shift
    if ui_use_color; then
        printf '\033[%sm%s\033[0m' "$code" "$*"
    else
        printf '%s' "$*"
    fi
}


ui_apply_color() {
    local code="$1"
    local text="$2"
    if [ -n "$code" ]; then
        ui_color "$code" "$text"
    else
        printf '%s' "$text"
    fi
}


ui_empty_users_text() {
    printf '暂无用户，请先添加用户'
}


ui_empty_forwards_text() {
    printf '暂无转发，请先添加转发'
}


ui_has_users() {
    config_init >/dev/null
    jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null
}


ui_require_users() {
    if ui_has_users; then
        return 0
    fi
    UI_STATUS=1
    UI_EDIT_ABORTED=1
    ui_warn "请先添加用户"
    return 1
}


ui_clear_screen() {
    [ -t 1 ] || return 0
    UI_TERM_WIDTH_CACHE=""
    printf '\033[H\033[2J\033[3J'
}


ui_screen_enter() {
    [ -t 1 ] || return 0
    [ "$UI_ALT_SCREEN_ACTIVE" = "1" ] && return 0
    printf '\033[?1049h\033[?1000h\033[?1006h\033[H'
    UI_ALT_SCREEN_ACTIVE=1
    UI_TERM_WIDTH_CACHE=""
    UI_TERM_HEIGHT_CACHE=""
}


ui_screen_leave() {
    [ "$UI_ALT_SCREEN_ACTIVE" = "1" ] || return 0
    printf '\033[?1006l\033[?1000l\033[?1049l'
    UI_ALT_SCREEN_ACTIVE=0
    UI_TERM_WIDTH_CACHE=""
    UI_TERM_HEIGHT_CACHE=""
}


ui_menu_cleanup() {
    trap - EXIT INT TERM
    ui_screen_leave
}


ui_notice_set() {
    UI_NOTICE_TEXT="$1"
    UI_NOTICE_COLOR="${2:-36}"
}


ui_notice_clear() {
    UI_NOTICE_TEXT=""
    UI_NOTICE_COLOR=""
}


ui_data_cache_clear() {
    UI_DATA_CACHE_VALUES=()
}


ui_cached_data() {
    local cache_key="$1"
    shift
    if [[ -v UI_DATA_CACHE_VALUES["$cache_key"] ]]; then
        printf '%s\n' "${UI_DATA_CACHE_VALUES[$cache_key]}"
        return 0
    fi
    UI_DATA_CACHE_VALUES["$cache_key"]="$("$@")"
    printf '%s\n' "${UI_DATA_CACHE_VALUES[$cache_key]}"
}


ui_dry_run_reset() {
    UI_DRY_RUN_LINES=()
}


ui_dry_run_add() {
    local line="$1"
    [ -n "$line" ] || return 0
    UI_DRY_RUN_LINES+=("$line")
    if [ "${#UI_DRY_RUN_LINES[@]}" -gt 8 ]; then
        UI_DRY_RUN_LINES=("${UI_DRY_RUN_LINES[@]: -8}")
    fi
}


ui_emit_dry_run() {
    local line="$1"
    if [ "${PFWD_DRY_RUN:-0}" = "1" ] && [ "$UI_ALT_SCREEN_ACTIVE" = "1" ]; then
        ui_dry_run_add "$line"
        return 0
    fi
    printf '%s\n' "$line"
}


ui_notice_render() {
    if [ -n "$UI_NOTICE_TEXT" ]; then
        ui_print_line "$UI_NOTICE_TEXT" "${UI_NOTICE_COLOR:-36}"
        printf '\n'
    fi
    if [ "${#UI_DRY_RUN_LINES[@]}" -gt 0 ]; then
        ui_print_line "最近 dry-run：" "$UI_C_DIM"
        printf '%s\n' "${UI_DRY_RUN_LINES[@]}"
        printf '\n'
    fi
}


ui_render_page() {
    local frame status renderer_key previous_key
    frame="$("$@")"
    status=$?
    [ "$status" -eq 0 ] || return "$status"
    renderer_key="$*"
    previous_key="$UI_PAGE_RENDERER_KEY"
    UI_PAGE_RENDERER_KEY="$renderer_key"
    ui_page_prepare_frame "$frame"
    if [ "$renderer_key" != "$previous_key" ]; then
        ui_page_apply_default_anchor "$renderer_key"
        UI_PAGE_PREV_LINES=()
    fi
    ui_page_draw
    ui_data_cache_clear
    ui_notice_clear
}


ui_term_height() {
    local height="${LINES:-}"
    if [ -n "$UI_TERM_HEIGHT_CACHE" ]; then
        printf '%s' "$UI_TERM_HEIGHT_CACHE"
        return 0
    fi
    if [ -z "$height" ] && [ -t 1 ] && command -v tput >/dev/null 2>&1; then
        height="$(tput lines 2>/dev/null || true)"
    fi
    [[ "$height" =~ ^[0-9]+$ ]] || height=24
    [ "$height" -ge 12 ] || height=12
    UI_TERM_HEIGHT_CACHE="$height"
    printf '%s' "$height"
}


ui_page_prepare_frame() {
    local frame="$1"
    UI_PAGE_ACTIVE=1
    UI_PAGE_SCROLLABLE=0
    mapfile -t UI_PAGE_LINES <<< "$frame"
    if [ "${#UI_PAGE_LINES[@]}" -gt 0 ] && [ -z "${UI_PAGE_LINES[-1]}" ]; then
        unset 'UI_PAGE_LINES[-1]'
    fi
    UI_PAGE_LINE_COUNT="${#UI_PAGE_LINES[@]}"
}


ui_page_apply_default_anchor() {
    local renderer_key="$1"
    local view_height line_index line_text candidate_offset previous_line
    case "$renderer_key" in
        ui_render_main_menu_page)
            view_height="$(ui_page_view_height)"
            UI_PAGE_OFFSET="$(ui_page_max_offset "$view_height")"
            candidate_offset="$UI_PAGE_OFFSET"
            for ((line_index = candidate_offset; line_index >= 0; line_index--)); do
                line_text="${UI_PAGE_LINES[$line_index]:-}"
                if [[ "$line_text" == 用户：* ]] || [ "$line_text" = "当前转发" ] || [[ "$line_text" == "== "* ]]; then
                    UI_PAGE_OFFSET="$line_index"
                    break
                fi
            done
            if [[ "${UI_PAGE_LINES[$UI_PAGE_OFFSET]:-}" == 用户：* ]] && [ "$UI_PAGE_OFFSET" -gt 0 ]; then
                previous_line="${UI_PAGE_LINES[$((UI_PAGE_OFFSET - 1))]:-}"
                if [ "$previous_line" = "当前转发" ]; then
                    UI_PAGE_OFFSET=$((UI_PAGE_OFFSET - 1))
                fi
            fi
            ;;
        ui_render_users_menu_page|ui_render_forwards_menu_page|ui_render_traffic_user_menu_page*|ui_render_traffic_select_user_page|ui_render_telegram_menu_page|ui_render_export_import_menu_page|ui_render_user_select_page*|ui_render_forward_select_page*|ui_render_user_forward_select_page*|ui_render_telegram_user_select_page*)
            view_height="$(ui_page_view_height)"
            UI_PAGE_OFFSET="$(ui_page_max_offset "$view_height")"
            ;;
        *)
            UI_PAGE_OFFSET=0
            ;;
    esac
}


ui_page_view_height() {
    local height footer_lines=1
    height="$(ui_term_height)"
    if [ "$UI_PAGE_LINE_COUNT" -gt $((height - 1)) ]; then
        footer_lines=2
        UI_PAGE_SCROLLABLE=1
    else
        UI_PAGE_SCROLLABLE=0
    fi
    height=$((height - footer_lines))
    [ "$height" -ge 3 ] || height=3
    printf '%s' "$height"
}


ui_page_max_offset() {
    local view_height="$1"
    local max_offset=$((UI_PAGE_LINE_COUNT - view_height))
    [ "$max_offset" -gt 0 ] || max_offset=0
    printf '%s' "$max_offset"
}


ui_page_clamp_offset() {
    local view_height max_offset
    view_height="$(ui_page_view_height)"
    max_offset="$(ui_page_max_offset "$view_height")"
    if [ "$UI_PAGE_OFFSET" -lt 0 ]; then
        UI_PAGE_OFFSET=0
    elif [ "$UI_PAGE_OFFSET" -gt "$max_offset" ]; then
        UI_PAGE_OFFSET="$max_offset"
    fi
}


ui_page_draw() {
    local prompt="${1:-}"
    local default="${2:-}"
    local buffer="${3:-}"
    local view_height max_offset start_line end_line i status_text line_changed

    ui_page_clamp_offset
    view_height="$(ui_page_view_height)"
    max_offset="$(ui_page_max_offset "$view_height")"
    start_line="$UI_PAGE_OFFSET"
    end_line=$((start_line + view_height))

    local prev_count="${#UI_PAGE_PREV_LINES[@]}"
    local use_diff=0
    if [ "$prev_count" -gt 0 ] && [ "$UI_PAGE_PREV_OFFSET" = "$start_line" ]; then
        use_diff=1
    fi

    printf '\033[H'
    for ((i = start_line; i < end_line && i < UI_PAGE_LINE_COUNT; i++)); do
        local screen_row=$((i - start_line))
        if [ "$use_diff" = "1" ] && [ "$screen_row" -lt "$prev_count" ]; then
            if [ "${UI_PAGE_LINES[$i]}" = "${UI_PAGE_PREV_LINES[$screen_row]}" ]; then
                printf '\033[B'
                continue
            fi
        fi
        if [ "$use_diff" = "1" ] && [ "$screen_row" -gt 0 ]; then
            printf '\033[%d;1H' "$((screen_row + 1))"
        elif [ "$use_diff" = "0" ] && [ "$screen_row" -gt 0 ]; then
            :
        fi
        printf '%s\033[K\n' "${UI_PAGE_LINES[$i]}"
    done

    local written_rows=$((end_line < UI_PAGE_LINE_COUNT ? end_line - start_line : UI_PAGE_LINE_COUNT - start_line))
    if [ "$written_rows" -lt "$view_height" ]; then
        for ((i = written_rows; i < view_height; i++)); do
            printf '\033[K\n'
        done
    fi

    if [ "$use_diff" = "1" ] && [ "$view_height" -lt "$prev_count" ]; then
        printf '\033[%d;1H\033[J' "$((view_height + 1))"
    elif [ "$use_diff" = "0" ]; then
        printf '\033[J'
    fi

    UI_PAGE_PREV_LINES=()
    for ((i = start_line; i < end_line && i < UI_PAGE_LINE_COUNT; i++)); do
        UI_PAGE_PREV_LINES+=("${UI_PAGE_LINES[$i]}")
    done
    UI_PAGE_PREV_OFFSET="$start_line"

    if [ "$UI_PAGE_SCROLLABLE" = "1" ]; then
        status_text="滚动 $((start_line + 1))-$(( end_line < UI_PAGE_LINE_COUNT ? end_line : UI_PAGE_LINE_COUNT ))/$UI_PAGE_LINE_COUNT  鼠标滚轮/↑↓/PgUp/PgDn"
        ui_print_line "$status_text" "$UI_C_DIM"
    fi

    # The prompt line may shrink when we switch from showing [default] to
    # showing typed input. Clear from the prompt row to the end of screen so
    # wrapped default text from the previous draw cannot remain on screen.
    printf '\033[J'

    if [ -n "$prompt" ]; then
        if [ -n "$default" ] && [ -z "$buffer" ]; then
            printf '%s [%s]: %s' "$prompt" "$default" "$buffer"
        else
            printf '%s: %s' "$prompt" "$buffer"
        fi
    fi
}


ui_page_deactivate() {
    UI_PAGE_ACTIVE=0
    UI_PAGE_SCROLLABLE=0
    UI_PAGE_LINE_COUNT=0
    UI_PAGE_LINES=()
    UI_PAGE_PREV_LINES=()
}


ui_page_scroll_lines() {
    local delta="$1"
    UI_PAGE_OFFSET=$((UI_PAGE_OFFSET + delta))
    ui_page_clamp_offset
    UI_PAGE_PREV_LINES=()
}


ui_page_scroll_wheel() {
    local direction="$1"
    local step="${UI_WHEEL_STEP:-4}"
    [[ "$step" =~ ^[0-9]+$ ]] || step=4
    [ "$step" -ge 1 ] || step=1
    if [ "$direction" -gt 0 ]; then
        ui_page_scroll_lines "$step"
    else
        ui_page_scroll_lines "-$step"
    fi
}


ui_page_scroll_pages() {
    local direction="$1"
    local view_height
    view_height="$(ui_page_view_height)"
    if [ "$direction" -gt 0 ]; then
        ui_page_scroll_lines "$view_height"
    else
        ui_page_scroll_lines "-$view_height"
    fi
}


ui_read_keypress() {
    local timeout="${1:-}"
    local first="" next="" sequence=""
    if [ -n "$timeout" ]; then
        if ! IFS= read -rsn1 -t "$timeout" first; then
            UI_REPLY=""
            return 124
        fi
    else
        if ! IFS= read -rsn1 first; then
            UI_REPLY=""
            return 1
        fi
    fi

    if [ -z "$first" ]; then
        UI_REPLY=$'\n'
    elif [ "$first" = $'\033' ]; then
        sequence="$first"
        while IFS= read -rsn1 -t 0.01 next; do
            sequence+="$next"
            case "$next" in
                [~A-Za-zMm]) break ;;
            esac
        done
        UI_REPLY="$sequence"
    else
        UI_REPLY="$first"
    fi
    return 0
}


ui_page_read_line() {
    local prompt="$1"
    local timeout_seconds="${2:-}"
    local default="${3:-}"
    local buffer="" key="" current_timeout="$timeout_seconds"

    while true; do
        ui_page_draw "$prompt" "$default" "$buffer"
        if ui_read_keypress "$current_timeout"; then
            key="$UI_REPLY"
        else
            case "$?" in
                124)
                    ui_page_deactivate
                    UI_REPLY=""
                    return 124
                    ;;
                *)
                    ui_page_deactivate
                    UI_REPLY=""
                    return 1
                    ;;
            esac
        fi

        case "$key" in
            $'\n'|$'\r')
                ui_page_deactivate
                UI_REPLY="$buffer"
                [ -n "$UI_REPLY" ] || UI_REPLY="$default"
                printf '\n'
                return 0
                ;;
            $'\177'|$'\010')
                if [ -n "$buffer" ]; then
                    buffer="${buffer%?}"
                    current_timeout=""
                fi
                ;;
            $'\033[A'|$'\033OA')
                ui_page_scroll_lines -1
                current_timeout="$timeout_seconds"
                ;;
            $'\033[B'|$'\033OB')
                ui_page_scroll_lines 1
                current_timeout="$timeout_seconds"
                ;;
            $'\033[<64;'*)
                ui_page_scroll_wheel -1
                current_timeout="$timeout_seconds"
                ;;
            $'\033[<65;'*)
                ui_page_scroll_wheel 1
                current_timeout="$timeout_seconds"
                ;;
            $'\033[5~')
                ui_page_scroll_pages -1
                current_timeout="$timeout_seconds"
                ;;
            $'\033[6~')
                ui_page_scroll_pages 1
                current_timeout="$timeout_seconds"
                ;;
            $'\033')
                current_timeout="$timeout_seconds"
                ;;
            *)
                if [[ "$key" =~ ^[[:print:]]$ ]]; then
                    buffer+="$key"
                    current_timeout=""
                fi
                ;;
        esac
    done
}
