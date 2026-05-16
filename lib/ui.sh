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
UI_DATA_CACHE=""
UI_DATA_CACHE_KEY=""

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
    UI_DATA_CACHE=""
    UI_DATA_CACHE_KEY=""
}

ui_cached_data() {
    local cache_key="$1"
    shift
    if [ "$UI_DATA_CACHE_KEY" = "$cache_key" ] && [ -n "$UI_DATA_CACHE" ]; then
        printf '%s\n' "$UI_DATA_CACHE"
        return 0
    fi
    UI_DATA_CACHE="$("$@")"
    UI_DATA_CACHE_KEY="$cache_key"
    printf '%s\n' "$UI_DATA_CACHE"
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

ui_compact_table_render() {
    local headers_tsv="$1"
    local rows="${2:-}"
    local shrink_csv="${3:-}"
    local color_rows="${4:-}"
    local color_column="${5:-0}"
    local -a headers=() widths=() row_lines=() color_lines=() cells=()
    local line i term_width

    IFS=$'\t' read -r -a headers <<< "$headers_tsv"
    [ "${#headers[@]}" -gt 0 ] || return 0

    for i in "${!headers[@]}"; do
        ui_display_width_value "${headers[$i]}"
        widths[$i]="$UI_WIDTH_RESULT"
    done

    if [ -n "$rows" ]; then
        while IFS= read -r line; do
            row_lines+=("$line")
            IFS=$'\t' read -r -a cells <<< "$line"
            for i in "${!headers[@]}"; do
                ui_display_width_value "${cells[$i]:-}"
                if [ "$UI_WIDTH_RESULT" -gt "${widths[$i]}" ]; then
                    widths[$i]="$UI_WIDTH_RESULT"
                fi
            done
        done <<< "$rows"
    fi

    if [ -n "$color_rows" ]; then
        while IFS= read -r line; do
            color_lines+=("$line")
        done <<< "$color_rows"
    fi

    term_width="$(ui_term_width)"
    ui_table_fit_widths widths "$shrink_csv" "$term_width"

    for i in "${!row_lines[@]}"; do
        line="${row_lines[$i]}"
        IFS=$'\t' read -r -a cells <<< "$line"
        ui_compact_table_print_row widths cells "${color_lines[$i]:-}" "$color_column"
    done
}

ui_compact_table_print_row() {
    local widths_name="$1"
    local cells_name="$2"
    local highlight_color="${3:-}"
    local highlight_column="${4:-0}"
    local -n widths_ref="$widths_name"
    local -n cells_ref="$cells_name"
    local i rendered

    for i in "${!widths_ref[@]}"; do
        rendered="$(ui_table_pad_cell "${cells_ref[$i]:-}" "${widths_ref[$i]}")"
        if [ "$i" -gt 0 ]; then
            printf '  '
        fi
        if [ $((i + 1)) -eq "$highlight_column" ] && [ -n "$highlight_color" ] && [ -n "${cells_ref[$i]:-}" ]; then
            ui_color "$highlight_color" "$rendered"
        else
            printf '%s' "$rendered"
        fi
    done
    printf '\n'
}

ui_term_width() {
    local width="${COLUMNS:-}"
    if [ -n "$UI_TERM_WIDTH_CACHE" ]; then
        printf '%s' "$UI_TERM_WIDTH_CACHE"
        return 0
    fi
    if [ -z "$width" ] && [ -t 1 ] && command -v tput >/dev/null 2>&1; then
        width="$(tput cols 2>/dev/null || true)"
    fi
    [[ "$width" =~ ^[0-9]+$ ]] || width=80
    [ "$width" -ge 60 ] || width=60
    UI_TERM_WIDTH_CACHE="$width"
    printf '%s' "$width"
}

ui_repeat_char() {
    local char="$1"
    local count="$2"
    local out=""
    while [ "${#out}" -lt "$count" ]; do
        out="${out}${char}"
    done
    printf '%s' "$out"
}

ui_center_padding() {
    local text="$1"
    local width len pad
    width="$(ui_term_width)"
    len="${#text}"
    if [ "$len" -ge "$width" ]; then
        echo ""
    else
        pad=$(( (width - len) / 2 ))
        printf '%*s' "$pad" ''
    fi
}

ui_center_line() {
    local text="$1"
    local code="${2:-}"
    printf '%s' "$(ui_center_padding "$text")"
    if [ -n "$code" ]; then
        ui_color "$code" "$text"
    else
        printf '%s' "$text"
    fi
    printf '\n'
}

ui_rule() {
    local char="${1:--}"
    local code="${2:-2;37}"
    local width
    width="$(ui_term_width)"
    ui_color "$code" "$(ui_repeat_char "$char" "$width")"
    printf '\n'
}

ui_print_line() {
    local text="$1"
    local code="${2:-}"
    if [ -n "$code" ]; then
        ui_color "$code" "$text"
    else
        printf '%s' "$text"
    fi
    printf '\n'
}

ui_display_width_value() {
    local text="$1"
    local i char char_code width=0
    for ((i = 0; i < ${#text}; i++)); do
        char="${text:i:1}"
        case "$char" in
            $'\n'|$'\r') ;;
            $'\t')
                width=$((width + 4))
                ;;
            *)
                printf -v char_code '%d' "'$char"
                if [ "$char_code" -ge 32 ] && [ "$char_code" -le 126 ]; then
                    width=$((width + 1))
                else
                    width=$((width + 2))
                fi
                ;;
        esac
    done
    UI_WIDTH_RESULT="$width"
}

ui_display_width() {
    ui_display_width_value "$1"
    printf '%s' "$UI_WIDTH_RESULT"
}

ui_table_fit_cell_value() {
    local text="$1"
    local max_width="$2"
    local out="" width=0 i char char_code char_width limit
    UI_TEXT_RESULT=""
    UI_WIDTH_RESULT=0
    [ "$max_width" -gt 0 ] || return 0

    ui_display_width_value "$text"
    if [ "$UI_WIDTH_RESULT" -le "$max_width" ]; then
        UI_TEXT_RESULT="$text"
        return 0
    fi

    if [ "$max_width" -le 3 ]; then
        printf -v UI_TEXT_RESULT '%.*s' "$max_width" "..."
        UI_WIDTH_RESULT="$max_width"
        return 0
    fi

    limit=$((max_width - 3))
    for ((i = 0; i < ${#text}; i++)); do
        char="${text:i:1}"
        case "$char" in
            $'\n'|$'\r')
                char_width=0
                ;;
            $'\t')
                char_width=4
                ;;
            *)
                printf -v char_code '%d' "'$char"
                if [ "$char_code" -ge 32 ] && [ "$char_code" -le 126 ]; then
                    char_width=1
                else
                    char_width=2
                fi
                ;;
        esac
        [ $((width + char_width)) -le "$limit" ] || break
        out+="$char"
        width=$((width + char_width))
    done
    UI_TEXT_RESULT="${out}..."
    UI_WIDTH_RESULT=$((width + 3))
}

ui_table_truncate() {
    ui_table_fit_cell_value "$1" "$2"
    printf '%s' "$UI_TEXT_RESULT"
}

ui_table_pad_cell() {
    local width="$2"
    ui_table_fit_cell_value "$1" "$width"
    printf '%s' "$UI_TEXT_RESULT"
    if [ "$UI_WIDTH_RESULT" -lt "$width" ]; then
        printf '%*s' "$((width - UI_WIDTH_RESULT))" ''
    fi
}

ui_table_total_width_value() {
    local -n widths_ref="$1"
    local total=1 i
    for i in "${!widths_ref[@]}"; do
        total=$((total + widths_ref[$i] + 3))
    done
    UI_WIDTH_RESULT="$total"
}

ui_table_total_width() {
    ui_table_total_width_value "$1"
    printf '%s' "$UI_WIDTH_RESULT"
}

ui_table_reduce_widths() {
    local widths_name="$1"
    local indexes_csv="$2"
    local min_width="$3"
    local term_width="$4"
    local -n widths_ref="$widths_name"
    local -a indexes=()
    local idx pos reduced total

    if [ -n "$indexes_csv" ]; then
        IFS=',' read -r -a indexes <<< "$indexes_csv"
    else
        for pos in "${!widths_ref[@]}"; do
            indexes+=("$((pos + 1))")
        done
    fi

    ui_table_total_width_value "$widths_name"
    total="$UI_WIDTH_RESULT"
    while [ "$total" -gt "$term_width" ]; do
        reduced=false
        for idx in "${indexes[@]}"; do
            [[ "$idx" =~ ^[0-9]+$ ]] || continue
            pos=$((idx - 1))
            [ "$pos" -ge 0 ] || continue
            [ "$pos" -lt "${#widths_ref[@]}" ] || continue
            if [ "${widths_ref[$pos]}" -gt "$min_width" ]; then
                widths_ref[$pos]=$((widths_ref[$pos] - 1))
                total=$((total - 1))
                reduced=true
                [ "$total" -le "$term_width" ] && break
            fi
        done
        [ "$reduced" = "true" ] || break
    done
}

ui_table_fit_widths() {
    local widths_name="$1"
    local shrink_csv="${2:-}"
    local term_width="$3"
    ui_table_reduce_widths "$widths_name" "$shrink_csv" 4 "$term_width"
    ui_table_reduce_widths "$widths_name" "" 4 "$term_width"
    ui_table_reduce_widths "$widths_name" "" 2 "$term_width"
}

ui_table_print_border() {
    local left="$1"
    local middle="$2"
    local right="$3"
    shift 3
    local widths=("$@")
    local line="$left" i
    for i in "${!widths[@]}"; do
        line+="$(ui_repeat_char "─" "$((widths[$i] + 2))")"
        if [ "$i" -lt $((${#widths[@]} - 1)) ]; then
            line+="$middle"
        fi
    done
    line+="$right"
    ui_print_line "$line" "$UI_C_DIM"
}

ui_table_print_row() {
    local widths_name="$1"
    local cells_name="$2"
    local headers_name="$3"
    local code="${4:-}"
    local -n widths_ref="$widths_name"
    local -n cells_ref="$cells_name"
    local -n headers_ref="$headers_name"
    local line="│" i
    for i in "${!widths_ref[@]}"; do
        local cell rendered pad
        cell="${cells_ref[$i]:-}"
        ui_table_fit_cell_value "$cell" "${widths_ref[$i]}"
        rendered="$UI_TEXT_RESULT"
        if [ -z "$code" ] && [ "${headers_ref[$i]:-}" = "状态" ]; then
            UI_CELL_COLOR=""
            local state_stop_at="" display_state stop_idx
            stop_idx=-1
            for stop_idx in "${!headers_ref[@]}"; do
                if [ "${headers_ref[$stop_idx]:-}" = "到期" ]; then
                    state_stop_at="${cells_ref[$stop_idx]:-}"
                    break
                fi
            done
            display_state="$(ui_forward_display_state "$cell" "$state_stop_at")"
            rendered="$(ui_forward_state_text "$display_state")"
            UI_CELL_COLOR="$(ui_forward_state_color "$display_state")"
            ui_display_width_value "$rendered"
            rendered="$(ui_apply_color "$UI_CELL_COLOR" "$rendered")"
        elif [ -z "$code" ] && [ "${headers_ref[$i]:-}" = "值" ] && [ "${headers_ref[0]:-}" = "项目" ]; then
            UI_CELL_COLOR=""
            local guard_label="" guard_state=""
            guard_label="${cells_ref[0]:-}"
            guard_state="$(ui_guard_summary_state "$guard_label" "$cell")"
            if [ -n "$guard_state" ]; then
                rendered="$(ui_forward_state_text "$guard_state")"
                UI_CELL_COLOR="$(ui_forward_state_color "$guard_state")"
                ui_display_width_value "$rendered"
                rendered="$(ui_apply_color "$UI_CELL_COLOR" "$rendered")"
            fi
        fi
        line+=" "
        line+="$rendered"
        if [ "$UI_WIDTH_RESULT" -lt "${widths_ref[$i]}" ]; then
            printf -v pad '%*s' "$((widths_ref[$i] - UI_WIDTH_RESULT))" ''
            line+="$pad"
        fi
        line+=" │"
    done
    if [ -n "$code" ]; then
        ui_print_line "$line" "$code"
    else
        printf '%s\n' "$line"
    fi
}

ui_table_render() {
    local headers_tsv="$1"
    local rows="${2:-}"
    local shrink_csv="${3:-}"
    local -a headers=() widths=() row_lines=() cells=()
    local line i term_width

    IFS=$'\t' read -r -a headers <<< "$headers_tsv"
    [ "${#headers[@]}" -gt 0 ] || return 0

    for i in "${!headers[@]}"; do
        ui_display_width_value "${headers[$i]}"
        widths[$i]="$UI_WIDTH_RESULT"
    done

    if [ -n "$rows" ]; then
        while IFS= read -r line; do
            row_lines+=("$line")
            IFS=$'\t' read -r -a cells <<< "$line"
            for i in "${!headers[@]}"; do
                ui_display_width_value "${cells[$i]:-}"
                if [ "$UI_WIDTH_RESULT" -gt "${widths[$i]}" ]; then
                    widths[$i]="$UI_WIDTH_RESULT"
                fi
            done
        done <<< "$rows"
    fi

    term_width="$(ui_term_width)"
    ui_table_fit_widths widths "$shrink_csv" "$term_width"
    ui_table_print_border "┌" "┬" "┐" "${widths[@]}"
    ui_table_print_row widths headers headers "$UI_C_BRIGHT"
    ui_table_print_border "├" "┼" "┤" "${widths[@]}"
    for line in "${row_lines[@]}"; do
        IFS=$'\t' read -r -a cells <<< "$line"
        ui_table_print_row widths cells headers
    done
    ui_table_print_border "└" "┴" "┘" "${widths[@]}"
}

ui_forward_state_text() {
    case "$1" in
        active|true|启用|已启用) printf '●' ;;
        paused|false|停用|暂停|已停用) printf '◉' ;;
        stopped|停止) printf '○' ;;
        *) printf '○' ;;
    esac
}

ui_forward_state_color() {
    case "$1" in
        active|true|启用|已启用) echo "$UI_C_ACTIVE" ;;
        paused|false|停用|暂停|已停用) echo "$UI_C_PAUSED" ;;
        stopped|停止) echo "$UI_C_STOPPED" ;;
        *) echo "$UI_C_PAUSED" ;;
    esac
}

ui_forward_display_state() {
    local enabled="$1"
    local stop_at="${2:-}"
    local now_minute
    if [ "$enabled" = "true" ] || [ "$enabled" = "启用" ] || [ "$enabled" = "已启用" ] || [ "$enabled" = "active" ]; then
        printf 'active'
        return 0
    fi
    if [ "$enabled" = "false" ] || [ "$enabled" = "停用" ] || [ "$enabled" = "已停用" ] || [ "$enabled" = "暂停" ] || [ "$enabled" = "paused" ]; then
        printf 'paused'
        return 0
    fi
    now_minute="$(pfwd_now_minute)"
    if [ -n "$stop_at" ] && [ "$stop_at" != "-" ] && [ "$stop_at" != "null" ] && [ "$stop_at" \< "$now_minute" -o "$stop_at" = "$now_minute" ]; then
        printf 'stopped'
        return 0
    fi
    printf 'paused'
}

ui_forward_state_cell() {
    local enabled="$1"
    local stop_at="${2:-}"
    local display_state state_text state_color
    display_state="$(ui_forward_display_state "$enabled" "$stop_at")"
    state_text="$(ui_forward_state_text "$display_state")"
    state_color="$(ui_forward_state_color "$display_state")"
    ui_color "$state_color" "$state_text"
}

ui_guard_summary_state() {
    local item="$1"
    local value="$2"
    case "$item" in
        "启用状态")
            case "$value" in
                已启用|启用|开启|开|true|active|●) printf 'active' ;;
                已停用|停用|关闭|关|false|paused|■) printf 'paused' ;;
            esac
            ;;
        "启用白名单"|"包含国内 IP"|"封锁 HTTP"|"封锁 TLS"|"封锁 SOCKS")
            case "$value" in
                开|开启|启用|已启用|true|active|●) printf 'active' ;;
                关|关闭|停用|已停用|false|paused|■) printf 'paused' ;;
            esac
            ;;
    esac
}

ui_guard_summary_rows() {
    local rows line item value guard_state
    rows="$(guard_render_status)"
    while IFS=$'\t' read -r item value; do
        [ -n "$item" ] || continue
        guard_state="$(ui_guard_summary_state "$item" "$value")"
        if [ -n "$guard_state" ]; then
            value="$(ui_forward_state_text "$guard_state")"
        fi
        printf '%s\t%s\n' "$item" "$value"
    done <<< "$rows"
}

ui_whitelist_summary_rows() {
    whitelist_render_status
}

ui_forward_line() {
    local enabled="$1"
    local body="$2"
    local stop_at="${3:-}"
    local display_state state_text state_color
    display_state="$(ui_forward_display_state "$enabled" "$stop_at")"
    state_text="$(ui_forward_state_text "$display_state")"
    state_color="$(ui_forward_state_color "$display_state")"
    ui_color "$state_color" "$state_text"
    printf ' %s\n' "$body"
}

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

ui_title() {
    local guard_status=""
    if command -v guard_enabled >/dev/null 2>&1; then
        if [ "$(guard_enabled)" = "true" ]; then
            guard_status="guard: $(jq -r '.forwarding_backend // "none"' <<< "$(forwarder_status_json 2>/dev/null || echo '{}')")"
        else
            guard_status="guard: off"
        fi
    fi
    local user_count forward_count
    user_count="$(jq '.users | length' "$PFWD_CONFIG_FILE" 2>/dev/null || echo "?")"
    forward_count="$(jq '[.forwards[] | select(.enabled == true)] | length' "$PFWD_CONFIG_FILE" 2>/dev/null || echo "?")"
    printf '\n'
    ui_color "$UI_C_TITLE" "pfwd v${PFWD_VERSION:-}"
    printf '  '
    ui_color "$UI_C_DIM" "用户: $user_count  转发: $forward_count"
    if [ -n "$guard_status" ]; then
        printf '  '
        ui_color "$UI_C_DIM_CYAN" "$guard_status"
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
    if [ -n "$UI_FORM_TITLE" ]; then
        ui_form_refresh
    fi
    ui_read "$prompt" "$default"
}

ui_form_edit_read() {
    local prompt="$1"
    local default="${2:-}"
    if [ -n "$UI_FORM_TITLE" ]; then
        ui_form_refresh
    fi
    ui_edit_read "$prompt" "$default"
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

ui_run_capture() {
    local output="" status=0
    if [ "${PFWD_DRY_RUN:-0}" = "1" ] && [ "$UI_ALT_SCREEN_ACTIVE" = "1" ]; then
        ui_dry_run_reset
    fi
    UI_REPLY=""
    output="$("$@" 2>&1)" || status=$?
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
            [ -n "$UI_REPLY" ] || pfwd_die "固定 MSS 模式必须提供 MSS 值"
            validate_mss_value "$UI_REPLY"
            UI_MSS_VALUE="$UI_REPLY"
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
            [ -n "$UI_REPLY" ] || pfwd_die "固定 SNAT 模式必须提供源地址"
            validate_ip_literal "$UI_REPLY"
            UI_SNAT_SOURCE="$UI_REPLY"
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

ui_config_value() {
    local filter="$1"
    config_init >/dev/null
    jq -r "$filter" "$PFWD_CONFIG_FILE"
}

ui_format_remote() {
    local host="$1"
    local port="$2"
    if [[ "$host" == *:* ]]; then
        printf '[%s]:%s' "$host" "$port"
    else
        printf '%s:%s' "$host" "$port"
    fi
}

ui_format_listen() {
    ui_format_remote "$1" "$2"
}

ui_format_listen_compact() {
    local host="$1"
    local port="$2"
    case "$host" in
        ""|"::"|"0.0.0.0") printf '%s' "$port" ;;
        *) ui_format_listen "$host" "$port" ;;
    esac
}

ui_join_remote() {
    local host="$1"
    local port="$2"
    ui_format_remote "$host" "$port"
}

ui_protocol_label() {
    case "${1:-tcp_udp}" in
        tcp) echo "TCP" ;;
        udp) echo "UDP" ;;
        *) echo "TCP+UDP" ;;
    esac
}

ui_select_protocol() {
    local prompt="$1"
    local current_protocol="${2:-tcp_udp}"
    local allow_clear="${3:-false}"
    UI_EDIT_ABORTED=0
    UI_REPLY=""
    case "$current_protocol" in
        tcp) ui_form_select_read "$prompt" "1" "1) TCP" "2) UDP" "3) TCP+UDP" || return 1 ;;
        udp) ui_form_select_read "$prompt" "2" "1) TCP" "2) UDP" "3) TCP+UDP" || return 1 ;;
        *) ui_form_select_read "$prompt" "3" "1) TCP" "2) UDP" "3) TCP+UDP" || return 1 ;;
    esac
    case "$UI_REPLY" in
        0)
            if [ "$allow_clear" = "true" ]; then
                UI_EDIT_ABORTED=1
                return 0
            fi
            ui_warn "无效选择，已使用 TCP+UDP"
            UI_REPLY="tcp_udp"
            ;;
        "")
            if [ "$allow_clear" = "true" ]; then
                UI_REPLY=""
            else
                UI_REPLY="tcp_udp"
            fi
            ;;
        1) UI_REPLY="tcp" ;;
        2) UI_REPLY="udp" ;;
        3) UI_REPLY="tcp_udp" ;;
        *) ui_warn "无效选择，已使用 TCP+UDP"; UI_REPLY="tcp_udp" ;;
    esac
}

ui_select_protocol_edit() {
    ui_select_protocol "$1" "${2:-tcp_udp}" true
}

ui_select_traffic_mode() {
    local prompt="$1"
    local allow_empty="${2:-false}"
    local current_mode="${3:-}"
    local allow_clear="${4:-false}"
    UI_TRAFFIC_MODE=""
    UI_EDIT_ABORTED=0
    case "$current_mode" in
        one-way) ui_form_select_read "$prompt" "1" "1) 单向计费" "   按 (上行+下行) x 倍率 计费；适合一倍总流量结算。" "2) 双向计费" "   按 (上行+下行) x 倍率 x 2 计费；适合双倍流量结算。" || return 1 ;;
        two-way) ui_form_select_read "$prompt" "2" "1) 单向计费" "   按 (上行+下行) x 倍率 计费；适合一倍总流量结算。" "2) 双向计费" "   按 (上行+下行) x 倍率 x 2 计费；适合双倍流量结算。" || return 1 ;;
        *) ui_form_select_read "$prompt" "2" "1) 单向计费" "   按 (上行+下行) x 倍率 计费；适合一倍总流量结算。" "2) 双向计费" "   按 (上行+下行) x 倍率 x 2 计费；适合双倍流量结算。" || return 1 ;;
    esac
    if [ "$allow_clear" = "true" ] && [ "$UI_REPLY" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi
    if [ -z "$UI_REPLY" ]; then
        if [ "$allow_clear" = "true" ] || [ "$allow_empty" = "true" ]; then
            UI_TRAFFIC_MODE=""
        else
            UI_TRAFFIC_MODE="two-way"
        fi
        return 0
    fi
    case "$UI_REPLY" in
        1) UI_TRAFFIC_MODE="one-way" ;;
        2) UI_TRAFFIC_MODE="two-way" ;;
        *) ui_warn "无效选择，已使用双向"; UI_TRAFFIC_MODE="two-way" ;;
    esac
}

ui_select_traffic_mode_edit() {
    ui_select_traffic_mode "$1" false "${2:-}" true
}

ui_read_traffic_ratio() {
    local prompt="$1"
    local default="${2:-1.0}"
    local allow_clear="${3:-false}"
    UI_TRAFFIC_RATIO=""
    UI_EDIT_ABORTED=0
    if [ "$allow_clear" = "true" ]; then
        ui_form_edit_read "$prompt" "$default" || return 1
        [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    else
        ui_form_read "$prompt" "$default" || return 1
    fi
    UI_TRAFFIC_RATIO="$(normalize_traffic_ratio_input "$UI_REPLY")"
}

ui_read_traffic_ratio_edit() {
    ui_read_traffic_ratio "$1" "${2:-1.0}" true
}

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

ui_format_bytes_or_dash() {
    local value="$1"
    if [ "$value" = "-" ] || [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "-"
    else
        format_bytes "$value"
    fi
}

ui_display_or_dash() {
    local value="$1"
    case "$value" in
        ""|"-"|"null"|"不限"|"不自动重置"|"未设置") echo "-" ;;
        *) echo "$value" ;;
    esac
}

ui_progress_bar() {
    local used="$1" limit="$2" width="${3:-10}"
    local pct i bar=""
    if [ "$limit" = "null" ] || [ -z "$limit" ] || [ "$limit" = "0" ] || [ "$limit" = "-" ]; then
        printf '[%s]' "$(printf '%*s' "$width" '' | tr ' ' '-')"
        return
    fi
    pct=$((used * 100 / limit))
    [ "$pct" -le 100 ] || pct=100
    local filled=$((pct * width / 100))
    for ((i = 0; i < width; i++)); do
        if [ "$i" -lt "$filled" ]; then
            bar+="="
        else
            bar+="-"
        fi
    done
    printf '[%s] %d%%' "$bar" "$pct"
}

ui_format_limit() {
    local value="$1"
    if [ "$value" = "-" ] || [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "-"
    else
        format_bytes "$value"
    fi
}

ui_format_rate() {
    local value="$1"
    if [ "$value" = "-" ] || [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "-"
    else
        echo "$value"
    fi
}

ui_format_reset_day() {
    local value="$1"
    reset_day_display "$value"
}

ui_main_usage_json() {
    ui_cached_data "main_usage_json" fw_read_counters
}

ui_forward_usage_json() {
    ui_main_usage_json
}

ui_load_user_config_tsv() {
    jq -r --arg id "$1" '
      .users[]? | select(.id == $id) |
      [
        (.limits.traffic_bytes // "null"),
        (.limits.rate // "null"),
        ([.id] | .[0])
      ] | @tsv
    ' "$PFWD_CONFIG_FILE"
}

ui_user_forward_count() {
    jq -r --arg id "$1" '[.forwards[]? | select(.user_id == $id)] | length' "$PFWD_CONFIG_FILE"
}

ui_main_user_rows() {
    local data="$1"
    jq -r --slurpfile cfg "$PFWD_CONFIG_FILE" '
      .users[]? as $u
      | ($cfg[0].forwards | map(select(.user_id == $u.id)) | length) as $count
      | [
          $u.id,
          ($count | tostring),
          (($u.billing_used_bytes // 0) | tostring),
          (($u.two_way_bytes // 0) | tostring),
          (($u.one_way_bytes // 0) | tostring),
          (($u.limits.traffic_bytes // "null") | tostring),
          (($u.reset_day // "-") | tostring)
        ]
      | @tsv
    ' <<< "$data"
}

ui_main_forward_rows() {
    local data="$1"
    jq -r '
      . as $data
      | .forwards
      | sort_by(.user_id, .listen_port, .id)
      | .[]?
      | . as $forward
      | (($data.users | map(select(.id == $forward.user_id)) | .[0].limits.rate) // null) as $user_rate
      | [
          (if $forward.enabled then "true" else "false" end),
          $forward.user_id,
          ($forward.listen_ip // "::"),
          ($forward.listen_port | tostring),
          $forward.remote_host,
          ($forward.remote_port | tostring),
          ($forward.input_bytes // "0"),
          ($forward.output_bytes // "0"),
          ($forward.stop_at // "-"),
          (($forward.traffic_ratio // 1) | tostring),
          (($forward.limits.rate // $user_rate) // "null"),
          (if ($forward.comment // "") == "" then "-" else $forward.comment end)
        ]
      | @tsv
    ' <<< "$data"
}

ui_user_list_rows() {
    local allow_zero="${1:-false}"
    local rows=""
    local index=1
    local user_id
    if [ "$allow_zero" = "true" ]; then
        rows+=$'0\t返回\n'
    fi
    while IFS= read -r user_id; do
        rows+="$index"$'\t'"$user_id"$'\n'
        index=$((index + 1))
    done < <(jq -r '.users[]?.id' "$PFWD_CONFIG_FILE")
    printf '%s' "${rows%$'\n'}"
}

ui_forward_list_rows() {
    local rows=""
    while IFS=$'\t' read -r index user enabled listen_ip listen_port remote_host remote_port protocol stop_at mode ratio mss_display snat_display comment; do
        local listen remote
        listen="$(ui_format_listen_compact "$listen_ip" "$listen_port")"
        remote="$(ui_format_remote "$remote_host" "$remote_port")"
        rows+="$index"$'\t'"$user"$'\t'"$listen"$'\t'"$remote"$'\t'"$(ui_protocol_label "$protocol")"$'\t'"$enabled"$'\t'"$stop_at"$'\t'"$mode"$'\t'"$(format_ratio "$ratio")"$'\t'"$mss_display"$'\t'"$snat_display"$'\t'"$(ui_display_or_dash "$comment")"$'\n'
    done < <(jq -r '
      (.forwards | sort_by(.user_id, .listen_port, .id))
      | to_entries[]
      | [
          ((.key + 1) | tostring),
          .value.user_id,
          (if .value.enabled then "启用" else "停用" end),
          (.value.listen_ip // "::"),
          (.value.listen_port | tostring),
          .value.remote_host,
          (.value.remote_port | tostring),
          (.value.protocol // "tcp_udp"),
          (.value.stop_at // "-"),
          (if (.value.traffic_mode // "two-way") == "one-way" then "单向" else "双向" end),
          ((.value.traffic_ratio // 1) | tostring),
          (
            if (.value.net.mss_mode // "") == "set" then
              ((.value.net.mss_value // "-") | tostring)
            elif (.value.net.mss_mode // "") == "clamp" then
              "clamp"
            else
              "-"
            end
          ),
          (
            if (.value.net.snat_mode // "masquerade") == "snat" and (.value.net.snat_source // "") != "" then
              .value.net.snat_source
            else
              "masquerade"
            end
          ),
          (if (.value.comment // "") == "" then "-" else .value.comment end)
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE")
    printf '%s' "${rows%$'\n'}"
}

ui_telegram_configured_user_rows() {
    jq -r '
      .users[]?
      | select((.telegram.bot_token // "") != "" and (.telegram.chat_id // "") != "")
      | [
          .id,
          (if (.telegram.enabled // false) then "已启用" else "已停用" end),
          (
            [
              (if (.telegram.schedule_interval_minutes // null) == null
               then "间隔 -"
               else "间隔 " + ((.telegram.schedule_interval_minutes | tostring) + "m")
               end),
              (if (.telegram.schedule_daily_time // null) == null
               then "每日 -"
               else "每日 " + .telegram.schedule_daily_time
               end)
            ] | join(" | ")
          )
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE"
}

ui_forward_select_rows() {
    local allow_zero="${1:-false}"
    local rows=""
    if [ "$allow_zero" = "true" ]; then
        rows+=$'0\t返回\t-\t-\t-\t-\t-\n'
    fi
    while IFS=$'\t' read -r index user listen_port remote_host remote_port protocol enabled stop_at; do
        local remote_text
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        rows+="$index"$'\t'"$user"$'\t'"$listen_port"$'\t'"$remote_text"$'\t'"$(ui_protocol_label "$protocol")"$'\t'"$enabled"$'\t'"$stop_at"$'\n'
    done < <(jq -r '
      (.forwards | sort_by(.user_id, .listen_port, .id))
      | to_entries[]
      | [
          ((.key + 1) | tostring),
          .value.user_id,
          (.value.listen_port | tostring),
          .value.remote_host,
          (.value.remote_port | tostring),
          (.value.protocol // "tcp_udp"),
          (if .value.enabled then "启用" else "停用" end),
          (.value.stop_at // "-")
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE")
    printf '%s' "${rows%$'\n'}"
}

ui_user_forward_select_rows() {
    local user_id="$1"
    local allow_zero="${2:-false}"
    local include_all="${3:-false}"
    local rows=""
    if [ "$allow_zero" = "true" ]; then
        rows+=$'0\t返回\t-\t-\t-\t-\n'
    fi
    if [ "$include_all" = "true" ]; then
        rows+=$'1\t全部端口\t-\t-\t-\t-\n'
    fi
    while IFS=$'\t' read -r index listen_port remote_host remote_port protocol enabled stop_at; do
        local remote_text
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        rows+="$index"$'\t'"$listen_port"$'\t'"$remote_text"$'\t'"$(ui_protocol_label "$protocol")"$'\t'"$enabled"$'\t'"$stop_at"$'\n'
    done < <(jq -r --arg id "$user_id" --argjson start_index "$( [ "$include_all" = "true" ] && echo 2 || echo 1 )" '
      ([.forwards[] | select(.user_id == $id)] | sort_by(.listen_port, .id))
      | to_entries[]
      | [
          ((.key + $start_index) | tostring),
          (.value.listen_port | tostring),
          .value.remote_host,
          (.value.remote_port | tostring),
          (.value.protocol // "tcp_udp"),
          (if .value.enabled then "启用" else "停用" end),
          (.value.stop_at // "-")
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE")
    printf '%s' "${rows%$'\n'}"
}

ui_user_delete_forward_rows() {
    local user_id="$1"
    local rows=""
    local listen_port remote_host remote_port protocol enabled stop_at remote_text state_text
    while IFS=$'\t' read -r listen_port remote_host remote_port protocol enabled stop_at; do
        [ -n "$listen_port" ] || continue
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        state_text="$(ui_forward_state_text "$(ui_forward_display_state "$enabled" "$stop_at")")"
        rows+="$listen_port"$'\t'"$remote_text"$'\t'"$(ui_protocol_label "$protocol")"$'\t'"$state_text"$'\n'
    done < <(config_user_forward_summary_tsv "$user_id")
    printf '%s' "${rows%$'\n'}"
}

ui_print_user_delete_preview() {
    local user_ids="$1"
    local has_forwards="false"
    local user_id count

    ui_print_line "将删除以下用户：" "$UI_C_WARN"
    while IFS= read -r user_id; do
        [ -n "$user_id" ] || continue
        printf '%s\n' "$user_id"
    done <<< "$user_ids"

    while IFS= read -r user_id; do
        [ -n "$user_id" ] || continue
        count="$(config_user_forward_count "$user_id")"
        [ "$count" -gt 0 ] || continue
        has_forwards="true"
        printf '\n'
        ui_print_line "用户：$user_id（以下转发将一并删除）" "$UI_C_WARN"
        ui_table_render $'监听\t目标\t协议\t状态' "$(ui_user_delete_forward_rows "$user_id")" "2,4"
    done <<< "$user_ids"

    if [ "$has_forwards" = "true" ]; then
        printf '\n'
        ui_print_line "以上关联转发会随用户一起删除。" "$UI_C_WARN"
    fi

    UI_REPLY="$has_forwards"
}

ui_print_user_traffic_summary() {
    local user_id="$1"
    local data total_limit used one_way two_way reset_day forward_count rate rows="" config_tsv=""
    data="$(ui_main_usage_json)"
    config_tsv="$(ui_load_user_config_tsv "$user_id")"
    total_limit="${config_tsv%%$'\t'*}"
    config_tsv="${config_tsv#*$'\t'}"
    rate="${config_tsv%%$'\t'*}"
    used="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .billing_used_bytes // 0' <<< "$data")"
    one_way="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .one_way_bytes // 0' <<< "$data")"
    two_way="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .two_way_bytes // 0' <<< "$data")"
    reset_day="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .reset_day // "-"' <<< "$data")"
    forward_count="$(ui_user_forward_count "$user_id")"
    rows+="用户名"$'\t'"$user_id"$'\n'
    rows+="转发数"$'\t'"${forward_count} 个"$'\n'
    rows+="重置日"$'\t'"$(ui_format_reset_day "$reset_day")"$'\n'
    rows+="总限额"$'\t'"$(ui_format_limit "$total_limit")"$'\n'
    rows+="每端口速率"$'\t'"$(ui_format_rate "$rate")"$'\n'
    rows+="计费用量"$'\t'"$(format_bytes "$used")"$'\n'
    rows+="双向计费"$'\t'"$(format_bytes "$two_way")"$'\n'
    rows+="单向计费"$'\t'"$(format_bytes "$one_way")"
    ui_table_render $'项目\t值' "$rows" "2"
}

ui_print_main_user_summary() {
    local data="$1"
    local rows=""
    ui_print_line "用户状态" "$UI_C_HEADER"

    if ! jq -e '.users | length > 0' <<< "$data" >/dev/null; then
        ui_print_line "$(ui_empty_users_text)"
        return
    fi

    while IFS=$'\t' read -r user count used two_way one_way limit reset_day; do
        rows+="$user"$'\t'"$count"$'\t'"$(format_bytes "$used")"$'\t'"$(ui_progress_bar "$used" "$limit")"$'\t'"$(format_bytes "$two_way")"$'\t'"$(format_bytes "$one_way")"$'\t'"$(ui_format_limit "$limit")"$'\t'"$(ui_format_reset_day "$reset_day")"$'\n'
    done < <(ui_main_user_rows "$data")
    rows="${rows%$'\n'}"
    ui_table_render $'用户名\t转发数\t计费用量\t用量进度\t双向计费\t单向计费\t总限额\t重置日' "$rows" "1,6,7"
}

ui_render_forward_groups() {
    local rows="$1"
    local headers_tsv="$2"
    local empty_text="$4"
    local current_user="" line user first_group=true
    local enabled="" col3="" col4="" col5="" col6="" col7="" col8="" col9="" col10="" col11="" col12=""
    local group_rows="" group_headers="" group_shrink="" row_buffer=""

    if [ -z "$rows" ]; then
        ui_print_line "$empty_text"
        return 0
    fi

    ui_render_forward_group_block() {
        local block_user="$1"
        local block_rows="$2"
        local block_headers="$3"
        local block_shrink="$4"
        local block_line="" block_enabled="" block_user_id=""
        local block_col3="" block_col4="" block_col5="" block_col6="" block_col7="" block_col8="" block_col9="" block_col10="" block_col11="" block_col12=""
        local block_display_state=""
        local render_rows=""

        [ -n "$block_rows" ] || return 0
        ui_print_line "用户：$block_user" "$UI_C_HEADER"
        while IFS= read -r block_line; do
            [ -n "$block_line" ] || continue
            IFS=$'\t' read -r block_enabled block_user_id block_col3 block_col4 block_col5 block_col6 block_col7 block_col8 block_col9 block_col10 block_col11 block_col12 <<< "$block_line"
            case "$headers_tsv" in
                $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t备注')
                    render_rows+="$block_enabled"$'\t'"$block_col3"$'\t'"$block_col4"$'\t'"$block_col5"$'\t'"$block_col6"$'\t'"$block_col7"$'\t'"$(format_ratio "$block_col8")"$'\t'"$(ui_display_or_dash "$block_col9")"$'\n'
                    ;;
                $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注')
                    render_rows+="$block_enabled"$'\t'"$block_col3"$'\t'"$block_col4"$'\t'"$block_col5"$'\t'"$block_col6"$'\t'"$block_col7"$'\t'"$(format_ratio "$block_col8")"$'\t'"$(ui_format_rate "$block_col9")"$'\t'"$(ui_display_or_dash "$block_col10")"$'\n'
                    ;;
                $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\t倍率\tMSS\tSNAT\t备注')
                    render_rows+="#$block_enabled"$'\t'"$block_col6"$'\t'"$block_col3"$'\t'"$block_col4"$'\t'"$block_col5"$'\t'"$block_col7"$'\t'"$block_col8"$'\t'"$(format_ratio "$block_col9")"$'\t'"$block_col10"$'\t'"$block_col11"$'\t'"$(ui_display_or_dash "$block_col12")"$'\n'
                    ;;
                $'序号\t用户\t监听\t目标\t协议\t状态\t到期')
                    render_rows+="#$block_enabled"$'\t'"$block_col6"$'\t'"$block_col3"$'\t'"$block_col4"$'\t'"$block_col5"$'\t'"$block_col7"$'\n'
                    ;;
                *)
                    ui_forward_line "$block_enabled" "$block_line" "$col7"
                    continue
                    ;;
            esac
        done <<< "$block_rows"
        render_rows="${render_rows%$'\n'}"
        ui_table_render "$block_headers" "$render_rows" "$block_shrink"
    }

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        IFS=$'\t' read -r _ user _ <<< "$line"
        if [ -z "$current_user" ] || [ "$user" != "$current_user" ]; then
            if [ "$first_group" = "false" ]; then
                case "$headers_tsv" in
                    $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t备注')
                        group_headers=$'状态\t监听\t目标\t上行\t下行\t到期\t倍率\t备注'
                        group_shrink="2,3,4,5,6,7,8"
                        ;;
                    $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注')
                        group_headers=$'状态\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注'
                        group_shrink="2,3,4,5,6,7,8,9"
                        ;;
                    $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\t倍率\tMSS\tSNAT\t备注')
                        group_headers=$'序号\t状态\t监听\t目标\t协议\t到期\t模式\t倍率\tMSS\tSNAT\t备注'
                        group_shrink="3,4,6,7,8,9,10,11"
                        ;;
                    $'序号\t用户\t监听\t目标\t协议\t状态\t到期')
                        group_headers=$'序号\t状态\t监听\t目标\t协议\t到期'
                        group_shrink="3,4,6"
                        ;;
                    *)
                        group_headers=""
                        group_shrink=""
                        ;;
                esac
                ui_render_forward_group_block "$current_user" "$group_rows" "$group_headers" "$group_shrink"
                printf '\n'
            fi
            current_user="$user"
            first_group=false
            group_rows=""
        fi
        group_rows+="$line"$'\n'
    done <<< "$rows"

    group_rows="${group_rows%$'\n'}"
    case "$headers_tsv" in
        $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t备注')
            group_headers=$'状态\t监听\t目标\t上行\t下行\t到期\t倍率\t备注'
            group_shrink="2,3,4,5,6,7,8"
            ;;
        $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注')
            group_headers=$'状态\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注'
            group_shrink="2,3,4,5,6,7,8,9"
            ;;
        $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\t倍率\tMSS\tSNAT\t备注')
            group_headers=$'序号\t状态\t监听\t目标\t协议\t到期\t模式\t倍率\tMSS\tSNAT\t备注'
            group_shrink="3,4,6,7,8,9,10,11"
            ;;
        $'序号\t用户\t监听\t目标\t协议\t状态\t到期')
            group_headers=$'序号\t状态\t监听\t目标\t协议\t到期'
            group_shrink="3,4,6"
            ;;
        *)
            group_headers=""
            group_shrink=""
            ;;
    esac
    ui_render_forward_group_block "$current_user" "$group_rows" "$group_headers" "$group_shrink"
}

ui_print_main_forward_summary() {
    local data="$1"
    local rows=""
    ui_print_line "当前转发" "$UI_C_HEADER"

    if ! jq -e '.forwards | length > 0' <<< "$data" >/dev/null; then
        ui_print_line "$(ui_empty_forwards_text)"
        return
    fi

    while IFS=$'\t' read -r enabled user listen_ip listen_port remote_host remote_port input_bytes output_bytes stop_at ratio rate comment; do
        local remote_text listen_text
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        listen_text="$(ui_format_listen_compact "$listen_ip" "$listen_port")"
        rows+="$enabled"$'\t'"$user"$'\t'"$listen_text"$'\t'"$remote_text"$'\t'"$(ui_format_bytes_or_dash "$input_bytes")"$'\t'"$(ui_format_bytes_or_dash "$output_bytes")"$'\t'"$(ui_display_or_dash "$stop_at")"$'\t'"$(format_ratio "$ratio")"$'\t'"$(ui_format_rate "$rate")"$'\t'"$(ui_display_or_dash "$comment")"$'\n'
    done < <(ui_main_forward_rows "$data")
    rows="${rows%$'\n'}"
    ui_render_forward_groups "$rows" $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t倍率\t限速\t备注' "4,10,2,7,3" "$(ui_empty_forwards_text)"
}

ui_print_main_forwards() {
    config_init >/dev/null
    config_snapshot_load
    local data
    data="$(ui_main_usage_json)"
    ui_print_main_user_summary "$data"
    ui_rule "-" "$UI_C_DIM"
    ui_print_main_forward_summary "$data"
    ui_rule "-" "$UI_C_DIM"
}

ui_print_forward_list() {
    config_init >/dev/null
    if ! jq -e '.forwards | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_empty_forwards_text
        return
    fi
    ui_render_forward_groups "$(ui_forward_list_rows)" $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\t倍率\tMSS\tSNAT\t备注' "4,12,2,7,8,10,3" "$(ui_empty_forwards_text)"
}

ui_print_user_list() {
    local allow_zero="${1:-false}"
    config_init >/dev/null
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_empty_users_text
        return
    fi
    ui_table_render $'序号\t用户名' "$(ui_user_list_rows "$allow_zero")" "2"
}

ui_select_user() {
    local allow_zero="${1:-false}"
    UI_EDIT_ABORTED=0
    config_init >/dev/null
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_users_text)"
        return 1
    fi
    ui_render_page ui_render_user_select_page "$allow_zero"
    ui_read "选择用户序号" || return 1
    if [ "$allow_zero" = "true" ] && [ "$UI_REPLY" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi
    [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; return 1; }
    local user_id
    user_id="$(jq -r --argjson idx "$UI_REPLY" '.users[$idx - 1].id // ""' "$PFWD_CONFIG_FILE")"
    [ -n "$user_id" ] || { ui_warn "用户序号不存在"; return 1; }
    UI_REPLY="$user_id"
}

ui_render_user_select_page() {
    local allow_zero="${1:-false}"
    ui_header "选择用户"
    ui_notice_render
    ui_print_user_list "$allow_zero"
}

ui_select_user_for_telegram_config() {
    config_init >/dev/null
    local rows=$'0\t返回\n1\t所有用户'
    local index=2 user_id
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_users_text)"
        return 1
    fi
    while IFS= read -r user_id; do
        rows+=$'\n'"$index"$'\t'"$user_id"
        index=$((index + 1))
    done < <(jq -r '.users[]?.id' "$PFWD_CONFIG_FILE")
    ui_render_page ui_render_telegram_user_select_page "$rows"
    ui_read "选择用户序号" || return 1
    [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; return 1; }
    case "$UI_REPLY" in
        0)
            UI_EDIT_ABORTED=1
            return 0
            ;;
        1)
            UI_REPLY="__ALL_USERS__"
            return 0
            ;;
    esac
    local user_id
    user_id="$(jq -r --argjson idx "$UI_REPLY" '.users[$idx - 2].id // ""' "$PFWD_CONFIG_FILE")"
    [ -n "$user_id" ] || { ui_warn "用户序号不存在"; return 1; }
    UI_REPLY="$user_id"
}

ui_select_users_for_telegram_config_multi() {
    config_init >/dev/null
    UI_EDIT_ABORTED=0
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_users_text)"
        return 1
    fi
    local rows=$'0\t返回\n1\t所有用户'
    local user_count index raw indexes selected_count user_ids
    local user_id
    user_count="$(jq '.users | length' "$PFWD_CONFIG_FILE")"
    index=2
    while IFS= read -r user_id; do
        rows+=$'\n'"$index"$'\t'"$user_id"
        index=$((index + 1))
    done < <(jq -r '.users[]?.id' "$PFWD_CONFIG_FILE")

    ui_render_page ui_render_telegram_user_select_page_config "$rows"
    ui_read "选择用户序号，可多选：2,4,6 或 2-5；1 表示所有用户" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$((user_count + 1))" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    selected_count="$(printf '%s\n' "$indexes" | sed '/^$/d' | wc -l | tr -d ' ')"
    if printf '%s\n' "$indexes" | grep -qx '1'; then
        [ "$selected_count" = "1" ] || { ui_warn "“所有用户”只能单独选择"; return 1; }
        UI_REPLY="__ALL_USERS__"
        return 0
    fi
    user_ids="$(jq -r --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      [ .users[]?.id ] as $ids
      | $idxs[]
      | $ids[. - 2] // empty
    ' "$PFWD_CONFIG_FILE")"
    [ -n "$user_ids" ] || { ui_warn "用户序号不存在"; return 1; }
    UI_REPLY="$user_ids"
}

ui_render_telegram_user_select_page() {
    local rows="$1"
    ui_header "选择用户"
    ui_notice_render
    ui_table_render $'序号\t用户' "$rows" "2"
}

ui_render_telegram_user_select_page_config() {
    local rows="$1"
    ui_header "选择用户"
    ui_notice_render
    ui_print_line "1 表示所有用户；也支持多选具体用户。" "$UI_C_ACCENT"
    ui_table_render $'序号\t用户' "$rows" "2"
}

ui_telegram_configured_user_select_rows() {
    local rows=""
    local index=1 user status schedule
    while IFS=$'\t' read -r user status schedule; do
        [ -n "$user" ] || continue
        rows+="$index"$'\t'"$user"$'\t'"$status"$'\t'"$schedule"$'\n'
        index=$((index + 1))
    done < <(ui_telegram_configured_user_rows)
    printf '%s' "${rows%$'\n'}"
}

ui_render_telegram_user_select_page_configured() {
    local rows="$1"
    local empty="${2:-false}"
    ui_header "选择已配置用户"
    ui_notice_render
    if [ "$empty" = "true" ]; then
        ui_warn "暂无已配置用户，请先配置 Telegram。"
        ui_table_render $'序号\t操作' "$rows" "2"
    else
        ui_print_line "支持多选：1,3,5 或 1-3" "$UI_C_ACCENT"
        ui_table_render $'序号\t用户\t状态\t定时发送' "$rows" "2,4"
    fi
}

ui_select_configured_users_multi() {
    config_init >/dev/null
    UI_EDIT_ABORTED=0
    local configured_count rows raw indexes user_ids
    configured_count="$(jq '[.users[]? | select((.telegram.bot_token // "") != "" and (.telegram.chat_id // "") != "")] | length' "$PFWD_CONFIG_FILE")"
    if [ "$configured_count" -eq 0 ]; then
        rows=$'0\t返回'
        ui_render_page ui_render_telegram_user_select_page_configured "$rows" "true"
        ui_read "选择 0 返回" || return 1
        if [ "$UI_REPLY" = "0" ]; then
            UI_EDIT_ABORTED=1
            return 0
        fi
        ui_warn "暂无已配置用户，请先配置 Telegram。"
        return 1
    fi

    rows="$(ui_telegram_configured_user_select_rows)"
    ui_render_page ui_render_telegram_user_select_page_configured "$rows" "false"
    ui_read "选择已配置用户序号，可多选：1,3,5 或 1-3" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$configured_count" true || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    user_ids="$(jq -r --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      [
        .users[]?
        | select((.telegram.bot_token // "") != "" and (.telegram.chat_id // "") != "")
        | .id
      ] as $ids
      | $idxs[]
      | $ids[. - 1] // empty
    ' "$PFWD_CONFIG_FILE")"
    [ -n "$user_ids" ] || { ui_warn "用户序号不存在"; return 1; }
    UI_REPLY="$user_ids"
}

ui_multiselect_normalize_tokens() {
    local raw="$1"
    raw="${raw// /}"
    raw="${raw#,}"
    raw="${raw%,}"
    printf '%s' "$raw"
}

ui_multiselect_parse_indexes() {
    local raw="$1"
    local max_index="$2"
    local allow_zero="${3:-false}"
    local normalized token start end value
    local -A seen=()
    local values=()

    UI_EDIT_ABORTED=0
    UI_REPLY=""
    normalized="$(ui_multiselect_normalize_tokens "$raw")"
    [ -n "$normalized" ] || { ui_warn "请选择至少一个序号"; return 1; }

    if [ "$allow_zero" = "true" ] && [ "$normalized" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi

    while IFS= read -r token; do
        [ -n "$token" ] || { ui_warn "多选格式无效"; return 1; }
        if [[ "$token" =~ ^[0-9]+$ ]]; then
            value="$token"
            if [ "$allow_zero" = "true" ] && [ "$value" = "0" ]; then
                ui_warn "0 只能单独输入表示返回"
                return 1
            fi
            if [ "$value" -lt 1 ] || [ "$value" -gt "$max_index" ]; then
                ui_warn "序号超出范围：$value"
                return 1
            fi
            seen["$value"]=1
        elif [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start="${BASH_REMATCH[1]}"
            end="${BASH_REMATCH[2]}"
            if [ "$start" -gt "$end" ]; then
                ui_warn "范围无效：$token"
                return 1
            fi
            if [ "$start" -lt 1 ] || [ "$end" -gt "$max_index" ]; then
                ui_warn "序号超出范围：$token"
                return 1
            fi
            for ((value = start; value <= end; value++)); do
                seen["$value"]=1
            done
        else
            ui_warn "多选格式无效：$token"
            return 1
        fi
    done < <(printf '%s\n' "$normalized" | tr ',' '\n')

    for ((value = 1; value <= max_index; value++)); do
        if [ -n "${seen[$value]:-}" ]; then
            values+=("$value")
        fi
    done
    [ "${#values[@]}" -gt 0 ] || { ui_warn "请选择至少一个序号"; return 1; }
    UI_REPLY="$(printf '%s\n' "${values[@]}")"
}

ui_resolve_user_ids_by_indexes() {
    local indexes="$1"
    jq -r --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      [ .users[]?.id ] as $ids
      | $idxs[]
      | $ids[. - 1] // empty
    ' "$PFWD_CONFIG_FILE"
}

ui_resolve_forward_ids_by_indexes() {
    local indexes="$1"
    jq -r --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      [ .forwards[]? | { id, user_id, listen_port, sort_id: .id } ]
      | sort_by(.user_id, .listen_port, .sort_id)
      | map(.id) as $ids
      | $idxs[]
      | $ids[. - 1] // empty
    ' "$PFWD_CONFIG_FILE"
}

ui_resolve_user_forward_ids_by_indexes() {
    local user_id="$1"
    local indexes="$2"
    jq -r --arg id "$user_id" --argjson idxs "$(printf '%s\n' "$indexes" | jq -Rcs 'split("\n") | map(select(length > 0) | tonumber)')" '
      [ .forwards[] | select(.user_id == $id) | { id, listen_port, sort_id: .id } ]
      | sort_by(.listen_port, .sort_id)
      | map(.id) as $ids
      | $idxs[]
      | $ids[. - 1] // empty
    ' "$PFWD_CONFIG_FILE"
}

ui_select_users_multi() {
    local allow_zero="${1:-false}"
    UI_EDIT_ABORTED=0
    config_init >/dev/null
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_users_text)"
        return 1
    fi
    local count raw indexes user_ids
    count="$(jq '.users | length' "$PFWD_CONFIG_FILE")"
    ui_render_page ui_render_user_select_page "$allow_zero"
    ui_read "选择用户序号，可多选：1,3,5 或 1-3" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$count" "$allow_zero" || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    user_ids="$(ui_resolve_user_ids_by_indexes "$indexes")"
    [ -n "$user_ids" ] || { ui_warn "用户序号不存在"; return 1; }
    UI_REPLY="$user_ids"
}

ui_select_forwards_multi() {
    local allow_zero="${1:-false}"
    UI_EDIT_ABORTED=0
    config_init >/dev/null
    if ! jq -e '.forwards | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_forwards_text)"
        return 1
    fi
    local count raw indexes forward_ids
    count="$(jq '.forwards | length' "$PFWD_CONFIG_FILE")"
    ui_render_page ui_render_forward_select_page "$allow_zero"
    ui_read "选择转发序号，可多选：1,3,5 或 1-3" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$count" "$allow_zero" || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    forward_ids="$(ui_resolve_forward_ids_by_indexes "$indexes")"
    [ -n "$forward_ids" ] || { ui_warn "转发序号不存在"; return 1; }
    UI_REPLY="$forward_ids"
}

ui_render_forward_scope_page() {
    local title="${1:-选择转发范围}"
    ui_header "$title"
    ui_notice_render
    ui_menu_item 0 "返回"
    ui_menu_item 1 "全部转发"
    ui_menu_item 2 "按用户选择"
}

ui_select_forward_scoped() {
    local allow_zero="${1:-false}"
    local scope_title="${2:-选择转发范围}"
    UI_EDIT_ABORTED=0

    while true; do
        ui_render_page ui_render_forward_scope_page "$scope_title" || return 1
        ui_read "选择范围" || return 1
        case "$UI_REPLY" in
            0)
                if [ "$allow_zero" = "true" ]; then
                    UI_EDIT_ABORTED=1
                    return 0
                fi
                ui_warn "无效选择"
                ;;
            1)
                ui_select_forward "$allow_zero" || return 1
                return 0
                ;;
            2)
                ui_select_user true || return 1
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local user_id="$UI_REPLY"
                ui_select_user_forward "$user_id" true || return 1
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                return 0
                ;;
            *)
                ui_warn "无效选择"
                ;;
        esac
    done
}

ui_select_forwards_multi_scoped() {
    local allow_zero="${1:-false}"
    local scope_title="${2:-选择转发范围}"
    UI_EDIT_ABORTED=0

    while true; do
        ui_render_page ui_render_forward_scope_page "$scope_title" || return 1
        ui_read "选择范围" || return 1
        case "$UI_REPLY" in
            0)
                if [ "$allow_zero" = "true" ]; then
                    UI_EDIT_ABORTED=1
                    return 0
                fi
                ui_warn "无效选择"
                ;;
            1)
                ui_select_forwards_multi "$allow_zero" || return 1
                return 0
                ;;
            2)
                ui_select_user true || return 1
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local user_id="$UI_REPLY"
                ui_select_user_forwards_multi "$user_id" true || return 1
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                return 0
                ;;
            *)
                ui_warn "无效选择"
                ;;
        esac
    done
}

ui_batch_print_result() {
    local ok="$1"
    local fail="$2"
    ui_print_line "完成：成功 $ok 项，失败 $fail 项" "$UI_C_ACCENT"
}

ui_select_user_forwards_multi() {
    local user_id="$1"
    local allow_zero="${2:-false}"
    UI_EDIT_ABORTED=0
    config_init >/dev/null
    if ! jq -e --arg id "$user_id" '[.forwards[]? | select(.user_id == $id)] | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "该用户暂无转发"
        return 1
    fi
    local count raw indexes forward_ids index_count
    count="$(jq -r --arg id "$user_id" '[.forwards[] | select(.user_id == $id)] | length' "$PFWD_CONFIG_FILE")"
    ui_render_page ui_render_user_forward_select_page "$user_id" "$allow_zero" "true"
    ui_read "选择转发序号，可多选：1,3,5 或 1-3" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$((count + 1))" "$allow_zero" || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    if printf '%s\n' "$indexes" | grep -qx '1'; then
        index_count="$(printf '%s\n' "$indexes" | sed '/^$/d' | wc -l | tr -d ' ')"
        if [ "$index_count" != "1" ]; then
            ui_warn "选择全部端口时不能和其他序号混合选择"
            return 1
        fi
        forward_ids="$(jq -r --arg id "$user_id" '
          [.forwards[] | select(.user_id == $id) | { id, listen_port, sort_id: .id }]
          | sort_by(.listen_port, .sort_id)
          | .[].id
        ' "$PFWD_CONFIG_FILE")"
    else
        forward_ids="$(ui_resolve_user_forward_ids_by_indexes "$user_id" "$(printf '%s\n' "$indexes" | awk '$1 > 1 { print $1 - 1 }')")"
    fi
    [ -n "$forward_ids" ] || { ui_warn "转发序号不存在"; return 1; }
    UI_REPLY="$forward_ids"
}

ui_resolve_listen_ports_by_forward_ids() {
    local forward_ids="$1"
    jq -r --argjson ids "$(printf '%s\n' "$forward_ids" | jq -Rcs 'split("\n") | map(select(length > 0))')" '
      [ .forwards[] | select(.id as $id | $ids | index($id)) | .listen_port ]
      | unique
      | .[]
    ' "$PFWD_CONFIG_FILE"
}

ui_print_guard_skip_ports() {
    local ports
    ports="$(guard_protocol_skip_ports_tsv | paste -sd, -)"
    if [ -n "$ports" ]; then
        ui_print_line "当前跳过端口：$ports" "$UI_C_ACCENT"
    else
        ui_print_line "当前跳过端口：-" "$UI_C_DIM"
    fi
}

ui_guard_skip_port_rows() {
    local start_index="${1:-1}"
    local idx="$start_index"
    while IFS= read -r port; do
        [ -n "$port" ] || continue
        printf '%s\t%s\n' "$idx" "$port"
        idx=$((idx + 1))
    done < <(guard_protocol_skip_ports_tsv)
}

ui_print_guard_skip_port_list() {
    local start_index="${1:-1}"
    ui_table_render $'序号\t端口' "$(ui_guard_skip_port_rows "$start_index")" "2"
}

ui_render_guard_skip_ports_menu_page() {
    ui_header "跳过端口"
    ui_notice_render
    ui_print_guard_skip_ports
    echo
    ui_menu_item 1 "增加端口"
    ui_menu_item 2 "删除端口"
    ui_menu_item 3 "修改端口"
    ui_menu_item 0 "返回"
}

ui_render_guard_skip_ports_delete_page() {
    ui_header "删除跳过端口"
    ui_notice_render
    ui_print_guard_skip_ports
    echo
    ui_menu_item 0 "返回"
    ui_menu_item 1 "所有端口"
    ui_print_guard_skip_port_list 2
}

ui_render_guard_skip_ports_update_page() {
    ui_header "修改跳过端口"
    ui_notice_render
    ui_print_guard_skip_ports
    echo
    ui_menu_item 0 "返回"
    ui_print_guard_skip_port_list
}

ui_guard_skip_ports_apply_list() {
    local ports="$1"
    local cmd=()
    local port
    if [ -z "$ports" ]; then
        ui_run cmd_guard protocols --clear-skip-ports
        return 0
    fi
    cmd=(cmd_guard protocols --replace-skip-ports)
    while IFS= read -r port; do
        [ -n "$port" ] || continue
        cmd+=(--skip-port "$port")
    done <<< "$ports"
    ui_run "${cmd[@]}"
    [ "$UI_STATUS" -eq 0 ] || return 1
}

ui_menu_guard_skip_ports_delete() {
    local count raw indexes delete_indexes remaining_ports port idx delete_all
    count="$(guard_protocol_skip_ports_count)"
    if [ "$count" -eq 0 ]; then
        ui_warn "当前没有跳过端口"
        ui_pause
        return 0
    fi
    while true; do
        ui_render_page ui_render_guard_skip_ports_delete_page
        ui_read "选择端口序号，可单/多/连续选择；1 表示删除全部" || return 1
        raw="$UI_REPLY"
        ui_multiselect_parse_indexes "$raw" "$((count + 1))" true || return 1
        [ "$UI_EDIT_ABORTED" = "1" ] && return 0
        indexes="$UI_REPLY"
        delete_all=0
        if printf '%s\n' "$indexes" | grep -qx '1'; then
            if [ "$(printf '%s\n' "$indexes" | sed '/^$/d' | wc -l | tr -d ' ')" != "1" ]; then
                ui_warn "删除全部时不能和其他序号混合选择"
                ui_pause
                continue
            fi
            delete_all=1
        fi
        if [ "$delete_all" -eq 1 ]; then
            ui_run cmd_guard protocols --clear-skip-ports
            if [ "$UI_STATUS" -eq 0 ]; then
                ui_notice_set "协议封锁跳过端口已清空" "$UI_C_MENU_NUM"
                ui_pause
            fi
            return 0
        fi
        delete_indexes="$(printf '%s\n' "$indexes" | awk '$1 > 1 { print $1 - 1 }')"
        [ -n "$delete_indexes" ] || { ui_warn "请选择要删除的端口"; ui_pause; continue; }
        remaining_ports=""
        idx=1
        while IFS= read -r port; do
            [ -n "$port" ] || continue
            if ! printf '%s\n' "$delete_indexes" | grep -qx "$idx"; then
                remaining_ports="${remaining_ports}${remaining_ports:+$'\n'}$port"
            fi
            idx=$((idx + 1))
        done < <(guard_protocol_skip_ports_tsv)
        ui_guard_skip_ports_apply_list "$remaining_ports"
        if [ "$UI_STATUS" -eq 0 ]; then
            ui_notice_set "协议封锁跳过端口已删除" "$UI_C_MENU_NUM"
            ui_pause
        fi
        return 0
    done
}

ui_menu_guard_skip_ports_update() {
    local count selected current_port new_port updated_ports port idx
    count="$(guard_protocol_skip_ports_count)"
    if [ "$count" -eq 0 ]; then
        ui_warn "当前没有跳过端口"
        ui_pause
        return 0
    fi
    while true; do
        ui_render_page ui_render_guard_skip_ports_update_page
        ui_read "选择要修改的端口序号" || return 1
        [ "$UI_REPLY" = "0" ] && return 0
        [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; ui_pause; continue; }
        selected="$UI_REPLY"
        [ "$selected" -ge 1 ] && [ "$selected" -le "$count" ] || { ui_warn "序号超出范围"; ui_pause; continue; }
        current_port="$(guard_protocol_skip_ports_tsv | sed -n "${selected}p")"
        [ -n "$current_port" ] || { ui_warn "端口序号不存在"; ui_pause; continue; }
        ui_form_set "修改跳过端口" "输入新的监听端口；仅用于跳过协议封锁。"
        ui_form_add_kv "当前端口" "$current_port"
        ui_form_read "新端口" "$current_port" || { ui_form_reset; return 0; }
        new_port="$UI_REPLY"
        [ -n "$new_port" ] || { ui_form_reset; ui_warn "必须提供端口"; ui_pause; continue; }
        if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
            ui_form_reset
            ui_warn "无效端口：$new_port"
            ui_pause
            continue
        fi
        updated_ports=""
        idx=1
        while IFS= read -r port; do
            [ -n "$port" ] || continue
            if [ "$idx" -eq "$selected" ]; then
                port="$new_port"
            fi
            if ! printf '%s\n' "$updated_ports" | sed '/^$/d' | grep -qx "$port"; then
                updated_ports="${updated_ports}${updated_ports:+$'\n'}$port"
            fi
            idx=$((idx + 1))
        done < <(guard_protocol_skip_ports_tsv)
        ui_guard_skip_ports_apply_list "$updated_ports"
        ui_form_reset
        if [ "$UI_STATUS" -eq 0 ]; then
            ui_notice_set "协议封锁跳过端口已更新" "$UI_C_MENU_NUM"
            ui_pause
        fi
        return 0
    done
}

ui_menu_guard_skip_ports() {
    local forward_ids ports
    while true; do
        ui_render_page ui_render_guard_skip_ports_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_select_forwards_multi_scoped true "选择需要跳过协议封锁的转发范围" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                forward_ids="$UI_REPLY"
                ports="$(ui_resolve_listen_ports_by_forward_ids "$forward_ids")"
                [ -n "$ports" ] || { ui_warn "未解析到监听端口"; ui_pause; continue; }
                while IFS= read -r port; do
                    [ -n "$port" ] || continue
                    ui_run cmd_guard protocols --skip-port "$port"
                    [ "$UI_STATUS" -eq 0 ] || break
                done <<< "$ports"
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "协议封锁跳过端口已更新" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_menu_guard_skip_ports_delete
                ui_maybe_pause success
                ;;
            3)
                ui_menu_guard_skip_ports_update
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}

ui_user_telegram_config() {
    local user_id="$1"
    config_init >/dev/null
    jq -c --arg id "$user_id" '.users[]? | select(.id == $id) | .telegram // {}' "$PFWD_CONFIG_FILE"
}

ui_user_telegram_server_name_default() {
    local current="$1"
    if [ -n "$current" ] && [ "$current" != "null" ]; then
        echo "$current"
    else
        hostname 2>/dev/null || echo pfwd
    fi
}

ui_print_telegram_configured_users() {
    config_init >/dev/null
    ui_print_line "已配置用户" "$UI_C_HEADER"
    if ! jq -e '[.users[]? | select((.telegram.bot_token // "") != "" and (.telegram.chat_id // "") != "")] | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_print_line "暂无已配置用户，请先配置 Telegram。"
        return
    fi
    ui_table_render $'用户\t状态\t定时发送' "$(ui_telegram_configured_user_rows)" "1,3"
}

ui_print_export_import_summary() {
    local rows=""
    rows+="当前配置"$'\t'"$PFWD_CONFIG_FILE"$'\n'
    rows+="当前状态"$'\t'"$PFWD_STATS_FILE"$'\n'
    rows+="说明"$'\t'"导出会包含主配置和流量状态；导入会覆盖当前内容。"
    ui_table_render $'项目\t值' "$rows" "2"
}

ui_select_forward_table() {
    local allow_zero="${1:-false}"
    config_init >/dev/null
    if ! jq -e '.forwards | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "$(ui_empty_forwards_text)"
        return 1
    fi
    ui_render_forward_groups "$(ui_forward_select_rows "$allow_zero")" $'序号\t用户\t监听\t目标\t协议\t状态\t到期' "4,2,7,3" "$(ui_empty_forwards_text)"
}

ui_render_forward_select_page() {
    local allow_zero="${1:-false}"
    ui_header "选择转发"
    ui_notice_render
    if [ "$allow_zero" = "true" ]; then
        ui_print_line "0) 返回" "$UI_C_ACCENT"
    fi
    ui_select_forward_table false
}

ui_select_forward() {
    local allow_zero="${1:-false}"
    UI_EDIT_ABORTED=0
    ui_render_page ui_render_forward_select_page "$allow_zero" || return 1
    ui_read "选择转发序号" || return 1
    if [ "$allow_zero" = "true" ] && [ "$UI_REPLY" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi
    [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; return 1; }
    local forward_id
    forward_id="$(jq -r --argjson idx "$UI_REPLY" '
      [ .forwards[]? | { id, user_id, listen_port, sort_id: .id } ]
      | sort_by(.user_id, .listen_port, .sort_id)
      | .[$idx - 1].id // ""
    ' "$PFWD_CONFIG_FILE")"
    [ -n "$forward_id" ] || { ui_warn "转发序号不存在"; return 1; }
    UI_REPLY="$forward_id"
}

ui_select_user_forward_table() {
    local user_id="$1"
    local allow_zero="${2:-false}"
    config_init >/dev/null
    if ! jq -e --arg id "$user_id" '[.forwards[]? | select(.user_id == $id)] | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "该用户暂无转发"
        return 1
    fi
    ui_table_render $'序号\t监听\t目标\t协议\t状态\t到期' "$(ui_user_forward_select_rows "$user_id" "$allow_zero")" "3,6,2"
}

ui_render_user_forward_select_page() {
    local user_id="$1"
    local allow_zero="${2:-false}"
    local include_all="${3:-false}"
    ui_header "选择转发"
    ui_notice_render
    if [ "$allow_zero" = "true" ]; then
        ui_print_line "0) 返回" "$UI_C_ACCENT"
    fi
    ui_print_line "用户：$user_id" "$UI_C_HEADER"
    ui_table_render $'序号\t监听\t目标\t协议\t状态\t到期' "$(ui_user_forward_select_rows "$user_id" false "$include_all")" "3,6,2"
}

ui_select_user_forward() {
    local user_id="$1"
    local allow_zero="${2:-false}"
    UI_EDIT_ABORTED=0
    ui_render_page ui_render_user_forward_select_page "$user_id" "$allow_zero" || return 1
    ui_read "选择转发序号" || return 1
    if [ "$allow_zero" = "true" ] && [ "$UI_REPLY" = "0" ]; then
        UI_EDIT_ABORTED=1
        return 0
    fi
    [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; return 1; }
    local forward_id
    forward_id="$(jq -r --arg id "$user_id" --argjson idx "$UI_REPLY" '
      [ .forwards[] | select(.user_id == $id) | { id, listen_port, sort_id: .id } ]
      | sort_by(.listen_port, .sort_id)
      | .[$idx - 1].id // ""
    ' "$PFWD_CONFIG_FILE")"
    [ -n "$forward_id" ] || { ui_warn "转发序号不存在"; return 1; }
    UI_REPLY="$forward_id"
}

ui_select_traffic_scope() {
    local user_id="$1"
    UI_EDIT_ABORTED=0
    echo "0) 返回"
    echo "1) 用户所有端口"
    echo "2) 选择端口，可多选"
    ui_read "作用范围" "1" || return 1
    case "$UI_REPLY" in
        0)
            UI_EDIT_ABORTED=1
            return 0
            ;;
        1|"") UI_REPLY="user:$user_id" ;;
        2)
            ui_select_user_forwards_multi "$user_id" true || return 1
            [ "$UI_EDIT_ABORTED" = "1" ] && return 0
            UI_REPLY="forward-list:$UI_REPLY"
            ;;
        *) ui_warn "无效选择"; return 1 ;;
    esac
}

ui_menu_users() {
    while true; do
        ui_render_page ui_render_users_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_read "用户名" || continue
                UI_REPLY="$(normalize_user_id "$UI_REPLY")"
                [ -n "$UI_REPLY" ] || { ui_warn "用户名不能为空"; ui_pause; continue; }
                ui_run cmd_user add "$UI_REPLY"
                if [ "$UI_STATUS" -eq 0 ]; then
                    ui_notice_set "用户已添加：$UI_REPLY" "$UI_C_MENU_NUM"
                fi
                ui_maybe_pause success
                ;;
            2)
                ui_select_users_multi true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local user_ids="$UI_REPLY" has_forwards="" confirm_prompt=""
                ui_print_user_delete_preview "$user_ids"
                has_forwards="$UI_REPLY"
                if [ "$has_forwards" = "true" ]; then
                    confirm_prompt="输入 delete 确认删除用户及其关联转发"
                else
                    confirm_prompt="输入 delete 确认批量删除"
                fi
                if ui_confirm_text "delete" "$confirm_prompt"; then
                    local ok=0 fail=0
                    while IFS= read -r user_id; do
                        [ -n "$user_id" ] || continue
                        ui_run_capture cmd_user delete "$user_id" --cascade
                        if [ "$UI_STATUS" -eq 0 ]; then
                            ok=$((ok + 1))
                        else
                            fail=$((fail + 1))
                            if [ -n "$UI_REPLY" ]; then
                                ui_error "$UI_REPLY"
                            else
                                ui_error "删除失败：$user_id"
                            fi
                        fi
                    done <<< "$user_ids"
                    ui_batch_print_result "$ok" "$fail"
                    ui_notice_set "批量删除用户完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                else
                    ui_warn "已取消"
                fi
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}

ui_menu_add_forward() {
    local user_id remote_host remote_port remote listen_ip listen_port random_range stop_at protocol traffic_mode traffic_ratio comment args=()
    local user_defaults="" default_rate="" default_stop_at="" default_traffic_mode="" stop_prompt=""
    ui_form_set "添加转发" "支持单端口、多端口：443,553 或 连续段：1000-1005；监听端口和目标端口数量需一致。"
    ui_select_user true || return 0
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    user_id="$UI_REPLY"
    user_defaults="$(config_user_forward_defaults_json "$user_id")"
    default_rate="$(jq -r '.rate // ""' <<< "$user_defaults")"
    default_stop_at="$(jq -r '.stop_at // ""' <<< "$user_defaults")"
    default_traffic_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$user_defaults")"
    ui_form_add_kv "用户" "$user_id"
    [ -z "$default_rate" ] || ui_form_add_kv "默认端口速率" "$default_rate"
    ui_form_read "目标 IP/域名" || return 0
    remote_host="$UI_REPLY"
    ui_form_add_kv "目标 IP/域名" "$remote_host"
    ui_form_read "目标端口" || return 0
    remote_port="$UI_REPLY"
    remote="$(ui_join_remote "$remote_host" "$remote_port")"
    ui_form_add_kv "目标端口" "$remote_port"
    ui_form_read "监听 IP，留空默认双栈" "$(ui_config_value '.settings.default_listen_ip // "::"')" || return 0
    listen_ip="$UI_REPLY"
    ui_form_add_kv "监听 IP" "$listen_ip"
    ui_form_read "固定监听端口，留空则使用随机端口" || return 0
    listen_port="$UI_REPLY"
    if [ -z "$listen_port" ]; then
        ui_form_add_kv "监听端口" "随机"
        ui_form_read "随机端口范围" "$(ui_config_value '.settings.default_random_port_range // "20000-30000"')" || return 0
        random_range="$UI_REPLY"
    else
        random_range=""
        ui_form_add_kv "监听端口" "$listen_port"
    fi
    [ -z "$random_range" ] || ui_form_add_kv "随机端口范围" "$random_range"
    if [ -n "$default_stop_at" ]; then
        stop_prompt="到期日期 YYYYMMDD，支持 +7/7d；回车继承默认值，输入 - 不限期"
    else
        stop_prompt="到期日期 YYYYMMDD，支持 +7/7d，留空不限期"
    fi
    ui_form_read "$stop_prompt" "$default_stop_at" || return 0
    stop_at="$UI_REPLY"
    ui_form_add_kv "到期日期" "$stop_at"
    ui_select_protocol "转发协议" || return 0
    protocol="$UI_REPLY"
    ui_form_add_kv "转发协议" "$(ui_protocol_label "$protocol")"
    ui_select_traffic_mode "计费模式" false "$default_traffic_mode" || return 0
    traffic_mode="$UI_TRAFFIC_MODE"
    ui_form_add_kv "计费模式" "$( [ "$traffic_mode" = "one-way" ] && echo "单向计费" || echo "双向计费" )"
    ui_read_traffic_ratio "流量倍率，默认 1.0" "1.0" || return 0
    traffic_ratio="$UI_TRAFFIC_RATIO"
    ui_form_add_kv "倍率" "$(format_ratio "$traffic_ratio")"
    ui_form_read "备注，留空不设置" || return 0
    comment="$UI_REPLY"
    ui_form_add_kv "备注" "$comment"
    ui_select_mss_mode "MSS 处理方式" "$remote_host" || return 0
    case "$UI_MSS_MODE" in
        clamp) ui_form_add_kv "MSS" "Clamp" ;;
        set) ui_form_add_kv "MSS" "$UI_MSS_VALUE" ;;
        *) ui_form_add_kv "MSS" "-" ;;
    esac
    ui_select_snat_mode "SNAT 处理方式" || return 0
    if [ "$UI_SNAT_MODE" = "snat" ]; then
        ui_form_add_kv "SNAT" "$UI_SNAT_SOURCE"
    else
        ui_form_add_kv "SNAT" "masquerade"
    fi

    args=(--user-id "$user_id" --remote "$remote" --listen-ip "$listen_ip" --protocol "$protocol" --traffic-mode "$traffic_mode" --traffic-ratio "$traffic_ratio")
    if [ -n "$listen_port" ]; then
        args+=(--listen-port "$listen_port")
    else
        args+=(--random-port "$random_range")
    fi
    [ -z "$stop_at" ] || args+=(--stop-at "$stop_at")
    case "$UI_MSS_MODE" in
        clamp) args+=(--mss-clamp) ;;
        set) args+=(--mss "$UI_MSS_VALUE") ;;
    esac
    if [ "$UI_SNAT_MODE" = "snat" ]; then
        args+=(--snat-source "$UI_SNAT_SOURCE")
    else
        args+=(--masquerade)
    fi
    [ -z "$comment" ] || args+=(--comment "$comment")

    ui_form_reset
    ui_run cmd_add "${args[@]}"
}

ui_menu_forwards() {
    while true; do
        ui_render_page ui_render_forwards_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_require_users || { ui_pause; continue; }
                ui_menu_add_forward
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "转发已添加" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_require_users || { ui_pause; continue; }
                ui_select_forward_scoped true "选择要修改的转发范围" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local forward_id="$UI_REPLY" current="" current_listen_ip="" current_listen_port="" current_remote_host="" current_remote_port="" current_stop_at="" current_protocol="" current_mode="" current_ratio="" current_comment=""
                local current_mss_mode="" current_mss_value="" current_snat_mode="" current_snat_source=""
                local listen_ip="" listen_port="" remote_host="" remote_port="" stop_at="" protocol="" traffic_mode="" traffic_ratio="" comment="" args=()
                current="$(jq -c --arg id "$forward_id" '.forwards[] | select(.id == $id)' "$PFWD_CONFIG_FILE")"
                current_listen_ip="$(jq -r '.listen_ip // "::"' <<< "$current")"
                current_listen_port="$(jq -r '.listen_port' <<< "$current")"
                current_remote_host="$(jq -r '.remote_host' <<< "$current")"
                current_remote_port="$(jq -r '.remote_port' <<< "$current")"
                current_stop_at="$(jq -r '.stop_at // ""' <<< "$current")"
                current_protocol="$(jq -r '.protocol // "tcp_udp"' <<< "$current")"
                current_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$current")"
                current_ratio="$(jq -r '(.traffic_ratio // 1) | tostring' <<< "$current")"
                current_comment="$(jq -r '.comment // ""' <<< "$current")"
                current_mss_mode="$(jq -r '.net.mss_mode // ""' <<< "$current")"
                current_mss_value="$(jq -r '.net.mss_value // ""' <<< "$current")"
                current_snat_mode="$(jq -r '.net.snat_mode // "masquerade"' <<< "$current")"
                current_snat_source="$(jq -r '.net.snat_source // ""' <<< "$current")"

                ui_form_set "修改转发" "回车保留当前值，0 返回上级，转发到期日输入 - 清空为不限期，备注输入 - 清空。"
                ui_form_add_kv "转发 ID" "$forward_id"
                ui_form_add_kv "当前监听 IP" "$current_listen_ip"
                ui_form_add_kv "当前监听端口" "$current_listen_port"
                ui_form_add_kv "当前目标 IP/域名" "$current_remote_host"
                ui_form_add_kv "当前目标端口" "$current_remote_port"
                ui_form_add_kv "当前协议" "$(ui_protocol_label "$current_protocol")"
                ui_form_add_kv "当前计费模式" "$( [ "$current_mode" = "one-way" ] && echo "单向计费" || echo "双向计费" )"
                ui_form_add_kv "当前倍率" "$(format_ratio "$current_ratio")"
                ui_form_add_kv "当前到期日" "${current_stop_at:-}"
                ui_form_add_kv "当前备注" "$current_comment"

                ui_form_edit_read "监听 IP" "$current_listen_ip" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                listen_ip="$UI_REPLY"
                ui_form_add_kv "新监听 IP" "$listen_ip"

                ui_form_edit_read "监听端口" "$current_listen_port" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                listen_port="$UI_REPLY"
                ui_form_add_kv "新监听端口" "$listen_port"

                ui_form_edit_read "目标 IP/域名" "$current_remote_host" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                remote_host="$UI_REPLY"
                ui_form_add_kv "新目标 IP/域名" "$remote_host"

                ui_form_edit_read "目标端口" "$current_remote_port" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                remote_port="$UI_REPLY"
                ui_form_add_kv "新目标端口" "$remote_port"

                ui_form_edit_read "转发到期日 YYYYMMDD，支持 +7/7d" "${current_stop_at:-}" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                stop_at="$UI_REPLY"
                ui_form_add_kv "新到期日" "$stop_at"

                ui_select_protocol_edit "转发协议" "$current_protocol" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                protocol="$UI_REPLY"
                [ -z "$protocol" ] || ui_form_add_kv "新协议" "$(ui_protocol_label "$protocol")"

                ui_select_traffic_mode_edit "计费模式" "$current_mode" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                traffic_mode="$UI_TRAFFIC_MODE"
                [ -z "$traffic_mode" ] || ui_form_add_kv "新计费模式" "$( [ "$traffic_mode" = "one-way" ] && echo "单向计费" || echo "双向计费" )"

                ui_read_traffic_ratio_edit "流量倍率" "$current_ratio" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                traffic_ratio="$UI_TRAFFIC_RATIO"
                ui_form_add_kv "新倍率" "$(format_ratio "$traffic_ratio")"

                ui_form_edit_read "备注" "$current_comment" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                comment="$UI_REPLY"
                ui_form_add_kv "新备注" "$comment"

                ui_select_mss_mode_edit "MSS 处理方式" "$current_mss_mode" "$current_mss_value" "$remote_host" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                case "$UI_MSS_MODE" in
                    clamp) ui_form_add_kv "新 MSS" "Clamp" ;;
                    set) ui_form_add_kv "新 MSS" "$UI_MSS_VALUE" ;;
                    __CLEAR__) ui_form_add_kv "新 MSS" "清空" ;;
                esac
                ui_select_snat_mode_edit "SNAT 处理方式" "$current_snat_mode" "$current_snat_source" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                case "$UI_SNAT_MODE" in
                    snat) ui_form_add_kv "新 SNAT" "$UI_SNAT_SOURCE" ;;
                    masquerade) ui_form_add_kv "新 SNAT" "masquerade" ;;
                esac

                args=(--forward-id "$forward_id")
                [ "$listen_ip" = "$current_listen_ip" ] || args+=(--listen-ip "$listen_ip")
                [ "$listen_port" = "$current_listen_port" ] || args+=(--listen-port "$listen_port")
                [ "$remote_host" = "$current_remote_host" ] || args+=(--remote-host "$remote_host")
                [ "$remote_port" = "$current_remote_port" ] || args+=(--remote-port "$remote_port")
                if [ "$stop_at" = "-" ]; then
                    [ -n "$current_stop_at" ] && args+=(--clear-stop-at)
                elif [ "$stop_at" != "$current_stop_at" ]; then
                    [ -n "$stop_at" ] && args+=(--stop-at "$stop_at")
                fi
                [ -z "$protocol" ] || [ "$protocol" = "$current_protocol" ] || args+=(--protocol "$protocol")
                [ -z "$traffic_mode" ] || [ "$traffic_mode" = "$current_mode" ] || args+=(--traffic-mode "$traffic_mode")
                [ -z "$traffic_ratio" ] || [ "$traffic_ratio" = "$current_ratio" ] || args+=(--traffic-ratio "$traffic_ratio")
                if [ "$comment" = "-" ]; then
                    [ -n "$current_comment" ] && args+=(--clear-comment)
                elif [ "$comment" != "$current_comment" ]; then
                    args+=(--comment "$comment")
                fi
                case "$UI_MSS_MODE" in
                    clamp)
                        if [ "$current_mss_mode" != "clamp" ]; then
                            args+=(--mss-clamp)
                        fi
                        ;;
                    set)
                        if [ "$current_mss_mode" != "set" ] || [ "$UI_MSS_VALUE" != "$current_mss_value" ]; then
                            args+=(--mss "$UI_MSS_VALUE")
                        fi
                        ;;
                    __CLEAR__)
                        if [ -n "$current_mss_mode" ] || [ -n "$current_mss_value" ]; then
                            args+=(--clear-mss)
                        fi
                        ;;
                esac
                case "$UI_SNAT_MODE" in
                    snat)
                        if [ "$current_snat_mode" != "snat" ] || [ "$UI_SNAT_SOURCE" != "$current_snat_source" ]; then
                            args+=(--snat-source "$UI_SNAT_SOURCE")
                        fi
                        ;;
                    masquerade)
                        if [ "$current_snat_mode" != "masquerade" ] || [ -n "$current_snat_source" ]; then
                            args+=(--masquerade)
                        fi
                        ;;
                esac

                if [ "${#args[@]}" -eq 2 ]; then
                    ui_warn "未修改"
                else
                    ui_form_reset
                    ui_run cmd_forward_update "${args[@]}"
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "转发已更新：$forward_id" "$UI_C_MENU_NUM"
                fi
                ui_form_reset
                ui_maybe_pause success
                ;;
            3)
                ui_require_users || { ui_pause; continue; }
                ui_select_forwards_multi_scoped true "选择要暂停的转发范围" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local stop_ids="$UI_REPLY" ok=0 fail=0
                while IFS= read -r forward_id; do
                    [ -n "$forward_id" ] || continue
                    if cmd_toggle_forward false "$forward_id"; then
                        ok=$((ok + 1))
                    else
                        fail=$((fail + 1))
                        ui_error "暂停失败：$forward_id"
                    fi
                done <<< "$stop_ids"
                ui_batch_print_result "$ok" "$fail"
                ui_notice_set "批量暂停完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                ;;
            4)
                ui_require_users || { ui_pause; continue; }
                ui_select_forwards_multi_scoped true "选择要恢复的转发范围" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local start_ids="$UI_REPLY" ok=0 fail=0
                while IFS= read -r forward_id; do
                    [ -n "$forward_id" ] || continue
                    if cmd_toggle_forward true "$forward_id"; then
                        ok=$((ok + 1))
                    else
                        fail=$((fail + 1))
                        ui_error "恢复失败：$forward_id"
                    fi
                done <<< "$start_ids"
                ui_batch_print_result "$ok" "$fail"
                ui_notice_set "批量恢复完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                ;;
            5)
                ui_require_users || { ui_pause; continue; }
                ui_select_forwards_multi_scoped true "选择要删除的转发范围" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local delete_ids="$UI_REPLY" summary=""
                while IFS= read -r forward_id; do
                    [ -n "$forward_id" ] || continue
                    summary+="$(
                        jq -r --arg id "$forward_id" '
                          .forwards[] | select(.id == $id) |
                          "\(.id)  用户:\(.user_id)  监听:\(.listen_port)"
                        ' "$PFWD_CONFIG_FILE"
                    )"$'\n'
                done <<< "$delete_ids"
                summary="${summary%$'\n'}"
                ui_print_line "将删除以下转发：" "$UI_C_WARN"
                printf '%s\n' "$summary"
                if ui_confirm_text "delete" "输入 delete 确认批量删除"; then
                    local ok=0 fail=0
                    while IFS= read -r forward_id; do
                        [ -n "$forward_id" ] || continue
                        if cmd_delete "$forward_id"; then
                            ok=$((ok + 1))
                        else
                            fail=$((fail + 1))
                            ui_error "删除失败：$forward_id"
                        fi
                    done <<< "$delete_ids"
                    ui_batch_print_result "$ok" "$fail"
                    ui_notice_set "批量删除转发完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                else
                    ui_warn "已取消"
                fi
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}

ui_menu_expire_limit() {
    local user_id=""
    while true; do
        if [ -z "$user_id" ]; then
            ui_render_page ui_render_traffic_select_user_page
            ui_read "选择用户序号" || return 0
            if ! ui_has_users; then
                case "$UI_REPLY" in
                    0) return 0 ;;
                    *) ui_require_users; ui_pause; continue ;;
                esac
            fi
            case "$UI_REPLY" in
                0) return 0 ;;
                '')
                    ui_warn "无效序号"
                    ui_pause
                    continue
                    ;;
            esac
            [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; ui_pause; continue; }
            user_id="$(jq -r --argjson idx "$UI_REPLY" '.users[$idx - 1].id // ""' "$PFWD_CONFIG_FILE")"
            [ -n "$user_id" ] || { ui_warn "用户序号不存在"; ui_pause; user_id=""; continue; }
        fi

        while true; do
            ui_render_page ui_render_traffic_user_menu_page "$user_id"
            ui_read "选择" || return 0
            case "$UI_REPLY" in
                1)
                    local scope="" current_stop_at=""
                    ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    scope="$UI_REPLY"
                    ui_form_set "流量管理" "修改转发到期日。支持 YYYYMMDD 或 YYYY-MM-DD HH:MM；仅日期默认 00:00。输入 - 清空，0 返回上级。"
                    ui_form_add_kv "用户" "$user_id"
                    ui_form_add_kv "作用范围" "$scope"
                    if [[ "$scope" == user:* ]]; then
                        ui_form_edit_read "转发到期日，支持 YYYYMMDD[ HH:MM]、+7/7d，输入 - 清空" || { ui_form_reset; ui_pause; continue; }
                        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                        if [ -z "$UI_REPLY" ]; then
                            ui_warn "未修改"
                        elif [ "$UI_REPLY" = "-" ]; then
                            ui_run cmd_expire user-clear --user-id "${scope#user:}"
                        else
                            ui_run cmd_expire user-set --user-id "${scope#user:}" --stop-at "$UI_REPLY"
                        fi
                    else
                        ui_form_edit_read "转发到期日，支持 YYYYMMDD[ HH:MM]、+7/7d，输入 - 清空" || { ui_form_reset; ui_pause; continue; }
                        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                        local stop_value="$UI_REPLY" ok=0 fail=0
                        if [ -z "$stop_value" ]; then
                            ui_warn "未修改"
                        else
                            while IFS= read -r forward_id; do
                                [ -n "$forward_id" ] || continue
                                current_stop_at="$(jq -r --arg id "$forward_id" '.forwards[] | select(.id == $id) | (.stop_at // "")' "$PFWD_CONFIG_FILE")"
                                if [ "$stop_value" = "$current_stop_at" ]; then
                                    continue
                                elif [ "$stop_value" = "-" ]; then
                                    if cmd_expire clear "$forward_id"; then
                                        ok=$((ok + 1))
                                    else
                                        fail=$((fail + 1))
                                        ui_error "清除到期失败：$forward_id"
                                    fi
                                else
                                    if cmd_expire set "$forward_id" --stop-at "$stop_value"; then
                                        ok=$((ok + 1))
                                    else
                                        fail=$((fail + 1))
                                        ui_error "设置到期失败：$forward_id"
                                    fi
                                fi
                            done <<< "${scope#forward-list:}"
                            ui_batch_print_result "$ok" "$fail"
                        fi
                    fi
                    ui_form_reset
                    ui_maybe_pause success
                    ;;
                2)
                    local scope="" traffic="" rate="" args=() current_mode="" traffic_mode="" current_scope_mode=""
                    ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    scope="$UI_REPLY"
                    ui_form_set "流量管理" "修改流量配额、速率和统计模式。留空不改，0 返回上级。"
                    ui_form_add_kv "用户" "$user_id"
                    ui_form_add_kv "作用范围" "$scope"
                    if [[ "$scope" == user:* ]]; then
                        ui_form_read "用户总流量，数字默认 GB；例如 100 / 1.5GB / 512MB；0 清除，留空不改" || { ui_form_reset; continue; }
                    else
                        ui_form_read "总流量，数字默认 GB；例如 100 / 1.5GB / 512MB；0 清除，留空不改" || { ui_form_reset; continue; }
                    fi
                    traffic="$UI_REPLY"
                    ui_form_add_kv "总流量" "$traffic"
                    if [[ "$scope" == user:* ]]; then
                        ui_form_read "每个端口速率，数字默认 Mbps；例如 50 / 12.5Mbps / 1.2Gbps；0 清除，留空不改" || { ui_form_reset; continue; }
                    else
                        ui_form_read "速率，数字默认 Mbps；例如 50 / 12.5Mbps / 1.2Gbps；0 清除，留空不改" || { ui_form_reset; continue; }
                    fi
                    rate="$UI_REPLY"
                    ui_form_add_kv "速率" "$rate"
                    if [[ "$scope" == user:* ]]; then
                        current_scope_mode="$(jq -r --arg id "${scope#user:}" '
                          [ .forwards[] | select(.user_id == $id) | (.traffic_mode // "two-way") ]
                          | unique
                          | if length == 1 then .[0] else "" end
                        ' "$PFWD_CONFIG_FILE")"
                        current_mode="$current_scope_mode"
                    else
                        current_scope_mode="$(jq -r --argjson ids "$(printf '%s\n' "${scope#forward-list:}" | jq -Rcs 'split("\n") | map(select(length > 0))')" '
                          [ .forwards[] | select(.id as $id | $ids | index($id)) | (.traffic_mode // "two-way") ]
                          | unique
                          | if length == 1 then .[0] else "" end
                        ' "$PFWD_CONFIG_FILE")"
                        current_mode="$current_scope_mode"
                    fi
                    ui_select_traffic_mode_edit "流量模式，回车不改，0 返回" "$current_mode" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                    traffic_mode="$UI_TRAFFIC_MODE"
                    [ -z "$traffic_mode" ] || ui_form_add_kv "流量模式" "$( [ "$traffic_mode" = "one-way" ] && echo "单向" || echo "双向" )"
                    [ -z "$traffic" ] || traffic="$(normalize_ui_traffic_input "$traffic")"
                    [ -z "$rate" ] || rate="$(normalize_ui_rate_input "$rate")"
                    if [[ "$scope" == user:* ]]; then
                        args=(set --user-id "${scope#user:}")
                    else
                        args=(set --forward-id "${scope#forward:}")
                    fi
                    if [[ "$scope" == user:* ]]; then
                        local changed="false" user_limit_args=()
                        if [ -n "$traffic" ]; then
                            user_limit_args=(set --user-id "${scope#user:}" --traffic "$traffic")
                            ui_run cmd_limit "${user_limit_args[@]}"
                            changed="true"
                        fi
                        if [ -n "$rate" ] || [ -n "$traffic_mode" ]; then
                            args=(--user-id "${scope#user:}")
                            [ -n "$rate" ] && args+=(--rate "$rate")
                            [ -n "$traffic_mode" ] && args+=(--traffic-mode "$traffic_mode")
                            ui_run cmd_user_forwards_limit "${args[@]}"
                            changed="true"
                        fi
                        if [ "$changed" = "false" ]; then
                            ui_warn "未修改"
                        fi
                    else
                        if [ -n "$traffic" ] || [ -n "$rate" ] || [ -n "$traffic_mode" ]; then
                            local ok=0 fail=0
                            while IFS= read -r forward_id; do
                                [ -n "$forward_id" ] || continue
                                args=(set --forward-id "$forward_id")
                                [ -z "$traffic" ] || args+=(--traffic "$traffic")
                                [ -z "$rate" ] || args+=(--rate "$rate")
                                [ -z "$traffic_mode" ] || args+=(--traffic-mode "$traffic_mode")
                                if cmd_limit "${args[@]}"; then
                                    ok=$((ok + 1))
                                else
                                    fail=$((fail + 1))
                                    ui_error "端口设置失败：$forward_id"
                                fi
                            done <<< "${scope#forward-list:}"
                            ui_batch_print_result "$ok" "$fail"
                        else
                            ui_warn "未修改"
                        fi
                    fi
                    ui_form_reset
                    ui_maybe_pause success
                    ;;
                3)
                    ui_form_set "流量管理" "重置统计或设置重置日。重置日支持 15 或 15 09:30；仅日期默认 00:00，0 关闭。"
                    ui_form_add_kv "用户" "$user_id"
                    ui_form_select_read "选择" "" "1) 立即重置" "2) 设置每月重置日" "0) 返回" || { ui_form_reset; continue; }
                    local reset_action="$UI_REPLY" scope="" args=()
                    case "$reset_action" in
                        1)
                            ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                            [ "$UI_EDIT_ABORTED" = "1" ] && continue
                            scope="$UI_REPLY"
                            if [[ "$scope" == user:* ]]; then
                                args=(--user-id "${scope#user:}")
                            else
                                local ok=0 fail=0
                                while IFS= read -r forward_id; do
                                    [ -n "$forward_id" ] || continue
                                    if cmd_traffic reset-now --forward-id "$forward_id"; then
                                        ok=$((ok + 1))
                                    else
                                        fail=$((fail + 1))
                                        ui_error "立即重置失败：$forward_id"
                                    fi
                                done <<< "${scope#forward-list:}"
                                ui_batch_print_result "$ok" "$fail"
                                ui_form_reset
                                ui_pause
                                continue
                            fi
                            ui_run cmd_traffic reset-now "${args[@]}"
                            ;;
                        2)
                            ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                            [ "$UI_EDIT_ABORTED" = "1" ] && continue
                            scope="$UI_REPLY"
                            ui_form_add_kv "作用范围" "$scope"
                            ui_form_read "每月重置日，支持 15 或 15 09:30；0 关闭自动重置" || { ui_form_reset; continue; }
                            local day="$UI_REPLY"
                            if [ -z "$day" ]; then
                                ui_warn "未修改"
                                ui_form_reset
                                ui_pause
                                continue
                            fi
                            if [[ "$scope" == user:* ]]; then
                                args=(set --user-id "${scope#user:}" --day "$day")
                            else
                                local ok=0 fail=0
                                while IFS= read -r forward_id; do
                                    [ -n "$forward_id" ] || continue
                                    if cmd_traffic reset-day set --forward-id "$forward_id" --day "$day"; then
                                        ok=$((ok + 1))
                                    else
                                        fail=$((fail + 1))
                                        ui_error "设置重置日失败：$forward_id"
                                    fi
                                done <<< "${scope#forward-list:}"
                                ui_batch_print_result "$ok" "$fail"
                                ui_form_reset
                                ui_pause
                                continue
                            fi
                            ui_run cmd_traffic reset-day "${args[@]}"
                            ;;
                        0)
                            ui_form_reset
                            continue
                            ;;
                        *) ui_warn "无效选择" ;;
                    esac
                    ui_form_reset
                    ui_maybe_pause success
                    ;;
                4)
                    local scope="" used="" args=()
                    ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    scope="$UI_REPLY"
                    ui_form_set "流量管理" "设置计费用量。输入 0 返回上级。"
                    ui_form_add_kv "用户" "$user_id"
                    ui_form_add_kv "作用范围" "$scope"
                    ui_form_edit_read "已用流量，数字默认 GB；例如 100 / 100GB / 512MB" || { ui_form_reset; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    used="$UI_REPLY"
                    if [ -z "$used" ]; then
                        ui_warn "未修改"
                        ui_form_reset
                        ui_pause
                        continue
                    fi
                    used="$(normalize_ui_traffic_input "$used")"
                    if [[ "$scope" == user:* ]]; then
                        args=(used set --user-id "${scope#user:}" --used "$used")
                    else
                        local ok=0 fail=0
                        while IFS= read -r forward_id; do
                            [ -n "$forward_id" ] || continue
                            if cmd_traffic used set --forward-id "$forward_id" --used "$used"; then
                                ok=$((ok + 1))
                            else
                                fail=$((fail + 1))
                                ui_error "设置已用流量失败：$forward_id"
                            fi
                        done <<< "${scope#forward-list:}"
                        ui_batch_print_result "$ok" "$fail"
                        ui_form_reset
                        ui_pause
                        continue
                    fi
                    ui_run cmd_traffic "${args[@]}"
                    ui_form_reset
                    ui_maybe_pause success
                    ;;
                0)
                    user_id=""
                    break
                    ;;
                *) ui_warn "无效选择"; ui_pause ;;
            esac
        done
    done
}

ui_menu_telegram() {
    while true; do
        ui_render_page ui_render_telegram_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                UI_EDIT_ABORTED=0
                ui_select_users_for_telegram_config_multi || { ui_pause; continue; }
                [ "${UI_EDIT_ABORTED:-0}" = "1" ] && continue
                local user_id="$UI_REPLY" token="" chat_id="" server_name="" enabled="" tg="" token_default="" chat_id_default="" server_name_default=""
                local selected_users="$UI_REPLY" selected_count target_user ok=0 fail=0
                selected_count="$(printf '%s\n' "$selected_users" | sed '/^$/d' | wc -l | tr -d ' ')"
                if [ "$user_id" = "__ALL_USERS__" ]; then
                    token_default=""
                    chat_id_default=""
                    server_name_default="$(hostname 2>/dev/null || echo pfwd)"
                    enabled="__KEEP__"
                elif [ "$selected_count" = "1" ]; then
                    target_user="$(printf '%s\n' "$selected_users" | sed -n '1p')"
                    tg="$(ui_user_telegram_config "$target_user")"
                    enabled="$(jq -r '.enabled // false' <<< "$tg")"
                    token_default="$(jq -r '.bot_token // ""' <<< "$tg")"
                    chat_id_default="$(jq -r '.chat_id // ""' <<< "$tg")"
                    server_name_default="$(ui_user_telegram_server_name_default "$(jq -r '.server_name // ""' <<< "$tg")")"
                else
                    token_default=""
                    chat_id_default=""
                    server_name_default="$(hostname 2>/dev/null || echo pfwd)"
                    enabled="__KEEP__"
                fi
                ui_form_set "Telegram 通知" "配置 Bot Token、Chat ID 和服务器名称。回车保留默认值。"
                if [ "$user_id" = "__ALL_USERS__" ]; then
                    ui_form_add_kv "目标用户" "所有用户"
                else
                    ui_form_add_kv "目标用户" "$(printf '%s\n' "$selected_users" | jq -Rrsc 'split("\n") | map(select(length > 0)) | join(", ")')"
                fi
                ui_form_read "Bot Token，例如 123456789:AA..." "$token_default" || { ui_form_reset; continue; }
                token="$UI_REPLY"
                ui_form_add_kv "Bot Token" "$token"
                ui_form_read "Chat ID，例如 123456789 或 -1001234567890" "$chat_id_default" || { ui_form_reset; continue; }
                chat_id="$UI_REPLY"
                ui_form_add_kv "Chat ID" "$chat_id"
                ui_form_read "服务器名称" "$server_name_default" || { ui_form_reset; continue; }
                server_name="$UI_REPLY"
                ui_form_add_kv "服务器名称" "$server_name"
                if [ "$user_id" = "__ALL_USERS__" ]; then
                    ui_run cmd_user telegram --all --bot-token "$token" --chat-id "$chat_id" --server-name "$server_name"
                else
                    while IFS= read -r target_user; do
                        [ -n "$target_user" ] || continue
                        tg="$(ui_user_telegram_config "$target_user")"
                        enabled="$(jq -r '.enabled // false' <<< "$tg")"
                        if cmd_user telegram "$target_user" --bot-token "$token" --chat-id "$chat_id" --server-name "$server_name" --enabled "$enabled"; then
                            ok=$((ok + 1))
                        else
                            fail=$((fail + 1))
                            ui_error "更新 Telegram 配置失败：$target_user"
                        fi
                    done <<< "$selected_users"
                    UI_STATUS=0
                    [ "$fail" -eq 0 ] || UI_STATUS=1
                    ui_batch_print_result "$ok" "$fail"
                fi
                ui_form_reset
                if [ "$user_id" = "__ALL_USERS__" ]; then
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "Telegram 配置已更新：全部用户" "$UI_C_MENU_NUM"
                else
                    ui_notice_set "Telegram 配置更新完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                fi
                ui_maybe_pause success
                ;;
            2)
                ui_select_user true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local schedule_user="$UI_REPLY" interval_choice="" interval_value="" daily_time=""
                ui_form_set "Telegram 通知" "留空表示不修改；输入 - 清空对应定时。"
                ui_form_add_kv "目标用户" "$schedule_user"
                ui_form_read "间隔发送，单位分钟；例如 60" || { ui_form_reset; continue; }
                interval_choice="$UI_REPLY"
                ui_form_add_kv "间隔发送" "$interval_choice"
                ui_form_read "每日发送时间 HH:MM；例如 09:30" || { ui_form_reset; continue; }
                daily_time="$UI_REPLY"
                ui_form_add_kv "每日发送时间" "$daily_time"
                if [ "$interval_choice" = "-" ]; then
                    interval_value=""
                else
                    interval_value="${interval_choice:-__KEEP__}"
                fi
                if [ "$daily_time" = "-" ]; then
                    daily_time=""
                elif [ -z "$daily_time" ]; then
                    daily_time="__KEEP__"
                fi
                ui_run cmd_notify_schedule --user-id "$schedule_user" --interval-minutes "$interval_value" --daily-time "$daily_time"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "定时发送已更新：$schedule_user" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_select_configured_users_multi || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local test_ids="$UI_REPLY" ok=0 fail=0
                while IFS= read -r user_id; do
                    [ -n "$user_id" ] || continue
                    if cmd_notify_test --user-id "$user_id"; then
                        ok=$((ok + 1))
                    else
                        fail=$((fail + 1))
                        ui_error "测试通知失败：$user_id"
                    fi
                done <<< "$test_ids"
                ui_batch_print_result "$ok" "$fail"
                ui_notice_set "测试通知完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                ui_maybe_pause success
                ;;
            4)
                ui_select_users_multi true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local enable_ids="$UI_REPLY" ok=0 fail=0
                while IFS= read -r user_id; do
                    [ -n "$user_id" ] || continue
                    if cmd_notify_enable --user-id "$user_id"; then
                        ok=$((ok + 1))
                    else
                        fail=$((fail + 1))
                        ui_error "恢复通知失败：$user_id"
                    fi
                done <<< "$enable_ids"
                ui_batch_print_result "$ok" "$fail"
                ui_notice_set "恢复通知完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                ui_maybe_pause success
                ;;
            5)
                ui_select_users_multi true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local disable_ids="$UI_REPLY" ok=0 fail=0
                while IFS= read -r user_id; do
                    [ -n "$user_id" ] || continue
                    if cmd_notify_disable --user-id "$user_id"; then
                        ok=$((ok + 1))
                    else
                        fail=$((fail + 1))
                        ui_error "暂停通知失败：$user_id"
                    fi
                done <<< "$disable_ids"
                ui_batch_print_result "$ok" "$fail"
                ui_notice_set "暂停通知完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                ui_maybe_pause success
                ;;
            6)
                ui_select_users_multi true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local delete_ids="$UI_REPLY"
                ui_print_line "将删除以下通知配置（Bot Token、Chat ID、服务器名称、间隔/定时设置）：" "$UI_C_WARN"
                printf '%s\n' "$delete_ids"
                if ui_confirm_text "delete" "输入 delete 确认批量删除"; then
                    local ok=0 fail=0
                    while IFS= read -r user_id; do
                        [ -n "$user_id" ] || continue
                        if cmd_notify_delete --user-id "$user_id"; then
                            ok=$((ok + 1))
                        else
                            fail=$((fail + 1))
                            ui_error "删除通知失败：$user_id"
                        fi
                    done <<< "$delete_ids"
                    ui_batch_print_result "$ok" "$fail"
                    ui_notice_set "删除通知完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                else
                    ui_warn "已取消"
                fi
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}

ui_menu_export_import() {
    while true; do
        ui_render_page ui_render_export_import_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_edit_read "导出文件路径" "$(pfwd_default_export_path)" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                ui_run cmd_export "$UI_REPLY"
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "配置已导出：$UI_REPLY" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_edit_read "导入文件路径" "" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                if [ -z "$UI_REPLY" ]; then
                    ui_warn "未修改"
                    ui_pause
                    continue
                fi
                local import_path="$UI_REPLY"
                if ui_confirm_text "import" "输入 import 确认覆盖当前配置"; then
                    ui_run cmd_import "$import_path"
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "配置已导入：$import_path" "$UI_C_MENU_NUM"
                else
                    ui_warn "已取消"
                fi
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}

ui_menu_update() {
    ui_clear_screen
    ui_header "更新"
    echo "将检查远端版本，并在确认后更新 pfwd 脚本和服务文件。"
    echo
    if ! service_installation_present; then
        ui_warn "未检测到已安装的 pfwd，请先执行安装。"
        ui_pause
        return 0
    fi
    ui_run cmd_update
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "pfwd 已更新" "$UI_C_MENU_NUM"
    ui_maybe_pause success
}

ui_print_guard_summary() {
    ui_table_render $'项目\t值' "$(ui_guard_summary_rows)" "2"
}

ui_menu_guard() {
    local include_cn
    while true; do
        ui_render_page ui_render_guard_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_run cmd_guard enable
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "guard 已启用" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_run cmd_guard disable
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "guard 已停用" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_form_set "协议封锁" "HTTPS 会同时开启 HTTP 和 TLS 封锁；仅覆盖 TCP 首包。"
                ui_form_select_read "HTTP" "1" "0) 返回" "1) 关闭" "2) 开启" || { ui_form_reset; continue; }
                local block_http="false" block_tls="false" block_socks="false"
                [ "$UI_REPLY" = "0" ] && { ui_form_reset; continue; }
                [ "$UI_REPLY" = "2" ] && block_http="true"
                ui_form_add_kv "HTTP" "$( [ "$block_http" = "true" ] && echo 开启 || echo 关闭 )"
                ui_form_select_read "TLS" "1" "0) 返回" "1) 关闭" "2) 开启" || { ui_form_reset; continue; }
                [ "$UI_REPLY" = "0" ] && { ui_form_reset; continue; }
                [ "$UI_REPLY" = "2" ] && block_tls="true"
                ui_form_add_kv "TLS" "$( [ "$block_tls" = "true" ] && echo 开启 || echo 关闭 )"
                ui_form_select_read "SOCKS" "1" "0) 返回" "1) 关闭" "2) 开启" || { ui_form_reset; continue; }
                [ "$UI_REPLY" = "0" ] && { ui_form_reset; continue; }
                [ "$UI_REPLY" = "2" ] && block_socks="true"
                ui_form_add_kv "SOCKS" "$( [ "$block_socks" = "true" ] && echo 开启 || echo 关闭 )"
                ui_run cmd_guard protocols --http "$block_http" --tls "$block_tls" --socks "$block_socks"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "guard 协议封锁已更新" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            4)
                ui_menu_guard_skip_ports
                ;;
            5)
                ui_run cmd_guard_whitelist --enabled true
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "白名单已启用" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            6)
                ui_run cmd_guard_whitelist --enabled false
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "白名单已停用" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            7)
                include_cn="$(whitelist_include_cn)"
                if [ "$include_cn" = "true" ]; then
                    ui_run cmd_guard_whitelist --include-cn false
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "已从白名单移出国内 IP 段" "$UI_C_MENU_NUM"
                else
                    ui_run cmd_guard_whitelist --include-cn true
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "已把国内 IP 段加入白名单" "$UI_C_MENU_NUM"
                fi
                ui_maybe_pause success
                ;;
            8)
                ui_menu_whitelist_cidrs
                ;;
            9)
                ui_run cmd_guard_whitelist refresh
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "白名单数据已刷新" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}

ui_print_whitelist_summary() {
    ui_table_render $'项目\t值' "$(ui_whitelist_summary_rows)" "2"
}

ui_custom_cidr_rows() {
    local idx=2 cidr
    printf '1\t删除所有自定义 CIDR\n'
    while IFS= read -r cidr; do
        [ -n "$cidr" ] || continue
        printf '%s\t%s\n' "$idx" "$cidr"
        idx=$((idx + 1))
    done < <(whitelist_custom_cidrs_tsv)
}

ui_print_custom_cidr_list() {
    ui_table_render $'序号\t自定义 CIDR' "$(ui_custom_cidr_rows)" "2"
}

ui_menu_whitelist_cidrs_delete() {
    local count raw indexes cidr_indexes resolved_indexes
    count="$(whitelist_custom_cidrs_count)"
    if [ "$count" -eq 0 ]; then
        ui_warn "暂无自定义 CIDR"
        ui_pause
        return 0
    fi
    ui_render_page ui_render_whitelist_cidrs_menu_page
    ui_read "选择 CIDR 序号，可单/多/连续选择；1 表示删除全部" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$((count + 1))" false || return 1
    indexes="$UI_REPLY"
    if printf '%s\n' "$indexes" | grep -qx '1'; then
        ui_run cmd_guard_whitelist_custom clear
        if [ "$UI_STATUS" -eq 0 ]; then
            ui_notice_set "自定义 CIDR 已清空" "$UI_C_MENU_NUM"
            ui_pause
        fi
        return 0
    fi
    resolved_indexes="$(printf '%s\n' "$indexes" | awk '$1 > 1 { print $1 - 1 }')"
    [ -n "$resolved_indexes" ] || { ui_warn "请选择要删除的自定义 CIDR"; return 1; }
    ui_run cmd_guard_whitelist_custom delete $resolved_indexes
    if [ "$UI_STATUS" -eq 0 ]; then
        ui_notice_set "自定义 CIDR 已删除" "$UI_C_MENU_NUM"
        ui_pause
    fi
}

ui_render_whitelist_cidrs_menu_page() {
    ui_header "自定义 CIDR"
    ui_notice_render
    ui_print_custom_cidr_list
    echo
    ui_menu_item 1 "删除所有自定义 CIDR"
    ui_menu_item 2 "增加 CIDR"
    ui_menu_item 3 "删除 CIDR"
    ui_menu_item 4 "修改 CIDR"
    ui_menu_item 0 "返回"
}

ui_menu_whitelist_cidrs() {
    local count selected display_index real_index current_cidr
    while true; do
        ui_render_page ui_render_whitelist_cidrs_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_run cmd_guard_whitelist_custom clear
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "自定义 CIDR 已清空" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            2)
                ui_form_set "增加自定义 CIDR" "输入一个 IPv4 或 IPv6 CIDR；会和允许国内 IP 共同组成白名单。"
                ui_form_read "CIDR" "" || { ui_form_reset; continue; }
                [ -n "$UI_REPLY" ] || { ui_form_reset; ui_warn "必须提供 CIDR"; ui_pause; continue; }
                ui_run cmd_guard_whitelist_custom add "$UI_REPLY"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "自定义 CIDR 已添加" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            3)
                ui_menu_whitelist_cidrs_delete
                ui_maybe_pause success
                ;;
            4)
                count="$(whitelist_custom_cidrs_count)"
                if [ "$count" -eq 0 ]; then
                    ui_warn "暂无自定义 CIDR"
                    ui_pause
                    continue
                fi
                ui_render_page ui_render_whitelist_cidrs_menu_page
                ui_read "选择要修改的 CIDR 序号（2-${count}+1）" || return 0
                [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; ui_pause; continue; }
                display_index="$UI_REPLY"
                [ "$display_index" -ge 2 ] && [ "$display_index" -le $((count + 1)) ] || { ui_warn "序号超出范围"; ui_pause; continue; }
                real_index=$((display_index - 1))
                current_cidr="$(whitelist_custom_cidr_by_index "$real_index")"
                [ -n "$current_cidr" ] || { ui_warn "自定义 CIDR 序号不存在"; ui_pause; continue; }
                ui_form_set "修改自定义 CIDR" "输入新的 IPv4 或 IPv6 CIDR。"
                ui_form_add_kv "当前 CIDR" "$current_cidr"
                ui_form_read "新 CIDR" "$current_cidr" || { ui_form_reset; continue; }
                [ -n "$UI_REPLY" ] || { ui_form_reset; ui_warn "必须提供 CIDR"; ui_pause; continue; }
                ui_run cmd_guard_whitelist_custom update "$real_index" "$UI_REPLY"
                ui_form_reset
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "自定义 CIDR 已更新" "$UI_C_MENU_NUM"
                ui_maybe_pause success
                ;;
            0) return 0 ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
}

ui_render_guard_menu_page() {
    ui_header "流量防护"
    ui_notice_render
    ui_print_guard_summary
    echo
    ui_menu_item 1 "启用 guard"
    ui_menu_item 2 "停用 guard"
    ui_menu_item 3 "设置封锁协议"
    ui_menu_item 4 "跳过端口"
    ui_menu_item 5 "启用白名单"
    ui_menu_item 6 "关闭白名单"
    ui_menu_item 7 "允许国内 IP"
    ui_menu_item 8 "自定义 CIDR"
    ui_menu_item 9 "刷新白名单数据"
    ui_menu_item 0 "返回"
}

ui_render_main_menu_page() {
    ui_title
    ui_notice_render
    ui_print_main_forwards
    echo
    ui_menu_item 1 "用户管理"
    ui_menu_item 2 "转发管理"
    ui_menu_item 3 "流量管理"
    ui_menu_item 4 "Telegram 通知"
    ui_menu_item 5 "流量防护"
    ui_menu_item 6 "配置导入导出"
    ui_menu_item 7 "更新"
    ui_menu_item 8 "卸载"
    ui_menu_item 0 "退出"
}

ui_render_users_menu_page() {
    ui_header "用户管理"
    ui_notice_render
    ui_print_user_list
    echo
    ui_menu_item 1 "添加用户"
    ui_menu_item 2 "删除用户"
    ui_menu_item 0 "返回"
}

ui_render_forwards_menu_page() {
    ui_header "转发管理"
    ui_notice_render
    ui_print_forward_list
    echo
    ui_menu_item 1 "添加转发"
    ui_menu_item 2 "修改转发"
    ui_menu_item 3 "暂停转发"
    ui_menu_item 4 "恢复转发"
    ui_menu_item 5 "删除转发"
    ui_menu_item 0 "返回"
}

ui_render_traffic_user_menu_page() {
    local user_id="$1"
    ui_header "流量管理"
    ui_notice_render
    ui_print_user_traffic_summary "$user_id"
    echo
    ui_menu_item 1 "转发到期日"
    ui_menu_item 2 "端口设置"
    ui_menu_item 3 "流量重置日"
    ui_menu_item 4 "设置已用流量"
    ui_menu_item 0 "返回"
}

ui_render_traffic_select_user_page() {
    ui_header "流量管理"
    ui_notice_render
    ui_print_user_list true
    if ! ui_has_users; then
        echo
        ui_menu_item 0 "返回"
    fi
}

ui_render_telegram_menu_page() {
    ui_header "Telegram 通知"
    ui_notice_render
    ui_print_telegram_configured_users
    echo
    ui_menu_item 1 "配置用户 Telegram"
    ui_menu_item 2 "设置定时发送"
    ui_menu_item 3 "发送测试通知"
    ui_menu_item 4 "恢复通知"
    ui_menu_item 5 "暂停通知"
    ui_menu_item 6 "删除通知"
    ui_menu_item 0 "返回"
}

ui_render_export_import_menu_page() {
    ui_header "配置导入导出"
    ui_notice_render
    ui_print_export_import_summary
    echo
    ui_menu_item 1 "导出配置"
    ui_menu_item 2 "导入配置"
    ui_menu_item 0 "返回"
}

ui_menu_uninstall() {
    ui_clear_screen
    ui_header "卸载"
    echo "步骤 1：停用 pfwd XDP boot restore，只停止并禁用 pfwd-xdp.service。"
    if ui_confirm_text "yes" "输入 yes 确认停用 pfwd-xdp.service，留空跳过"; then
        ui_run service_disable_forwarder
    else
        ui_warn "已跳过停用 pfwd-xdp.service"
    fi
    echo
    echo "步骤 2：完整卸载 pfwd 脚本、systemd、XDP 状态、配置和状态。"
    if ui_confirm_text "uninstall" "输入 uninstall 确认完整卸载"; then
        ui_run cmd_uninstall
    else
        ui_warn "已跳过完整卸载"
    fi
    ui_pause
}

cmd_menu() {
    ui_dependency_preflight
    config_init >/dev/null
    ui_runtime_install_preflight
    ui_detect_color_support
    ui_screen_enter
    trap ui_menu_cleanup EXIT INT TERM
    while true; do
        ui_render_page ui_render_main_menu_page
        if ui_read_timed "选择" "$UI_REFRESH_INTERVAL"; then
            :
        else
            case "$?" in
                124) continue ;;
                *) break ;;
            esac
        fi
        case "$UI_REPLY" in
            1) ui_menu_users ;;
            2) ui_menu_forwards ;;
            3) ui_menu_expire_limit ;;
            4) ui_menu_telegram ;;
            5) ui_menu_guard ;;
            6) ui_menu_export_import ;;
            7) ui_menu_update ;;
            8) ui_menu_uninstall ;;
            0) break ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
    ui_menu_cleanup
}
