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
declare -ag UI_PAGE_LINES=()

ui_main_status_title() {
    ui_color "1;96" "端口转发"
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

ui_notice_render() {
    [ -n "$UI_NOTICE_TEXT" ] || return 0
    ui_print_line "$UI_NOTICE_TEXT" "${UI_NOTICE_COLOR:-36}"
    printf '\n'
}

ui_render_page() {
    local frame status renderer_key previous_key
    frame="$("$@")"
    status=$?
    [ "$status" -eq 0 ] || return "$status"
    renderer_key="$*"
    previous_key="$UI_PAGE_RENDERER_KEY"
    UI_PAGE_RENDERER_KEY="$renderer_key"
    if [ "$renderer_key" != "$previous_key" ]; then
        UI_PAGE_OFFSET=0
    fi
    ui_page_prepare_frame "$frame"
    ui_page_draw
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
    local view_height max_offset start_line end_line i status_text

    ui_page_clamp_offset
    view_height="$(ui_page_view_height)"
    max_offset="$(ui_page_max_offset "$view_height")"
    start_line="$UI_PAGE_OFFSET"
    end_line=$((start_line + view_height))

    ui_clear_screen
    for ((i = start_line; i < end_line && i < UI_PAGE_LINE_COUNT; i++)); do
        printf '%s\n' "${UI_PAGE_LINES[$i]}"
    done

    if [ "$UI_PAGE_SCROLLABLE" = "1" ]; then
        status_text="滚动 $((start_line + 1))-$(( end_line < UI_PAGE_LINE_COUNT ? end_line : UI_PAGE_LINE_COUNT ))/$UI_PAGE_LINE_COUNT  鼠标滚轮/↑↓/PgUp/PgDn/j/k"
        ui_print_line "$status_text" "2;37"
    fi

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
}

ui_page_scroll_lines() {
    local delta="$1"
    UI_PAGE_OFFSET=$((UI_PAGE_OFFSET + delta))
    ui_page_clamp_offset
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

    if [ "$first" = $'\033' ]; then
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
            $'\033[A'|$'\033OA'|$'\033[<64;'*|k)
                ui_page_scroll_lines -1
                current_timeout="$timeout_seconds"
                ;;
            $'\033[B'|$'\033OB'|$'\033[<65;'*|j)
                ui_page_scroll_lines 1
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
    ui_print_line "$line" "2;37"
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
            local state_stop_at="" display_state
            case "${#headers_ref[@]}" in
                6)
                    state_stop_at="${cells_ref[5]:-}"
                    ;;
                7)
                    state_stop_at="${cells_ref[6]:-}"
                    ;;
                9)
                    state_stop_at="${cells_ref[6]:-}"
                    ;;
                11)
                    state_stop_at="${cells_ref[6]:-}"
                    ;;
            esac
            display_state="$(ui_forward_display_state "$cell" "$state_stop_at")"
            rendered="$(ui_forward_state_text "$display_state")"
            UI_CELL_COLOR="$(ui_forward_state_color "$display_state")"
            ui_display_width_value "$rendered"
            if [ -n "$UI_CELL_COLOR" ] && ui_use_color; then
                rendered=$'\033['"${UI_CELL_COLOR}"'m'"$rendered"$'\033[0m'
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
    ui_table_print_row widths headers headers "1;37"
    ui_table_print_border "├" "┼" "┤" "${widths[@]}"
    for line in "${row_lines[@]}"; do
        IFS=$'\t' read -r -a cells <<< "$line"
        ui_table_print_row widths cells headers
    done
    ui_table_print_border "└" "┴" "┘" "${widths[@]}"
}

ui_forward_state_text() {
    case "$1" in
        active|true|启用) printf '●' ;;
        paused|false|停用|暂停) printf '■' ;;
        stopped|停止) printf '■' ;;
        *) printf '■' ;;
    esac
}

ui_forward_state_color() {
    case "$1" in
        active|true|启用) echo "1;32" ;;
        paused|false|停用|暂停) echo "1;33" ;;
        stopped|停止) echo "1;31" ;;
        *) echo "1;33" ;;
    esac
}

ui_forward_display_state() {
    local enabled="$1"
    local stop_at="${2:-}"
    local today
    if [ "$enabled" = "true" ] || [ "$enabled" = "启用" ] || [ "$enabled" = "active" ]; then
        printf 'active'
        return 0
    fi
    today="$(date '+%Y-%m-%d')"
    if [ -n "$stop_at" ] && [ "$stop_at" != "-" ] && [ "$stop_at" != "null" ] && [ "$stop_at" \< "$today" -o "$stop_at" = "$today" ]; then
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
    ui_color "1;36" "== $* =="
    printf '\n'
}

ui_title() {
    printf '\n'
    ui_rule "=" "2;36"
    ui_print_line "pfwd" "1;96"
    ui_main_status_title
    printf '\n'
    ui_print_line "状态总览" "1;37"
    ui_rule "=" "2;36"
    ui_print_line "操作流程：用户 -> 添加转发 -> 流量管理" "36"
    ui_rule "-" "2;37"
}

ui_menu_item() {
    local number="$1"
    local label="$2"
    ui_color "32" "$number."
    printf ' %s\n' "$label"
}

ui_success() {
    ui_color "32" "$*"
    printf '\n'
}

ui_warn() {
    ui_color "33" "$*"
    printf '\n'
}

ui_error() {
    ui_color "31" "$*"
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

ui_pause() {
    [ -t 0 ] || return 0
    printf '按回车继续...'
    IFS= read -r _ || true
}

ui_run() {
    if ( "$@" ); then
        UI_STATUS=0
        return 0
    fi
    UI_STATUS=1
    ui_error "操作失败"
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
    local recommended=""
    local source="fallback"

    UI_MSS_MODE=""
    UI_MSS_VALUE=""

    if [ -n "$remote_host" ]; then
        ui_recommended_mss_value "$remote_host"
        recommended="$UI_MSS_RECOMMENDED"
        source="$UI_MSS_RECOMMEND_SOURCE"
    fi

    echo "1) 不设置"
    echo "   默认值，不主动改 TCP MSS；适合常规公网转发、大多数直连链路。"
    echo "2) MSS Clamp"
    echo "   按路径 MTU 自动调整 TCP MSS；适合 PPPoE、VPN、隧道、跨境链路。"
    echo "3) 固定 MSS"
    echo "   手动写死 TCP MSS；适合已知链路 MTU、上游有统一要求或 clamp 效果不稳定。"
    ui_read "$prompt" "1" || return 1
    case "$UI_REPLY" in
        1|"")
            UI_MSS_MODE=""
            UI_MSS_VALUE=""
            ;;
        2)
            UI_MSS_MODE="clamp"
            UI_MSS_VALUE=""
            ;;
        3)
            UI_MSS_MODE="set"
            if [ -n "$recommended" ]; then
                if [ "$source" = "fallback" ]; then
                    ui_warn "未探测到链路 MTU，已使用通用推荐值：$recommended"
                else
                    ui_print_line "固定 MSS 推荐值：$recommended" "36"
                fi
            fi
            ui_read "固定 MSS 值" "$recommended" || return 1
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
    local prompt="$1"
    local current_mode="$2"
    local current_value="$3"
    local remote_host="${4:-}"
    local recommended="" source="fallback" fixed_default=""

    UI_MSS_MODE=""
    UI_MSS_VALUE=""
    UI_EDIT_ABORTED=0

    ui_recommended_mss_value "$remote_host"
    recommended="$UI_MSS_RECOMMENDED"
    source="$UI_MSS_RECOMMEND_SOURCE"

    echo "1) 不设置"
    echo "   默认值，不主动改 TCP MSS；适合常规公网转发、大多数直连链路。"
    echo "2) MSS Clamp"
    echo "   按路径 MTU 自动调整 TCP MSS；适合 PPPoE、VPN、隧道、跨境链路。"
    echo "3) 固定 MSS"
    echo "   手动写死 TCP MSS；适合已知链路 MTU、上游有统一要求或 clamp 效果不稳定。"
    case "$current_mode" in
        clamp) ui_read "$prompt" "2" || return 1 ;;
        set) ui_read "$prompt" "3" || return 1 ;;
        *) ui_read "$prompt" "1" || return 1 ;;
    esac

    case "$UI_REPLY" in
        0)
            UI_EDIT_ABORTED=1
            return 0
            ;;
        "")
            UI_MSS_MODE=""
            UI_MSS_VALUE=""
            return 0
            ;;
        1)
            UI_MSS_MODE="__CLEAR__"
            UI_MSS_VALUE="__CLEAR__"
            ;;
        2)
            UI_MSS_MODE="clamp"
            UI_MSS_VALUE="__CLEAR__"
            ;;
        3)
            UI_MSS_MODE="set"
            if [ -n "$current_value" ]; then
                fixed_default="$current_value"
                if [ -n "$recommended" ] && [ "$recommended" != "$current_value" ]; then
                    ui_print_line "当前固定 MSS：$current_value；推荐值：$recommended" "36"
                fi
            else
                fixed_default="$recommended"
                if [ -n "$recommended" ]; then
                    if [ "$source" = "fallback" ]; then
                        ui_warn "未探测到链路 MTU，已使用通用推荐值：$recommended"
                    else
                        ui_print_line "固定 MSS 推荐值：$recommended" "36"
                    fi
                fi
            fi
            ui_edit_read "固定 MSS 值" "$fixed_default" || return 1
            [ "$UI_EDIT_ABORTED" = "1" ] && return 0
            [ -n "$UI_REPLY" ] || pfwd_die "固定 MSS 模式必须提供 MSS 值"
            validate_mss_value "$UI_REPLY"
            UI_MSS_VALUE="$UI_REPLY"
            ;;
        *)
            ui_warn "无效选择"
            return 1
            ;;
    esac
}

ui_select_snat_mode() {
    local prompt="$1"
    UI_SNAT_MODE="masquerade"
    UI_SNAT_SOURCE=""

    echo "1) Masquerade"
    echo "   默认值，出站源地址跟随本机出口地址；适合动态公网 IP、普通单出口转发。"
    echo "2) 固定 SNAT 源地址"
    echo "   把出站源地址固定改写为指定 IP；适合本机有额外内网 IP、多地址出口、后端白名单来源 IP。"
    ui_read "$prompt" "1" || return 1
    case "$UI_REPLY" in
        1|"")
            UI_SNAT_MODE="masquerade"
            UI_SNAT_SOURCE=""
            ;;
        2)
            UI_SNAT_MODE="snat"
            ui_read "固定 SNAT 源地址（必须是显式 IP，例如内网 IP）" || return 1
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
    local prompt="$1"
    local current_mode="$2"
    local current_source="$3"

    UI_SNAT_MODE=""
    UI_SNAT_SOURCE=""
    UI_EDIT_ABORTED=0

    echo "1) Masquerade"
    echo "   默认值，出站源地址跟随本机出口地址；适合动态公网 IP、普通单出口转发。"
    echo "2) 固定 SNAT 源地址"
    echo "   把出站源地址固定改写为指定 IP；适合本机有额外内网 IP、多地址出口、后端白名单来源 IP。"
    case "$current_mode" in
        snat) ui_read "$prompt" "2" || return 1 ;;
        *) ui_read "$prompt" "1" || return 1 ;;
    esac
    case "$UI_REPLY" in
        0)
            UI_EDIT_ABORTED=1
            return 0
            ;;
        "")
            UI_SNAT_MODE=""
            UI_SNAT_SOURCE=""
            return 0
            ;;
        1)
            UI_SNAT_MODE="masquerade"
            UI_SNAT_SOURCE="__CLEAR__"
            ;;
        2)
            UI_SNAT_MODE="snat"
            ui_edit_read "固定 SNAT 源地址（必须是显式 IP，例如内网 IP）" "$current_source" || return 1
            [ "$UI_EDIT_ABORTED" = "1" ] && return 0
            [ -n "$UI_REPLY" ] || pfwd_die "固定 SNAT 模式必须提供源地址"
            validate_ip_literal "$UI_REPLY"
            UI_SNAT_SOURCE="$UI_REPLY"
            ;;
        *)
            ui_warn "无效选择"
            return 1
            ;;
    esac
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
    UI_REPLY=""
    echo "1) TCP"
    echo "2) UDP"
    echo "3) 全转发"
    ui_read "$prompt" "3" || return 1
    case "$UI_REPLY" in
        1) UI_REPLY="tcp" ;;
        2) UI_REPLY="udp" ;;
        3|"") UI_REPLY="tcp_udp" ;;
        *) ui_warn "无效选择，已使用全转发"; UI_REPLY="tcp_udp" ;;
    esac
}

ui_select_protocol_edit() {
    local prompt="$1"
    local current_protocol="${2:-tcp_udp}"
    UI_EDIT_ABORTED=0
    UI_REPLY=""
    echo "1) TCP"
    echo "2) UDP"
    echo "3) 全转发"
    case "$current_protocol" in
        tcp) ui_read "$prompt" "1" || return 1 ;;
        udp) ui_read "$prompt" "2" || return 1 ;;
        *) ui_read "$prompt" "3" || return 1 ;;
    esac
    case "$UI_REPLY" in
        0)
            UI_EDIT_ABORTED=1
            return 0
            ;;
        "")
            UI_REPLY=""
            return 0
            ;;
        1) UI_REPLY="tcp" ;;
        2) UI_REPLY="udp" ;;
        3) UI_REPLY="tcp_udp" ;;
        *) ui_warn "无效选择"; return 1 ;;
    esac
}

ui_select_traffic_mode() {
    local prompt="$1"
    local allow_empty="${2:-false}"
    UI_TRAFFIC_MODE=""
    echo "1) 单向"
    echo "2) 双向"
    ui_read "$prompt" "2" || return 1
    if [ "$allow_empty" = "true" ] && [ -z "$UI_REPLY" ]; then
        UI_TRAFFIC_MODE=""
        return 0
    fi
    case "$UI_REPLY" in
        1) UI_TRAFFIC_MODE="one-way" ;;
        2|"") UI_TRAFFIC_MODE="two-way" ;;
        *) ui_warn "无效选择，已使用双向"; UI_TRAFFIC_MODE="two-way" ;;
    esac
}

ui_select_traffic_mode_edit() {
    local prompt="$1"
    local current_mode="${2:-}"
    UI_TRAFFIC_MODE=""
    UI_EDIT_ABORTED=0
    echo "1) 单向"
    echo "2) 双向"
    case "$current_mode" in
        one-way) ui_read "$prompt" "1" || return 1 ;;
        two-way) ui_read "$prompt" "2" || return 1 ;;
        *) ui_read "$prompt" || return 1 ;;
    esac
    case "$UI_REPLY" in
        0)
            UI_EDIT_ABORTED=1
            return 0
            ;;
        "")
            UI_TRAFFIC_MODE=""
            return 0
            ;;
        1) UI_TRAFFIC_MODE="one-way" ;;
        2) UI_TRAFFIC_MODE="two-way" ;;
        *) ui_warn "无效选择"; return 1 ;;
    esac
}

ui_missing_dependencies() {
    local missing=()
    command -v jq >/dev/null 2>&1 || missing+=(jq)
    command -v nft >/dev/null 2>&1 || missing+=(nft)
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
            pfwd_run apt-get install -y jq nftables iproute2 systemd curl tar
            ;;
        dnf)
            pfwd_run dnf install -y jq nftables iproute systemd curl tar
            ;;
        yum)
            pfwd_run yum install -y jq nftables iproute systemd curl tar
            ;;
        pacman)
            pfwd_run pacman -Sy --noconfirm jq nftables iproute2 systemd curl tar
            ;;
        apk)
            pfwd_run apk add jq nftables iproute2 curl tar
            ui_warn "Alpine 默认不提供 systemd/systemctl，pfwd 的服务管理需要 systemd。"
            ;;
        *)
            ui_warn "未识别包管理器，请手动安装 jq、nftables、iproute2、systemd、curl、tar。"
            return 1
            ;;
    esac
}

ui_install_forwarder() {
    ui_info "pfwd 已内置 nft 后端 helper；无需额外安装转发内核。"
}

ui_install_missing_dependencies() {
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

ui_main_usage_json() {
    fw_read_counters
}

ui_forward_usage_json() {
    if ! command -v nft >/dev/null 2>&1; then
        jq -n --slurpfile cfg "$PFWD_CONFIG_FILE" '
          {forwards: ($cfg[0].forwards | map(. + {total_bytes: "-"}))}
        '
        return
    fi
    fw_read_counters
}

ui_print_user_traffic_summary() {
    local user_id="$1"
    local data total_limit used one_way two_way reset_day forward_count rate rows=""
    data="$(fw_read_counters)"
    total_limit="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .limits.traffic_bytes // "null"' "$PFWD_CONFIG_FILE")"
    rate="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .limits.rate // "null"' "$PFWD_CONFIG_FILE")"
    used="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .billing_used_bytes // 0' <<< "$data")"
    one_way="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .one_way_bytes // 0' <<< "$data")"
    two_way="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .two_way_bytes // 0' <<< "$data")"
    reset_day="$(jq -r --arg id "$user_id" '.users[]? | select(.id == $id) | .reset_day // "-"' <<< "$data")"
    forward_count="$(jq -r --arg id "$user_id" '[.forwards[]? | select(.user_id == $id)] | length' "$PFWD_CONFIG_FILE")"
    rows+="用户名"$'\t'"$user_id"$'\n'
    rows+="转发数"$'\t'"${forward_count} 个"$'\n'
    rows+="重置日"$'\t'"$(ui_display_or_dash "$reset_day")"$'\n'
    rows+="总限额"$'\t'"$(ui_format_limit "$total_limit")"$'\n'
    rows+="每端口速率"$'\t'"$(ui_format_rate "$rate")"$'\n'
    rows+="计费用量"$'\t'"$(format_bytes "$used")"$'\n'
    rows+="双向"$'\t'"$(format_bytes "$two_way")"$'\n'
    rows+="单向"$'\t'"$(format_bytes "$one_way")"
    ui_table_render $'项目\t值' "$rows" "2"
}

ui_print_main_user_summary() {
    local data="$1"
    local rows=""
    ui_print_line "用户状态" "1;36"

    if ! jq -e '.users | length > 0' <<< "$data" >/dev/null; then
        ui_print_line "暂无用户，请先到“用户管理”添加用户。"
        return
    fi

    while IFS=$'\t' read -r user count used two_way one_way limit reset_day; do
        rows+="$user"$'\t'"$count"$'\t'"$(format_bytes "$used")"$'\t'"$(format_bytes "$two_way")"$'\t'"$(format_bytes "$one_way")"$'\t'"$(ui_format_limit "$limit")"$'\t'"$(ui_display_or_dash "$reset_day")"$'\n'
    done < <(jq -r --slurpfile cfg "$PFWD_CONFIG_FILE" '
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
    ' <<< "$data")
    rows="${rows%$'\n'}"
    ui_table_render $'用户名\t转发数\t计费用量\t双向\t单向\t总限额\t重置日' "$rows" "1,6,7"
}

ui_render_forward_groups() {
    local rows="$1"
    local headers_tsv="$2"
    local empty_text="$4"
    local current_user="" line user first_group=true
    local enabled="" col3="" col4="" col5="" col6="" col7="" col8="" col9="" col10="" col11=""
    local group_rows="" compact_headers="" compact_shrink="" state_text="" state_color="" display_state="" group_title=""

    if [ -z "$rows" ]; then
        ui_print_line "$empty_text"
        return 0
    fi

    ui_render_forward_group_block() {
        local block_user="$1"
        local block_rows="$2"
        local block_headers="$3"
        local block_shrink="$4"
        local color_column="$5"
        local block_line="" block_enabled="" visible_rows="" color_rows=""

        [ -n "$block_rows" ] || return 0
        ui_print_line "$block_user" "1;36"
        if [ -n "$group_title" ]; then
            ui_print_line "$group_title" "2;37"
        fi
        while IFS= read -r block_line; do
            [ -n "$block_line" ] || continue
            IFS=$'\t' read -r block_enabled _ col3 col4 col5 col6 col7 col8 col9 col10 col11 <<< "$block_line"
            case "$headers_tsv" in
                $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t备注')
                    display_state="$(ui_forward_display_state "$block_enabled" "$col7")"
                    state_text="$(ui_forward_state_text "$display_state")"
                    state_color="$(ui_forward_state_color "$display_state")"
                    visible_rows+="$state_text"$'\t'"$col3"$'\t'"$col4"$'\t'"$col5"$'\t'"$col6"$'\t'"$col7"$'\t'"$(ui_display_or_dash "$col8")"$'\n'
                    color_rows+="$state_color"$'\n'
                    ;;
                $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\tMSS\tSNAT\t备注')
                    display_state="$(ui_forward_display_state "$col6" "$col7")"
                    state_text="$(ui_forward_state_text "$display_state")"
                    state_color="$(ui_forward_state_color "$display_state")"
                    visible_rows+="#$block_enabled"$'\t'"$state_text"$'\t'"$col3"$'\t'"$col4"$'\t'"$col5"$'\t'"$col7"$'\t'"$col8"$'\t'"$col9"$'\t'"$col10"$'\t'"$(ui_display_or_dash "$col11")"$'\n'
                    color_rows+="$state_color"$'\n'
                    ;;
                $'序号\t用户\t监听\t目标\t协议\t状态\t到期')
                    display_state="$(ui_forward_display_state "$col6" "$col7")"
                    state_text="$(ui_forward_state_text "$display_state")"
                    state_color="$(ui_forward_state_color "$display_state")"
                    visible_rows+="#$block_enabled"$'\t'"$state_text"$'\t'"$col3"$'\t'"$col4"$'\t'"$col5"$'\t'"$col7"$'\n'
                    color_rows+="$state_color"$'\n'
                    ;;
                *)
                    ui_forward_line "$block_enabled" "$block_line" "$col7"
                    continue
                    ;;
            esac
        done <<< "$block_rows"
        visible_rows="${visible_rows%$'\n'}"
        color_rows="${color_rows%$'\n'}"
        ui_compact_table_render "$block_headers" "$visible_rows" "$block_shrink" "$color_rows" "$color_column"
    }

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        IFS=$'\t' read -r _ user _ <<< "$line"
        if [ -z "$current_user" ] || [ "$user" != "$current_user" ]; then
            if [ "$first_group" = "false" ]; then
                case "$headers_tsv" in
                    $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t备注')
                        compact_headers=$'状态\t监听\t目标\t上行\t下行\t到期\t备注'
                        compact_shrink="2,3,4,5,6,7"
                        group_title="状态  监听  目标  上行  下行  到期  备注"
                        ;;
                    $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\tMSS\tSNAT\t备注')
                        compact_headers=$'序号\t状态\t监听\t目标\t协议\t到期\t模式\tMSS\tSNAT\t备注'
                        compact_shrink="3,4,6,7,8,9,10"
                        group_title="序号  状态  监听  目标  协议  到期  模式  MSS  SNAT  备注"
                        ;;
                    $'序号\t用户\t监听\t目标\t协议\t状态\t到期')
                        compact_headers=$'序号\t状态\t监听\t目标\t协议\t到期'
                        compact_shrink="3,4,6"
                        group_title="序号  状态  监听  目标  协议  到期"
                        ;;
                    *)
                        compact_headers=""
                        compact_shrink=""
                        group_title=""
                        ;;
                esac
                case "$headers_tsv" in
                    $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t备注')
                        ui_render_forward_group_block "$current_user" "$group_rows" "$compact_headers" "$compact_shrink" "1"
                        ;;
                    *)
                        ui_render_forward_group_block "$current_user" "$group_rows" "$compact_headers" "$compact_shrink" "2"
                        ;;
                esac
                ui_rule "-" "2;37"
            fi
            current_user="$user"
            first_group=false
            group_rows=""
        fi
        group_rows+="$line"$'\n'
    done <<< "$rows"

    group_rows="${group_rows%$'\n'}"
    case "$headers_tsv" in
        $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t备注')
            compact_headers=$'状态\t监听\t目标\t上行\t下行\t到期\t备注'
            compact_shrink="2,3,4,5,6,7"
            group_title="状态  监听  目标  上行  下行  到期  备注"
            ;;
        $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\tMSS\tSNAT\t备注')
            compact_headers=$'序号\t状态\t监听\t目标\t协议\t到期\t模式\tMSS\tSNAT\t备注'
            compact_shrink="3,4,6,7,8,9,10"
            group_title="序号  状态  监听  目标  协议  到期  模式  MSS  SNAT  备注"
            ;;
        $'序号\t用户\t监听\t目标\t协议\t状态\t到期')
            compact_headers=$'序号\t状态\t监听\t目标\t协议\t到期'
            compact_shrink="3,4,6"
            group_title="序号  状态  监听  目标  协议  到期"
            ;;
        *)
            compact_headers=""
            compact_shrink=""
            group_title=""
            ;;
    esac
    case "$headers_tsv" in
        $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t备注')
            ui_render_forward_group_block "$current_user" "$group_rows" "$compact_headers" "$compact_shrink" "1"
            ;;
        *)
            ui_render_forward_group_block "$current_user" "$group_rows" "$compact_headers" "$compact_shrink" "2"
            ;;
    esac
}

ui_print_main_forward_summary() {
    local data="$1"
    local rows=""
    ui_print_line "当前转发" "1;36"

    if ! jq -e '.forwards | length > 0' <<< "$data" >/dev/null; then
        ui_print_line "暂无转发，先按上面的流程添加转发。"
        return
    fi

    while IFS=$'\t' read -r enabled user listen_ip listen_port remote_host remote_port input_bytes output_bytes stop_at comment; do
        local remote_text listen_text
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        listen_text="$(ui_format_listen_compact "$listen_ip" "$listen_port")"
        rows+="$enabled"$'\t'"$user"$'\t'"$listen_text"$'\t'"$remote_text"$'\t'"$(ui_format_bytes_or_dash "$input_bytes")"$'\t'"$(ui_format_bytes_or_dash "$output_bytes")"$'\t'"$(ui_display_or_dash "$stop_at")"$'\t'"$(ui_display_or_dash "$comment")"$'\n'
    done < <(jq -r '
      .forwards
      | sort_by(.user_id, .listen_port, .id)
      | .[]?
      | [
          (if .enabled then "true" else "false" end),
          .user_id,
          (.listen_ip // "::"),
          (.listen_port | tostring),
          .remote_host,
          (.remote_port | tostring),
          (.input_bytes // "0"),
          (.output_bytes // "0"),
          (.stop_at // "-"),
          (if (.comment // "") == "" then "-" else .comment end)
        ]
      | @tsv
    ' <<< "$data")
    rows="${rows%$'\n'}"
    ui_render_forward_groups "$rows" $'状态\t用户\t监听\t目标\t上行\t下行\t到期\t备注' "4,8,2,7,3" "暂无转发，先按上面的流程添加转发。"
}

ui_print_main_forwards() {
    config_init >/dev/null
    local data
    data="$(ui_main_usage_json)"
    ui_print_main_user_summary "$data"
    ui_rule "-" "2;37"
    ui_print_main_forward_summary "$data"
    ui_rule "-" "2;37"
}

ui_print_forward_list() {
    config_init >/dev/null
    local rows=""
    if ! jq -e '.forwards | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        echo "暂无转发"
        return
    fi
    while IFS=$'\t' read -r index user enabled listen_ip listen_port remote_host remote_port protocol stop_at mode mss_display snat_display comment; do
        local listen remote
        listen="$(ui_format_listen_compact "$listen_ip" "$listen_port")"
        remote="$(ui_format_remote "$remote_host" "$remote_port")"
        rows+="$index"$'\t'"$user"$'\t'"$listen"$'\t'"$remote"$'\t'"$(ui_protocol_label "$protocol")"$'\t'"$enabled"$'\t'"$stop_at"$'\t'"$mode"$'\t'"$mss_display"$'\t'"$snat_display"$'\t'"$(ui_display_or_dash "$comment")"$'\n'
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
          (
            if (.value.nft.mss_mode // "") == "set" then
              ((.value.nft.mss_value // "-") | tostring)
            elif (.value.nft.mss_mode // "") == "clamp" then
              "clamp"
            else
              "-"
            end
          ),
          (
            if (.value.nft.snat_mode // "masquerade") == "snat" and (.value.nft.snat_source // "") != "" then
              .value.nft.snat_source
            else
              "masquerade"
            end
          ),
          (if (.value.comment // "") == "" then "-" else .value.comment end)
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE")
    rows="${rows%$'\n'}"
    ui_render_forward_groups "$rows" $'序号\t用户\t监听\t目标\t协议\t状态\t到期\t模式\tMSS\tSNAT\t备注' "4,11,2,7,8,10,3" "暂无转发"
}

ui_print_user_list() {
    local allow_zero="${1:-false}"
    config_init >/dev/null
    local rows="" index=1 user_id
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        echo "暂无用户"
        return
    fi
    if [ "$allow_zero" = "true" ]; then
        rows+=$'0\t返回\n'
    fi
    while IFS= read -r user_id; do
        rows+="$index"$'\t'"$user_id"$'\n'
        index=$((index + 1))
    done < <(jq -r '.users[]?.id' "$PFWD_CONFIG_FILE")
    rows="${rows%$'\n'}"
    ui_table_render $'序号\t用户名' "$rows" "2"
}

ui_select_user() {
    local allow_zero="${1:-false}"
    UI_EDIT_ABORTED=0
    config_init >/dev/null
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "暂无用户，请先添加用户"
        return 1
    fi
    ui_print_user_list "$allow_zero"
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

ui_select_user_for_telegram_config() {
    config_init >/dev/null
    local rows=$'0\t返回\n1\t所有用户'
    local index=2 user_id
    if ! jq -e '.users | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "暂无用户，请先添加用户"
        return 1
    fi
    while IFS= read -r user_id; do
        rows+=$'\n'"$index"$'\t'"$user_id"
        index=$((index + 1))
    done < <(jq -r '.users[]?.id' "$PFWD_CONFIG_FILE")
    ui_table_render $'序号\t用户' "$rows" "2"
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
        ui_warn "暂无用户，请先添加用户"
        return 1
    fi
    local count raw indexes user_ids
    count="$(jq '.users | length' "$PFWD_CONFIG_FILE")"
    ui_print_user_list "$allow_zero"
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
        ui_warn "暂无转发，请先添加转发"
        return 1
    fi
    local count raw indexes forward_ids
    count="$(jq '.forwards | length' "$PFWD_CONFIG_FILE")"
    ui_select_forward_table "$allow_zero"
    ui_read "选择转发序号，可多选：1,3,5 或 1-3" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$count" "$allow_zero" || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    forward_ids="$(ui_resolve_forward_ids_by_indexes "$indexes")"
    [ -n "$forward_ids" ] || { ui_warn "转发序号不存在"; return 1; }
    UI_REPLY="$forward_ids"
}

ui_batch_print_result() {
    local ok="$1"
    local fail="$2"
    ui_print_line "完成：成功 $ok 项，失败 $fail 项" "36"
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
    local count raw indexes forward_ids
    count="$(jq -r --arg id "$user_id" '[.forwards[] | select(.user_id == $id)] | length' "$PFWD_CONFIG_FILE")"
    ui_select_user_forward_table "$user_id" "$allow_zero"
    ui_read "选择转发序号，可多选：1,3,5 或 1-3" || return 1
    raw="$UI_REPLY"
    ui_multiselect_parse_indexes "$raw" "$count" "$allow_zero" || return 1
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    indexes="$UI_REPLY"
    forward_ids="$(ui_resolve_user_forward_ids_by_indexes "$user_id" "$indexes")"
    [ -n "$forward_ids" ] || { ui_warn "转发序号不存在"; return 1; }
    UI_REPLY="$forward_ids"
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
    local rows=""
    ui_print_line "已配置用户" "1;36"
    if ! jq -e '[.users[]? | select((.telegram.bot_token // "") != "" and (.telegram.chat_id // "") != "")] | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_print_line "暂无已配置用户"
        return
    fi

    while IFS=$'\t' read -r user_id status schedule_text; do
        rows+="$user_id"$'\t'"$status"$'\t'"$schedule_text"$'\n'
    done < <(jq -r '
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
    ' "$PFWD_CONFIG_FILE")
    rows="${rows%$'\n'}"
    ui_table_render $'用户\t状态\t定时发送' "$rows" "1,3"
}

ui_select_forward_table() {
    local allow_zero="${1:-false}"
    config_init >/dev/null
    local rows=""
    if ! jq -e '.forwards | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "暂无转发，请先添加转发"
        return 1
    fi
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
    rows="${rows%$'\n'}"
    ui_render_forward_groups "$rows" $'序号\t用户\t监听\t目标\t协议\t状态\t到期' "4,2,7,3" "暂无转发，请先添加转发"
}

ui_select_forward() {
    local allow_zero="${1:-false}"
    UI_EDIT_ABORTED=0
    ui_select_forward_table "$allow_zero" || return 1
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
    local rows=""
    if ! jq -e --arg id "$user_id" '[.forwards[]? | select(.user_id == $id)] | length > 0' "$PFWD_CONFIG_FILE" >/dev/null; then
        ui_warn "该用户暂无转发"
        return 1
    fi
    if [ "$allow_zero" = "true" ]; then
        rows+=$'0\t返回\t-\t-\t-\t-\n'
    fi
    while IFS=$'\t' read -r index listen_port remote_host remote_port protocol enabled stop_at; do
        local remote_text
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        rows+="$index"$'\t'"$listen_port"$'\t'"$remote_text"$'\t'"$(ui_protocol_label "$protocol")"$'\t'"$enabled"$'\t'"$stop_at"$'\n'
    done < <(jq -r --arg id "$user_id" '
      ([.forwards[] | select(.user_id == $id)] | sort_by(.listen_port, .id))
      | to_entries[]
      | [
          ((.key + 1) | tostring),
          (.value.listen_port | tostring),
          .value.remote_host,
          (.value.remote_port | tostring),
          (.value.protocol // "tcp_udp"),
          (if .value.enabled then "启用" else "停用" end),
          (.value.stop_at // "-")
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE")
    rows="${rows%$'\n'}"
    ui_table_render $'序号\t监听\t目标\t协议\t状态\t到期' "$rows" "3,6,2"
}

ui_select_user_forward() {
    local user_id="$1"
    local allow_zero="${2:-false}"
    UI_EDIT_ABORTED=0
    ui_select_user_forward_table "$user_id" "$allow_zero" || return 1
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
                    ui_notice_set "用户已添加：$UI_REPLY" "32"
                fi
                ui_maybe_pause success
                ;;
            2)
                ui_select_users_multi true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local user_ids="$UI_REPLY" user_list=""
                while IFS= read -r user_id; do
                    [ -n "$user_id" ] || continue
                    user_list+="${user_id}"$'\n'
                done <<< "$user_ids"
                user_list="${user_list%$'\n'}"
                ui_print_line "将删除以下用户：" "33"
                printf '%s\n' "$user_list"
                if ui_confirm_text "delete" "输入 delete 确认批量删除"; then
                    local ok=0 fail=0
                    while IFS= read -r user_id; do
                        [ -n "$user_id" ] || continue
                        if cmd_user delete "$user_id"; then
                            ok=$((ok + 1))
                        else
                            fail=$((fail + 1))
                            ui_error "删除失败：$user_id"
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
    local user_id remote_host remote_port remote listen_ip listen_port random_range stop_at protocol traffic_mode comment args=()
    ui_clear_screen
    ui_header "添加转发"
    echo "支持单端口、多端口：443,553 或 连续段：1000-1005；监听端口和目标端口数量需一致。"
    ui_select_user true || return 0
    [ "$UI_EDIT_ABORTED" = "1" ] && return 0
    user_id="$UI_REPLY"
    ui_read "目标 IP/域名" || return 0
    remote_host="$UI_REPLY"
    ui_read "目标端口" || return 0
    remote_port="$UI_REPLY"
    remote="$(ui_join_remote "$remote_host" "$remote_port")"
    ui_read "监听 IP，留空默认双栈" "$(ui_config_value '.settings.default_listen_ip // "::"')" || return 0
    listen_ip="$UI_REPLY"
    ui_read "固定监听端口，留空则使用随机端口" || return 0
    listen_port="$UI_REPLY"
    if [ -z "$listen_port" ]; then
        ui_read "随机端口范围" "$(ui_config_value '.settings.default_random_port_range // "20000-30000"')" || return 0
        random_range="$UI_REPLY"
    else
        random_range=""
    fi
    ui_read "到期日期 YYYYMMDD，支持 +7/7d，留空不限期" || return 0
    stop_at="$UI_REPLY"
    ui_select_protocol "转发协议" || return 0
    protocol="$UI_REPLY"
    ui_select_traffic_mode "流量模式" || return 0
    traffic_mode="$UI_TRAFFIC_MODE"
    ui_read "备注，留空不设置" || return 0
    comment="$UI_REPLY"
    ui_select_mss_mode "MSS 处理方式" "$remote_host" || return 0
    ui_select_snat_mode "SNAT 处理方式" || return 0

    args=(--user-id "$user_id" --remote "$remote" --listen-ip "$listen_ip" --protocol "$protocol" --traffic-mode "$traffic_mode")
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

    ui_run cmd_add "${args[@]}"
}

ui_menu_forwards() {
    while true; do
        ui_render_page ui_render_forwards_menu_page
        ui_read "选择" || return 0
        case "$UI_REPLY" in
            1)
                ui_menu_add_forward
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "转发已添加" "32"
                ui_maybe_pause success
                ;;
            2)
                ui_select_forward true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local forward_id="$UI_REPLY" current="" current_listen_ip="" current_listen_port="" current_remote_host="" current_remote_port="" current_stop_at="" current_protocol="" current_mode="" current_comment=""
                local current_mss_mode="" current_mss_value="" current_snat_mode="" current_snat_source=""
                local listen_ip="" listen_port="" remote_host="" remote_port="" stop_at="" protocol="" traffic_mode="" comment="" args=()
                current="$(jq -c --arg id "$forward_id" '.forwards[] | select(.id == $id)' "$PFWD_CONFIG_FILE")"
                current_listen_ip="$(jq -r '.listen_ip // "::"' <<< "$current")"
                current_listen_port="$(jq -r '.listen_port' <<< "$current")"
                current_remote_host="$(jq -r '.remote_host' <<< "$current")"
                current_remote_port="$(jq -r '.remote_port' <<< "$current")"
                current_stop_at="$(jq -r '.stop_at // ""' <<< "$current")"
                current_protocol="$(jq -r '.protocol // "tcp_udp"' <<< "$current")"
                current_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$current")"
                current_comment="$(jq -r '.comment // ""' <<< "$current")"
                current_mss_mode="$(jq -r '.nft.mss_mode // ""' <<< "$current")"
                current_mss_value="$(jq -r '.nft.mss_value // ""' <<< "$current")"
                current_snat_mode="$(jq -r '.nft.snat_mode // "masquerade"' <<< "$current")"
                current_snat_source="$(jq -r '.nft.snat_source // ""' <<< "$current")"

                ui_clear_screen
                ui_header "修改转发"
                echo "回车保留当前值，0 返回上级，转发到期日输入 - 清空为不限期，备注输入 - 清空。"

                ui_edit_read "监听 IP" "$current_listen_ip" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                listen_ip="$UI_REPLY"

                ui_edit_read "监听端口" "$current_listen_port" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                listen_port="$UI_REPLY"

                ui_edit_read "目标 IP/域名" "$current_remote_host" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                remote_host="$UI_REPLY"

                ui_edit_read "目标端口" "$current_remote_port" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                remote_port="$UI_REPLY"

                ui_edit_read "转发到期日 YYYYMMDD，支持 +7/7d" "${current_stop_at:-}" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                stop_at="$UI_REPLY"

                ui_select_protocol_edit "转发协议" "$current_protocol" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                protocol="$UI_REPLY"

                ui_select_traffic_mode_edit "流量模式" "$current_mode" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                traffic_mode="$UI_TRAFFIC_MODE"

                ui_edit_read "备注" "$current_comment" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                comment="$UI_REPLY"

                ui_select_mss_mode_edit "MSS 处理方式" "$current_mss_mode" "$current_mss_value" "$remote_host" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                ui_select_snat_mode_edit "SNAT 处理方式" "$current_snat_mode" "$current_snat_source" || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }

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
                    ui_run cmd_forward_update "${args[@]}"
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "转发已更新：$forward_id" "32"
                fi
                ui_maybe_pause success
                ;;
            3)
                ui_select_forwards_multi || { ui_pause; continue; }
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
                ui_select_forwards_multi || { ui_pause; continue; }
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
                ui_select_forwards_multi || { ui_pause; continue; }
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
                ui_print_line "将删除以下转发：" "33"
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
    while true; do
        ui_render_page ui_render_traffic_select_user_page
        ui_read "选择用户序号" || return 0
        case "$UI_REPLY" in
            0) return 0 ;;
            '')
                ui_warn "无效序号"
                ui_pause
                continue
                ;;
        esac
        [[ "$UI_REPLY" =~ ^[0-9]+$ ]] || { ui_warn "无效序号"; ui_pause; continue; }
        local user_id
        user_id="$(jq -r --argjson idx "$UI_REPLY" '.users[$idx - 1].id // ""' "$PFWD_CONFIG_FILE")"
        [ -n "$user_id" ] || { ui_warn "用户序号不存在"; ui_pause; continue; }
        while true; do
            ui_render_page ui_render_traffic_user_menu_page "$user_id"
            ui_read "选择" || return 0
            case "$UI_REPLY" in
                1)
                    local scope="" current_stop_at=""
                    ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    scope="$UI_REPLY"
                    if [[ "$scope" == user:* ]]; then
                        ui_edit_read "转发到期日 YYYYMMDD，支持 +7/7d，输入 - 清空" || { ui_pause; continue; }
                        [ "$UI_EDIT_ABORTED" = "1" ] && { ui_warn "已取消"; ui_pause; continue; }
                        if [ -z "$UI_REPLY" ]; then
                            ui_warn "未修改"
                        elif [ "$UI_REPLY" = "-" ]; then
                            ui_run cmd_expire user-clear --user-id "${scope#user:}"
                        else
                            ui_run cmd_expire user-set --user-id "${scope#user:}" --stop-at "$UI_REPLY"
                        fi
                    else
                        ui_edit_read "转发到期日 YYYYMMDD，支持 +7/7d，输入 - 清空" || { ui_pause; continue; }
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
                    ui_maybe_pause success
                    ;;
                2)
                    local scope="" traffic="" rate="" args=() current_mode="" traffic_mode="" current_scope_mode=""
                    ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    scope="$UI_REPLY"
                    if [[ "$scope" == user:* ]]; then
                        ui_read "用户总流量，数字默认 GB；例如 100 / 1.5GB / 512MB；0 清除，留空不改" || continue
                    else
                        ui_read "总流量，数字默认 GB；例如 100 / 1.5GB / 512MB；0 清除，留空不改" || continue
                    fi
                    traffic="$UI_REPLY"
                    if [[ "$scope" == user:* ]]; then
                        ui_read "每个端口速率，数字默认 Mbps；例如 50 / 12.5Mbps / 1.2Gbps；0 清除，留空不改" || continue
                    else
                        ui_read "速率，数字默认 Mbps；例如 50 / 12.5Mbps / 1.2Gbps；0 清除，留空不改" || continue
                    fi
                    rate="$UI_REPLY"
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
                    ui_maybe_pause success
                    ;;
                3)
                    echo "1) 立即重置"
                    echo "2) 设置每月重置日"
                    echo "0) 返回"
                    ui_read "选择" || continue
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
                                ui_pause
                                continue
                            fi
                            ui_run cmd_traffic reset-now "${args[@]}"
                            ;;
                        2)
                            ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                            [ "$UI_EDIT_ABORTED" = "1" ] && continue
                            scope="$UI_REPLY"
                            ui_read "每月重置日 1-31；0 关闭自动重置" || continue
                            local day="$UI_REPLY"
                            if [ -z "$day" ]; then
                                ui_warn "未修改"
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
                                ui_pause
                                continue
                            fi
                            ui_run cmd_traffic reset-day "${args[@]}"
                            ;;
                        0)
                            continue
                            ;;
                        *) ui_warn "无效选择" ;;
                    esac
                    ui_maybe_pause success
                    ;;
                4)
                    local scope="" used="" args=()
                    ui_select_traffic_scope "$user_id" || { ui_pause; continue; }
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    scope="$UI_REPLY"
                    ui_edit_read "已用流量，数字默认 GB；例如 100 / 100GB / 512MB" || continue
                    [ "$UI_EDIT_ABORTED" = "1" ] && continue
                    used="$UI_REPLY"
                    if [ -z "$used" ]; then
                        ui_warn "未修改"
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
                        ui_pause
                        continue
                    fi
                    ui_run cmd_traffic "${args[@]}"
                    ui_maybe_pause success
                    ;;
                0) return 0 ;;
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
                ui_select_user_for_telegram_config || { ui_pause; continue; }
                [ "${UI_EDIT_ABORTED:-0}" = "1" ] && continue
                local user_id="$UI_REPLY" token="" chat_id="" server_name="" enabled="" tg="" token_default="" chat_id_default="" server_name_default=""
                if [ "$user_id" = "__ALL_USERS__" ]; then
                    token_default=""
                    chat_id_default=""
                    server_name_default="$(hostname 2>/dev/null || echo pfwd)"
                    enabled="__KEEP__"
                else
                    tg="$(ui_user_telegram_config "$user_id")"
                    enabled="$(jq -r '.enabled // false' <<< "$tg")"
                    token_default="$(jq -r '.bot_token // ""' <<< "$tg")"
                    chat_id_default="$(jq -r '.chat_id // ""' <<< "$tg")"
                    server_name_default="$(ui_user_telegram_server_name_default "$(jq -r '.server_name // ""' <<< "$tg")")"
                fi
                ui_read "Bot Token，例如 123456789:AA..." "$token_default" || continue
                token="$UI_REPLY"
                ui_read "Chat ID，例如 123456789 或 -1001234567890" "$chat_id_default" || continue
                chat_id="$UI_REPLY"
                ui_read "服务器名称" "$server_name_default" || continue
                server_name="$UI_REPLY"
                if [ "$user_id" = "__ALL_USERS__" ]; then
                    ui_run cmd_user telegram --all --bot-token "$token" --chat-id "$chat_id" --server-name "$server_name"
                else
                    ui_run cmd_user telegram "$user_id" --bot-token "$token" --chat-id "$chat_id" --server-name "$server_name" --enabled "$enabled"
                fi
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "Telegram 配置已更新" "32"
                ui_maybe_pause success
                ;;
            2)
                ui_select_user true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local schedule_user="$UI_REPLY" interval_choice="" interval_value="" daily_time=""
                echo "留空表示不修改；输入 0 可清除对应定时。"
                ui_read "间隔发送，单位分钟；例如 60" || continue
                interval_choice="$UI_REPLY"
                ui_read "每日发送时间 HH:MM；例如 09:30" || continue
                daily_time="$UI_REPLY"
                if [ "$interval_choice" = "0" ]; then
                    interval_value=""
                else
                    interval_value="${interval_choice:-__KEEP__}"
                fi
                if [ "$daily_time" = "0" ]; then
                    daily_time=""
                elif [ -z "$daily_time" ]; then
                    daily_time="__KEEP__"
                fi
                ui_run cmd_notify_schedule --user-id "$schedule_user" --interval-minutes "$interval_value" --daily-time "$daily_time"
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "定时发送已更新：$schedule_user" "32"
                ui_maybe_pause success
                ;;
            3)
                ui_select_users_multi true || { ui_pause; continue; }
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
                        ui_error "启用通知失败：$user_id"
                    fi
                done <<< "$enable_ids"
                ui_batch_print_result "$ok" "$fail"
                ui_notice_set "启用通知完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
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
                        ui_error "停用通知失败：$user_id"
                    fi
                done <<< "$disable_ids"
                ui_batch_print_result "$ok" "$fail"
                ui_notice_set "停用通知完成：成功 $ok 项，失败 $fail 项" "$( [ "$fail" -gt 0 ] && echo 33 || echo 32 )"
                ui_maybe_pause success
                ;;
            6)
                ui_select_users_multi true || { ui_pause; continue; }
                [ "$UI_EDIT_ABORTED" = "1" ] && continue
                local delete_ids="$UI_REPLY"
                ui_print_line "将删除以下通知配置：" "33"
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
                [ "$UI_STATUS" -eq 0 ] && ui_notice_set "配置已导出：$UI_REPLY" "32"
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
                    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "配置已导入：$import_path" "32"
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
    [ "$UI_STATUS" -eq 0 ] && ui_notice_set "pfwd 已更新" "32"
    ui_maybe_pause success
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
    ui_menu_item 5 "配置导入导出"
    ui_menu_item 6 "更新"
    ui_menu_item 7 "卸载"
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
}

ui_render_telegram_menu_page() {
    ui_header "Telegram 通知"
    ui_notice_render
    ui_print_telegram_configured_users
    echo
    ui_menu_item 1 "配置用户 Telegram"
    ui_menu_item 2 "设置定时发送"
    ui_menu_item 3 "发送测试通知"
    ui_menu_item 4 "启用通知"
    ui_menu_item 5 "停用通知"
    ui_menu_item 6 "删除通知"
    ui_menu_item 0 "返回"
}

ui_render_export_import_menu_page() {
    ui_header "配置导入导出"
    ui_notice_render
    echo "当前配置：$PFWD_CONFIG_FILE"
    echo "当前状态：$PFWD_STATS_FILE"
    echo "导出会包含主配置和流量状态；导入会覆盖当前内容。"
    echo
    ui_menu_item 1 "导出配置"
    ui_menu_item 2 "导入配置"
    ui_menu_item 0 "返回"
}

ui_menu_uninstall() {
    ui_clear_screen
    ui_header "卸载"
    echo "步骤 1：停用 pfwd boot restore，只停止并禁用 pfwd-forward.service。"
    if ui_confirm_text "yes" "输入 yes 确认停用 pfwd-forward.service，留空跳过"; then
        ui_run service_disable_forwarder
    else
        ui_warn "已跳过停用 pfwd-forward.service"
    fi
    echo
    echo "步骤 2：完整卸载 pfwd 脚本、systemd、nftables、配置和状态。"
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
            5) ui_menu_export_import ;;
            6) ui_menu_update ;;
            7) ui_menu_uninstall ;;
            0) break ;;
            *) ui_warn "无效选择"; ui_pause ;;
        esac
    done
    ui_menu_cleanup
}
