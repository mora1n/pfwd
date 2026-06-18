#!/usr/bin/env bash

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
