#!/usr/bin/env bash

validate_user_id() {
    local value="$1"
    value="$(normalize_user_id "$value")"
    [ -n "$value" ] || pfwd_die "用户名不能为空"
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]] || pfwd_die "无效用户名：不能包含控制字符"
}

normalize_user_id() {
    local value="$1"
    value="$(printf '%s' "$value" | sed 's/[[:space:]]*$//')"
    printf '%s' "$value"
}

validate_port() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] || pfwd_die "无效端口：$value"
    [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || pfwd_die "端口超出范围：$value"
}

validate_port_range() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+-[0-9]+$ ]] || pfwd_die "无效端口范围：$value"
    local start="${value%-*}"
    local end="${value#*-}"
    validate_port "$start"
    validate_port "$end"
    [ "$start" -le "$end" ] || pfwd_die "端口范围顺序错误：$value"
}

expand_port_spec() {
    local value token start end port
    value="$(printf '%s' "$1" | tr -d '[:space:]')"
    [ -n "$value" ] || pfwd_die "端口不能为空"
    case "$value" in
        ,*|*,|*,,*) pfwd_die "无效端口列表：$1" ;;
    esac

    IFS=',' read -ra tokens <<< "$value"
    for token in "${tokens[@]}"; do
        [ -n "$token" ] || pfwd_die "无效端口列表：$1"
        if [[ "$token" == *-* ]]; then
            validate_port_range "$token"
            start="${token%-*}"
            end="${token#*-}"
            for ((port = start; port <= end; port++)); do
                echo "$port"
            done
        else
            validate_port "$token"
            echo "$token"
        fi
    done
}

validate_date() {
    local value="$1"
    normalize_date_input "$value" >/dev/null
}

normalize_date_input() {
    local value="$1"
    local normalized=""
    value="$(printf '%s' "$value" | tr -d '[:space:]')"
    [ -n "$value" ] || pfwd_die "日期不能为空"

    if [[ "$value" =~ ^[0-9]{8}$ ]]; then
        normalized="${value:0:4}-${value:4:2}-${value:6:2}"
    elif [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        normalized="$value"
    elif [[ "$value" =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}$ ]]; then
        normalized="${value//\//-}"
    elif [[ "$value" =~ ^\+([0-9]+)$ ]]; then
        normalized="$(date -d "+${BASH_REMATCH[1]} days" '+%Y-%m-%d' 2>/dev/null)" || pfwd_die "无效日期：$value"
    elif [[ "$value" =~ ^([0-9]+)[dD]$ ]]; then
        normalized="$(date -d "+${BASH_REMATCH[1]} days" '+%Y-%m-%d' 2>/dev/null)" || pfwd_die "无效日期：$value"
    else
        pfwd_die "无效日期：$value，支持 YYYYMMDD、YYYY-MM-DD、YYYY/MM/DD、+7、7d"
    fi

    local checked
    checked="$(date -d "$normalized" '+%Y-%m-%d' 2>/dev/null)" || pfwd_die "无效日期：$value"
    [ "$checked" = "$normalized" ] || pfwd_die "无效日期：$value"
    echo "$normalized"
}

validate_traffic_mode() {
    local value="$1"
    case "$value" in
        one-way|two-way) ;;
        *) pfwd_die "无效流量统计模式：$value" ;;
    esac
}

validate_traffic_ratio() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]] || pfwd_die "无效流量倍率：$value"
    awk -v value="$value" 'BEGIN { exit !(value > 0) }' || pfwd_die "流量倍率必须大于 0：$value"
}

validate_forward_protocol() {
    local value="$1"
    case "$value" in
        tcp|udp|tcp_udp) ;;
        *) pfwd_die "无效转发协议：$value" ;;
    esac
}

validate_listen_ip() {
    local value="$1"
    case "$value" in
        ""|"::"|"0.0.0.0") ;;
        *)
            pfwd_die "当前 nft 后端仅支持通配监听地址（:: 或 0.0.0.0），不支持具体 listen_ip：$value"
            ;;
    esac
}

validate_mss_mode() {
    local value="$1"
    case "$value" in
        ""|clamp|set) ;;
        *) pfwd_die "无效 MSS 模式：$value" ;;
    esac
}

validate_mss_value() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] || pfwd_die "无效 MSS 值：$value"
    [ "$value" -ge 536 ] && [ "$value" -le 65535 ] || pfwd_die "MSS 超出范围：$value"
}

validate_snat_mode() {
    local value="$1"
    case "$value" in
        masquerade|snat) ;;
        *) pfwd_die "无效 SNAT 模式：$value" ;;
    esac
}

validate_ip_literal() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$value" == *:* ]] || pfwd_die "需要显式 IP 地址：$value"
}

forward_protocols_conflict() {
    local left="$1"
    local right="$2"
    validate_forward_protocol "$left"
    validate_forward_protocol "$right"
    if [ "$left" = "tcp_udp" ] || [ "$right" = "tcp_udp" ] || [ "$left" = "$right" ]; then
        return 0
    fi
    return 1
}

validate_host_port() {
    local value="$1"
    local parsed host port
    parsed="$(parse_host_port "$value")"
    host="${parsed%	*}"
    port="${parsed##*	}"
    [ -n "$host" ] || pfwd_die "远端主机不能为空"
    validate_port "$port"
}

validate_host_port_spec() {
    local value="$1"
    local parsed host ports
    parsed="$(parse_host_port_spec "$value")"
    host="${parsed%	*}"
    ports="${parsed##*	}"
    [ -n "$host" ] || pfwd_die "远端主机不能为空"
    expand_port_spec "$ports" >/dev/null
}

parse_host_port() {
    local value="$1"
    local host port rest
    if [[ "$value" == \[* ]]; then
        rest="${value#\[}"
        if [[ "$rest" != *\]:* ]]; then
            pfwd_die "IPv6 远端地址必须使用 [IPv6]:PORT"
        fi
        host="${rest%%\]:*}"
        port="${rest##*\]:}"
        [ -n "$host" ] || pfwd_die "远端主机不能为空"
    else
        [[ "$value" == *:* ]] || pfwd_die "远端地址必须是 HOST:PORT"
        host="${value%:*}"
        port="${value##*:}"
        if [[ "$host" == *:* ]]; then
            pfwd_die "IPv6 远端地址必须使用 [IPv6]:PORT"
        fi
    fi
    [ -n "$port" ] || pfwd_die "远端端口不能为空"
    validate_port "$port"
    printf '%s\t%s\n' "$host" "$port"
}

parse_host_port_spec() {
    local value="$1"
    local host ports rest
    if [[ "$value" == \[* ]]; then
        rest="${value#\[}"
        if [[ "$rest" != *\]:* ]]; then
            pfwd_die "IPv6 远端地址必须使用 [IPv6]:PORT"
        fi
        host="${rest%%\]:*}"
        ports="${rest##*\]:}"
        [ -n "$host" ] || pfwd_die "远端主机不能为空"
    else
        [[ "$value" == *:* ]] || pfwd_die "远端地址必须是 HOST:PORT"
        host="${value%:*}"
        ports="${value##*:}"
        if [[ "$host" == *:* ]]; then
            pfwd_die "IPv6 远端地址必须使用 [IPv6]:PORT"
        fi
    fi
    [ -n "$ports" ] || pfwd_die "远端端口不能为空"
    expand_port_spec "$ports" >/dev/null
    printf '%s\t%s\n' "$host" "$ports"
}

validate_bool() {
    local value="$1"
    case "$value" in
        true|false) ;;
        *) pfwd_die "无效布尔值：$value" ;;
    esac
}

validate_reset_day() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] || pfwd_die "无效重置日：$value"
    [ "$value" -ge 0 ] && [ "$value" -le 31 ] || pfwd_die "重置日必须是 0-31：$value"
}

validate_telegram_bot_token() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+:[A-Za-z0-9_-]{30,}$ ]] || pfwd_die "Telegram Bot Token 格式无效"
}

validate_telegram_chat_id() {
    local value="$1"
    [[ "$value" =~ ^-?[0-9]+$ ]] || pfwd_die "Telegram Chat ID 格式无效"
}

validate_telegram_schedule_interval() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] || pfwd_die "定时发送间隔必须是正整数分钟"
    [ "$value" -ge 1 ] || pfwd_die "定时发送间隔必须大于 0 分钟"
}

validate_hhmm_time() {
    local value="$1"
    [[ "$value" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || pfwd_die "每日发送时间格式无效，必须是 HH:MM"
}

parse_size_bytes() {
    local raw="$1"
    local value unit multiplier
    raw="$(echo "$raw" | tr -d ' ' | tr '[:lower:]' '[:upper:]')"
    if [ "$raw" = "0" ]; then
        echo "null"
        return
    fi
    [[ "$raw" =~ ^([0-9]+([.][0-9]+)?)(B|KB|MB|GB|TB)?$ ]] || pfwd_die "无效流量大小：$1"
    value="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[3]:-B}"
    case "$unit" in
        B) multiplier=1 ;;
        KB) multiplier=1024 ;;
        MB) multiplier=$((1024 * 1024)) ;;
        GB) multiplier=$((1024 * 1024 * 1024)) ;;
        TB) multiplier=$((1024 * 1024 * 1024 * 1024)) ;;
        *) pfwd_die "无效流量单位：$1" ;;
    esac
    awk -v value="$value" -v multiplier="$multiplier" 'BEGIN { printf "%.0f\n", value * multiplier }'
}

normalize_ui_traffic_input() {
    local raw="$1"
    raw="$(printf '%s' "$raw" | tr -d ' ')"
    [ -n "$raw" ] || return 0
    if [ "$raw" = "0" ]; then
        echo "0"
        return 0
    fi
    if [[ "$raw" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        echo "${raw}GB"
        return 0
    fi
    raw="$(printf '%s' "$raw" | tr '[:lower:]' '[:upper:]')"
    if [[ "$raw" =~ ^[0-9]+([.][0-9]+)?(B|KB|MB|GB|TB)$ ]]; then
        echo "$raw"
        return 0
    fi
    if [[ "$raw" =~ ^([0-9]+([.][0-9]+)?)(K|M|G|T)$ ]]; then
        echo "${BASH_REMATCH[1]}${BASH_REMATCH[3]}B"
        return 0
    fi
    pfwd_die "无效流量大小：$1；支持数字(默认GB)或小数 + B/KB/MB/GB/TB"
}

normalize_rate() {
    local raw="$1"
    raw="$(echo "$raw" | tr -d ' ' | tr '[:upper:]' '[:lower:]')"
    if [ "$raw" = "0" ]; then
        echo ""
        return
    fi
    [[ "$raw" =~ ^([0-9]+([.][0-9]+)?)(k|kbps|kbit|m|mbps|mbit|g|gbps|gbit)$ ]] || pfwd_die "无效速率：$1"
    local value="${BASH_REMATCH[1]}"
    local unit="${BASH_REMATCH[3]}"
    case "$unit" in
        k|kbps|kbit) echo "${value}kbit" ;;
        m|mbps|mbit) echo "${value}mbit" ;;
        g|gbps|gbit) echo "${value}gbit" ;;
        *) pfwd_die "无效速率：$1" ;;
    esac
}

normalize_ui_rate_input() {
    local raw="$1"
    raw="$(printf '%s' "$raw" | tr -d ' ')"
    [ -n "$raw" ] || return 0
    if [ "$raw" = "0" ]; then
        echo "0"
        return 0
    fi
    if [[ "$raw" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        echo "${raw}Mbps"
        return 0
    fi
    raw="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
    if [[ "$raw" =~ ^[0-9]+([.][0-9]+)?(k|m|g|kbps|mbps|gbps|kbit|mbit|gbit)$ ]]; then
        case "$raw" in
            *kbps|*mbps|*gbps|*kbit|*mbit|*gbit) echo "$raw" ;;
            *k) echo "${raw%k}kbps" ;;
            *m) echo "${raw%m}mbps" ;;
            *g) echo "${raw%g}gbps" ;;
        esac
        return 0
    fi
    pfwd_die "无效速率：$1；支持数字(默认Mbps)或小数 + K/M/G、Kbps/Mbps/Gbps"
}

normalize_traffic_ratio_input() {
    local raw="$1"
    raw="$(printf '%s' "$raw" | tr -d '[:space:]')"
    [ -n "$raw" ] || return 0
    validate_traffic_ratio "$raw"
    awk -v value="$raw" 'BEGIN {
        formatted = sprintf("%.6f", value + 0)
        sub(/0+$/, "", formatted)
        sub(/[.]$/, "", formatted)
        if (formatted == "") formatted = "1"
        print formatted
    }'
}

format_ratio() {
    local raw="${1:-1}"
    awk -v value="$raw" 'BEGIN {
        formatted = sprintf("%.2f", value + 0)
        sub(/0+$/, "", formatted)
        sub(/[.]$/, "", formatted)
        if (formatted == "") formatted = "1"
        print formatted "x"
    }'
}

format_bytes() {
    local bytes="$1"
    if [ "$bytes" -ge 1099511627776 ]; then
        awk -v b="$bytes" 'BEGIN { printf "%.2fTB", b / 1099511627776 }'
    elif [ "$bytes" -ge 1073741824 ]; then
        awk -v b="$bytes" 'BEGIN { printf "%.2fGB", b / 1073741824 }'
    elif [ "$bytes" -ge 1048576 ]; then
        awk -v b="$bytes" 'BEGIN { printf "%.2fMB", b / 1048576 }'
    elif [ "$bytes" -ge 1024 ]; then
        awk -v b="$bytes" 'BEGIN { printf "%.2fKB", b / 1024 }'
    else
        echo "${bytes}B"
    fi
}
