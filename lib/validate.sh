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
    local normalized="" date_part="" time_part="" checked=""
    value="$(printf '%s' "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [ -n "$value" ] || pfwd_die "日期不能为空"

    if [[ "$value" =~ ^([0-9]{8}|[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{4}/[0-9]{2}/[0-9]{2})([[:space:]]+([0-9]{2}:[0-9]{2}))?$ ]]; then
        date_part="${BASH_REMATCH[1]}"
        time_part="${BASH_REMATCH[3]:-00:00}"
        if [[ "$date_part" =~ ^[0-9]{8}$ ]]; then
            normalized="${date_part:0:4}-${date_part:4:2}-${date_part:6:2} ${time_part}"
        elif [[ "$date_part" =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}$ ]]; then
            normalized="${date_part//\//-} ${time_part}"
        else
            normalized="${date_part} ${time_part}"
        fi
    elif [[ "$value" =~ ^\+([0-9]+)$ ]]; then
        normalized="$(date -d "+${BASH_REMATCH[1]} days" '+%Y-%m-%d 00:00' 2>/dev/null)" || pfwd_die "无效日期：$value"
    elif [[ "$value" =~ ^([0-9]+)[dD]$ ]]; then
        normalized="$(date -d "+${BASH_REMATCH[1]} days" '+%Y-%m-%d 00:00' 2>/dev/null)" || pfwd_die "无效日期：$value"
    else
        pfwd_die "无效日期：$value，支持 YYYYMMDD、YYYY-MM-DD、YYYY/MM/DD、可选 HH:MM、+7、7d"
    fi

    checked="$(date -d "$normalized" '+%Y-%m-%d %H:%M' 2>/dev/null)" || pfwd_die "无效日期：$value"
    [ "$checked" = "$normalized" ] || pfwd_die "无效日期：$value"
    echo "$normalized"
}

validate_reset_day() {
    local value="$1"
    normalize_reset_day_input "$value" >/dev/null
}

normalize_reset_day_input() {
    local value="$1"
    local day="" time_part="00:00"
    value="$(printf '%s' "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [ -n "$value" ] || pfwd_die "重置日不能为空"

    if [ "$value" = "0" ]; then
        printf '0\n'
        return 0
    fi

    if [[ "$value" =~ ^([0-9]{1,2})([[:space:]]+|T)?([0-9]{2}:[0-9]{2})?$ ]]; then
        day="${BASH_REMATCH[1]}"
        [ -n "${BASH_REMATCH[3]:-}" ] && time_part="${BASH_REMATCH[3]}"
    else
        pfwd_die "无效重置日：$value，支持 0、1-31、或 15 09:30"
    fi

    [[ "$day" =~ ^[0-9]+$ ]] || pfwd_die "无效重置日：$value"
    [ "$day" -ge 1 ] && [ "$day" -le 31 ] || pfwd_die "重置日必须是 1-31，或 0 表示关闭：$value"
    validate_hhmm_time "$time_part"
    printf '%02d %s\n' "$day" "$time_part"
}

reset_day_to_json() {
    local value="$1"
    local normalized
    normalized="$(normalize_reset_day_input "$value")"
    if [ "$normalized" = "0" ]; then
        printf 'null\n'
    else
        jq -Rn --arg value "$normalized" '$value'
    fi
}

reset_day_display() {
    local value="$1"
    if [ -z "$value" ] || [ "$value" = "null" ] || [ "$value" = "-" ]; then
        printf '%s\n' "-"
    else
        printf '%s\n' "$value"
    fi
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
            pfwd_die "当前转发快路径仅支持通配监听地址（:: 或 0.0.0.0），不支持具体 listen_ip：$value"
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

validate_ipv4_cidr() {
    local value="$1"
    [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$ ]] || pfwd_die "无效 IPv4 CIDR：$value"
    local ip mask octet
    ip="${value%/*}"
    mask="${value#*/}"
    [ "$mask" -ge 0 ] && [ "$mask" -le 32 ] || pfwd_die "无效 IPv4 CIDR 掩码：$value"
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || pfwd_die "无效 IPv4 CIDR：$value"
        [ "$octet" -ge 0 ] && [ "$octet" -le 255 ] || pfwd_die "无效 IPv4 CIDR：$value"
    done
}

validate_ipv6_cidr() {
    local value="$1"
    local output
    output="$(python3 - "$value" <<'PY'
import ipaddress
import sys

value = sys.argv[1]
try:
    network = ipaddress.IPv6Network(value, strict=False)
except Exception:
    sys.exit(1)

sys.stdout.write(str(network))
PY
)" || pfwd_die "无效 IPv6 CIDR：$value"
    [ -n "$output" ] || pfwd_die "无效 IPv6 CIDR：$value"
}

validate_ip_cidr() {
    local value="$1"
    case "$value" in
        *:*)
            validate_ipv6_cidr "$value"
            ;;
        *)
            validate_ipv4_cidr "$value"
            ;;
    esac
}

normalize_ip_literal_to_cidr() {
    local value="$1"
    local output
    output="$(python3 - "$value" <<'PY'
import ipaddress
import sys

value = sys.argv[1]
try:
    addr = ipaddress.ip_address(value)
except Exception:
    sys.exit(1)

mask = 32 if addr.version == 4 else 128
sys.stdout.write(f"{addr}/{mask}")
PY
)" || pfwd_die "无效 IP 地址：$value"
    [ -n "$output" ] || pfwd_die "无效 IP 地址：$value"
    printf '%s\n' "$output"
}

normalize_ip_or_cidr() {
    local value="$1"
    value="$(printf '%s' "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [ -n "$value" ] || pfwd_die "IP/CIDR 不能为空"
    case "$value" in
        */*)
            validate_ip_cidr "$value"
            printf '%s\n' "$value"
            ;;
        *)
            normalize_ip_literal_to_cidr "$value"
            ;;
    esac
}

validate_prefix_len_range() {
    local value="$1" max_bits="$2" label="$3"
    [[ "$value" =~ ^[0-9]+$ ]] || pfwd_die "$label 必须是 0-$max_bits 的整数"
    [ "$value" -ge 0 ] && [ "$value" -le "$max_bits" ] || pfwd_die "$label 必须是 0-$max_bits 的整数"
}

validate_ipv4_prefix_len() {
    validate_prefix_len_range "$1" 32 "${2:-IPv4 前缀长度}"
}

validate_ipv6_prefix_len() {
    validate_prefix_len_range "$1" 128 "${2:-IPv6 前缀长度}"
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

parse_downmask_size_bytes() {
    local raw="$1"
    local value unit multiplier
    raw="$(printf '%s' "$raw" | tr -d ' ' | tr '[:lower:]' '[:upper:]')"
    [[ "$raw" =~ ^([0-9]+([.][0-9]+)?)(B|KB|MB|GB|TB|K|M|G|T)?$ ]] || pfwd_die "无效 downmask 容量：$1；支持数字(默认字节)或小数 + B/KB/MB/GB/TB"
    value="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[3]:-B}"
    case "$unit" in
        B) multiplier=1 ;;
        K|KB) multiplier=1024 ;;
        M|MB) multiplier=$((1024 * 1024)) ;;
        G|GB) multiplier=$((1024 * 1024 * 1024)) ;;
        T|TB) multiplier=$((1024 * 1024 * 1024 * 1024)) ;;
        *) pfwd_die "无效 downmask 容量单位：$1" ;;
    esac
    awk -v value="$value" -v multiplier="$multiplier" 'BEGIN { printf "%.0f\n", value * multiplier }'
}

normalize_ui_downmask_size_input() {
    local raw="$1"
    raw="$(printf '%s' "$raw" | tr -d ' ')"
    [ -n "$raw" ] || return 0
    raw="$(printf '%s' "$raw" | tr '[:lower:]' '[:upper:]')"
    if [[ "$raw" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        printf '%s\n' "$raw"
        return 0
    fi
    if [[ "$raw" =~ ^[0-9]+([.][0-9]+)?(B|KB|MB|GB|TB)$ ]]; then
        printf '%s\n' "$raw"
        return 0
    fi
    if [[ "$raw" =~ ^([0-9]+([.][0-9]+)?)(K|M|G|T)$ ]]; then
        printf '%s%sB\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}"
        return 0
    fi
    pfwd_die "无效 downmask 容量：$1；支持数字(默认字节)或小数 + B/KB/MB/GB/TB"
}

validate_downmask_udp_payload_bytes() {
    local value="$1"
    local min_payload=17
    local max_payload=65507
    [[ "$value" =~ ^[0-9]+$ ]] || pfwd_die "udp-payload-bytes 必须是非负整数"
    [ "$value" -ge "$min_payload" ] || pfwd_die "udp-payload-bytes 必须 >= ${min_payload} 字节"
    [ "$value" -le "$max_payload" ] || pfwd_die "udp-payload-bytes 必须 <= ${max_payload} 字节"
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

validate_downmask_pull_mode() {
    local value="$1"
    case "$value" in
        off|public|ab) ;;
        *) pfwd_die "无效 pull_mode：$value，必须是 off|public|ab" ;;
    esac
}

validate_downmask_bind_ip() {
    local value="$1"
    case "$value" in
        ""|"::"|"0.0.0.0") ;;
        *) validate_ip_literal "$value" ;;
    esac
}

validate_downmask_ratio() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]] || pfwd_die "无效比例：$value"
    awk -v value="$value" 'BEGIN { exit !(value >= 1.0) }' || pfwd_die "比例必须 >= 1.0：$value"
}

validate_downmask_speed_limit() {
    local value="$1"
    downmask_rate_to_bytes_per_second "$value" >/dev/null
}

downmask_rate_to_bytes_per_second() {
    local raw="$1"
    local value unit multiplier
    raw="$(printf '%s' "$raw" | tr -d ' ')"
    [ -n "$raw" ] || pfwd_die "限速不能为空"
    if [[ "$raw" =~ ^([0-9]+([.][0-9]+)?)$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    if [[ "$raw" =~ ^([0-9]+([.][0-9]+)?)([KkMmGgTt])$ ]]; then
        value="${BASH_REMATCH[1]}"
        unit="${BASH_REMATCH[3]}"
        case "$unit" in
            K|k) multiplier=1024 ;;
            M|m) multiplier=$((1024 * 1024)) ;;
            G|g) multiplier=$((1024 * 1024 * 1024)) ;;
            T|t) multiplier=$((1024 * 1024 * 1024 * 1024)) ;;
        esac
        awk -v value="$value" -v multiplier="$multiplier" 'BEGIN { printf "%.0f\n", value * multiplier }'
        return 0
    fi
    if [[ "$raw" =~ ^([0-9]+([.][0-9]+)?)(B/s|KB/s|MB/s|GB/s|TB/s|Bps|KBps|MBps|GBps|TBps)$ ]]; then
        value="${BASH_REMATCH[1]}"
        unit="${BASH_REMATCH[3]}"
        case "$unit" in
            B/s|Bps) multiplier=1 ;;
            KB/s|KBps) multiplier=1024 ;;
            MB/s|MBps) multiplier=$((1024 * 1024)) ;;
            GB/s|GBps) multiplier=$((1024 * 1024 * 1024)) ;;
            TB/s|TBps) multiplier=$((1024 * 1024 * 1024 * 1024)) ;;
        esac
        awk -v value="$value" -v multiplier="$multiplier" 'BEGIN { printf "%.0f\n", value * multiplier }'
        return 0
    fi
    if [[ "$raw" =~ ^([0-9]+([.][0-9]+)?)([Kk]bps|[Mm]bps|[Gg]bps|[Tt]bps|[Kk]bit/[Ss]|[Mm]bit/[Ss]|[Gg]bit/[Ss]|[Tt]bit/[Ss])$ ]]; then
        value="${BASH_REMATCH[1]}"
        unit="${BASH_REMATCH[3]}"
        case "$unit" in
            Kbps|kbps|Kbit/s|kbit/s) multiplier=125 ;;
            Mbps|mbps|Mbit/s|mbit/s) multiplier=125000 ;;
            Gbps|gbps|Gbit/s|gbit/s) multiplier=125000000 ;;
            Tbps|tbps|Tbit/s|tbit/s) multiplier=125000000000 ;;
        esac
        awk -v value="$value" -v multiplier="$multiplier" 'BEGIN { printf "%.0f\n", value * multiplier }'
        return 0
    fi
    pfwd_die "无效 downmask 限速：$1；支持 4M、4MB/s、32Mbps、1GB/s"
}

format_bits_per_second_decimal() {
    local bytes_per_second="$1"
    awk -v bps="$bytes_per_second" '
    BEGIN {
        bits = bps * 8
        if (bits >= 1000000000) printf "%.1f Gbps", bits / 1000000000
        else if (bits >= 1000000) printf "%.1f Mbps", bits / 1000000
        else if (bits >= 1000) printf "%.1f Kbps", bits / 1000
        else printf "%.0f bps", bits
    }'
}

format_downmask_speed_hint() {
    local raw="$1"
    local bps
    bps="$(downmask_rate_to_bytes_per_second "$raw")" || return 1
    printf '%s（%s/s，约 %s）' "$raw" "$(format_bytes "$bps")" "$(format_bits_per_second_decimal "$bps")"
}

validate_downmask_time_window() {
    local value="$1"
    validate_hhmm_time "$value"
}

validate_downmask_protocol() {
    local value="$1"
    case "$value" in
        tcp|udp) ;;
        *) pfwd_die "无效协议：$value，必须是 tcp 或 udp" ;;
    esac
}

validate_downmask_protocol_mode() {
    local value="$1"
    case "$value" in
        single|parallel) ;;
        *) pfwd_die "无效协议模式：$value，必须是 single 或 parallel" ;;
    esac
}

validate_downmask_target_host() {
    local value="$1"
    [ -n "$value" ] || pfwd_die "B机主机不能为空"
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]] || pfwd_die "无效 B机主机：不能包含控制字符"
}

validate_downmask_weight() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] || pfwd_die "weight 必须是正整数"
    [ "$value" -ge 1 ] || pfwd_die "weight 必须 >= 1"
}

validate_downmask_percent() {
    local label="$1"
    local value="$2"
    [[ "$value" =~ ^[0-9]+$ ]] || pfwd_die "$label 必须是 0-100 的整数"
    [ "$value" -ge 0 ] && [ "$value" -le 100 ] || pfwd_die "$label 必须位于 0-100"
}

validate_downmask_parallel_limit() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] || pfwd_die "parallel-limit 必须是正整数"
    [ "$value" -ge 1 ] || pfwd_die "parallel-limit 必须 >= 1"
}

validate_downmask_local_ip() {
    local value="$1"
    [ -n "$value" ] || pfwd_die "local_ip 不能为空"
    validate_ip_literal "$value"
}

validate_downmask_token() {
    local value="$1"
    [ -n "$value" ] || pfwd_die "token 不能为空"
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
