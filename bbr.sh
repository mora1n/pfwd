#!/usr/bin/env bash
set -euo pipefail

BBR_VERSION="0.1.0"
PFWD_BBR_IFB="${PFWD_BBR_IFB:-ifb-pfwd}"

bbr_detect_script_source() {
    local candidate=""

    if [ "${BASH_SOURCE[0]-}" != "" ]; then
        candidate="${BASH_SOURCE[0]}"
    elif [ "${0-}" != "" ] && [ "${0-}" != "bash" ] && [ "${0-}" != "-bash" ]; then
        candidate="${0}"
    fi

    [ -n "$candidate" ] || return 1
    if [ -e "$candidate" ]; then
        readlink -f "$candidate" 2>/dev/null || realpath "$candidate" 2>/dev/null || return 1
        return 0
    fi
    return 1
}

SCRIPT_PATH="$(bbr_detect_script_source || true)"
if [ -n "$SCRIPT_PATH" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
else
    SCRIPT_DIR=""
fi

pfwd_root_prefix() {
    local prefix="${PFWD_ROOT_PREFIX:-/}"
    prefix="${prefix%/}"
    if [ -z "$prefix" ]; then
        echo ""
    else
        echo "$prefix"
    fi
}

pfwd_path() {
    local rel="$1"
    local prefix
    prefix="$(pfwd_root_prefix)"
    if [ -z "$prefix" ]; then
        echo "/$rel"
    else
        echo "$prefix/$rel"
    fi
}

PFWD_STATE_DIR="${PFWD_STATE_DIR:-$(pfwd_path var/lib/pfwd)}"
PFWD_BBR_STATE_FILE="${PFWD_BBR_STATE_FILE:-$PFWD_STATE_DIR/bbr-state.env}"
PFWD_BBR_SYSCTL_CONF="${PFWD_BBR_SYSCTL_CONF:-$(pfwd_path etc/sysctl.d/99-pfwd-bbr.conf)}"
PFWD_BBR_SERVICE_FILE="${PFWD_BBR_SERVICE_FILE:-$(pfwd_path etc/systemd/system/pfwd-bbr.service)}"
PFWD_BBR_INSTALL_DIR="${PFWD_BBR_INSTALL_DIR:-$(pfwd_path usr/local/lib/pfwd)}"
PFWD_BBR_BIN_PATH="${PFWD_BBR_BIN_PATH:-$(pfwd_path usr/local/bin/bbr.sh)}"
PFWD_BBR_ALIAS_BIN_PATH="${PFWD_BBR_ALIAS_BIN_PATH:-$(pfwd_path usr/local/bin/pfwd-bbr)}"
PFWD_BBR_ENTRY_NAME="${PFWD_BBR_ENTRY_NAME:-pfwd-bbr}"
BBR_UI_REPLY=""

bbr_die() {
    echo "错误：$*" >&2
    exit 1
}

bbr_info() {
    echo "$*"
}

bbr_now_iso() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

bbr_root_prefix_real() {
    [ "$(pfwd_root_prefix)" = "" ]
}

bbr_run() {
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        printf 'DRY-RUN:'
        printf ' %q' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

bbr_mkdir_p() {
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        printf 'DRY-RUN: mkdir -p'
        printf ' %q' "$@"
        printf '\n'
        return 0
    fi
    mkdir -p "$@"
}

bbr_write_value() {
    local path="$1"
    local value="$2"
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        printf 'DRY-RUN: write %s => %q\n' "$path" "$value"
        return 0
    fi
    printf '%s' "$value" > "$path"
}

bbr_write_atomic() {
    local target="$1"
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        printf 'DRY-RUN: write file %q\n' "$target"
        cat >/dev/null
        return 0
    fi
    local tmp
    tmp="$(mktemp "${target}.tmp.XXXXXX")"
    cat > "$tmp"
    mv "$tmp" "$target"
}

bbr_remove_path() {
    local path="$1"
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        printf 'DRY-RUN: rm -f %q\n' "$path"
        return 0
    fi
    rm -f "$path"
}

bbr_remove_tree() {
    local path="$1"
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        printf 'DRY-RUN: rm -rf %q\n' "$path"
        return 0
    fi
    rm -rf "$path"
}

bbr_require_mutation_context() {
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        return 0
    fi
    [ "${EUID:-$(id -u)}" -eq 0 ] || bbr_die "需要 root 权限"
}

bbr_command_name() {
    if [ -n "${0:-}" ] && [ "${0:-}" != "bash" ] && [ "${0:-}" != "-bash" ]; then
        basename "$0"
    elif [ -n "$SCRIPT_PATH" ]; then
        basename "$SCRIPT_PATH"
    else
        printf '%s\n' "$PFWD_BBR_ENTRY_NAME"
    fi
}

bbr_preferred_command_name() {
    printf '%s\n' "$PFWD_BBR_ENTRY_NAME"
}

bbr_is_tty() {
    [ -t 0 ] && [ -t 1 ]
}

bbr_pause() {
    [ -t 0 ] || return 0
    printf '按回车继续...'
    IFS= read -r _ || true
}

bbr_read() {
    local prompt="$1"
    local default="${2:-}"
    BBR_UI_REPLY=""
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$prompt" "$default"
    else
        printf '%s: ' "$prompt"
    fi
    if ! IFS= read -r BBR_UI_REPLY; then
        BBR_UI_REPLY=""
        return 1
    fi
    [ -n "$BBR_UI_REPLY" ] || BBR_UI_REPLY="$default"
    return 0
}

bbr_confirm_text() {
    local expected="$1"
    local prompt="$2"
    bbr_read "$prompt" || return 1
    [ "$BBR_UI_REPLY" = "$expected" ]
}

bbr_default_iface_prompt() {
    local iface
    iface="$(bbr_default_route_iface)"
    if [ -n "$iface" ]; then
        printf '默认路由网卡（当前：%s）\n' "$iface"
    else
        printf '默认路由网卡（当前未探测到）\n'
    fi
}

bbr_menu_status() {
    bbr_status
    bbr_pause
}

bbr_menu_choose_profile() {
    echo "1) balanced"
    echo "   通用平衡档，适合大多数中转和公网主机。"
    echo "2) gaming"
    echo "   偏低延迟，适合对交互响应更敏感的链路。"
    echo "3) lowmem"
    echo "   偏保守内存占用，适合小内存主机。"
    echo "4) relay"
    echo "   偏中转吞吐和连接数，适合高并发转发节点。"
    bbr_read "优化档位" "1" || return 1
    case "$BBR_UI_REPLY" in
        1|"") BBR_UI_REPLY="balanced" ;;
        2) BBR_UI_REPLY="gaming" ;;
        3) BBR_UI_REPLY="lowmem" ;;
        4) BBR_UI_REPLY="relay" ;;
        *) bbr_die "无效优化档位：$BBR_UI_REPLY" ;;
    esac
}

bbr_menu_choose_nic_steering() {
    echo "1) 关闭"
    echo "   保持当前网卡队列分发默认状态。"
    echo "2) 开启"
    echo "   启用 RPS/XPS；适合多核主机、并发流量较大时。"
    bbr_read "NIC steering" "1" || return 1
    case "$BBR_UI_REPLY" in
        1|"") BBR_UI_REPLY="false" ;;
        2) BBR_UI_REPLY="true" ;;
        *) bbr_die "无效选择：$BBR_UI_REPLY" ;;
    esac
}

bbr_menu_choose_iface_mode() {
    echo "1) 使用默认路由网卡"
    echo "   适合单出口主机，自动沿系统默认路由选择网卡。"
    echo "2) 手动指定网卡"
    echo "   适合多网卡、多出口或默认路由不等于目标出口时。"
    bbr_default_iface_prompt
    bbr_read "网卡选择" "1" || return 1
    case "$BBR_UI_REPLY" in
        1|"")
            BBR_UI_REPLY="auto|"
            ;;
        2)
            local iface=""
            bbr_read "网卡名，例如 eth0" || return 1
            iface="$BBR_UI_REPLY"
            [ -n "$iface" ] || bbr_die "必须提供网卡名"
            BBR_UI_REPLY="explicit|$iface"
            ;;
        *)
            bbr_die "无效选择：$BBR_UI_REPLY"
            ;;
    esac
}

bbr_menu_rate_prompt() {
    local label="$1"
    echo "留空表示不设置。支持 100mbit / 100M / 1gbit。"
    bbr_read "$label" "" || return 1
    if [ -n "$BBR_UI_REPLY" ]; then
        BBR_UI_REPLY="$(bbr_normalize_rate "$BBR_UI_REPLY")"
    fi
}

bbr_menu_optimize() {
    local profile="balanced"
    local nic_steering="false"
    local tc_iface_mode="auto"
    local tc_iface_value=""
    local egress_rate=""
    local ingress_rate=""
    local iface_spec=""

    bbr_menu_choose_profile || return 1
    profile="$BBR_UI_REPLY"

    bbr_menu_choose_nic_steering || return 1
    nic_steering="$BBR_UI_REPLY"

    bbr_menu_choose_iface_mode || return 1
    iface_spec="$BBR_UI_REPLY"
    tc_iface_mode="${iface_spec%%|*}"
    tc_iface_value="${iface_spec#*|}"

    bbr_menu_rate_prompt "出口限速 egress rate" || return 1
    egress_rate="$BBR_UI_REPLY"

    bbr_menu_rate_prompt "入口限速 ingress rate" || return 1
    ingress_rate="$BBR_UI_REPLY"

    if [ -z "$egress_rate" ] && [ -z "$ingress_rate" ]; then
        bbr_info "提示：本次不会启用 tc shaping。"
    fi

    bbr_optimize_apply "$profile" "$nic_steering" "$tc_iface_mode" "$tc_iface_value" "$egress_rate" "$ingress_rate"
    bbr_enable_service
    bbr_info "优化已应用：profile=$profile"
    bbr_pause
}

bbr_menu_reset() {
    if bbr_confirm_text "reset" "输入 reset 确认重置优化"; then
        bbr_reset
        bbr_disable_service
        bbr_info "优化已重置"
    else
        bbr_info "已取消"
    fi
    bbr_pause
}

bbr_menu_install() {
    bbr_install
    bbr_info "pfwd-bbr 已安装"
    bbr_pause
}

bbr_menu_uninstall() {
    if bbr_confirm_text "uninstall" "输入 uninstall 确认卸载 pfwd-bbr"; then
        bbr_uninstall
        bbr_info "pfwd-bbr 已卸载"
    else
        bbr_info "已取消"
    fi
    bbr_pause
}

bbr_menu() {
    while true; do
        printf '\n== pfwd-bbr ==\n'
        echo "1) 查看状态"
        echo "2) 应用优化"
        echo "3) 重置优化"
        echo "4) 安装开机恢复服务"
        echo "5) 卸载 pfwd-bbr"
        echo "0) 退出"
        bbr_read "选择" || return 0
        case "$BBR_UI_REPLY" in
            1) bbr_menu_status ;;
            2) bbr_menu_optimize ;;
            3) bbr_menu_reset ;;
            4) bbr_menu_install ;;
            5) bbr_menu_uninstall ;;
            0) return 0 ;;
            *) bbr_info "无效选择"; bbr_pause ;;
        esac
    done
}

bbr_ensure_shortcuts() {
    [ -n "$SCRIPT_PATH" ] || return 0
    [ -z "${PFWD_ROOT_PREFIX:-}" ] || return 0
    [ "${PFWD_DRY_RUN:-0}" != "1" ] || return 0
    [ "${EUID:-$(id -u)}" -eq 0 ] || return 0

    bbr_mkdir_p "$(dirname "$PFWD_BBR_BIN_PATH")" "$(dirname "$PFWD_BBR_ALIAS_BIN_PATH")"
    ln -sf "$SCRIPT_PATH" "$PFWD_BBR_BIN_PATH"
    ln -sf "$SCRIPT_PATH" "$PFWD_BBR_ALIAS_BIN_PATH"
}

bbr_normalize_rate() {
    local raw="$1"
    raw="$(echo "$raw" | tr -d ' ' | tr '[:upper:]' '[:lower:]')"
    if [ "$raw" = "0" ]; then
        echo ""
        return 0
    fi
    [[ "$raw" =~ ^([0-9]+([.][0-9]+)?)(k|kbps|kbit|m|mbps|mbit|g|gbps|gbit)$ ]] || bbr_die "无效速率：$1"
    local value="${BASH_REMATCH[1]}"
    local unit="${BASH_REMATCH[3]}"
    case "$unit" in
        k|kbps|kbit) echo "${value}kbit" ;;
        m|mbps|mbit) echo "${value}mbit" ;;
        g|gbps|gbit) echo "${value}gbit" ;;
        *) bbr_die "无效速率：$1" ;;
    esac
}

bbr_default_route_iface() {
    ip route show default 2>/dev/null | awk '{print $5; exit}'
}

bbr_iface_exists() {
    local iface="$1"
    [ -n "$iface" ] && [ -d "/sys/class/net/$iface" ]
}

bbr_resolve_iface() {
    local mode="$1"
    local value="$2"
    case "$mode" in
        explicit)
            bbr_iface_exists "$value" || bbr_die "未知网卡：$value"
            printf '%s\n' "$value"
            ;;
        auto)
            local iface
            iface="$(bbr_default_route_iface)"
            [ -n "$iface" ] || bbr_die "未找到默认路由网卡，请使用 --tc-iface"
            bbr_iface_exists "$iface" || bbr_die "默认路由网卡不存在：$iface"
            printf '%s\n' "$iface"
            ;;
        *)
            bbr_die "未知网卡选择模式：$mode"
            ;;
    esac
}

bbr_state_reset_vars() {
    BBR_STATE_PRESENT=false
    BBR_STATE_PROFILE=""
    BBR_STATE_NIC_STEERING="false"
    BBR_STATE_BQL_LIMIT="65536"
    BBR_STATE_TC_IFACE_MODE="auto"
    BBR_STATE_TC_IFACE_VALUE=""
    BBR_STATE_EGRESS_RATE=""
    BBR_STATE_INGRESS_RATE=""
    BBR_STATE_APPLIED_AT=""
}

bbr_state_load() {
    bbr_state_reset_vars
    [ -f "$PFWD_BBR_STATE_FILE" ] || return 0
    BBR_STATE_PRESENT=true
    while IFS='=' read -r key value; do
        [ -n "$key" ] || continue
        case "$key" in
            PROFILE) BBR_STATE_PROFILE="$value" ;;
            NIC_STEERING) BBR_STATE_NIC_STEERING="$value" ;;
            BQL_LIMIT) BBR_STATE_BQL_LIMIT="$value" ;;
            TC_IFACE_MODE) BBR_STATE_TC_IFACE_MODE="$value" ;;
            TC_IFACE_VALUE) BBR_STATE_TC_IFACE_VALUE="$value" ;;
            EGRESS_RATE) BBR_STATE_EGRESS_RATE="$value" ;;
            INGRESS_RATE) BBR_STATE_INGRESS_RATE="$value" ;;
            APPLIED_AT) BBR_STATE_APPLIED_AT="$value" ;;
        esac
    done < "$PFWD_BBR_STATE_FILE"
}

bbr_state_save() {
    bbr_mkdir_p "$PFWD_STATE_DIR"
    cat <<EOF | bbr_write_atomic "$PFWD_BBR_STATE_FILE"
PROFILE=$1
NIC_STEERING=$2
BQL_LIMIT=$3
TC_IFACE_MODE=$4
TC_IFACE_VALUE=$5
EGRESS_RATE=$6
INGRESS_RATE=$7
APPLIED_AT=$(bbr_now_iso)
EOF
}

bbr_state_delete() {
    bbr_remove_path "$PFWD_BBR_STATE_FILE"
}

bbr_sysctl_cc_available() {
    local value=""
    value="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
    [[ " $value " == *" bbr "* ]]
}

bbr_try_load_cc() {
    bbr_sysctl_cc_available && return 0
    bbr_run modprobe tcp_bbr >/dev/null 2>&1 || true
    bbr_sysctl_cc_available
}

bbr_profile_prepare() {
    BBR_PROFILE="$1"
    case "$BBR_PROFILE" in
        gaming)
            BBR_BUF_MAX=134217728
            BBR_CONNTRACK_MAX=524288
            BBR_CONNTRACK_TCP_EST=3600
            BBR_CONNTRACK_TCP_TIME_WAIT=15
            BBR_CONNTRACK_TCP_CLOSE_WAIT=60
            BBR_CONNTRACK_TCP_FIN_WAIT=30
            BBR_UDP_TIMEOUT=120
            BBR_UDP_STREAM_TIMEOUT=300
            BBR_TCP_RMEM="4096 131072 134217728"
            BBR_TCP_WMEM="4096 131072 134217728"
            BBR_TCP_MEM="65536 98304 131072"
            BBR_BACKLOG=50000
            BBR_SOMAXCONN=32768
            BBR_FILE_MAX=3407872
            BBR_FT_TCP_TIMEOUT=300
            BBR_FT_UDP_TIMEOUT=120
            BBR_CONNTRACK_BUCKETS=131072
            BBR_GRO_NORMAL_BATCH=8
            BBR_MAX_SYN_BACKLOG=16384
            BBR_MAX_TW_BUCKETS=262144
            BBR_NETDEV_BUDGET=600
            BBR_NETDEV_BUDGET_USECS=8000
            BBR_OPTMEM_MAX=65536
            BBR_KEEPALIVE_TIME=60
            BBR_KEEPALIVE_INTVL=10
            BBR_KEEPALIVE_PROBES=6
            BBR_TCP_SYNACK_RETRIES=2
            BBR_TCP_FIN_TIMEOUT=10
            BBR_TCP_ECN=2
            BBR_TCP_FRTO=2
            BBR_INOTIFY_INSTANCES=8192
            BBR_INOTIFY_WATCHES=262144
            BBR_RELAY_TUNING=false
            ;;
        lowmem)
            BBR_BUF_MAX=16777216
            BBR_CONNTRACK_MAX=131072
            BBR_CONNTRACK_TCP_EST=3600
            BBR_CONNTRACK_TCP_TIME_WAIT=15
            BBR_CONNTRACK_TCP_CLOSE_WAIT=30
            BBR_CONNTRACK_TCP_FIN_WAIT=20
            BBR_UDP_TIMEOUT=30
            BBR_UDP_STREAM_TIMEOUT=120
            BBR_TCP_RMEM="4096 65536 16777216"
            BBR_TCP_WMEM="4096 65536 16777216"
            BBR_TCP_MEM="16384 24576 32768"
            BBR_BACKLOG=10000
            BBR_SOMAXCONN=4096
            BBR_FILE_MAX=1048576
            BBR_FT_TCP_TIMEOUT=60
            BBR_FT_UDP_TIMEOUT=15
            BBR_CONNTRACK_BUCKETS=32768
            BBR_GRO_NORMAL_BATCH=4
            BBR_MAX_SYN_BACKLOG=4096
            BBR_MAX_TW_BUCKETS=65536
            BBR_NETDEV_BUDGET=300
            BBR_NETDEV_BUDGET_USECS=8000
            BBR_OPTMEM_MAX=32768
            BBR_KEEPALIVE_TIME=60
            BBR_KEEPALIVE_INTVL=10
            BBR_KEEPALIVE_PROBES=6
            BBR_TCP_SYNACK_RETRIES=2
            BBR_TCP_FIN_TIMEOUT=10
            BBR_TCP_ECN=2
            BBR_TCP_FRTO=2
            BBR_INOTIFY_INSTANCES=4096
            BBR_INOTIFY_WATCHES=131072
            BBR_RELAY_TUNING=false
            ;;
        relay)
            BBR_BUF_MAX=67108864
            BBR_CONNTRACK_MAX=1048576
            BBR_CONNTRACK_TCP_EST=7200
            BBR_CONNTRACK_TCP_TIME_WAIT=15
            BBR_CONNTRACK_TCP_CLOSE_WAIT=60
            BBR_CONNTRACK_TCP_FIN_WAIT=30
            BBR_UDP_TIMEOUT=120
            BBR_UDP_STREAM_TIMEOUT=300
            BBR_TCP_RMEM="4096 131072 67108864"
            BBR_TCP_WMEM="4096 65536 67108864"
            BBR_TCP_MEM="131072 196608 262144"
            BBR_BACKLOG=65536
            BBR_SOMAXCONN=65535
            BBR_FILE_MAX=6815744
            BBR_FT_TCP_TIMEOUT=300
            BBR_FT_UDP_TIMEOUT=120
            BBR_CONNTRACK_BUCKETS=262144
            BBR_GRO_NORMAL_BATCH=8
            BBR_MAX_SYN_BACKLOG=131072
            BBR_MAX_TW_BUCKETS=262144
            BBR_NETDEV_BUDGET=600
            BBR_NETDEV_BUDGET_USECS=8000
            BBR_OPTMEM_MAX=65536
            BBR_KEEPALIVE_TIME=60
            BBR_KEEPALIVE_INTVL=10
            BBR_KEEPALIVE_PROBES=6
            BBR_TCP_SYNACK_RETRIES=1
            BBR_TCP_FIN_TIMEOUT=15
            BBR_TCP_ECN=1
            BBR_TCP_FRTO=0
            BBR_INOTIFY_INSTANCES=8192
            BBR_INOTIFY_WATCHES=524288
            BBR_RELAY_TUNING=true
            ;;
        balanced)
            BBR_BUF_MAX=33554432
            BBR_CONNTRACK_MAX=1048576
            BBR_CONNTRACK_TCP_EST=7200
            BBR_CONNTRACK_TCP_TIME_WAIT=15
            BBR_CONNTRACK_TCP_CLOSE_WAIT=60
            BBR_CONNTRACK_TCP_FIN_WAIT=30
            BBR_UDP_TIMEOUT=60
            BBR_UDP_STREAM_TIMEOUT=180
            BBR_TCP_RMEM="4096 87380 33554432"
            BBR_TCP_WMEM="4096 65536 33554432"
            BBR_TCP_MEM="32768 49152 65536"
            BBR_BACKLOG=10000
            BBR_SOMAXCONN=8192
            BBR_FILE_MAX=1000000
            BBR_FT_TCP_TIMEOUT=300
            BBR_FT_UDP_TIMEOUT=30
            BBR_CONNTRACK_BUCKETS=262144
            BBR_GRO_NORMAL_BATCH=8
            BBR_MAX_SYN_BACKLOG=8192
            BBR_MAX_TW_BUCKETS=262144
            BBR_NETDEV_BUDGET=300
            BBR_NETDEV_BUDGET_USECS=8000
            BBR_OPTMEM_MAX=65536
            BBR_KEEPALIVE_TIME=60
            BBR_KEEPALIVE_INTVL=10
            BBR_KEEPALIVE_PROBES=6
            BBR_TCP_SYNACK_RETRIES=2
            BBR_TCP_FIN_TIMEOUT=10
            BBR_TCP_ECN=2
            BBR_TCP_FRTO=2
            BBR_INOTIFY_INSTANCES=8192
            BBR_INOTIFY_WATCHES=262144
            BBR_RELAY_TUNING=false
            ;;
        *)
            bbr_die "未知优化档位：$BBR_PROFILE"
            ;;
    esac
}

bbr_render_sysctl_conf() {
    local enable_bbr="$1"
    cat <<EOF
# generated by bbr.sh
# profile: $BBR_PROFILE
fs.file-max = $BBR_FILE_MAX
fs.inotify.max_user_instances = $BBR_INOTIFY_INSTANCES
fs.inotify.max_user_watches = $BBR_INOTIFY_WATCHES
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
$( [ "$enable_bbr" = "true" ] && printf '%s\n' 'net.core.default_qdisc = fq' 'net.ipv4.tcp_congestion_control = bbr' )
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_early_retrans = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_rfc1337 = 0
net.ipv4.tcp_ecn = $BBR_TCP_ECN
net.ipv4.tcp_frto = $BBR_TCP_FRTO
net.ipv4.tcp_keepalive_time = $BBR_KEEPALIVE_TIME
net.ipv4.tcp_keepalive_intvl = $BBR_KEEPALIVE_INTVL
net.ipv4.tcp_keepalive_probes = $BBR_KEEPALIVE_PROBES
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = $BBR_TCP_FIN_TIMEOUT
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = $BBR_TCP_SYNACK_RETRIES
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = $BBR_MAX_SYN_BACKLOG
net.ipv4.tcp_max_tw_buckets = $BBR_MAX_TW_BUCKETS
$( [ "$BBR_RELAY_TUNING" = "true" ] && printf '%s\n' 'net.ipv4.neigh.default.unres_qlen = 10000' )
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.core.rmem_max = $BBR_BUF_MAX
net.core.wmem_max = $BBR_BUF_MAX
net.ipv4.tcp_mem = $BBR_TCP_MEM
net.ipv4.tcp_rmem = $BBR_TCP_RMEM
net.ipv4.tcp_wmem = $BBR_TCP_WMEM
net.core.optmem_max = $BBR_OPTMEM_MAX
net.core.netdev_max_backlog = $BBR_BACKLOG
net.core.netdev_budget = $BBR_NETDEV_BUDGET
net.core.netdev_budget_usecs = $BBR_NETDEV_BUDGET_USECS
net.core.somaxconn = $BBR_SOMAXCONN
net.core.gro_normal_batch = $BBR_GRO_NORMAL_BATCH
net.netfilter.nf_conntrack_max = $BBR_CONNTRACK_MAX
net.netfilter.nf_conntrack_tcp_timeout_established = $BBR_CONNTRACK_TCP_EST
net.netfilter.nf_conntrack_tcp_timeout_time_wait = $BBR_CONNTRACK_TCP_TIME_WAIT
net.netfilter.nf_conntrack_tcp_timeout_close_wait = $BBR_CONNTRACK_TCP_CLOSE_WAIT
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = $BBR_CONNTRACK_TCP_FIN_WAIT
net.netfilter.nf_conntrack_tcp_loose = 1
net.netfilter.nf_conntrack_udp_timeout = $BBR_UDP_TIMEOUT
net.netfilter.nf_conntrack_udp_timeout_stream = $BBR_UDP_STREAM_TIMEOUT
net.netfilter.nf_conntrack_acct = 1
net.netfilter.nf_conntrack_helper = 0
net.netfilter.nf_conntrack_buckets = $BBR_CONNTRACK_BUCKETS
net.netfilter.nf_flowtable_tcp_timeout = $BBR_FT_TCP_TIMEOUT
net.netfilter.nf_flowtable_udp_timeout = $BBR_FT_UDP_TIMEOUT
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.route_localnet = 1
net.ipv4.conf.default.route_localnet = 1
EOF
}

bbr_apply_sysctl_profile() {
    local profile="$1"
    bbr_profile_prepare "$profile"
    bbr_mkdir_p "$(dirname "$PFWD_BBR_SYSCTL_CONF")"
    local enable_bbr="false"
    if bbr_try_load_cc; then
        enable_bbr="true"
    fi
    bbr_render_sysctl_conf "$enable_bbr" | bbr_write_atomic "$PFWD_BBR_SYSCTL_CONF"
    bbr_run sysctl -p "$PFWD_BBR_SYSCTL_CONF" >/dev/null
}

bbr_online_cpu_count() {
    nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1
}

bbr_cpu_mask_all() {
    local count remaining bits value
    local -a parts=()
    count="$(bbr_online_cpu_count)"
    remaining="$count"
    while [ "$remaining" -gt 0 ]; do
        if [ "$remaining" -ge 32 ]; then
            value="ffffffff"
            bits=32
        else
            printf -v value '%x' $(( (1 << remaining) - 1 ))
            bits="$remaining"
        fi
        parts=("$value" "${parts[@]}")
        remaining=$((remaining - bits))
    done
    local IFS=,
    printf '%s\n' "${parts[*]}"
}

bbr_apply_bql_limit() {
    local iface="$1"
    local limit="$2"
    local queue_file
    for queue_file in /sys/class/net/"$iface"/queues/tx-*/byte_queue_limits/limit_max; do
        [ -f "$queue_file" ] || continue
        bbr_write_value "$queue_file" "$limit"
    done
}

bbr_apply_nic_steering() {
    local iface="$1"
    local cpu_mask queue_file
    cpu_mask="$(bbr_cpu_mask_all)"
    if [ "${PFWD_DRY_RUN:-0}" = "1" ]; then
        printf 'DRY-RUN: sysctl -w net.core.rps_sock_flow_entries=32768\n'
    else
        sysctl -w net.core.rps_sock_flow_entries=32768 >/dev/null 2>&1 || true
    fi
    for queue_file in /sys/class/net/"$iface"/queues/rx-*/rps_cpus; do
        [ -f "$queue_file" ] || continue
        bbr_write_value "$queue_file" "$cpu_mask"
    done
    for queue_file in /sys/class/net/"$iface"/queues/rx-*/rps_flow_cnt; do
        [ -f "$queue_file" ] || continue
        bbr_write_value "$queue_file" "4096"
    done
    for queue_file in /sys/class/net/"$iface"/queues/tx-*/xps_cpus; do
        [ -f "$queue_file" ] || continue
        bbr_write_value "$queue_file" "$cpu_mask"
    done
}

bbr_clear_nic_steering() {
    local iface="$1"
    local queue_file
    for queue_file in /sys/class/net/"$iface"/queues/rx-*/rps_cpus; do
        [ -f "$queue_file" ] || continue
        bbr_write_value "$queue_file" "0"
    done
    for queue_file in /sys/class/net/"$iface"/queues/rx-*/rps_flow_cnt; do
        [ -f "$queue_file" ] || continue
        bbr_write_value "$queue_file" "0"
    done
    for queue_file in /sys/class/net/"$iface"/queues/tx-*/xps_cpus; do
        [ -f "$queue_file" ] || continue
        bbr_write_value "$queue_file" "0"
    done
}

bbr_tc_clear() {
    local iface="${1:-}"
    [ -n "$iface" ] || return 0
    bbr_run tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
    bbr_run tc qdisc del dev "$iface" ingress >/dev/null 2>&1 || true
    bbr_run tc qdisc del dev "$PFWD_BBR_IFB" root >/dev/null 2>&1 || true
    bbr_run ip link del "$PFWD_BBR_IFB" >/dev/null 2>&1 || true
}

bbr_tc_ensure_ifb() {
    if ip link show "$PFWD_BBR_IFB" >/dev/null 2>&1; then
        bbr_run ip link set dev "$PFWD_BBR_IFB" up
        return 0
    fi
    bbr_run modprobe ifb >/dev/null 2>&1 || true
    bbr_run ip link add "$PFWD_BBR_IFB" type ifb
    bbr_run ip link set dev "$PFWD_BBR_IFB" up
}

bbr_apply_tc_state() {
    local iface="$1"
    local egress_rate="$2"
    local ingress_rate="$3"

    bbr_tc_clear "$iface"
    if [ -n "$egress_rate" ]; then
        bbr_run tc qdisc replace dev "$iface" root tbf rate "$egress_rate" burst 256kbit latency 50ms
    fi
    if [ -n "$ingress_rate" ]; then
        bbr_tc_ensure_ifb
        bbr_run tc qdisc replace dev "$iface" handle ffff: ingress
        bbr_run tc filter replace dev "$iface" parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev "$PFWD_BBR_IFB"
        bbr_run tc qdisc replace dev "$PFWD_BBR_IFB" root tbf rate "$ingress_rate" burst 256kbit latency 50ms
    fi
}

bbr_clear_previous_runtime() {
    bbr_state_load
    [ "$BBR_STATE_PRESENT" = "true" ] || return 0
    local iface=""
    iface="$(bbr_resolve_iface "$BBR_STATE_TC_IFACE_MODE" "$BBR_STATE_TC_IFACE_VALUE" 2>/dev/null || true)"
    if [ -n "$iface" ]; then
        bbr_tc_clear "$iface"
        if [ "$BBR_STATE_NIC_STEERING" = "true" ]; then
            bbr_clear_nic_steering "$iface"
        fi
    fi
    return 0
}

bbr_apply_runtime_state() {
    local nic_steering="$1"
    local bql_limit="$2"
    local tc_iface_mode="$3"
    local tc_iface_value="$4"
    local egress_rate="$5"
    local ingress_rate="$6"
    local iface=""

    iface="$(bbr_resolve_iface "$tc_iface_mode" "$tc_iface_value" 2>/dev/null || true)"
    if [ -z "$iface" ] && { [ "$nic_steering" = "true" ] || [ -n "$egress_rate" ] || [ -n "$ingress_rate" ]; }; then
        bbr_die "未找到可用网卡，请使用 --tc-iface 显式指定"
    fi
    if [ -z "$iface" ]; then
        return 0
    fi

    bbr_apply_bql_limit "$iface" "$bql_limit"
    if [ "$nic_steering" = "true" ]; then
        bbr_apply_nic_steering "$iface"
    else
        bbr_clear_nic_steering "$iface"
    fi
    bbr_apply_tc_state "$iface" "$egress_rate" "$ingress_rate"
}

bbr_status() {
    bbr_state_load
    local cc qdisc release state_iface
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
    release="$(uname -r 2>/dev/null || echo unknown)"
    state_iface=""
    if [ "$BBR_STATE_PRESENT" = "true" ]; then
        state_iface="$(bbr_resolve_iface "$BBR_STATE_TC_IFACE_MODE" "$BBR_STATE_TC_IFACE_VALUE" 2>/dev/null || true)"
    fi
    echo "bbr status"
    echo "  kernel_release=$release"
    echo "  congestion_control=$cc"
    echo "  qdisc=$qdisc"
    echo "  bbr_available=$(bbr_sysctl_cc_available && echo true || echo false)"
    echo "  bbr_active=$([ "$cc" = "bbr" ] && echo true || echo false)"
    echo "  state_present=$BBR_STATE_PRESENT"
    echo "  applied_profile=${BBR_STATE_PROFILE:-none}"
    echo "  nic_steering=${BBR_STATE_NIC_STEERING:-false}"
    echo "  bql_limit=${BBR_STATE_BQL_LIMIT:-65536}"
    echo "  tc_iface_mode=${BBR_STATE_TC_IFACE_MODE:-auto}"
    echo "  tc_iface_value=${BBR_STATE_TC_IFACE_VALUE:-}"
    echo "  tc_iface_resolved=${state_iface:-}"
    echo "  egress_rate=${BBR_STATE_EGRESS_RATE:-}"
    echo "  ingress_rate=${BBR_STATE_INGRESS_RATE:-}"
    echo "  applied_at=${BBR_STATE_APPLIED_AT:-}"
    echo "  sysctl_conf=$PFWD_BBR_SYSCTL_CONF"
    echo "  service_file=$PFWD_BBR_SERVICE_FILE"
}

bbr_optimize_apply() {
    local profile="$1"
    local nic_steering="$2"
    local tc_iface_mode="$3"
    local tc_iface_value="$4"
    local egress_rate="$5"
    local ingress_rate="$6"
    local bql_limit="65536"

    bbr_require_mutation_context
    bbr_clear_previous_runtime
    bbr_apply_sysctl_profile "$profile"
    bbr_apply_runtime_state "$nic_steering" "$bql_limit" "$tc_iface_mode" "$tc_iface_value" "$egress_rate" "$ingress_rate"
    bbr_mkdir_p "$PFWD_STATE_DIR"
    bbr_state_save "$profile" "$nic_steering" "$bql_limit" "$tc_iface_mode" "$tc_iface_value" "$egress_rate" "$ingress_rate"
}

bbr_reset() {
    bbr_require_mutation_context
    bbr_clear_previous_runtime
    bbr_remove_path "$PFWD_BBR_SYSCTL_CONF"
    bbr_state_delete
}

bbr_restore() {
    bbr_require_mutation_context
    bbr_state_load
    [ "$BBR_STATE_PRESENT" = "true" ] || return 0
    [ -f "$PFWD_BBR_SYSCTL_CONF" ] && bbr_run sysctl -p "$PFWD_BBR_SYSCTL_CONF" >/dev/null
    bbr_apply_runtime_state \
        "$BBR_STATE_NIC_STEERING" \
        "$BBR_STATE_BQL_LIMIT" \
        "$BBR_STATE_TC_IFACE_MODE" \
        "$BBR_STATE_TC_IFACE_VALUE" \
        "$BBR_STATE_EGRESS_RATE" \
        "$BBR_STATE_INGRESS_RATE"
}

bbr_service_available() {
    command -v systemctl >/dev/null 2>&1 && [ -f "$PFWD_BBR_SERVICE_FILE" ]
}

bbr_enable_service() {
    if ! bbr_service_available; then
        echo "提示：未检测到已安装的 pfwd-bbr.service；当前优化仅对本次运行生效。" >&2
        return 0
    fi
    systemctl daemon-reload
    systemctl enable pfwd-bbr.service >/dev/null 2>&1 || true
}

bbr_disable_service() {
    if ! command -v systemctl >/dev/null 2>&1; then
        return 0
    fi
    systemctl stop pfwd-bbr.service >/dev/null 2>&1 || true
    systemctl disable pfwd-bbr.service >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
}

bbr_service_unit() {
    cat <<EOF
[Unit]
Description=pfwd bbr runtime restore
After=network-online.target systemd-sysctl.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PFWD_BBR_ALIAS_BIN_PATH __restore

[Install]
WantedBy=multi-user.target
EOF
}

bbr_install() {
    bbr_require_mutation_context
    [ -n "$SCRIPT_DIR" ] || bbr_die "无法定位 bbr.sh 源目录"

    bbr_mkdir_p "$PFWD_BBR_INSTALL_DIR" "$(dirname "$PFWD_BBR_BIN_PATH")" "$(dirname "$PFWD_BBR_ALIAS_BIN_PATH")" "$(dirname "$PFWD_BBR_SERVICE_FILE")"
    if [ "$SCRIPT_PATH" != "$PFWD_BBR_INSTALL_DIR/bbr.sh" ]; then
        cp "$SCRIPT_DIR/bbr.sh" "$PFWD_BBR_INSTALL_DIR/bbr.sh"
    fi
    chmod +x "$PFWD_BBR_INSTALL_DIR/bbr.sh"
    ln -sf "$PFWD_BBR_INSTALL_DIR/bbr.sh" "$PFWD_BBR_BIN_PATH"
    ln -sf "$PFWD_BBR_INSTALL_DIR/bbr.sh" "$PFWD_BBR_ALIAS_BIN_PATH"
    bbr_service_unit > "$PFWD_BBR_SERVICE_FILE"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        if [ -f "$PFWD_BBR_STATE_FILE" ]; then
            systemctl enable pfwd-bbr.service >/dev/null 2>&1 || true
        fi
    fi
}

bbr_uninstall() {
    bbr_require_mutation_context
    bbr_reset
    bbr_disable_service
    bbr_remove_path "$PFWD_BBR_SERVICE_FILE"
    bbr_remove_path "$PFWD_BBR_BIN_PATH"
    bbr_remove_path "$PFWD_BBR_ALIAS_BIN_PATH"
    bbr_remove_path "$PFWD_BBR_INSTALL_DIR/bbr.sh"
}

bbr_help() {
    local cmd
    cmd="$(bbr_preferred_command_name)"
    cat <<EOF
$cmd - pfwd BBR / optimize manager

用法：
  $cmd
  $cmd status
  $cmd optimize [balanced|gaming|lowmem|relay] [--nic-steering] [--egress-rate RATE] [--ingress-rate RATE] [--tc-iface IFACE]
  $cmd optimize reset
  $cmd reset
  $cmd install
  $cmd uninstall

说明：
  - 无参数且在交互终端运行时，会进入交互式菜单。
  - optimize 会写入 /etc/sysctl.d/99-pfwd-bbr.conf，并按需要应用 BQL、RPS/XPS 与 tc shaping。
  - 若已安装 pfwd-bbr.service，成功的 optimize 会自动启用该 unit 以便开机恢复。
EOF
}

main() {
    bbr_ensure_shortcuts
    local cmd="${1:-}"

    if [ -z "$cmd" ]; then
        if bbr_is_tty; then
            bbr_menu
            return 0
        fi
        cmd="help"
    fi

    case "$cmd" in
        help|-h|--help)
            bbr_help
            ;;
        version|--version)
            echo "$(bbr_command_name) $BBR_VERSION"
            ;;
        status)
            shift
            bbr_status "$@"
            ;;
        install)
            shift
            [ "$#" -eq 0 ] || bbr_die "$(bbr_command_name) install 不接受额外参数"
            bbr_install
            ;;
        uninstall)
            shift
            [ "$#" -eq 0 ] || bbr_die "$(bbr_command_name) uninstall 不接受额外参数"
            bbr_uninstall
            ;;
        optimize)
            shift
            local profile="balanced"
            local nic_steering="false"
            local tc_iface_mode="auto"
            local tc_iface_value=""
            local egress_rate=""
            local ingress_rate=""

            while [ "$#" -gt 0 ]; do
                case "$1" in
                    balanced|gaming|lowmem|relay)
                        profile="$1"
                        shift
                        ;;
                    --nic-steering)
                        nic_steering="true"
                        shift
                        ;;
                    --egress-rate)
                        egress_rate="$(bbr_normalize_rate "${2:-}")"
                        shift 2
                        ;;
                    --ingress-rate)
                        ingress_rate="$(bbr_normalize_rate "${2:-}")"
                        shift 2
                        ;;
                    --tc-iface)
                        tc_iface_mode="explicit"
                        tc_iface_value="${2:-}"
                        [ -n "$tc_iface_value" ] || bbr_die "必须提供 --tc-iface 的网卡名"
                        shift 2
                        ;;
                    reset)
                        shift
                        [ "$#" -eq 0 ] || bbr_die "$(bbr_command_name) optimize reset 不接受额外参数"
                        bbr_reset
                        bbr_disable_service
                        return 0
                        ;;
                    *)
                        bbr_die "未知选项：$1"
                        ;;
                esac
            done

            bbr_optimize_apply "$profile" "$nic_steering" "$tc_iface_mode" "$tc_iface_value" "$egress_rate" "$ingress_rate"
            bbr_enable_service
            ;;
        reset)
            shift
            [ "$#" -eq 0 ] || bbr_die "$(bbr_command_name) reset 不接受额外参数"
            bbr_reset
            bbr_disable_service
            ;;
        __restore)
            shift
            [ "$#" -eq 0 ] || bbr_die "$(bbr_command_name) __restore 不接受额外参数"
            bbr_restore
            ;;
        *)
            bbr_die "未知命令：$cmd"
            ;;
    esac
}

main "$@"
