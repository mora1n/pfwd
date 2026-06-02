#!/usr/bin/env bash
set -euo pipefail

PFWD_VERSION="0.2.9"

pfwd_detect_script_source() {
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

PFWD_SCRIPT_PATH="$(pfwd_detect_script_source || true)"
if [ -n "$PFWD_SCRIPT_PATH" ]; then
    PFWD_SCRIPT_DIR="$(cd "$(dirname "$PFWD_SCRIPT_PATH")" && pwd)"
else
    PFWD_SCRIPT_DIR=""
fi
PFWD_LIB_DIR="${PFWD_LIB_DIR:-${PFWD_SCRIPT_DIR:+$PFWD_SCRIPT_DIR/lib}}"
PFWD_REPO_RAW_URL="${PFWD_REPO_RAW_URL:-https://raw.githubusercontent.com/mora1n/pfwd/main}"
PFWD_LIB_FILES=(core config validate whitelist egress_whitelist forwarder runtime firewall stats notify guard downmask service commands ui)

pfwd_bootstrap_xdp_asset_name() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "pfwd-xdp-linux-amd64" ;;
        aarch64|arm64) echo "pfwd-xdp-linux-arm64" ;;
        *) return 1 ;;
    esac
}

pfwd_bootstrap_downmask_asset_name() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "pfwd-downmask-linux-amd64" ;;
        aarch64|arm64) echo "pfwd-downmask-linux-arm64" ;;
        *) return 1 ;;
    esac
}

pfwd_bootstrap_root_prefix() {
    local prefix="${PFWD_ROOT_PREFIX:-/}"
    prefix="${prefix%/}"
    if [ -z "$prefix" ]; then
        echo ""
    else
        echo "$prefix"
    fi
}

pfwd_bootstrap_path() {
    local rel="$1"
    local prefix
    prefix="$(pfwd_bootstrap_root_prefix)"
    if [ -z "$prefix" ]; then
        echo "/$rel"
    else
        echo "$prefix/$rel"
    fi
}

pfwd_bootstrap_download() {
    local url="$1"
    local target="$2"
    if [[ "$url" == file://* ]]; then
        cp "${url#file://}" "$target"
        return
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 --max-time 60 "$url" -o "$target"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$target" "$url"
    else
        echo "错误：需要 curl 或 wget 下载模块文件" >&2
        exit 1
    fi
}

pfwd_bootstrap_cleanup_partial_install() {
    local install_dir bin_path bbr_bin_path bbr_alias_path systemd_dir unit
    install_dir="$(pfwd_bootstrap_path usr/local/lib/pfwd)"
    bin_path="$(pfwd_bootstrap_path usr/local/bin/pfwd)"
    bbr_bin_path="$(pfwd_bootstrap_path usr/local/bin/bbr.sh)"
    bbr_alias_path="$(pfwd_bootstrap_path usr/local/bin/pfwd-bbr)"
    systemd_dir="$(pfwd_bootstrap_path etc/systemd/system)"

    rm -f "$bin_path" "$bbr_bin_path" "$bbr_alias_path"
    for unit in pfwd-forward.service pfwd.service pfwd.timer pfwd-bbr.service pfwd-xdp.service pfwd-downmask-feed.service; do
        rm -f "$systemd_dir/$unit"
    done
    rm -rf "$install_dir"
}

pfwd_bootstrap_install() {
    local install_dir bin_path systemd_dir lib_dir xdp_asset status
    install_dir="$(pfwd_bootstrap_path usr/local/lib/pfwd)"
    bin_path="$(pfwd_bootstrap_path usr/local/bin/pfwd)"
    systemd_dir="$(pfwd_bootstrap_path etc/systemd/system)"
    lib_dir="$install_dir/lib"

    mkdir -p "$lib_dir" "$install_dir/assets" "$(dirname "$bin_path")" "$systemd_dir"
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/pfwd.sh" "$install_dir/pfwd.sh"
    chmod +x "$install_dir/pfwd.sh"
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/bbr.sh" "$install_dir/bbr.sh"
    chmod +x "$install_dir/bbr.sh"
    xdp_asset="$(pfwd_bootstrap_xdp_asset_name)" || {
        echo "错误：当前架构暂不支持 XDP 预编译二进制：$(uname -m)" >&2
        exit 1
    }
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/assets/$xdp_asset" "$install_dir/assets/$xdp_asset"
    chmod +x "$install_dir/assets/$xdp_asset"
    local downmask_asset
    if downmask_asset="$(pfwd_bootstrap_downmask_asset_name)"; then
        if ! pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/assets/$downmask_asset" "$install_dir/assets/$downmask_asset"; then
            echo "错误：缺少必需的 downmask 预编译资产：assets/$downmask_asset" >&2
            echo "请补齐发布源中的该文件，或在源码仓库中先执行 ./downmask/build.sh 后再安装。" >&2
            exit 1
        fi
        chmod +x "$install_dir/assets/$downmask_asset"
    fi
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/assets/pfwd-geo-cn-v4.bin" "$install_dir/assets/pfwd-geo-cn-v4.bin"
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/assets/pfwd-geo-cn-v6.bin" "$install_dir/assets/pfwd-geo-cn-v6.bin"
    pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/assets/pfwd-geo-meta.json" "$install_dir/assets/pfwd-geo-meta.json"

    local lib
    for lib in "${PFWD_LIB_FILES[@]}"; do
        pfwd_bootstrap_download "$PFWD_REPO_RAW_URL/lib/$lib.sh" "$lib_dir/$lib.sh"
    done

    ln -sf "$install_dir/pfwd.sh" "$bin_path"
    echo "bootstrap 已完成，继续执行完整安装：$bin_path"
    if PFWD_BOOTSTRAPPED=1 "$bin_path" install; then
        return 0
    fi
    status=$?
    echo "bootstrap 安装失败，正在回滚临时安装文件" >&2
    pfwd_bootstrap_cleanup_partial_install || true
    exit "$status"
}

pfwd_load_libs_or_bootstrap() {
    local cmd="${1:-help}"
    local missing=()
    local lib
    for lib in "${PFWD_LIB_FILES[@]}"; do
        [ -f "$PFWD_LIB_DIR/$lib.sh" ] || missing+=("$lib.sh")
    done

    if [ "${#missing[@]}" -gt 0 ]; then
        if [ "$cmd" = "install" ]; then
            pfwd_bootstrap_install
            exit 0
        fi
        echo "错误：缺少模块目录：${PFWD_LIB_DIR:-<stdin>}" >&2
        echo "缺少模块：${missing[*]}" >&2
        echo "请先执行：wget -qO- $PFWD_REPO_RAW_URL/pfwd.sh | sudo bash -s -- install" >&2
        exit 1
    fi

    for lib in "${PFWD_LIB_FILES[@]}"; do
        # shellcheck source=/dev/null
        source "$PFWD_LIB_DIR/$lib.sh"
    done
}

pfwd_load_libs_or_bootstrap "${1:-help}"

pfwd_main() {
    if [ "${1:-}" != "uninstall" ]; then
        service_ensure_shortcut
    fi

    if [ "$#" -eq 0 ]; then
        if [ -t 0 ]; then
            cmd_menu
            return
        fi
        pfwd_die "请在交互式终端运行 pfwd，或使用 pfwd help 查看命令"
    fi

    local cmd="$1"
    shift || true

    case "$cmd" in
        help|-h|--help) pfwd_help ;;
        version|--version) echo "pfwd $PFWD_VERSION" ;;
        menu) cmd_menu "$@" ;;
        init) cmd_init "$@" ;;
        user) cmd_user "$@" ;;
        add) cmd_add "$@" ;;
        list) cmd_list "$@" ;;
        start) cmd_toggle_forward true "$@" ;;
        stop) cmd_toggle_forward false "$@" ;;
        delete) cmd_delete "$@" ;;
        forward) cmd_forward "$@" ;;
        expire) cmd_expire "$@" ;;
        limit) cmd_limit "$@" ;;
        user-forwards-limit) cmd_user_forwards_limit "$@" ;;
        traffic) cmd_traffic "$@" ;;
        stats) cmd_stats "$@" ;;
        export) cmd_export "$@" ;;
        import) cmd_import "$@" ;;
        render) cmd_render "$@" ;;
        refresh) cmd_refresh "$@" ;;
        restart) cmd_restart "$@" ;;
        reconcile) cmd_reconcile "$@" ;;
        notify-test) cmd_notify_test "$@" ;;
        notify-enable) cmd_notify_enable "$@" ;;
        notify-schedule) cmd_notify_schedule "$@" ;;
        notify-disable) cmd_notify_disable "$@" ;;
        notify-delete) cmd_notify_delete "$@" ;;
        guard) cmd_guard "$@" ;;
        downmask) cmd_downmask "$@" ;;
        doctor) cmd_doctor "$@" ;;
        install) cmd_install "$@" ;;
        update) cmd_update "$@" ;;
        uninstall) cmd_uninstall "$@" ;;
        __forward_boot) cmd_forward_boot "$@" ;;
        __update_finalize) cmd_update_finalize "$@" ;;
        *)
            pfwd_die "未知命令：$cmd"
            ;;
    esac
}

pfwd_help() {
    cat <<'EOF'
pfwd - XDP 端口转发管理脚本

用法：
  pfwd
  pfwd menu
  pfwd init
  pfwd user add <username>
  pfwd user list
  pfwd user delete <username> [--cascade]
  pfwd user telegram <username>|--all --bot-token TOKEN --chat-id CHAT_ID [--server-name NAME] [--enabled true|false]
  pfwd add --user-id ID --remote HOST:PORT[,PORT]|HOST:START-END --listen-port PORT[,PORT]|START-END [--listen-ip IP] [--protocol tcp|udp|tcp_udp] [--traffic-mode one-way|two-way] [--traffic-ratio 1.0] [--comment TEXT] [--mss-clamp|--mss VALUE] [--masquerade|--snat-source IP]
  pfwd add --user-id ID --remote HOST:PORT[,PORT]|HOST:START-END --random-port START-END [--listen-ip IP] [--protocol tcp|udp|tcp_udp] [--traffic-mode one-way|two-way] [--traffic-ratio 1.0] [--comment TEXT] [--mss-clamp|--mss VALUE] [--masquerade|--snat-source IP]
  pfwd list [--user-id ID]
  pfwd start <forward_id>
  pfwd stop <forward_id>
  pfwd delete <forward_id>
  pfwd forward update --forward-id ID [--listen-ip IP] [--listen-port PORT] [--remote-host HOST] [--remote-port PORT] [--stop-at YYYYMMDD[ HH:MM]|YYYY-MM-DD[ HH:MM]|YYYY/MM/DD[ HH:MM]|+7|7d|--clear-stop-at] [--protocol tcp|udp|tcp_udp] [--traffic-mode one-way|two-way] [--traffic-ratio 1.0] [--comment TEXT|--clear-comment] [--mss-clamp|--mss VALUE|--clear-mss] [--masquerade|--snat-source IP]
  pfwd expire set <forward_id> --stop-at YYYYMMDD[ HH:MM]|YYYY-MM-DD[ HH:MM]|YYYY/MM/DD[ HH:MM]|+7|7d
  pfwd expire clear <forward_id>
  pfwd expire user-set --user-id ID --stop-at YYYYMMDD[ HH:MM]|YYYY-MM-DD[ HH:MM]|YYYY/MM/DD[ HH:MM]|+7|7d
  pfwd expire user-clear --user-id ID
  pfwd limit set --forward-id ID [--traffic 100GB] [--rate 50Mbps] [--traffic-mode one-way|two-way]
  pfwd limit set --user-id ID [--traffic 1TB] [--rate 200Mbps]
  pfwd user-forwards-limit --user-id ID [--traffic 100GB] [--rate 50Mbps] [--traffic-mode one-way|two-way]
  pfwd traffic used set --user-id ID|--forward-id ID --used 100GB
  pfwd traffic reset-day set --user-id ID|--forward-id ID --day 0|15|15T09:30|'15 09:30'
  pfwd traffic reset-now --user-id ID|--forward-id ID
  pfwd stats [--user-id ID|--forward-id ID]
  pfwd export [file]
  pfwd import <file>
  pfwd render [forwarder|status|xdp|nft|tc|guard|units]
  pfwd refresh
  pfwd restart
  pfwd reconcile
  pfwd notify-test --user-id ID
  pfwd notify-schedule --user-id ID [--interval-minutes 60|--clear-interval] [--daily-time 09:30|--clear-daily]
  pfwd notify-disable --user-id ID
  pfwd notify-delete --user-id ID
  pfwd guard enable|disable|status|apply|remove
  pfwd guard protocols [--http on|off] [--https on|off] [--tls on|off] [--socks on|off] [--skip-port PORT[,PORT]|START-END] [--replace-skip-ports] [--clear-skip-ports]
  pfwd guard whitelist [--enabled true|false] [--include-cn true|false] [--cn-mode off|all|provinces] [--cidr IPv4/IPv6 CIDR|单个IP] [--replace-custom] [--clear-custom]
  pfwd guard whitelist status
  pfwd guard whitelist-cn list|status|all|off|select <省份...>
  pfwd guard whitelist-custom list|add|clear|delete|update ...
  pfwd guard egress-whitelist [--enabled true|false] [--include-cn true|false] [--cn-mode off|all|provinces] [--cidr IPv4/IPv6 CIDR|单个IP] [--replace-custom] [--clear-custom]
  pfwd guard egress-whitelist status
  pfwd guard egress-whitelist-cn list|status|all|off|select <省份...>
  pfwd guard egress-whitelist-custom list|add|clear|delete|update ...
  pfwd downmask status
  pfwd downmask policy [--pull-mode off|public|ab] [--min-ratio 1.5] [--max-ratio 2.8] [--time-window-start HH:MM|empty=all-day] [--time-window-end HH:MM|empty=all-day] [--max-jitter SEC] [--min-deficit-bytes 20MB] [--max-bytes-per-run 800MB] [--iface NAME]
  pfwd downmask public [--active-source NAME(cloudflare_dynamic|linode_tokyo_100mb|cachefly_100mb)] [--speed-limit 4M(default, bytes/s; also 32Mbps/4MB/s)]
  pfwd downmask public custom list|add|delete|clear ...   # query 源 URL 用 {bytes} 占位；range 源需支持 Range
  pfwd downmask ab-pull [--protocol tcp|udp] [--protocol-mode single|parallel] [--tcp-enabled true|false] [--udp-enabled true|false] [--remote-host HOST(IP)] [--remote-port PORT] [--local-ip IP] [--token TOKEN(openssl rand -hex 16)] [--speed-limit 4M(default, bytes/s; also 32Mbps/4MB/s)] [--timeout SEC] [--parallel-limit N] [--speed-jitter-percent 12] [--bytes-jitter-percent 18]
  pfwd downmask ab-pull targets list|add|delete|update|clear ...
  pfwd downmask ab-feed [--tcp-enabled true|false] [--udp-enabled true|false] [--bind-ip IP] [--tcp-port PORT] [--udp-port PORT] [--token TOKEN(openssl rand -hex 16)] [--seed-file PATH] [--udp-payload-bytes 1200|1.2KB]
  pfwd downmask seed generate [--path PATH] [--size 1GB]   # 推荐 256MB-4GB
  pfwd doctor [--bench]
  pfwd install
  pfwd update [--check|--yes]
  pfwd uninstall

环境变量：
  PFWD_ROOT_PREFIX   测试/安装根目录前缀。默认：/
  PFWD_CONFIG_FILE   覆盖配置文件路径。
  PFWD_DRY_RUN       设置为 1 时只打印会修改系统的命令，不实际执行。

无参数运行时默认进入交互菜单；使用 pfwd help 查看命令列表。
端口支持单个端口、逗号列表和范围，例如 443、443,553、1000-1005。
监听 IP 默认使用 :: 双栈监听；非 localhost 规则优先走 XDP，localhost/::1 自动走 nftables；两类规则并存时数据面显示为 hybrid，这属于正常分流，不是 fallback。XDP 真不可用时才会自动回退到 nftables。
转发协议支持 tcp、udp、tcp_udp；默认 tcp_udp。同一监听端口可拆分为一条 TCP 和一条 UDP 转发。
远端地址支持域名、IPv4 和 [IPv6]:PORT；localhost 会渲染为本地 IPv4/IPv6 双栈目标。
  `refresh` 会按当前配置重新应用运行态；`restart` 会先停止当前 XDP/nft/tc 运行态，再重新应用。
  MSS 和固定 SNAT 通过 `.forwards[].net` 字段持久化；转发网卡通过 `settings.forward.interface` 指定。
  MSS 默认不设置；SNAT 默认使用 masquerade。交互界面添加/修改转发时也可直接设置。
  内核调优已拆分到 `pfwd-bbr`（兼容入口仍保留 `bbr.sh`）。
  流量防护（协议封锁 + 入口白名单 + 出口白名单）由 `guard` 子命令管理。
  入口白名单限制的是入站来源 IPv4 / IPv6 CIDR；可选关闭国内段、允许全部国内 IP，或按省份批量允许；也可额外追加自定义 CIDR，且支持输入单个 IP（自动规范化为 /32 或 /128）。
  出口白名单限制的是转发目标解析出的 IPv4 / IPv6 CIDR；规则目标仍可填写域名，但解析出的每个目标 IP 都必须命中出口白名单；同时会作用于宿主机全部非 loopback 出口流量，并共享同一套国内 IP / 省份策略。
  两类白名单的国内 IP / 省份匹配默认使用随 `pfwd-xdp` 一起发布的预编译 geo 资产；自定义 CIDR 仍独立生效。
EOF
}

pfwd_main "$@"
