#!/bin/bash
#===============================================================================
#  pfwd - Port Forwarding Tool
#
#  Methods: nftables (with flowtable fast path) / realm
#  Features: CLI + Interactive / IPv4/IPv6 manual control / Traffic stats
#            / Boot persistence / Backup import/export / Kernel optimization
#
#  License: MIT
#===============================================================================

set -euo pipefail

#===============================================================================
#  Section 1: Constants & Colors
#===============================================================================

readonly VERSION="1.8.3"

# Paths
readonly DATA_DIR="/var/lib/pfwd"
readonly NFT_CONFIG="/etc/nftables.d/port_forward.nft"
readonly NFT_BACKUP_DIR="/root/.pfwd_backup"
readonly NFT_RESTORE_SCRIPT="$DATA_DIR/restore-nft.sh"
readonly NFT_RESTORE_SERVICE="/etc/systemd/system/pfwd-nft-restore.service"
readonly REALM_BIN="/usr/local/bin/realm"
readonly REALM_CONFIG_DIR="/etc/realm"
readonly REALM_CONFIG="$REALM_CONFIG_DIR/config.toml"
readonly REALM_SERVICE="/etc/systemd/system/realm-forward.service"
readonly SYSCTL_CONF="/etc/sysctl.d/99-pfwd.conf"
readonly UFW_BEFORE_RULES="/etc/ufw/before.rules"
readonly UFW_BEFORE6_RULES="/etc/ufw/before6.rules"
readonly TRAFFIC_DATA="$DATA_DIR/traffic_stats.dat"
readonly TRAFFIC_COLLECTOR="$DATA_DIR/traffic-collector.sh"
readonly TRAFFIC_SAVE_SERVICE="/etc/systemd/system/pfwd-traffic-save.service"
readonly TRAFFIC_SAVE_TIMER="/etc/systemd/system/pfwd-traffic-save.timer"

# Install paths
readonly INSTALL_DIR="/usr/local/bin"
readonly INSTALLED_SCRIPT="$INSTALL_DIR/pfwd.sh"
readonly SHORTCUT_LINK="$INSTALL_DIR/pfwd"

# nftables names
readonly NFT_TABLE="inet port_forward"
readonly IPTABLES_FWD_DNAT_COMMENT="pfwd-managed forward dnat"
readonly IPTABLES_FWD_EST_COMMENT="pfwd-managed forward established"
readonly IPTABLES_INPUT_DNAT_COMMENT="pfwd-managed input dnat"

# Colors (use $'...' so escape chars are real, works with echo -e and read -rp)
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

# disable_colors - strip all color codes
disable_colors() {
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
}

# Pre-scan for --no-color / --no-clear before anything else
for _arg in "$@"; do
    case "$_arg" in
        --no-color) disable_colors; ;;
        --no-clear) _NO_CLEAR=true; ;;
    esac
done
unset _arg

# Magic number constants
readonly MAX_PORT_RANGE=100        # max ports in a single range expansion
readonly MAX_BULK_PORTS=500        # max ports in paired range expansion
readonly NET_CACHE_TTL=30          # network detection cache TTL (seconds)
readonly MIN_DOWNLOAD_SIZE=1024    # minimum valid download size (bytes)

# Pre-generated separator lines (avoid subshell printf calls)
readonly SEP_EQ="============================================================"
readonly SEP_DASH="------------------------------------------------------------"
readonly SEP_EQ_40="========================================"
readonly SEP_DASH_40="----------------------------------------"

# Quiet mode flag
QUIET=false

# Batch mode flag: when true, per-rule save/restart is skipped
_BATCH_MODE=false

# nft output cache (TTL-based, avoids repeated nft list table calls)
_NFT_CACHE="" _NFT_CACHE_TIME=0 _NFT_CACHE_TTL=2

_nft_cached_table() {
    local now; now=$(date +%s)
    if (( now - _NFT_CACHE_TIME >= _NFT_CACHE_TTL )) || [[ -z "$_NFT_CACHE" ]]; then
        _NFT_CACHE=$(nft list table $NFT_TABLE 2>/dev/null) || _NFT_CACHE=""
        _NFT_CACHE_TIME=$now
    fi
    echo "$_NFT_CACHE"
}

_nft_table_exists() { [[ -n "$(_nft_cached_table)" ]]; }

_nft_cached_chain() {
    local chain="$1" data
    data=$(_nft_cached_table)
    [[ -z "$data" ]] && return 1
    echo "$data" | awk -v c="$chain" '$0 ~ "chain "c" [{]",/^\t[}]/'
}

_nft_invalidate_cache() { _NFT_CACHE="" _NFT_CACHE_TIME=0; }

_mark_nft_dirty() {
    _DIRTY_NFT=true
    _DIRTY_UFW_SYNC=true
    _DIRTY_UFW_RELOAD=true
    _NFT_BACKUP_NEEDED=true
    _nft_invalidate_cache
}

_mark_realm_dirty() {
    _DIRTY_REALM_CONFIG=true
    _DIRTY_REALM_SERVICE=true
}

_mark_realm_service_unit_dirty() {
    _DIRTY_REALM_SERVICE_UNIT=true
    _DIRTY_REALM_SERVICE=true
}

_reset_change_flags() {
    _DIRTY_NFT=false
    _DIRTY_UFW_SYNC=false
    _DIRTY_UFW_RELOAD=false
    _DIRTY_REALM_CONFIG=false
    _DIRTY_REALM_SERVICE=false
    _DIRTY_REALM_SERVICE_UNIT=false
    _NFT_BACKUP_NEEDED=false
    _UFW_FILES_CHANGED=false
}

_nft_count_rules() {
    local parsed="${1:-}"
    if [[ -z "$parsed" ]]; then
        parsed=$(_parse_nft_prerouting_rules)
    fi
    if [[ -z "$parsed" ]]; then
        echo 0
        return
    fi
    awk 'END { print NR+0 }' <<< "$parsed"
}

_realm_count_endpoints() {
    local endpoints="${1:-}"
    if [[ -z "$endpoints" ]]; then
        endpoints=$(_parse_realm_endpoints)
    fi
    if [[ -z "$endpoints" ]]; then
        echo 0
        return
    fi
    awk 'END { print NR+0 }' <<< "$endpoints"
}

_realm_network_value() {
    local key="$1"
    awk -F'=' -v k="$key" '
        /^[[:space:]]*\[network\][[:space:]]*$/ { in_network=1; next }
        /^[[:space:]]*\[/ { in_network=0 }
        in_network {
            line=$0
            sub(/[[:space:]]+#.*/, "", line)
            if (line ~ "^[[:space:]]*" k "[[:space:]]*=") {
                sub("^[[:space:]]*" k "[[:space:]]*=[[:space:]]*", "", line)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                gsub(/^"|"$/, "", line)
                print line
                exit
            }
        }
    ' "$REALM_CONFIG" 2>/dev/null
}

_pfwd_rule_scope() {
    local lport="$1" ipver="$2" proto="$3" target="${4:-}" tport="${5:-}"
    printf '%s:%s:%s:%s:%s' "$lport" "$ipver" "$proto" "$target" "$tport"
}

_pfwd_rule_tag() {
    local scope
    scope=$(_pfwd_rule_scope "$@")
    printf 'pfwd:%s' "$scope"
}

_pfwd_forward_tag() {
    local kind="$1"
    shift
    local scope
    scope=$(_pfwd_rule_scope "$@")
    printf 'pfwd_%s:%s' "$kind" "$scope"
}

_pfwd_postrouting_handles_by_tag() {
    local tag="$1"
    nft -a list chain $NFT_TABLE postrouting 2>/dev/null | \
        { grep -F "comment \"$tag\"" || true; } | \
        awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }'
}

_pfwd_forward_handles_by_scope() {
    local scope="$1"
    local rule_tag="pfwd:${scope}"
    nft -a list chain $NFT_TABLE forward 2>/dev/null | \
        { grep -F \
            -e "comment \"pfwd_fwd:${scope}\"" \
            -e "comment \"pfwd_ret:${scope}\"" \
            -e "comment \"${rule_tag}:mss\"" || true; } | \
        awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }'
}

_nft_rule_option_summary() {
    local snat_mode="${1:-}" snat_source="${2:-}" mss_mode="${3:-}" mss_value="${4:-}"
    local parts=()
    if [[ "$snat_mode" == "snat" && -n "$snat_source" ]]; then
        parts+=("snat:${snat_source}")
    fi
    case "$mss_mode" in
        clamp) parts+=("mss:clamp") ;;
        set)
            if [[ -n "$mss_value" ]]; then
                parts+=("mss:${mss_value}")
            else
                parts+=("mss:set")
            fi
            ;;
    esac
    if (( ${#parts[@]} == 0 )); then
        echo "-"
    else
        local IFS=','
        echo "${parts[*]}"
    fi
}

_pfwd_collect_state() {
    PFWD_NFT_RULES=$(_parse_nft_export_rules)
    PFWD_REALM_ENDPOINTS=$(_parse_realm_endpoints)
    PFWD_NFT_COUNT=$(_nft_count_rules "$(_parse_nft_prerouting_rules)")
    PFWD_REALM_COUNT=$(_realm_count_endpoints "$PFWD_REALM_ENDPOINTS")
    PFWD_NFT_RUNNING=false
    PFWD_REALM_RUNNING=false
    _nft_table_exists && PFWD_NFT_RUNNING=true
    systemctl is-active realm-forward >/dev/null 2>&1 && PFWD_REALM_RUNNING=true

    local current_cc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
    [[ "$current_cc" == "bbr" ]] && PFWD_BBR_ENABLED=true || PFWD_BBR_ENABLED=false

    PFWD_LOOPBACK_DNAT=false
    if [[ -n "$PFWD_NFT_RULES" ]] && awk -F'|' '$4 ~ /^127\./ || $4 == "::1" { found=1 } END { exit(found ? 0 : 1) }' <<< "$PFWD_NFT_RULES"; then
        PFWD_LOOPBACK_DNAT=true
    fi

    PFWD_UFW_LOOPBACK_STATE="n/a"
    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | head -1 | grep -q '^Status: active'; then
            if [[ -f "$UFW_BEFORE_RULES" ]] && grep -q '^# pfwd-managed loopback dnat start$' "$UFW_BEFORE_RULES" 2>/dev/null; then
                PFWD_UFW_LOOPBACK_STATE="ok"
            elif $PFWD_LOOPBACK_DNAT; then
                PFWD_UFW_LOOPBACK_STATE="missing"
            else
                PFWD_UFW_LOOPBACK_STATE="idle"
            fi
        else
            PFWD_UFW_LOOPBACK_STATE="disabled"
        fi
    fi

    PFWD_REALM_NOFILE=""
    if [[ -f "$REALM_SERVICE" ]]; then
        PFWD_REALM_NOFILE=$(awk -F'=' '/^LimitNOFILE=/{print $2; exit}' "$REALM_SERVICE" 2>/dev/null || true)
    fi
    if [[ -z "$PFWD_REALM_NOFILE" ]] && systemctl is-active realm-forward >/dev/null 2>&1; then
        PFWD_REALM_NOFILE=$(systemctl show realm-forward -p LimitNOFILE --value 2>/dev/null || true)
    fi

    PFWD_REALM_TCP_TIMEOUT=""
    PFWD_REALM_UDP_TIMEOUT=""
    PFWD_REALM_TCP_KEEPALIVE=""
    PFWD_REALM_TCP_KEEPALIVE_PROBE=""
    if [[ -f "$REALM_CONFIG" ]]; then
        PFWD_REALM_TCP_TIMEOUT=$(_realm_network_value tcp_timeout)
        PFWD_REALM_UDP_TIMEOUT=$(_realm_network_value udp_timeout)
        PFWD_REALM_TCP_KEEPALIVE=$(_realm_network_value tcp_keepalive)
        PFWD_REALM_TCP_KEEPALIVE_PROBE=$(_realm_network_value tcp_keepalive_probe)
    fi
}

_mktemp_in_dir() {
    local target="$1" dir
    dir=$(dirname "$target")
    mkdir -p "$dir" 2>/dev/null || true
    mktemp "$dir/.pfwd.XXXXXX"
}

_atomic_replace_file() {
    local tmp_file="$1" target="$2" mode="${3:-}"
    [[ -f "$tmp_file" ]] || return 1
    if [[ -n "$mode" ]]; then
        chmod "$mode" "$tmp_file" 2>/dev/null || true
    fi
    mv -f "$tmp_file" "$target"
}

_backup_nft_config() {
    [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]] || return 0
    mkdir -p "$NFT_BACKUP_DIR"
    cp "$NFT_CONFIG" "$NFT_BACKUP_DIR/nftables_$(date +%Y%m%d_%H%M%S).nft" 2>/dev/null || true
    ls -t "$NFT_BACKUP_DIR"/nftables_*.nft 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
}

# nft batch file for atomic operations (Phase 2)
_NFT_BATCH_FILE=""

# No-clear flag for interactive menu
_NO_CLEAR=false

# Change tracking flags (coalesce save/reload/restart side effects)
_DIRTY_NFT=false
_DIRTY_UFW_SYNC=false
_DIRTY_UFW_RELOAD=false
_DIRTY_REALM_CONFIG=false
_DIRTY_REALM_SERVICE=false
_DIRTY_REALM_SERVICE_UNIT=false
_NFT_BACKUP_NEEDED=false
_UFW_FILES_CHANGED=false

# Cached state snapshot for UI/status views
PFWD_NFT_RULES=""
PFWD_REALM_ENDPOINTS=""
PFWD_NFT_COUNT=0
PFWD_REALM_COUNT=0
PFWD_NFT_RUNNING=false
PFWD_REALM_RUNNING=false
PFWD_BBR_ENABLED=false
PFWD_LOOPBACK_DNAT=false
PFWD_UFW_LOOPBACK_STATE="n/a"
PFWD_REALM_NOFILE=""
PFWD_REALM_TCP_TIMEOUT=""
PFWD_REALM_UDP_TIMEOUT=""
PFWD_REALM_TCP_KEEPALIVE=""
PFWD_REALM_TCP_KEEPALIVE_PROBE=""

# Network detection cache
_NET_CACHE_TIME=0

# GitHub mirrors for smart download (China acceleration)
GITHUB_MIRRORS=(
    "https://ghproxy.com/"
    "https://mirror.ghproxy.com/"
    "https://gh.ddlc.top/"
    "https://github.moeyy.xyz/"
    "https://gh-proxy.com/"
    ""  # Direct connection (last resort)
)

#===============================================================================
#  Section 2: Utility Functions
#===============================================================================

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}" >&2
        echo "Try: sudo $0 $*" >&2
        exit 1
    fi
}

msg_info()  { $QUIET || echo -e "${BLUE}[INFO]${NC} $*"; }
msg_ok()    { $QUIET || echo -e "${GREEN}[OK]${NC} $*"; }
msg_warn()  { $QUIET || echo -e "${YELLOW}[WARN]${NC} $*"; }
msg_err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
msg_dim()   { $QUIET || echo -e "${DIM}$*${NC}"; }

# show_progress <current> <total> [label] - display progress bar
show_progress() {
    local current="$1" total="$2" label="${3:-Progress}"
    local pct=0
    (( total > 0 )) && pct=$(( current * 100 / total ))
    local filled=$(( pct / 5 ))       # 20 chars wide
    local empty=$(( 20 - filled ))
    local bar=""
    local i
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    printf "\r  %s: [%s] %d%% (%d/%d)" "$label" "$bar" "$pct" "$current" "$total"
    (( current == total )) && echo ""
}

wait_for_enter() {
    echo ""
    read -rp "Press Enter to return to main menu..."
}

# smart_download <url> <output_path> [timeout] - Smart download with GitHub mirror support
# Auto-detects GitHub URLs and tries multiple mirror sources to improve download success rate
smart_download() {
    local original_url="$1"
    local output_path="$2"
    local timeout=${3:-15}

    # Detect if it's a GitHub URL
    local is_github=false
    [[ "$original_url" =~ github\.com|githubusercontent\.com|github\.io ]] && is_github=true

    # Non-GitHub URL: direct download
    if [ "$is_github" = false ]; then
        if command -v wget >/dev/null 2>&1; then
            wget -q --timeout="$timeout" -O "$output_path" "$original_url" 2>/dev/null && return 0
        fi
        if command -v curl >/dev/null 2>&1; then
            curl -sL --connect-timeout "$timeout" --max-time 60 -o "$output_path" "$original_url" 2>/dev/null && return 0
        fi
        return 1
    fi

    # GitHub URL - try multiple mirror sources
    for mirror in "${GITHUB_MIRRORS[@]}"; do
        local download_url
        local try_timeout
        if [ -z "$mirror" ]; then
            download_url="$original_url"
            try_timeout=8
        else
            download_url="${mirror}${original_url}"
            try_timeout="$timeout"
        fi

        msg_dim "  Trying: ${download_url}"
        rm -f "$output_path" 2>/dev/null

        # wget preferred
        if command -v wget >/dev/null 2>&1; then
            if wget --timeout="$try_timeout" --tries=1 -q -O "$output_path" "$download_url" 2>/dev/null; then
                if [ -f "$output_path" ] && [ -s "$output_path" ]; then
                    local fsize=$(stat -c%s "$output_path" 2>/dev/null || stat -f%z "$output_path" 2>/dev/null || echo 0)
                    if [ "$fsize" -gt $MIN_DOWNLOAD_SIZE ]; then
                        [ -n "$mirror" ] && msg_ok "Downloaded via mirror successfully"
                        return 0
                    fi
                fi
            fi
        fi

        # wget 失败，尝试 curl
        rm -f "$output_path" 2>/dev/null
        if command -v curl >/dev/null 2>&1; then
            if timeout $((try_timeout + 10)) curl -sL --connect-timeout "$try_timeout" -o "$output_path" "$download_url" 2>/dev/null; then
                if [ -f "$output_path" ] && [ -s "$output_path" ]; then
                    local fsize=$(stat -c%s "$output_path" 2>/dev/null || stat -f%z "$output_path" 2>/dev/null || echo 0)
                    if [ "$fsize" -gt $MIN_DOWNLOAD_SIZE ]; then
                        [ -n "$mirror" ] && msg_ok "Downloaded via mirror successfully"
                        return 0
                    fi
                fi
            fi
        fi

        msg_dim "  Failed, trying next..."
    done

    rm -f "$output_path" 2>/dev/null
    msg_err "All download sources failed"
    return 1
}

# smart_api_get <url> [timeout] - Smart API request
# For GitHub API requests with automatic timeout and error handling
smart_api_get() {
    local original_url="$1"
    local timeout=${2:-10}
    local result=""

    # wget preferred
    if command -v wget >/dev/null 2>&1; then
        result=$(wget --timeout="$timeout" --tries=2 -qO- "$original_url" 2>/dev/null)
        if [ -n "$result" ] && [[ "$result" != *"rate limit"* ]] && [[ "$result" == *"tag_name"* || "$result" == *"{"* ]]; then
            echo "$result"
            return 0
        fi
    fi

    # curl fallback
    if command -v curl >/dev/null 2>&1; then
        result=$(curl -s --connect-timeout "$timeout" --max-time $((timeout + 5)) "$original_url" 2>/dev/null)
        if [ -n "$result" ] && [[ "$result" != *"rate limit"* ]]; then
            echo "$result"
            return 0
        fi
    fi

    echo "$result"
    return 1
}

# check_port_in_use <port> [proto] - Check if port is in use
# proto: tcp/udp/both (default: tcp)
# Returns: 0=not in use, 1=in use
check_port_in_use() {
    local port=$1
    local proto=${2:-tcp}

    # Check TCP port
    if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
        if command -v ss >/dev/null 2>&1; then
            if ss -tuln 2>/dev/null | grep -q ":$port "; then
                msg_warn "Port $port (TCP) is already in use"
                # Try to show process info
                if command -v ss >/dev/null 2>&1; then
                    local process_info=$(ss -tlnp 2>/dev/null | grep ":$port " | head -1)
                    if [[ -n "$process_info" ]]; then
                        msg_dim "  Process: $process_info"
                    fi
                fi
                read -rp "Continue adding rule anyway? [y/N]: " confirm
                [[ "$confirm" =~ ^[Yy]$ ]] || return 1
            fi
        elif command -v netstat >/dev/null 2>&1; then
            if netstat -tuln 2>/dev/null | grep -q ":$port "; then
                msg_warn "Port $port (TCP) is already in use"
                read -rp "Continue adding rule anyway? [y/N]: " confirm
                [[ "$confirm" =~ ^[Yy]$ ]] || return 1
            fi
        fi
    fi

    # Check UDP port
    if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
        if command -v ss >/dev/null 2>&1; then
            if ss -uln 2>/dev/null | grep -q ":$port "; then
                msg_warn "Port $port (UDP) is already in use"
                local process_info=$(ss -ulnp 2>/dev/null | grep ":$port " | head -1)
                if [[ -n "$process_info" ]]; then
                    msg_dim "  Process: $process_info"
                fi
                read -rp "Continue adding rule anyway? [y/N]: " confirm
                [[ "$confirm" =~ ^[Yy]$ ]] || return 1
            fi
        elif command -v netstat >/dev/null 2>&1; then
            if netstat -uln 2>/dev/null | grep -q ":$port "; then
                msg_warn "Port $port (UDP) is already in use"
                read -rp "Continue adding rule anyway? [y/N]: " confirm
                [[ "$confirm" =~ ^[Yy]$ ]] || return 1
            fi
        fi
    fi

    return 0
}

# detect_local_network - Detect local network environment
# Sets global variables: LOCAL_HAS_IPV4, LOCAL_HAS_IPV6, LOCAL_IPV4, LOCAL_IPV6, LOCAL_IPV4_TYPE, LOCAL_IPV6_TYPE
detect_local_network() {
    # 30-second TTL cache
    local now
    now=$(date +%s)
    if (( now - _NET_CACHE_TIME < NET_CACHE_TTL )) && [[ -n "${LOCAL_IPV4:-}${LOCAL_IPV6:-}" ]]; then
        return 0
    fi
    _NET_CACHE_TIME=$now

    LOCAL_HAS_IPV4=false
    LOCAL_HAS_IPV6=false
    LOCAL_IPV4=""
    LOCAL_IPV6=""
    LOCAL_IPV4_TYPE=""
    LOCAL_IPV6_TYPE=""

    # Detect IPv4
    LOCAL_IPV4=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1]; exit}') || true
    if [ -n "$LOCAL_IPV4" ]; then
        LOCAL_HAS_IPV4=true
        # Private address detection: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 (CGNAT)
        if [[ "$LOCAL_IPV4" =~ ^10\. ]] || \
           [[ "$LOCAL_IPV4" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
           [[ "$LOCAL_IPV4" =~ ^192\.168\. ]] || \
           [[ "$LOCAL_IPV4" =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]]; then
            LOCAL_IPV4_TYPE="private"
        else
            LOCAL_IPV4_TYPE="public"
        fi
    fi

    # Detect IPv6
    LOCAL_IPV6=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6 /{split($2,a,"/"); print a[1]; exit}') || true
    if [ -n "$LOCAL_IPV6" ]; then
        LOCAL_HAS_IPV6=true
        # Private address detection: fc00::/7 ULA, fe80::/10 link-local
        if [[ "$LOCAL_IPV6" =~ ^[fF][cCdD] ]] || [[ "$LOCAL_IPV6" =~ ^[fF][eE][89aAbB] ]]; then
            LOCAL_IPV6_TYPE="private"
        else
            LOCAL_IPV6_TYPE="public"
        fi
    fi
}

# detect_script_path - Detect script path
# Sets global variable: SCRIPT_PATH
detect_script_path() {
    # If $0 is an executable regular file, use it directly
    if [[ -f "$0" && -x "$0" && ! "$0" =~ ^/dev/fd/ && ! "$0" =~ ^/proc/ ]]; then
        SCRIPT_PATH="$0"
        return 0
    fi

    # Check if shortcut command exists
    if [[ -x "$SHORTCUT_LINK" ]]; then
        SCRIPT_PATH="$SHORTCUT_LINK"
        return 0
    fi

    # Check other possible installation paths
    for path in "$INSTALLED_SCRIPT" "/usr/bin/pfwd" "/usr/bin/pfwd.sh"; do
        if [[ -x "$path" ]]; then
            SCRIPT_PATH="$path"
            return 0
        fi
    done

    # Running via process substitution, cannot exec $0 directly
    if [[ "$0" =~ ^/dev/fd/ || "$0" =~ ^/proc/ ]]; then
        SCRIPT_PATH=""
        USE_LOOP_MENU=true
        return 1
    fi

    SCRIPT_PATH=""
    return 1
}

# ensure_script_installed - Ensure script is installed locally
# Called once at script start to support exec restart
ensure_script_installed() {
    detect_script_path

    # If script is already installed, no action needed
    if [[ -n "$SCRIPT_PATH" && -x "$SCRIPT_PATH" ]]; then
        return 0
    fi

    # Running via process substitution, set flag to use loop menu
    SCRIPT_PATH=""
    USE_LOOP_MENU=true
    return 1
}

# return_to_main_menu - Return to main menu
# Alternative to exec $0, solves exec $0 failure when running via bash <(curl ...)
return_to_main_menu() {
    # If valid script path exists, use exec to restart
    if [[ -n "$SCRIPT_PATH" && -x "$SCRIPT_PATH" ]]; then
        exec "$SCRIPT_PATH"
    fi

    # No valid path, set flag to continue main loop
    RETURN_TO_MENU=true
    return 0
}

# detect_ip_type <address> -> "ipv4" | "ipv6" | "domain" | "unknown"
detect_ip_type() {
    local addr="$1"
    if [[ "$addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "ipv4"
    elif [[ "$addr" =~ : ]]; then
        echo "ipv6"
    elif [[ "$addr" =~ ^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$ ]]; then
        echo "domain"
    else
        echo "unknown"
    fi
}

# validate_port <port> -> 0=valid, 1=invalid
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

# validate_port_range <spec> -> 0=valid, 1=invalid
# Accepts "80" or "8080-8090"
validate_port_range() {
    local spec="$1"
    if [[ "$spec" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        local s="${BASH_REMATCH[1]}" e="${BASH_REMATCH[2]}"
        (( s >= 1 && s <= 65535 && e >= 1 && e <= 65535 && s <= e ))
    elif [[ "$spec" =~ ^[0-9]+$ ]]; then
        (( spec >= 1 && spec <= 65535 ))
    else
        return 1
    fi
}

# expand_port_range <port_spec> -> echo space-separated port list
# Expands port ranges for deletion: "80" -> "80", "8080-8090" -> "8080 8081 ... 8090"
expand_port_range() {
    local spec="$1"

    # Check if it's a port range
    if [[ "$spec" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        local start="${BASH_REMATCH[1]}"
        local end="${BASH_REMATCH[2]}"

        # Validate port validity
        if ! validate_port "$start" || ! validate_port "$end"; then
            msg_err "Invalid port range: $spec"
            return 1
        fi

        # Validate range order
        if (( start > end )); then
            msg_err "Invalid port range: start ($start) > end ($end)"
            return 1
        fi

        # Validate range size (prevent accidental operations)
        local range_size=$((end - start + 1))
        if (( range_size > MAX_PORT_RANGE )); then
            msg_err "Port range too large: $range_size ports (max $MAX_PORT_RANGE)"
            return 1
        fi

        # Expand range
        local ports=()
        for ((p=start; p<=end; p++)); do
            ports+=("$p")
        done
        echo "${ports[@]}"
    else
        # Single port
        if validate_port "$spec"; then
            echo "$spec"
        else
            return 1
        fi
    fi
}

# validate_target <target> -> 0=valid, 1=invalid
validate_target() {
    local target="$1"
    local t
    t=$(detect_ip_type "$target")
    [[ "$t" != "unknown" ]]
}

# validate_mss_value <value> -> 0=valid, 1=invalid
validate_mss_value() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 536 && value <= 65535 ))
}

# parse_rule <rule_str> -> sets RULE_LPORT, RULE_TARGET, RULE_TPORT
# Formats: port:target:port  or  port:[ipv6]:port
parse_rule() {
    local rule="$1"
    RULE_LPORT=""
    RULE_TARGET=""
    RULE_TPORT=""

    # Handle IPv6 bracket format: lport:[ipv6addr]:tport
    if [[ "$rule" =~ ^([0-9]+):\[([^\]]+)\]:([0-9]+)$ ]]; then
        RULE_LPORT="${BASH_REMATCH[1]}"
        RULE_TARGET="${BASH_REMATCH[2]}"
        RULE_TPORT="${BASH_REMATCH[3]}"
    # Standard format: lport:target:tport
    elif [[ "$rule" =~ ^([0-9]+):(.+):([0-9]+)$ ]]; then
        RULE_LPORT="${BASH_REMATCH[1]}"
        RULE_TARGET="${BASH_REMATCH[2]}"
        RULE_TPORT="${BASH_REMATCH[3]}"
    else
        msg_err "Invalid rule format: $rule"
        msg_err "Expected: local_port:target:target_port or local_port:[ipv6]:target_port"
        return 1
    fi

    if ! validate_port "$RULE_LPORT"; then
        msg_err "Invalid local port: $RULE_LPORT"
        return 1
    fi
    if ! validate_port "$RULE_TPORT"; then
        msg_err "Invalid target port: $RULE_TPORT"
        return 1
    fi
    if ! validate_target "$RULE_TARGET"; then
        msg_err "Invalid target address: $RULE_TARGET"
        return 1
    fi
    return 0
}

# _expand_range_pair <lrange> <trange> <target> -> populates EXPANDED_RULES
# Expands paired local/target port ranges into lport:target:tport triples
_expand_range_pair() {
    local lrange="$1" trange="$2" target="$3"

    local lstart lend tstart tend
    if [[ "$lrange" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        lstart="${BASH_REMATCH[1]}"; lend="${BASH_REMATCH[2]}"
    else
        lstart="$lrange"; lend="$lrange"
    fi
    if [[ "$trange" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        tstart="${BASH_REMATCH[1]}"; tend="${BASH_REMATCH[2]}"
    else
        tstart="$trange"; tend="$trange"
    fi

    local lcount=$(( lend - lstart + 1 ))
    local tcount=$(( tend - tstart + 1 ))
    if (( lcount != tcount )); then
        msg_err "Port range length mismatch: $lrange ($lcount ports) vs $trange ($tcount ports)"
        return 1
    fi
    if (( lcount > MAX_BULK_PORTS )); then
        msg_err "Port range too large: $lcount ports (max $MAX_BULK_PORTS)"
        return 1
    fi

    local i
    for (( i=0; i<lcount; i++ )); do
        EXPANDED_RULES+=("$(( lstart + i )):$target:$(( tstart + i ))")
    done
}

# expand_port_spec <spec> <target> -> populates EXPANDED_RULES
# Accepts: 80 / 80,443 / 8080-8090 / 33389:3389 / 8080-8090:3080-3090 / mixed
expand_port_spec() {
    local spec="$1" target="$2"
    EXPANDED_RULES=()

    IFS=',' read -ra parts <<< "$spec"
    for part in "${parts[@]}"; do
        part="${part//[[:space:]]/}"
        [[ -z "$part" ]] && continue

        if [[ "$part" =~ ^([0-9-]+):([0-9-]+)$ ]]; then
            # Port mapping: lport:tport or lrange:trange
            local lspec="${BASH_REMATCH[1]}" tspec="${BASH_REMATCH[2]}"
            if ! validate_port_range "$lspec"; then
                msg_err "Invalid local port spec: $lspec"; continue
            fi
            if ! validate_port_range "$tspec"; then
                msg_err "Invalid target port spec: $tspec"; continue
            fi
            _expand_range_pair "$lspec" "$tspec" "$target" || continue
        elif [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            # Port range with same local/target: 8080-8090
            if ! validate_port_range "$part"; then
                msg_err "Invalid port range: $part"; continue
            fi
            _expand_range_pair "$part" "$part" "$target" || continue
        elif [[ "$part" =~ ^[0-9]+$ ]]; then
            # Single port
            if ! validate_port "$part"; then
                msg_err "Invalid port: $part"; continue
            fi
            EXPANDED_RULES+=("$part:$target:$part")
        else
            msg_err "Invalid port spec: $part"; continue
        fi
    done

    if (( ${#EXPANDED_RULES[@]} == 0 )); then
        msg_err "No valid port specs found"
        return 1
    fi
}

# format_bytes <bytes> -> human readable string
format_bytes() {
    local bytes="${1:-0}"
    [[ "$bytes" =~ ^[0-9]+$ ]] || { echo "0 B"; return; }
    if (( bytes < 1024 )); then
        echo "${bytes} B"
    elif (( bytes < 1048576 )); then
        printf "%d.%02d KB" $((bytes/1024)) $(( (bytes%1024)*100/1024 ))
    elif (( bytes < 1073741824 )); then
        printf "%d.%02d MB" $((bytes/1048576)) $(( (bytes%1048576)*100/1048576 ))
    else
        printf "%d.%02d GB" $((bytes/1073741824)) $(( (bytes%1073741824)*100/1073741824 ))
    fi
}

# ensure_jq - install jq if not available
ensure_jq() {
    command -v jq >/dev/null 2>&1 && return 0
    msg_info "Installing jq..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq jq >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q jq >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q jq >/dev/null 2>&1
    elif command -v apk >/dev/null 2>&1; then
        apk add --quiet jq >/dev/null 2>&1
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm jq >/dev/null 2>&1
    else
        msg_err "Cannot install jq automatically. Please install it manually."
        return 1
    fi
    command -v jq >/dev/null 2>&1 || { msg_err "Failed to install jq"; return 1; }
    msg_ok "jq installed"
}

# ensure_nft - check nftables available
ensure_nft() {
    if ! command -v nft >/dev/null 2>&1; then
        msg_err "nftables is not installed. Install it with your package manager."
        msg_err "  Debian/Ubuntu: apt install nftables"
        msg_err "  CentOS/RHEL:  yum install nftables"
        return 1
    fi
}

# get_local_ip - best-effort local IP for export metadata
get_local_ip() {
    local ip
    ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet / { sub(/\/.*/, "", $2); print $2; exit }' || true)
    [[ -n "$ip" ]] && { echo "$ip"; return; }
    ip=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6 / { sub(/\/.*/, "", $2); print $2; exit }' || true)
    [[ -n "$ip" ]] && { echo "$ip"; return; }
    hostname -I 2>/dev/null | awk '{print $1}'
}

# get_all_nics - get all up network interfaces except lo and virtual NICs
get_all_nics() {
    ip -o link show up 2>/dev/null | awk -F': ' '{
        name = $2; sub(/@.*/, "", name)
        if (name == "lo") next
        if (name ~ /^(veth|docker|br-|virbr|vnet|tun|tap|dummy)/) next
        nics = (nics ? nics "," : "") name
    } END { print nics }'
}

# ensure_shortcut - install/update pfwd to /usr/local/bin on first run
ensure_shortcut() {
    local current_script
    current_script="$(realpath "${BASH_SOURCE[0]}" 2>/dev/null || readlink -f "${BASH_SOURCE[0]}")"

    # Already running from installed location, just ensure symlink
    if [[ "$current_script" == "$INSTALLED_SCRIPT" ]]; then
        [[ ! -L "$SHORTCUT_LINK" ]] && ln -sf "$INSTALLED_SCRIPT" "$SHORTCUT_LINK"
        return 0
    fi

    # First-time install
    if [[ ! -f "$INSTALLED_SCRIPT" ]]; then
        cp "$current_script" "$INSTALLED_SCRIPT"
        chmod +x "$INSTALLED_SCRIPT"
        ln -sf "$INSTALLED_SCRIPT" "$SHORTCUT_LINK"
        msg_ok "Installed pfwd to $INSTALL_DIR (use 'pfwd' command from now on)"
        return 0
    fi

    # Already exists: MD5 check for update
    local cur_md5 inst_md5
    cur_md5=$(md5sum "$current_script" 2>/dev/null | awk '{print $1}')
    inst_md5=$(md5sum "$INSTALLED_SCRIPT" 2>/dev/null | awk '{print $1}')
    if [[ "$cur_md5" != "$inst_md5" ]]; then
        cp "$current_script" "$INSTALLED_SCRIPT"
        chmod +x "$INSTALLED_SCRIPT"
        [[ ! -L "$SHORTCUT_LINK" ]] && ln -sf "$INSTALLED_SCRIPT" "$SHORTCUT_LINK"
        msg_ok "pfwd updated to latest version"
    fi
}

# remove_shortcut - remove pfwd from /usr/local/bin
remove_shortcut() {
    rm -f "$SHORTCUT_LINK" "$INSTALLED_SCRIPT"
    msg_ok "pfwd shortcut removed"
}

# ensure_bbr_enabled - auto-enable BBR for optimal performance
ensure_bbr_enabled() {
    local current_cc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")

    if [[ "$current_cc" != "bbr" ]]; then
        msg_info "Enabling BBR congestion control for optimal performance..."

        # Check if BBR module is available
        if ! lsmod | grep -q tcp_bbr; then
            modprobe tcp_bbr 2>/dev/null || true
        fi

        # Temporarily enable BBR
        sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
        sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true

        # Verify if successful
        current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
        if [[ "$current_cc" == "bbr" ]]; then
            msg_ok "BBR enabled (runtime only)"
            msg_dim "  Run 'pfwd optimize' to persist BBR across reboots"
        else
            msg_warn "Failed to enable BBR (kernel may not support it)"
            msg_dim "  Realm will still work, but performance may be suboptimal"
        fi
    fi
}

#===============================================================================
#  Section 3: Kernel Optimization
#===============================================================================

# ensure_kernel_optimized - skip optimize_kernel if already configured
# Checks ip_forward and sysctl file; only runs full optimization if needed
ensure_ip_forwarding() {
    # Only enable IP forwarding (required for port forwarding); full kernel
    # optimization must be triggered explicitly via: pfwd optimize [profile]
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
        sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    fi
    if [[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" != "1" ]]; then
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true
        sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    fi
}

# ensure_route_localnet - enable route_localnet for DNAT to 127.0.0.0/8
# Required when forwarding to loopback (127.x.x.x) targets
ensure_route_localnet() {
    local current_all current_default
    current_all=$(sysctl -n net.ipv4.conf.all.route_localnet 2>/dev/null || echo 0)
    current_default=$(sysctl -n net.ipv4.conf.default.route_localnet 2>/dev/null || echo 0)

    [[ "$current_all" == "1" && "$current_default" == "1" ]] && return 0

    sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.route_localnet=1 >/dev/null 2>&1 || true
    msg_info "Enabled route_localnet (required for DNAT to loopback)"

    mkdir -p "$(dirname "$SYSCTL_CONF")"
    touch "$SYSCTL_CONF"
    grep -q '^net.ipv4.conf.all.route_localnet *= *1$' "$SYSCTL_CONF" 2>/dev/null || \
        echo "net.ipv4.conf.all.route_localnet = 1" >> "$SYSCTL_CONF"
    grep -q '^net.ipv4.conf.default.route_localnet *= *1$' "$SYSCTL_CONF" 2>/dev/null || \
        echo "net.ipv4.conf.default.route_localnet = 1" >> "$SYSCTL_CONF"
    msg_dim "  Persisted to $SYSCTL_CONF"
}

# _rewrite_ufw_file <file> <anchor> <marker_start> <marker_end> <block>
# Pure shell/awk implementation: remove old managed block and insert new block before anchor.
_rewrite_ufw_file() {
    local file="$1" anchor="$2" marker_start="$3" marker_end="$4" block="$5"
    [[ -f "$file" ]] || return 0

    local tmp_file block_file
    tmp_file=$(mktemp)
    block_file=$(mktemp)

    if [[ -n "$block" ]]; then
        {
            printf '%s\n' "$marker_start"
            printf '%s' "$block"
            [[ "$block" == *$'\n' ]] || printf '\n'
            printf '%s\n' "$marker_end"
        } > "$block_file"
    else
        : > "$block_file"
    fi

    awk -v start="$marker_start" -v end="$marker_end" -v anchor="$anchor" -v block_file="$block_file" '
        BEGIN {
            skip = 0
            inserted = 0
            block = ""
            while ((getline line < block_file) > 0) {
                block = block line "\n"
            }
            close(block_file)
        }
        {
            if ($0 == start) { skip = 1; next }
            if ($0 == end) { skip = 0; next }
            if (skip) next

            if (!inserted && $0 == anchor) {
                if (length(block) > 0) {
                    printf "%s", block
                }
                inserted = 1
            }
            print
        }
        END {
            if (!inserted && length(block) > 0) {
                printf "%s", block
            }
            print "COMMIT"
        }
    ' "$file" | awk '
        BEGIN { last = "" }
        {
            if ($0 == "COMMIT") {
                last = $0
                next
            }
            print
        }
        END {
            print "COMMIT"
        }
    ' > "$tmp_file"

    mv "$tmp_file" "$file"
    rm -f "$block_file"
}

# ufw_sync_loopback_dnat_rules - sync UFW before.rules accepts for loopback DNAT rules
# Generates accept rules from current nft DNAT rules targeting 127.0.0.0/8 or ::1.
ufw_sync_loopback_dnat_rules() {
    command -v ufw >/dev/null 2>&1 || return 0
    [[ -f "$UFW_BEFORE_RULES" ]] || return 0

    local marker_start="# pfwd-managed loopback dnat start"
    local marker_end="# pfwd-managed loopback dnat end"
    local block_v4="" block_v6=""
    local line proto tport
    local prerouting_lines
    prerouting_lines=$(_nft_cached_chain prerouting | grep "dnat" || true)

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        _extract_nft_proto_ipver "$line"
        proto="$_PROTO"
        [[ -z "$proto" ]] && continue

        if [[ "$line" =~ dnat\ ip\ to\ (127\.[0-9.]+):([0-9]+) ]]; then
            tport="${BASH_REMATCH[2]}"
            printf -v block_v4 '%s-A ufw-before-input -m conntrack --ctstate DNAT -p %s -d 127.0.0.1 --dport %s -j ACCEPT\n' "$block_v4" "$proto" "$tport"
        elif [[ "$line" =~ dnat\ ip6\ to\ \[(::1)\]:([0-9]+) ]]; then
            tport="${BASH_REMATCH[2]}"
            printf -v block_v6 '%s-A ufw6-before-input -m conntrack --ctstate DNAT -p %s -d ::1 --dport %s -j ACCEPT\n' "$block_v6" "$proto" "$tport"
        fi
    done <<< "$prerouting_lines"

    local before_hash before6_hash after_hash after6_hash
    before_hash=$(cksum "$UFW_BEFORE_RULES" 2>/dev/null | awk '{print $1":"$2}' || true)
    _rewrite_ufw_file "$UFW_BEFORE_RULES" '-A ufw-before-input -j ufw-not-local' "$marker_start" "$marker_end" "$block_v4"
    after_hash=$(cksum "$UFW_BEFORE_RULES" 2>/dev/null | awk '{print $1":"$2}' || true)
    [[ "$before_hash" != "$after_hash" ]] && _UFW_FILES_CHANGED=true

    if [[ -f "$UFW_BEFORE6_RULES" ]]; then
        before6_hash=$(cksum "$UFW_BEFORE6_RULES" 2>/dev/null | awk '{print $1":"$2}' || true)
        _rewrite_ufw_file "$UFW_BEFORE6_RULES" '-A ufw6-before-input -j ufw6-not-local' "$marker_start" "$marker_end" "$block_v6"
        after6_hash=$(cksum "$UFW_BEFORE6_RULES" 2>/dev/null | awk '{print $1":"$2}' || true)
        [[ "$before6_hash" != "$after6_hash" ]] && _UFW_FILES_CHANGED=true
    fi

    if $_UFW_FILES_CHANGED; then
        _DIRTY_UFW_RELOAD=true
    fi
    _DIRTY_UFW_SYNC=false
}

optimize_kernel() {
    local profile="${1:-balanced}"
    msg_info "Applying kernel optimizations (profile: $profile)..."

    local marker_start="# pfwd-managed-start"
    local marker_end="# pfwd-managed-end"

    # Remove old managed block if exists
    if [[ -f "$SYSCTL_CONF" ]]; then
        sed -i "/$marker_start/,/$marker_end/d" "$SYSCTL_CONF"
    fi

    mkdir -p "$(dirname "$SYSCTL_CONF")"

    # Profile-specific values
    local buf_max conntrack_max conntrack_tcp_est udp_timeout udp_stream_timeout
    local tcp_rmem tcp_wmem tcp_mem backlog somaxconn file_max
    local ft_tcp_timeout ft_udp_timeout conntrack_buckets gro_normal_batch
    local max_syn_backlog max_tw_buckets

    case "$profile" in
        gaming)
            buf_max=134217728        # 128MB
            conntrack_max=524288
            conntrack_tcp_est=3600
            udp_timeout=120          # Longer UDP timeout for gaming
            udp_stream_timeout=300
            tcp_rmem="4096 131072 134217728"
            tcp_wmem="4096 131072 134217728"
            tcp_mem="65536 98304 131072"
            backlog=50000
            somaxconn=32768
            file_max=3407872
            ft_tcp_timeout=300
            ft_udp_timeout=120
            conntrack_buckets=131072
            gro_normal_batch=8
            max_syn_backlog=16384
            max_tw_buckets=262144
            ;;
        lowmem)
            buf_max=16777216         # 16MB
            conntrack_max=131072
            conntrack_tcp_est=3600
            udp_timeout=30
            udp_stream_timeout=120
            tcp_rmem="4096 65536 16777216"
            tcp_wmem="4096 65536 16777216"
            tcp_mem="16384 24576 32768"
            backlog=10000
            somaxconn=4096
            file_max=1048576
            ft_tcp_timeout=60
            ft_udp_timeout=15
            conntrack_buckets=32768
            gro_normal_batch=4
            max_syn_backlog=4096
            max_tw_buckets=65536
            ;;
        balanced|*)
            buf_max=33554432         # 32MB
            conntrack_max=1048576
            conntrack_tcp_est=7200
            udp_timeout=60
            udp_stream_timeout=180
            tcp_rmem="4096 131072 33554432"
            tcp_wmem="4096 131072 33554432"
            tcp_mem="32768 49152 65536"
            backlog=4096
            somaxconn=4096
            file_max=6815744
            ft_tcp_timeout=300
            ft_udp_timeout=30
            conntrack_buckets=262144
            gro_normal_batch=8
            max_syn_backlog=4096
            max_tw_buckets=262144
            ;;
    esac

    cat >> "$SYSCTL_CONF" << EOF
$marker_start

# Profile: $profile

# File System
fs.file-max = $file_max

# IP Forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.default.forwarding = 1

# BBR Congestion Control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Optimization
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
net.ipv4.tcp_rfc1337 = 0                    # 防止 TIME-WAIT 暗杀攻击（0=防护，1=严格 RFC1337）
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_frto = 2

# UDP Optimization
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# Buffers
net.core.rmem_max = $buf_max
net.core.wmem_max = $buf_max
net.ipv4.tcp_mem = $tcp_mem
net.ipv4.tcp_rmem = $tcp_rmem
net.ipv4.tcp_wmem = $tcp_wmem
net.core.netdev_max_backlog = $backlog
net.core.somaxconn = $somaxconn

# Connection Tracking
net.netfilter.nf_conntrack_max = $conntrack_max
net.netfilter.nf_conntrack_tcp_timeout_established = $conntrack_tcp_est
net.netfilter.nf_conntrack_tcp_loose = 1
net.netfilter.nf_conntrack_udp_timeout = $udp_timeout
net.netfilter.nf_conntrack_udp_timeout_stream = $udp_stream_timeout
net.netfilter.nf_conntrack_acct = 1
net.netfilter.nf_conntrack_helper = 0
net.netfilter.nf_conntrack_buckets = $conntrack_buckets

# Flowtable Timeout
net.netfilter.nf_flowtable_tcp_timeout = $ft_tcp_timeout
net.netfilter.nf_flowtable_udp_timeout = $ft_udp_timeout

# GRO Optimization
net.core.gro_normal_batch = $gro_normal_batch

# DNAT Optimization
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.route_localnet = 1

# TCP Keepalive
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10

# SYN 防护与连接管理
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = $max_syn_backlog
net.ipv4.tcp_max_tw_buckets = $max_tw_buckets

$marker_end
EOF

    # tcp_adv_win_scale obsolete since kernel 6.6; skip on newer kernels
    local kver_num
    kver_num=$(uname -r | awk -F'[.-]' '{printf "%d%03d", $1, $2}')
    if (( kver_num < 6006 )); then
        echo "net.ipv4.tcp_adv_win_scale = 1" >> "$SYSCTL_CONF"
    fi

    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true

    # Cap BQL limit_max to prevent bufferbloat
    # flowtable fast path bypasses fq_codel; without this cap the NIC TX ring
    # buffer can grow to the kernel default (~1.75GB), causing latency spikes
    apply_bql_limits

    # Verify IP forwarding is actually enabled
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]]; then
        msg_warn "sysctl failed to enable IPv4 forwarding, trying direct write..."
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
        if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]]; then
            msg_err "Cannot enable IPv4 forwarding — port forwarding will not work"
        fi
    fi
    if [[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" != "1" ]]; then
        msg_warn "sysctl failed to enable IPv6 forwarding, trying direct write..."
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true
    fi

    msg_ok "Kernel optimizations applied ($profile profile)"
    msg_dim "  IP forwarding: enabled"
    msg_dim "  BBR congestion control: enabled"
    msg_dim "  TCP fast open: enabled"
    msg_dim "  Conntrack max: $conntrack_max (buckets: $conntrack_buckets)"
    msg_dim "  Conntrack accounting: enabled"
    msg_dim "  Flowtable timeout: tcp=${ft_tcp_timeout}s udp=${ft_udp_timeout}s"
    msg_dim "  Flowtable acceleration: via nftables"
    msg_dim "  BQL limit_max: capped at 64KB (anti-bufferbloat)"
}

# reset_kernel_optimization - remove pfwd-managed sysctl block and reload
reset_kernel_optimization() {
    if [[ ! -f "$SYSCTL_CONF" ]]; then
        msg_warn "No kernel optimization config found ($SYSCTL_CONF)"
        return 0
    fi

    local marker_start="# pfwd-managed-start"
    local marker_end="# pfwd-managed-end"

    if ! grep -q "$marker_start" "$SYSCTL_CONF" 2>/dev/null; then
        msg_warn "No pfwd-managed optimization block found in $SYSCTL_CONF"
        return 0
    fi

    sed -i "/$marker_start/,/$marker_end/d" "$SYSCTL_CONF"
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
    msg_ok "Kernel optimization removed (pfwd-managed block deleted)"
    msg_dim "  Note: some live kernel parameters may remain until reboot"
}

# apply_bql_limits - cap NIC TX byte queue limits to prevent bufferbloat
# flowtable fast path bypasses fq_codel AQM; without this cap the NIC TX ring
# buffer can grow to the kernel default (~1.75GB on some NICs), causing latency
# spikes under load (100ms idle → 300ms+ under traffic).
# 64KB cap: at 1Gbps drains in ~0.5ms; at 100Mbps ~5ms — acceptable for relay.
apply_bql_limits() {
    local limit="${1:-65536}"  # Default: 64KB
    local count=0
    for f in /sys/class/net/*/queues/tx-*/byte_queue_limits/limit_max; do
        [[ -f "$f" ]] || continue
        echo "$limit" > "$f" 2>/dev/null && ((count++)) || true
    done
    [[ $count -gt 0 ]] && msg_dim "  BQL limit_max: ${count} TX queue(s) capped at ${limit} bytes"
    return 0
}

#===============================================================================
#  Section 3b: Shared Helper Functions
#===============================================================================

# _extract_nft_proto_ipver <line> - sets _PROTO and _IPVER from nft rule line
_extract_nft_proto_ipver() {
    local line="$1"; _PROTO="" _IPVER=""
    if [[ "$line" =~ "ip protocol tcp" ]]; then _PROTO=tcp _IPVER=4
    elif [[ "$line" =~ "ip protocol udp" ]]; then _PROTO=udp _IPVER=4
    elif [[ "$line" =~ "ip6 nexthdr tcp" ]]; then _PROTO=tcp _IPVER=6
    elif [[ "$line" =~ "ip6 nexthdr udp" ]]; then _PROTO=udp _IPVER=6
    # postrouting masquerade 格式 fallback
    else
        [[ "$line" =~ "tcp dport" ]] && _PROTO=tcp
        [[ "$line" =~ "udp dport" ]] && _PROTO=udp
        if [[ "$line" =~ "ip daddr" ]]; then _IPVER=4
        elif [[ "$line" =~ "ip6 daddr" ]]; then _IPVER=6
        fi
    fi
}

# _extract_nft_dnat_target <line> - sets _TARGET and _TPORT from nft rule line
_extract_nft_dnat_target() {
    local line="$1"; _TARGET="" _TPORT=""
    if [[ "$line" =~ dnat\ ip\ to\ ([0-9.]+):([0-9]+) ]]; then
        _TARGET="${BASH_REMATCH[1]}"; _TPORT="${BASH_REMATCH[2]}"
    elif [[ "$line" =~ dnat\ ip6\ to\ \[([^\]]+)\]:([0-9]+) ]]; then
        _TARGET="${BASH_REMATCH[1]}"; _TPORT="${BASH_REMATCH[2]}"
    elif [[ "$line" =~ dnat\ ip\ to\ ([^\ ]+) ]]; then
        local full="${BASH_REMATCH[1]}"
        _TARGET="${full%:*}"; _TPORT="${full##*:}"
    elif [[ "$line" =~ dnat\ ip6\ to\ ([^\ ]+) ]]; then
        _TARGET="${BASH_REMATCH[1]}"; _TPORT=""
    fi
}

# _ensure_forward_counters - auto-migrate: add forward chain counter rules for existing rules
_ensure_forward_counters() {
    _nft_table_exists || return 0

    local pre_output
    pre_output=$(_nft_cached_chain prerouting | grep "dnat" || true)
    [[ -z "$pre_output" ]] && return 0

    local fwd_output
    fwd_output=$(nft list chain $NFT_TABLE forward 2>/dev/null || true)

    local added=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        _extract_nft_proto_ipver "$line"
        local proto="$_PROTO" ipver="$_IPVER"
        [[ -z "$proto" ]] && continue

        local lport=""
        [[ "$line" =~ dport\ ([0-9]+) ]] && lport="${BASH_REMATCH[1]}"
        [[ -z "$lport" ]] && continue

        _extract_nft_dnat_target "$line"
        local target="$_TARGET" tport="$_TPORT"
        [[ -z "$target" || -z "$tport" ]] && continue

        local scope ret_tag fwd_tag
        scope=$(_pfwd_rule_scope "$lport" "$ipver" "$proto" "$target" "$tport")
        ret_tag=$(_pfwd_forward_tag "ret" "$lport" "$ipver" "$proto" "$target" "$tport")
        fwd_tag=$(_pfwd_forward_tag "fwd" "$lport" "$ipver" "$proto" "$target" "$tport")

        # Already has forward counter
        echo "$fwd_output" | grep -Fq "comment \"$ret_tag\"" && continue

        local ip_family="ip"
        [[ "$ipver" == "6" ]] && ip_family="ip6"

        nft insert rule $NFT_TABLE forward $ip_family daddr "$target" "$proto" dport "$tport" counter comment "$fwd_tag" 2>/dev/null || true
        nft insert rule $NFT_TABLE forward $ip_family saddr "$target" "$proto" sport "$tport" counter comment "$ret_tag" 2>/dev/null || true
        ((added++)) || true
    done <<< "$pre_output"

    if (( added > 0 )); then
        _nft_invalidate_cache
        nft_save 2>/dev/null || true
    fi
}

# _extract_nft_bytes <line> - extract traffic bytes from counter
_extract_nft_bytes() {
    local line="$1"; _BYTES=0
    [[ "$line" =~ bytes\ ([0-9]+) ]] && _BYTES="${BASH_REMATCH[1]}"
}

# _extract_nft_comment <line> - extract comment
_extract_nft_comment() {
    local line="$1"; _COMMENT=""
    [[ "$line" =~ comment\ \"([^\"]+)\" ]] && _COMMENT="${BASH_REMATCH[1]}"
}

# _sort_parsed_rules - unified sort by protocol then port number
_sort_parsed_rules() { sort -t'|' -k1,1 -k2,2n; }

# _nft_traffic_from_chain <chain_data> <port> - extract traffic bytes from cached chain data
_nft_traffic_from_chain() {
    local data="$1" port="$2"
    echo "$data" | awk -v p="$port" '
        $0 ~ "dport "p"( |$)" && /counter/ {
            for(i=1;i<=NF;i++) if($i=="bytes") { sum+=$(i+1) }
        }
        END { print sum+0 }
    '
}

# _nft_handles_by_port <chain> <port> <proto> - get nft rule handles matching port/proto
# Output: space-separated handle numbers
_nft_handles_by_port() {
    local chain="$1" port="$2" proto="${3:-both}"
    local lines
    case "$proto" in
        tcp)
            lines=$(nft -a list chain $NFT_TABLE "$chain" 2>/dev/null | \
                { grep -E "(ip protocol tcp|ip6 nexthdr tcp).*dport $port\b" || true; })
            ;;
        udp)
            lines=$(nft -a list chain $NFT_TABLE "$chain" 2>/dev/null | \
                { grep -E "(ip protocol udp|ip6 nexthdr udp).*dport $port\b" || true; })
            ;;
        both)
            lines=$(nft -a list chain $NFT_TABLE "$chain" 2>/dev/null | \
                { grep -E "dport $port\b" || true; })
            ;;
        *)
            return 1
            ;;
    esac
    echo "$lines" | awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }'
}

# _dispatch_add_rule <method> <lport> <target> <tport> <ip_ver> <proto> <comment> [mss_mode] [mss_value] [snat_mode] [snat_source] [replace_mode]
# Unified add rule dispatcher for nft/realm
_dispatch_add_rule() {
    local method="$1" lport="$2" target="$3" tport="$4" ip_ver="$5" proto="$6" comment="$7"
    local mss_mode="${8:-}" mss_value="${9:-}" snat_mode="${10:-}" snat_source="${11:-}" replace_mode="${12:-false}"
    case "$method" in
        nft|nftables)
            nft_add_rule "$lport" "$target" "$tport" "$ip_ver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode"
            ;;
        realm)
            realm_add_endpoint "$lport" "$target" "$tport" "$ip_ver" "$comment"
            ;;
        *)
            msg_err "Unknown method: $method (use nft or realm)"
            return 1
            ;;
    esac
}

# _expand_port_list <ports_str> - expand comma-separated port specs into array
# Sets: all_ports array (caller must declare: local -a all_ports=())
_expand_port_list() {
    local ports_str="$1"
    IFS=',' read -ra port_specs <<< "$ports_str"
    all_ports=()
    for spec in "${port_specs[@]}"; do
        spec="${spec//[[:space:]]/}"
        [[ -z "$spec" ]] && continue
        local expanded
        if ! expanded=$(expand_port_range "$spec"); then
            continue
        fi
        all_ports+=($expanded)
    done
}

sync_managed_firewall_state() {
    local parsed="${1:-}"
    if [[ -z "$parsed" ]]; then
        parsed=$(_parse_nft_prerouting_rules)
    fi
    sync_managed_iptables_accept_rules "$parsed"
    ufw_sync_loopback_dnat_rules
}

# _batch_finalize <method> - finalize after batch add (save/persist/restart once)
_batch_finalize() {
    local method="$1"
    case "$method" in
        nft|nftables)
            # If batch file exists, commit atomically
            if [[ -n "$_NFT_BATCH_FILE" && -f "$_NFT_BATCH_FILE" ]]; then
                if nft -f "$_NFT_BATCH_FILE" 2>/dev/null; then
                    msg_dim "  Atomic batch commit successful"
                    _mark_nft_dirty
                else
                    msg_warn "Atomic batch failed, rules were added individually"
                fi
                rm -f "$_NFT_BATCH_FILE"
                _NFT_BATCH_FILE=""
                _nft_invalidate_cache
            fi
            if $_DIRTY_NFT; then
                sync_managed_firewall_state
                nft_save "auto"
                nft_setup_persistence
            elif $_DIRTY_UFW_SYNC; then
                ufw_sync_loopback_dnat_rules
            fi
            if $_DIRTY_UFW_RELOAD; then
                ufw_reload_if_enabled
                sync_managed_iptables_accept_rules
            fi
            ;;
        realm)
            realm_restart_service
            ;;
    esac
}

# _parse_delete_input <input_str> <total_rules> - parse delete input with prefix support
# Supports: #N (rule number), pN (port number), N (auto-detect)
# Ranges:   #N-#M / #N-M (rule range), pN-pM / pN-M (port range), N-M (port range)
# Sets: delete_rule_numbers array, delete_port_numbers array
# Returns: 0 on success, 1 on ambiguity error
_parse_delete_input() {
    local input_str="$1" total_rules="$2"
    delete_rule_numbers=()
    delete_port_numbers=()

    IFS=',' read -ra input_items <<< "$input_str"

    for item in "${input_items[@]}"; do
        item="${item//[[:space:]]/}"
        [[ -z "$item" ]] && continue

        # 1. Rule number range: #N-#M or #N-M
        if [[ "$item" =~ ^#([0-9]+)-#?([0-9]+)$ ]]; then
            local rstart="${BASH_REMATCH[1]}" rend="${BASH_REMATCH[2]}"
            if (( rstart > rend )); then
                msg_err "Invalid range: #$rstart-#$rend (start > end)"
                return 1
            fi
            if (( rstart < 1 || rend > total_rules )); then
                msg_err "Rule range #$rstart-#$rend out of bounds (1-$total_rules)"
                return 1
            fi
            if (( rend - rstart + 1 > MAX_PORT_RANGE )); then
                msg_err "Range too large: $((rend - rstart + 1)) items (max $MAX_PORT_RANGE)"
                return 1
            fi
            for (( r=rstart; r<=rend; r++ )); do
                delete_rule_numbers+=("$r")
            done

        # 2. Port range with p prefix: pN-pM or pN-M
        elif [[ "$item" =~ ^p([0-9]+)-p?([0-9]+)$ ]]; then
            local pstart="${BASH_REMATCH[1]}" pend="${BASH_REMATCH[2]}"
            if (( pstart > pend )); then
                msg_err "Invalid range: p$pstart-p$pend (start > end)"
                return 1
            fi
            if ! validate_port "$pstart" || ! validate_port "$pend"; then
                msg_err "Port out of range in p$pstart-p$pend (valid: 1-65535)"
                return 1
            fi
            if (( pend - pstart + 1 > MAX_PORT_RANGE )); then
                msg_err "Port range too large: $((pend - pstart + 1)) ports (max $MAX_PORT_RANGE)"
                return 1
            fi
            for (( p=pstart; p<=pend; p++ )); do
                delete_port_numbers+=("$p")
            done

        # 3. Pure numeric range: N-M → port range
        elif [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local nstart="${BASH_REMATCH[1]}" nend="${BASH_REMATCH[2]}"
            if (( nstart > nend )); then
                msg_err "Invalid range: $nstart-$nend (start > end)"
                return 1
            fi
            if ! validate_port "$nstart" || ! validate_port "$nend"; then
                msg_err "Port out of range in $nstart-$nend (valid: 1-65535)"
                return 1
            fi
            if (( nend - nstart + 1 > MAX_PORT_RANGE )); then
                msg_err "Port range too large: $((nend - nstart + 1)) ports (max $MAX_PORT_RANGE)"
                return 1
            fi
            for (( p=nstart; p<=nend; p++ )); do
                delete_port_numbers+=("$p")
            done

        # 4. Single rule number: #N
        elif [[ "$item" =~ ^#([0-9]+)$ ]]; then
            local rnum="${BASH_REMATCH[1]}"
            if (( rnum < 1 || rnum > total_rules )); then
                msg_err "Rule number #$rnum out of range (1-$total_rules)"
                return 1
            fi
            delete_rule_numbers+=("$rnum")

        # 5. Single port with p prefix: pN
        elif [[ "$item" =~ ^p([0-9]+)$ ]]; then
            local port="${BASH_REMATCH[1]}"
            delete_port_numbers+=("$port")

        # 6. Plain number: ambiguity check
        elif [[ "$item" =~ ^[0-9]+$ ]]; then
            local num="$item"
            if (( num >= 1 && num <= total_rules )); then
                msg_err "Input '$num' is ambiguous (could be rule number or port number)"
                echo -e "${DIM}  Use prefix to specify:${NC}"
                echo -e "${DIM}    #$num  - delete rule number $num${NC}"
                echo -e "${DIM}    p$num  - delete port number $num${NC}"
                return 1
            else
                delete_port_numbers+=("$num")
            fi

        else
            msg_err "Invalid input format: '$item'"
            return 1
        fi
    done

    return 0
}

#===============================================================================
#  Section 4: nftables Functions (with flowtable acceleration)
#===============================================================================

# nft_ensure_table - create table, chains, and flowtable if not exist
nft_ensure_table() {
    ensure_nft || return 1

    # Check if table already exists
    if _nft_table_exists; then
        return 0
    fi

    local nics
    nics=$(get_all_nics)
    if [[ -z "$nics" ]]; then
        msg_warn "No network interfaces detected for flowtable, using fallback"
        nics="eth0"
    fi

    msg_info "Creating nftables table..."

    nft add table $NFT_TABLE

    # Flowtable setup with diagnostics
    local flowtable_ok=false
    local kver
    kver=$(uname -r | grep -oE '^[0-9]+\.[0-9]+' || echo "0.0")
    local kmajor kminor
    IFS='.' read -r kmajor kminor <<< "$kver"

    if (( kmajor < 4 || (kmajor == 4 && kminor < 16) )); then
        msg_warn "Kernel $kver too old for flowtable (requires >= 4.16), skipping fast path"
    else
        # Try to load nf_flow_table module
        if ! lsmod | grep -q nf_flow_table; then
            msg_info "Loading nf_flow_table kernel module..."
            if modprobe nf_flow_table 2>/dev/null; then
                msg_ok "nf_flow_table module loaded"
                # Auto-persist module (idempotent)
                local modules_conf="/etc/modules-load.d/nf_flow_table.conf"
                if [[ ! -f "$modules_conf" ]] || ! grep -q '^nf_flow_table$' "$modules_conf" 2>/dev/null; then
                    mkdir -p /etc/modules-load.d
                    echo 'nf_flow_table' >> "$modules_conf"
                    msg_dim "  Module persisted to $modules_conf"
                fi
            else
                msg_warn "Cannot load nf_flow_table module (kernel may not support it)"
                msg_dim "  Install: apt install linux-modules-extra-$(uname -r)  (Debian/Ubuntu)"
                msg_dim "  Or: modprobe nf_flow_table  (if module is available)"
            fi
        fi

        # Try to create flowtable (three-level fallback)
        local ft_err
        if ft_err=$(nft add flowtable $NFT_TABLE ft "{ hook ingress priority 0; devices = { $nics }; flags offload; counter; }" 2>&1); then
            flowtable_ok=true
            msg_dim "  Flowtable: hardware offload + counter enabled"
        elif ft_err=$(nft add flowtable $NFT_TABLE ft "{ hook ingress priority 0; devices = { $nics }; counter; }" 2>&1); then
            flowtable_ok=true
            msg_dim "  Flowtable: counter enabled (no hardware offload)"
        elif ft_err=$(nft add flowtable $NFT_TABLE ft "{ hook ingress priority 0; devices = { $nics }; }" 2>&1); then
            flowtable_ok=true
            msg_dim "  Flowtable: basic mode (kernel < 5.7, no counter)"
        else
            msg_warn "Flowtable creation failed, continuing without fast path"
            msg_dim "  devices=($nics) error: $ft_err"
        fi
    fi

    # NAT chains
    nft add chain $NFT_TABLE prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'
    nft add chain $NFT_TABLE postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'

    # Forward chain with optional flowtable offload
    nft add chain $NFT_TABLE forward '{ type filter hook forward priority 0; policy accept; }'
    if $flowtable_ok; then
        nft add rule $NFT_TABLE forward ct state established flow add @ft counter 2>/dev/null || \
            msg_dim "  Flowtable offload rule skipped"
    fi
    nft add rule $NFT_TABLE forward ct state established,related accept

    # Input chain (for realm traffic counters and DNAT bypass)
    nft add chain $NFT_TABLE input '{ type filter hook input priority filter - 10; policy accept; }'
    nft add rule $NFT_TABLE input ip daddr 127.0.0.0/8 ct status dnat counter accept comment '"Allow DNAT to localhost before iptables"'

    if $flowtable_ok; then
        msg_ok "nftables table created with flowtable acceleration"
    else
        msg_ok "nftables table created (without flowtable)"
    fi

    ensure_forward_accept
}

_iptables_rule_present() {
    local bin="$1"; shift
    "$bin" -C "$@" >/dev/null 2>&1
}

_iptables_rule_ensure() {
    local bin="$1"; shift
    if ! _iptables_rule_present "$bin" "$@"; then
        "$bin" -I "$@" >/dev/null 2>&1 || true
    fi
}

_iptables_rule_delete_all() {
    local bin="$1"; shift
    while _iptables_rule_present "$bin" "$@"; do
        "$bin" -D "$@" >/dev/null 2>&1 || break
    done
}

_sync_managed_iptables_family() {
    local bin="$1" family="$2" parsed="${3:-}"
    command -v "$bin" >/dev/null 2>&1 || return 0

    local need_forward=false need_input=false
    local proto lport ipver target tport comment bytes
    while IFS='|' read -r proto lport ipver target tport comment bytes; do
        [[ -z "$lport" ]] && continue
        [[ "$ipver" == "$family" ]] || continue
        need_forward=true
        if [[ "$target" =~ ^127\. || "$target" == "::1" ]]; then
            need_input=true
        fi
    done <<< "$parsed"

    local forward_policy input_policy
    forward_policy=$("$bin" -S FORWARD 2>/dev/null | awk '/-P FORWARD/{print $3}')
    input_policy=$("$bin" -S INPUT 2>/dev/null | awk '/-P INPUT/{print $3}')

    if [[ "$forward_policy" == "DROP" && "$need_forward" == true ]]; then
        _iptables_rule_ensure "$bin" FORWARD -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_FWD_DNAT_COMMENT" -j ACCEPT
        _iptables_rule_ensure "$bin" FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$IPTABLES_FWD_EST_COMMENT" -j ACCEPT
    else
        _iptables_rule_delete_all "$bin" FORWARD -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_FWD_DNAT_COMMENT" -j ACCEPT
        _iptables_rule_delete_all "$bin" FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$IPTABLES_FWD_EST_COMMENT" -j ACCEPT
    fi

    if [[ "$input_policy" == "DROP" && "$need_input" == true ]]; then
        _iptables_rule_ensure "$bin" INPUT -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_INPUT_DNAT_COMMENT" -j ACCEPT
    else
        _iptables_rule_delete_all "$bin" INPUT -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_INPUT_DNAT_COMMENT" -j ACCEPT
    fi
}

sync_managed_iptables_accept_rules() {
    local parsed="${1:-}"
    if [[ -z "$parsed" ]]; then
        parsed=$(_parse_nft_prerouting_rules)
    fi

    _sync_managed_iptables_family iptables 4 "$parsed"
    _sync_managed_iptables_family ip6tables 6 "$parsed"
}

# ensure_forward_accept - keep managed iptables ACCEPT rules in sync with current nft state
ensure_forward_accept() {
    sync_managed_iptables_accept_rules
}

# nft_rule_exists <lport> <proto> <ip_ver> -> 0=exists, 1=not found
nft_find_existing_rule() {
    local lport="$1" proto="$2" ip_ver="$3" parsed="${4:-}"
    _NFT_EXIST_TARGET=""
    _NFT_EXIST_TPORT=""
    _NFT_EXIST_COMMENT=""
    _NFT_EXIST_BYTES="0"
    if [[ -z "$parsed" ]]; then
        parsed=$(_parse_nft_prerouting_rules)
    fi
    [[ -z "$parsed" ]] && return 1

    local found_proto found_lport found_ipver found_target found_tport found_comment found_bytes
    while IFS='|' read -r found_proto found_lport found_ipver found_target found_tport found_comment found_bytes; do
        [[ -z "$found_lport" ]] && continue
        if [[ "$found_lport" == "$lport" && "$found_proto" == "$proto" && "$found_ipver" == "$ip_ver" ]]; then
            _NFT_EXIST_TARGET="$found_target"
            _NFT_EXIST_TPORT="$found_tport"
            _NFT_EXIST_COMMENT="$found_comment"
            _NFT_EXIST_BYTES="$found_bytes"
            return 0
        fi
    done <<< "$parsed"

    return 1
}

nft_rule_exists() {
    nft_find_existing_rule "$1" "$2" "$3"
}

_nft_resolve_targets() {
    local target="$1" ip_ver="${2:-46}"
    local target_type resolved_v4="" resolved_v6=""
    target_type=$(detect_ip_type "$target")

    case "$target_type" in
        ipv4)
            [[ "$ip_ver" == "6" ]] && return 0
            printf 'ip|4|%s\n' "$target"
            ;;
        ipv6)
            [[ "$ip_ver" == "4" ]] && return 0
            printf 'ip6|6|%s\n' "$target"
            ;;
        domain)
            resolved_v4=$(getent ahosts "$target" 2>/dev/null | awk '/STREAM/{print $1}' | grep -E '^[0-9]+\.' | head -1 || true)
            resolved_v6=$(getent ahosts "$target" 2>/dev/null | awk '/STREAM/{print $1}' | grep ':' | head -1 || true)
            if [[ -z "$resolved_v4" && -z "$resolved_v6" ]]; then
                msg_err "Cannot resolve domain: $target"
                msg_err "Consider using realm for domain-based forwarding"
                return 1
            fi
            if [[ -n "$resolved_v4" && ( "$ip_ver" == "4" || "$ip_ver" == "46" ) ]]; then
                printf 'ip|4|%s\n' "$resolved_v4"
            fi
            if [[ -n "$resolved_v6" && ( "$ip_ver" == "6" || "$ip_ver" == "46" ) ]]; then
                printf 'ip6|6|%s\n' "$resolved_v6"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

_nft_prerouting_handles_exact() {
    local lport="$1" proto="$2" ip_ver="$3" target="$4" tport="$5"
    local chain_data="${6:-}"
    [[ -n "$chain_data" ]] || chain_data=$(nft -a list chain $NFT_TABLE prerouting 2>/dev/null || true)
    [[ -z "$chain_data" ]] && return 0

    local line handle=""
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        _extract_nft_proto_ipver "$line"
        [[ "$_PROTO" == "$proto" && "$_IPVER" == "$ip_ver" ]] || continue
        [[ "$line" =~ dport\ ([0-9]+) ]] || continue
        [[ "${BASH_REMATCH[1]}" == "$lport" ]] || continue
        _extract_nft_dnat_target "$line"
        [[ "$_TARGET" == "$target" && "$_TPORT" == "$tport" ]] || continue
        handle=""
        [[ "$line" =~ handle\ ([0-9]+) ]] && handle="${BASH_REMATCH[1]}"
        [[ -n "$handle" ]] && printf '%s\n' "$handle"
    done <<< "$chain_data"
}

_nft_delete_exact_rule() {
    local lport="$1" proto="$2" ip_ver="$3" target="$4" tport="$5"
    local scope rule_tag deleted=0
    scope=$(_pfwd_rule_scope "$lport" "$ip_ver" "$proto" "$target" "$tport")
    rule_tag=$(_pfwd_rule_tag "$lport" "$ip_ver" "$proto" "$target" "$tport")

    if $_BATCH_MODE && [[ -z "${_NFT_BATCH_FILE:-}" ]]; then
        _NFT_BATCH_FILE=$(mktemp)
    fi

    local prerouting_handles post_handles helper_handles h
    prerouting_handles=$(_nft_prerouting_handles_exact "$lport" "$proto" "$ip_ver" "$target" "$tport")
    post_handles=$(_pfwd_postrouting_handles_by_tag "$rule_tag")
    helper_handles=$(_pfwd_forward_handles_by_scope "$scope")

    for h in $prerouting_handles; do
        if $_BATCH_MODE && [[ -n "${_NFT_BATCH_FILE:-}" ]]; then
            echo "delete rule $NFT_TABLE prerouting handle $h" >> "$_NFT_BATCH_FILE"
            ((deleted++)) || true
        elif nft delete rule $NFT_TABLE prerouting handle "$h" 2>/dev/null; then
            ((deleted++)) || true
        fi
    done

    for h in $post_handles; do
        if $_BATCH_MODE && [[ -n "${_NFT_BATCH_FILE:-}" ]]; then
            echo "delete rule $NFT_TABLE postrouting handle $h" >> "$_NFT_BATCH_FILE"
            ((deleted++)) || true
        elif nft delete rule $NFT_TABLE postrouting handle "$h" 2>/dev/null; then
            ((deleted++)) || true
        fi
    done

    for h in $helper_handles; do
        if $_BATCH_MODE && [[ -n "${_NFT_BATCH_FILE:-}" ]]; then
            echo "delete rule $NFT_TABLE forward handle $h" >> "$_NFT_BATCH_FILE"
            ((deleted++)) || true
        elif nft delete rule $NFT_TABLE forward handle "$h" 2>/dev/null; then
            ((deleted++)) || true
        fi
    done

    (( deleted > 0 )) || return 1
    $_BATCH_MODE || _nft_invalidate_cache
    return 0
}

# _nft_add_single_rule <ip_family> <proto> <lport> <target> <tport> <comment>
# Unified helper for adding a single nft rule (IPv4 or IPv6).
# In batch mode, appends to $_NFT_BATCH_FILE instead of executing directly.
_nft_add_single_rule() {
    local ip_family="$1" proto="$2" lport="$3" target="$4" tport="$5" comment="${6:-}"
    local mss_mode="${7:-}" mss_value="${8:-}" snat_mode="${9:-masquerade}" snat_source="${10:-}" replace_mode="${11:-false}"
    local ipver="4" ip_match="ip protocol" dnat_keyword="ip" dnat_target="$target:$tport"
    if [[ "$ip_family" == "ip6" ]]; then
        ipver="6"
        ip_match="ip6 nexthdr"
        dnat_keyword="ip6"
        dnat_target="[$target]:$tport"
    fi

    if nft_rule_exists "$lport" "$proto" "$ipver"; then
        if [[ "$replace_mode" != "true" ]]; then
            msg_err "Conflict: IPv$ipver $proto port $lport already forwards to ${_NFT_EXIST_TARGET}:${_NFT_EXIST_TPORT}"
            msg_err "Use --replace to update that rule explicitly"
            return 1
        fi
        msg_info "Replacing existing IPv$ipver $proto rule for port $lport"
        if ! _nft_delete_exact_rule "$lport" "$proto" "$ipver" "$_NFT_EXIST_TARGET" "$_NFT_EXIST_TPORT"; then
            msg_err "Failed to prepare replacement for IPv$ipver $proto port $lport"
            return 1
        fi
    fi

    local nft_result=0
    local postrouting_action="masquerade"
    local rule_scope rule_tag fwd_tag ret_tag
    rule_scope=$(_pfwd_rule_scope "$lport" "$ipver" "$proto" "$target" "$tport")
    rule_tag=$(_pfwd_rule_tag "$lport" "$ipver" "$proto" "$target" "$tport")
    fwd_tag=$(_pfwd_forward_tag "fwd" "$lport" "$ipver" "$proto" "$target" "$tport")
    ret_tag=$(_pfwd_forward_tag "ret" "$lport" "$ipver" "$proto" "$target" "$tport")
    if [[ "$snat_mode" == "snat" && -n "$snat_source" ]]; then
        postrouting_action="snat to $snat_source"
    fi
    if $_BATCH_MODE && [[ -n "$_NFT_BATCH_FILE" ]]; then
        # Append to batch file for atomic commit
        if [[ -n "$comment" ]]; then
            echo "add rule $NFT_TABLE prerouting $ip_match $proto $proto dport $lport counter dnat $dnat_keyword to $dnat_target comment \"$comment\"" >> "$_NFT_BATCH_FILE"
            echo "add rule $NFT_TABLE postrouting ct status dnat $ip_family daddr $target $proto dport $tport counter $postrouting_action comment \"$rule_tag\"" >> "$_NFT_BATCH_FILE"
        else
            echo "add rule $NFT_TABLE prerouting $ip_match $proto $proto dport $lport counter dnat $dnat_keyword to $dnat_target" >> "$_NFT_BATCH_FILE"
            echo "add rule $NFT_TABLE postrouting ct status dnat $ip_family daddr $target $proto dport $tport counter $postrouting_action comment \"$rule_tag\"" >> "$_NFT_BATCH_FILE"
        fi
        echo "insert rule $NFT_TABLE forward $ip_family daddr $target $proto dport $tport counter comment \"$fwd_tag\"" >> "$_NFT_BATCH_FILE"
        echo "insert rule $NFT_TABLE forward $ip_family saddr $target $proto sport $tport counter comment \"$ret_tag\"" >> "$_NFT_BATCH_FILE"
        if [[ "$proto" == "tcp" ]]; then
            if [[ "$mss_mode" == "clamp" ]]; then
                echo "insert rule $NFT_TABLE forward $ip_family daddr $target $proto dport $tport $proto flags syn / syn,rst tcp option maxseg size set rt mtu comment \"${rule_tag}:mss\"" >> "$_NFT_BATCH_FILE"
            elif [[ "$mss_mode" == "set" && -n "$mss_value" ]]; then
                echo "insert rule $NFT_TABLE forward $ip_family daddr $target $proto dport $tport $proto flags syn / syn,rst tcp option maxseg size set $mss_value comment \"${rule_tag}:mss\"" >> "$_NFT_BATCH_FILE"
            fi
        fi
    else
        # Direct execution
        if [[ -n "$comment" ]]; then
            nft add rule $NFT_TABLE prerouting $ip_match "$proto" "$proto" dport "$lport" counter dnat $dnat_keyword to "$dnat_target" comment "$comment" 2>&1 && \
            nft add rule $NFT_TABLE postrouting ct status dnat $ip_family daddr "$target" "$proto" dport "$tport" counter $postrouting_action comment "$rule_tag" 2>&1
            nft_result=$?
        else
            nft add rule $NFT_TABLE prerouting $ip_match "$proto" "$proto" dport "$lport" counter dnat $dnat_keyword to "$dnat_target" 2>&1 && \
            nft add rule $NFT_TABLE postrouting ct status dnat $ip_family daddr "$target" "$proto" dport "$tport" counter $postrouting_action comment "$rule_tag" 2>&1
            nft_result=$?
        fi

        if (( nft_result == 0 )); then
            nft insert rule $NFT_TABLE forward $ip_family daddr "$target" "$proto" dport "$tport" counter comment "$fwd_tag" 2>/dev/null || true
            nft insert rule $NFT_TABLE forward $ip_family saddr "$target" "$proto" sport "$tport" counter comment "$ret_tag" 2>/dev/null || true
            if [[ "$proto" == "tcp" ]]; then
                if [[ "$mss_mode" == "clamp" ]]; then
                    nft insert rule $NFT_TABLE forward $ip_family daddr "$target" tcp dport "$tport" tcp flags syn / syn,rst tcp option maxseg size set rt mtu comment "${rule_tag}:mss" 2>/dev/null || true
                elif [[ "$mss_mode" == "set" && -n "$mss_value" ]]; then
                    nft insert rule $NFT_TABLE forward $ip_family daddr "$target" tcp dport "$tport" tcp flags syn / syn,rst tcp option maxseg size set "$mss_value" comment "${rule_tag}:mss" 2>/dev/null || true
                fi
            fi
        else
            msg_err "Failed to add IPv$ipver $proto rule :$lport -> $dnat_target"
            # Rollback: remove prerouting rule if it was added but postrouting failed
            local rb_handle
            rb_handle=$(nft -a list chain $NFT_TABLE prerouting 2>/dev/null | \
                { grep -E "$ip_match $proto.*dport $lport.*dnat $dnat_keyword to .*$target.*$tport" || true; } | \
                awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }' | tail -1)
            if [[ -n "$rb_handle" ]]; then
                nft delete rule $NFT_TABLE prerouting handle "$rb_handle" 2>/dev/null
                msg_dim "  Rolled back prerouting rule (handle $rb_handle)"
            fi
            return 1
        fi
    fi

    msg_dim "  Added IPv$ipver $proto :$lport -> $dnat_target"
    return 0
}

# nft_add_rule <lport> <target> <tport> <ip_ver> <proto> <comment>
# ip_ver: 4, 6, or 46
# proto: tcp, udp, or both
# comment: optional comment for the rule
# mss_mode: empty, clamp, or set
# mss_value: MSS value when mss_mode=set
# snat_mode: masquerade (default) or snat
# snat_source: source IP when snat_mode=snat
# replace_mode: false (default) or true
nft_add_rule() {
    local lport="$1" target="$2" tport="$3" ip_ver="${4:-46}" proto="${5:-tcp}" comment="${6:-}"
    local mss_mode="${7:-}" mss_value="${8:-}" snat_mode="${9:-masquerade}" snat_source="${10:-}" replace_mode="${11:-false}"

    nft_ensure_table || return 1

    # Initialize batch file if in batch mode and not yet created
    if $_BATCH_MODE && [[ -z "$_NFT_BATCH_FILE" ]]; then
        _NFT_BATCH_FILE=$(mktemp)
    fi

    # Check port availability
    if ! check_port_in_use "$lport" "$proto"; then
        msg_info "Cancelled"
        return 1
    fi

    local target_type
    target_type=$(detect_ip_type "$target")

    local resolved_targets
    if ! resolved_targets=$(_nft_resolve_targets "$target" "$ip_ver"); then
        return 1
    fi
    if [[ "$target_type" == "domain" ]]; then
        local resolved_summary=()
        while IFS='|' read -r _family _ipver resolved_target; do
            [[ -z "$resolved_target" ]] && continue
            resolved_summary+=("IPv${_ipver}:${resolved_target}")
        done <<< "$resolved_targets"
        if (( ${#resolved_summary[@]} > 0 )); then
            local IFS=' '
            msg_dim "  Resolved $target -> ${resolved_summary[*]}"
        fi
    fi

    local protos=()
    case "$proto" in
        tcp)  protos=(tcp) ;;
        udp)  protos=(udp) ;;
        both) protos=(tcp udp) ;;
        *)    msg_err "Invalid protocol: $proto"; return 1 ;;
    esac

    # Enable route_localnet if forwarding to loopback
    local _effective_target="$target"
    if [[ -n "$resolved_targets" ]]; then
        while IFS='|' read -r _family _ipver resolved_target; do
            if [[ "$_ipver" == "4" && -n "$resolved_target" ]]; then
                _effective_target="$resolved_target"
                break
            fi
        done <<< "$resolved_targets"
    fi
    if [[ "$_effective_target" =~ ^127\. ]]; then
        ensure_route_localnet
    fi

    local added=0

    local p family resolved_ip effective_ipver
    for p in "${protos[@]}"; do
        while IFS='|' read -r family effective_ipver resolved_ip; do
            [[ -n "$family" && -n "$effective_ipver" && -n "$resolved_ip" ]] || continue
            if _nft_add_single_rule "$family" "$p" "$lport" "$resolved_ip" "$tport" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode"; then
                ((added++)) || true
            fi
        done <<< "$resolved_targets"
    done

    if (( added == 0 )); then
        msg_err "No rules were added for :$lport -> $target:$tport"
        return 1
    fi

    _mark_nft_dirty
    if ! $_BATCH_MODE; then
        _batch_finalize nft
    fi
    msg_ok "nftables rule added: :$lport -> $target:$tport ($proto, IPv$ip_ver)"
}

_nft_collect_add_conflicts() {
    local target="$1" ip_ver="${2:-46}" proto="${3:-tcp}"
    NFT_ADD_CONFLICTS=()

    local parsed resolved_targets
    parsed=$(_parse_nft_prerouting_rules)
    [[ -n "$parsed" ]] || return 0
    if ! resolved_targets=$(_nft_resolve_targets "$target" "$ip_ver"); then
        return 1
    fi

    local -a protos=()
    case "$proto" in
        tcp)  protos=(tcp) ;;
        udp)  protos=(udp) ;;
        both) protos=(tcp udp) ;;
        *)    return 1 ;;
    esac

    local -A seen=()
    local expanded p family effective_ipver resolved_ip conflict_key
    for expanded in "${EXPANDED_RULES[@]}"; do
        parse_rule "$expanded" || continue
        for p in "${protos[@]}"; do
            while IFS='|' read -r family effective_ipver resolved_ip; do
                [[ -n "$family" && -n "$effective_ipver" && -n "$resolved_ip" ]] || continue
                conflict_key="${RULE_LPORT}|${p}|${effective_ipver}"
                [[ -z "${seen[$conflict_key]:-}" ]] || continue
                if nft_find_existing_rule "$RULE_LPORT" "$p" "$effective_ipver" "$parsed"; then
                    NFT_ADD_CONFLICTS+=("${p}|${RULE_LPORT}|${effective_ipver}|${_NFT_EXIST_TARGET}|${_NFT_EXIST_TPORT}|${resolved_ip}|${RULE_TPORT}")
                    seen["$conflict_key"]=1
                fi
            done <<< "$resolved_targets"
        done
    done
}

# nft_delete_port <port> - delete all rules matching this local port
nft_delete_port() {
    local port="$1"
    local proto="${2:-both}"  # Default: delete all protocols
    ensure_nft || return 1

    if ! _nft_table_exists; then
        msg_warn "No nftables forwarding table found"
        return 0
    fi

    local deleted=0

    # Step 1: Find prerouting DNAT rules matching dport $port (with protocol filter)
    local prerouting_lines
    case "$proto" in
        tcp)
            prerouting_lines=$(nft -a list chain $NFT_TABLE prerouting 2>/dev/null | \
                { grep -E "(ip protocol tcp|ip6 nexthdr tcp).*dport $port\b" || true; })
            ;;
        udp)
            prerouting_lines=$(nft -a list chain $NFT_TABLE prerouting 2>/dev/null | \
                { grep -E "(ip protocol udp|ip6 nexthdr udp).*dport $port\b" || true; })
            ;;
        both)
            prerouting_lines=$(nft -a list chain $NFT_TABLE prerouting 2>/dev/null | \
                { grep -E "dport $port\b" || true; })
            ;;
        *)
            msg_err "Invalid protocol: $proto"
            return 1
            ;;
    esac

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        # Extract handle from prerouting rule
        local handle=""
        if [[ "$line" =~ handle\ ([0-9]+) ]]; then
            handle="${BASH_REMATCH[1]}"
        fi
        [[ -z "$handle" ]] && continue

        # Extract DNAT target address and port for postrouting matching
        local dnat_addr="" dnat_port="" rule_tag="" rule_scope=""
        # IPv4: dnat ip to 1.2.3.4:3389
        if [[ "$line" =~ dnat\ ip\ to\ ([0-9.]+):([0-9]+) ]]; then
            dnat_addr="${BASH_REMATCH[1]}"
            dnat_port="${BASH_REMATCH[2]}"
        # IPv6: dnat ip6 to [::1]:3389
        elif [[ "$line" =~ dnat\ ip6\ to\ \[([^\]]+)\]:([0-9]+) ]]; then
            dnat_addr="${BASH_REMATCH[1]}"
            dnat_port="${BASH_REMATCH[2]}"
        fi
        _extract_nft_proto_ipver "$line"
        if [[ -n "$_PROTO" && -n "$_IPVER" && -n "$dnat_addr" && -n "$dnat_port" ]]; then
            rule_scope=$(_pfwd_rule_scope "$port" "$_IPVER" "$_PROTO" "$dnat_addr" "$dnat_port")
            rule_tag=$(_pfwd_rule_tag "$port" "$_IPVER" "$_PROTO" "$dnat_addr" "$dnat_port")
        fi

        # Delete the prerouting rule
        nft delete rule $NFT_TABLE prerouting handle "$handle" 2>/dev/null && ((deleted++)) || true

        # Step 2: Delete matching postrouting SNAT/masquerade rule using managed tag when available
        if [[ -n "$rule_tag" ]]; then
            local tagged_post_handles
            tagged_post_handles=$(_pfwd_postrouting_handles_by_tag "$rule_tag")
            for h in $tagged_post_handles; do
                nft delete rule $NFT_TABLE postrouting handle "$h" 2>/dev/null && ((deleted++)) || true
            done
        elif [[ -n "$dnat_addr" && -n "$dnat_port" ]]; then
            local post_handles
            post_handles=$(nft -a list chain $NFT_TABLE postrouting 2>/dev/null | \
                { grep -E "daddr $dnat_addr.*dport $dnat_port" || true; } | \
                awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }')
            for h in $post_handles; do
                nft delete rule $NFT_TABLE postrouting handle "$h" 2>/dev/null && ((deleted++)) || true
            done
        fi

        # Step 2b: Delete managed forward helper rules (including optional MSS rule)
        if [[ -n "$rule_scope" ]]; then
            local helper_handles
            helper_handles=$(_pfwd_forward_handles_by_scope "$rule_scope")
            for h in $helper_handles; do
                nft delete rule $NFT_TABLE forward handle "$h" 2>/dev/null && ((deleted++)) || true
            done
        fi
    done <<< "$prerouting_lines"

    if (( deleted > 0 )); then
        _mark_nft_dirty
        if ! $_BATCH_MODE; then
            _batch_finalize nft
        fi
        local proto_msg=""
        [[ "$proto" != "both" ]] && proto_msg=" ($proto)"
        msg_ok "Deleted $deleted nftables rule(s) for port $port$proto_msg"
    else
        msg_warn "No nftables rules found for port $port"
    fi
}

# nft_delete_ports_batch <ports_array> <proto> - batch delete multiple ports efficiently
# Fetches chain data once, collects all handles, then deletes in bulk
nft_delete_ports_batch() {
    local -n _ports_ref=$1
    local proto="${2:-both}"
    ensure_nft || return 1

    if ! _nft_table_exists; then
        msg_warn "No nftables forwarding table found"
        return 0
    fi

    # Fetch all chain data once with handles
    local pre_data post_data fwd_data
    pre_data=$(nft -a list chain $NFT_TABLE prerouting 2>/dev/null || true)
    post_data=$(nft -a list chain $NFT_TABLE postrouting 2>/dev/null || true)
    fwd_data=$(nft -a list chain $NFT_TABLE forward 2>/dev/null || true)

    local total_deleted=0

    for port in "${_ports_ref[@]}"; do
        local deleted=0

        # Filter prerouting lines for this port
        local prerouting_lines=""
        case "$proto" in
            tcp) prerouting_lines=$(echo "$pre_data" | { grep -E "(ip protocol tcp|ip6 nexthdr tcp).*dport $port\b" || true; }) ;;
            udp) prerouting_lines=$(echo "$pre_data" | { grep -E "(ip protocol udp|ip6 nexthdr udp).*dport $port\b" || true; }) ;;
            both) prerouting_lines=$(echo "$pre_data" | { grep -E "dport $port\b" || true; }) ;;
        esac

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local handle=""
            [[ "$line" =~ handle\ ([0-9]+) ]] && handle="${BASH_REMATCH[1]}"
            [[ -z "$handle" ]] && continue

            local dnat_addr="" dnat_port="" rule_tag="" rule_scope=""
            if [[ "$line" =~ dnat\ ip\ to\ ([0-9.]+):([0-9]+) ]]; then
                dnat_addr="${BASH_REMATCH[1]}"; dnat_port="${BASH_REMATCH[2]}"
            elif [[ "$line" =~ dnat\ ip6\ to\ \[([^\]]+)\]:([0-9]+) ]]; then
                dnat_addr="${BASH_REMATCH[1]}"; dnat_port="${BASH_REMATCH[2]}"
            fi
            _extract_nft_proto_ipver "$line"
            if [[ -n "$_PROTO" && -n "$_IPVER" && -n "$dnat_addr" && -n "$dnat_port" ]]; then
                rule_scope=$(_pfwd_rule_scope "$port" "$_IPVER" "$_PROTO" "$dnat_addr" "$dnat_port")
                rule_tag=$(_pfwd_rule_tag "$port" "$_IPVER" "$_PROTO" "$dnat_addr" "$dnat_port")
            fi

            nft delete rule $NFT_TABLE prerouting handle "$handle" 2>/dev/null && ((deleted++)) || true

            if [[ -n "$rule_tag" ]]; then
                local post_handles
                post_handles=$(echo "$post_data" | { grep -F "comment \"$rule_tag\"" || true; } | \
                    awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }')
                for h in $post_handles; do
                    nft delete rule $NFT_TABLE postrouting handle "$h" 2>/dev/null && ((deleted++)) || true
                done

                local helper_handles
                helper_handles=$(echo "$fwd_data" | grep -F \
                    -e "comment \"pfwd_fwd:${rule_scope}\"" \
                    -e "comment \"pfwd_ret:${rule_scope}\"" \
                    -e "comment \"${rule_tag}:mss\"" | \
                    awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }' || true)
                for h in $helper_handles; do
                    nft delete rule $NFT_TABLE forward handle "$h" 2>/dev/null && ((deleted++)) || true
                done
            elif [[ -n "$dnat_addr" && -n "$dnat_port" ]]; then
                local post_handles
                post_handles=$(echo "$post_data" | { grep -E "daddr $dnat_addr.*dport $dnat_port" || true; } | \
                    awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }')
                for h in $post_handles; do
                    nft delete rule $NFT_TABLE postrouting handle "$h" 2>/dev/null && ((deleted++)) || true
                done
            fi
        done <<< "$prerouting_lines"

        if (( deleted > 0 )); then
            local proto_msg=""
            [[ "$proto" != "both" ]] && proto_msg=" ($proto)"
            msg_ok "Deleted $deleted nftables rule(s) for port $port$proto_msg"
            ((total_deleted += deleted)) || true
        else
            msg_warn "No nftables rules found for port $port"
        fi
    done

    if (( total_deleted > 0 )); then
        _mark_nft_dirty
        _batch_finalize nft
    fi
}

# _parse_nft_prerouting_rules - parse nft prerouting output into structured data
# Output: proto|lport|ipver|target|tport|comment|bytes (one line per rule)
# Args: [nft_output] - if empty, fetches from nft
_parse_nft_prerouting_rules() {
    local nft_output="${1:-}"
    if [[ -z "$nft_output" ]]; then
        nft_output=$(_nft_cached_chain prerouting | grep "dnat" || true)
    fi
    [[ -z "$nft_output" ]] && return 0

    echo "$nft_output" | awk '
    /dnat/ {
        proto=""; ipver=""; lport=""; target=""; tport=""; comment=""; bytes="0"

        # Extract protocol and IP version
        if (match($0, /ip protocol tcp/))      { proto="tcp"; ipver="4" }
        else if (match($0, /ip protocol udp/)) { proto="udp"; ipver="4" }
        else if (match($0, /ip6 nexthdr tcp/)) { proto="tcp"; ipver="6" }
        else if (match($0, /ip6 nexthdr udp/)) { proto="udp"; ipver="6" }
        else {
            if (match($0, /tcp dport/)) proto="tcp"
            if (match($0, /udp dport/)) proto="udp"
            if (match($0, /ip daddr/))  ipver="4"
            if (match($0, /ip6 daddr/)) ipver="6"
        }

        # Extract local port: "dport NNN"
        if (match($0, /dport [0-9]+/)) {
            s = substr($0, RSTART, RLENGTH)
            sub(/dport /, "", s)
            lport = s
        }

        # Extract DNAT target using index() (mawk-compatible, no bracket regex)
        if (match($0, /dnat ip6 to /)) {
            # IPv6: "dnat ip6 to [addr]:port"
            rest = substr($0, RSTART + 13)
            p = index(rest, "]:")
            if (p > 0) {
                target = substr(rest, 1, p - 1)
                rest2 = substr(rest, p + 2)
                # Extract port (digits before space or end)
                match(rest2, /[0-9]+/)
                tport = substr(rest2, RSTART, RLENGTH)
            }
        } else if (match($0, /dnat ip to /)) {
            # IPv4: "dnat ip to 1.2.3.4:5678"
            rest = substr($0, RSTART + 11)
            # Get until space or end of string
            if (match(rest, /[^ ]+/)) {
                s = substr(rest, RSTART, RLENGTH)
                n = split(s, parts, ":")
                target = parts[1]; tport = parts[n]
            }
        }

        # Extract bytes: "bytes NNN"
        if (match($0, /bytes [0-9]+/)) {
            s = substr($0, RSTART, RLENGTH)
            sub(/bytes /, "", s)
            bytes = s
        }

        # Extract comment: comment "text"
        if (match($0, /comment "/)) {
            rest = substr($0, RSTART + 9)
            p = index(rest, "\"")
            if (p > 1) comment = substr(rest, 1, p - 1)
        }

        if (lport != "" && proto != "") {
            printf "%s|%s|%s|%s|%s|%s|%s\n", proto, lport, ipver, target, tport, comment, bytes
        }
    }
    '
}

# _parse_nft_export_rules - parse nft rules plus optional pfwd MSS/SNAT metadata
# Output: proto|lport|ipver|target|tport|comment|snat_mode|snat_source|mss_mode|mss_value
_parse_nft_export_rules() {
    local parsed
    parsed=$(_parse_nft_prerouting_rules)
    [[ -z "$parsed" ]] && return 0

    local post_data forward_data
    post_data=$(_nft_cached_chain postrouting || true)
    forward_data=$(_nft_cached_chain forward || true)

    local proto lport ipver target tport comment bytes
    while IFS='|' read -r proto lport ipver target tport comment bytes; do
        [[ -z "$lport" ]] && continue

        local tag snat_mode="masquerade" snat_source="" mss_mode="" mss_value=""
        local post_line="" mss_line=""
        tag=$(_pfwd_rule_tag "$lport" "$ipver" "$proto" "$target" "$tport")

        post_line=$(printf '%s\n' "$post_data" | grep -F "comment \"$tag\"" | head -1 || true)
        if [[ -n "$post_line" && "$post_line" =~ snat\ to\ ([^[:space:]]+) ]]; then
            snat_mode="snat"
            snat_source="${BASH_REMATCH[1]}"
        fi

        mss_line=$(printf '%s\n' "$forward_data" | grep -F "comment \"${tag}:mss\"" | head -1 || true)
        if [[ -n "$mss_line" ]]; then
            if [[ "$mss_line" =~ tcp\ option\ maxseg\ size\ set\ rt\ mtu ]]; then
                mss_mode="clamp"
            elif [[ "$mss_line" =~ tcp\ option\ maxseg\ size\ set\ ([0-9]+) ]]; then
                mss_mode="set"
                mss_value="${BASH_REMATCH[1]}"
            fi
        fi

        printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
            "$snat_mode" "$snat_source" "$mss_mode" "$mss_value"
    done <<< "$parsed"
}

# _parse_nft_bidirectional_traffic - parse prerouting + forward chain for traffic stats
# Output: proto|lport|ipver|target|tport|comment|in_bytes|out_bytes|total_bytes
_parse_nft_bidirectional_traffic() {
    # Get prerouting rules (inbound traffic)
    local prerouting_output
    prerouting_output=$(_nft_cached_chain prerouting | grep "dnat" || true)
    [[ -z "$prerouting_output" ]] && return 0

    # Get forward chain return counters (outbound traffic)
    local forward_ret_output
    forward_ret_output=$(_nft_cached_chain forward | grep "pfwd_ret:" || true)

    # Use awk to combine prerouting (inbound) with forward return (outbound) data
    {
        echo "===PREROUTING==="
        echo "$prerouting_output"
        echo "===FORWARD_RET==="
        echo "$forward_ret_output"
    } | awk '
    /^===PREROUTING===/ { section="pre"; next }
    /^===FORWARD_RET===/ { section="fwd"; next }

    section == "pre" && /dnat/ {
        proto=""; ipver=""; lport=""; target=""; tport=""; comment=""; bytes="0"

        if (match($0, /ip protocol tcp/))      { proto="tcp"; ipver="4" }
        else if (match($0, /ip protocol udp/)) { proto="udp"; ipver="4" }
        else if (match($0, /ip6 nexthdr tcp/)) { proto="tcp"; ipver="6" }
        else if (match($0, /ip6 nexthdr udp/)) { proto="udp"; ipver="6" }

        # dport
        if (match($0, /dport [0-9]+/)) {
            s = substr($0, RSTART, RLENGTH); sub(/dport /, "", s); lport = s
        }
        # dnat target (mawk-compatible: avoid bracket regex)
        if (match($0, /dnat ip6 to /)) {
            rest = substr($0, RSTART + 13)
            p = index(rest, "]:")
            if (p > 0) {
                target = substr(rest, 1, p - 1)
                rest2 = substr(rest, p + 2)
                match(rest2, /[0-9]+/); tport = substr(rest2, RSTART, RLENGTH)
            }
        } else if (match($0, /dnat ip to /)) {
            rest = substr($0, RSTART + 11)
            if (match(rest, /[^ ]+/)) {
                s = substr(rest, RSTART, RLENGTH)
                n = split(s, da, ":"); target = da[1]; tport = da[n]
            }
        }
        # bytes
        if (match($0, /bytes [0-9]+/)) {
            s = substr($0, RSTART, RLENGTH); sub(/bytes /, "", s); bytes = s
        }
        # comment
        if (match($0, /comment "/)) {
            rest = substr($0, RSTART + 9)
            ci = index(rest, "\"")
            if (ci > 1) comment = substr(rest, 1, ci - 1)
        }

        if (lport != "" && proto != "") {
            key = proto "|" lport "|" ipver
            in_bytes[key] = bytes
            info[key] = target "|" tport "|" comment
        }
    }

    section == "fwd" && /pfwd_ret:/ {
        # Extract pfwd_ret:<lport>:<ipver>:<proto> using POSIX match+substr
        if (match($0, /pfwd_ret:[0-9]+:[46]:[a-z]+/)) {
            s = substr($0, RSTART, RLENGTH)
            sub(/pfwd_ret:/, "", s)
            n = split(s, rp, ":")
            if (n >= 3) {
                key = rp[3] "|" rp[1] "|" rp[2]
                if (key in in_bytes) {
                    ob = "0"
                    if (match($0, /bytes [0-9]+/)) {
                        bs = substr($0, RSTART, RLENGTH)
                        sub(/bytes /, "", bs)
                        ob = bs
                    }
                    out_bytes[key] = ob
                }
            }
        }
    }

    END {
        for (key in in_bytes) {
            ib = in_bytes[key]
            ob = (key in out_bytes) ? out_bytes[key] : "0"
            total = ib + ob
            printf "%s|%s|%d|%d|%d\n", key, info[key], ib, ob, total
        }
    }
    '
}

# nft_list_rules - display all forwarding rules in a table
nft_list_rules() {
    local filter="${1:-}"
    local parsed="${2:-}"
    if ! command -v nft >/dev/null 2>&1; then
        msg_dim "  nftables is not installed"
        return 0
    fi

    if ! _nft_table_exists; then
        msg_dim "  No nftables forwarding rules"
        return 0
    fi

    if [[ -z "$parsed" ]]; then
        parsed=$(_traffic_read_merged)
    fi

    # Fallback to prerouting-only if no merged data (e.g. no dat file yet)
    if [[ -z "$parsed" ]]; then
        parsed=$(_parse_nft_prerouting_rules)
    fi

    if [[ -z "$parsed" ]]; then
        msg_dim "  No nftables forwarding rules"
        return 0
    fi

    echo -e "${CYAN}nftables forwarding rules:${NC}"
    echo -e "  ${DIM}┌────┬────────┬──────┬──────┬──────────────────────────────┬──────────────────┬────────────────────┬──────────┐${NC}"
    printf "  ${DIM}│${NC}${BOLD}%-4s${NC}${DIM}│${NC}${BOLD}%-8s${NC}${DIM}│${NC}${BOLD}%-6s${NC}${DIM}│${NC}${BOLD}%-6s${NC}${DIM}│${NC}${BOLD}%-30s${NC}${DIM}│${NC}${BOLD}%-18s${NC}${DIM}│${NC}${BOLD}%-20s${NC}${DIM}│${NC}${BOLD}%-10s${NC}${DIM}│${NC}\n" " # " " L.Port" " Proto" " IPvr" " Target" " Options" " Comment" " Traffic"
    echo -e "  ${DIM}├────┼────────┼──────┼──────┼──────────────────────────────┼──────────────────┼────────────────────┼──────────┤${NC}"

    # Sort by protocol (tcp first) and then by port number
    local sorted_rules
    sorted_rules=$(echo "$parsed" | _sort_parsed_rules)

    # Display sorted rules (supports both 10-field export format and older traffic-only formats)
    local idx=0
    while IFS='|' read -r proto lport ipver target tport comment f7 f8 f9 f10; do
        [[ -z "$lport" ]] && continue
        local snat_mode="masquerade" snat_source="" mss_mode="" mss_value="" bytes="0"
        if [[ -n "$f10" || "$f7" == "masquerade" || "$f7" == "snat" || "$f9" == "clamp" || "$f9" == "set" ]]; then
            snat_mode="$f7"
            snat_source="$f8"
            mss_mode="$f9"
            mss_value="$f10"
            bytes=$(nft_get_traffic "$lport")
        else
            bytes="${f9:-$f7}"
        fi
        # Apply filter if specified
        if [[ -n "$filter" ]]; then
            local opts_text
            opts_text=$(_nft_rule_option_summary "$snat_mode" "$snat_source" "$mss_mode" "$mss_value")
            local line_text=":$lport $proto IPv$ipver ${target}:${tport} ${comment:--} ${opts_text}"
            [[ ! "$line_text" =~ $filter ]] && continue
        fi
        ((idx++)) || true
        local traffic
        traffic=$(format_bytes "$bytes")
        # Color coding: proto (tcp=green, udp=yellow), ipver (4=cyan, 6=blue)
        local proto_color="" ipver_color="" traffic_color=""
        if [[ -n "$GREEN" ]]; then
            [[ "$proto" == "tcp" ]] && proto_color="$GREEN" || proto_color="$YELLOW"
            [[ "$ipver" == "4" ]] && ipver_color="$CYAN" || ipver_color="$BLUE"
            if (( bytes > 1073741824 )); then traffic_color="$RED"
            elif (( bytes > 104857600 )); then traffic_color="$YELLOW"
            elif (( bytes > 1048576 )); then traffic_color="$GREEN"
            fi
        fi
        local target_display="$target:$tport"
        local option_display
        option_display=$(_nft_rule_option_summary "$snat_mode" "$snat_source" "$mss_mode" "$mss_value")
        # Truncate target/options/comment to fit column widths
        local disp_target=" ${target_display}" disp_opts=" ${option_display}" disp_comment=" ${comment:--}"
        (( ${#disp_target} > 30 )) && disp_target="${disp_target:0:28}.."
        (( ${#disp_opts} > 18 )) && disp_opts="${disp_opts:0:16}.."
        (( ${#disp_comment} > 20 )) && disp_comment="${disp_comment:0:18}.."
        printf "  ${DIM}│${NC}%-4s${DIM}│${NC}%-8s${DIM}│${NC}${proto_color}%-6s${NC}${DIM}│${NC}${ipver_color}%-6s${NC}${DIM}│${NC}%-30s${DIM}│${NC}%-18s${DIM}│${NC}%-20s${DIM}│${NC}${traffic_color}%-10s${NC}${DIM}│${NC}\n" \
            " $idx" " :$lport" " $proto" " v$ipver" "$disp_target" "$disp_opts" "$disp_comment" " $traffic"
    done <<< "$sorted_rules"
    echo -e "  ${DIM}└────┴────────┴──────┴──────┴──────────────────────────────┴──────────────────┴────────────────────┴──────────┘${NC}"
}

# nft_get_traffic <port> - get traffic bytes for a port
nft_get_traffic() {
    local port="$1"
    local chain_data
    chain_data=$(_nft_cached_chain prerouting) || chain_data=""
    local bytes
    bytes=$(_nft_traffic_from_chain "$chain_data" "$port")
    echo "${bytes:-0}"
}

# nft_save - persist rules to file
nft_save() {
    local mode="${1:-auto}"
    mkdir -p "$(dirname "$NFT_CONFIG")"
    local tmp_file
    tmp_file=$(_mktemp_in_dir "$NFT_CONFIG") || return 1

    if [[ "$mode" == "backup" || "$mode" == "explicit" || $_NFT_BACKUP_NEEDED == true ]]; then
        _backup_nft_config
    fi

    if ! nft list table $NFT_TABLE > "$tmp_file" 2>/dev/null; then
        rm -f "$tmp_file" 2>/dev/null || true
        msg_warn "Failed to export nftables rules to $NFT_CONFIG"
        return 1
    fi
    if [[ ! -s "$tmp_file" ]]; then
        rm -f "$tmp_file" 2>/dev/null || true
        msg_warn "Exported nftables rules were empty; keeping existing $NFT_CONFIG"
        return 1
    fi
    if ! _atomic_replace_file "$tmp_file" "$NFT_CONFIG" 0644; then
        rm -f "$tmp_file" 2>/dev/null || true
        msg_warn "Failed to atomically replace $NFT_CONFIG"
        return 1
    fi
    _NFT_BACKUP_NEEDED=false

    msg_dim "  Rules saved to $NFT_CONFIG"
    _DIRTY_NFT=false
    _nft_invalidate_cache
}

# ufw_reload_if_enabled - reload ufw if it's enabled to apply nftables changes
ufw_reload_if_enabled() {
    if ! $_DIRTY_UFW_RELOAD; then
        return 0
    fi

    # Check if ufw is installed
    if ! command -v ufw >/dev/null 2>&1; then
        _DIRTY_UFW_RELOAD=false
        return 0
    fi

    # Check if ufw is enabled
    local ufw_status
    ufw_status=$(ufw status 2>/dev/null | head -1)
    if [[ "$ufw_status" =~ "Status: active" ]]; then
        msg_dim "  Reloading ufw to apply nftables changes..."
        if ufw reload >/dev/null 2>&1; then
            msg_dim "  ufw reloaded successfully"
            # Re-add iptables ACCEPT rules after UFW reload (may have been flushed)
            ensure_forward_accept
        else
            msg_warn "Failed to reload ufw, you may need to reload it manually"
        fi
    fi
    _DIRTY_UFW_RELOAD=false
}

# nft_flush_all - delete entire table and config files
nft_flush_all() {
    nft delete table $NFT_TABLE 2>/dev/null || true
    _nft_invalidate_cache
    sync_managed_iptables_accept_rules ""
    ufw_sync_loopback_dnat_rules
    ufw_reload_if_enabled
    rm -f "$NFT_CONFIG"
    rm -f "$NFT_RESTORE_SCRIPT"
    if [[ -f "$NFT_RESTORE_SERVICE" ]]; then
        systemctl disable pfwd-nft-restore 2>/dev/null || true
        rm -f "$NFT_RESTORE_SERVICE"
    fi
    # Clean up traffic collector timer/service/script/data
    systemctl stop pfwd-traffic-save.timer 2>/dev/null || true
    systemctl disable pfwd-traffic-save.timer 2>/dev/null || true
    rm -f "$TRAFFIC_SAVE_SERVICE" "$TRAFFIC_SAVE_TIMER"
    rm -f "$TRAFFIC_COLLECTOR" "$TRAFFIC_DATA"
    systemctl daemon-reload 2>/dev/null || true
    msg_ok "nftables rules and persistence removed"
}

# nft_setup_persistence - create restore script + systemd service
nft_setup_persistence() {
    mkdir -p "$DATA_DIR"
    mkdir -p "$(dirname "$NFT_CONFIG")"

    # nft_save already exports rules to NFT_CONFIG, only re-export if file missing
    if [[ ! -f "$NFT_CONFIG" || ! -s "$NFT_CONFIG" ]]; then
        nft_save "auto" >/dev/null 2>&1 || true
    fi

    # Create restore script
    local restore_tmp service_tmp collector_tmp timer_tmp
    restore_tmp=$(_mktemp_in_dir "$NFT_RESTORE_SCRIPT") || return 1
    cat > "$restore_tmp" << 'RESTORE_EOF'
#!/bin/bash
# pfwd nftables restore script
LOG="/var/log/pfwd-restore.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }

log "Restoring nftables rules..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null

# Enable route_localnet (required for DNAT to 127.x.x.x)
echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet 2>/dev/null
echo 1 > /proc/sys/net/ipv4/conf/default/route_localnet 2>/dev/null

# Sync UFW before.rules for loopback DNAT rules
sync_ufw_loopback_dnat() {
    local before_rules="/etc/ufw/before.rules"
    local before6_rules="/etc/ufw/before6.rules"
    local marker_start="# pfwd-managed loopback dnat start"
    local marker_end="# pfwd-managed loopback dnat end"
    local block_v4="" block_v6="" line proto tport

    rewrite_ufw_file() {
        local file="$1" anchor="$2" start="$3" end="$4" block="$5"
        [[ -f "$file" ]] || return 0
        local tmp_file block_file
        tmp_file=$(mktemp)
        block_file=$(mktemp)
        if [[ -n "$block" ]]; then
            {
                printf '%s\n' "$start"
                printf '%s' "$block"
                [[ "$block" == *$'\n' ]] || printf '\n'
                printf '%s\n' "$end"
            } > "$block_file"
        else
            : > "$block_file"
        fi
        awk -v start="$start" -v end="$end" -v anchor="$anchor" -v block_file="$block_file" '
            BEGIN {
                skip = 0
                inserted = 0
                block = ""
                while ((getline line < block_file) > 0) {
                    block = block line "\n"
                }
                close(block_file)
            }
            {
                if ($0 == start) { skip = 1; next }
                if ($0 == end) { skip = 0; next }
                if (skip) next
                if (!inserted && $0 == anchor) {
                    if (length(block) > 0) printf "%s", block
                    inserted = 1
                }
                print
            }
            END {
                if (!inserted && length(block) > 0) printf "%s", block
                print "COMMIT"
            }
        ' "$file" | awk '
            BEGIN { last = "" }
            {
                if ($0 == "COMMIT") {
                    last = $0
                    next
                }
                print
            }
            END {
                print "COMMIT"
            }
        ' > "$tmp_file"
        mv "$tmp_file" "$file"
        rm -f "$block_file"
    }

    [[ -f "$before_rules" ]] || return 0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$line" =~ "ip protocol tcp" ]]; then proto=tcp
        elif [[ "$line" =~ "ip protocol udp" ]]; then proto=udp
        elif [[ "$line" =~ "ip6 nexthdr tcp" ]]; then proto=tcp
        elif [[ "$line" =~ "ip6 nexthdr udp" ]]; then proto=udp
        else continue
        fi

        if [[ "$line" =~ dnat\ ip\ to\ (127\.[0-9.]+):([0-9]+) ]]; then
            tport="${BASH_REMATCH[2]}"
            printf -v block_v4 '%s-A ufw-before-input -m conntrack --ctstate DNAT -p %s -d 127.0.0.1 --dport %s -j ACCEPT\n' "$block_v4" "$proto" "$tport"
        elif [[ "$line" =~ dnat\ ip6\ to\ \[(::1)\]:([0-9]+) ]]; then
            tport="${BASH_REMATCH[2]}"
            printf -v block_v6 '%s-A ufw6-before-input -m conntrack --ctstate DNAT -p %s -d ::1 --dport %s -j ACCEPT\n' "$block_v6" "$proto" "$tport"
        fi
    done < <(nft list chain inet port_forward prerouting 2>/dev/null | grep 'dnat' || true)

    rewrite_ufw_file "$before_rules" '-A ufw-before-input -j ufw-not-local' "$marker_start" "$marker_end" "$block_v4"
    if [[ -f "$before6_rules" ]]; then
        rewrite_ufw_file "$before6_rules" '-A ufw6-before-input -j ufw6-not-local' "$marker_start" "$marker_end" "$block_v6"
    fi

    if command -v ufw >/dev/null 2>&1; then
        ufw status 2>/dev/null | grep -q '^Status: active' && ufw reload >/dev/null 2>&1 || true
    fi
}
sync_ufw_loopback_dnat

# Cap BQL limit_max to prevent bufferbloat (flowtable bypasses fq_codel AQM)
for _bql_f in /sys/class/net/*/queues/tx-*/byte_queue_limits/limit_max; do
    [[ -f "$_bql_f" ]] && echo 65536 > "$_bql_f" 2>/dev/null || true
done
log "BQL limit_max capped at 65536 bytes on all TX queues"

NFT_CONFIG="/etc/nftables.d/port_forward.nft"
if [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]]; then
    nft delete table inet port_forward 2>/dev/null
    if nft -f "$NFT_CONFIG" 2>/dev/null; then
        log "Rules restored from $NFT_CONFIG"
        # Re-sync managed iptables ACCEPT rules only when current nft rules need them.
        if command -v iptables >/dev/null 2>&1; then
            has_v4=false
            has_loopback_v4=false
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                if [[ "$line" =~ "ip protocol tcp" || "$line" =~ "ip protocol udp" ]]; then
                    has_v4=true
                fi
                if [[ "$line" =~ dnat\ ip\ to\ (127\.[0-9.]+):([0-9]+) ]]; then
                    has_loopback_v4=true
                fi
            done < <(nft list chain inet port_forward prerouting 2>/dev/null | grep 'dnat' || true)
            policy=$(iptables -S FORWARD 2>/dev/null | awk '/-P FORWARD/{print $3}')
            if [[ "$policy" == "DROP" && "$has_v4" == true ]]; then
                iptables -C FORWARD -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed forward dnat" -j ACCEPT 2>/dev/null || \
                    iptables -I FORWARD -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed forward dnat" -j ACCEPT 2>/dev/null
                iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "pfwd-managed forward established" -j ACCEPT 2>/dev/null || \
                    iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "pfwd-managed forward established" -j ACCEPT 2>/dev/null
                log "Synced managed iptables FORWARD ACCEPT rules"
            else
                while iptables -C FORWARD -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed forward dnat" -j ACCEPT >/dev/null 2>&1; do
                    iptables -D FORWARD -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed forward dnat" -j ACCEPT >/dev/null 2>&1 || break
                done
                while iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "pfwd-managed forward established" -j ACCEPT >/dev/null 2>&1; do
                    iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "pfwd-managed forward established" -j ACCEPT >/dev/null 2>&1 || break
                done
            fi
            input_policy=$(iptables -S INPUT 2>/dev/null | awk '/-P INPUT/{print $3}')
            if [[ "$input_policy" == "DROP" && "$has_loopback_v4" == true ]]; then
                iptables -C INPUT -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed input dnat" -j ACCEPT 2>/dev/null || \
                    iptables -I INPUT -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed input dnat" -j ACCEPT 2>/dev/null
                log "Synced managed iptables INPUT ACCEPT rule"
            else
                while iptables -C INPUT -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed input dnat" -j ACCEPT >/dev/null 2>&1; do
                    iptables -D INPUT -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed input dnat" -j ACCEPT >/dev/null 2>&1 || break
                done
            fi
        fi
        if command -v ip6tables >/dev/null 2>&1; then
            has_v6=false
            has_loopback_v6=false
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                if [[ "$line" =~ "ip6 nexthdr tcp" || "$line" =~ "ip6 nexthdr udp" ]]; then
                    has_v6=true
                fi
                if [[ "$line" =~ dnat\ ip6\ to\ \[(::1)\]:([0-9]+) ]]; then
                    has_loopback_v6=true
                fi
            done < <(nft list chain inet port_forward prerouting 2>/dev/null | grep 'dnat' || true)
            policy6=$(ip6tables -S FORWARD 2>/dev/null | awk '/-P FORWARD/{print $3}')
            if [[ "$policy6" == "DROP" && "$has_v6" == true ]]; then
                ip6tables -C FORWARD -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed forward dnat" -j ACCEPT 2>/dev/null || \
                    ip6tables -I FORWARD -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed forward dnat" -j ACCEPT 2>/dev/null
                ip6tables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "pfwd-managed forward established" -j ACCEPT 2>/dev/null || \
                    ip6tables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "pfwd-managed forward established" -j ACCEPT 2>/dev/null
                log "Synced managed ip6tables FORWARD ACCEPT rules"
            else
                while ip6tables -C FORWARD -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed forward dnat" -j ACCEPT >/dev/null 2>&1; do
                    ip6tables -D FORWARD -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed forward dnat" -j ACCEPT >/dev/null 2>&1 || break
                done
                while ip6tables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "pfwd-managed forward established" -j ACCEPT >/dev/null 2>&1; do
                    ip6tables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "pfwd-managed forward established" -j ACCEPT >/dev/null 2>&1 || break
                done
            fi
            input_policy6=$(ip6tables -S INPUT 2>/dev/null | awk '/-P INPUT/{print $3}')
            if [[ "$input_policy6" == "DROP" && "$has_loopback_v6" == true ]]; then
                ip6tables -C INPUT -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed input dnat" -j ACCEPT 2>/dev/null || \
                    ip6tables -I INPUT -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed input dnat" -j ACCEPT 2>/dev/null
                log "Synced managed ip6tables INPUT ACCEPT rule"
            else
                while ip6tables -C INPUT -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed input dnat" -j ACCEPT >/dev/null 2>&1; do
                    ip6tables -D INPUT -m conntrack --ctstate DNAT -m comment --comment "pfwd-managed input dnat" -j ACCEPT >/dev/null 2>&1 || break
                done
            fi
        fi
    else
        log "Failed to restore rules from $NFT_CONFIG"
    fi
else
    log "No rules file found at $NFT_CONFIG"
fi
RESTORE_EOF
    _atomic_replace_file "$restore_tmp" "$NFT_RESTORE_SCRIPT" 0755

    # Create systemd service (with ExecStop to save traffic on shutdown)
    service_tmp=$(_mktemp_in_dir "$NFT_RESTORE_SERVICE") || return 1
    cat > "$service_tmp" << EOF
[Unit]
Description=pfwd nftables rules restore
After=network-online.target nftables.service systemd-sysctl.service ufw.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$NFT_RESTORE_SCRIPT
ExecStop=$TRAFFIC_COLLECTOR
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    _atomic_replace_file "$service_tmp" "$NFT_RESTORE_SERVICE" 0644

    # Create traffic collector script
    collector_tmp=$(_mktemp_in_dir "$TRAFFIC_COLLECTOR") || return 1
    cat > "$collector_tmp" << 'COLLECTOR_EOF'
#!/bin/bash
# pfwd traffic data collector - runs independently via systemd timer
# Reads nft counters, computes deltas, writes accumulated data to disk
set -euo pipefail

NFT_TABLE="inet port_forward"
TRAFFIC_DATA="/var/lib/pfwd/traffic_stats.dat"

# Check if nft table exists
nft list table $NFT_TABLE >/dev/null 2>&1 || exit 0

# Parse prerouting (inbound) + forward return (outbound) counters via awk
current_data=$(\
    {
        echo "===PREROUTING==="
        nft list chain $NFT_TABLE prerouting 2>/dev/null | grep "dnat" || true
        echo "===FORWARD_RET==="
        nft list chain $NFT_TABLE forward 2>/dev/null | grep "pfwd_ret:" || true
    } | awk '
    /^===PREROUTING===/ { section="pre"; next }
    /^===FORWARD_RET===/ { section="fwd"; next }

    section == "pre" && /dnat/ {
        proto=""; ipver=""; lport=""; target=""; tport=""; bytes="0"; comment=""
        if (match($0, /ip protocol tcp/))      { proto="tcp"; ipver="4" }
        else if (match($0, /ip protocol udp/)) { proto="udp"; ipver="4" }
        else if (match($0, /ip6 nexthdr tcp/)) { proto="tcp"; ipver="6" }
        else if (match($0, /ip6 nexthdr udp/)) { proto="udp"; ipver="6" }
        if (match($0, /dport [0-9]+/)) {
            s = substr($0, RSTART, RLENGTH); sub(/dport /, "", s); lport = s
        }
        if (match($0, /dnat ip6 to \[/)) {
            rest = substr($0, RSTART + 12)
            p = index(rest, "]:")
            if (p > 0) {
                target = substr(rest, 1, p - 1)
                rest2 = substr(rest, p + 2)
                match(rest2, /[0-9]+/); tport = substr(rest2, RSTART, RLENGTH)
            }
        } else if (match($0, /dnat ip to /)) {
            rest = substr($0, RSTART + 11)
            if (match(rest, /[^ ]+/)) {
                s = substr(rest, RSTART, RLENGTH)
                n = split(s, da, ":"); target = da[1]; tport = da[n]
            }
        }
        if (match($0, /bytes [0-9]+/)) {
            s = substr($0, RSTART, RLENGTH); sub(/bytes /, "", s); bytes = s
        }
        if (match($0, /comment "/)) {
            rest = substr($0, RSTART + 9)
            ci = index(rest, "\"")
            if (ci > 1) comment = substr(rest, 1, ci - 1)
        }
        if (lport != "" && proto != "") {
            key = proto "|" lport "|" ipver
            in_bytes[key] = bytes
            info[key] = target "|" tport "|" comment
        }
    }

    section == "fwd" && /pfwd_ret:/ {
        if (match($0, /pfwd_ret:[0-9]+:[46]:[a-z]+/)) {
            s = substr($0, RSTART, RLENGTH)
            sub(/pfwd_ret:/, "", s)
            n = split(s, rp, ":")
            if (n >= 3) {
                key = rp[3] "|" rp[1] "|" rp[2]
                if (key in in_bytes) {
                    ob = "0"
                    if (match($0, /bytes [0-9]+/)) {
                        bs = substr($0, RSTART, RLENGTH)
                        sub(/bytes /, "", bs)
                        ob = bs
                    }
                    out_bytes[key] = ob
                }
            }
        }
    }

    END {
        for (key in in_bytes) {
            ib = in_bytes[key]
            ob = (key in out_bytes) ? out_bytes[key] : "0"
            print key "|" info[key] "|" ib "|" ob
        }
    }
    '
)

# Read existing saved data into associative arrays
declare -A acc_in acc_out snap_in snap_out
if [[ -f "$TRAFFIC_DATA" ]]; then
    while IFS='|' read -r s_proto s_lport s_ipver s_acc_in s_acc_out s_snap_in s_snap_out; do
        [[ -z "$s_lport" ]] && continue
        local_key="${s_proto}|${s_lport}|${s_ipver}"
        acc_in[$local_key]="${s_acc_in:-0}"
        acc_out[$local_key]="${s_acc_out:-0}"
        snap_in[$local_key]="${s_snap_in:-0}"
        snap_out[$local_key]="${s_snap_out:-0}"
    done < "$TRAFFIC_DATA"
fi

# Compute deltas and update accumulated values
if [[ -n "$current_data" ]]; then
    while IFS='|' read -r proto lport ipver target tport comment cur_in cur_out; do
        [[ -z "$lport" ]] && continue
        key="${proto}|${lport}|${ipver}"
        prev_snap_in="${snap_in[$key]:-0}"
        prev_snap_out="${snap_out[$key]:-0}"
        # Delta calculation: handle counter reset (rule rebuilt)
        if (( cur_in >= prev_snap_in )); then
            delta_in=$(( cur_in - prev_snap_in ))
        else
            delta_in=$cur_in
        fi
        if (( cur_out >= prev_snap_out )); then
            delta_out=$(( cur_out - prev_snap_out ))
        else
            delta_out=$cur_out
        fi
        acc_in[$key]=$(( ${acc_in[$key]:-0} + delta_in ))
        acc_out[$key]=$(( ${acc_out[$key]:-0} + delta_out ))
        snap_in[$key]=$cur_in
        snap_out[$key]=$cur_out
    done <<< "$current_data"
fi

# Write updated data atomically
tmp_file="${TRAFFIC_DATA}.tmp"
: > "$tmp_file"
for key in "${!acc_in[@]}"; do
    echo "${key}|${acc_in[$key]}|${acc_out[$key]}|${snap_in[$key]}|${snap_out[$key]}" >> "$tmp_file"
done
mv -f "$tmp_file" "$TRAFFIC_DATA"
COLLECTOR_EOF
    _atomic_replace_file "$collector_tmp" "$TRAFFIC_COLLECTOR" 0755

    # Create traffic save timer
    service_tmp=$(_mktemp_in_dir "$TRAFFIC_SAVE_SERVICE") || return 1
    cat > "$service_tmp" << EOF
[Unit]
Description=pfwd traffic data collector
After=pfwd-nft-restore.service

[Service]
Type=oneshot
ExecStart=$TRAFFIC_COLLECTOR
EOF
    _atomic_replace_file "$service_tmp" "$TRAFFIC_SAVE_SERVICE" 0644

    timer_tmp=$(_mktemp_in_dir "$TRAFFIC_SAVE_TIMER") || return 1
    cat > "$timer_tmp" << 'EOF'
[Unit]
Description=Periodically save pfwd traffic statistics

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
    _atomic_replace_file "$timer_tmp" "$TRAFFIC_SAVE_TIMER" 0644

    systemctl daemon-reload 2>/dev/null
    systemctl enable pfwd-nft-restore >/dev/null 2>&1 || true
    systemctl enable --now pfwd-traffic-save.timer >/dev/null 2>&1 || true
}

#===============================================================================
#  Section 5: realm Functions
#===============================================================================

# realm_is_installed - check if realm binary exists
realm_is_installed() {
    [[ -x "$REALM_BIN" ]]
}

# realm_install - download and install realm binary
realm_install() {
    msg_info "Installing realm..."

    local arch
    arch=$(uname -m)
    local realm_arch=""
    case "$arch" in
        x86_64|amd64)  realm_arch="x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) realm_arch="aarch64-unknown-linux-gnu" ;;
        armv7l)        realm_arch="armv7-unknown-linux-gnueabihf" ;;
        *)
            msg_err "Unsupported architecture: $arch"
            return 1
            ;;
    esac

    # Get latest release URL
    local api_url="https://api.github.com/repos/zhboner/realm/releases/latest"
    local download_url=""

    msg_dim "  Fetching latest version info..."
    local api_result
    api_result=$(smart_api_get "$api_url" 10)

    if [[ -n "$api_result" ]]; then
        download_url=$(echo "$api_result" | awk -v arch="$realm_arch" '/browser_download_url/ && $0 ~ arch && !/\.sha256/ { gsub(/.*"(https:)/, "https:"); gsub(/".*/, ""); print; exit }' || true)
    fi

    if [[ -z "$download_url" ]]; then
        msg_err "Failed to get realm download URL"
        msg_err "Try manual install from: https://github.com/zhboner/realm/releases"
        return 1
    fi

    msg_dim "  Downloading: $download_url"
    local tmp_file
    tmp_file=$(mktemp)

    # Use smart download function
    if ! smart_download "$download_url" "$tmp_file" 15; then
        rm -f "$tmp_file"
        msg_err "Download failed"
        msg_err "Try manual install from: https://github.com/zhboner/realm/releases"
        return 1
    fi

    # Check if it's a tar.gz
    if file "$tmp_file" 2>/dev/null | grep -qi "gzip\|tar"; then
        local tmp_dir
        tmp_dir=$(mktemp -d)
        if ! tar -xzf "$tmp_file" -C "$tmp_dir" 2>/dev/null; then
            msg_err "Failed to extract realm archive"
            rm -rf "$tmp_dir" "$tmp_file"
            return 1
        fi
        local realm_extracted
        realm_extracted=$(find "$tmp_dir" -name "realm" -type f | head -1)
        if [[ -n "$realm_extracted" ]]; then
            mv "$realm_extracted" "$REALM_BIN"
        else
            msg_err "Could not find realm binary in archive"
            rm -rf "$tmp_dir" "$tmp_file"
            return 1
        fi
        rm -rf "$tmp_dir"
    else
        mv "$tmp_file" "$REALM_BIN"
    fi

    chmod +x "$REALM_BIN"
    rm -f "$tmp_file"

    # Verify
    if realm_is_installed; then
        local ver
        ver=$("$REALM_BIN" --version 2>/dev/null || echo "unknown")
        msg_ok "realm installed: $ver"
    else
        msg_err "realm installation failed"
        return 1
    fi

    # Setup service
    realm_setup_service

    # Auto-enable BBR for optimal performance
    ensure_bbr_enabled
}

# realm_setup_service - create systemd service file
realm_setup_service() {
    mkdir -p "$REALM_CONFIG_DIR"

    cat > "$REALM_SERVICE" << EOF
[Unit]
Description=Realm Port Forward
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=30
StartLimitBurst=10

[Service]
Type=simple
User=root
ExecStart=$REALM_BIN -c $REALM_CONFIG -n 1048576 --log-level warn
Restart=always
RestartSec=2
LimitNOFILE=1048576
LimitNPROC=65535
TasksMax=infinity
OOMScoreAdjust=-900
WorkingDirectory=$REALM_CONFIG_DIR
RuntimeDirectory=realm
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF

    _mark_realm_service_unit_dirty
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable realm-forward >/dev/null 2>&1 || true
}

# realm_ensure_config - ensure managed default config exists
realm_ensure_config() {
    mkdir -p "$REALM_CONFIG_DIR"

    local marker_start="# pfwd-managed realm defaults start"
    local marker_end="# pfwd-managed realm defaults end"
    local managed_block
    managed_block=$(cat <<'EOF'
# pfwd-managed realm defaults start
[log]
level = "warn"
output = "/var/log/realm.log"

[network]
no_tcp = false
use_udp = true
ipv6_only = false
tcp_timeout = 300
udp_timeout = 60
tcp_keepalive = 15
tcp_keepalive_probe = 3
# pfwd-managed realm defaults end
EOF
)

    if [[ ! -f "$REALM_CONFIG" ]]; then
        printf '%s\n' "$managed_block" > "$REALM_CONFIG"
        msg_dim "  Created initial realm config"
        _mark_realm_dirty
        return 0
    fi

    local tmp_file
    tmp_file=$(mktemp)
    awk -v start="$marker_start" -v end="$marker_end" -v block="$managed_block" '
        BEGIN { skip = 0; inserted = 0 }
        {
            if ($0 == start) { skip = 1; next }
            if ($0 == end) { skip = 0; next }
            if (skip) next
            if (!inserted) {
                printf "%s\n\n", block
                inserted = 1
            }
            print
        }
        END {
            if (!inserted) {
                printf "%s\n", block
            }
        }
    ' "$REALM_CONFIG" > "$tmp_file"
    mv "$tmp_file" "$REALM_CONFIG"
    _mark_realm_dirty
}

# realm_add_endpoint <lport> <target> <tport> <ip_ver> [comment]
realm_add_endpoint() {
    local lport="$1" target="$2" tport="$3" ip_ver="${4:-46}" comment="${5:-}"

    if ! realm_is_installed; then
        msg_err "realm is not installed. Run: pfwd install"
        return 1
    fi

    realm_ensure_config

    # Auto-enable BBR when adding first realm endpoint
    local endpoint_count
    endpoint_count=$(grep -c "^\[\[endpoints\]\]" "$REALM_CONFIG" 2>/dev/null || echo 0)
    if (( endpoint_count == 0 )); then
        ensure_bbr_enabled
    fi

    # Check port availability (realm supports TCP+UDP, check both)
    if ! check_port_in_use "$lport" "both"; then
        msg_info "Cancelled"
        return 1
    fi

    # Check for duplicate realm endpoint — replace if exists
    if [[ -f "$REALM_CONFIG" ]] && grep -q "listen = \".*:${lport}\"" "$REALM_CONFIG" 2>/dev/null; then
        msg_info "Replacing existing realm endpoint for port $lport"
        realm_delete_endpoint "$lport"
    fi

    # Determine listen address based on ip_ver
    local listen_addr
    case "$ip_ver" in
        4)  listen_addr="0.0.0.0:$lport" ;;
        6)  listen_addr="[::]:$lport" ;;
        46) listen_addr="[::]:$lport" ;;
        *)  listen_addr="[::]:$lport" ;;
    esac

    # Determine remote address format
    local remote_addr
    local target_type
    target_type=$(detect_ip_type "$target")
    case "$target_type" in
        ipv6) remote_addr="[$target]:$tport" ;;
        *)    remote_addr="$target:$tport" ;;
    esac

    # Append endpoint to config
    {
        echo ""
        [[ -n "$comment" ]] && echo "# $comment"
        echo "[[endpoints]]"
        echo "listen = \"$listen_addr\""
        echo "remote = \"$remote_addr\""
    } >> "$REALM_CONFIG"

    _mark_realm_dirty
    realm_setup_traffic_counter "$lport"
    if ! $_BATCH_MODE; then
        realm_restart_service
    fi
    msg_ok "realm endpoint added: :$lport -> $target:$tport (IPv$ip_ver)"
}

# realm_delete_endpoint <port> - remove endpoint by local port
realm_delete_endpoint() {
    local port="$1"
    local proto="${2:-both}"  # Default: delete all protocols

    if [[ ! -f "$REALM_CONFIG" ]]; then
        msg_warn "No realm config found"
        return 0
    fi

    local before_count after_count removed_count=0
    before_count=$(_realm_count_endpoints "$(_parse_realm_endpoints)")

    # Use awk to remove the endpoint block matching this port (and protocol if specified)
    # An endpoint block = optional comment line + [[endpoints]] + listen + remote
    # We detect blocks by "listen = ..." containing the port
    local tmp_file
    tmp_file=$(mktemp)

    awk -v port="$port" -v proto="$proto" '
    BEGIN { skip=0; buf=""; comment="" }
    {
        # Track comment lines before [[endpoints]]
        if (/^# / && !skip) {
            comment = $0 "\n"
            next
        }
        if (/^\[\[endpoints\]\]/) {
            buf = comment $0 "\n"
            comment = ""
            skip = 0
            next
        }
        if (buf != "") {
            buf = buf $0 "\n"
            # Check if this listen line contains our port
            if (/^listen/) {
                if ($0 ~ ":" port "\"") {
                    skip = 1
                    buf = ""
                }
            }
            # After remote line, flush the buffer
            if (/^remote/) {
                if (!skip) {
                    printf "%s", buf
                }
                buf = ""
                skip = 0
            }
            next
        }
        comment = ""
        print
    }
    ' "$REALM_CONFIG" > "$tmp_file"

    mv "$tmp_file" "$REALM_CONFIG"
    after_count=$(_realm_count_endpoints "$(_parse_realm_endpoints)")
    removed_count=$(( before_count - after_count ))

    # Also remove traffic counter rules from nft (with protocol filter)
    if _nft_table_exists; then
        local handles removed_input_counter=false
        handles=$(_nft_handles_by_port input "$port" "$proto")
        for h in $handles; do
            nft delete rule $NFT_TABLE input handle "$h" 2>/dev/null && removed_input_counter=true || true
        done
        if $removed_input_counter; then
            _mark_nft_dirty
        fi
    fi

    if (( removed_count > 0 )); then
        _mark_realm_dirty
        if ! $_BATCH_MODE; then
            _batch_finalize realm
            if $_DIRTY_NFT || $_DIRTY_UFW_SYNC || $_DIRTY_UFW_RELOAD; then
                _batch_finalize nft
            fi
        fi
        local proto_msg=""
        [[ "$proto" != "both" ]] && proto_msg=" ($proto)"
        msg_ok "realm endpoint deleted for port $port$proto_msg"
    else
        msg_warn "No realm endpoints found for port $port"
    fi
}

# _parse_realm_endpoints - parse realm config into structured data
# Output: lport|target|tport|ip_ver|listen|remote|comment (one line per endpoint)
_parse_realm_endpoints() {
    [[ -f "$REALM_CONFIG" ]] || return 0

    awk '
    BEGIN { listen=""; remote=""; comment="" }
    /^# / { comment=$0; sub(/^# /, "", comment); next }
    /^\[\[endpoints\]\]/ { listen=""; remote=""; next }
    /^listen/ {
        # Extract value between quotes: listen = "..."
        if (match($0, /"[^"]+"/)) {
            listen = substr($0, RSTART+1, RLENGTH-2)
        }
        next
    }
    /^remote/ {
        # Extract value between quotes: remote = "..."
        if (match($0, /"[^"]+"/)) {
            remote = substr($0, RSTART+1, RLENGTH-2)
        }
        if (listen != "" && remote != "") {
            # Determine ip_ver from listen address
            ip_ver="46"
            if (listen ~ /^0\.0\.0\.0:/) ip_ver="4"
            if (substr(listen, 1, 4) == "[::]:") ip_ver="46"
            # Extract port from listen
            split(listen, la, ":")
            lport = la[length(la)]
            # Extract target and port from remote
            if (substr(remote, 1, 1) == "[") {
                # IPv6 remote [addr]:port - use index to split on "]:"
                tmp = substr(remote, 2)
                idx = index(tmp, "]:")
                if (idx > 0) {
                    rtarget = substr(tmp, 1, idx - 1)
                    rtport = substr(tmp, idx + 2)
                } else {
                    rtarget = tmp; rtport = ""
                }
                printf "%s|%s|%s|%s|%s|%s|%s\n", lport, rtarget, rtport, ip_ver, listen, remote, comment
            } else {
                # IPv4/domain remote addr:port
                n = split(remote, ra, ":")
                tport = ra[n]
                target = remote
                sub(":"tport"$", "", target)
                printf "%s|%s|%s|%s|%s|%s|%s\n", lport, target, tport, ip_ver, listen, remote, comment
            }
        }
        comment=""
        next
    }
    { comment="" }
    ' "$REALM_CONFIG" 2>/dev/null
}

# realm_list_endpoints - display realm endpoints
realm_list_endpoints() {
    local filter="${1:-}"
    local endpoints="${2:-}"
    if [[ ! -f "$REALM_CONFIG" ]]; then
        msg_dim "  No realm config found"
        return 0
    fi

    if [[ -z "$endpoints" ]]; then
        endpoints=$(_parse_realm_endpoints)
    fi

    if [[ -z "$endpoints" ]]; then
        msg_dim "  No realm endpoints configured"
        return 0
    fi

    _pfwd_collect_state

    echo -e "${CYAN}realm forwarding endpoints:${NC}"
    local svc_status
    if $PFWD_REALM_RUNNING; then
        svc_status="${GREEN}running${NC}"
    else
        svc_status="${RED}stopped${NC}"
    fi
    echo -e "  Service: $svc_status"

    if $PFWD_BBR_ENABLED; then
        echo -e "  BBR: ${GREEN}enabled${NC}"
    else
        echo -e "  BBR: ${YELLOW}disabled${NC} (run 'pfwd optimize' to enable)"
    fi

    [[ -n "$PFWD_REALM_NOFILE" ]] && echo -e "  LimitNOFILE: ${CYAN}${PFWD_REALM_NOFILE}${NC}"
    [[ -n "$PFWD_REALM_TCP_TIMEOUT" || -n "$PFWD_REALM_UDP_TIMEOUT" ]] && \
        echo -e "  Timeouts: tcp=${CYAN}${PFWD_REALM_TCP_TIMEOUT:-default}${NC}, udp=${CYAN}${PFWD_REALM_UDP_TIMEOUT:-default}${NC}"

    printf "  ${BOLD}%-4s %-25s %-30s %-15s %s${NC}\n" "#" "Listen" "Remote" "Comment" "Traffic"

    # Pre-fetch nft input chain data ONCE (instead of per-endpoint)
    local nft_input_data=""
    if _nft_table_exists; then
        nft_input_data=$(_nft_cached_chain input)
    fi

    # Collect endpoints with port numbers for sorting
    local endpoint_data=""
    while IFS='|' read -r lport target tport ip_ver listen remote comment; do
        local traffic_bytes=0
        if [[ -n "$nft_input_data" ]]; then
            traffic_bytes=$(_nft_traffic_from_chain "$nft_input_data" "$lport")
        fi

        # Add to endpoint_data: port|listen|remote|comment|traffic_bytes
        endpoint_data+="${lport}|${listen}|${remote}|${comment}|${traffic_bytes:-0}"$'\n'
    done <<< "$endpoints"

    # Sort by port number
    local sorted_endpoints
    sorted_endpoints=$(echo "$endpoint_data" | sort -t'|' -k1,1n)

    # Display sorted endpoints
    local idx=0
    while IFS='|' read -r lport listen remote comment traffic_bytes; do
        [[ -z "$lport" ]] && continue
        # Apply filter if specified
        if [[ -n "$filter" ]]; then
            local line_text="$listen $remote ${comment:--}"
            [[ ! "$line_text" =~ $filter ]] && continue
        fi
        ((idx++)) || true
        local traffic
        traffic=$(format_bytes "$traffic_bytes")
        # Color coding for traffic
        local traffic_color=""
        if [[ -n "$GREEN" ]]; then
            if (( traffic_bytes > 1073741824 )); then traffic_color="$RED"
            elif (( traffic_bytes > 104857600 )); then traffic_color="$YELLOW"
            elif (( traffic_bytes > 1048576 )); then traffic_color="$GREEN"
            fi
        fi
        printf "  %-4s %-25s %-30s %-15s ${traffic_color}%s${NC}\n" \
            "$idx" "$listen" "$remote" "${comment:--}" "$traffic"
    done <<< "$sorted_endpoints"
}

# realm_restart_service - restart realm service
realm_restart_service() {
    if ! $_DIRTY_REALM_SERVICE && ! $_DIRTY_REALM_SERVICE_UNIT; then
        return 0
    fi
    if [[ ! -f "$REALM_SERVICE" ]]; then
        realm_setup_service
    fi
    if $_DIRTY_REALM_SERVICE_UNIT; then
        systemctl daemon-reload 2>/dev/null || true
        _DIRTY_REALM_SERVICE_UNIT=false
    fi
    systemctl restart realm-forward 2>/dev/null || true
    _DIRTY_REALM_SERVICE=false
}

# realm_uninstall - remove realm completely
realm_uninstall() {
    systemctl stop realm-forward 2>/dev/null || true
    systemctl disable realm-forward 2>/dev/null || true
    rm -f "$REALM_SERVICE"
    rm -f "$REALM_BIN"
    rm -rf "$REALM_CONFIG_DIR"
    systemctl daemon-reload 2>/dev/null || true
    msg_ok "realm uninstalled"
}

# realm_setup_traffic_counter <port> - add nft input counter for realm traffic
realm_setup_traffic_counter() {
    local port="$1"

    # Ensure nftables table and input chain exist
    if ! nft_ensure_table 2>/dev/null; then
        msg_dim "  Traffic counter skipped: nftables table setup failed"
        return 0
    fi

    # Check if counter already exists for this port
    if _nft_cached_chain input | grep -qE "dport $port\b"; then
        return 0
    fi

    local added=false
    nft add rule $NFT_TABLE input tcp dport "$port" counter 2>/dev/null && added=true || true
    nft add rule $NFT_TABLE input udp dport "$port" counter 2>/dev/null && added=true || true
    if $added; then
        _mark_nft_dirty
    fi
}

#===============================================================================
#  Section 6: Traffic Statistics
#===============================================================================

# _traffic_read_merged - read-only merge of saved data + live nft counters
# Output: same format as _parse_nft_bidirectional_traffic
_traffic_read_merged() {
    local parsed
    parsed=$(_parse_nft_bidirectional_traffic)
    [[ -z "$parsed" ]] && return 0

    # Load saved accumulated + snapshot data
    declare -A acc_in acc_out snap_in snap_out
    if [[ -f "$TRAFFIC_DATA" ]]; then
        while IFS='|' read -r s_proto s_lport s_ipver s_acc_in s_acc_out s_snap_in s_snap_out; do
            [[ -z "$s_lport" ]] && continue
            local key="${s_proto}|${s_lport}|${s_ipver}"
            acc_in[$key]="${s_acc_in:-0}"
            acc_out[$key]="${s_acc_out:-0}"
            snap_in[$key]="${s_snap_in:-0}"
            snap_out[$key]="${s_snap_out:-0}"
        done < "$TRAFFIC_DATA"
    fi

    # Merge: accumulated + (current - snapshot) for each rule
    while IFS='|' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
        [[ -z "$lport" ]] && continue
        local key="${proto}|${lport}|${ipver}"
        local prev_snap_in="${snap_in[$key]:-0}"
        local prev_snap_out="${snap_out[$key]:-0}"
        local delta_in delta_out
        if (( in_bytes >= prev_snap_in )); then
            delta_in=$(( in_bytes - prev_snap_in ))
        else
            delta_in=$in_bytes
        fi
        if (( out_bytes >= prev_snap_out )); then
            delta_out=$(( out_bytes - prev_snap_out ))
        else
            delta_out=$out_bytes
        fi
        local merged_in=$(( ${acc_in[$key]:-0} + delta_in ))
        local merged_out=$(( ${acc_out[$key]:-0} + delta_out ))
        local merged_total=$(( merged_in + merged_out ))
        echo "${proto}|${lport}|${ipver}|${target}|${tport}|${comment}|${merged_in}|${merged_out}|${merged_total}"
    done <<< "$parsed"
}

show_traffic_stats() {
    echo -e "${BOLD}Traffic Statistics${NC}"
    echo -e "${DIM}$SEP_EQ${NC}"

    local has_rules=false

    # nftables bidirectional traffic (merged with persisted data)
    if _nft_table_exists; then
        local parsed_nft
        parsed_nft=$(_traffic_read_merged)

        if [[ -n "$parsed_nft" ]]; then
            has_rules=true
            echo -e "\n${CYAN}nftables forwarding:${NC}"
            echo -e "  ${DIM}┌────────┬──────┬──────┬─────────────────────────┬────────────┬────────────┬────────────┐${NC}"
            printf "  ${DIM}│${NC}${BOLD}%-8s${NC}${DIM}│${NC}${BOLD}%-6s${NC}${DIM}│${NC}${BOLD}%-6s${NC}${DIM}│${NC}${BOLD}%-25s${NC}${DIM}│${NC}${BOLD}%-14s${NC}${DIM}│${NC}${BOLD}%-14s${NC}${DIM}│${NC}${BOLD}%-12s${NC}${DIM}│${NC}\n" " L.Port" " Proto" " IPvr" " Target" " Inbound ↓" " Outbound ↑" " Total"
            echo -e "  ${DIM}├────────┼──────┼──────┼─────────────────────────┼────────────┼────────────┼────────────┤${NC}"

            # Sort by protocol and port number
            local sorted_rules
            sorted_rules=$(echo "$parsed_nft" | _sort_parsed_rules)

            # Display sorted rules: proto|lport|ipver|target|tport|comment|in_bytes|out_bytes|total_bytes
            while IFS='|' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
                [[ -z "$lport" ]] && continue
                local in_traffic out_traffic total_traffic
                in_traffic=$(format_bytes "$in_bytes")
                out_traffic=$(format_bytes "$out_bytes")
                total_traffic=$(format_bytes "$total_bytes")
                printf "  ${DIM}│${NC}%-8s${DIM}│${NC}%-6s${DIM}│${NC}%-6s${DIM}│${NC}%-25s${DIM}│${NC}%-12s${DIM}│${NC}%-12s${DIM}│${NC}%-12s${DIM}│${NC}\n" " :$lport" " $proto" " v$ipver" " $target" " $in_traffic" " $out_traffic" " $total_traffic"
            done <<< "$sorted_rules"
            echo -e "  ${DIM}└────────┴──────┴──────┴─────────────────────────┴────────────┴────────────┴────────────┘${NC}"
        fi
    fi

    # realm input chain traffic
    if [[ -f "$REALM_CONFIG" ]] && _nft_table_exists; then
        local input_rules
        input_rules=$(_nft_cached_chain input | awk '/counter/ && /dport/' || true)

        if [[ -n "$input_rules" ]]; then
            has_rules=true
            echo -e "\n${CYAN}realm traffic:${NC}"
            echo -e "  ${DIM}┌────────┬──────┬────────────┐${NC}"
            printf "  ${DIM}│${NC}${BOLD}%-8s${NC}${DIM}│${NC}${BOLD}%-6s${NC}${DIM}│${NC}${BOLD}%-12s${NC}${DIM}│${NC}\n" " L.Port" " Proto" " Traffic"
            echo -e "  ${DIM}├────────┼──────┼────────────┤${NC}"

            # Collect rules for sorting
            local realm_data=""
            while IFS= read -r line; do
                local lport="" proto="" bytes=""

                if [[ "$line" =~ "tcp dport" ]]; then proto="tcp"
                elif [[ "$line" =~ "udp dport" ]]; then proto="udp"
                fi

                [[ "$line" =~ dport\ ([0-9]+) ]] && lport="${BASH_REMATCH[1]}"
                [[ "$line" =~ bytes\ ([0-9]+) ]] && bytes="${BASH_REMATCH[1]}"

                if [[ -n "$lport" && -n "$proto" ]]; then
                    realm_data+="${proto}|${lport}|${bytes:-0}"$'\n'
                fi
            done <<< "$input_rules"

            # Sort by protocol and port number
            local sorted_realm
            sorted_realm=$(echo "$realm_data" | _sort_parsed_rules)

            # Display sorted rules
            while IFS='|' read -r proto lport bytes; do
                [[ -z "$lport" ]] && continue
                local traffic
                traffic=$(format_bytes "$bytes")
                printf "  ${DIM}│${NC}%-8s${DIM}│${NC}%-6s${DIM}│${NC}%-12s${DIM}│${NC}\n" " :$lport" " $proto" " $traffic"
            done <<< "$sorted_realm"
            echo -e "  ${DIM}└────────┴──────┴────────────┘${NC}"
        fi
    fi

    if ! $has_rules; then
        msg_dim "  No forwarding rules found"
    fi
}

# show_traffic_rate - sample traffic twice and show bytes/s
show_traffic_rate() {
    echo -e "${BOLD}Traffic Rate (sampling 2s...)${NC}"
    echo -e "${DIM}$SEP_EQ${NC}"

    if ! _nft_table_exists; then
        msg_dim "  No nftables forwarding rules"
        return 0
    fi

    # First sample
    _nft_invalidate_cache
    local sample1
    sample1=$(_parse_nft_bidirectional_traffic)
    [[ -z "$sample1" ]] && { msg_dim "  No rules to measure"; return 0; }

    # Store first sample in associative array
    declare -A s1_in s1_out
    while IFS='|' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
        [[ -z "$lport" ]] && continue
        local key="${proto}|${lport}|${ipver}"
        s1_in[$key]="$in_bytes"
        s1_out[$key]="$out_bytes"
    done <<< "$sample1"

    sleep 2

    # Second sample
    _nft_invalidate_cache
    local sample2
    sample2=$(_parse_nft_bidirectional_traffic)

    echo ""
    echo -e "${CYAN}nftables traffic rate:${NC}"
    printf "  ${BOLD}%-8s %-6s %-6s %-25s %-14s %-14s${NC}\n" "L.Port" "Proto" "IPver" "Target" "In Rate" "Out Rate"

    local sorted_s2
    sorted_s2=$(echo "$sample2" | _sort_parsed_rules)

    while IFS='|' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
        [[ -z "$lport" ]] && continue
        local key="${proto}|${lport}|${ipver}"
        local prev_in="${s1_in[$key]:-$in_bytes}"
        local prev_out="${s1_out[$key]:-$out_bytes}"
        local in_rate=$(( (in_bytes - prev_in) / 2 ))
        local out_rate=$(( (out_bytes - prev_out) / 2 ))
        (( in_rate < 0 )) && in_rate=0
        (( out_rate < 0 )) && out_rate=0
        local in_rate_str out_rate_str target_display
        in_rate_str="$(format_bytes "$in_rate")/s"
        out_rate_str="$(format_bytes "$out_rate")/s"
        target_display="$target:$tport"
        printf "  %-8s %-6s %-6s %-25s %-14s %-14s\n" ":$lport" "$proto" "IPv$ipver" "$target_display" "$in_rate_str" "$out_rate_str"
    done <<< "$sorted_s2"
}

#===============================================================================
#  Section 7: Backup / Import / Export
#===============================================================================

# cmd_export [filepath] - export all rules to JSON
cmd_export() {
    local filepath="${1:-$DATA_DIR/backup_$(date '+%Y%m%d_%H%M%S').json}"

    ensure_jq || return 1
    mkdir -p "$(dirname "$filepath")"

    # Build nft rules JSON array with awk (single pass, includes optional MSS/SNAT fields)
    local nft_json="[]"
    if _nft_table_exists; then
        local parsed_nft
        parsed_nft=$(_parse_nft_export_rules)
        if [[ -n "$parsed_nft" ]]; then
            nft_json=$(echo "$parsed_nft" | awk -F'|' '
            BEGIN { printf "[" ; first=1 }
            {
                proto=$1; lport=$2; ipver=$3; target=$4; tport=$5; comment=$6; snat_mode=$7; snat_source=$8; mss_mode=$9; mss_value=$10
                # Strip port from target if embedded
                sub(/:[0-9]+$/, "", target)
                # Handle IPv6 bracket format
                if (substr(target, 1, 1) == "[") target = substr(target, 2)
                sub(/]$/, "", target)
                if (!first) printf ","
                first=0
                # Escape double quotes in strings
                gsub(/"/, "\\\"", comment)
                gsub(/"/, "\\\"", target)
                gsub(/"/, "\\\"", snat_source)
                printf "{\"type\":\"nftables\",\"local_port\":\"%s\",\"target_ip\":\"%s\",\"target_port\":\"%s\",\"protocol\":\"%s\",\"ip_ver\":\"%s\",\"comment\":\"%s\"", lport, target, tport, proto, ipver, comment
                if (snat_mode == "snat") {
                    printf ",\"snat_mode\":\"snat\",\"snat_source\":\"%s\"", snat_source
                }
                if (mss_mode != "") {
                    printf ",\"mss_mode\":\"%s\"", mss_mode
                    if (mss_mode == "set" && mss_value != "") {
                        printf ",\"mss_value\":\"%s\"", mss_value
                    }
                }
                printf "}"
            }
            END { printf "]" }
            ')
        fi
    fi

    # Build realm rules JSON array with awk (single pass)
    local realm_json="[]"
    if [[ -f "$REALM_CONFIG" ]]; then
        local realm_data
        realm_data=$(_parse_realm_endpoints)
        if [[ -n "$realm_data" ]]; then
            realm_json=$(echo "$realm_data" | awk -F'|' '
            BEGIN { printf "[" ; first=1 }
            {
                lport=$1; target=$2; tport=$3; ipver=$4; comment=$7
                if (!first) printf ","
                first=0
                gsub(/"/, "\\\"", comment)
                printf "{\"type\":\"realm\",\"local_port\":\"%s\",\"target_ip\":\"%s\",\"target_port\":\"%s\",\"ip_ver\":\"%s\",\"comment\":\"%s\"}", lport, target, tport, ipver, comment
            }
            END { printf "]" }
            ')
        fi
    fi

    # Single jq call to build complete export JSON
    jq -n \
        --arg version "$VERSION" \
        --arg tool "pfwd" \
        --arg export_time "$(date '+%Y-%m-%dT%H:%M:%S')" \
        --arg source_ip "$(get_local_ip)" \
        --argjson nft "$nft_json" \
        --argjson realm "$realm_json" \
        '{
            export_info: {
                version: $version,
                tool: $tool,
                export_time: $export_time,
                source_ip: $source_ip
            },
            forward_rules: ($nft + $realm)
        }' > "$filepath"

    msg_ok "Exported to: $filepath"

    local count
    count=$(jq '.forward_rules | length' "$filepath")
    msg_info "Total rules exported: $count"

    # Show SCP hint
    local source_ip
    source_ip=$(get_local_ip)
    msg_dim "  To copy to another server:"
    msg_dim "  scp ${source_ip}:${filepath} /tmp/"
    msg_dim "  Or use base64:"
    msg_dim "  echo '$(base64 -w0 "$filepath")' | base64 -d > backup.json"
}

# cmd_import <filepath> [method] - import rules from JSON
cmd_import() {
    local filepath="$1"
    local override_method="${2:-}"

    ensure_jq || return 1

    # Handle URL imports
    if [[ "$filepath" =~ ^https?:// ]]; then
        local tmp_file
        tmp_file=$(mktemp)
        msg_info "Downloading from: $filepath"
        if command -v curl >/dev/null 2>&1; then
            curl -sL -o "$tmp_file" "$filepath"
        elif command -v wget >/dev/null 2>&1; then
            wget -qO "$tmp_file" "$filepath"
        else
            msg_err "Neither curl nor wget available"
            return 1
        fi
        filepath="$tmp_file"
    fi

    if [[ ! -f "$filepath" ]]; then
        msg_err "File not found: $filepath"
        return 1
    fi

    # Validate JSON
    if ! jq '.' "$filepath" >/dev/null 2>&1; then
        msg_err "Invalid JSON file: $filepath"
        return 1
    fi

    local count
    count=$(jq '.forward_rules | length' "$filepath")
    msg_info "Found $count rule(s) in backup"

    # Show rules summary
    jq -r '.forward_rules[] | "  [\(.type)] :\(.local_port) -> \(.target_ip):\(.target_port)"' "$filepath"

    local imported=0 failed=0
    local nft_batch_count=0 realm_batch_count=0

    _BATCH_MODE=true
    while IFS='|' read -r method lport target tport proto ipver comment mss_mode mss_value snat_mode snat_source; do
        [[ -z "$method" ]] && continue
        case "$method" in
            nft|nftables)
                if nft_add_rule "$lport" "$target" "$tport" "$ipver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source"; then
                    ((imported++)) || true
                    ((nft_batch_count++)) || true
                else
                    msg_warn "Failed to import nft rule :$lport -> $target:$tport"
                    ((failed++)) || true
                fi
                ;;
            realm)
                if realm_add_endpoint "$lport" "$target" "$tport" "$ipver" "$comment"; then
                    ((imported++)) || true
                    ((realm_batch_count++)) || true
                else
                    msg_warn "Failed to import realm rule :$lport -> $target:$tport"
                    ((failed++)) || true
                fi
                ;;
            *)
                msg_warn "Unknown method '$method' for rule :$lport, skipping"
                ((failed++)) || true
                ;;
        esac
    done < <(
        jq -r --arg override "$override_method" '
            .forward_rules[] |
            [
                ($override | select(length > 0) // .type),
                (.local_port | tostring),
                (.target_ip | tostring),
                (.target_port | tostring),
                (.protocol // "tcp" | tostring),
                (.ip_ver // "46" | tostring),
                (.comment // "" | tostring),
                (.mss_mode // "" | tostring),
                (.mss_value // "" | tostring),
                (.snat_mode // "" | tostring),
                (.snat_source // "" | tostring)
            ] | @tsv
        ' "$filepath"
    )
    _BATCH_MODE=false

    (( nft_batch_count > 0 )) && _batch_finalize nft
    (( realm_batch_count > 0 )) && _batch_finalize realm

    msg_ok "Import complete: $imported imported, $failed failed"
}

#===============================================================================
#  Section 8: Boot Persistence (handled in nft_setup_persistence and realm_setup_service)
#===============================================================================

# This section's logic is embedded in:
# - nft_setup_persistence() for nftables restore on boot
# - realm_setup_service() for realm systemd service

#===============================================================================
#  Section 9: CLI Argument Parser
#===============================================================================

show_help() {
    cat << EOF
pfwd - Port Forwarding Tool v$VERSION

Usage: pfwd [command] [options] [rules...]

Commands:
  (none/add)  Add forwarding rules (default)
  del         Delete forwarding rules
  list        List all forwarding rules
  status      Show running status and rule counts
  doctor      Run forwarding diagnostics
  start       Start forwarding (nft / realm / all)
  stop        Stop forwarding (nft / realm / all)
  restart     Restart forwarding (nft / realm / all)
  stats       Traffic statistics
  export      Export config to JSON
  import      Import config from JSON
  install     Install realm binary
  uninstall   Uninstall (realm / nftables / all)
  optimize    Run kernel optimization [balanced|gaming|lowmem]
  help        Show this help

Quick syntax:
  pfwd <port> <target>                    Add single nft rule
  pfwd <port> <target> <tport>            Add single mapped nft rule
  pfwd -m nft -t <target> 80,443          Add multiple nft rules
  pfwd -m nft -t <target> --replace 443   Replace an existing nft rule explicitly
  pfwd -m realm -t example.com 443        Add realm endpoint

Port formats:
  Single port:    80
  Multiple ports: 80,443
  Port range:     8080-8090
  Port mapping:   33389:3389
  Range mapping:  8080-8090:3080-3090
  Mixed:          80,443,8080-8090,33389:3389

Delete syntax:
  pfwd del -m nft 443
  pfwd del -m nft 8000-8010 --both
  pfwd del -m realm 443
  Interactive delete supports:
    #N       displayed rule number
    #N-#M    displayed rule range
    pPORT    direct port
    pA-B     direct port range

Traffic / diagnosis:
  pfwd list
  pfwd list -f mss
  pfwd status
  pfwd doctor
  pfwd stats
  pfwd stats --rate

Import / export:
  pfwd export [filepath]
  pfwd import <filepath> [-m nft|realm]
  pfwd import --url <URL> [-m nft|realm]
  Export/import preserves nft MSS and fixed-SNAT fields.

New examples:
  pfwd -m nft -t 10.0.0.2 --mss-clamp 443
  pfwd -m nft -t 10.0.0.2 --mss 1360 8443:443
  pfwd -m nft -t 10.0.0.2 --replace 8443:443
  pfwd -m nft -t 10.0.0.2 --snat-source 192.168.1.2 9443:443
  pfwd -m nft -t 10.0.0.2 --snat-source 192.168.1.2 --mss 1360 9443:443
  pfwd list -f snat
  pfwd export /tmp/pfwd-backup.json
  pfwd import /tmp/pfwd-backup.json
  Interactive add/delete/list/status also show MSS/SNAT options.

Common scenarios:
  pfwd 8080 1.2.3.4
  pfwd -m nft -t 1.2.3.4 --both 80,443
  pfwd -m nft -t 127.0.0.1 33389:3389
  pfwd -m realm -t example.com 443 -c "tls relay"
  pfwd doctor
  pfwd import backup.json
  pfwd optimize balanced

Performance tips:
  - nft is the fastest path for fixed IP targets.
  - realm is preferred for domain targets or when target IP changes.
  - Batch add/delete/import now coalesces nft save, UFW reload and realm restart.
  - For realm throughput, keep BBR enabled and check LimitNOFILE in 'pfwd status'.
  - If using loopback DNAT (127.0.0.1 / ::1), verify UFW loopback exceptions stay synced.

Options:
  -m, --method <nft|realm>   Forwarding method (required)
  -t, --target <addr>        Target IP or domain (required)
  -4                         IPv4 only
  -6                         IPv6 only
  -46                        Dual-stack (default)
  --tcp                      TCP only (default)
  --udp                      UDP only
  --both                     TCP + UDP
  --mss-clamp                nft only: clamp TCP MSS to PMTU on forwarded SYN packets
  --mss <value>              nft only: set a fixed TCP MSS value (e.g. 1360/1452)
  --replace                  nft only: replace an existing rule for the same port/proto/IP family
  --snat-source <addr>       nft only: use fixed SNAT source instead of masquerade
  --masquerade               nft only: force default masquerade mode
  -c, --comment <text>       Add comment to rule
  -q, --quiet                Quiet mode
  --no-color                 Disable colored output
  --no-clear                 Don't clear screen in interactive menu
EOF
}

# cmd_add - add forwarding rules from CLI
cmd_add() {
    local method="" ip_ver="46" proto="tcp" comment="" target="" rules_str=""
    local mss_mode="" mss_value="" snat_mode="masquerade" snat_source="" replace_mode="false"
    local -a positional_args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--method)  method="$2"; shift 2 ;;
            -t|--target)  target="$2"; shift 2 ;;
            -4)           ip_ver="4"; shift ;;
            -6)           ip_ver="6"; shift ;;
            -46)          ip_ver="46"; shift ;;
            --tcp)        proto="tcp"; shift ;;
            --udp)        proto="udp"; shift ;;
            --both)       proto="both"; shift ;;
            --mss-clamp)  mss_mode="clamp"; mss_value=""; shift ;;
            --mss)        mss_mode="set"; mss_value="$2"; shift 2 ;;
            --replace)    replace_mode="true"; shift ;;
            --snat-source) snat_mode="snat"; snat_source="$2"; shift 2 ;;
            --masquerade) snat_mode="masquerade"; snat_source=""; shift ;;
            -c|--comment) comment="$2"; shift 2 ;;
            -q|--quiet)   QUIET=true; shift ;;
            -*)           msg_err "Unknown option: $1"; show_help; return 1 ;;
            *)            positional_args+=("$1"); shift ;;
        esac
    done

    # Merge positional args: "80 443 8080-8090" -> "80,443,8080-8090"
    if (( ${#positional_args[@]} > 0 )); then
        local IFS=','
        rules_str="${positional_args[*]}"
    fi

    if [[ -z "$method" ]]; then
        msg_err "Method is required. Use -m nft or -m realm"
        return 1
    fi

    if [[ -z "$rules_str" ]]; then
        msg_err "No ports specified"
        msg_err "Usage: pfwd -m nft -t <target> <ports>"
        return 1
    fi

    if [[ -z "$target" ]]; then
        msg_err "Target is required. Use -t <ip|domain>"
        return 1
    fi

    if [[ -n "$mss_mode" && "$method" != "nft" ]]; then
        msg_err "MSS options are only supported with -m nft"
        return 1
    fi
    if [[ "$mss_mode" == "set" ]]; then
        if ! validate_mss_value "$mss_value"; then
            msg_err "Invalid MSS value: $mss_value (must be 536-65535)"
            return 1
        fi
    fi
    if [[ "$snat_mode" == "snat" ]]; then
        if [[ "$method" != "nft" ]]; then
            msg_err "Fixed SNAT source is only supported with -m nft"
            return 1
        fi
        local snat_type
        snat_type=$(detect_ip_type "$snat_source")
        if [[ "$snat_type" != "ipv4" && "$snat_type" != "ipv6" ]]; then
            msg_err "Invalid SNAT source address: $snat_source"
            return 1
        fi
    fi
    if [[ "$replace_mode" == "true" && "$method" != "nft" ]]; then
        msg_err "--replace is only supported with -m nft"
        return 1
    fi

    # Ensure IP forwarding is on (full optimization: use 'pfwd optimize [profile]')
    ensure_ip_forwarding 2>/dev/null || true

    local added=0 failed=0

    # Enable batch mode: skip per-rule save/restart
    _BATCH_MODE=true

    if ! validate_target "$target"; then
        msg_err "Invalid target: $target"
        _BATCH_MODE=false
        return 1
    fi
    if ! expand_port_spec "$rules_str" "$target"; then
        _BATCH_MODE=false
        return 1
    fi
    for expanded in "${EXPANDED_RULES[@]}"; do
        if ! parse_rule "$expanded"; then
            ((failed++)) || true; continue
        fi
        if _dispatch_add_rule "$method" "$RULE_LPORT" "$RULE_TARGET" "$RULE_TPORT" "$ip_ver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode"; then
            ((added++)) || true
        else
            ((failed++)) || true
        fi
    done

    # Batch finalize: save/persist/restart once
    _BATCH_MODE=false
    _batch_finalize "$method"

    if (( added > 0 || failed > 0 )); then
        msg_info "Result: $added added, $failed failed"
    fi
}

# cmd_delete - delete forwarding rules
cmd_delete() {
    local method="" ports_str="" proto="both"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--method) method="$2"; shift 2 ;;
            --tcp)       proto="tcp"; shift ;;
            --udp)       proto="udp"; shift ;;
            --both)      proto="both"; shift ;;
            -q|--quiet)  QUIET=true; shift ;;
            -*)          msg_err "Unknown option: $1"; return 1 ;;
            *)           ports_str="$1"; shift ;;
        esac
    done

    if [[ -z "$method" ]]; then
        msg_err "Method is required. Use -m nft or -m realm"
        return 1
    fi

    if [[ -z "$ports_str" ]]; then
        msg_err "No ports specified"
        return 1
    fi

    # Parse port list (comma-separated, with range support)
    local -a all_ports=()
    _expand_port_list "$ports_str"

    if (( ${#all_ports[@]} == 0 )); then
        msg_err "No valid ports found"
        return 1
    fi

    # Delete ports (use batch for nft when multiple ports)
    case "$method" in
        nft|nftables)
            if (( ${#all_ports[@]} > 1 )); then
                nft_delete_ports_batch all_ports "$proto"
            else
                nft_delete_port "${all_ports[0]}" "$proto"
            fi
            ;;
        realm)
            _BATCH_MODE=true
            for port in "${all_ports[@]}"; do
                realm_delete_endpoint "$port" "$proto"
            done
            _BATCH_MODE=false
            _batch_finalize realm
            if $_DIRTY_NFT || $_DIRTY_UFW_SYNC || $_DIRTY_UFW_RELOAD; then
                _batch_finalize nft
            fi
            ;;
        *)
            msg_err "Unknown method: $method"
            return 1
            ;;
    esac
}

# cmd_list - list all forwarding rules
cmd_list() {
    local filter=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--filter) filter="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    _pfwd_collect_state
    echo -e "${BOLD}Forwarding Rules${NC}"
    echo -e "${DIM}$SEP_EQ${NC}"
    [[ -n "$filter" ]] && echo -e "  ${DIM}Filter: $filter${NC}"
    echo ""
    nft_list_rules "$filter" "$(_traffic_read_merged)"
    echo ""
    realm_list_endpoints "$filter" "$PFWD_REALM_ENDPOINTS"
}

# _nft_saved_rule_count - count persisted prerouting DNAT rules in NFT_CONFIG
_nft_saved_rule_count() {
    [[ -f "$NFT_CONFIG" ]] || { echo 0; return; }
    awk '/dnat ip to / || /dnat ip6 to / { count++ } END { print count+0 }' "$NFT_CONFIG" 2>/dev/null
}

_doctor_print_check() {
    local level="$1" title="$2" detail="${3:-}"
    local color="$GREEN"
    case "$level" in
        WARN) color="$YELLOW" ;;
        ERROR) color="$RED" ;;
    esac
    if [[ -n "$detail" ]]; then
        echo -e "  ${color}[${level}]${NC} ${title} ${DIM}- ${detail}${NC}"
    else
        echo -e "  ${color}[${level}]${NC} ${title}"
    fi
}

cmd_doctor() {
    _pfwd_collect_state
    echo -e "${BOLD}pfwd Doctor${NC}"
    echo -e "${DIM}$SEP_EQ${NC}"

    local running_rules="$PFWD_NFT_COUNT"
    local saved_rules saved_valid=false
    saved_rules=$(_nft_saved_rule_count)

    if command -v nft >/dev/null 2>&1; then
        _doctor_print_check OK "nft command available"
    else
        _doctor_print_check ERROR "nft command missing" "install nftables before using nft forwarding"
    fi

    if _nft_table_exists; then
        _doctor_print_check OK "nft table loaded" "$running_rules rule(s) active"
        local chain
        for chain in prerouting postrouting forward input; do
            if _nft_cached_chain "$chain" >/dev/null; then
                _doctor_print_check OK "chain ${chain} present"
            else
                _doctor_print_check ERROR "chain ${chain} missing" "runtime table is incomplete"
            fi
        done
    elif (( saved_rules > 0 )); then
        _doctor_print_check WARN "saved nft config exists but table is not loaded" "run 'pfwd start nft' or 'pfwd restart nft'"
    else
        _doctor_print_check WARN "no active nft forwarding table"
    fi

    if [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]]; then
        if command -v nft >/dev/null 2>&1 && nft -c -f "$NFT_CONFIG" >/dev/null 2>&1; then
            saved_valid=true
            _doctor_print_check OK "persisted nft config is valid" "$saved_rules rule(s) saved"
        else
            _doctor_print_check ERROR "persisted nft config failed validation" "$NFT_CONFIG"
        fi
    else
        _doctor_print_check WARN "persisted nft config missing" "$NFT_CONFIG"
    fi

    if (( saved_rules > 0 && running_rules == 0 )); then
        _doctor_print_check WARN "rules are saved but not running" "use 'pfwd start nft'"
    elif (( running_rules > 0 && saved_rules == 0 )); then
        _doctor_print_check WARN "rules are running but not saved" "use 'pfwd restart nft' or modify rules to trigger save"
    elif (( running_rules != saved_rules )); then
        _doctor_print_check WARN "saved/runtime rule counts differ" "saved=${saved_rules}, running=${running_rules}"
    fi

    local fwd4 fwd6
    fwd4=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    fwd6=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "0")
    [[ "$fwd4" == "1" ]] && _doctor_print_check OK "IPv4 forwarding enabled" || _doctor_print_check ERROR "IPv4 forwarding disabled" "run 'pfwd optimize balanced' or enable net.ipv4.ip_forward=1"
    [[ "$fwd6" == "1" ]] && _doctor_print_check OK "IPv6 forwarding enabled" || _doctor_print_check WARN "IPv6 forwarding disabled"

    if $PFWD_LOOPBACK_DNAT; then
        local route_all route_default
        route_all=$(sysctl -n net.ipv4.conf.all.route_localnet 2>/dev/null || echo 0)
        route_default=$(sysctl -n net.ipv4.conf.default.route_localnet 2>/dev/null || echo 0)
        if [[ "$route_all" == "1" && "$route_default" == "1" ]]; then
            _doctor_print_check OK "route_localnet enabled for loopback DNAT"
        else
            _doctor_print_check ERROR "route_localnet missing for loopback DNAT" "run 'pfwd optimize balanced' or re-add the loopback rule"
        fi

        if command -v ufw >/dev/null 2>&1; then
            case "$PFWD_UFW_LOOPBACK_STATE" in
                ok) _doctor_print_check OK "UFW loopback DNAT exceptions synced" ;;
                missing) _doctor_print_check ERROR "UFW loopback DNAT exceptions missing" "reload pfwd rules or run 'ufw reload'" ;;
                disabled) _doctor_print_check WARN "UFW disabled; loopback exception sync not needed" ;;
                *) _doctor_print_check WARN "UFW loopback state: $PFWD_UFW_LOOPBACK_STATE" ;;
            esac
        fi
    fi

    if command -v iptables >/dev/null 2>&1; then
        local fwd_policy input_policy
        fwd_policy=$(iptables -S FORWARD 2>/dev/null | awk '/-P FORWARD/{print $3}')
        input_policy=$(iptables -S INPUT 2>/dev/null | awk '/-P INPUT/{print $3}')
        if [[ "$fwd_policy" == "DROP" ]]; then
            if _iptables_rule_present iptables FORWARD -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_FWD_DNAT_COMMENT" -j ACCEPT && \
               _iptables_rule_present iptables FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$IPTABLES_FWD_EST_COMMENT" -j ACCEPT; then
                _doctor_print_check OK "iptables FORWARD managed exceptions present"
            else
                _doctor_print_check ERROR "iptables FORWARD policy is DROP but pfwd exceptions are missing" "run 'pfwd restart nft' or reload UFW"
            fi
        else
            _doctor_print_check OK "iptables FORWARD policy is ${fwd_policy:-unset}"
        fi
        if [[ "$input_policy" == "DROP" && $PFWD_LOOPBACK_DNAT == true ]]; then
            if _iptables_rule_present iptables INPUT -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_INPUT_DNAT_COMMENT" -j ACCEPT; then
                _doctor_print_check OK "iptables INPUT managed exception present for loopback DNAT"
            else
                _doctor_print_check ERROR "iptables INPUT loopback DNAT exception missing" "run 'pfwd restart nft' or reload UFW"
            fi
        fi
    fi

    if command -v ip6tables >/dev/null 2>&1; then
        local fwd_policy6 input_policy6
        fwd_policy6=$(ip6tables -S FORWARD 2>/dev/null | awk '/-P FORWARD/{print $3}')
        input_policy6=$(ip6tables -S INPUT 2>/dev/null | awk '/-P INPUT/{print $3}')
        if [[ "$fwd_policy6" == "DROP" ]]; then
            if _iptables_rule_present ip6tables FORWARD -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_FWD_DNAT_COMMENT" -j ACCEPT && \
               _iptables_rule_present ip6tables FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$IPTABLES_FWD_EST_COMMENT" -j ACCEPT; then
                _doctor_print_check OK "ip6tables FORWARD managed exceptions present"
            else
                _doctor_print_check ERROR "ip6tables FORWARD policy is DROP but pfwd exceptions are missing" "run 'pfwd restart nft'"
            fi
        else
            _doctor_print_check OK "ip6tables FORWARD policy is ${fwd_policy6:-unset}"
        fi
        if [[ "$input_policy6" == "DROP" && $PFWD_LOOPBACK_DNAT == true ]]; then
            if _iptables_rule_present ip6tables INPUT -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_INPUT_DNAT_COMMENT" -j ACCEPT; then
                _doctor_print_check OK "ip6tables INPUT managed exception present for loopback DNAT"
            else
                _doctor_print_check ERROR "ip6tables INPUT loopback DNAT exception missing" "run 'pfwd restart nft'"
            fi
        fi
    fi

    if [[ -f "$NFT_RESTORE_SERVICE" ]]; then
        _doctor_print_check OK "boot restore service present" "$NFT_RESTORE_SERVICE"
    else
        _doctor_print_check WARN "boot restore service missing" "rules may not survive reboot"
    fi
}

# cmd_stop - stop forwarding without removing config
# cmd_status - show running status and rule counts
cmd_status() {
    _pfwd_collect_state
    echo -e "${BOLD}pfwd Status${NC}"
    echo -e "${DIM}$SEP_EQ_40${NC}"

    local nft_status realm_status
    $PFWD_NFT_RUNNING && nft_status="${GREEN}running${NC}" || nft_status="${RED}stopped${NC}"
    $PFWD_REALM_RUNNING && realm_status="${GREEN}running${NC}" || realm_status="${RED}stopped${NC}"
    echo -e "  nftables:  $nft_status  ($PFWD_NFT_COUNT rules)"
    echo -e "  realm:     $realm_status  ($PFWD_REALM_COUNT endpoints)"
    if [[ -n "$PFWD_NFT_RULES" ]]; then
        local nft_mss_count=0 nft_snat_count=0
        while IFS='|' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value; do
            [[ -z "$lport" ]] && continue
            [[ "$snat_mode" == "snat" ]] && ((nft_snat_count++)) || true
            [[ -n "$mss_mode" ]] && ((nft_mss_count++)) || true
        done <<< "$PFWD_NFT_RULES"
        if (( nft_mss_count > 0 || nft_snat_count > 0 )); then
            echo -e "  nft opts:  mss=${CYAN}${nft_mss_count}${NC}, fixed-snat=${CYAN}${nft_snat_count}${NC}"
        fi
    fi

    # realm binary
    if realm_is_installed; then
        local ver
        ver=$("$REALM_BIN" --version 2>/dev/null || echo "unknown")
        echo -e "  realm bin: ${GREEN}installed${NC} ($ver)"
    else
        echo -e "  realm bin: ${DIM}not installed${NC}"
    fi

    if [[ -n "$PFWD_REALM_NOFILE" ]]; then
        echo -e "  realm nofile: ${CYAN}${PFWD_REALM_NOFILE}${NC}"
    fi
    if [[ -n "$PFWD_REALM_TCP_TIMEOUT" || -n "$PFWD_REALM_UDP_TIMEOUT" ]]; then
        echo -e "  realm timeout: tcp=${CYAN}${PFWD_REALM_TCP_TIMEOUT:-default}${NC}, udp=${CYAN}${PFWD_REALM_UDP_TIMEOUT:-default}${NC}"
    fi

    # kernel forwarding
    local fwd4 fwd6
    fwd4=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    fwd6=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "0")
    local fwd_label
    if [[ "$fwd4" == "1" && "$fwd6" == "1" ]]; then
        fwd_label="${GREEN}IPv4+IPv6${NC}"
    elif [[ "$fwd4" == "1" ]]; then
        fwd_label="${YELLOW}IPv4 only${NC}"
    elif [[ "$fwd6" == "1" ]]; then
        fwd_label="${YELLOW}IPv6 only${NC}"
    else
        fwd_label="${RED}disabled${NC}"
    fi
    echo -e "  forwarding: $fwd_label"
    $PFWD_BBR_ENABLED && echo -e "  BBR: ${GREEN}enabled${NC}" || echo -e "  BBR: ${YELLOW}disabled${NC}"
    if $PFWD_LOOPBACK_DNAT; then
        case "$PFWD_UFW_LOOPBACK_STATE" in
            ok) echo -e "  loopback DNAT/UFW: ${GREEN}synced${NC}" ;;
            missing) echo -e "  loopback DNAT/UFW: ${RED}missing rule${NC}" ;;
            disabled) echo -e "  loopback DNAT/UFW: ${DIM}ufw disabled${NC}" ;;
            *) echo -e "  loopback DNAT/UFW: ${YELLOW}${PFWD_UFW_LOOPBACK_STATE}${NC}" ;;
        esac
    fi
}

# cmd_stop - stop forwarding without removing config
cmd_stop() {
    local target="${1:-all}"
    case "$target" in
        nft|nftables)
            if _nft_table_exists; then
                nft_setup_persistence
                nft delete table $NFT_TABLE 2>/dev/null || true
                _nft_invalidate_cache
                msg_ok "nftables forwarding stopped (config saved)"
            else
                msg_warn "nftables forwarding is not running"
            fi
            ;;
        realm)
            if systemctl is-active realm-forward >/dev/null 2>&1; then
                systemctl stop realm-forward 2>/dev/null || true
                msg_ok "realm forwarding stopped"
            else
                msg_warn "realm forwarding is not running"
            fi
            ;;
        all)
            cmd_stop nft
            cmd_stop realm
            ;;
        *)
            msg_err "Specify what to stop: nft, realm, or all"
            return 1
            ;;
    esac
}

# cmd_start - start forwarding from saved config
cmd_start() {
    local target="${1:-all}"
    case "$target" in
        nft|nftables)
            if _nft_table_exists; then
                msg_warn "nftables forwarding is already running"
                return 0
            fi
            if [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]]; then
                nft -f "$NFT_CONFIG" 2>/dev/null
                _nft_invalidate_cache
                if _nft_table_exists; then
                    local _restored_count
                    _restored_count=$(_nft_cached_chain prerouting | grep -c 'dnat') || _restored_count=0
                    msg_ok "nftables forwarding started ($_restored_count rules restored)"
                else
                    msg_err "Failed to restore nftables rules"
                    return 1
                fi
            else
                msg_warn "No saved nftables config found"
            fi
            ;;
        realm)
            if systemctl is-active realm-forward >/dev/null 2>&1; then
                msg_warn "realm forwarding is already running"
                return 0
            fi
            if [[ -f "$REALM_SERVICE" && -f "$REALM_CONFIG" ]]; then
                systemctl start realm-forward 2>/dev/null || true
                msg_ok "realm forwarding started"
            else
                msg_warn "No realm service configured"
            fi
            ;;
        all)
            cmd_start nft
            cmd_start realm
            ;;
        *)
            msg_err "Specify what to start: nft, realm, or all"
            return 1
            ;;
    esac
}

# cmd_uninstall - uninstall components
cmd_uninstall() {
    local target="${1:-}"

    case "$target" in
        nft|nftables)
            nft_flush_all
            ;;
        realm)
            realm_uninstall
            ;;
        all)
            nft_flush_all
            realm_uninstall
            # Remove sysctl config
            if [[ -f "$SYSCTL_CONF" ]]; then
                local marker_start="# pfwd-managed-start"
                local marker_end="# pfwd-managed-end"
                sed -i "/$marker_start/,/$marker_end/d" "$SYSCTL_CONF"
                sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
            fi
            remove_shortcut
            rm -rf "$DATA_DIR"
            msg_ok "All pfwd components removed"
            ;;
        *)
            msg_err "Specify what to uninstall: nft, realm, or all"
            return 1
            ;;
    esac
}

# parse_cli_args - main CLI entry point
parse_cli_args() {
    if [[ $# -eq 0 ]]; then
        interactive_menu
        return
    fi

    # Shortcut syntax: pfwd <port> <target> [tport]
    # Detect: first arg is a number/port-spec and second arg exists
    if [[ $# -ge 2 && "$1" =~ ^[0-9] && ! "$1" =~ ^[0-9]+$ ]] || \
       [[ $# -ge 2 && "$1" =~ ^[0-9]+$ ]]; then
        local _first="$1"
        local _second="${2:-}"
        # Make sure second arg is not a known subcommand flag
        if [[ -n "$_second" && ! "$_second" =~ ^- ]]; then
            local _tport_arg=""
            local _extra_start=3
            if [[ $# -ge 3 && "${3:-}" =~ ^[0-9]+$ ]]; then
                # pfwd 8080 1.2.3.4 80 → port mapping
                _tport_arg=":$3"
                _extra_start=4
            fi
            # Rewrite: pfwd <ports> <target> [tport] → pfwd add -m nft -t <target> <ports_with_mapping>
            local _rewritten_ports
            if [[ -n "$_tport_arg" ]]; then
                # Single port with target port mapping
                _rewritten_ports="${_first}${_tport_arg}"
            else
                _rewritten_ports="$_first"
            fi
            local -a _shortcut_args=("-m" "nft" "-t" "$_second" "$_rewritten_ports")
            local _arg_index
            for (( _arg_index=_extra_start; _arg_index<=$#; _arg_index++ )); do
                _shortcut_args+=("${!_arg_index}")
            done
            cmd_add "${_shortcut_args[@]}"
            return
        fi
    fi

    case "$1" in
        add)
            shift
            cmd_add "$@"
            ;;
        -m|--method)
            # Default to add when -m is first arg
            cmd_add "$@"
            ;;
        -4|-6|-46)
            # Flags before -m, treat as add
            cmd_add "$@"
            ;;
        -t|--target)
            # Target flag, treat as add
            cmd_add "$@"
            ;;
        del|delete)
            shift
            cmd_delete "$@"
            ;;
        list|ls)
            shift
            cmd_list "$@"
            ;;
        start)
            shift
            cmd_start "${1:-all}"
            ;;
        stop)
            shift
            cmd_stop "${1:-all}"
            ;;
        restart)
            shift
            local rt="${1:-all}"
            cmd_stop "$rt"
            cmd_start "$rt"
            ;;
        stats|traffic)
            shift
            if [[ "${1:-}" == "--rate" ]]; then
                show_traffic_rate
            else
                show_traffic_stats
            fi
            ;;
        status)
            cmd_status
            ;;
        doctor|diagnose)
            cmd_doctor
            ;;
        export)
            shift
            cmd_export "${1:-}"
            ;;
        import)
            shift
            local import_path="" import_method="" import_url=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --url) import_url="$2"; shift 2 ;;
                    -m|--method) import_method="$2"; shift 2 ;;
                    -*) msg_err "Unknown option: $1"; return 1 ;;
                    *)  import_path="$1"; shift ;;
                esac
            done
            local src="${import_url:-$import_path}"
            if [[ -z "$src" ]]; then
                msg_err "Specify a file path or --url"
                return 1
            fi
            cmd_import "$src" "$import_method"
            ;;
        install)
            realm_install
            ;;
        uninstall)
            shift
            cmd_uninstall "${1:-}"
            ;;
        optimize)
            shift
            case "${1:-balanced}" in
                reset|undo) reset_kernel_optimization ;;
                *) optimize_kernel "${1:-balanced}" ;;
            esac
            ;;
        help|--help|-h)
            show_help
            ;;
        --version|-v)
            echo "pfwd v$VERSION"
            ;;
        -q|--quiet)
            QUIET=true
            shift
            parse_cli_args "$@"
            ;;
        --no-color)
            # Already handled in pre-scan, just consume the flag
            shift
            parse_cli_args "$@"
            ;;
        --no-clear)
            # Already handled in pre-scan, just consume the flag
            shift
            parse_cli_args "$@"
            ;;
        *)
            msg_err "Unknown command: $1"
            show_help
            return 1
            ;;
    esac
}

#===============================================================================
#  Section 10: Interactive Menu
#===============================================================================

show_header() {
    $_NO_CLEAR || clear 2>/dev/null || true

    _pfwd_collect_state

    local rule_count=$((PFWD_NFT_COUNT + PFWD_REALM_COUNT))

    # Check running status (colored + plain text)
    local status_text status_plain
    if $PFWD_NFT_RUNNING || $PFWD_REALM_RUNNING; then
        status_text="${GREEN}Running${NC}"; status_plain="Running"
    else
        status_text="${RED}Stopped${NC}"; status_plain="Stopped"
    fi

    # Detect network (colored + plain text)
    detect_local_network
    local net_info="" net_plain=""
    if $LOCAL_HAS_IPV4 && $LOCAL_HAS_IPV6; then
        local v4_label="${GREEN}IPv4${NC}" v4_plain="IPv4"
        local v6_label="${GREEN}IPv6${NC}" v6_plain="IPv6"
        if [[ "$LOCAL_IPV4_TYPE" == "private" ]]; then
            v4_label="${YELLOW}IPv4(NAT)${NC}"; v4_plain="IPv4(NAT)"
        elif [[ "$LOCAL_IPV4_TYPE" == "public" ]]; then
            v4_label="${GREEN}IPv4${NC}"; v4_plain="IPv4"
        fi
        if [[ "$LOCAL_IPV6_TYPE" == "private" ]]; then
            v6_label="${YELLOW}IPv6(ULA)${NC}"; v6_plain="IPv6(ULA)"
        elif [[ "$LOCAL_IPV6_TYPE" == "public" ]]; then
            v6_label="${GREEN}IPv6${NC}"; v6_plain="IPv6"
        fi
        net_info="${v4_label}+${v6_label}"; net_plain="${v4_plain}+${v6_plain}"
    elif $LOCAL_HAS_IPV4; then
        if [[ "$LOCAL_IPV4_TYPE" == "private" ]]; then
            net_info="${YELLOW}IPv4(NAT)${NC}"; net_plain="IPv4(NAT)"
        else
            net_info="${GREEN}IPv4${NC}"; net_plain="IPv4"
        fi
    elif $LOCAL_HAS_IPV6; then
        if [[ "$LOCAL_IPV6_TYPE" == "private" ]]; then
            net_info="${YELLOW}IPv6(ULA)${NC}"; net_plain="IPv6(ULA)"
        else
            net_info="${CYAN}IPv6${NC}"; net_plain="IPv6"
        fi
    else
        net_info="${RED}No IP${NC}"; net_plain="No IP"
    fi

    local perf_parts=()
    perf_parts+=("nft:${PFWD_NFT_COUNT}")
    perf_parts+=("realm:${PFWD_REALM_COUNT}")
    $PFWD_BBR_ENABLED && perf_parts+=("BBR:on") || perf_parts+=("BBR:off")
    if $PFWD_LOOPBACK_DNAT; then
        case "$PFWD_UFW_LOOPBACK_STATE" in
            ok) perf_parts+=("loopback:ufw-ok") ;;
            missing) perf_parts+=("loopback:ufw-missing") ;;
            disabled) perf_parts+=("loopback:ufw-off") ;;
        esac
    fi
    local perf_plain perf_text
    perf_plain=$(IFS=' │ '; echo "${perf_parts[*]}")
    perf_text="$perf_plain"

    # ── Compute dynamic box inner width ──
    local title_l_plain="  pfwd - Port Forwarding Tool"
    local title_r_plain="v$VERSION  "
    local title_min_gap=2
    local title_plain_len=$(( ${#title_l_plain} + title_min_gap + ${#title_r_plain} ))

    local seg1="Status: ${status_plain}"
    local seg2="Rules: ${rule_count}"
    local seg3="Net: ${net_plain}"
    local seg4="Perf: ${perf_plain}"
    local status_plain_len=$(( 2 + ${#seg1} + 3 + ${#seg2} + 3 + ${#seg3} + 2 ))
    local perf_plain_len=$(( 2 + ${#seg4} + 2 ))

    local inner_w=$title_plain_len
    (( status_plain_len > inner_w )) && inner_w=$status_plain_len
    (( perf_plain_len > inner_w )) && inner_w=$perf_plain_len
    (( inner_w < 56 )) && inner_w=56
    local term_w
    term_w=$(tput cols 2>/dev/null || echo 80)
    (( inner_w > term_w - 2 )) && inner_w=$((term_w - 2))

    if (( status_plain_len > inner_w )); then
        local max_net=$(( inner_w - 2 - ${#seg1} - 3 - ${#seg2} - 3 - 5 - 2 ))
        (( max_net < 3 )) && max_net=3
        net_plain="${net_plain:0:$max_net}"
        net_info="$net_plain"
        seg3="Net: ${net_plain}"
        status_plain_len=$(( 2 + ${#seg1} + 3 + ${#seg2} + 3 + ${#seg3} + 2 ))
    fi
    if (( perf_plain_len > inner_w )); then
        local max_perf=$(( inner_w - 2 - 6 - 2 ))
        (( max_perf < 8 )) && max_perf=8
        perf_plain="${perf_plain:0:$max_perf}"
        perf_text="$perf_plain"
        seg4="Perf: ${perf_plain}"
        perf_plain_len=$(( 2 + ${#seg4} + 2 ))
    fi

    local border_eq border_dash
    printf -v border_eq '%*s' "$inner_w" ''
    border_eq=${border_eq// /═}
    printf -v border_dash '%*s' "$inner_w" ''
    border_dash=${border_dash// /─}

    local title_gap=$(( inner_w - ${#title_l_plain} - ${#title_r_plain} ))
    (( title_gap < 1 )) && title_gap=1
    local title_gap_str
    printf -v title_gap_str '%*s' "$title_gap" ''

    local status_right_pad=$(( inner_w - status_plain_len ))
    (( status_right_pad < 0 )) && status_right_pad=0
    local status_pad_str
    printf -v status_pad_str '%*s' "$status_right_pad" ''

    local perf_right_pad=$(( inner_w - perf_plain_len ))
    (( perf_right_pad < 0 )) && perf_right_pad=0
    local perf_pad_str
    printf -v perf_pad_str '%*s' "$perf_right_pad" ''

    echo ""
    echo -e "${CYAN}╔${border_eq}╗${NC}"
    echo -e "${CYAN}║${NC}${title_l_plain}${title_gap_str}${DIM}${title_r_plain}${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╟${border_dash}╢${NC}"
    echo -e "${CYAN}║${NC}  Status: ${status_text} ${CYAN}│${NC} Rules: ${CYAN}${rule_count}${NC} ${CYAN}│${NC} Net: ${net_info}  ${status_pad_str}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Perf: ${perf_text}  ${perf_pad_str}${CYAN}║${NC}"
    echo -e "${CYAN}╚${border_eq}╝${NC}"
    echo ""
}

interactive_menu() {
    while true; do
        show_header

        # Determine forwarding status for menu item 4
        local _nft_running=false _realm_running=false
        _nft_running=$PFWD_NFT_RUNNING
        _realm_running=$PFWD_REALM_RUNNING
        local _fwd_label
        if $_nft_running || $_realm_running; then
            _fwd_label="${RED}Stop forwarding${NC}"
        else
            _fwd_label="${GREEN}Start forwarding${NC}"
        fi

        echo -e "  ${DIM}── Rule Management ──${NC}"
        echo -e "  ${CYAN}1)${NC} Add forwarding rules"
        echo -e "  ${CYAN}2)${NC} View forwarding rules"
        echo -e "  ${CYAN}3)${NC} Delete forwarding rules"
        echo ""
        echo -e "  ${DIM}── Service Control ──${NC}"
        echo -e "  ${CYAN}4)${NC} ${_fwd_label}"
        echo -e "  ${CYAN}5)${NC} Traffic statistics"
        echo -e "  ${CYAN}s)${NC} Status overview"
        echo -e "  ${CYAN}d)${NC} Doctor / diagnostics"
        echo ""
        echo -e "  ${DIM}── Configuration ──${NC}"
        echo -e "  ${CYAN}6)${NC} Import/Export config"
        echo -e "  ${CYAN}7)${NC} Install/Update realm"
        echo -e "  ${CYAN}8)${NC} Kernel optimization"
        echo -e "  ${CYAN}h)${NC} Help / CLI cheatsheet"
        echo ""
        echo -e "  ${DIM}── System ──${NC}"
        echo -e "  ${CYAN}9)${NC} ${RED}Uninstall${NC}"
        echo -e "  ${CYAN}0)${NC} ${DIM}Exit${NC}"
        echo ""
        read -rp "${CYAN}Select [0-9/s/d/h]:${NC} " choice

        case "$choice" in
            1) menu_add_rule || true ;;
            2) cmd_list; wait_for_enter ;;
            3) menu_delete_rule || true ;;
            4)
                if $_nft_running || $_realm_running; then
                    menu_stop_forward || true
                else
                    menu_start_forward || true
                fi
                ;;
            5) show_traffic_stats; wait_for_enter ;;
            s|S) cmd_status; wait_for_enter ;;
            d|D) cmd_doctor; wait_for_enter ;;
            6) menu_export_import || true ;;
            7) realm_install; wait_for_enter ;;
            8)
                echo ""
                echo -e "  ${CYAN}1)${NC} balanced  (default, high bandwidth)"
                echo -e "  ${CYAN}2)${NC} gaming    (low latency, longer UDP timeout)"
                echo -e "  ${CYAN}3)${NC} lowmem    (for 512MB-1GB VPS)"
                echo -e "  ${CYAN}4)${NC} ${YELLOW}Reset${NC}     (undo optimization, remove pfwd config)"
                echo -e "  ${CYAN}0)${NC} ${DIM}Back${NC}"
                echo ""
                read -rp "Select [0-4, default=1]: " _kp
                case "$_kp" in
                    0) continue ;;
                    2) optimize_kernel gaming; wait_for_enter ;;
                    3) optimize_kernel lowmem; wait_for_enter ;;
                    4) reset_kernel_optimization; wait_for_enter ;;
                    *) optimize_kernel balanced; wait_for_enter ;;
                esac
                ;;
            h|H) show_help; wait_for_enter ;;
            9) menu_uninstall || true ;;
            0) echo "Bye."; exit 0 ;;
            *) msg_warn "Invalid choice"; sleep 1.5 ;;
        esac
    done
}

# menu_add_rule - interactive rule addition
menu_add_rule() {
    local mss_mode="" mss_value="" snat_mode="masquerade" snat_source="" replace_mode="false"
    echo ""
    echo -e "${BOLD}Add Forwarding Rule${NC}"
    echo -e "${DIM}$SEP_DASH_40${NC}"

    # 1. Method selection
    echo ""
    echo "  1) nftables  (kernel-level, fast path with flowtable)"
    echo "  2) realm     (userspace, supports domain targets)"
    echo "  0) Back"
    echo ""
    read -rp "Method [0-2]: " method_choice

    local method
    case "$method_choice" in
        1) method="nft" ;;
        2) method="realm" ;;
        0) return ;;
        *) msg_err "Invalid choice"; wait_for_enter; return ;;
    esac

    # 2. IP version
    echo ""
    echo "  1) IPv4 only"
    echo "  2) IPv6 only"
    echo "  3) Dual-stack (default)"
    echo "  0) Back"
    echo ""
    read -rp "IP version [3]: " ipver_choice
    ipver_choice=${ipver_choice:-3}

    local ip_ver
    case "$ipver_choice" in
        1) ip_ver="4" ;;
        2) ip_ver="6" ;;
        3) ip_ver="46" ;;
        0) return ;;
        *) ip_ver="46" ;;
    esac

    # 3. Protocol (nftables only)
    local proto="tcp"
    if [[ "$method" == "nft" ]]; then
        echo ""
        echo "  1) TCP only (default)"
        echo "  2) UDP only"
        echo "  3) TCP + UDP"
        echo "  0) Back"
        echo ""
        read -rp "Protocol [1]: " proto_choice
        proto_choice=${proto_choice:-1}

        case "$proto_choice" in
            1) proto="tcp" ;;
            2) proto="udp" ;;
            3) proto="both" ;;
            0) return ;;
            *) proto="tcp" ;;
        esac
    fi

    # 4. Target IP/domain
    echo ""
    echo -e "${BOLD}Enter target IP address or domain (empty to cancel):${NC}"
    echo -e "  ${DIM}IPv4:   ${BOLD}1.2.3.4${NC}"
    echo -e "  ${DIM}IPv6:   ${BOLD}2001:db8::1${NC}"
    echo -e "  ${DIM}Domain: ${BOLD}example.com${NC}"
    echo ""
    local target=""
    read -rp "Target: " target
    if [[ -z "$target" ]]; then
        msg_info "Cancelled"
        return
    fi
    if ! validate_target "$target"; then
        msg_err "Invalid target: $target"
        wait_for_enter
        return
    fi
    local target_type
    target_type=$(detect_ip_type "$target")
    case "$target_type" in
        ipv4)   msg_dim "  Valid IPv4 address" ;;
        ipv6)   msg_dim "  Valid IPv6 address" ;;
        domain) msg_dim "  Valid domain name" ;;
    esac

    # 5. Port config (simplified input)
    echo ""
    echo -e "${BOLD}Enter port(s) to forward (empty to cancel):${NC}"
    echo -e "  ${DIM}Single:        ${BOLD}80${NC}"
    echo -e "  ${DIM}Multiple:      ${BOLD}80,443${NC}"
    echo -e "  ${DIM}Range:         ${BOLD}8080-8090${NC}"
    echo -e "  ${DIM}Mapping:       ${BOLD}33389:3389${NC}"
    echo -e "  ${DIM}Range mapping: ${BOLD}8080-8090:3080-3090${NC}"
    echo -e "  ${DIM}Mixed:         ${BOLD}80,443,8080-8090,33389:3389${NC}"
    echo ""
    local port_spec=""
    read -rp "Port(s): " port_spec

    if [[ -z "$port_spec" ]]; then
        msg_info "Cancelled"
        return
    fi

    # 6. Comment (both nft and realm)
    local comment=""
    echo ""
    read -rp "Comment (optional): " comment

    # 7. Optional nft advanced settings
    if [[ "$method" == "nft" ]]; then
        echo ""
        echo -e "${BOLD}Optional nft advanced settings:${NC}"
        echo "  SNAT mode:"
        echo "    1) Masquerade (default)"
        echo "    2) Fixed source SNAT"
        echo "    0) Back"
        echo ""
        local snat_choice
        read -rp "SNAT mode [1]: " snat_choice
        snat_choice=${snat_choice:-1}
        case "$snat_choice" in
            1) snat_mode="masquerade"; snat_source="" ;;
            2)
                snat_mode="snat"
                read -rp "SNAT source address: " snat_source
                if [[ -z "$snat_source" ]]; then
                    msg_err "SNAT source address is required"
                    wait_for_enter
                    return
                fi
                local snat_type
                snat_type=$(detect_ip_type "$snat_source")
                if [[ "$snat_type" != "ipv4" && "$snat_type" != "ipv6" ]]; then
                    msg_err "Invalid SNAT source address: $snat_source"
                    wait_for_enter
                    return
                fi
                ;;
            0) return ;;
            *) snat_mode="masquerade"; snat_source="" ;;
        esac

        if [[ "$proto" != "udp" ]]; then
            echo ""
            echo "  TCP MSS handling:"
            echo "    1) Off (default)"
            echo "    2) Clamp to PMTU"
            echo "    3) Fixed MSS value"
            echo "    0) Back"
            echo ""
            local mss_choice
            read -rp "MSS mode [1]: " mss_choice
            mss_choice=${mss_choice:-1}
            case "$mss_choice" in
                1) mss_mode=""; mss_value="" ;;
                2) mss_mode="clamp"; mss_value="" ;;
                3)
                    mss_mode="set"
                    read -rp "MSS value: " mss_value
                    if ! validate_mss_value "$mss_value"; then
                        msg_err "Invalid MSS value: $mss_value (must be 536-65535)"
                        wait_for_enter
                        return
                    fi
                    ;;
                0) return ;;
                *) mss_mode=""; mss_value="" ;;
            esac
        fi
    fi

    if ! expand_port_spec "$port_spec" "$target"; then
        msg_err "Failed to expand port spec"
        wait_for_enter
        return
    fi

    echo ""
    echo -e "${BOLD}=== Confirmation ===${NC}"
    echo -e "  Method:   ${CYAN}${method}${NC}"
    echo -e "  IP ver:   ${CYAN}${ip_ver}${NC}"
    [[ "$method" == "nft" ]] && echo -e "  Protocol: ${CYAN}${proto}${NC}"
    echo -e "  Target:   ${CYAN}${target}${NC}"
    echo -e "  Raw spec: ${CYAN}${port_spec}${NC}"
    [[ -n "$comment" ]] && echo -e "  Comment:  ${CYAN}${comment}${NC}"
    if [[ "$method" == "nft" ]]; then
        if [[ "$snat_mode" == "snat" ]]; then
            echo -e "  SNAT:     ${CYAN}fixed ${snat_source}${NC}"
        else
            echo -e "  SNAT:     ${CYAN}masquerade${NC}"
        fi
        if [[ -n "$mss_mode" ]]; then
            if [[ "$mss_mode" == "clamp" ]]; then
                echo -e "  MSS:      ${CYAN}clamp to PMTU${NC}"
            else
                echo -e "  MSS:      ${CYAN}fixed ${mss_value}${NC}"
            fi
        fi
    fi
    echo -e "  Expanded:"
    local preview_count=0
    for expanded in "${EXPANDED_RULES[@]}"; do
        ((preview_count++)) || true
        if parse_rule "$expanded"; then
            echo -e "    ${DIM}- :${RULE_LPORT} -> ${RULE_TARGET}:${RULE_TPORT}${NC}"
        fi
        (( preview_count >= 8 )) && break
    done
    if (( ${#EXPANDED_RULES[@]} > 8 )); then
        echo -e "    ${DIM}... and $(( ${#EXPANDED_RULES[@]} - 8 )) more${NC}"
    fi
    if [[ "$method" == "realm" && "$target_type" == "domain" ]]; then
        echo -e "  ${DIM}Realm will keep domain target and resolve it at runtime.${NC}"
    elif [[ "$method" == "nft" && "$target_type" == "domain" ]]; then
        echo -e "  ${DIM}nft will resolve the domain once during add/import.${NC}"
    fi
    if [[ "$method" == "nft" ]]; then
        if _nft_collect_add_conflicts "$target" "$ip_ver" "$proto" && (( ${#NFT_ADD_CONFLICTS[@]} > 0 )); then
            echo ""
            echo -e "${YELLOW}Existing nft rules conflict with this request:${NC}"
            local conflict
            for conflict in "${NFT_ADD_CONFLICTS[@]}"; do
                IFS='|' read -r cproto clport cipver old_target old_tport new_target new_tport <<< "$conflict"
                echo -e "    ${DIM}- :${clport} ${cproto} IPv${cipver} ${old_target}:${old_tport} -> ${new_target}:${new_tport}${NC}"
            done
            echo ""
            read -rp "Replace conflicting nft rule(s)? [y/N]: " replace_confirm
            if [[ "$replace_confirm" =~ ^[Yy]$ ]]; then
                replace_mode="true"
            else
                msg_info "Cancelled"
                wait_for_enter
                return
            fi
        fi
    fi
    echo ""
    read -rp "Proceed? [Y/n]: " confirm
    confirm=${confirm:-Y}
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        msg_info "Cancelled"
        return
    fi

    echo ""
    msg_info "Processing ${#EXPANDED_RULES[@]} expanded rule(s)..."

    ensure_ip_forwarding 2>/dev/null || true

    _BATCH_MODE=true
    local added=0 failed=0
    local total_rules=${#EXPANDED_RULES[@]}
    local progress_idx=0
    for expanded in "${EXPANDED_RULES[@]}"; do
        ((progress_idx++)) || true
        (( total_rules > 3 )) && show_progress "$progress_idx" "$total_rules" "Adding"
        if ! parse_rule "$expanded"; then
            ((failed++)) || true; continue
        fi
        if _dispatch_add_rule "$method" "$RULE_LPORT" "$RULE_TARGET" "$RULE_TPORT" "$ip_ver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode"; then
            ((added++)) || true
        else
            ((failed++)) || true
        fi
    done

    _BATCH_MODE=false
    _batch_finalize "$method"

    echo ""
    msg_info "Result: $added rules added, $failed failed"
    wait_for_enter
}

# menu_delete_rule - interactive rule deletion
menu_delete_rule() {
    echo ""
    echo -e "${BOLD}Delete Forwarding Rule${NC}"
    echo -e "${DIM}$SEP_DASH_40${NC}"

    local nft_parsed="" realm_parsed=""
    if _nft_table_exists; then
        nft_parsed=$(_parse_nft_export_rules)
    fi
    realm_parsed=$(_parse_realm_endpoints)

    local -a rule_methods=() rule_ports=() rule_labels=() rule_specs=()
    local idx=0

    if [[ -n "$nft_parsed" ]]; then
        while IFS='|' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value; do
            [[ -z "$lport" ]] && continue
            ((idx++)) || true
            rule_methods+=("nft")
            rule_ports+=("$lport")
            rule_specs+=("${proto}|${lport}|${ipver}|${target}|${tport}")
            local option_label traffic_label
            option_label=$(_nft_rule_option_summary "$snat_mode" "$snat_source" "$mss_mode" "$mss_value")
            traffic_label=$(format_bytes "$(nft_get_traffic "$lport")")
            rule_labels+=("$(printf "[nft] :%s %s IPv%s -> %s:%s [opts:%s] (%s)" "$lport" "$proto" "$ipver" "$target" "$tport" "$option_label" "$traffic_label")")
        done <<< "$(echo "$nft_parsed" | _sort_parsed_rules)"
    fi

    if [[ -n "$realm_parsed" ]]; then
        while IFS='|' read -r lport target tport ip_ver listen remote comment; do
            [[ -z "$lport" ]] && continue
            ((idx++)) || true
            rule_methods+=("realm")
            rule_ports+=("$lport")
            rule_specs+=("$lport")
            local comment_label="${comment:-no comment}"
            rule_labels+=("$(printf "[realm] :%s -> %s (%s)" "$lport" "$remote" "$comment_label")")
        done <<< "$realm_parsed"
    fi

    if (( idx == 0 )); then
        msg_dim "  No forwarding rules found"
        wait_for_enter
        return
    fi

    echo ""
    echo -e "${CYAN}Current rules:${NC}"
    for (( i=0; i<idx; i++ )); do
        echo -e "  ${BOLD}$((i+1)))${NC} ${rule_labels[$i]}"
    done
    echo ""
    echo -e "${DIM}Use #N for displayed rule numbers, pPORT for direct port deletion.${NC}"
    echo -e "${DIM}Examples: #1,#3   #2-#5   p443   p8000-8010${NC}"
    read -rp "Selection: " input_str

    if [[ -z "$input_str" ]]; then
        msg_info "Cancelled"
        return
    fi

    local -a delete_rule_numbers=() delete_port_numbers=()
    if ! _parse_delete_input "$input_str" "$idx"; then
        wait_for_enter
        return
    fi

    local proto="both"
    local port_method=""
    if (( ${#delete_port_numbers[@]} > 0 )); then
        echo ""
        echo "Port selections need a method:"
        echo "  1) nftables"
        echo "  2) realm"
        echo ""
        read -rp "Method [1]: " method_choice
        method_choice=${method_choice:-1}
        case "$method_choice" in
            2) port_method="realm" ;;
            *) port_method="nft" ;;
        esac
        if [[ "$port_method" == "nft" ]]; then
            echo ""
            echo "  1) TCP only"
            echo "  2) UDP only"
            echo "  3) Both TCP and UDP (default)"
            echo ""
            read -rp "Protocol [3]: " proto_choice
            proto_choice=${proto_choice:-3}
            case "$proto_choice" in
                1) proto="tcp" ;;
                2) proto="udp" ;;
                *) proto="both" ;;
            esac
        fi
    fi

    local delete_count=0 nft_rule_deleted=0
    if (( ${#delete_rule_numbers[@]} > 0 )); then
        local realm_batch_needed=false
        for rnum in "${delete_rule_numbers[@]}"; do
            local ri=$((rnum - 1))
            local method="${rule_methods[$ri]}"
            local port="${rule_ports[$ri]}"
            case "$method" in
                nft)
                    local rule_proto rule_lport rule_ipver rule_target rule_tport
                    IFS='|' read -r rule_proto rule_lport rule_ipver rule_target rule_tport <<< "${rule_specs[$ri]}"
                    if _nft_delete_exact_rule "$rule_lport" "$rule_proto" "$rule_ipver" "$rule_target" "$rule_tport"; then
                        ((nft_rule_deleted++)) || true
                        ((delete_count++)) || true
                    fi
                    ;;
                realm)
                    realm_batch_needed=true
                    ;;
            esac
        done
        if (( nft_rule_deleted > 0 )); then
            _mark_nft_dirty
            _batch_finalize nft
        fi
        if [[ "$realm_batch_needed" == true ]]; then
            _BATCH_MODE=true
            for rnum in "${delete_rule_numbers[@]}"; do
                local ri=$((rnum - 1))
                [[ "${rule_methods[$ri]}" == "realm" ]] || continue
                realm_delete_endpoint "${rule_ports[$ri]}" "$proto"
                ((delete_count++)) || true
            done
            _BATCH_MODE=false
            _batch_finalize realm
            if $_DIRTY_NFT || $_DIRTY_UFW_SYNC || $_DIRTY_UFW_RELOAD; then
                _batch_finalize nft
            fi
        fi
    fi

    if (( ${#delete_port_numbers[@]} > 0 )); then
        case "$port_method" in
            realm)
                _BATCH_MODE=true
                for port in "${delete_port_numbers[@]}"; do
                    realm_delete_endpoint "$port" "$proto"
                    ((delete_count++)) || true
                done
                _BATCH_MODE=false
                _batch_finalize realm
                if $_DIRTY_NFT || $_DIRTY_UFW_SYNC || $_DIRTY_UFW_RELOAD; then
                    _batch_finalize nft
                fi
                ;;
            *)
                if (( ${#delete_port_numbers[@]} > 1 )); then
                    nft_delete_ports_batch delete_port_numbers "$proto"
                    delete_count=$(( delete_count + ${#delete_port_numbers[@]} ))
                else
                    for port in "${delete_port_numbers[@]}"; do
                        nft_delete_port "$port" "$proto"
                        ((delete_count++)) || true
                    done
                fi
                ;;
        esac
    fi

    echo ""
    msg_info "Deletion requests processed: $delete_count"
    wait_for_enter
}

# menu_export_import - interactive import/export
menu_export_import() {
    echo ""
    echo -e "${BOLD}Import / Export Configuration${NC}"
    echo -e "${DIM}$SEP_DASH_40${NC}"
    echo ""
    echo "  1) Export to JSON file"
    echo "  2) Import from JSON file"
    echo "  3) Import from URL"
    echo "  4) List backup files"
    echo "  0) Back"
    echo ""
    read -rp "Choice [0-4]: " ie_choice

    case "$ie_choice" in
        1)
            echo ""
            read -rp "Export path [default: auto-generated]: " epath
            if [[ -n "$epath" ]]; then
                cmd_export "$epath"
            else
                cmd_export
            fi
            ;;
        2)
            echo ""
            read -rp "JSON file path: " ipath
            if [[ -z "$ipath" ]]; then
                msg_info "Cancelled"
                return
            fi
            echo ""
            echo "Override method? (leave empty to keep original)"
            echo "  nft   - Import all as nftables"
            echo "  realm - Import all as realm"
            echo ""
            read -rp "Method [keep original]: " imethod
            cmd_import "$ipath" "$imethod"
            ;;
        3)
            echo ""
            read -rp "URL: " iurl
            if [[ -z "$iurl" ]]; then
                msg_info "Cancelled"
                return
            fi
            echo ""
            read -rp "Override method [keep original]: " imethod
            cmd_import "$iurl" "$imethod"
            ;;
        4)
            echo ""
            echo -e "${BOLD}Backup files:${NC}"
            if ls "$DATA_DIR"/backup_*.json >/dev/null 2>&1; then
                ls -lh "$DATA_DIR"/backup_*.json
            else
                msg_dim "  No backup files found in $DATA_DIR"
            fi
            ;;
        0) return ;;
        *)
            msg_warn "Invalid choice"
            ;;
    esac

    wait_for_enter
}

# menu_stop_forward - interactive stop forwarding
menu_stop_forward() {
    echo ""
    echo -e "${BOLD}Stop Forwarding${NC}"
    echo -e "${DIM}$SEP_DASH_40${NC}"
    echo ""
    echo "  1) Stop nftables only"
    echo "  2) Stop realm only"
    echo "  3) Stop all"
    echo "  0) Back"
    echo ""
    read -rp "Choice [0-3]: " schoice
    case "$schoice" in
        1) cmd_stop nft ;;
        2) cmd_stop realm ;;
        3) cmd_stop all ;;
        0) return ;;
        *) msg_warn "Invalid choice" ;;
    esac
    wait_for_enter
}

# menu_start_forward - interactive start forwarding
menu_start_forward() {
    echo ""
    echo -e "${BOLD}Start Forwarding${NC}"
    echo -e "${DIM}$SEP_DASH_40${NC}"
    echo ""
    echo "  1) Start nftables only"
    echo "  2) Start realm only"
    echo "  3) Start all"
    echo "  0) Back"
    echo ""
    read -rp "Choice [0-3]: " schoice
    case "$schoice" in
        1) cmd_start nft ;;
        2) cmd_start realm ;;
        3) cmd_start all ;;
        0) return ;;
        *) msg_warn "Invalid choice" ;;
    esac
    wait_for_enter
}

# menu_uninstall - interactive uninstall
menu_uninstall() {
    echo ""
    echo -e "${BOLD}Uninstall${NC}"
    echo -e "${DIM}$SEP_DASH_40${NC}"
    echo ""
    echo "  1) Uninstall nftables rules only"
    echo "  2) Uninstall realm only"
    echo "  3) Uninstall everything"
    echo "  0) Back"
    echo ""
    read -rp "Choice [0-3]: " uchoice

    case "$uchoice" in
        1) cmd_uninstall nft ;;
        2) cmd_uninstall realm ;;
        3)
            echo ""
            read -rp "Are you sure? This will remove ALL forwarding rules. [y/N]: " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] && cmd_uninstall all || msg_info "Cancelled"
            ;;
        0) return ;;
        *) msg_warn "Invalid choice" ;;
    esac

    wait_for_enter
}

#===============================================================================
#  Section 11: Main Entry
#===============================================================================

# Initialize script path detection
SCRIPT_PATH=""
USE_LOOP_MENU=false
RETURN_TO_MENU=false

require_root "$@"
ensure_shortcut
ensure_script_installed
parse_cli_args "$@"
