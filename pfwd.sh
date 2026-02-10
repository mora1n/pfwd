#!/bin/bash
#===============================================================================
#  pfwd - Port Forwarding Tool v1.0.0
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

readonly VERSION="1.4.2"

# Paths
readonly DATA_DIR="/var/lib/pfwd"
readonly NFT_CONFIG="/etc/nftables.d/port_forward.nft"
readonly NFT_RESTORE_SCRIPT="$DATA_DIR/restore-nft.sh"
readonly NFT_RESTORE_SERVICE="/etc/systemd/system/pfwd-nft-restore.service"
readonly REALM_BIN="/usr/local/bin/realm"
readonly REALM_CONFIG_DIR="/etc/realm"
readonly REALM_CONFIG="$REALM_CONFIG_DIR/config.toml"
readonly REALM_SERVICE="/etc/systemd/system/realm-forward.service"
readonly SYSCTL_CONF="/etc/sysctl.d/99-pfwd.conf"

# Install paths
readonly INSTALL_DIR="/usr/local/bin"
readonly INSTALLED_SCRIPT="$INSTALL_DIR/pfwd.sh"
readonly SHORTCUT_LINK="$INSTALL_DIR/pfwd"

# nftables names
readonly NFT_TABLE="inet port_forward"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'

# Quiet mode flag
QUIET=false

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
                    if [ "$fsize" -gt 1024 ]; then
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
                    if [ "$fsize" -gt 1024 ]; then
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
    LOCAL_HAS_IPV4=false
    LOCAL_HAS_IPV6=false
    LOCAL_IPV4=""
    LOCAL_IPV6=""
    LOCAL_IPV4_TYPE=""
    LOCAL_IPV6_TYPE=""

    # Detect IPv4
    LOCAL_IPV4=$(ip -4 addr show scope global 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1 | head -1) || true
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
    LOCAL_IPV6=$(ip -6 addr show scope global 2>/dev/null | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -1) || true
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
        if (( range_size > 100 )); then
            msg_err "Port range too large: $range_size ports (max 100)"
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
    if (( lcount > 500 )); then
        msg_err "Port range too large: $lcount ports (max 500)"
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

# _expand_triple_range <lspec> <target> <tspec> -> populates EXPANDED_RULES
# Expand ranges in legacy triple format: lspec:target:tspec
_expand_triple_range() {
    local lspec="$1" target="$2" tspec="$3"
    EXPANDED_RULES=()
    _expand_range_pair "$lspec" "$tspec" "$target"
}

# expand_rules <rule> -> populates EXPANDED_RULES
# Compatibility layer for old triple format with range support
# Detects ranges in lport:target:tport format, falls back to parse_rule for plain triples
expand_rules() {
    local rule="$1"
    EXPANDED_RULES=()

    # IPv6 bracket format: lspec:[ipv6]:tspec
    if [[ "$rule" =~ ^([0-9-]+):\[([^\]]+)\]:([0-9-]+)$ ]]; then
        local lspec="${BASH_REMATCH[1]}" target="${BASH_REMATCH[2]}" tspec="${BASH_REMATCH[3]}"
        if [[ "$lspec" == *-* || "$tspec" == *-* ]]; then
            _expand_triple_range "$lspec" "$target" "$tspec"
            return $?
        fi
        # No range, single rule
        EXPANDED_RULES=("$rule")
        return 0
    fi

    # Standard format: lspec:target:tspec (target may contain dots/colons for domain/ipv4)
    if [[ "$rule" =~ ^([0-9-]+):(.+):([0-9-]+)$ ]]; then
        local lspec="${BASH_REMATCH[1]}" target="${BASH_REMATCH[2]}" tspec="${BASH_REMATCH[3]}"
        if [[ "$lspec" == *-* || "$tspec" == *-* ]]; then
            _expand_triple_range "$lspec" "$target" "$tspec"
            return $?
        fi
        # No range, single rule
        EXPANDED_RULES=("$rule")
        return 0
    fi

    # lspec:target (no target port, same port as local) - with range support
    if [[ "$rule" =~ ^([0-9-]+):(.+)$ ]]; then
        local lspec="${BASH_REMATCH[1]}" target="${BASH_REMATCH[2]}"
        # Only if target looks like an address (not a port)
        if validate_target "$target" && [[ "$lspec" == *-* ]]; then
            _expand_triple_range "$lspec" "$target" "$lspec"
            return $?
        fi
    fi

    # No range detected, return as-is for parse_rule
    EXPANDED_RULES=("$rule")
    return 0
}

# format_bytes <bytes> -> human readable string
format_bytes() {
    local bytes="${1:-0}"
    [[ "$bytes" =~ ^[0-9]+$ ]] || { echo "0 B"; return; }
    if (( bytes < 1024 )); then
        echo "${bytes} B"
    elif (( bytes < 1048576 )); then
        awk "BEGIN{printf \"%.2f KB\", $bytes/1024}"
    elif (( bytes < 1073741824 )); then
        awk "BEGIN{printf \"%.2f MB\", $bytes/1048576}"
    else
        awk "BEGIN{printf \"%.2f GB\", $bytes/1073741824}"
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

#===============================================================================
#  Section 3: Kernel Optimization
#===============================================================================

optimize_kernel() {
    msg_info "Applying kernel optimizations..."

    local marker_start="# pfwd-managed-start"
    local marker_end="# pfwd-managed-end"

    # Remove old managed block if exists
    if [[ -f "$SYSCTL_CONF" ]]; then
        sed -i "/$marker_start/,/$marker_end/d" "$SYSCTL_CONF"
    fi

    mkdir -p "$(dirname "$SYSCTL_CONF")"

    cat >> "$SYSCTL_CONF" << EOF
$marker_start

# IP Forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# BBR Congestion Control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Optimization
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_early_retrans = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1

# Buffers (256MB)
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.ipv4.tcp_rmem = 8192 262144 268435456
net.ipv4.tcp_wmem = 8192 262144 268435456
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 65535

# Connection Tracking
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_loose = 1
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180

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

$marker_end
EOF

    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true

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

    msg_ok "Kernel optimizations applied"
    msg_dim "  IP forwarding: enabled"
    msg_dim "  BBR congestion control: enabled"
    msg_dim "  TCP fast open: enabled"
    msg_dim "  Conntrack max: 1048576"
    msg_dim "  Flowtable acceleration: via nftables"
}

#===============================================================================
#  Section 4: nftables Functions (with flowtable acceleration)
#===============================================================================

# nft_ensure_table - create table, chains, and flowtable if not exist
nft_ensure_table() {
    ensure_nft || return 1

    # Check if table already exists
    if nft list table $NFT_TABLE >/dev/null 2>&1; then
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

        # Try to create flowtable
        local ft_err
        if ft_err=$(nft add flowtable $NFT_TABLE ft "{ hook ingress priority 0; devices = { $nics }; }" 2>&1); then
            flowtable_ok=true
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

    # Input chain (for realm traffic counters)
    nft add chain $NFT_TABLE input '{ type filter hook input priority filter; policy accept; }'

    if $flowtable_ok; then
        msg_ok "nftables table created with flowtable acceleration"
    else
        msg_ok "nftables table created (without flowtable)"
    fi

    ensure_forward_accept
}

# ensure_forward_accept - add FORWARD ACCEPT rules if system firewall drops forwarded traffic
ensure_forward_accept() {
    # Check iptables FORWARD chain
    if command -v iptables >/dev/null 2>&1; then
        local policy
        policy=$(iptables -S FORWARD 2>/dev/null | awk '/-P FORWARD/{print $3}')
        if [[ "$policy" == "DROP" ]]; then
            iptables -C FORWARD -m conntrack --ctstate DNAT -j ACCEPT 2>/dev/null || \
                iptables -I FORWARD -m conntrack --ctstate DNAT -j ACCEPT
            iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
                iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
            msg_info "Added iptables FORWARD ACCEPT rules (DNAT + ESTABLISHED)"
        fi
    fi
    # Check ip6tables FORWARD chain
    if command -v ip6tables >/dev/null 2>&1; then
        local policy6
        policy6=$(ip6tables -S FORWARD 2>/dev/null | awk '/-P FORWARD/{print $3}')
        if [[ "$policy6" == "DROP" ]]; then
            ip6tables -C FORWARD -m conntrack --ctstate DNAT -j ACCEPT 2>/dev/null || \
                ip6tables -I FORWARD -m conntrack --ctstate DNAT -j ACCEPT
            ip6tables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
                ip6tables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
            msg_info "Added ip6tables FORWARD ACCEPT rules (DNAT + ESTABLISHED)"
        fi
    fi
}

# nft_rule_exists <lport> <proto> <ip_ver> -> 0=exists, 1=not found
nft_rule_exists() {
    local lport="$1" proto="$2" ip_ver="$3"
    local ip_match
    case "$ip_ver" in
        4)  ip_match="ip protocol $proto" ;;
        6)  ip_match="ip6 nexthdr $proto" ;;
        *)  return 1 ;;
    esac
    nft list chain $NFT_TABLE prerouting 2>/dev/null | grep -q "$ip_match.*dport $lport.*dnat"
}

# nft_add_rule <lport> <target> <tport> <ip_ver> <proto>
# ip_ver: 4, 6, or 46
# proto: tcp, udp, or both
nft_add_rule() {
    local lport="$1" target="$2" tport="$3" ip_ver="${4:-46}" proto="${5:-tcp}"

    nft_ensure_table || return 1

    # Check port availability
    if ! check_port_in_use "$lport" "$proto"; then
        msg_info "Cancelled"
        return 1
    fi

    local target_type
    target_type=$(detect_ip_type "$target")

    # Resolve domain to IP if needed
    local resolved_v4="" resolved_v6=""
    if [[ "$target_type" == "domain" ]]; then
        resolved_v4=$(getent ahosts "$target" 2>/dev/null | awk '/STREAM/{print $1}' | grep -E '^[0-9]+\.' | head -1 || true)
        resolved_v6=$(getent ahosts "$target" 2>/dev/null | awk '/STREAM/{print $1}' | grep ':' | head -1 || true)

        if [[ -z "$resolved_v4" && -z "$resolved_v6" ]]; then
            msg_err "Cannot resolve domain: $target"
            msg_err "Consider using realm for domain-based forwarding"
            return 1
        fi
        msg_dim "  Resolved $target -> ${resolved_v4:+IPv4:$resolved_v4 }${resolved_v6:+IPv6:$resolved_v6}"
    fi

    local protos=()
    case "$proto" in
        tcp)  protos=(tcp) ;;
        udp)  protos=(udp) ;;
        both) protos=(tcp udp) ;;
        *)    msg_err "Invalid protocol: $proto"; return 1 ;;
    esac

    local added=0

    for p in "${protos[@]}"; do
        # IPv4 rules
        if [[ "$ip_ver" == "4" || "$ip_ver" == "46" ]]; then
            local v4_target=""
            if [[ "$target_type" == "ipv4" ]]; then
                v4_target="$target"
            elif [[ "$target_type" == "domain" && -n "$resolved_v4" ]]; then
                v4_target="$resolved_v4"
            fi

            if [[ -n "$v4_target" ]]; then
                if nft_rule_exists "$lport" "$p" "4"; then
                    msg_info "Replacing existing IPv4 $p rule for port $lport"
                    nft_delete_port "$lport"
                fi
                if nft add rule $NFT_TABLE prerouting ip protocol "$p" "$p" dport "$lport" counter dnat ip to "$v4_target:$tport" 2>&1 && \
                   nft add rule $NFT_TABLE postrouting ip daddr "$v4_target" "$p" dport "$tport" counter masquerade 2>&1; then
                    msg_dim "  Added IPv4 $p :$lport -> $v4_target:$tport"
                    ((added++)) || true
                else
                    msg_err "Failed to add IPv4 $p rule :$lport -> $v4_target:$tport"
                    # Rollback: remove prerouting rule if it was added but postrouting failed
                    local rb_handle
                    rb_handle=$(nft -a list chain $NFT_TABLE prerouting 2>/dev/null | \
                        { grep -E "ip protocol $p.*dport $lport.*dnat ip to $v4_target:$tport" || true; } | \
                        awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }' | tail -1)
                    if [[ -n "$rb_handle" ]]; then
                        nft delete rule $NFT_TABLE prerouting handle "$rb_handle" 2>/dev/null
                        msg_dim "  Rolled back prerouting rule (handle $rb_handle)"
                    fi
                fi
            elif [[ "$ip_ver" == "4" ]]; then
                msg_warn "Target $target has no IPv4 address, skipping IPv4 $p rule"
            fi
        fi

        # IPv6 rules
        if [[ "$ip_ver" == "6" || "$ip_ver" == "46" ]]; then
            local v6_target=""
            if [[ "$target_type" == "ipv6" ]]; then
                v6_target="$target"
            elif [[ "$target_type" == "domain" && -n "$resolved_v6" ]]; then
                v6_target="$resolved_v6"
            fi

            if [[ -n "$v6_target" ]]; then
                if nft_rule_exists "$lport" "$p" "6"; then
                    msg_info "Replacing existing IPv6 $p rule for port $lport"
                    nft_delete_port "$lport"
                fi
                if nft add rule $NFT_TABLE prerouting ip6 nexthdr "$p" "$p" dport "$lport" counter dnat ip6 to "[$v6_target]:$tport" 2>&1 && \
                   nft add rule $NFT_TABLE postrouting ip6 daddr "$v6_target" "$p" dport "$tport" counter masquerade 2>&1; then
                    msg_dim "  Added IPv6 $p :$lport -> [$v6_target]:$tport"
                    ((added++)) || true
                else
                    msg_err "Failed to add IPv6 $p rule :$lport -> [$v6_target]:$tport"
                    # Rollback: remove prerouting rule if it was added but postrouting failed
                    local rb_handle6
                    rb_handle6=$(nft -a list chain $NFT_TABLE prerouting 2>/dev/null | \
                        { grep -E "ip6 nexthdr $p.*dport $lport.*dnat ip6 to \[$v6_target\]:$tport" || true; } | \
                        awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }' | tail -1)
                    if [[ -n "$rb_handle6" ]]; then
                        nft delete rule $NFT_TABLE prerouting handle "$rb_handle6" 2>/dev/null
                        msg_dim "  Rolled back prerouting rule (handle $rb_handle6)"
                    fi
                fi
            elif [[ "$ip_ver" == "6" ]]; then
                msg_warn "Target $target has no IPv6 address, skipping IPv6 $p rule"
            fi
        fi
    done

    if (( added == 0 )); then
        msg_err "No rules were added for :$lport -> $target:$tport"
        return 1
    fi

    nft_save
    nft_setup_persistence
    msg_ok "nftables rule added: :$lport -> $target:$tport ($proto, IPv$ip_ver)"
}

# nft_delete_port <port> - delete all rules matching this local port
nft_delete_port() {
    local port="$1"
    local proto="${2:-both}"  # Default: delete all protocols
    ensure_nft || return 1

    if ! nft list table $NFT_TABLE >/dev/null 2>&1; then
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
        local dnat_addr="" dnat_port=""
        # IPv4: dnat ip to 1.2.3.4:3389
        if [[ "$line" =~ dnat\ ip\ to\ ([0-9.]+):([0-9]+) ]]; then
            dnat_addr="${BASH_REMATCH[1]}"
            dnat_port="${BASH_REMATCH[2]}"
        # IPv6: dnat ip6 to [::1]:3389
        elif [[ "$line" =~ dnat\ ip6\ to\ \[([^\]]+)\]:([0-9]+) ]]; then
            dnat_addr="${BASH_REMATCH[1]}"
            dnat_port="${BASH_REMATCH[2]}"
        fi

        # Delete the prerouting rule
        nft delete rule $NFT_TABLE prerouting handle "$handle" 2>/dev/null && ((deleted++)) || true

        # Step 2: Delete matching postrouting masquerade rule using extracted target info
        if [[ -n "$dnat_addr" && -n "$dnat_port" ]]; then
            local post_handles
            post_handles=$(nft -a list chain $NFT_TABLE postrouting 2>/dev/null | \
                { grep -E "daddr $dnat_addr.*dport $dnat_port" || true; } | \
                awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }')
            for h in $post_handles; do
                nft delete rule $NFT_TABLE postrouting handle "$h" 2>/dev/null && ((deleted++)) || true
            done
        fi
    done <<< "$prerouting_lines"

    # Step 3: Delete input chain rules matching dport $port (with protocol filter)
    local input_handles
    case "$proto" in
        tcp)
            input_handles=$(nft -a list chain $NFT_TABLE input 2>/dev/null | \
                { grep -E "(ip protocol tcp|ip6 nexthdr tcp).*dport $port\b" || true; } | \
                awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }')
            ;;
        udp)
            input_handles=$(nft -a list chain $NFT_TABLE input 2>/dev/null | \
                { grep -E "(ip protocol udp|ip6 nexthdr udp).*dport $port\b" || true; } | \
                awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }')
            ;;
        both)
            input_handles=$(nft -a list chain $NFT_TABLE input 2>/dev/null | \
                { grep -E "dport $port\b" || true; } | \
                awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }')
            ;;
    esac
    for h in $input_handles; do
        nft delete rule $NFT_TABLE input handle "$h" 2>/dev/null && ((deleted++)) || true
    done

    if (( deleted > 0 )); then
        nft_save
        local proto_msg=""
        [[ "$proto" != "both" ]] && proto_msg=" ($proto)"
        msg_ok "Deleted $deleted nftables rule(s) for port $port$proto_msg"
    else
        msg_warn "No nftables rules found for port $port"
    fi
}

# nft_list_rules - display all forwarding rules in a table
nft_list_rules() {
    ensure_nft || return 1

    if ! nft list table $NFT_TABLE >/dev/null 2>&1; then
        msg_dim "  No nftables forwarding rules"
        return 0
    fi

    local rules
    rules=$(nft list chain $NFT_TABLE prerouting 2>/dev/null | grep "dnat" || true)

    if [[ -z "$rules" ]]; then
        msg_dim "  No nftables forwarding rules"
        return 0
    fi

    echo -e "${CYAN}nftables forwarding rules:${NC}"
    printf "  ${BOLD}%-8s %-6s %-6s %-30s %s${NC}\n" "L.Port" "Proto" "IPver" "Target" "Traffic"

    while IFS= read -r line; do
        local lport="" target="" proto="" ipver="" bytes=""

        # Extract protocol
        if [[ "$line" =~ "ip protocol tcp" ]]; then
            proto="tcp"; ipver="4"
        elif [[ "$line" =~ "ip protocol udp" ]]; then
            proto="udp"; ipver="4"
        elif [[ "$line" =~ "ip6 nexthdr tcp" ]]; then
            proto="tcp"; ipver="6"
        elif [[ "$line" =~ "ip6 nexthdr udp" ]]; then
            proto="udp"; ipver="6"
        fi

        # Extract local port
        if [[ "$line" =~ dport\ ([0-9]+) ]]; then
            lport="${BASH_REMATCH[1]}"
        fi

        # Extract target (IPv4 or IPv6)
        if [[ "$line" =~ dnat\ ip\ to\ ([^\ ]+) ]]; then
            target="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ dnat\ ip6\ to\ ([^\ ]+) ]]; then
            target="${BASH_REMATCH[1]}"
        fi

        # Extract traffic bytes
        if [[ "$line" =~ bytes\ ([0-9]+) ]]; then
            bytes="${BASH_REMATCH[1]}"
        fi

        local traffic
        traffic=$(format_bytes "${bytes:-0}")
        printf "  %-8s %-6s %-6s %-30s %s\n" ":$lport" "$proto" "IPv$ipver" "$target" "$traffic"
    done <<< "$rules"
}

# nft_get_traffic <port> - get traffic bytes for a port
nft_get_traffic() {
    local port="$1"
    local bytes
    bytes=$(nft list chain $NFT_TABLE prerouting 2>/dev/null | { grep -E "dport $port\b.*counter" || true; } | grep -oE 'bytes [0-9]+' | awk '{sum+=$2} END{print sum+0}')
    echo "${bytes:-0}"
}

# nft_save - persist rules to file
nft_save() {
    mkdir -p "$(dirname "$NFT_CONFIG")"
    nft list table $NFT_TABLE > "$NFT_CONFIG" 2>/dev/null || true

    # Dual backup: main config + backup directory
    local backup_dir="/root/.pfwd_backup"
    mkdir -p "$backup_dir"
    if [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]]; then
        cp "$NFT_CONFIG" "$backup_dir/nftables_$(date +%Y%m%d_%H%M%S).nft" 2>/dev/null || true
        # Keep last 5 backups
        ls -t "$backup_dir"/nftables_*.nft 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
    fi

    msg_dim "  Rules saved to $NFT_CONFIG (backup: $backup_dir)"
}

# nft_flush_all - delete entire table and config files
nft_flush_all() {
    nft delete table $NFT_TABLE 2>/dev/null || true
    rm -f "$NFT_CONFIG"
    rm -f "$NFT_RESTORE_SCRIPT"
    if [[ -f "$NFT_RESTORE_SERVICE" ]]; then
        systemctl disable pfwd-nft-restore 2>/dev/null || true
        rm -f "$NFT_RESTORE_SERVICE"
        systemctl daemon-reload 2>/dev/null || true
    fi
    msg_ok "nftables rules and persistence removed"
}

# nft_setup_persistence - create restore script + systemd service
nft_setup_persistence() {
    mkdir -p "$DATA_DIR"
    mkdir -p "$(dirname "$NFT_CONFIG")"

    # Save current rules
    nft list table $NFT_TABLE > "$NFT_CONFIG" 2>/dev/null || true

    # Create restore script
    cat > "$NFT_RESTORE_SCRIPT" << 'RESTORE_EOF'
#!/bin/bash
# pfwd nftables restore script
LOG="/var/log/pfwd-restore.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }

log "Restoring nftables rules..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null

NFT_CONFIG="/etc/nftables.d/port_forward.nft"
if [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]]; then
    nft delete table inet port_forward 2>/dev/null
    if nft -f "$NFT_CONFIG" 2>/dev/null; then
        log "Rules restored from $NFT_CONFIG"
    else
        log "Failed to restore rules from $NFT_CONFIG"
    fi
else
    log "No rules file found at $NFT_CONFIG"
fi
RESTORE_EOF
    chmod +x "$NFT_RESTORE_SCRIPT"

    # Create systemd service
    cat > "$NFT_RESTORE_SERVICE" << EOF
[Unit]
Description=pfwd nftables rules restore
After=network-online.target nftables.service systemd-sysctl.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$NFT_RESTORE_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload 2>/dev/null
    systemctl enable pfwd-nft-restore >/dev/null 2>&1 || true
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
        tar -xzf "$tmp_file" -C "$tmp_dir" 2>/dev/null
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
}

# realm_setup_service - create systemd service file
realm_setup_service() {
    mkdir -p "$REALM_CONFIG_DIR"

    cat > "$REALM_SERVICE" << EOF
[Unit]
Description=Realm Port Forward
After=network.target

[Service]
Type=simple
User=root
ExecStart=$REALM_BIN -c $REALM_CONFIG
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload 2>/dev/null
    systemctl enable realm-forward >/dev/null 2>&1 || true
}

# realm_ensure_config - create initial config if not exists
realm_ensure_config() {
    mkdir -p "$REALM_CONFIG_DIR"
    if [[ ! -f "$REALM_CONFIG" ]]; then
        cat > "$REALM_CONFIG" << 'EOF'
[log]
level = "warn"
output = "/var/log/realm.log"

[network]
no_tcp = false
use_udp = true
EOF
        msg_dim "  Created initial realm config"
    fi
}

# realm_add_endpoint <lport> <target> <tport> <ip_ver> [comment]
realm_add_endpoint() {
    local lport="$1" target="$2" tport="$3" ip_ver="${4:-46}" comment="${5:-}"

    if ! realm_is_installed; then
        msg_err "realm is not installed. Run: pfwd install"
        return 1
    fi

    realm_ensure_config

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

    realm_restart_service
    realm_setup_traffic_counter "$lport"
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

    # Also remove traffic counter rules from nft (with protocol filter)
    if nft list table $NFT_TABLE >/dev/null 2>&1; then
        local handles
        case "$proto" in
            tcp)
                handles=$(nft -a list chain $NFT_TABLE input 2>/dev/null | \
                    { grep -E "(ip protocol tcp|ip6 nexthdr tcp).*dport $port\b" || true; } | \
                    awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }')
                ;;
            udp)
                handles=$(nft -a list chain $NFT_TABLE input 2>/dev/null | \
                    { grep -E "(ip protocol udp|ip6 nexthdr udp).*dport $port\b" || true; } | \
                    awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }')
                ;;
            both)
                handles=$(nft -a list chain $NFT_TABLE input 2>/dev/null | \
                    { grep -E "dport $port\b" || true; } | \
                    awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }')
                ;;
        esac
        for h in $handles; do
            nft delete rule $NFT_TABLE input handle "$h" 2>/dev/null
        done
    fi

    realm_restart_service
    local proto_msg=""
    [[ "$proto" != "both" ]] && proto_msg=" ($proto)"
    msg_ok "realm endpoint deleted for port $port$proto_msg"
}

# realm_list_endpoints - display realm endpoints
realm_list_endpoints() {
    if [[ ! -f "$REALM_CONFIG" ]]; then
        msg_dim "  No realm config found"
        return 0
    fi

    local endpoints
    endpoints=$(awk '
    BEGIN { listen=""; remote=""; comment="" }
    /^# / { comment=$0; sub(/^# /, "", comment); next }
    /^\[\[endpoints\]\]/ { listen=""; remote=""; next }
    /^listen/ {
        match($0, /"([^"]+)"/, m)
        if (RSTART) listen=m[1]
        next
    }
    /^remote/ {
        match($0, /"([^"]+)"/, m)
        if (RSTART) remote=m[1]
        if (listen != "" && remote != "") {
            printf "%s|%s|%s\n", listen, remote, comment
        }
        comment=""
        next
    }
    { comment="" }
    ' "$REALM_CONFIG" 2>/dev/null)

    if [[ -z "$endpoints" ]]; then
        msg_dim "  No realm endpoints configured"
        return 0
    fi

    echo -e "${CYAN}realm forwarding endpoints:${NC}"
    local svc_status
    if systemctl is-active realm-forward >/dev/null 2>&1; then
        svc_status="${GREEN}running${NC}"
    else
        svc_status="${RED}stopped${NC}"
    fi
    echo -e "  Service: $svc_status"
    printf "  ${BOLD}%-25s %-30s %-15s %s${NC}\n" "Listen" "Remote" "Comment" "Traffic"

    while IFS='|' read -r listen remote comment; do
        # Extract port from listen address
        local lport
        lport="${listen##*:}"

        local traffic_bytes=0
        if nft list table $NFT_TABLE >/dev/null 2>&1; then
            traffic_bytes=$(nft list chain $NFT_TABLE input 2>/dev/null | { grep -E "dport $lport\b.*counter" || true; } | grep -oE 'bytes [0-9]+' | awk '{sum+=$2} END{print sum+0}')
        fi
        local traffic
        traffic=$(format_bytes "${traffic_bytes:-0}")

        printf "  %-25s %-30s %-15s %s\n" "$listen" "$remote" "${comment:--}" "$traffic"
    done <<< "$endpoints"
}

# realm_restart_service - restart realm service
realm_restart_service() {
    if [[ ! -f "$REALM_SERVICE" ]]; then
        realm_setup_service
    fi
    systemctl restart realm-forward 2>/dev/null || true
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
    if nft list chain $NFT_TABLE input 2>/dev/null | grep -qE "dport $port\b"; then
        return 0
    fi

    nft add rule $NFT_TABLE input tcp dport "$port" counter 2>/dev/null || true
    nft add rule $NFT_TABLE input udp dport "$port" counter 2>/dev/null || true
    nft_save 2>/dev/null || true
}

#===============================================================================
#  Section 6: Traffic Statistics
#===============================================================================

show_traffic_stats() {
    echo -e "${BOLD}Traffic Statistics${NC}"
    echo -e "${DIM}$(printf '=%.0s' {1..60})${NC}"

    local has_rules=false

    # nftables prerouting traffic
    if nft list table $NFT_TABLE >/dev/null 2>&1; then
        local nft_rules
        nft_rules=$(nft list chain $NFT_TABLE prerouting 2>/dev/null | grep "dnat" || true)

        if [[ -n "$nft_rules" ]]; then
            has_rules=true
            echo -e "\n${CYAN}nftables forwarding:${NC}"
            printf "  ${BOLD}%-8s %-6s %-6s %-25s %s${NC}\n" "L.Port" "Proto" "IPver" "Target" "Traffic"

            while IFS= read -r line; do
                local lport="" target="" proto="" ipver="" bytes=""

                if [[ "$line" =~ "ip protocol tcp" ]]; then proto="tcp"; ipver="4"
                elif [[ "$line" =~ "ip protocol udp" ]]; then proto="udp"; ipver="4"
                elif [[ "$line" =~ "ip6 nexthdr tcp" ]]; then proto="tcp"; ipver="6"
                elif [[ "$line" =~ "ip6 nexthdr udp" ]]; then proto="udp"; ipver="6"
                fi

                [[ "$line" =~ dport\ ([0-9]+) ]] && lport="${BASH_REMATCH[1]}"

                if [[ "$line" =~ dnat\ ip\ to\ ([^\ ]+) ]]; then target="${BASH_REMATCH[1]}"
                elif [[ "$line" =~ dnat\ ip6\ to\ ([^\ ]+) ]]; then target="${BASH_REMATCH[1]}"
                fi

                [[ "$line" =~ bytes\ ([0-9]+) ]] && bytes="${BASH_REMATCH[1]}"

                local traffic
                traffic=$(format_bytes "${bytes:-0}")
                printf "  %-8s %-6s %-6s %-25s %s\n" ":$lport" "$proto" "IPv$ipver" "$target" "$traffic"
            done <<< "$nft_rules"
        fi
    fi

    # realm input chain traffic
    if [[ -f "$REALM_CONFIG" ]] && nft list table $NFT_TABLE >/dev/null 2>&1; then
        local input_rules
        input_rules=$(nft list chain $NFT_TABLE input 2>/dev/null | awk '/counter/ && /dport/' || true)

        if [[ -n "$input_rules" ]]; then
            has_rules=true
            echo -e "\n${CYAN}realm traffic:${NC}"
            printf "  ${BOLD}%-8s %-6s %s${NC}\n" "L.Port" "Proto" "Traffic"

            while IFS= read -r line; do
                local lport="" proto="" bytes=""

                if [[ "$line" =~ "tcp dport" ]]; then proto="tcp"
                elif [[ "$line" =~ "udp dport" ]]; then proto="udp"
                fi

                [[ "$line" =~ dport\ ([0-9]+) ]] && lport="${BASH_REMATCH[1]}"
                [[ "$line" =~ bytes\ ([0-9]+) ]] && bytes="${BASH_REMATCH[1]}"

                local traffic
                traffic=$(format_bytes "${bytes:-0}")
                printf "  %-8s %-6s %s\n" ":$lport" "$proto" "$traffic"
            done <<< "$input_rules"
        fi
    fi

    if ! $has_rules; then
        msg_dim "  No forwarding rules found"
    fi
}

#===============================================================================
#  Section 7: Backup / Import / Export
#===============================================================================

# cmd_export [filepath] - export all rules to JSON
cmd_export() {
    local filepath="${1:-$DATA_DIR/backup_$(date '+%Y%m%d_%H%M%S').json}"

    ensure_jq || return 1
    mkdir -p "$(dirname "$filepath")"

    local export_data
    export_data=$(jq -n \
        --arg version "$VERSION" \
        --arg tool "pfwd" \
        --arg export_time "$(date '+%Y-%m-%dT%H:%M:%S')" \
        --arg source_ip "$(get_local_ip)" \
        '{
            export_info: {
                version: $version,
                tool: $tool,
                export_time: $export_time,
                source_ip: $source_ip
            },
            forward_rules: []
        }')

    # Collect nftables rules
    if nft list table $NFT_TABLE >/dev/null 2>&1; then
        local nft_rules
        nft_rules=$(nft list chain $NFT_TABLE prerouting 2>/dev/null | grep "dnat" || true)

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local lport="" target="" tport="" proto="" ipver=""

            if [[ "$line" =~ "ip protocol tcp" ]]; then proto="tcp"; ipver="4"
            elif [[ "$line" =~ "ip protocol udp" ]]; then proto="udp"; ipver="4"
            elif [[ "$line" =~ "ip6 nexthdr tcp" ]]; then proto="tcp"; ipver="6"
            elif [[ "$line" =~ "ip6 nexthdr udp" ]]; then proto="udp"; ipver="6"
            fi

            [[ "$line" =~ dport\ ([0-9]+) ]] && lport="${BASH_REMATCH[1]}"

            if [[ "$line" =~ dnat\ ip\ to\ ([0-9.]+):([0-9]+) ]]; then
                target="${BASH_REMATCH[1]}"
                tport="${BASH_REMATCH[2]}"
            elif [[ "$line" =~ dnat\ ip6\ to\ \[([^\]]+)\]:([0-9]+) ]]; then
                target="${BASH_REMATCH[1]}"
                tport="${BASH_REMATCH[2]}"
            fi

            if [[ -n "$lport" && -n "$target" && -n "$tport" ]]; then
                export_data=$(echo "$export_data" | jq \
                    --arg type "nftables" \
                    --arg local_port "$lport" \
                    --arg target_ip "$target" \
                    --arg target_port "$tport" \
                    --arg protocol "$proto" \
                    --arg ip_ver "$ipver" \
                    '.forward_rules += [{
                        type: $type,
                        local_port: $local_port,
                        target_ip: $target_ip,
                        target_port: $target_port,
                        protocol: $protocol,
                        ip_ver: $ip_ver
                    }]')
            fi
        done <<< "$nft_rules"
    fi

    # Collect realm endpoints
    if [[ -f "$REALM_CONFIG" ]]; then
        local realm_data
        realm_data=$(awk '
        BEGIN { listen=""; remote=""; comment="" }
        /^# / { comment=$0; sub(/^# /, "", comment); next }
        /^\[\[endpoints\]\]/ { listen=""; remote=""; next }
        /^listen/ {
            match($0, /"([^"]+)"/, m)
            if (RSTART) listen=m[1]
            next
        }
        /^remote/ {
            match($0, /"([^"]+)"/, m)
            if (RSTART) remote=m[1]
            if (listen != "" && remote != "") {
                # Determine ip_ver from listen address
                ip_ver="46"
                if (listen ~ /^0\.0\.0\.0:/) ip_ver="4"
                if (listen ~ /^\[::]:/) ip_ver="46"
                # Extract port from listen
                split(listen, la, ":")
                lport = la[length(la)]
                # Extract target and port from remote
                if (remote ~ /^\[/) {
                    # IPv6 remote [addr]:port
                    match(remote, /\[([^\]]+)\]:([0-9]+)/, rm)
                    if (RSTART) {
                        printf "%s|%s|%s|%s|%s\n", lport, rm[1], rm[2], ip_ver, comment
                    }
                } else {
                    # IPv4/domain remote addr:port
                    n = split(remote, ra, ":")
                    tport = ra[n]
                    target = remote
                    sub(":"tport"$", "", target)
                    printf "%s|%s|%s|%s|%s\n", lport, target, tport, ip_ver, comment
                }
            }
            comment=""
            next
        }
        { comment="" }
        ' "$REALM_CONFIG" 2>/dev/null)

        while IFS='|' read -r lport target tport ipver comment; do
            [[ -z "$lport" ]] && continue
            export_data=$(echo "$export_data" | jq \
                --arg type "realm" \
                --arg local_port "$lport" \
                --arg target_ip "$target" \
                --arg target_port "$tport" \
                --arg ip_ver "$ipver" \
                --arg comment "$comment" \
                '.forward_rules += [{
                    type: $type,
                    local_port: $local_port,
                    target_ip: $target_ip,
                    target_port: $target_port,
                    ip_ver: $ip_ver,
                    comment: $comment
                }]')
        done <<< "$realm_data"
    fi

    echo "$export_data" | jq '.' > "$filepath"
    msg_ok "Exported to: $filepath"

    local count
    count=$(echo "$export_data" | jq '.forward_rules | length')
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

    while IFS= read -r rule; do
        local rtype lport target tport proto ipver comment
        rtype=$(echo "$rule" | jq -r '.type')
        lport=$(echo "$rule" | jq -r '.local_port')
        target=$(echo "$rule" | jq -r '.target_ip')
        tport=$(echo "$rule" | jq -r '.target_port')
        proto=$(echo "$rule" | jq -r '.protocol // "tcp"')
        ipver=$(echo "$rule" | jq -r '.ip_ver // "46"')
        comment=$(echo "$rule" | jq -r '.comment // ""')

        # Override method if specified
        local method="$rtype"
        [[ -n "$override_method" ]] && method="$override_method"

        case "$method" in
            nftables|nft)
                if nft_add_rule "$lport" "$target" "$tport" "$ipver" "$proto"; then
                    ((imported++)) || true
                else
                    msg_warn "Failed to import nft rule :$lport -> $target:$tport"
                    ((failed++)) || true
                fi
                ;;
            realm)
                if realm_add_endpoint "$lport" "$target" "$tport" "$ipver" "$comment"; then
                    ((imported++)) || true
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
    done < <(jq -c '.forward_rules[]' "$filepath")

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
    cat << 'EOF'
pfwd - Port Forwarding Tool

Usage: pfwd [command] [options] [rules...]

Commands:
  (none/add)  Add forwarding rules (default)
  del         Delete forwarding rules
  list        List all forwarding rules
  start       Start forwarding (nft / realm / all)
  stop        Stop forwarding (nft / realm / all)
  restart     Restart forwarding (nft / realm / all)
  stats       Traffic statistics
  export      Export config to JSON
  import      Import config from JSON
  install     Install realm binary
  uninstall   Uninstall (realm / nftables / all)
  optimize    Run kernel optimization only
  help        Show this help

Add rules (new syntax):
  pfwd -m nft|realm -t <target> [options] <ports>

Add rules (legacy syntax):
  pfwd -m nft|realm [options] local_port:target:target_port[,...]

Options:
  -m, --method <nft|realm>   Forwarding method (required)
  -t, --target <addr>        Target IP or domain (enables new syntax)
  -4                         IPv4 only
  -6                         IPv6 only
  -46                        Dual-stack (default)
  --tcp                      TCP only (default)
  --udp                      UDP only
  --both                     TCP + UDP
  -c, --comment <text>       Comment (realm only)
  -q, --quiet                Quiet mode

Port formats (with -t):
  Single port:    80
  Multiple ports: 80,443
  Port range:     8080-8090
  Port mapping:   33389:3389
  Range mapping:  8080-8090:3080-3090
  Mixed:          80,443,8080-8090,33389:3389

Backup/Import/Export:
  pfwd export [filepath]
  pfwd import <filepath> [-m nft|realm]
  pfwd import --url <URL> [-m nft|realm]

Examples (new syntax):
  pfwd -m nft -t 1.2.3.4 80,443,8080-8090
  pfwd -m nft -t 1.2.3.4 -4 --both 80 443 8080-8090
  pfwd -m realm -t example.com 80,443 -c "web"
  pfwd -m nft -t 1.2.3.4 33389:3389

Examples (legacy syntax):
  pfwd -m nft -4 --both 3389:1.2.3.4:3389
  pfwd -m nft 8080-8090:1.2.3.4:3080-3090
  pfwd -m realm -46 3389:example.com:3389,10281:example.com:10281

Other:
  pfwd del -m nft 3389
  pfwd del -m nft --tcp 8080
  pfwd del -m nft --udp 8080
  pfwd del -m nft 8080-8088
  pfwd del -m nft 80,443,8080-8082
  pfwd del -m realm 3389
  pfwd list
  pfwd stats
  pfwd export ~/backup.json
  pfwd import ~/backup.json -m nft

Delete options:
  pfwd del -m <method> [--tcp|--udp|--both] <port|port-range|port1,port2,...>
      Delete forwarding rule(s)

      Options:
        -m, --method <nft|realm>  Forwarding method
        --tcp                     Delete only TCP rules
        --udp                     Delete only UDP rules
        --both                    Delete both TCP and UDP rules (default)

      Examples:
        pfwd del -m nft 3389                    # Delete all rules for port 3389
        pfwd del -m nft --tcp 8080             # Delete only TCP rule for 8080
        pfwd del -m nft --udp 8080             # Delete only UDP rule for 8080
        pfwd del -m nft 8080-8088             # Delete ports 8080 and 8088
        pfwd del -m nft 80,443,8080-8082        # Delete multiple ports and ranges
EOF
}

# cmd_add - add forwarding rules from CLI
cmd_add() {
    local method="" ip_ver="46" proto="tcp" comment="" target="" rules_str=""
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
        msg_err "No rules specified"
        msg_err "Format: local_port:target:target_port  or  -t <target> <ports>"
        return 1
    fi

    # Ensure kernel forwarding is on
    optimize_kernel 2>/dev/null || true

    local added=0 failed=0

    if [[ -n "$target" ]]; then
        # New syntax: -t <target> <port_spec>
        if ! validate_target "$target"; then
            msg_err "Invalid target: $target"
            return 1
        fi
        if ! expand_port_spec "$rules_str" "$target"; then
            return 1
        fi
        for expanded in "${EXPANDED_RULES[@]}"; do
            if ! parse_rule "$expanded"; then
                ((failed++)) || true; continue
            fi
            case "$method" in
                nft|nftables)
                    if nft_add_rule "$RULE_LPORT" "$RULE_TARGET" "$RULE_TPORT" "$ip_ver" "$proto"; then
                        ((added++)) || true
                    else
                        ((failed++)) || true
                    fi
                    ;;
                realm)
                    if realm_add_endpoint "$RULE_LPORT" "$RULE_TARGET" "$RULE_TPORT" "$ip_ver" "$comment"; then
                        ((added++)) || true
                    else
                        ((failed++)) || true
                    fi
                    ;;
                *)
                    msg_err "Unknown method: $method (use nft or realm)"
                    return 1
                    ;;
            esac
        done
    else
        # Legacy syntax: lport:target:tport[,...]
        IFS=',' read -ra rules_arr <<< "$rules_str"
        for rule in "${rules_arr[@]}"; do
            if ! expand_rules "$rule"; then
                ((failed++)) || true; continue
            fi
            for expanded in "${EXPANDED_RULES[@]}"; do
                if ! parse_rule "$expanded"; then
                    ((failed++)) || true; continue
                fi
                case "$method" in
                    nft|nftables)
                        if nft_add_rule "$RULE_LPORT" "$RULE_TARGET" "$RULE_TPORT" "$ip_ver" "$proto"; then
                            ((added++)) || true
                        else
                            ((failed++)) || true
                        fi
                        ;;
                    realm)
                        if realm_add_endpoint "$RULE_LPORT" "$RULE_TARGET" "$RULE_TPORT" "$ip_ver" "$comment"; then
                            ((added++)) || true
                        else
                            ((failed++)) || true
                        fi
                        ;;
                    *)
                        msg_err "Unknown method: $method (use nft or realm)"
                        return 1
                        ;;
                esac
            done
        done
    fi

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
    IFS=',' read -ra port_specs <<< "$ports_str"
    local all_ports=()

    for spec in "${port_specs[@]}"; do
        spec="${spec//[[:space:]]/}"  # Remove whitespace
        [[ -z "$spec" ]] && continue
        # Expand port range
        local expanded
        if ! expanded=$(expand_port_range "$spec"); then
            continue
        fi
        all_ports+=($expanded)
    done

    if (( ${#all_ports[@]} == 0 )); then
        msg_err "No valid ports found"
        return 1
    fi

    # Delete ports
    for port in "${all_ports[@]}"; do
        case "$method" in
            nft|nftables)
                nft_delete_port "$port" "$proto"
                ;;
            realm)
                realm_delete_endpoint "$port" "$proto"
                ;;
            *)
                msg_err "Unknown method: $method"
                return 1
                ;;
        esac
    done
}

# cmd_list - list all forwarding rules
cmd_list() {
    echo -e "${BOLD}Forwarding Rules${NC}"
    echo -e "${DIM}$(printf '=%.0s' {1..60})${NC}"
    echo ""
    nft_list_rules
    echo ""
    realm_list_endpoints
}

# cmd_stop - stop forwarding without removing config
cmd_stop() {
    local target="${1:-all}"
    case "$target" in
        nft|nftables)
            if nft list table $NFT_TABLE >/dev/null 2>&1; then
                nft_setup_persistence
                nft delete table $NFT_TABLE 2>/dev/null || true
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
            if nft list table $NFT_TABLE >/dev/null 2>&1; then
                msg_warn "nftables forwarding is already running"
                return 0
            fi
            if [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]]; then
                nft -f "$NFT_CONFIG" 2>/dev/null
                if nft list table $NFT_TABLE >/dev/null 2>&1; then
                    local _restored_count
                    _restored_count=$(nft list chain $NFT_TABLE prerouting 2>/dev/null | grep -c 'dnat') || _restored_count=0
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
            cmd_list
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
            show_traffic_stats
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
            optimize_kernel
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
    clear 2>/dev/null || true

    # Count rules (cache nft output to avoid duplicate calls)
    local nft_count=0
    local _nft_prerouting=""
    if _nft_prerouting=$(nft list chain $NFT_TABLE prerouting 2>/dev/null); then
        nft_count=$(echo "$_nft_prerouting" | grep -c 'dnat') || nft_count=0
    fi
    local realm_count=0
    if [[ -f "$REALM_CONFIG" ]]; then
        realm_count=$(grep -c '^\[\[endpoints\]\]' "$REALM_CONFIG" 2>/dev/null) || realm_count=0
    fi
    local rule_count=$((nft_count + realm_count))

    # Check running status
    local status_text
    if [[ $nft_count -gt 0 ]] || systemctl is-active realm-forward >/dev/null 2>&1; then
        status_text="${GREEN}Running${NC}"
    else
        status_text="${RED}Stopped${NC}"
    fi

    # Detect network
    detect_local_network
    local net_info=""
    if $LOCAL_HAS_IPV4 && $LOCAL_HAS_IPV6; then
        local v4_label="${GREEN}IPv4${NC}"
        local v6_label="${GREEN}IPv6${NC}"
        [[ "$LOCAL_IPV4_TYPE" == "private" ]] && v4_label="${YELLOW}IPv4(private)${NC}"
        [[ "$LOCAL_IPV6_TYPE" == "private" ]] && v6_label="${YELLOW}IPv6(private)${NC}"
        [[ "$LOCAL_IPV4_TYPE" == "public" ]] && v4_label="${GREEN}IPv4(public)${NC}"
        [[ "$LOCAL_IPV6_TYPE" == "public" ]] && v6_label="${GREEN}IPv6(public)${NC}"
        net_info="${v4_label} + ${v6_label}"
    elif $LOCAL_HAS_IPV4; then
        if [[ "$LOCAL_IPV4_TYPE" == "private" ]]; then
            net_info="${YELLOW}IPv4(private)${NC}"
        else
            net_info="${GREEN}IPv4(public)${NC}"
        fi
    elif $LOCAL_HAS_IPV6; then
        if [[ "$LOCAL_IPV6_TYPE" == "private" ]]; then
            net_info="${YELLOW}IPv6(private)${NC}"
        else
            net_info="${CYAN}IPv6(public)${NC}"
        fi
    else
        net_info="${RED}No public IP${NC}"
    fi

    echo ""
    echo -e "${CYAN}================================================${NC}"
    echo -e "     ${BOLD}pfwd${NC} - Port Forwarding Tool  ${DIM}v$VERSION${NC}"
    echo -e "${CYAN}------------------------------------------------${NC}"
    echo -e "  Status: ${status_text}    Rules: ${CYAN}${rule_count}${NC}    Network: ${net_info}"
    echo -e "${CYAN}================================================${NC}"
    echo ""
}

interactive_menu() {
    while true; do
        show_header

        # Determine forwarding status for menu item 4
        local _nft_running=false _realm_running=false
        nft list table $NFT_TABLE >/dev/null 2>&1 && _nft_running=true
        systemctl is-active realm-forward >/dev/null 2>&1 && _realm_running=true
        local _fwd_label
        if $_nft_running || $_realm_running; then
            _fwd_label="Stop forwarding"
        else
            _fwd_label="Start forwarding"
        fi

        echo -e "  ${BOLD}1)${NC} Add forwarding rules"
        echo -e "  ${BOLD}2)${NC} View forwarding rules"
        echo -e "  ${BOLD}3)${NC} Delete forwarding rules"
        echo -e "  ${BOLD}4)${NC} ${_fwd_label}"
        echo -e "  ${BOLD}5)${NC} Traffic statistics"
        echo -e "  ${BOLD}6)${NC} Import/Export config"
        echo -e "  ${BOLD}7)${NC} Install/Update realm"
        echo -e "  ${BOLD}8)${NC} Kernel optimization"
        echo -e "  ${BOLD}9)${NC} Uninstall"
        echo -e "  ${BOLD}0)${NC} Exit"
        echo ""
        read -rp "Select [0-9]: " choice

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
            6) menu_export_import || true ;;
            7) realm_install; wait_for_enter ;;
            8) optimize_kernel; wait_for_enter ;;
            9) menu_uninstall || true ;;
            0) echo "Bye."; exit 0 ;;
            *) msg_warn "Invalid choice"; sleep 1.5 ;;
        esac
    done
}

# menu_add_rule - interactive rule addition
menu_add_rule() {
    echo ""
    echo -e "${BOLD}Add Forwarding Rule${NC}"
    echo -e "${DIM}$(printf -- '-%.0s' {1..40})${NC}"

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

    # 6. Comment (realm only)
    local comment=""
    if [[ "$method" == "realm" ]]; then
        echo ""
        read -rp "Comment (optional): " comment
    fi

    # 7. Confirmation summary
    echo ""
    echo -e "${BOLD}=== Confirmation ===${NC}"
    echo -e "  Method:   ${CYAN}${method}${NC}"
    echo -e "  IP ver:   ${CYAN}${ip_ver}${NC}"
    [[ "$method" == "nft" ]] && echo -e "  Protocol: ${CYAN}${proto}${NC}"
    echo -e "  Target:   ${CYAN}${target}${NC}"
    echo -e "  Ports:    ${CYAN}${port_spec}${NC}"
    [[ -n "$comment" ]] && echo -e "  Comment:  ${CYAN}${comment}${NC}"
    echo ""
    read -rp "Proceed? [Y/n]: " confirm
    confirm=${confirm:-Y}
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        msg_info "Cancelled"
        return
    fi

    # 8. Expand and add rules
    echo ""
    msg_info "Processing rules..."

    # Ensure kernel optimization
    optimize_kernel 2>/dev/null || true

    if ! expand_port_spec "$port_spec" "$target"; then
        msg_err "Failed to expand port spec"
        wait_for_enter
        return
    fi

    local added=0 failed=0
    for expanded in "${EXPANDED_RULES[@]}"; do
        if ! parse_rule "$expanded"; then
            ((failed++)) || true; continue
        fi

        case "$method" in
            nft)
                if nft_add_rule "$RULE_LPORT" "$RULE_TARGET" "$RULE_TPORT" "$ip_ver" "$proto"; then
                    ((added++)) || true
                else
                    ((failed++)) || true
                fi
                ;;
            realm)
                if realm_add_endpoint "$RULE_LPORT" "$RULE_TARGET" "$RULE_TPORT" "$ip_ver" "$comment"; then
                    ((added++)) || true
                else
                    ((failed++)) || true
                fi
                ;;
        esac
    done

    # 9. Summary
    echo ""
    msg_info "Result: $added rules added, $failed failed"
    wait_for_enter
}

# menu_delete_rule - interactive rule deletion
menu_delete_rule() {
    echo ""
    echo -e "${BOLD}Delete Forwarding Rule${NC}"
    echo -e "${DIM}$(printf -- '-%.0s' {1..40})${NC}"

    # Show current rules first
    cmd_list
    echo ""

    # Method selection
    echo "  1) nftables"
    echo "  2) realm"
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

    # Protocol selection (nftables only)
    local proto="both"
    if [[ "$method" == "nft" ]]; then
        echo ""
        echo "  1) TCP only"
        echo "  2) UDP only"
        echo "  3) Both TCP and UDP (default)"
        echo "  0) Back"
        echo ""
        read -rp "Protocol [3]: " proto_choice
        proto_choice=${proto_choice:-3}

        case "$proto_choice" in
            1) proto="tcp" ;;
            2) proto="udp" ;;
            3) proto="both" ;;
            0) return ;;
            *) proto="both" ;;
        esac
    fi

    echo ""
    echo "Enter port(s) to delete (comma-separated, ranges supported, empty to cancel)"
    echo -e "  ${DIM}Examples: 80  or  80,443  or  8080-8090  or  80,8080-8090${NC}"
    read -rp "Port(s): " ports_str

    if [[ -z "$ports_str" ]]; then
        msg_info "Cancelled"
        return
    fi

    # Parse port list (comma-separated, with range support)
    IFS=',' read -ra port_specs <<< "$ports_str"
    local all_ports=()

    for spec in "${port_specs[@]}"; do
        spec="${spec//[[:space:]]/}"  # Remove whitespace
        [[ -z "$spec" ]] && continue
        # Expand port range
        local expanded
        if ! expanded=$(expand_port_range "$spec"); then
            continue
        fi
        all_ports+=($expanded)
    done

    # Delete ports
    for port in "${all_ports[@]}"; do
        case "$method" in
            nft)   nft_delete_port "$port" "$proto" ;;
            realm) realm_delete_endpoint "$port" "$proto" ;;
        esac
    done

    wait_for_enter
}

# menu_export_import - interactive import/export
menu_export_import() {
    echo ""
    echo -e "${BOLD}Import / Export Configuration${NC}"
    echo -e "${DIM}$(printf -- '-%.0s' {1..40})${NC}"
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
    echo -e "${DIM}$(printf -- '-%.0s' {1..40})${NC}"
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
    echo -e "${DIM}$(printf -- '-%.0s' {1..40})${NC}"
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
    echo -e "${DIM}$(printf -- '-%.0s' {1..40})${NC}"
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
