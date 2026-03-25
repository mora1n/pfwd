#!/bin/bash
#===============================================================================
#  pfwd - Port Forwarding Tool
#
#  Method: nftables
#  Features: CLI + Interactive / IPv4/IPv6 manual control / Traffic stats
#            / Boot persistence / Backup import/export / Kernel optimization
#
#  License: MIT
#===============================================================================

set -euo pipefail

#===============================================================================
#  Section 1: Constants, Platform Adapters & Serialization
#===============================================================================

readonly VERSION="2.1.0"

pfwd_path() {
    local path="$1"
    local prefix="${PFWD_ROOT_PREFIX:-}"
    if [[ -z "$prefix" ]]; then
        printf '%s\n' "$path"
        return 0
    fi
    prefix="${prefix%/}"
    if [[ "$path" == "/" ]]; then
        printf '%s\n' "$prefix"
    else
        printf '%s%s\n' "$prefix" "$path"
    fi
}

# Paths
readonly DATA_DIR="$(pfwd_path /var/lib/pfwd)"
readonly RULES_STATE_FILE="$DATA_DIR/rules.v1.tsv"
readonly NFT_CONFIG="$(pfwd_path /etc/nftables.d/port_forward.nft)"
readonly NFT_BACKUP_DIR="$(pfwd_path /root/.pfwd_backup)"
readonly NFT_RESTORE_SERVICE="$(pfwd_path /etc/systemd/system/pfwd-nft-restore.service)"
readonly SYSCTL_CONF="$(pfwd_path /etc/sysctl.d/99-pfwd.conf)"
readonly UFW_BEFORE_RULES="$(pfwd_path /etc/ufw/before.rules)"
readonly UFW_BEFORE6_RULES="$(pfwd_path /etc/ufw/before6.rules)"
readonly TRAFFIC_DATA="$DATA_DIR/traffic_stats.dat"
readonly TRAFFIC_FLOW_DATA="$DATA_DIR/traffic_flows.dat"
readonly TRAFFIC_SAVE_SERVICE="$(pfwd_path /etc/systemd/system/pfwd-traffic-save.service)"
readonly TRAFFIC_SAVE_TIMER="$(pfwd_path /etc/systemd/system/pfwd-traffic-save.timer)"
readonly TRAFFIC_DEFAULT_INTERVAL="1m"
readonly TRAFFIC_DATA_VERSION="4"
readonly TRAFFIC_FLOW_VERSION="2"
readonly EXPORT_FORMAT_VERSION="3"
readonly TRAFFIC_STALE_MULTIPLIER="3"
readonly REQUIREMENTS_NOTICE_VERSION="1"

readonly INSTALLED_SCRIPT="$(pfwd_path /usr/local/bin/pfwd.sh)"
readonly SHORTCUT_LINK="$(pfwd_path /usr/local/bin/pfwd)"
readonly NF_FLOW_TABLE_MODULES_CONF="$(pfwd_path /etc/modules-load.d/nf_flow_table.conf)"

# nftables names
readonly NFT_TABLE="inet port_forward"
readonly IPTABLES_FWD_DNAT_COMMENT="pfwd-managed forward dnat"
readonly IPTABLES_FWD_EST_COMMENT="pfwd-managed forward established"
readonly IPTABLES_INPUT_DNAT_COMMENT="pfwd-managed input dnat"

# Colors (use $'...' so escape chars are real, works with echo -e and read -rp)
reset_colors() {
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[1;33m'
    BLUE=$'\033[0;34m'
    CYAN=$'\033[0;36m'
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    NC=$'\033[0m'
}

reset_colors

# disable_colors - strip all color codes
disable_colors() {
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
}

init_runtime_flags() {
    local arg
    reset_colors
    _NO_CLEAR=false
    PFWD_MAIN_ARGS=()
    for arg in "$@"; do
        case "$arg" in
            --no-color) disable_colors ;;
            --no-clear) _NO_CLEAR=true ;;
            *) PFWD_MAIN_ARGS+=("$arg") ;;
        esac
    done
}

# Magic number constants
readonly MAX_PORT_RANGE=100        # max ports in a single range expansion
readonly MAX_BULK_PORTS=500        # max ports in paired range expansion
readonly NET_CACHE_TTL=30          # network detection cache TTL (seconds)

# Pre-generated separator lines (avoid subshell printf calls)
readonly SEP_EQ="============================================================"
readonly SEP_DASH="------------------------------------------------------------"
readonly SEP_EQ_40="========================================"
readonly SEP_DASH_40="----------------------------------------"

# Quiet mode flag
QUIET=false
PFWD_MAIN_ARGS=()

# Batch mode flag: when true, per-rule save/restart is skipped
_BATCH_MODE=false

# nft output cache (TTL-based, avoids repeated nft list table calls)
_NFT_CACHE="" _NFT_CACHE_TIME=0 _NFT_CACHE_TTL=2

# Per-run caches for repeated add/import/refresh operations
declare -A _TARGET_RESOLVE_CACHE=()
declare -A _TARGET_RESOLVE_STATUS=()
_PORT_USAGE_SNAPSHOT_READY=false
_PORT_USAGE_BACKEND="none"
_PORT_USAGE_TCP_LISTEN=""
_PORT_USAGE_TCP_PROC=""
_PORT_USAGE_UDP_LISTEN=""
_PORT_USAGE_UDP_PROC=""

plat_nft_list_table() {
    nft list table "$@" 2>/dev/null
}

plat_nft_list_chain() {
    nft list chain "$@" 2>/dev/null
}

plat_nft_list_chain_handles() {
    nft -a list chain "$@" 2>/dev/null
}

plat_nft_apply_file() {
    local file="$1"
    nft -f "$file" 2>/dev/null
}

plat_nft_check_file() {
    local file="$1"
    nft -c -f "$file" >/dev/null 2>&1
}

plat_nft_delete_table() {
    nft delete table "$@" 2>/dev/null
}

plat_nft_delete_rule_handle() {
    local family="$1" table="$2" chain="$3" handle="$4"
    nft delete rule "$family" "$table" "$chain" handle "$handle" 2>/dev/null
}

plat_nft_quiet() {
    nft "$@" 2>/dev/null
}

plat_nft_capture() {
    nft "$@" 2>&1
}

plat_systemctl_daemon_reload() {
    systemctl daemon-reload 2>/dev/null || true
}

plat_systemctl_enable_now() {
    local unit="$1"
    systemctl enable --now "$unit" >/dev/null 2>&1 || true
}

plat_systemctl_enable() {
    local unit="$1"
    systemctl enable "$unit" >/dev/null 2>&1 || true
}

plat_systemctl_disable() {
    local unit="$1"
    systemctl disable "$unit" >/dev/null 2>&1 || true
}

plat_systemctl_stop() {
    local unit="$1"
    systemctl stop "$unit" >/dev/null 2>&1 || true
}

plat_sysctl_get() {
    local key="$1" default_value="${2:-}"
    local value
    value=$(sysctl -n "$key" 2>/dev/null || true)
    if [[ -n "$value" ]]; then
        echo "$value"
    else
        echo "$default_value"
    fi
}

plat_sysctl_set() {
    local key="$1" value="$2"
    sysctl -w "$key=$value" >/dev/null 2>&1 || true
}

plat_sysctl_apply_file() {
    local filepath="$1"
    sysctl -p "$filepath" >/dev/null 2>&1 || true
}

plat_ufw_status_line() {
    ufw status 2>/dev/null | head -1
}

plat_ufw_reload() {
    ufw reload >/dev/null 2>&1
}

plat_iptables_restore_test() {
    local filepath="$1"
    iptables-restore --test < "$filepath" >/dev/null 2>&1
}

plat_iptables_policy() {
    local bin="$1" chain="$2"
    "$bin" -S "$chain" 2>/dev/null | awk -v c="$chain" '$1=="-P" && $2==c {print $3; exit}'
}

plat_conntrack_dump_family() {
    local family="$1"
    conntrack -L -f "$family" -o extended 2>/dev/null
}

json_forward_rules_summary() {
    local filepath="$1" override_method="${2:-}"
    while IFS=$'\t' read -r method lport target tport _proto _ipver comment mss_mode mss_value snat_mode snat_source; do
        [[ -z "$method" ]] && continue
        local options_summary
        options_summary=$(_nft_rule_option_summary "$snat_mode" "$snat_source" "$mss_mode" "$mss_value")
        printf '  [%s] :%s -> %s:%s [opts:%s]\n' "$method" "$lport" "$target" "$tport" "$options_summary"
    done < <(json_forward_rules_tsv "$filepath" "$override_method")
}

json_forward_rules_tsv() {
    local filepath="$1" override_method="${2:-}"
    jq -r --arg override "$override_method" '
        .forward_rules[] |
        [
            (if ($override | length) > 0 then $override else (.kind // .type // "nft") end),
            ((.local.port // .local_port) | tostring),
            ((.target.host // .target_ip) | tostring),
            ((.target.port // .target_port) | tostring),
            ((.network.protocol // .protocol // "tcp") | tostring),
            ((.network.ip_version // .ip_ver // "46") | tostring),
            ((.options.comment // .comment // "") | tostring),
            ((.options.mss_mode // .mss_mode // "") | tostring),
            ((.options.mss_value // .mss_value // "") | tostring),
            ((.options.snat_mode // .snat_mode // "masquerade") | tostring),
            ((.options.snat_source // .snat_source // "") | tostring)
        ] | @tsv
    ' "$filepath"
}

json_forward_rules_count() {
    local filepath="$1"
    jq -r '(.forward_rules | length)' "$filepath"
}

json_require_v3_backup() {
    local filepath="$1"
    jq -e '
        has("forward_rules")
        and (.forward_rules | type == "array")
        and (.export_info.version_format // 0) == 3
    ' "$filepath" >/dev/null 2>&1
}

json_export_rules_from_tsv() {
    jq -Rn '
        [
            inputs
            | select(length > 0)
            | split("\t") as $f
            | {
                kind: "nft",
                local: {
                    port: (($f[1] // "0") | tonumber)
                },
                target: (
                    {
                        host: ($f[3] // ""),
                        port: (($f[4] // "0") | tonumber)
                    }
                    + (if (($f[10] // "") | length) > 0 then { resolved_host: ($f[10] // "") } else {} end)
                ),
                network: {
                    protocol: ($f[0] // "tcp"),
                    ip_version: ($f[2] // "46")
                },
                comment: ($f[5] // ""),
                snat_mode: ($f[6] // "masquerade"),
                snat_source: ($f[7] // ""),
                mss_mode: ($f[8] // ""),
                mss_value: ($f[9] // ""),
                options: {
                    comment: ($f[5] // ""),
                    snat_mode: ($f[6] // "masquerade"),
                    snat_source: ($f[7] // ""),
                    mss_mode: ($f[8] // ""),
                    mss_value: ($f[9] // "")
                }
            }
        ]
    '
}

_nft_cached_table() {
    local now; now=$(date +%s)
    if (( now - _NFT_CACHE_TIME >= _NFT_CACHE_TTL )) || [[ -z "$_NFT_CACHE" ]]; then
        _NFT_CACHE=$(plat_nft_list_table $NFT_TABLE) || _NFT_CACHE=""
        _NFT_CACHE_TIME=$now
    fi
    echo "$_NFT_CACHE"
}

_nft_table_exists() { [[ -n "$(_nft_cached_table)" ]]; }

_nft_cached_chain() {
    local chain="$1" data chain_data
    data=$(_nft_cached_table)
    [[ -z "$data" ]] && return 1
    chain_data=$(echo "$data" | awk -v c="$chain" '$0 ~ "chain "c" [{]",/^\t[}]/')
    [[ -n "$chain_data" ]] || return 1
    printf '%s\n' "$chain_data"
}

_nft_chain_has_rules() {
    local chain="$1" chain_data body
    if ! chain_data=$(_nft_cached_chain "$chain"); then
        return 1
    fi
    body=$(printf '%s\n' "$chain_data" | sed '1d;$d')
    grep -Eq '^[[:space:]]+[^[:space:]}]' <<< "$body"
}

_nft_rule_handles_by_comment() {
    local chain="$1" tag="$2" line
    while IFS= read -r line; do
        [[ "$line" == *"comment \"$tag\""* ]] || continue
        [[ "$line" =~ handle[[:space:]]+([0-9]+) ]] || continue
        printf '%s\n' "${BASH_REMATCH[1]}"
    done < <(plat_nft_list_chain_handles $NFT_TABLE "$chain" || true)
}

_nft_cached_chains_concat() {
    local chain
    for chain in "$@"; do
        _nft_cached_chain "$chain" || true
    done
}

_nft_flowtable_block() {
    local data block
    data=$(_nft_cached_table)
    [[ -z "$data" ]] && return 1
    block=$(awk '/flowtable ft[[:space:]]*{/,/^[[:space:]]*}/' <<< "$data")
    [[ -n "$block" ]] || return 1
    printf '%s\n' "$block"
}

_nft_flowtable_mode() {
    local block
    if ! block=$(_nft_flowtable_block); then
        echo "disabled"
        return 0
    fi
    if grep -q 'flags offload' <<< "$block"; then
        echo "offload"
    elif grep -q 'counter' <<< "$block"; then
        echo "counter"
    else
        echo "basic"
    fi
}

_nft_flowtable_devices() {
    local block devices
    if ! block=$(_nft_flowtable_block); then
        echo "-"
        return 0
    fi
    devices=$(sed -n 's/.*devices[[:space:]]*=[[:space:]]*{[[:space:]]*\([^}]*\)[[:space:]]*}.*/\1/p' <<< "$block" | head -1)
    devices=$(echo "$devices" | tr -d '[:space:]')
    echo "${devices:--}"
}

_nft_reset_snapshot() {
    _NFT_SNAPSHOT_READY=false
    _NFT_SNAPSHOT_CACHE_TIME=0
    _NFT_SNAPSHOT_PREROUTING=""
    _NFT_SNAPSHOT_PARSED=""
    _NFT_SNAPSHOT_POSTROUTING=""
    _NFT_SNAPSHOT_FORWARD=""
    _NFT_SNAPSHOT_SNAT_MODE=()
    _NFT_SNAPSHOT_SNAT_SOURCE=()
    _NFT_SNAPSHOT_MSS_MODE=()
    _NFT_SNAPSHOT_MSS_VALUE=()
    _NFT_SNAPSHOT_OUT_BYTES=()
}

_nft_index_postrouting_snapshot() {
    local line tag snat_source
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        _extract_nft_comment "$line"
        tag="$_COMMENT"
        [[ -n "$tag" ]] || continue

        if [[ "$line" =~ snat([[:space:]]+ip6?|[[:space:]]+ip)?[[:space:]]+to[[:space:]]+(\[[^]]+\]|[^[:space:]]+) ]]; then
            snat_source="${BASH_REMATCH[2]}"
            snat_source="${snat_source#[}"
            snat_source="${snat_source%]}"
            _NFT_SNAPSHOT_SNAT_MODE["$tag"]="snat"
            _NFT_SNAPSHOT_SNAT_SOURCE["$tag"]="$snat_source"
        fi
    done <<< "$1"
}

_nft_index_forward_snapshot() {
    local line tag ret_lport ret_ipver ret_proto
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue

        _extract_nft_comment "$line"
        tag="$_COMMENT"
        if [[ -n "$tag" ]]; then
            if [[ "$line" =~ tcp\ option\ maxseg\ size\ set\ rt\ mtu ]]; then
                _NFT_SNAPSHOT_MSS_MODE["$tag"]="clamp"
            elif [[ "$line" =~ tcp\ option\ maxseg\ size\ set\ ([0-9]+) ]]; then
                _NFT_SNAPSHOT_MSS_MODE["$tag"]="set"
                _NFT_SNAPSHOT_MSS_VALUE["$tag"]="${BASH_REMATCH[1]}"
            fi
        fi

        [[ "$tag" =~ ^pfwd_ret:([0-9]+):([46]):([a-z]+): ]] || continue
        ret_lport="${BASH_REMATCH[1]}"
        ret_ipver="${BASH_REMATCH[2]}"
        ret_proto="${BASH_REMATCH[3]}"
        _extract_nft_bytes "$line"
        _NFT_SNAPSHOT_OUT_BYTES["${ret_proto}|${ret_lport}|${ret_ipver}"]="${_BYTES:-0}"
    done <<< "$1"
}

_nft_prepare_snapshot() {
    _nft_cached_table >/dev/null
    if $_NFT_SNAPSHOT_READY && (( _NFT_SNAPSHOT_CACHE_TIME == _NFT_CACHE_TIME )); then
        return 0
    fi

    _nft_reset_snapshot
    _NFT_SNAPSHOT_CACHE_TIME=$_NFT_CACHE_TIME
    _NFT_SNAPSHOT_PREROUTING=$(_nft_prerouting_dnat_lines)
    _NFT_SNAPSHOT_PARSED=$(_parse_nft_prerouting_rules "$_NFT_SNAPSHOT_PREROUTING")
    _NFT_SNAPSHOT_POSTROUTING=$(_nft_cached_chains_concat postrouting $(_pfwd_subchain_list postrouting) || true)
    _NFT_SNAPSHOT_FORWARD=$(_nft_cached_chains_concat forward $(_pfwd_subchain_list forward) || true)

    [[ -n "$_NFT_SNAPSHOT_POSTROUTING" ]] && _nft_index_postrouting_snapshot "$_NFT_SNAPSHOT_POSTROUTING"
    [[ -n "$_NFT_SNAPSHOT_FORWARD" ]] && _nft_index_forward_snapshot "$_NFT_SNAPSHOT_FORWARD"

    _NFT_SNAPSHOT_READY=true
}

_nft_invalidate_cache() {
    _NFT_CACHE=""
    _NFT_CACHE_TIME=0
    _nft_reset_snapshot
}

_mark_nft_dirty() {
    _DIRTY_NFT=true
    _DIRTY_UFW_SYNC=true
    _DIRTY_UFW_RELOAD=true
    _NFT_BACKUP_NEEDED=true
    _nft_invalidate_cache
}

_reset_change_flags() {
    _DIRTY_NFT=false
    _DIRTY_UFW_SYNC=false
    _DIRTY_UFW_RELOAD=false
    _NFT_BACKUP_NEEDED=false
    _UFW_FILES_CHANGED=false
}

_nft_count_rules() {
    local parsed="${1:-}"
    if [[ -z "$parsed" ]]; then
        _nft_prepare_snapshot
        parsed="$_NFT_SNAPSHOT_PARSED"
    fi
    if [[ -z "$parsed" ]]; then
        echo 0
        return
    fi
    awk 'END { print NR+0 }' <<< "$parsed"
}

traffic_stats_backend() {
    if [[ $EUID -eq 0 ]] && command -v conntrack >/dev/null 2>&1; then
        echo "conntrack"
    elif [[ -r /proc/net/nf_conntrack ]]; then
        echo "proc"
    elif command -v conntrack >/dev/null 2>&1; then
        echo "conntrack(root)"
    else
        echo "none"
    fi
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

_traffic_rule_key() {
    printf '%s|%s|%s|%s|%s' "$1" "$2" "$3" "$4" "$5"
}

_pfwd_chain_prefix() {
    case "$1" in
        prerouting) echo "pfwd_pr" ;;
        postrouting) echo "pfwd_po" ;;
        forward) echo "pfwd_fw" ;;
        *) return 1 ;;
    esac
}

_pfwd_subchain_name() {
    local section="$1" proto="$2" ipver="$3"
    local prefix
    prefix=$(_pfwd_chain_prefix "$section") || return 1
    printf '%s_v%s_%s' "$prefix" "$ipver" "$proto"
}

_pfwd_subchain_list() {
    local section="$1" ipver proto
    for ipver in 4 6; do
        for proto in tcp udp; do
            printf '%s\n' "$(_pfwd_subchain_name "$section" "$proto" "$ipver")"
        done
    done
}

_pfwd_rule_chain_candidates() {
    local section="$1" proto="$2" ipver="$3"
    printf '%s\n' "$(_pfwd_subchain_name "$section" "$proto" "$ipver")"
    echo "$section"
}

_pfwd_port_search_chains() {
    local section="$1" proto="${2:-both}" ipver
    case "$proto" in
        tcp|udp)
            for ipver in 4 6; do
                printf '%s\n' "$(_pfwd_subchain_name "$section" "$proto" "$ipver")"
            done
            ;;
        both)
            _pfwd_subchain_list "$section"
            ;;
        *)
            return 1
            ;;
    esac
    echo "$section"
}

_pfwd_dispatch_tag() {
    local section="$1" proto="$2" ipver="$3"
    printf 'pfwd_dispatch:%s:v%s:%s' "$section" "$ipver" "$proto"
}

_pfwd_dispatch_match_tokens() {
    local proto="$1" ipver="$2"
    if [[ "$ipver" == "6" ]]; then
        printf 'ip6 nexthdr %s' "$proto"
    else
        printf 'ip protocol %s' "$proto"
    fi
}

_nft_prefixed_chain_handles() {
    local chain="$1"
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf '%s\t%s\n' "$chain" "$line"
    done < <(plat_nft_list_chain_handles $NFT_TABLE "$chain" || true)
}

_nft_prefixed_chain_handles_concat() {
    local chain
    for chain in "$@"; do
        _nft_prefixed_chain_handles "$chain"
    done
}

_pfwd_postrouting_handle_refs_by_tag() {
    local tag="$1" proto="$2" ipver="$3"
    local chain line handle
    while IFS=$'\t' read -r chain line; do
        [[ -n "$line" ]] || continue
        [[ "$line" == *"comment \"$tag\""* ]] || continue
        handle=""
        [[ "$line" =~ handle\ ([0-9]+) ]] && handle="${BASH_REMATCH[1]}"
        [[ -n "$handle" ]] && printf '%s\t%s\n' "$chain" "$handle"
    done < <(_nft_prefixed_chain_handles_concat $(_pfwd_rule_chain_candidates postrouting "$proto" "$ipver"))
}

_pfwd_forward_handle_refs_by_rule() {
    local lport="$1" ipver="$2" proto="$3" target="$4" tport="$5"
    local scope rule_tag chain line handle
    scope=$(_pfwd_rule_scope "$lport" "$ipver" "$proto" "$target" "$tport")
    rule_tag=$(_pfwd_rule_tag "$lport" "$ipver" "$proto" "$target" "$tport")
    while IFS=$'\t' read -r chain line; do
        [[ -n "$line" ]] || continue
        if [[ "$line" != *"comment \"pfwd_fwd:${scope}\""* && \
              "$line" != *"comment \"pfwd_ret:${scope}\""* && \
              "$line" != *"comment \"${rule_tag}:mss\""* ]]; then
            continue
        fi
        handle=""
        [[ "$line" =~ handle\ ([0-9]+) ]] && handle="${BASH_REMATCH[1]}"
        [[ -n "$handle" ]] && printf '%s\t%s\n' "$chain" "$handle"
    done < <(_nft_prefixed_chain_handles_concat $(_pfwd_rule_chain_candidates forward "$proto" "$ipver"))
}

_nft_forward_established_accept_handle() {
    plat_nft_list_chain_handles $NFT_TABLE forward | \
        awk '
            /ct state established,related accept/ {
                for (i = 1; i <= NF; i++) {
                    if ($i == "handle") {
                        print $(i + 1)
                        exit
                    }
                }
            }
        '
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
    pfwd_state_ensure_initialized
    PFWD_NFT_RULES=$(pfwd_state_rules_tsv)
    PFWD_NFT_COUNT=$(pfwd_state_rule_count "$PFWD_NFT_RULES")
    PFWD_NFT_RUNNING=false
    _nft_table_exists && PFWD_NFT_RUNNING=true

    local current_cc
    current_cc=$(plat_sysctl_get net.ipv4.tcp_congestion_control "")
    [[ "$current_cc" == "bbr" ]] && PFWD_BBR_ENABLED=true || PFWD_BBR_ENABLED=false

    PFWD_LOOPBACK_DNAT=false
    if awk -F'\t' '$5 ~ /^127\./ || $5 == "::1" { found=1 } END { exit(found ? 0 : 1) }' <<< "$(_pfwd_state_runtime_rules_tsv "$PFWD_NFT_RULES" "false")"; then
        PFWD_LOOPBACK_DNAT=true
    fi

    PFWD_UFW_LOOPBACK_STATE="n/a"
    if command -v ufw >/dev/null 2>&1; then
        if plat_ufw_status_line | grep -q '^Status: active'; then
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

    PFWD_TRAFFIC_INTERVAL=$(traffic_current_interval)
    PFWD_TRAFFIC_BACKEND=$(traffic_stats_backend)
}

_pfwd_collect_runtime_health() {
    local parsed="${1:-}"
    if [[ -z "$parsed" ]]; then
        parsed=$(_pfwd_runtime_rules_to_parsed_tsv "$(_pfwd_state_runtime_rules_tsv "$PFWD_NFT_RULES" "false")")
    fi

    PFWD_HEALTH_HAS_IPV4_RULES=false
    PFWD_HEALTH_HAS_IPV6_RULES=false
    PFWD_HEALTH_HAS_LOOPBACK_RULES=false
    PFWD_IPTABLES_V4_FORWARD_STATE="n/a"
    PFWD_IPTABLES_V6_FORWARD_STATE="n/a"
    PFWD_IPTABLES_V4_INPUT_STATE="n/a"
    PFWD_IPTABLES_V6_INPUT_STATE="n/a"
    PFWD_UFW_PERSISTENCE_STATE="n/a"
    PFWD_RUNTIME_HEALTH_DEGRADED=false

    local proto lport ipver target tport comment bytes
    while IFS=$'\t' read -r proto lport ipver target tport comment bytes; do
        [[ -z "$lport" ]] && continue
        case "$ipver" in
            4)
                PFWD_HEALTH_HAS_IPV4_RULES=true
                [[ "$target" =~ ^127\. ]] && PFWD_HEALTH_HAS_LOOPBACK_RULES=true
                ;;
            6)
                PFWD_HEALTH_HAS_IPV6_RULES=true
                [[ "$target" == "::1" ]] && PFWD_HEALTH_HAS_LOOPBACK_RULES=true
                ;;
        esac
    done <<< "$parsed"

    local forward_policy input_policy
    if command -v iptables >/dev/null 2>&1; then
        forward_policy=$(plat_iptables_policy iptables FORWARD)
        input_policy=$(plat_iptables_policy iptables INPUT)
        if $PFWD_HEALTH_HAS_IPV4_RULES; then
            if [[ "$forward_policy" == "DROP" ]]; then
                if _iptables_rule_present iptables FORWARD -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_FWD_DNAT_COMMENT" -j ACCEPT && \
                   _iptables_rule_present iptables FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$IPTABLES_FWD_EST_COMMENT" -j ACCEPT; then
                    PFWD_IPTABLES_V4_FORWARD_STATE="ok"
                else
                    PFWD_IPTABLES_V4_FORWARD_STATE="missing"
                    PFWD_RUNTIME_HEALTH_DEGRADED=true
                fi
            else
                PFWD_IPTABLES_V4_FORWARD_STATE="policy-open"
            fi
        else
            PFWD_IPTABLES_V4_FORWARD_STATE="not-needed"
        fi

        if $PFWD_HEALTH_HAS_LOOPBACK_RULES; then
            if [[ "$input_policy" == "DROP" ]]; then
                if _iptables_rule_present iptables INPUT -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_INPUT_DNAT_COMMENT" -j ACCEPT; then
                    PFWD_IPTABLES_V4_INPUT_STATE="ok"
                else
                    PFWD_IPTABLES_V4_INPUT_STATE="missing"
                    PFWD_RUNTIME_HEALTH_DEGRADED=true
                fi
            else
                PFWD_IPTABLES_V4_INPUT_STATE="policy-open"
            fi
        else
            PFWD_IPTABLES_V4_INPUT_STATE="not-needed"
        fi
    else
        if $PFWD_HEALTH_HAS_IPV4_RULES; then
            PFWD_IPTABLES_V4_FORWARD_STATE="unavailable"
        else
            PFWD_IPTABLES_V4_FORWARD_STATE="not-needed"
        fi
        if $PFWD_HEALTH_HAS_LOOPBACK_RULES; then
            PFWD_IPTABLES_V4_INPUT_STATE="unavailable"
        else
            PFWD_IPTABLES_V4_INPUT_STATE="not-needed"
        fi
    fi

    local forward_policy6 input_policy6
    if command -v ip6tables >/dev/null 2>&1; then
        forward_policy6=$(plat_iptables_policy ip6tables FORWARD)
        input_policy6=$(plat_iptables_policy ip6tables INPUT)
        if $PFWD_HEALTH_HAS_IPV6_RULES; then
            if [[ "$forward_policy6" == "DROP" ]]; then
                if _iptables_rule_present ip6tables FORWARD -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_FWD_DNAT_COMMENT" -j ACCEPT && \
                   _iptables_rule_present ip6tables FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$IPTABLES_FWD_EST_COMMENT" -j ACCEPT; then
                    PFWD_IPTABLES_V6_FORWARD_STATE="ok"
                else
                    PFWD_IPTABLES_V6_FORWARD_STATE="missing"
                    PFWD_RUNTIME_HEALTH_DEGRADED=true
                fi
            else
                PFWD_IPTABLES_V6_FORWARD_STATE="policy-open"
            fi
        else
            PFWD_IPTABLES_V6_FORWARD_STATE="not-needed"
        fi

        if $PFWD_HEALTH_HAS_LOOPBACK_RULES; then
            if [[ "$input_policy6" == "DROP" ]]; then
                if _iptables_rule_present ip6tables INPUT -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_INPUT_DNAT_COMMENT" -j ACCEPT; then
                    PFWD_IPTABLES_V6_INPUT_STATE="ok"
                else
                    PFWD_IPTABLES_V6_INPUT_STATE="missing"
                    PFWD_RUNTIME_HEALTH_DEGRADED=true
                fi
            else
                PFWD_IPTABLES_V6_INPUT_STATE="policy-open"
            fi
        else
            PFWD_IPTABLES_V6_INPUT_STATE="not-needed"
        fi
    else
        if $PFWD_HEALTH_HAS_IPV6_RULES; then
            PFWD_IPTABLES_V6_FORWARD_STATE="unavailable"
        else
            PFWD_IPTABLES_V6_FORWARD_STATE="not-needed"
        fi
        if $PFWD_HEALTH_HAS_LOOPBACK_RULES; then
            PFWD_IPTABLES_V6_INPUT_STATE="unavailable"
        else
            PFWD_IPTABLES_V6_INPUT_STATE="not-needed"
        fi
    fi

    if command -v ufw >/dev/null 2>&1; then
        case "$PFWD_UFW_LOOPBACK_STATE" in
            ok) PFWD_UFW_PERSISTENCE_STATE="ok" ;;
            missing)
                PFWD_UFW_PERSISTENCE_STATE="degraded"
                PFWD_RUNTIME_HEALTH_DEGRADED=true
                ;;
            idle) PFWD_UFW_PERSISTENCE_STATE="idle" ;;
            disabled) PFWD_UFW_PERSISTENCE_STATE="disabled" ;;
            *) PFWD_UFW_PERSISTENCE_STATE="n/a" ;;
        esac
    else
        PFWD_UFW_PERSISTENCE_STATE="unavailable"
    fi
}

_pfwd_repair_runtime_health() {
    local parsed="${1:-}"
    sync_managed_iptables_accept_rules "$parsed" || return 1
    ufw_sync_loopback_dnat_rules || return 1
    if $_DIRTY_UFW_RELOAD; then
        ufw_reload_if_enabled || return 1
        sync_managed_iptables_accept_rules "$parsed" || return 1
    fi
}

_pfwd_report_runtime_health_failure() {
    [[ "$PFWD_IPTABLES_V4_FORWARD_STATE" == "missing" ]] && msg_err "IPv4 iptables FORWARD managed exceptions are still missing"
    [[ "$PFWD_IPTABLES_V6_FORWARD_STATE" == "missing" ]] && msg_err "IPv6 ip6tables FORWARD managed exceptions are still missing"
    [[ "$PFWD_IPTABLES_V4_INPUT_STATE" == "missing" ]] && msg_err "IPv4 iptables INPUT loopback DNAT exception is still missing"
    [[ "$PFWD_IPTABLES_V6_INPUT_STATE" == "missing" ]] && msg_err "IPv6 ip6tables INPUT loopback DNAT exception is still missing"
    [[ "$PFWD_UFW_PERSISTENCE_STATE" == "degraded" ]] && msg_err "UFW loopback DNAT persistence is still degraded"
}

_pfwd_enforce_runtime_health() {
    local parsed="${1:-}"
    _pfwd_collect_state
    _pfwd_collect_runtime_health "$parsed"
    $PFWD_RUNTIME_HEALTH_DEGRADED || return 0

    msg_warn "Detected degraded firewall guard state; attempting repair"
    _pfwd_repair_runtime_health "$parsed" || true

    _pfwd_collect_state
    _pfwd_collect_runtime_health "$parsed"
    if $PFWD_RUNTIME_HEALTH_DEGRADED; then
        _pfwd_report_runtime_health_failure
        return 1
    fi
    return 0
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

_pfwd_state_target_file() {
    if $_BATCH_MODE; then
        if [[ -z "$PFWD_STATE_BATCH_FILE" || ! -f "$PFWD_STATE_BATCH_FILE" ]]; then
            mkdir -p "$DATA_DIR"
            PFWD_STATE_BATCH_FILE=$(_mktemp_in_dir "$RULES_STATE_FILE") || return 1
            if [[ -f "$RULES_STATE_FILE" ]]; then
                cat "$RULES_STATE_FILE" > "$PFWD_STATE_BATCH_FILE"
            else
                : > "$PFWD_STATE_BATCH_FILE"
            fi
        fi
        PFWD_STATE_TARGET_FILE="$PFWD_STATE_BATCH_FILE"
    else
        mkdir -p "$DATA_DIR"
        PFWD_STATE_TARGET_FILE="$RULES_STATE_FILE"
    fi
    return 0
}

_pfwd_state_discard_batch() {
    if [[ -n "$PFWD_STATE_BATCH_FILE" ]]; then
        rm -f "$PFWD_STATE_BATCH_FILE" 2>/dev/null || true
        PFWD_STATE_BATCH_FILE=""
    fi
    PFWD_STATE_TARGET_FILE=""
}

_pfwd_state_commit_batch() {
    [[ -n "$PFWD_STATE_BATCH_FILE" && -f "$PFWD_STATE_BATCH_FILE" ]] || return 0
    mkdir -p "$DATA_DIR"
    _atomic_replace_file "$PFWD_STATE_BATCH_FILE" "$RULES_STATE_FILE" 0644
    PFWD_STATE_BATCH_FILE=""
    PFWD_STATE_TARGET_FILE=""
}

pfwd_state_rules_tsv() {
    local filepath="${1:-}"
    if [[ -z "$filepath" ]]; then
        if [[ -n "$PFWD_STATE_BATCH_FILE" && -f "$PFWD_STATE_BATCH_FILE" ]]; then
            filepath="$PFWD_STATE_BATCH_FILE"
        else
            filepath="$RULES_STATE_FILE"
        fi
    fi
    [[ -f "$filepath" ]] || return 0
    awk 'NF > 0' "$filepath"
}

pfwd_state_rule_count() {
    local rules="${1:-}"
    if [[ -z "$rules" ]]; then
        rules=$(pfwd_state_rules_tsv)
    fi
    [[ -z "$rules" ]] && {
        echo 0
        return 0
    }
    awk 'END { print NR+0 }' <<< "$rules"
}

_pfwd_state_write_rules() {
    local target_file="$1"
    local tmp_file
    tmp_file=$(_mktemp_in_dir "$target_file") || return 1
    cat > "$tmp_file"
    _atomic_replace_file "$tmp_file" "$target_file" 0644
}

_pfwd_state_rule_identity() {
    printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5"
}

_pfwd_state_find_conflict() {
    local rules="$1" lport="$2" proto="$3" ipver="$4"
    PFWD_STATE_CONFLICT_TARGET=""
    PFWD_STATE_CONFLICT_TPORT=""
    while IFS=$'\t' read -r row_proto row_lport row_ipver row_target row_tport row_comment row_snat_mode row_snat_source row_mss_mode row_mss_value; do
        [[ -z "$row_lport" ]] && continue
        if [[ "$row_proto" == "$proto" && "$row_lport" == "$lport" && "$row_ipver" == "$ipver" ]]; then
            PFWD_STATE_CONFLICT_TARGET="$row_target"
            PFWD_STATE_CONFLICT_TPORT="$row_tport"
            return 0
        fi
    done <<< "$rules"
    return 1
}

_pfwd_state_runtime_rules_tsv() {
    local rules="${1:-}" strict="${2:-false}"
    if [[ -z "$rules" ]]; then
        rules=$(pfwd_state_rules_tsv)
    fi
    [[ -n "$rules" ]] || return 0

    local proto lport ipver target_input tport comment snat_mode snat_source mss_mode mss_value
    local resolved_targets family effective_ipver resolved_ip
    while IFS=$'\t' read -r proto lport ipver target_input tport comment snat_mode snat_source mss_mode mss_value; do
        [[ -z "$lport" ]] && continue
        if [[ "$strict" == "true" ]]; then
            if ! resolved_targets=$(_nft_resolve_targets "$target_input" "$ipver"); then
                msg_err "Failed to resolve target '$target_input' for IPv${ipver} rule :$lport -> $target_input:$tport"
                return 1
            fi
        else
            resolved_targets=$(_nft_resolve_targets "$target_input" "$ipver" 2>/dev/null || true)
            [[ -n "$resolved_targets" ]] || continue
        fi
        while IFS='|' read -r family effective_ipver resolved_ip; do
            [[ -n "$resolved_ip" && "$effective_ipver" == "$ipver" ]] || continue
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$proto" "$lport" "$ipver" "$target_input" "$resolved_ip" "$tport" "$comment" \
                "$snat_mode" "$snat_source" "$mss_mode" "$mss_value"
        done <<< "$resolved_targets"
    done <<< "$rules"
}

_pfwd_state_resolved_target() {
    local target_input="$1" ipver="$2"
    local resolved_targets family effective_ipver resolved_ip
    resolved_targets=$(_nft_resolve_targets "$target_input" "$ipver" 2>/dev/null || true)
    if [[ -z "$resolved_targets" ]]; then
        return 1
    fi
    while IFS='|' read -r family effective_ipver resolved_ip; do
        [[ "$effective_ipver" == "$ipver" && -n "$resolved_ip" ]] || continue
        printf '%s\n' "$resolved_ip"
        return 0
    done <<< "$resolved_targets"
    return 1
}

pfwd_state_export_rows_tsv() {
    local rules="${1:-}"
    if [[ -z "$rules" ]]; then
        rules=$(pfwd_state_rules_tsv)
    fi
    [[ -n "$rules" ]] || return 0

    local proto lport ipver target_input tport comment snat_mode snat_source mss_mode mss_value resolved_host
    while IFS=$'\t' read -r proto lport ipver target_input tport comment snat_mode snat_source mss_mode mss_value; do
        [[ -z "$lport" ]] && continue
        resolved_host=$(_pfwd_state_resolved_target "$target_input" "$ipver" 2>/dev/null || true)
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$proto" "$lport" "$ipver" "$target_input" "$tport" "$comment" \
            "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" "$resolved_host"
    done <<< "$rules"
}

_pfwd_state_target_label() {
    local target_input="$1" ipver="$2"
    local resolved_host=""
    if resolved_host=$(_pfwd_state_resolved_target "$target_input" "$ipver" 2>/dev/null); then
        if [[ "$resolved_host" != "$target_input" ]]; then
            printf '%s => %s' "$target_input" "$resolved_host"
            return 0
        fi
    fi
    printf '%s' "$target_input"
}

_pfwd_chain_from_text() {
    local data="$1" chain="$2"
    awk -v c="$chain" '$0 ~ "chain " c " [{]",/^[[:space:]]*}/' <<< "$data"
}

_pfwd_state_rules_from_nft_text() {
    local data="$1"
    [[ -n "$data" ]] || return 0

    local prerouting_data="" postrouting_data="" forward_data="" chain
    for chain in $(_pfwd_subchain_list prerouting); do
        prerouting_data+="$(_pfwd_chain_from_text "$data" "$chain")"$'\n'
    done
    for chain in $(_pfwd_subchain_list postrouting); do
        postrouting_data+="$(_pfwd_chain_from_text "$data" "$chain")"$'\n'
    done
    for chain in $(_pfwd_subchain_list forward); do
        forward_data+="$(_pfwd_chain_from_text "$data" "$chain")"$'\n'
    done

    _nft_reset_snapshot
    [[ -n "$postrouting_data" ]] && _nft_index_postrouting_snapshot "$postrouting_data"
    [[ -n "$forward_data" ]] && _nft_index_forward_snapshot "$forward_data"

    local parsed proto lport ipver target tport comment bytes
    parsed=$(_parse_nft_prerouting_rules "$prerouting_data")
    [[ -n "$parsed" ]] || return 0

    while IFS=$'\t' read -r proto lport ipver target tport comment bytes; do
        [[ -z "$lport" ]] && continue
        local tag snat_mode="masquerade" snat_source="" mss_mode="" mss_value=""
        tag=$(_pfwd_rule_tag "$lport" "$ipver" "$proto" "$target" "$tport")
        [[ -n "${_NFT_SNAPSHOT_SNAT_MODE[$tag]:-}" ]] && snat_mode="${_NFT_SNAPSHOT_SNAT_MODE[$tag]}"
        [[ -n "${_NFT_SNAPSHOT_SNAT_SOURCE[$tag]:-}" ]] && snat_source="${_NFT_SNAPSHOT_SNAT_SOURCE[$tag]}"
        [[ -n "${_NFT_SNAPSHOT_MSS_MODE[${tag}:mss]:-}" ]] && mss_mode="${_NFT_SNAPSHOT_MSS_MODE[${tag}:mss]}"
        [[ -n "${_NFT_SNAPSHOT_MSS_VALUE[${tag}:mss]:-}" ]] && mss_value="${_NFT_SNAPSHOT_MSS_VALUE[${tag}:mss]}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
            "$snat_mode" "$snat_source" "$mss_mode" "$mss_value"
    done <<< "$parsed"
}

pfwd_state_ensure_initialized() {
    if [[ -f "$RULES_STATE_FILE" ]]; then
        return 0
    fi

    local migrated_rules=""
    if _nft_table_exists; then
        migrated_rules=$(_parse_nft_export_rules || true)
    elif [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]]; then
        migrated_rules=$(_pfwd_state_rules_from_nft_text "$(cat "$NFT_CONFIG")" || true)
    fi

    [[ -n "$migrated_rules" ]] || return 0

    mkdir -p "$DATA_DIR"
    printf '%s\n' "$migrated_rules" | _pfwd_state_write_rules "$RULES_STATE_FILE"
    msg_info "Migrated existing nftables rules into $RULES_STATE_FILE"
}

pfwd_state_add_rule() {
    local lport="$1" target_input="$2" tport="$3" ip_ver="${4:-46}" proto="${5:-tcp}" comment="${6:-}"
    local mss_mode="${7:-}" mss_value="${8:-}" snat_mode="${9:-masquerade}" snat_source="${10:-}" replace_mode="${11:-false}"
    local target_file current_rules

    if ! validate_comment "$comment"; then
        msg_err "Comment must be a single line without tabs"
        return 1
    fi
    validate_snat_request "$ip_ver" "$snat_mode" "$snat_source" || return 1

    if ! check_port_in_use "$lport" "$proto"; then
        msg_info "Cancelled"
        return 1
    fi

    pfwd_state_ensure_initialized
    _pfwd_state_target_file || return 1
    target_file="$PFWD_STATE_TARGET_FILE"
    current_rules=$(pfwd_state_rules_tsv "$target_file")

    local resolved_targets
    if ! resolved_targets=$(_nft_resolve_targets "$target_input" "$ip_ver"); then
        return 1
    fi

    local -a protos=()
    case "$proto" in
        tcp) protos=(tcp) ;;
        udp) protos=(udp) ;;
        both) protos=(tcp udp) ;;
        *) msg_err "Invalid protocol: $proto"; return 1 ;;
    esac

    local additions="" display_additions="" family effective_ipver resolved_ip p need_route_localnet=false
    declare -A replace_keys=()
    for p in "${protos[@]}"; do
        while IFS='|' read -r family effective_ipver resolved_ip; do
            [[ -n "$effective_ipver" && -n "$resolved_ip" ]] || continue
            [[ "$resolved_ip" =~ ^127\. ]] && need_route_localnet=true
            if _pfwd_state_find_conflict "$current_rules" "$lport" "$p" "$effective_ipver"; then
                if [[ "$replace_mode" != "true" ]]; then
                    msg_err "Conflict: IPv${effective_ipver} $p port $lport already forwards to ${PFWD_STATE_CONFLICT_TARGET}:${PFWD_STATE_CONFLICT_TPORT}"
                    msg_err "Use --replace to update that rule explicitly"
                    return 1
                fi
                replace_keys["$p|$lport|$effective_ipver"]=1
                msg_info "Replacing existing IPv${effective_ipver} $p rule for port $lport"
            fi
            printf -v additions '%s%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$additions" "$p" "$lport" "$effective_ipver" "$target_input" "$tport" "$comment" \
                "$snat_mode" "$snat_source" "$mss_mode" "$mss_value"
            printf -v display_additions '%sIPv%s %s :%s -> %s:%s\n' \
                "$display_additions" "$effective_ipver" "$p" "$lport" "$resolved_ip" "$tport"
        done <<< "$resolved_targets"
    done

    [[ -n "$additions" ]] || {
        msg_err "No rules were added for :$lport -> $target_input:$tport"
        return 1
    }

    local tmp_file
    tmp_file=$(_mktemp_in_dir "$target_file") || return 1
    if [[ -n "$current_rules" ]]; then
        while IFS=$'\t' read -r row_proto row_lport row_ipver row_target row_tport row_comment row_snat_mode row_snat_source row_mss_mode row_mss_value; do
            [[ -z "$row_lport" ]] && continue
            if [[ -n "${replace_keys["$row_proto|$row_lport|$row_ipver"]:-}" ]]; then
                continue
            fi
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$row_proto" "$row_lport" "$row_ipver" "$row_target" "$row_tport" "$row_comment" \
                "$row_snat_mode" "$row_snat_source" "$row_mss_mode" "$row_mss_value" >> "$tmp_file"
        done <<< "$current_rules"
    fi
    printf '%s' "$additions" >> "$tmp_file"
    _atomic_replace_file "$tmp_file" "$target_file" 0644

    if $need_route_localnet; then
        ensure_route_localnet
    fi

    _mark_nft_dirty
    while IFS= read -r display_line; do
        [[ -n "$display_line" ]] || continue
        if $_BATCH_MODE; then
            msg_dim "  Queued $display_line"
        else
            msg_dim "  Added $display_line"
        fi
    done <<< "$display_additions"
    return 0
}

pfwd_state_delete_exact_rule() {
    local proto="$1" lport="$2" ipver="$3" target_input="$4" tport="$5"
    local target_file current_rules tmp_file deleted=0

    pfwd_state_ensure_initialized
    _pfwd_state_target_file || return 1
    target_file="$PFWD_STATE_TARGET_FILE"
    current_rules=$(pfwd_state_rules_tsv "$target_file")
    [[ -n "$current_rules" ]] || return 1

    tmp_file=$(_mktemp_in_dir "$target_file") || return 1
    while IFS=$'\t' read -r row_proto row_lport row_ipver row_target row_tport row_comment row_snat_mode row_snat_source row_mss_mode row_mss_value; do
        [[ -z "$row_lport" ]] && continue
        if [[ "$row_proto" == "$proto" && "$row_lport" == "$lport" && "$row_ipver" == "$ipver" && "$row_target" == "$target_input" && "$row_tport" == "$tport" ]]; then
            ((deleted++)) || true
            continue
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$row_proto" "$row_lport" "$row_ipver" "$row_target" "$row_tport" "$row_comment" \
            "$row_snat_mode" "$row_snat_source" "$row_mss_mode" "$row_mss_value" >> "$tmp_file"
    done <<< "$current_rules"

    (( deleted > 0 )) || {
        rm -f "$tmp_file" 2>/dev/null || true
        return 1
    }

    _atomic_replace_file "$tmp_file" "$target_file" 0644
    _mark_nft_dirty
    return 0
}

pfwd_state_delete_port_rules() {
    local port="$1" proto="${2:-both}"
    local target_file current_rules tmp_file deleted=0

    pfwd_state_ensure_initialized
    _pfwd_state_target_file || return 1
    target_file="$PFWD_STATE_TARGET_FILE"
    current_rules=$(pfwd_state_rules_tsv "$target_file")
    [[ -n "$current_rules" ]] || return 1

    tmp_file=$(_mktemp_in_dir "$target_file") || return 1
    while IFS=$'\t' read -r row_proto row_lport row_ipver row_target row_tport row_comment row_snat_mode row_snat_source row_mss_mode row_mss_value; do
        [[ -z "$row_lport" ]] && continue
        if [[ "$row_lport" == "$port" ]]; then
            case "$proto" in
                both) ((deleted++)) || true; continue ;;
                tcp|udp)
                    if [[ "$row_proto" == "$proto" ]]; then
                        ((deleted++)) || true
                        continue
                    fi
                    ;;
            esac
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$row_proto" "$row_lport" "$row_ipver" "$row_target" "$row_tport" "$row_comment" \
            "$row_snat_mode" "$row_snat_source" "$row_mss_mode" "$row_mss_value" >> "$tmp_file"
    done <<< "$current_rules"

    (( deleted > 0 )) || {
        rm -f "$tmp_file" 2>/dev/null || true
        return 1
    }

    _atomic_replace_file "$tmp_file" "$target_file" 0644
    _mark_nft_dirty
    PFWD_STATE_DELETE_COUNT=$deleted
    return 0
}

_pfwd_runtime_rules_to_parsed_tsv() {
    local runtime_rules="${1:-}"
    [[ -n "$runtime_rules" ]] || return 0

    local proto lport ipver target_input resolved_target tport comment snat_mode snat_source mss_mode mss_value
    while IFS=$'\t' read -r proto lport ipver target_input resolved_target tport comment snat_mode snat_source mss_mode mss_value; do
        [[ -z "$lport" ]] && continue
        printf '%s\t%s\t%s\t%s\t%s\t%s\t0\n' \
            "$proto" "$lport" "$ipver" "$resolved_target" "$tport" "$comment"
    done <<< "$runtime_rules"
}

_pfwd_is_real_nic() {
    local iface="$1"
    [[ -n "$iface" && "$iface" != "lo" ]] || return 1
    [[ ! "$iface" =~ ^(veth|docker|br-|virbr|vnet|tun|tap|dummy) ]] || return 1
    return 0
}

_pfwd_default_route_device() {
    local family="$1"
    local flag="-4"
    [[ "$family" == "6" ]] && flag="-6"
    ip -o "$flag" route show default 2>/dev/null | awk '
        {
            for (i = 1; i <= NF; i++) {
                if ($i == "dev") {
                    print $(i + 1)
                    exit
                }
            }
        }
    '
}

_pfwd_route_device_for_target() {
    local target="$1" ipver="$2"
    local family_flag="-4" route_output=""
    [[ "$ipver" == "6" ]] && family_flag="-6"
    route_output=$(_mss_route_probe "$family_flag" "$target" 2>/dev/null || true)
    [[ -n "$route_output" ]] || return 1
    _mss_route_field "$route_output" dev
}

_pfwd_collect_flowtable_devices() {
    local runtime_rules="${1:-}"
    [[ -n "$runtime_rules" ]] || return 0

    declare -A seen=()
    local proto lport ipver target_input resolved_target tport comment snat_mode snat_source mss_mode mss_value
    local default_dev route_dev
    while IFS=$'\t' read -r proto lport ipver target_input resolved_target tport comment snat_mode snat_source mss_mode mss_value; do
        [[ -n "$resolved_target" ]] || continue
        default_dev=$(_pfwd_default_route_device "$ipver")
        if _pfwd_is_real_nic "$default_dev"; then
            seen["$default_dev"]=1
        fi
        route_dev=$(_pfwd_route_device_for_target "$resolved_target" "$ipver" 2>/dev/null || true)
        if _pfwd_is_real_nic "$route_dev"; then
            seen["$route_dev"]=1
        fi
    done <<< "$runtime_rules"

    local devices=()
    local dev
    for dev in "${!seen[@]}"; do
        devices+=("$dev")
    done
    if (( ${#devices[@]} == 0 )); then
        return 0
    fi
    printf '%s\n' "${devices[@]}" | sort | paste -sd, -
}

_pfwd_flowtable_modes() {
    local devices_csv="${1:-}"
    local kver major minor
    [[ -n "$devices_csv" ]] || {
        echo "disabled"
        return 0
    }
    kver=$(uname -r | awk -F'[.-]' '{print $1"."$2}')
    IFS='.' read -r major minor <<< "$kver"
    if (( major < 4 || (major == 4 && minor < 16) )); then
        echo "disabled"
        return 0
    fi
    printf '%s\n' offload counter basic disabled
}

_pfwd_ports_to_nft_expr() {
    local ports_csv="$1"
    local -a ports=()
    local port
    IFS=',' read -ra ports <<< "$ports_csv"
    (( ${#ports[@]} > 0 )) || {
        echo ""
        return 0
    }

    local sorted
    sorted=$(printf '%s\n' "${ports[@]}" | awk 'NF > 0' | sort -n -u)
    local -a expr_parts=()
    local start="" prev="" current=""
    while IFS= read -r current; do
        [[ -n "$current" ]] || continue
        if [[ -z "$start" ]]; then
            start="$current"
            prev="$current"
            continue
        fi
        if (( current == prev + 1 )); then
            prev="$current"
            continue
        fi
        if [[ "$start" == "$prev" ]]; then
            expr_parts+=("$start")
        else
            expr_parts+=("$start-$prev")
        fi
        start="$current"
        prev="$current"
    done <<< "$sorted"

    if [[ -n "$start" ]]; then
        if [[ "$start" == "$prev" ]]; then
            expr_parts+=("$start")
        else
            expr_parts+=("$start-$prev")
        fi
    fi

    if (( ${#expr_parts[@]} == 1 )); then
        printf '%s\n' "${expr_parts[0]}"
        return 0
    fi

    local IFS=', '
    printf '{ %s }\n' "${expr_parts[*]}"
}

_pfwd_render_nft_config() {
    local runtime_rules="$1" output_file="$2" flow_mode="$3" devices_csv="${4:-}"

    declare -A prerouting_ports=()
    declare -A prerouting_seen=()
    declare -A postrouting_keys=()
    declare -A forward_keys=()
    declare -A subchain_nonempty=()

    local proto lport ipver target_input resolved_target tport comment snat_mode snat_source mss_mode mss_value group_key
    while IFS=$'\t' read -r proto lport ipver target_input resolved_target tport comment snat_mode snat_source mss_mode mss_value; do
        [[ -n "$lport" && -n "$resolved_target" ]] || continue
        group_key="${proto}|${ipver}|${resolved_target}|${tport}|${snat_mode}|${snat_source}|${mss_mode}|${mss_value}"
        if [[ -z "${prerouting_seen["$group_key|$lport"]:-}" ]]; then
            if [[ -n "${prerouting_ports[$group_key]:-}" ]]; then
                prerouting_ports["$group_key"]+=",${lport}"
            else
                prerouting_ports["$group_key"]="$lport"
            fi
            prerouting_seen["$group_key|$lport"]=1
        fi
        postrouting_keys["$group_key"]=1
        [[ -n "$mss_mode" ]] && forward_keys["$group_key"]=1
        subchain_nonempty["prerouting|${ipver}|${proto}"]=1
        subchain_nonempty["postrouting|${ipver}|${proto}"]=1
        [[ -n "$mss_mode" ]] && subchain_nonempty["forward|${ipver}|${proto}"]=1
    done <<< "$runtime_rules"

    {
        echo "table inet port_forward {"
        if [[ "$flow_mode" != "disabled" && -n "$devices_csv" ]]; then
            printf '    flowtable ft {\n'
            printf '        hook ingress priority 0;\n'
            printf '        devices = { %s };\n' "${devices_csv//,/\, }"
            case "$flow_mode" in
                offload) printf '        flags offload;\n        counter;\n' ;;
                counter) printf '        counter;\n' ;;
            esac
            printf '    }\n\n'
        fi

        printf '    chain prerouting {\n'
        printf '        type nat hook prerouting priority dstnat; policy accept;\n'
        local ipver proto match_tokens section_key
        for ipver in 4 6; do
            for proto in tcp udp; do
                section_key="prerouting|${ipver}|${proto}"
                [[ -n "${subchain_nonempty[$section_key]:-}" ]] || continue
                match_tokens=$(_pfwd_dispatch_match_tokens "$proto" "$ipver")
                printf '        %s jump %s\n' "$match_tokens" "$(_pfwd_subchain_name prerouting "$proto" "$ipver")"
            done
        done
        printf '    }\n\n'

        printf '    chain postrouting {\n'
        printf '        type nat hook postrouting priority srcnat; policy accept;\n'
        for ipver in 4 6; do
            for proto in tcp udp; do
                section_key="postrouting|${ipver}|${proto}"
                [[ -n "${subchain_nonempty[$section_key]:-}" ]] || continue
                match_tokens=$(_pfwd_dispatch_match_tokens "$proto" "$ipver")
                printf '        ct status dnat %s jump %s\n' "$match_tokens" "$(_pfwd_subchain_name postrouting "$proto" "$ipver")"
            done
        done
        printf '    }\n\n'

        printf '    chain forward {\n'
        printf '        type filter hook forward priority 0; policy accept;\n'
        if [[ "$flow_mode" != "disabled" && -n "$devices_csv" ]]; then
            printf '        ct state established flow add @ft counter\n'
        fi
        for ipver in 4 6; do
            for proto in tcp udp; do
                section_key="forward|${ipver}|${proto}"
                [[ -n "${subchain_nonempty[$section_key]:-}" ]] || continue
                match_tokens=$(_pfwd_dispatch_match_tokens "$proto" "$ipver")
                printf '        %s jump %s\n' "$match_tokens" "$(_pfwd_subchain_name forward "$proto" "$ipver")"
            done
        done
        printf '        ct state established,related accept\n'
        printf '    }\n\n'

        printf '    chain input {\n'
        printf '        type filter hook input priority filter - 10; policy accept;\n'
        printf '        ip daddr 127.0.0.0/8 ct status dnat counter accept comment "Allow DNAT to localhost before iptables"\n'
        printf '        ip6 daddr ::1 ct status dnat counter accept comment "Allow DNAT to localhost before iptables"\n'
        printf '    }\n\n'

        for ipver in 4 6; do
            for proto in tcp udp; do
                local pr_chain po_chain fw_chain
                pr_chain=$(_pfwd_subchain_name prerouting "$proto" "$ipver")
                po_chain=$(_pfwd_subchain_name postrouting "$proto" "$ipver")
                fw_chain=$(_pfwd_subchain_name forward "$proto" "$ipver")

                printf '    chain %s {\n' "$pr_chain"
                local key
                while IFS= read -r key; do
                    [[ -n "$key" ]] || continue
                    IFS='|' read -r key_proto key_ipver key_target key_tport key_snat_mode key_snat_source key_mss_mode key_mss_value <<< "$key"
                    [[ "$key_proto" == "$proto" && "$key_ipver" == "$ipver" ]] || continue
                    local dnat_keyword="ip" dnat_target="" port_expr=""
                    port_expr=$(_pfwd_ports_to_nft_expr "${prerouting_ports[$key]}")
                    if [[ "$ipver" == "6" ]]; then
                        dnat_keyword="ip6"
                        dnat_target="[$key_target]:$key_tport"
                    else
                        dnat_target="$key_target:$key_tport"
                    fi
                    printf '        %s dport %s dnat %s to %s\n' "$proto" "$port_expr" "$dnat_keyword" "$dnat_target"
                done < <(printf '%s\n' "${!prerouting_ports[@]}" | sort)
                printf '    }\n\n'

                printf '    chain %s {\n' "$po_chain"
                while IFS= read -r key; do
                    [[ -n "$key" ]] || continue
                    IFS='|' read -r key_proto key_ipver key_target key_tport key_snat_mode key_snat_source key_mss_mode key_mss_value <<< "$key"
                    [[ "$key_proto" == "$proto" && "$key_ipver" == "$ipver" ]] || continue
                    if [[ "$key_snat_mode" == "snat" && -n "$key_snat_source" ]]; then
                        printf '        ct status dnat %s daddr %s %s dport %s snat to %s\n' \
                            "$([[ "$ipver" == "6" ]] && echo ip6 || echo ip)" "$key_target" "$proto" "$key_tport" "$key_snat_source"
                    else
                        printf '        ct status dnat %s daddr %s %s dport %s masquerade\n' \
                            "$([[ "$ipver" == "6" ]] && echo ip6 || echo ip)" "$key_target" "$proto" "$key_tport"
                    fi
                done < <(printf '%s\n' "${!postrouting_keys[@]}" | sort)
                printf '    }\n\n'

                printf '    chain %s {\n' "$fw_chain"
                while IFS= read -r key; do
                    [[ -n "$key" ]] || continue
                    IFS='|' read -r key_proto key_ipver key_target key_tport key_snat_mode key_snat_source key_mss_mode key_mss_value <<< "$key"
                    [[ "$key_proto" == "$proto" && "$key_ipver" == "$ipver" ]] || continue
                    if [[ "$key_mss_mode" == "clamp" ]]; then
                        printf '        %s daddr %s tcp dport %s tcp flags syn / syn,rst tcp option maxseg size set rt mtu\n' \
                            "$([[ "$ipver" == "6" ]] && echo ip6 || echo ip)" "$key_target" "$key_tport"
                    elif [[ "$key_mss_mode" == "set" && -n "$key_mss_value" ]]; then
                        printf '        %s daddr %s tcp dport %s tcp flags syn / syn,rst tcp option maxseg size set %s\n' \
                            "$([[ "$ipver" == "6" ]] && echo ip6 || echo ip)" "$key_target" "$key_tport" "$key_mss_value"
                    fi
                done < <(printf '%s\n' "${!forward_keys[@]}" | sort)
                printf '    }\n\n'
            done
        done
        echo "}"
    } > "$output_file"
}

_pfwd_validate_rendered_nft() {
    local filepath="$1"
    local validate_tmp
    validate_tmp=$(_mktemp_in_dir "$filepath.validate") || return 1
    sed 's/^table inet port_forward /table inet pfwd_validate /' "$filepath" > "$validate_tmp"
    local result=0
    nft -c -f "$validate_tmp" >/dev/null 2>&1 || result=$?
    rm -f "$validate_tmp" 2>/dev/null || true
    return "$result"
}

_pfwd_apply_rendered_nft() {
    local filepath="$1"
    ensure_ip_forwarding 2>/dev/null || true
    apply_bql_limits 65536 >/dev/null 2>&1 || true
    plat_nft_delete_table $NFT_TABLE || true
    if ! plat_nft_apply_file "$filepath"; then
        return 1
    fi
    _nft_invalidate_cache
    _nft_table_exists
}

pfwd_apply_saved_state() {
    local state_file="${1:-}" rules runtime_rules devices_csv=""
    local generated_ok=false flow_mode candidate_file parsed_runtime=""

    ensure_nft || return 1
    pfwd_state_ensure_initialized
    if [[ -n "$state_file" ]]; then
        rules=$(pfwd_state_rules_tsv "$state_file")
    else
        rules=$(pfwd_state_rules_tsv)
    fi

    if [[ -z "$rules" ]]; then
        plat_nft_delete_table $NFT_TABLE || true
        _nft_invalidate_cache
        rm -f "$NFT_CONFIG"
        sync_managed_firewall_state "" || return 1
        ufw_reload_if_enabled || true
        return 0
    fi

    runtime_rules=$(_pfwd_state_runtime_rules_tsv "$rules" "true") || return 1
    [[ -n "$runtime_rules" ]] || {
        msg_err "No runtime-resolved rules were produced from $RULES_STATE_FILE"
        return 1
    }

    devices_csv=$(_pfwd_collect_flowtable_devices "$runtime_rules" || true)
    parsed_runtime=$(_pfwd_runtime_rules_to_parsed_tsv "$runtime_rules")

    for flow_mode in $(_pfwd_flowtable_modes "$devices_csv"); do
        candidate_file=$(_mktemp_in_dir "$NFT_CONFIG") || return 1
        _pfwd_render_nft_config "$runtime_rules" "$candidate_file" "$flow_mode" "$devices_csv"
        if ! _pfwd_validate_rendered_nft "$candidate_file"; then
            rm -f "$candidate_file" 2>/dev/null || true
            continue
        fi
        if ! _pfwd_apply_rendered_nft "$candidate_file"; then
            rm -f "$candidate_file" 2>/dev/null || true
            continue
        fi
        if [[ "$flow_mode" != "disabled" ]]; then
            msg_dim "  Flowtable mode: $flow_mode (${devices_csv//,/ })"
        else
            msg_dim "  Flowtable mode: disabled"
        fi
        if [[ "$_NFT_BACKUP_NEEDED" == true ]]; then
            _backup_nft_config
        fi
        _atomic_replace_file "$candidate_file" "$NFT_CONFIG" 0644
        generated_ok=true
        break
    done

    $generated_ok || {
        msg_err "Failed to render/apply nftables state from $RULES_STATE_FILE"
        return 1
    }

    _NFT_BACKUP_NEEDED=false
    _nft_invalidate_cache
    if awk -F'\t' '$4 ~ /^127\./ || $4 == "::1" { found=1 } END { exit(found ? 0 : 1) }' <<< "$rules"; then
        ensure_route_localnet
    fi

    _DIRTY_UFW_SYNC=true
    sync_managed_firewall_state "$parsed_runtime" || return 1
    if $_DIRTY_UFW_RELOAD; then
        ufw_reload_if_enabled || return 1
        sync_managed_iptables_accept_rules "$parsed_runtime" || return 1
    fi
    return 0
}

traffic_validate_interval() {
    case "${1:-}" in
        30s|1m|5m|10m|30m|1h) return 0 ;;
        *) return 1 ;;
    esac
}

traffic_current_interval() {
    local interval=""
    if [[ -f "$TRAFFIC_SAVE_TIMER" ]]; then
        interval=$(awk -F'=' '/^OnUnitActiveSec=/{print $2; exit}' "$TRAFFIC_SAVE_TIMER" 2>/dev/null || true)
    fi
    if traffic_validate_interval "$interval"; then
        echo "$interval"
    else
        echo "$TRAFFIC_DEFAULT_INTERVAL"
    fi
}

traffic_write_timer_unit() {
    local interval="${1:-$(traffic_current_interval)}"
    traffic_validate_interval "$interval" || {
        msg_err "Invalid traffic interval: $interval"
        return 1
    }

    local timer_tmp
    timer_tmp=$(_mktemp_in_dir "$TRAFFIC_SAVE_TIMER") || return 1
    cat > "$timer_tmp" << EOF
[Unit]
Description=Periodically save pfwd traffic statistics

[Timer]
OnBootSec=$interval
OnUnitActiveSec=$interval
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
    _atomic_replace_file "$timer_tmp" "$TRAFFIC_SAVE_TIMER" 0644
}

traffic_configure_interval() {
    local interval="$1"
    require_root "$0 stats --interval $interval"
    traffic_validate_interval "$interval" || {
        msg_err "Unsupported interval: $interval"
        msg_err "Use one of: 30s, 1m, 5m, 10m, 30m, 1h"
        return 1
    }
    traffic_write_timer_unit "$interval" || return 1
    plat_systemctl_daemon_reload
    if [[ -f "$TRAFFIC_SAVE_SERVICE" ]]; then
        plat_systemctl_enable_now pfwd-traffic-save.timer
    fi
    msg_ok "Traffic collector interval set to $interval"
}

_traffic_delete_records() {
    local scope="$1" key1="${2:-}" key2="${3:-}" key3="${4:-}" key4="${5:-}" key5="${6:-}"
    local filepath tmp_file
    for filepath in "$TRAFFIC_DATA" "$TRAFFIC_FLOW_DATA"; do
        [[ -f "$filepath" ]] || continue
        tmp_file=$(_mktemp_in_dir "$filepath") || return 1

        awk -F'|' -v scope="$scope" -v key1="$key1" -v key2="$key2" -v key3="$key3" -v key4="$key4" -v key5="$key5" '
            function keep_line() {
                print $0
            }
            scope == "nft_rule" {
                if (($2 == "nft_rule" || $2 == "nft_flow") && $3 == key1 && $4 == key2 && $5 == key3) {
                    if (($1 == "v4" || $1 == "v2") && $6 == key4 && $7 == key5) next
                    if ($1 != "v4" && $1 != "v2") next
                }
                if ($1 == key1 && $2 == key2 && $3 == key3 && (NF == 7 || NF == 9)) next
                keep_line()
                next
            }
            scope == "nft_port" {
                if (($2 == "nft_rule" || $2 == "nft_flow") && $4 == key1 && (key2 == "both" || $3 == key2)) next
                if ((NF == 7 || NF == 9) && $2 == key1 && (key2 == "both" || $1 == key2)) next
                keep_line()
                next
            }
            scope == "nft_all" {
                if ($2 == "nft_rule" || $2 == "nft_flow" || NF == 7 || NF == 9) next
                keep_line()
                next
            }
            { keep_line() }
        ' "$filepath" > "$tmp_file"

        _atomic_replace_file "$tmp_file" "$filepath" 0644
    done
}

_backup_nft_config() {
    [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]] || return 0
    mkdir -p "$NFT_BACKUP_DIR"
    cp "$NFT_CONFIG" "$NFT_BACKUP_DIR/nftables_$(date +%Y%m%d_%H%M%S).nft" 2>/dev/null || true

    local -a backups=()
    local backup_path
    shopt -s nullglob
    backups=("$NFT_BACKUP_DIR"/nftables_*.nft)
    shopt -u nullglob
    (( ${#backups[@]} > 5 )) || return 0

    mapfile -t backups < <(printf '%s\n' "${backups[@]}" | sort)
    while (( ${#backups[@]} > 5 )); do
        backup_path="${backups[0]}"
        rm -f -- "$backup_path" 2>/dev/null || true
        backups=("${backups[@]:1}")
    done
}

# nft batch file for atomic operations (Phase 2)
_NFT_BATCH_FILE=""

# No-clear flag for interactive menu
_NO_CLEAR=false

# Change tracking flags (coalesce save/reload/restart side effects)
_DIRTY_NFT=false
_DIRTY_UFW_SYNC=false
_DIRTY_UFW_RELOAD=false
_NFT_BACKUP_NEEDED=false
_UFW_FILES_CHANGED=false

# Cached nft snapshot for repeated read-only views
_NFT_SNAPSHOT_READY=false
_NFT_SNAPSHOT_CACHE_TIME=0
_NFT_SNAPSHOT_PREROUTING=""
_NFT_SNAPSHOT_PARSED=""
_NFT_SNAPSHOT_POSTROUTING=""
_NFT_SNAPSHOT_FORWARD=""
declare -A _NFT_SNAPSHOT_SNAT_MODE=()
declare -A _NFT_SNAPSHOT_SNAT_SOURCE=()
declare -A _NFT_SNAPSHOT_MSS_MODE=()
declare -A _NFT_SNAPSHOT_MSS_VALUE=()
declare -A _NFT_SNAPSHOT_OUT_BYTES=()

# Shared add workflow result state
PFWD_ADD_ADDED=0
PFWD_ADD_FAILED=0
PFWD_ADD_TOTAL=0
PFWD_SHORTCUT_ARGS=()
PFWD_IMPORT_PATH=""
PFWD_IMPORT_METHOD=""
PFWD_EFFECTIVE_IP_VER=""
PFWD_REQUEST_IP_VER=""
PFWD_STATE_BATCH_FILE=""
PFWD_STATE_TARGET_FILE=""

# Cached state snapshot for UI/status views
PFWD_NFT_RULES=""
PFWD_NFT_COUNT=0
PFWD_NFT_RUNNING=false
PFWD_BBR_ENABLED=false
PFWD_LOOPBACK_DNAT=false
PFWD_UFW_LOOPBACK_STATE="n/a"
PFWD_TRAFFIC_INTERVAL="$TRAFFIC_DEFAULT_INTERVAL"
PFWD_TRAFFIC_BACKEND="none"
PFWD_HEALTH_HAS_IPV4_RULES=false
PFWD_HEALTH_HAS_IPV6_RULES=false
PFWD_HEALTH_HAS_LOOPBACK_RULES=false
PFWD_IPTABLES_V4_FORWARD_STATE="n/a"
PFWD_IPTABLES_V6_FORWARD_STATE="n/a"
PFWD_IPTABLES_V4_INPUT_STATE="n/a"
PFWD_IPTABLES_V6_INPUT_STATE="n/a"
PFWD_UFW_PERSISTENCE_STATE="n/a"
PFWD_RUNTIME_HEALTH_DEGRADED=false
_TRAFFIC_SNAPSHOT_RULES=""
_TRAFFIC_SNAPSHOT_FLOWS=""
_TRAFFIC_DATA_WARNED=false
_TRAFFIC_FLOW_WARNED=false

# Network detection cache
_NET_CACHE_TIME=0
_AUTO_SHORTCUT_CHECKED=false

#===============================================================================
#  Section 2: Domain Utilities & Validation
#===============================================================================

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}" >&2
        echo "Try: sudo $0 $*" >&2
        exit 1
    fi
}

can_prompt_user() {
    [[ -t 0 && -t 1 ]]
}

cli_requires_root() {
    if [[ $# -eq 0 ]]; then
        return 0
    fi

    case "$1" in
        -q|--quiet|--no-color|--no-clear)
            shift
            cli_requires_root "$@"
            return
            ;;
    esac

    if [[ $# -ge 2 && "$1" =~ ^[0-9] && ! "$1" =~ ^- && -n "${2:-}" && ! "${2:-}" =~ ^- ]]; then
        return 0
    fi

    case "${1:-}" in
        help|--help|-h|--version|-v|list|ls|status|doctor|diagnose|verify|export)
            return 1
            ;;
        stats|traffic)
            [[ "${2:-}" == "--interval" && -n "${3:-}" ]] && return 0
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

require_option_value() {
    local option="$1"
    local value_candidate="${2-}"
    if [[ "$value_candidate" == "$option" ]]; then
        value_candidate="${3-}"
    fi
    if [[ -z "$value_candidate" || "$value_candidate" == -* ]]; then
        msg_err "Option $option requires a value"
        return 1
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

_pfwd_port_usage_collect() {
    $_PORT_USAGE_SNAPSHOT_READY && return 0

    if command -v ss >/dev/null 2>&1; then
        _PORT_USAGE_BACKEND="ss"
        _PORT_USAGE_TCP_LISTEN=$(ss -H -tln 2>/dev/null || true)
        _PORT_USAGE_TCP_PROC=$(ss -H -tlnp 2>/dev/null || true)
        _PORT_USAGE_UDP_LISTEN=$(ss -H -uln 2>/dev/null || true)
        _PORT_USAGE_UDP_PROC=$(ss -H -ulnp 2>/dev/null || true)
    elif command -v netstat >/dev/null 2>&1; then
        _PORT_USAGE_BACKEND="netstat"
        _PORT_USAGE_TCP_LISTEN=$(netstat -tln 2>/dev/null || true)
        _PORT_USAGE_UDP_LISTEN=$(netstat -uln 2>/dev/null || true)
        _PORT_USAGE_TCP_PROC=""
        _PORT_USAGE_UDP_PROC=""
    else
        _PORT_USAGE_BACKEND="none"
        _PORT_USAGE_TCP_LISTEN=""
        _PORT_USAGE_TCP_PROC=""
        _PORT_USAGE_UDP_LISTEN=""
        _PORT_USAGE_UDP_PROC=""
    fi

    _PORT_USAGE_SNAPSHOT_READY=true
}

_pfwd_port_snapshot_match() {
    local snapshot="$1" port="$2"
    [[ -n "$snapshot" ]] || return 1
    grep -Eq "(^|[[:space:]])[^[:space:]]*:${port}([[:space:]]|$)" <<< "$snapshot"
}

# check_port_in_use <port> [proto] - Check if port is in use
# proto: tcp/udp/both (default: tcp)
# Returns: 0=not in use, 1=in use
check_port_in_use() {
    local port=$1
    local proto=${2:-tcp}
    local process_info=""

    _pfwd_port_usage_collect

    # Check TCP port
    if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
        if [[ "$_PORT_USAGE_BACKEND" == "ss" || "$_PORT_USAGE_BACKEND" == "netstat" ]]; then
            if _pfwd_port_snapshot_match "$_PORT_USAGE_TCP_LISTEN" "$port"; then
                msg_warn "Port $port (TCP) is already in use"
                if [[ "$_PORT_USAGE_BACKEND" == "ss" ]]; then
                    process_info=$(grep -E "(^|[[:space:]])[^[:space:]]*:${port}([[:space:]]|$)" <<< "$_PORT_USAGE_TCP_PROC" | head -1 || true)
                    if [[ -n "$process_info" ]]; then
                        msg_dim "  Process: $process_info"
                    fi
                fi
                if ! can_prompt_user; then
                    msg_err "Port $port (TCP) is already in use; refusing to continue in non-interactive mode"
                    return 1
                fi
                read -rp "Continue adding rule anyway? [y/N]: " confirm
                [[ "$confirm" =~ ^[Yy]$ ]] || return 1
            fi
        fi
    fi

    # Check UDP port
    if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
        if [[ "$_PORT_USAGE_BACKEND" == "ss" || "$_PORT_USAGE_BACKEND" == "netstat" ]]; then
            if _pfwd_port_snapshot_match "$_PORT_USAGE_UDP_LISTEN" "$port"; then
                msg_warn "Port $port (UDP) is already in use"
                if [[ "$_PORT_USAGE_BACKEND" == "ss" ]]; then
                    process_info=$(grep -E "(^|[[:space:]])[^[:space:]]*:${port}([[:space:]]|$)" <<< "$_PORT_USAGE_UDP_PROC" | head -1 || true)
                    if [[ -n "$process_info" ]]; then
                        msg_dim "  Process: $process_info"
                    fi
                fi
                if ! can_prompt_user; then
                    msg_err "Port $port (UDP) is already in use; refusing to continue in non-interactive mode"
                    return 1
                fi
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

# detect_script_path - detect a persistent executable path for systemd units
detect_script_path() {
    local resolved_path=""
    if [[ -f "$0" && -x "$0" && ! "$0" =~ ^/dev/fd/ && ! "$0" =~ ^/proc/ ]]; then
        resolved_path=$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || true)
        if [[ -n "$resolved_path" && -x "$resolved_path" ]]; then
            SCRIPT_PATH="$resolved_path"
            return 0
        fi
    fi

    if [[ -x "$SHORTCUT_LINK" ]]; then
        SCRIPT_PATH="$SHORTCUT_LINK"
        return 0
    fi

    for path in "$INSTALLED_SCRIPT" "/usr/bin/pfwd" "/usr/bin/pfwd.sh"; do
        if [[ -x "$path" ]]; then
            SCRIPT_PATH="$path"
            return 0
        fi
    done

    SCRIPT_PATH=""
    return 1
}

ensure_shortcut_command() {
    $_AUTO_SHORTCUT_CHECKED && return 0
    _AUTO_SHORTCUT_CHECKED=true

    local quiet_requested=false
    local arg
    for arg in "$@"; do
        case "$arg" in
            -q|--quiet)
                quiet_requested=true
                break
                ;;
        esac
    done

    local source_path="${SCRIPT_PATH:-}"
    [[ -n "$source_path" && -x "$source_path" ]] || return 0
    [[ "$source_path" == "$SHORTCUT_LINK" ]] && return 0

    if [[ $EUID -ne 0 ]]; then
        [[ -x "$SHORTCUT_LINK" ]] || $quiet_requested || msg_dim "  Tip: run once as root from a persistent path to install $SHORTCUT_LINK"
        return 0
    fi

    mkdir -p "$(dirname "$SHORTCUT_LINK")" 2>/dev/null || true

    if [[ -e "$SHORTCUT_LINK" && ! -L "$SHORTCUT_LINK" ]]; then
        local existing_path=""
        existing_path=$(realpath "$SHORTCUT_LINK" 2>/dev/null || readlink -f "$SHORTCUT_LINK" 2>/dev/null || true)
        [[ "$existing_path" == "$source_path" ]] && return 0
        $quiet_requested || msg_warn "$SHORTCUT_LINK exists as a regular file; leaving it unchanged"
        return 0
    fi

    local current_target=""
    if [[ -L "$SHORTCUT_LINK" ]]; then
        current_target=$(readlink -f "$SHORTCUT_LINK" 2>/dev/null || true)
        [[ "$current_target" == "$source_path" ]] && return 0
    fi

    if ln -sfn "$source_path" "$SHORTCUT_LINK" 2>/dev/null; then
        $quiet_requested || msg_ok "Installed shortcut command: $SHORTCUT_LINK"
    else
        $quiet_requested || msg_warn "Unable to install shortcut command at $SHORTCUT_LINK"
    fi
}

# detect_ip_type <address> -> "ipv4" | "ipv6" | "domain" | "unknown"
detect_ip_type() {
    local addr="$1"

    # IPv4 验证：检查格式和数值范围
    if [[ "$addr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        local o1="${BASH_REMATCH[1]}" o2="${BASH_REMATCH[2]}"
        local o3="${BASH_REMATCH[3]}" o4="${BASH_REMATCH[4]}"
        if (( o1 <= 255 && o2 <= 255 && o3 <= 255 && o4 <= 255 )); then
            echo "ipv4"
            return 0
        fi
    fi

    # IPv6 验证：使用更严格的正则表达式
    if [[ "$addr" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]] || \
       [[ "$addr" =~ ^::([0-9a-fA-F]{0,4}:){0,6}[0-9a-fA-F]{0,4}$ ]] || \
       [[ "$addr" =~ ^([0-9a-fA-F]{0,4}:){1,6}:$ ]]; then
        echo "ipv6"
        return 0
    fi

    # 域名验证
    if [[ "$addr" =~ ^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$ ]]; then
        echo "domain"
        return 0
    fi

    echo "unknown"
    return 1
}

# validate_target_reachable <target> - 验证目标地址是否可达
validate_target_reachable() {
    local target="$1"
    local target_type
    target_type=$(detect_ip_type "$target")

    case "$target_type" in
        ipv4|ipv6)
            # 使用 ping 测试连通性（可选，用户可通过 --skip-ping 跳过）
            if [[ "${SKIP_PING_CHECK:-false}" != "true" ]]; then
                if ! ping -c 1 -W 2 "$target" >/dev/null 2>&1; then
                    msg_warn "Target $target is not reachable (ping failed)"
                    if ! can_prompt_user; then
                        msg_err "Target $target is not reachable; refusing to continue in non-interactive mode"
                        return 1
                    fi
                    read -rp "Continue anyway? [y/N]: " confirm
                    [[ "$confirm" =~ ^[Yy]$ ]] || return 1
                fi
            fi
            ;;
        domain)
            # 验证域名可以解析
            if ! getent ahosts "$target" >/dev/null 2>&1; then
                msg_err "Cannot resolve domain: $target"
                return 1
            fi
            ;;
        *)
            msg_err "Invalid target address: $target"
            return 1
            ;;
    esac
    return 0
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

validate_snat_request() {
    local ip_ver="${1:-46}" snat_mode="${2:-masquerade}" snat_source="${3:-}" emit_notice="${4:-false}"
    PFWD_EFFECTIVE_IP_VER="$ip_ver"
    [[ "$snat_mode" == "snat" ]] || return 0

    local snat_type expected_ipver expected_label
    snat_type=$(detect_ip_type "$snat_source")
    case "$snat_type" in
        ipv4)
            expected_ipver="4"
            expected_label="IPv4"
            ;;
        ipv6)
            expected_ipver="6"
            expected_label="IPv6"
            ;;
        *)
            msg_err "Invalid SNAT source address: $snat_source"
            return 1
            ;;
    esac

    if [[ "$ip_ver" == "46" ]]; then
        PFWD_EFFECTIVE_IP_VER="$expected_ipver"
        if [[ "$emit_notice" == "true" ]]; then
            msg_info "Fixed SNAT is single-stack; auto-switched to IPv${expected_ipver}"
        fi
    fi

    if [[ "$PFWD_EFFECTIVE_IP_VER" != "$expected_ipver" ]]; then
        msg_err "SNAT source $snat_source is $expected_label but rule family is IPv${PFWD_EFFECTIVE_IP_VER}"
        return 1
    fi
}

# validate_mss_value <value> -> 0=valid, 1=invalid
validate_mss_value() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 536 && value <= 65535 ))
}

_mss_default_probe_target() {
    local family_flag="$1"
    case "$family_flag" in
        -4) printf '1.1.1.1\n' ;;
        -6) printf '2001:4860:4860::8888\n' ;;
        *) return 1 ;;
    esac
}

_mss_route_probe() {
    local family_flag="$1" route_target="$2" route_source="${3:-}"
    local route_output
    if [[ -n "$route_source" ]]; then
        route_output=$(ip -o "$family_flag" route get "$route_target" from "$route_source" 2>/dev/null | head -1 || true)
    else
        route_output=$(ip -o "$family_flag" route get "$route_target" 2>/dev/null | head -1 || true)
    fi
    [[ -n "$route_output" ]] || return 1
    printf '%s\n' "$route_output"
}

_mss_route_field() {
    local route_output="$1" field_name="$2"
    local prev="" token
    for token in $route_output; do
        if [[ "$prev" == "$field_name" ]]; then
            printf '%s\n' "$token"
            return 0
        fi
        prev="$token"
    done
    return 1
}

_mss_iface_for_address() {
    local family_flag="$1" target_addr="$2"
    local _idx iface _family addr _rest
    while read -r _idx iface _family addr _rest; do
        [[ "${addr%/*}" == "$target_addr" ]] || continue
        printf '%s\n' "$iface"
        return 0
    done < <(ip -o "$family_flag" addr show 2>/dev/null)
    return 1
}

_iface_link_mtu() {
    local iface="$1"
    ip -o link show dev "$iface" 2>/dev/null | awk '
        {
            for (i = 1; i <= NF; i++) {
                if ($i == "mtu") {
                    print $(i + 1)
                    exit
                }
            }
        }
    '
}

_iface_is_pppoe_like() {
    local iface="$1"
    [[ -n "$iface" ]] || return 1
    [[ "$iface" == ppp* ]] && return 0
    ip -d link show dev "$iface" 2>/dev/null | grep -Eqi 'ppp|pppoe|pointopoint'
}

_mss_resolve_target_for_family() {
    local target="$1" family="$2"
    local target_type resolved=""
    case "$family" in
        ipv4|4) family="ipv4" ;;
        ipv6|6) family="ipv6" ;;
        *) return 1 ;;
    esac

    target_type=$(detect_ip_type "$target")
    case "$target_type" in
        "$family")
            printf '%s\n' "$target"
            return 0
            ;;
        domain)
            if [[ "$family" == "ipv4" ]]; then
                resolved=$(getent ahosts "$target" 2>/dev/null | awk '/STREAM/{print $1}' | grep -E '^[0-9]+\.' | head -1 || true)
            else
                resolved=$(getent ahosts "$target" 2>/dev/null | awk '/STREAM/{print $1}' | grep ':' | head -1 || true)
            fi
            [[ -n "$resolved" ]] || return 1
            printf '%s\n' "$resolved"
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

_mss_collect_path_mtu() {
    local family_flag="$1" route_target="$2" fallback_addr="${3:-}" route_source="${4:-}"
    local route_output="" route_iface="" route_mtu="" route_advmss="" iface="" mtu="" effective_mtu=""
    local pppoe_overhead=8

    MSS_PATH_IFACE=""
    MSS_PATH_MTU=""
    MSS_PATH_ROUTE_MTU=""
    MSS_PATH_ADVMSS=""
    MSS_PATH_EFFECTIVE_MTU=""
    MSS_PATH_PPPoE="false"
    MSS_PATH_SUGGESTED_MSS=""
    MSS_PATH_SOURCE_KIND=""

    route_output=$(_mss_route_probe "$family_flag" "$route_target" "$route_source") || route_output=""
    if [[ -n "$route_output" ]]; then
        route_iface=$(_mss_route_field "$route_output" dev || true)
        route_mtu=$(_mss_route_field "$route_output" mtu || true)
        route_advmss=$(_mss_route_field "$route_output" advmss || true)
    fi

    iface="$route_iface"
    if [[ -z "$iface" && -n "$fallback_addr" ]]; then
        iface=$(_mss_iface_for_address "$family_flag" "$fallback_addr" || true)
    fi
    [[ -n "$iface" ]] || return 1

    mtu=$(_iface_link_mtu "$iface") || true
    [[ "$mtu" =~ ^[0-9]+$ ]] || return 1

    effective_mtu="$mtu"
    if [[ "$route_mtu" =~ ^[0-9]+$ ]] && (( route_mtu > 0 && route_mtu < effective_mtu )); then
        effective_mtu="$route_mtu"
    fi

    if _iface_is_pppoe_like "$iface"; then
        MSS_PATH_PPPoE="true"
        if (( effective_mtu > 1492 )); then
            effective_mtu=$(( effective_mtu - pppoe_overhead ))
        fi
    fi

    MSS_PATH_IFACE="$iface"
    MSS_PATH_MTU="$mtu"
    MSS_PATH_ROUTE_MTU="$route_mtu"
    MSS_PATH_ADVMSS="$route_advmss"
    MSS_PATH_EFFECTIVE_MTU="$effective_mtu"
}

_mss_path_candidate_for_family() {
    local family="$1"
    local overhead candidate

    MSS_PATH_SUGGESTED_MSS=""
    MSS_PATH_SOURCE_KIND=""

    case "$family" in
        ipv4|4) overhead=40 ;;
        ipv6|6) overhead=60 ;;
        *) return 1 ;;
    esac

    if validate_mss_value "${MSS_PATH_ADVMSS:-}"; then
        MSS_PATH_SUGGESTED_MSS="$MSS_PATH_ADVMSS"
        MSS_PATH_SOURCE_KIND="advmss"
        return 0
    fi

    [[ "${MSS_PATH_EFFECTIVE_MTU:-}" =~ ^[0-9]+$ ]] || return 1
    candidate=$(( MSS_PATH_EFFECTIVE_MTU - overhead ))
    validate_mss_value "$candidate" || return 1

    MSS_PATH_SUGGESTED_MSS="$candidate"
    if [[ "${MSS_PATH_ROUTE_MTU:-}" =~ ^[0-9]+$ ]] && (( MSS_PATH_ROUTE_MTU > 0 && MSS_PATH_ROUTE_MTU < MSS_PATH_MTU )); then
        MSS_PATH_SOURCE_KIND="route-mtu"
    else
        MSS_PATH_SOURCE_KIND="link-mtu"
    fi
}

suggest_mss_for_snat_source() {
    local snat_source="$1" target="${2:-}"
    MSS_SUGGEST_IFACE=""
    MSS_SUGGEST_MTU=""
    MSS_SUGGEST_EFFECTIVE_MTU=""
    MSS_SUGGEST_VALUE=""
    MSS_SUGGEST_FAMILY=""
    MSS_SUGGEST_LOGIC=""
    MSS_SUGGEST_PPPoE="false"
    MSS_SUGGEST_SOURCE_IFACE=""
    MSS_SUGGEST_SOURCE_MTU=""
    MSS_SUGGEST_SOURCE_ROUTE_MTU=""
    MSS_SUGGEST_SOURCE_ADVMSS=""
    MSS_SUGGEST_SOURCE_EFFECTIVE_MTU=""
    MSS_SUGGEST_SOURCE_PPPoE="false"
    MSS_SUGGEST_SOURCE_VALUE=""
    MSS_SUGGEST_SOURCE_KIND=""
    MSS_SUGGEST_TARGET_ADDR=""
    MSS_SUGGEST_TARGET_IFACE=""
    MSS_SUGGEST_TARGET_MTU=""
    MSS_SUGGEST_TARGET_ROUTE_MTU=""
    MSS_SUGGEST_TARGET_ADVMSS=""
    MSS_SUGGEST_TARGET_EFFECTIVE_MTU=""
    MSS_SUGGEST_TARGET_PPPoE="false"
    MSS_SUGGEST_TARGET_VALUE=""
    MSS_SUGGEST_TARGET_KIND=""
    MSS_SUGGEST_BOTTLENECK=""

    command -v ip >/dev/null 2>&1 || return 1

    local family family_flag source_probe_target resolved_target overhead suggested selected_value selected_effective
    local ip_header_bytes tcp_header_bytes=20 chosen_ifc chosen_mtu chosen_route_mtu chosen_pppoe chosen_label
    local chosen_advmss chosen_kind
    local source_available=false target_available=false
    family=$(detect_ip_type "$snat_source")
    case "$family" in
        ipv4)
            family_flag="-4"
            overhead=40
            ip_header_bytes=20
            MSS_SUGGEST_FAMILY="IPv4"
            ;;
        ipv6)
            family_flag="-6"
            overhead=60
            ip_header_bytes=40
            MSS_SUGGEST_FAMILY="IPv6"
            ;;
        *)
            return 1
            ;;
    esac

    source_probe_target=$(_mss_default_probe_target "$family_flag" || true)
    if [[ -n "$source_probe_target" ]] && \
       _mss_collect_path_mtu "$family_flag" "$source_probe_target" "$snat_source" "$snat_source" && \
       _mss_path_candidate_for_family "$family"; then
        source_available=true
        MSS_SUGGEST_SOURCE_IFACE="$MSS_PATH_IFACE"
        MSS_SUGGEST_SOURCE_MTU="$MSS_PATH_MTU"
        MSS_SUGGEST_SOURCE_ROUTE_MTU="$MSS_PATH_ROUTE_MTU"
        MSS_SUGGEST_SOURCE_ADVMSS="$MSS_PATH_ADVMSS"
        MSS_SUGGEST_SOURCE_EFFECTIVE_MTU="$MSS_PATH_EFFECTIVE_MTU"
        MSS_SUGGEST_SOURCE_PPPoE="$MSS_PATH_PPPoE"
        MSS_SUGGEST_SOURCE_VALUE="$MSS_PATH_SUGGESTED_MSS"
        MSS_SUGGEST_SOURCE_KIND="$MSS_PATH_SOURCE_KIND"
    fi

    resolved_target=$(_mss_resolve_target_for_family "$target" "$family" || true)
    if [[ -n "$resolved_target" ]] && \
       _mss_collect_path_mtu "$family_flag" "$resolved_target" && \
       _mss_path_candidate_for_family "$family"; then
        target_available=true
        MSS_SUGGEST_TARGET_ADDR="$resolved_target"
        MSS_SUGGEST_TARGET_IFACE="$MSS_PATH_IFACE"
        MSS_SUGGEST_TARGET_MTU="$MSS_PATH_MTU"
        MSS_SUGGEST_TARGET_ROUTE_MTU="$MSS_PATH_ROUTE_MTU"
        MSS_SUGGEST_TARGET_ADVMSS="$MSS_PATH_ADVMSS"
        MSS_SUGGEST_TARGET_EFFECTIVE_MTU="$MSS_PATH_EFFECTIVE_MTU"
        MSS_SUGGEST_TARGET_PPPoE="$MSS_PATH_PPPoE"
        MSS_SUGGEST_TARGET_VALUE="$MSS_PATH_SUGGESTED_MSS"
        MSS_SUGGEST_TARGET_KIND="$MSS_PATH_SOURCE_KIND"
    fi

    $source_available || $target_available || return 1

    if $source_available && $target_available; then
        if (( MSS_SUGGEST_SOURCE_VALUE < MSS_SUGGEST_TARGET_VALUE )); then
            MSS_SUGGEST_BOTTLENECK="source"
        elif (( MSS_SUGGEST_TARGET_VALUE < MSS_SUGGEST_SOURCE_VALUE )); then
            MSS_SUGGEST_BOTTLENECK="target"
        else
            MSS_SUGGEST_BOTTLENECK="both"
        fi
    elif $source_available; then
        MSS_SUGGEST_BOTTLENECK="source"
    else
        MSS_SUGGEST_BOTTLENECK="target"
    fi

    case "$MSS_SUGGEST_BOTTLENECK" in
        source)
            selected_value="$MSS_SUGGEST_SOURCE_VALUE"
            selected_effective="$MSS_SUGGEST_SOURCE_EFFECTIVE_MTU"
            chosen_ifc="$MSS_SUGGEST_SOURCE_IFACE"
            chosen_mtu="$MSS_SUGGEST_SOURCE_MTU"
            chosen_route_mtu="$MSS_SUGGEST_SOURCE_ROUTE_MTU"
            chosen_advmss="$MSS_SUGGEST_SOURCE_ADVMSS"
            chosen_pppoe="$MSS_SUGGEST_SOURCE_PPPoE"
            chosen_kind="$MSS_SUGGEST_SOURCE_KIND"
            chosen_label="source-side"
            ;;
        target)
            selected_value="$MSS_SUGGEST_TARGET_VALUE"
            selected_effective="$MSS_SUGGEST_TARGET_EFFECTIVE_MTU"
            chosen_ifc="$MSS_SUGGEST_TARGET_IFACE"
            chosen_mtu="$MSS_SUGGEST_TARGET_MTU"
            chosen_route_mtu="$MSS_SUGGEST_TARGET_ROUTE_MTU"
            chosen_advmss="$MSS_SUGGEST_TARGET_ADVMSS"
            chosen_pppoe="$MSS_SUGGEST_TARGET_PPPoE"
            chosen_kind="$MSS_SUGGEST_TARGET_KIND"
            chosen_label="backend-side"
            ;;
        both)
            selected_value="$MSS_SUGGEST_SOURCE_VALUE"
            selected_effective="$MSS_SUGGEST_SOURCE_EFFECTIVE_MTU"
            chosen_ifc="$MSS_SUGGEST_SOURCE_IFACE"
            chosen_mtu="$MSS_SUGGEST_SOURCE_MTU"
            chosen_route_mtu="$MSS_SUGGEST_SOURCE_ROUTE_MTU"
            chosen_advmss="$MSS_SUGGEST_SOURCE_ADVMSS"
            chosen_pppoe="$MSS_SUGGEST_SOURCE_PPPoE"
            chosen_kind="$MSS_SUGGEST_SOURCE_KIND"
            chosen_label="shared"
            ;;
        *)
            return 1
            ;;
    esac

    suggested="$selected_value"
    validate_mss_value "$suggested" || return 1

    MSS_SUGGEST_IFACE="$chosen_ifc"
    MSS_SUGGEST_MTU="$chosen_mtu"
    MSS_SUGGEST_EFFECTIVE_MTU="$selected_effective"
    MSS_SUGGEST_VALUE="$suggested"
    MSS_SUGGEST_PPPoE="$chosen_pppoe"
    if $source_available && $target_available; then
        case "$MSS_SUGGEST_BOTTLENECK" in
            source)
                if [[ "$MSS_SUGGEST_SOURCE_KIND" == "advmss" ]]; then
                    MSS_SUGGEST_LOGIC="source-side route advmss ${MSS_SUGGEST_SOURCE_VALUE} via ${MSS_SUGGEST_SOURCE_IFACE}; backend-side candidate ${MSS_SUGGEST_TARGET_VALUE} to ${MSS_SUGGEST_TARGET_ADDR} via ${MSS_SUGGEST_TARGET_IFACE}; using the smaller source-side value ${suggested}"
                else
                    MSS_SUGGEST_LOGIC="source-side effective MTU ${MSS_SUGGEST_SOURCE_EFFECTIVE_MTU} on ${MSS_SUGGEST_SOURCE_IFACE}; backend-side candidate ${MSS_SUGGEST_TARGET_VALUE} to ${MSS_SUGGEST_TARGET_ADDR} via ${MSS_SUGGEST_TARGET_IFACE}; using the smaller source-side value ${selected_effective}; ${MSS_SUGGEST_FAMILY} MSS = ${selected_effective} - ${ip_header_bytes} (IP) - ${tcp_header_bytes} (TCP) = ${suggested}"
                fi
                ;;
            target)
                if [[ "$MSS_SUGGEST_TARGET_KIND" == "advmss" ]]; then
                    MSS_SUGGEST_LOGIC="source-side candidate ${MSS_SUGGEST_SOURCE_VALUE} via ${MSS_SUGGEST_SOURCE_IFACE}; backend-side route advmss ${MSS_SUGGEST_TARGET_VALUE} to ${MSS_SUGGEST_TARGET_ADDR} via ${MSS_SUGGEST_TARGET_IFACE}; using the smaller backend-side value ${suggested}"
                else
                    MSS_SUGGEST_LOGIC="source-side candidate ${MSS_SUGGEST_SOURCE_VALUE} via ${MSS_SUGGEST_SOURCE_IFACE}; backend-side effective MTU ${MSS_SUGGEST_TARGET_EFFECTIVE_MTU} to ${MSS_SUGGEST_TARGET_ADDR} via ${MSS_SUGGEST_TARGET_IFACE}; using the smaller backend-side value ${selected_effective}; ${MSS_SUGGEST_FAMILY} MSS = ${selected_effective} - ${ip_header_bytes} (IP) - ${tcp_header_bytes} (TCP) = ${suggested}"
                fi
                ;;
            both)
                if [[ "$chosen_kind" == "advmss" ]]; then
                    MSS_SUGGEST_LOGIC="source-side and backend-side both resolve to route advmss ${suggested}; using that shared ${MSS_SUGGEST_FAMILY} MSS"
                else
                    MSS_SUGGEST_LOGIC="source-side and backend-side both resolve to effective MTU ${selected_effective}; ${MSS_SUGGEST_FAMILY} MSS = ${selected_effective} - ${ip_header_bytes} (IP) - ${tcp_header_bytes} (TCP) = ${suggested}"
                fi
                ;;
        esac
    elif $source_available; then
        if [[ "$MSS_SUGGEST_SOURCE_KIND" == "advmss" ]]; then
            MSS_SUGGEST_LOGIC="backend-side path unavailable; using source-side route advmss ${suggested} on ${MSS_SUGGEST_SOURCE_IFACE}"
        else
            MSS_SUGGEST_LOGIC="backend-side path unavailable; using source-side effective MTU ${selected_effective} on ${MSS_SUGGEST_SOURCE_IFACE}; ${MSS_SUGGEST_FAMILY} MSS = ${selected_effective} - ${ip_header_bytes} (IP) - ${tcp_header_bytes} (TCP) = ${suggested}"
        fi
    else
        if [[ "$MSS_SUGGEST_TARGET_KIND" == "advmss" ]]; then
            MSS_SUGGEST_LOGIC="source-side path unavailable; using backend-side route advmss ${suggested} to ${MSS_SUGGEST_TARGET_ADDR} via ${MSS_SUGGEST_TARGET_IFACE}"
        else
            MSS_SUGGEST_LOGIC="source-side path unavailable; using backend-side effective MTU ${selected_effective} to ${MSS_SUGGEST_TARGET_ADDR} via ${MSS_SUGGEST_TARGET_IFACE}; ${MSS_SUGGEST_FAMILY} MSS = ${selected_effective} - ${ip_header_bytes} (IP) - ${tcp_header_bytes} (TCP) = ${suggested}"
        fi
    fi
    return 0
}

validate_comment() {
    local comment="${1:-}"
    [[ "$comment" != *$'\n'* && "$comment" != *$'\r'* && "$comment" != *$'\t'* ]]
}

nft_escape_string() {
    local value="${1:-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s' "$value"
}

nft_quote_token() {
    printf '"%s"' "$(nft_escape_string "${1:-}")"
}

nft_join_tokens() {
    local line="" token
    for token in "$@"; do
        [[ -n "$line" ]] && line+=" "
        line+="$token"
    done
    printf '%s' "$line"
}

nft_append_command() {
    local file="$1"
    shift
    nft_join_tokens "$@" >> "$file"
    printf '\n' >> "$file"
}

_nft_stage_delete_handle() {
    local chain="$1" handle="$2"
    [[ -n "$chain" && -n "$handle" ]] || return 1
    if $_BATCH_MODE && [[ -n "${_NFT_BATCH_FILE:-}" ]]; then
        nft_append_command "$_NFT_BATCH_FILE" delete rule $NFT_TABLE "$chain" handle "$handle"
    else
        plat_nft_delete_rule_handle $NFT_TABLE "$chain" "$handle"
    fi
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

_validate_add_request() {
    local method="$1" ip_ver="${2:-46}" target="$3" rules_str="$4" comment="$5"
    local mss_mode="${6:-}" mss_value="${7:-}" snat_mode="${8:-masquerade}" snat_source="${9:-}" replace_mode="${10:-false}"

    if [[ -z "$method" ]]; then
        msg_err "Method is required. Use -m nft"
        return 1
    fi
    if [[ "$method" == "realm" ]]; then
        return 0
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
    if ! validate_comment "$comment"; then
        msg_err "Comment must be a single line without tabs"
        return 1
    fi
    if [[ "$snat_mode" == "snat" ]]; then
        if [[ "$method" != "nft" ]]; then
            msg_err "Fixed SNAT source is only supported with -m nft"
            return 1
        fi
        validate_snat_request "$ip_ver" "$snat_mode" "$snat_source" "true" || return 1
    fi
    if [[ "$replace_mode" == "true" && "$method" != "nft" ]]; then
        msg_err "--replace is only supported with -m nft"
        return 1
    fi
    if ! validate_target "$target"; then
        msg_err "Invalid target: $target"
        return 1
    fi
}

_prepare_add_request() {
    local method="$1" ip_ver="${2:-46}" target="$3" rules_str="$4" comment="$5"
    local mss_mode="${6:-}" mss_value="${7:-}" snat_mode="${8:-masquerade}" snat_source="${9:-}" replace_mode="${10:-false}"
    PFWD_REQUEST_IP_VER="$ip_ver"

    if ! _validate_add_request "$method" "$ip_ver" "$target" "$rules_str" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode"; then
        return 1
    fi
    if [[ "$snat_mode" == "snat" ]]; then
        PFWD_REQUEST_IP_VER="${PFWD_EFFECTIVE_IP_VER:-$ip_ver}"
    fi
    [[ "$method" == "realm" ]] && return 0

    if ! expand_port_spec "$rules_str" "$target"; then
        return 1
    fi
}

_execute_add_request() {
    local method="$1" ip_ver="$2" proto="$3" comment="$4"
    local mss_mode="${5:-}" mss_value="${6:-}" snat_mode="${7:-masquerade}" snat_source="${8:-}" replace_mode="${9:-false}"
    local progress_label="${10:-Adding}" progress_mode="${11:-false}"
    local added=0 failed=0 progress_idx=0
    local total_rules=${#EXPANDED_RULES[@]}

    PFWD_ADD_ADDED=0
    PFWD_ADD_FAILED=0
    PFWD_ADD_TOTAL=$total_rules

    ensure_ip_forwarding 2>/dev/null || true

    _BATCH_MODE=true

    local expanded
    for expanded in "${EXPANDED_RULES[@]}"; do
        ((progress_idx++)) || true
        if [[ "$progress_mode" == "true" && $total_rules -gt 3 ]]; then
            show_progress "$progress_idx" "$total_rules" "$progress_label"
        fi
        if ! parse_rule "$expanded"; then
            ((failed++)) || true
            continue
        fi
        if _dispatch_add_rule "$method" "$RULE_LPORT" "$RULE_TARGET" "$RULE_TPORT" "$ip_ver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode"; then
            ((added++)) || true
        else
            ((failed++)) || true
        fi
    done

    _BATCH_MODE=false
    if ! _batch_finalize "$method"; then
        failed=$(( failed + added ))
        added=0
        PFWD_ADD_ADDED=$added
        PFWD_ADD_FAILED=$failed
        return 1
    fi

    PFWD_ADD_ADDED=$added
    PFWD_ADD_FAILED=$failed
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

_pfwd_os_release_value() {
    local key="$1"
    [[ -r /etc/os-release ]] || return 1
    awk -F= -v lookup="$key" '
        $1 == lookup {
            value=$2
            gsub(/^"/, "", value)
            gsub(/"$/, "", value)
            print value
            exit
        }
    ' /etc/os-release
}

_pfwd_detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
        return 0
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
        return 0
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
        return 0
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper"
        return 0
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
        return 0
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
        return 0
    fi

    local os_id os_like
    os_id=$(_pfwd_os_release_value ID 2>/dev/null || true)
    os_like=$(_pfwd_os_release_value ID_LIKE 2>/dev/null || true)

    case " $os_id $os_like " in
        *" debian "*|*" ubuntu "*) echo "apt" ;;
        *" fedora "*) echo "dnf" ;;
        *" rocky "*|*" almalinux "*|*" amzn "*|*" ol "*) echo "dnf" ;;
        *" rhel "*|*" centos "*) echo "yum" ;;
        *" opensuse "*|*" suse "*) echo "zypper" ;;
        *" arch "*) echo "pacman" ;;
        *" alpine "*) echo "apk" ;;
        *) echo "unknown" ;;
    esac
}

_pfwd_package_name_for_tool() {
    local manager="$1" tool="$2"
    case "$tool:$manager" in
        nft:*) echo "nftables" ;;
        ip:dnf|ip:yum) echo "iproute" ;;
        ip:*) echo "iproute2" ;;
        jq:*) echo "jq" ;;
        conntrack:apt) echo "conntrack" ;;
        conntrack:*) echo "conntrack-tools" ;;
        *) return 1 ;;
    esac
}

_pfwd_install_command_for_tools() {
    local manager="$1"
    shift || true

    local tool pkg
    local -a packages=()
    local -A seen=()

    for tool in "$@"; do
        pkg=$(_pfwd_package_name_for_tool "$manager" "$tool" 2>/dev/null || true)
        [[ -n "$pkg" ]] || continue
        [[ -z "${seen[$pkg]:-}" ]] || continue
        packages+=("$pkg")
        seen["$pkg"]=1
    done

    ((${#packages[@]} > 0)) || return 1

    case "$manager" in
        apt) printf 'apt-get install -y %s\n' "${packages[*]}" ;;
        dnf) printf 'dnf install -y %s\n' "${packages[*]}" ;;
        yum) printf 'yum install -y %s\n' "${packages[*]}" ;;
        zypper) printf 'zypper install -y %s\n' "${packages[*]}" ;;
        pacman) printf 'pacman -Sy --needed %s\n' "${packages[*]}" ;;
        apk) printf 'apk add %s\n' "${packages[*]}" ;;
        *) return 1 ;;
    esac
}

_pfwd_requirement_tool_label() {
    case "${1:-}" in
        nft) echo "nft (nftables, core forwarding)" ;;
        ip) echo "ip (iproute2/iproute, network detection)" ;;
        jq) echo "jq (import/export)" ;;
        conntrack) echo "conntrack (direct traffic stats backend)" ;;
        *) echo "$1" ;;
    esac
}

_pfwd_requirement_tool_labels() {
    local tool labels=""
    for tool in "$@"; do
        labels+="${labels:+, }$(_pfwd_requirement_tool_label "$tool")"
    done
    printf '%s\n' "$labels"
}

_pfwd_print_install_hint() {
    local manager install_cmd
    manager=$(_pfwd_detect_package_manager)
    install_cmd=$(_pfwd_install_command_for_tools "$manager" "$@" 2>/dev/null || true)
    if [[ -n "$install_cmd" ]]; then
        msg_info "Install hint: $install_cmd"
    else
        msg_info "Install the missing packages with your distro package manager."
    fi
}

_pfwd_requirements_notice_marker() {
    local base_dir
    if [[ $EUID -eq 0 ]]; then
        base_dir="$DATA_DIR"
    elif [[ -n "${XDG_CACHE_HOME:-}" ]]; then
        base_dir="$XDG_CACHE_HOME/pfwd"
    elif [[ -n "${HOME:-}" ]]; then
        base_dir="$HOME/.cache/pfwd"
    else
        base_dir="/tmp/pfwd.$UID"
    fi
    printf '%s/requirements-notice.v%s\n' "$base_dir" "$REQUIREMENTS_NOTICE_VERSION"
}

_pfwd_mark_requirements_notice_seen() {
    local marker="${1:-}"
    [[ -n "$marker" ]] || return 0
    mkdir -p "$(dirname "$marker")" 2>/dev/null || return 0
    : > "$marker" 2>/dev/null || true
}

_pfwd_skip_requirements_notice() {
    if [[ $# -eq 0 ]]; then
        return 1
    fi

    case "$1" in
        -q|--quiet)
            return 0
            ;;
        help|--help|-h|--version|-v|__restore-nft|__traffic-collector)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

maybe_show_requirements_notice() {
    _pfwd_skip_requirements_notice "$@" && return 0

    local marker
    marker=$(_pfwd_requirements_notice_marker)
    [[ -f "$marker" ]] && return 0

    local -a missing_core=() missing_feature=() missing_recommended=()
    command -v nft >/dev/null 2>&1 || missing_core+=("nft")
    command -v ip >/dev/null 2>&1 || missing_core+=("ip")
    command -v jq >/dev/null 2>&1 || missing_feature+=("jq")
    command -v conntrack >/dev/null 2>&1 || missing_recommended+=("conntrack")

    if ((${#missing_core[@]} > 0 || ${#missing_feature[@]} > 0 || ${#missing_recommended[@]} > 0)); then
        msg_warn "One-time dependency hint:"
        ((${#missing_core[@]} > 0)) && msg_warn "  Missing core tools: $(_pfwd_requirement_tool_labels "${missing_core[@]}")"
        ((${#missing_feature[@]} > 0)) && msg_info "  Missing feature tools: $(_pfwd_requirement_tool_labels "${missing_feature[@]}")"
        ((${#missing_recommended[@]} > 0)) && msg_info "  Missing recommended tools: $(_pfwd_requirement_tool_labels "${missing_recommended[@]}")"
        _pfwd_print_install_hint "${missing_core[@]}" "${missing_feature[@]}" "${missing_recommended[@]}"
    fi

    _pfwd_mark_requirements_notice_seen "$marker"
}

# ensure_jq - require jq explicitly instead of installing it implicitly
ensure_jq() {
    if command -v jq >/dev/null 2>&1; then
        return 0
    fi
    msg_err "jq is required for import/export."
    _pfwd_print_install_hint jq
    return 1
}

# ensure_nft - check nftables available
ensure_nft() {
    if ! command -v nft >/dev/null 2>&1; then
        msg_err "nftables (nft) is required for forwarding."
        _pfwd_print_install_hint nft
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
    ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    echo "${ip:-}"
    return 0
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

# ensure_bbr_enabled - auto-enable BBR for optimal performance
ensure_bbr_enabled() {
    local current_cc
    current_cc=$(plat_sysctl_get net.ipv4.tcp_congestion_control "")

    if [[ "$current_cc" != "bbr" ]]; then
        msg_info "Enabling BBR congestion control for optimal performance..."

        # Check if BBR module is available
        if ! lsmod | grep -q tcp_bbr; then
            modprobe tcp_bbr 2>/dev/null || true
        fi

        # Temporarily enable BBR
        plat_sysctl_set net.core.default_qdisc fq
        plat_sysctl_set net.ipv4.tcp_congestion_control bbr

        # Verify if successful
        current_cc=$(plat_sysctl_get net.ipv4.tcp_congestion_control "")
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
#  Section 3: System Policy & Kernel Tuning
#===============================================================================

sysctl_key_supported() {
    sysctl -N "$1" >/dev/null 2>&1
}

sysctl_cc_supported() {
    local cc="$1" available
    available=$(plat_sysctl_get net.ipv4.tcp_available_congestion_control "")
    [[ " $available " == *" $cc "* ]]
}

_PFWD_SYSCTL_RENDERED=""
_PFWD_SYSCTL_SKIPPED_KEYS=()

_pfwd_sysctl_reset_render() {
    _PFWD_SYSCTL_RENDERED=""
    _PFWD_SYSCTL_SKIPPED_KEYS=()
}

_pfwd_sysctl_append_line() {
    printf -v _PFWD_SYSCTL_RENDERED '%s%s\n' "$_PFWD_SYSCTL_RENDERED" "$1"
}

_pfwd_sysctl_append_section() {
    local title="$1"
    [[ -n "$_PFWD_SYSCTL_RENDERED" ]] && _pfwd_sysctl_append_line ""
    _pfwd_sysctl_append_line "# $title"
}

_pfwd_sysctl_append_setting() {
    local key="$1" value="$2"
    if sysctl_key_supported "$key"; then
        _pfwd_sysctl_append_line "$key = $value"
    else
        _PFWD_SYSCTL_SKIPPED_KEYS+=("$key")
    fi
    return 0
}

_pfwd_sysctl_print_skipped() {
    local -A seen=()
    local key
    for key in "${_PFWD_SYSCTL_SKIPPED_KEYS[@]}"; do
        [[ -n "$key" ]] || continue
        [[ -n "${seen[$key]:-}" ]] && continue
        seen["$key"]=1
        msg_dim "  Skipped unsupported sysctl: $key"
    done
}

# ensure_kernel_optimized - skip optimize_kernel if already configured
# Checks ip_forward and sysctl file; only runs full optimization if needed
ensure_ip_forwarding() {
    # Only enable IP forwarding (required for port forwarding); full kernel
    # optimization must be triggered explicitly via: pfwd optimize [profile]
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
        plat_sysctl_set net.ipv4.ip_forward 1
    fi
    if [[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" != "1" ]]; then
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true
        plat_sysctl_set net.ipv6.conf.all.forwarding 1
    fi
}

# ensure_route_localnet - enable route_localnet for DNAT to 127.0.0.0/8
# Required when forwarding to loopback (127.x.x.x) targets
ensure_route_localnet() {
    local current_all current_default
    current_all=$(plat_sysctl_get net.ipv4.conf.all.route_localnet 0)
    current_default=$(plat_sysctl_get net.ipv4.conf.default.route_localnet 0)

    [[ "$current_all" == "1" && "$current_default" == "1" ]] && return 0

    plat_sysctl_set net.ipv4.conf.all.route_localnet 1
    plat_sysctl_set net.ipv4.conf.default.route_localnet 1
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

    # 验证锚点是否存在
    if ! grep -qF "$anchor" "$file" 2>/dev/null; then
        msg_warn "UFW anchor '$anchor' not found in $file"
        msg_warn "Rules will be appended to the end of the file"
    fi

    local tmp_file block_file
    tmp_file=$(_mktemp_in_dir "$file") || return 1
    block_file=$(_mktemp_in_dir "$file.block") || {
        rm -f "$tmp_file" 2>/dev/null || true
        return 1
    }

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

    if ! awk -v start="$marker_start" -v end="$marker_end" -v anchor="$anchor" -v block_file="$block_file" '
        BEGIN {
            inserted = 0
            block = ""
            while ((getline line < block_file) > 0) {
                block = block line "\n"
            }
            close(block_file)
        }
        {
            lines[++count] = $0
        }
        END {
            last_commit = 0
            for (i = 1; i <= count; i++) {
                if (lines[i] == "COMMIT") {
                    last_commit = i
                }
            }

            for (i = 1; i <= count; i++) {
                if (lines[i] == start) {
                    while (i <= count && lines[i] != end) {
                        i++
                    }
                    continue
                }

                if (!inserted && lines[i] == anchor) {
                    if (length(block) > 0) {
                        printf "%s", block
                    }
                    inserted = 1
                } else if (!inserted && last_commit > 0 && i == last_commit) {
                    if (length(block) > 0) {
                        printf "%s", block
                    }
                    inserted = 1
                }

                print lines[i]
            }

            if (!inserted && length(block) > 0) {
                printf "%s", block
            }
        }
    ' "$file" > "$tmp_file"; then
        rm -f "$tmp_file" "$block_file" 2>/dev/null || true
        return 1
    fi

    mv "$tmp_file" "$file"
    rm -f "$block_file" 2>/dev/null || true
}

# ufw_sync_loopback_dnat_rules - sync UFW before.rules accepts for loopback DNAT rules
# Generates accept rules from current nft DNAT rules targeting 127.0.0.0/8 or ::1.
ufw_sync_loopback_dnat_rules() {
    command -v ufw >/dev/null 2>&1 || return 0
    [[ -f "$UFW_BEFORE_RULES" ]] || return 0

    local marker_start="# pfwd-managed loopback dnat start"
    local marker_end="# pfwd-managed loopback dnat end"
    local block_v4="" block_v6=""
    local proto lport ipver target_input resolved_target tport comment snat_mode snat_source mss_mode mss_value
    local runtime_rules
    runtime_rules=$(_pfwd_state_runtime_rules_tsv "" "false")

    while IFS=$'\t' read -r proto lport ipver target_input resolved_target tport comment snat_mode snat_source mss_mode mss_value; do
        [[ -z "$lport" ]] && continue
        if [[ "$resolved_target" =~ ^127\. ]]; then
            printf -v block_v4 '%s-A ufw-before-input -m conntrack --ctstate DNAT -p %s -d 127.0.0.1 --dport %s -j ACCEPT\n' "$block_v4" "$proto" "$tport"
        elif [[ "$resolved_target" == "::1" ]]; then
            printf -v block_v6 '%s-A ufw6-before-input -m conntrack --ctstate DNAT -p %s -d ::1 --dport %s -j ACCEPT\n' "$block_v6" "$proto" "$tport"
        fi
    done <<< "$runtime_rules"

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
    require_root "$0 optimize $profile"
    local marker_start="# pfwd-managed-start"
    local marker_end="# pfwd-managed-end"
    local buf_max conntrack_max conntrack_tcp_est udp_timeout udp_stream_timeout
    local conntrack_tcp_time_wait conntrack_tcp_close_wait conntrack_tcp_fin_wait
    local tcp_rmem tcp_wmem tcp_mem backlog somaxconn file_max
    local ft_tcp_timeout ft_udp_timeout conntrack_buckets gro_normal_batch
    local max_syn_backlog max_tw_buckets netdev_budget netdev_budget_usecs
    local optmem_max keepalive_time keepalive_intvl keepalive_probes
    local tcp_synack_retries tcp_fin_timeout tcp_ecn tcp_frto
    local inotify_instances inotify_watches accept_ra_default="" accept_ra_all=""
    local enable_ipv6_lo_forwarding=false enable_accept_ra=false
    local enable_relay_tuning=false bbr_supported=false

    case "$profile" in
        gaming)
            buf_max=134217728        # 128MB
            conntrack_max=524288
            conntrack_tcp_est=3600
            conntrack_tcp_time_wait=15
            conntrack_tcp_close_wait=60
            conntrack_tcp_fin_wait=30
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
            netdev_budget=600
            netdev_budget_usecs=4000
            optmem_max=65536
            keepalive_time=300
            keepalive_intvl=15
            keepalive_probes=3
            tcp_synack_retries=2
            tcp_fin_timeout=10
            tcp_ecn=2
            tcp_frto=2
            inotify_instances=8192
            inotify_watches=262144
            ;;
        lowmem)
            buf_max=16777216         # 16MB
            conntrack_max=131072
            conntrack_tcp_est=3600
            conntrack_tcp_time_wait=15
            conntrack_tcp_close_wait=30
            conntrack_tcp_fin_wait=20
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
            netdev_budget=300
            netdev_budget_usecs=3000
            optmem_max=32768
            keepalive_time=300
            keepalive_intvl=15
            keepalive_probes=3
            tcp_synack_retries=2
            tcp_fin_timeout=10
            tcp_ecn=2
            tcp_frto=2
            inotify_instances=4096
            inotify_watches=131072
            ;;
        relay)
            buf_max=67108864         # 64MB
            conntrack_max=1048576
            conntrack_tcp_est=7200
            conntrack_tcp_time_wait=15
            conntrack_tcp_close_wait=60
            conntrack_tcp_fin_wait=30
            udp_timeout=120
            udp_stream_timeout=300
            tcp_rmem="4096 131072 67108864"
            tcp_wmem="4096 65536 67108864"
            tcp_mem="131072 196608 262144"
            backlog=65536
            somaxconn=65535
            file_max=6815744
            ft_tcp_timeout=300
            ft_udp_timeout=120
            conntrack_buckets=262144
            gro_normal_batch=8
            max_syn_backlog=131072
            max_tw_buckets=262144
            netdev_budget=600
            netdev_budget_usecs=5000
            optmem_max=65536
            keepalive_time=600
            keepalive_intvl=15
            keepalive_probes=2
            tcp_synack_retries=1
            tcp_fin_timeout=15
            tcp_ecn=1
            tcp_frto=0
            inotify_instances=8192
            inotify_watches=524288
            enable_ipv6_lo_forwarding=true
            enable_accept_ra=true
            accept_ra_all=2
            accept_ra_default=2
            enable_relay_tuning=true
            ;;
        balanced)
            buf_max=33554432         # 32MB
            conntrack_max=1048576
            conntrack_tcp_est=7200
            conntrack_tcp_time_wait=15
            conntrack_tcp_close_wait=60
            conntrack_tcp_fin_wait=30
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
            netdev_budget=300
            netdev_budget_usecs=3000
            optmem_max=65536
            keepalive_time=300
            keepalive_intvl=15
            keepalive_probes=3
            tcp_synack_retries=2
            tcp_fin_timeout=10
            tcp_ecn=2
            tcp_frto=2
            inotify_instances=8192
            inotify_watches=262144
            ;;
        *)
            msg_err "Unknown optimize profile: $profile"
            msg_dim "  Valid profiles: balanced, gaming, lowmem, relay"
            return 1
            ;;
    esac

    msg_info "Applying kernel optimizations (profile: $profile)..."

    if ! sysctl_cc_supported bbr; then
        modprobe tcp_bbr 2>/dev/null || true
    fi
    if sysctl_cc_supported bbr; then
        bbr_supported=true
    fi

    if [[ -f "$SYSCTL_CONF" ]]; then
        sed -i "/$marker_start/,/$marker_end/d" "$SYSCTL_CONF"
    fi

    mkdir -p "$(dirname "$SYSCTL_CONF")"
    touch "$SYSCTL_CONF"
    _pfwd_sysctl_reset_render

    _pfwd_sysctl_append_line "# Profile: $profile"

    _pfwd_sysctl_append_section "File System"
    _pfwd_sysctl_append_setting fs.file-max "$file_max"
    _pfwd_sysctl_append_setting fs.inotify.max_user_instances "$inotify_instances"
    _pfwd_sysctl_append_setting fs.inotify.max_user_watches "$inotify_watches"

    _pfwd_sysctl_append_section "IP Forwarding"
    _pfwd_sysctl_append_setting net.ipv4.ip_forward 1
    _pfwd_sysctl_append_setting net.ipv6.conf.all.forwarding 1
    _pfwd_sysctl_append_setting net.ipv4.conf.all.forwarding 1
    _pfwd_sysctl_append_setting net.ipv4.conf.default.forwarding 1
    _pfwd_sysctl_append_setting net.ipv6.conf.default.forwarding 1
    if $enable_ipv6_lo_forwarding; then
        _pfwd_sysctl_append_setting net.ipv6.conf.lo.forwarding 1
    fi
    if $enable_accept_ra; then
        _pfwd_sysctl_append_setting net.ipv6.conf.all.accept_ra "$accept_ra_all"
        _pfwd_sysctl_append_setting net.ipv6.conf.default.accept_ra "$accept_ra_default"
    fi

    _pfwd_sysctl_append_section "Congestion Control"
    if $bbr_supported; then
        _pfwd_sysctl_append_setting net.core.default_qdisc fq
        _pfwd_sysctl_append_setting net.ipv4.tcp_congestion_control bbr
    fi

    _pfwd_sysctl_append_section "TCP Optimization"
    _pfwd_sysctl_append_setting net.ipv4.tcp_fastopen 3
    _pfwd_sysctl_append_setting net.ipv4.tcp_early_retrans 3
    _pfwd_sysctl_append_setting net.ipv4.tcp_slow_start_after_idle 0
    _pfwd_sysctl_append_setting net.ipv4.tcp_notsent_lowat 16384
    _pfwd_sysctl_append_setting net.ipv4.tcp_mtu_probing 1
    _pfwd_sysctl_append_setting net.ipv4.tcp_timestamps 1
    _pfwd_sysctl_append_setting net.ipv4.tcp_sack 1
    _pfwd_sysctl_append_setting net.ipv4.tcp_window_scaling 1
    _pfwd_sysctl_append_setting net.ipv4.tcp_moderate_rcvbuf 1
    _pfwd_sysctl_append_setting net.ipv4.tcp_no_metrics_save 1
    _pfwd_sysctl_append_setting net.ipv4.tcp_rfc1337 0
    _pfwd_sysctl_append_setting net.ipv4.tcp_ecn "$tcp_ecn"
    _pfwd_sysctl_append_setting net.ipv4.tcp_frto "$tcp_frto"
    _pfwd_sysctl_append_setting net.ipv4.tcp_keepalive_time "$keepalive_time"
    _pfwd_sysctl_append_setting net.ipv4.tcp_keepalive_intvl "$keepalive_intvl"
    _pfwd_sysctl_append_setting net.ipv4.tcp_keepalive_probes "$keepalive_probes"
    _pfwd_sysctl_append_setting net.ipv4.tcp_tw_reuse 1
    _pfwd_sysctl_append_setting net.ipv4.tcp_fin_timeout "$tcp_fin_timeout"
    _pfwd_sysctl_append_setting net.ipv4.tcp_syncookies 1
    _pfwd_sysctl_append_setting net.ipv4.tcp_synack_retries "$tcp_synack_retries"
    _pfwd_sysctl_append_setting net.ipv4.ip_local_port_range "1024 65535"
    _pfwd_sysctl_append_setting net.ipv4.tcp_max_syn_backlog "$max_syn_backlog"
    _pfwd_sysctl_append_setting net.ipv4.tcp_max_tw_buckets "$max_tw_buckets"
    if $enable_relay_tuning; then
        _pfwd_sysctl_append_setting net.ipv4.tcp_fack 1
        _pfwd_sysctl_append_setting net.ipv4.neigh.default.unres_qlen 10000
    fi
    if sysctl_key_supported net.ipv4.tcp_adv_win_scale; then
        _pfwd_sysctl_append_setting net.ipv4.tcp_adv_win_scale 1
    fi

    _pfwd_sysctl_append_section "UDP Optimization"
    _pfwd_sysctl_append_setting net.ipv4.udp_rmem_min 8192
    _pfwd_sysctl_append_setting net.ipv4.udp_wmem_min 8192

    _pfwd_sysctl_append_section "Buffers"
    _pfwd_sysctl_append_setting net.core.rmem_max "$buf_max"
    _pfwd_sysctl_append_setting net.core.wmem_max "$buf_max"
    _pfwd_sysctl_append_setting net.ipv4.tcp_mem "$tcp_mem"
    _pfwd_sysctl_append_setting net.ipv4.tcp_rmem "$tcp_rmem"
    _pfwd_sysctl_append_setting net.ipv4.tcp_wmem "$tcp_wmem"
    _pfwd_sysctl_append_setting net.core.optmem_max "$optmem_max"
    _pfwd_sysctl_append_setting net.core.netdev_max_backlog "$backlog"
    _pfwd_sysctl_append_setting net.core.netdev_budget "$netdev_budget"
    _pfwd_sysctl_append_setting net.core.netdev_budget_usecs "$netdev_budget_usecs"
    _pfwd_sysctl_append_setting net.core.somaxconn "$somaxconn"
    _pfwd_sysctl_append_setting net.core.gro_normal_batch "$gro_normal_batch"

    _pfwd_sysctl_append_section "Connection Tracking"
    _pfwd_sysctl_append_setting net.netfilter.nf_conntrack_max "$conntrack_max"
    _pfwd_sysctl_append_setting net.netfilter.nf_conntrack_tcp_timeout_established "$conntrack_tcp_est"
    _pfwd_sysctl_append_setting net.netfilter.nf_conntrack_tcp_timeout_time_wait "$conntrack_tcp_time_wait"
    _pfwd_sysctl_append_setting net.netfilter.nf_conntrack_tcp_timeout_close_wait "$conntrack_tcp_close_wait"
    _pfwd_sysctl_append_setting net.netfilter.nf_conntrack_tcp_timeout_fin_wait "$conntrack_tcp_fin_wait"
    _pfwd_sysctl_append_setting net.netfilter.nf_conntrack_tcp_loose 1
    _pfwd_sysctl_append_setting net.netfilter.nf_conntrack_udp_timeout "$udp_timeout"
    _pfwd_sysctl_append_setting net.netfilter.nf_conntrack_udp_timeout_stream "$udp_stream_timeout"
    _pfwd_sysctl_append_setting net.netfilter.nf_conntrack_acct 1
    _pfwd_sysctl_append_setting net.netfilter.nf_conntrack_helper 0
    _pfwd_sysctl_append_setting net.netfilter.nf_conntrack_buckets "$conntrack_buckets"

    _pfwd_sysctl_append_section "Flowtable Timeout"
    _pfwd_sysctl_append_setting net.netfilter.nf_flowtable_tcp_timeout "$ft_tcp_timeout"
    _pfwd_sysctl_append_setting net.netfilter.nf_flowtable_udp_timeout "$ft_udp_timeout"

    _pfwd_sysctl_append_section "DNAT Optimization"
    _pfwd_sysctl_append_setting net.ipv4.conf.all.rp_filter 0
    _pfwd_sysctl_append_setting net.ipv4.conf.default.rp_filter 0
    _pfwd_sysctl_append_setting net.ipv4.conf.all.route_localnet 1
    _pfwd_sysctl_append_setting net.ipv4.conf.default.route_localnet 1

    cat >> "$SYSCTL_CONF" << EOF
$marker_start
$_PFWD_SYSCTL_RENDERED$marker_end
EOF

    plat_sysctl_apply_file "$SYSCTL_CONF"

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
    if $bbr_supported; then
        msg_dim "  BBR congestion control: enabled"
    else
        msg_warn "BBR is not available on this kernel; skipped persistence"
    fi
    msg_dim "  TCP fast open: enabled"
    msg_dim "  Conntrack max: $conntrack_max (buckets: $conntrack_buckets)"
    msg_dim "  Conntrack accounting: enabled"
    msg_dim "  Flowtable timeout: tcp=${ft_tcp_timeout}s udp=${ft_udp_timeout}s"
    msg_dim "  Flowtable acceleration: via nftables"
    msg_dim "  BQL limit_max: capped at 64KB (anti-bufferbloat)"
    _pfwd_sysctl_print_skipped
}

# reset_kernel_optimization - remove pfwd-managed sysctl block and reload
reset_kernel_optimization() {
    require_root "$0 optimize reset"
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
    plat_sysctl_apply_file "$SYSCTL_CONF"
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
#  Section 3b: Firewall Parsing Helpers
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

# _extract_nft_bytes <line> - extract traffic bytes from counter
_extract_nft_bytes() {
    local line="$1"; _BYTES=0
    [[ "$line" =~ bytes\ ([0-9]+) ]] && _BYTES="${BASH_REMATCH[1]}"
}

# _extract_nft_comment <line> - extract comment
_extract_nft_comment() {
    local line="$1" rest="" ch="" escaped=false i
    _COMMENT=""
    [[ "$line" == *'comment "'* ]] || return 0
    rest="${line#*comment \"}"
    for (( i=0; i<${#rest}; i++ )); do
        ch="${rest:i:1}"
        if $escaped; then
            _COMMENT+="$ch"
            escaped=false
        elif [[ "$ch" == "\\" ]]; then
            escaped=true
        elif [[ "$ch" == "\"" ]]; then
            break
        else
            _COMMENT+="$ch"
        fi
    done
    if $escaped; then
        _COMMENT+="\\"
    fi
    return 0
}

# _sort_parsed_rules - unified sort by protocol then port number
_sort_parsed_rules() { sort -t$'\t' -k1,1 -k2,2n; }

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
            lines=$(plat_nft_list_chain_handles $NFT_TABLE "$chain" | \
                { grep -E "(ip protocol tcp|ip6 nexthdr tcp).*dport $port\b" || true; })
            ;;
        udp)
            lines=$(plat_nft_list_chain_handles $NFT_TABLE "$chain" | \
                { grep -E "(ip protocol udp|ip6 nexthdr udp).*dport $port\b" || true; })
            ;;
        both)
            lines=$(plat_nft_list_chain_handles $NFT_TABLE "$chain" | \
                { grep -E "dport $port\b" || true; })
            ;;
        *)
            return 1
            ;;
    esac
    echo "$lines" | awk '/handle [0-9]+/ { for(i=1;i<=NF;i++) if($i=="handle") print $(i+1) }'
}

# _dispatch_add_rule <method> <lport> <target> <tport> <ip_ver> <proto> <comment> [mss_mode] [mss_value] [snat_mode] [snat_source] [replace_mode]
# Unified add rule dispatcher for nft
_dispatch_add_rule() {
    local method="$1" lport="$2" target="$3" tport="$4" ip_ver="$5" proto="$6" comment="$7"
    local mss_mode="${8:-}" mss_value="${9:-}" snat_mode="${10:-}" snat_source="${11:-}" replace_mode="${12:-false}"
    case "$method" in
        nft|nftables)
            pfwd_state_add_rule "$lport" "$target" "$tport" "$ip_ver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode"
            ;;
        *)
            msg_err "Unknown method: $method (use nft)"
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
        parsed=$(_pfwd_runtime_rules_to_parsed_tsv "$(_pfwd_state_runtime_rules_tsv "" "false")")
    fi
    sync_managed_iptables_accept_rules "$parsed" || return 1
    ufw_sync_loopback_dnat_rules || return 1
    return 0
}

# _batch_finalize <method> - finalize after batch add (save/persist/restart once)
_batch_finalize() {
    local method="$1"
    case "$method" in
        nft|nftables)
            if $_DIRTY_NFT; then
                local state_source=""
                [[ -n "$PFWD_STATE_BATCH_FILE" ]] && state_source="$PFWD_STATE_BATCH_FILE"
                if ! pfwd_apply_saved_state "$state_source"; then
                    _pfwd_state_discard_batch
                    return 1
                fi
                if [[ -n "$PFWD_STATE_BATCH_FILE" ]]; then
                    _pfwd_state_commit_batch || return 1
                fi
                nft_setup_persistence
                _reset_change_flags
            elif $_DIRTY_UFW_SYNC; then
                ufw_sync_loopback_dnat_rules || return 1
            fi
            if $_DIRTY_UFW_RELOAD; then
                ufw_reload_if_enabled || return 1
                sync_managed_iptables_accept_rules || return 1
            fi
            if [[ -n "$PFWD_STATE_BATCH_FILE" && ! $_DIRTY_NFT ]]; then
                _pfwd_state_discard_batch
            fi
            rm -f "$_NFT_BATCH_FILE" 2>/dev/null || true
            _NFT_BATCH_FILE=""
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
#  Section 4: Firewall Repository & Mutations
#===============================================================================

_ensure_nft_dispatch_chains() {
    _nft_table_exists || return 0

    local chains_changed=false dispatch_changed=false
    local section chain proto ipver tag match_tokens subchain
    for section in prerouting postrouting forward; do
        while IFS= read -r chain; do
            [[ -n "$chain" ]] || continue
            if ! _nft_cached_chain "$chain" >/dev/null; then
                plat_nft_quiet add chain $NFT_TABLE "$chain"
                chains_changed=true
            fi
        done < <(_pfwd_subchain_list "$section")
    done

    $chains_changed && _nft_invalidate_cache

    local prerouting_data postrouting_data forward_data
    prerouting_data=$(_nft_cached_chain prerouting || true)
    postrouting_data=$(_nft_cached_chain postrouting || true)
    forward_data=$(_nft_cached_chain forward || true)

    local forward_accept_handle=""
    forward_accept_handle=$(_nft_forward_established_accept_handle)

    for ipver in 4 6; do
        for proto in tcp udp; do
            match_tokens=$(_pfwd_dispatch_match_tokens "$proto" "$ipver")

            tag=$(_pfwd_dispatch_tag prerouting "$proto" "$ipver")
            subchain=$(_pfwd_subchain_name prerouting "$proto" "$ipver")
            if _nft_chain_has_rules "$subchain"; then
                if [[ "$prerouting_data" != *"comment \"$tag\""* ]]; then
                    plat_nft_quiet add rule $NFT_TABLE prerouting $match_tokens \
                        jump "$subchain" comment "$(nft_quote_token "$tag")"
                    dispatch_changed=true
                fi
            else
                while IFS= read -r handle; do
                    [[ -n "$handle" ]] || continue
                    plat_nft_delete_rule_handle $NFT_TABLE prerouting "$handle"
                    dispatch_changed=true
                done < <(_nft_rule_handles_by_comment prerouting "$tag")
            fi

            tag=$(_pfwd_dispatch_tag postrouting "$proto" "$ipver")
            subchain=$(_pfwd_subchain_name postrouting "$proto" "$ipver")
            if _nft_chain_has_rules "$subchain"; then
                if [[ "$postrouting_data" != *"comment \"$tag\""* ]]; then
                    plat_nft_quiet add rule $NFT_TABLE postrouting ct status dnat $match_tokens \
                        jump "$subchain" comment "$(nft_quote_token "$tag")"
                    dispatch_changed=true
                fi
            else
                while IFS= read -r handle; do
                    [[ -n "$handle" ]] || continue
                    plat_nft_delete_rule_handle $NFT_TABLE postrouting "$handle"
                    dispatch_changed=true
                done < <(_nft_rule_handles_by_comment postrouting "$tag")
            fi

            tag=$(_pfwd_dispatch_tag forward "$proto" "$ipver")
            subchain=$(_pfwd_subchain_name forward "$proto" "$ipver")
            if _nft_chain_has_rules "$subchain"; then
                if [[ "$forward_data" != *"comment \"$tag\""* ]]; then
                    if [[ -n "$forward_accept_handle" ]]; then
                        plat_nft_quiet insert rule $NFT_TABLE forward handle "$forward_accept_handle" $match_tokens \
                            jump "$subchain" comment "$(nft_quote_token "$tag")"
                    else
                        plat_nft_quiet add rule $NFT_TABLE forward $match_tokens \
                            jump "$subchain" comment "$(nft_quote_token "$tag")"
                    fi
                    dispatch_changed=true
                fi
            else
                while IFS= read -r handle; do
                    [[ -n "$handle" ]] || continue
                    plat_nft_delete_rule_handle $NFT_TABLE forward "$handle"
                    dispatch_changed=true
                done < <(_nft_rule_handles_by_comment forward "$tag")
            fi
        done
    done

    $dispatch_changed && _nft_invalidate_cache
}

# nft_ensure_table - create table, chains, and flowtable if not exist
nft_ensure_table() {
    ensure_nft || return 1

    # Check if table already exists
    if _nft_table_exists; then
        _ensure_nft_dispatch_chains
        return 0
    fi

    local nics
    nics=$(get_all_nics)
    if [[ -z "$nics" ]]; then
        msg_warn "No network interfaces detected for flowtable, using fallback"
        nics="eth0"
    fi

    msg_info "Creating nftables table..."

    plat_nft_quiet add table $NFT_TABLE

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
                local modules_conf="$NF_FLOW_TABLE_MODULES_CONF"
                if [[ ! -f "$modules_conf" ]] || ! grep -q '^nf_flow_table$' "$modules_conf" 2>/dev/null; then
                    mkdir -p "$(dirname "$modules_conf")"
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
        if ft_err=$(plat_nft_capture add flowtable $NFT_TABLE ft "{ hook ingress priority 0; devices = { $nics }; flags offload; counter; }"); then
            flowtable_ok=true
            msg_dim "  Flowtable: hardware offload + counter enabled"
        elif ft_err=$(plat_nft_capture add flowtable $NFT_TABLE ft "{ hook ingress priority 0; devices = { $nics }; counter; }"); then
            flowtable_ok=true
            msg_dim "  Flowtable: counter enabled (no hardware offload)"
        elif ft_err=$(plat_nft_capture add flowtable $NFT_TABLE ft "{ hook ingress priority 0; devices = { $nics }; }"); then
            flowtable_ok=true
            msg_dim "  Flowtable: basic mode (kernel < 5.7, no counter)"
        else
            msg_warn "Flowtable creation failed, continuing without fast path"
            msg_dim "  devices=($nics) error: $ft_err"
        fi
    fi

    # NAT chains
    plat_nft_quiet add chain $NFT_TABLE prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'
    plat_nft_quiet add chain $NFT_TABLE postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'

    # Forward chain with optional flowtable offload
    plat_nft_quiet add chain $NFT_TABLE forward '{ type filter hook forward priority 0; policy accept; }'
    if $flowtable_ok; then
        plat_nft_quiet add rule $NFT_TABLE forward ct state established flow add @ft counter || \
            msg_dim "  Flowtable offload rule skipped"
    fi
    plat_nft_quiet add rule $NFT_TABLE forward ct state established,related accept

    # Input chain (for DNAT bypass)
    plat_nft_quiet add chain $NFT_TABLE input '{ type filter hook input priority filter - 10; policy accept; }'
    plat_nft_quiet add rule $NFT_TABLE input ip daddr 127.0.0.0/8 ct status dnat counter accept comment '"Allow DNAT to localhost before iptables"'
    _nft_invalidate_cache
    _ensure_nft_dispatch_chains

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
        "$bin" -I "$@" >/dev/null 2>&1 || return 1
        _iptables_rule_present "$bin" "$@" || return 1
    fi
    return 0
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
    while IFS=$'\t' read -r proto lport ipver target tport comment bytes; do
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
        _iptables_rule_ensure "$bin" FORWARD -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_FWD_DNAT_COMMENT" -j ACCEPT || return 1
        _iptables_rule_ensure "$bin" FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$IPTABLES_FWD_EST_COMMENT" -j ACCEPT || return 1
    else
        _iptables_rule_delete_all "$bin" FORWARD -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_FWD_DNAT_COMMENT" -j ACCEPT
        _iptables_rule_delete_all "$bin" FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$IPTABLES_FWD_EST_COMMENT" -j ACCEPT
    fi

    if [[ "$input_policy" == "DROP" && "$need_input" == true ]]; then
        _iptables_rule_ensure "$bin" INPUT -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_INPUT_DNAT_COMMENT" -j ACCEPT || return 1
    else
        _iptables_rule_delete_all "$bin" INPUT -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_INPUT_DNAT_COMMENT" -j ACCEPT
    fi
}

sync_managed_iptables_accept_rules() {
    local parsed="${1:-}"
    if [[ -z "$parsed" ]]; then
        parsed=$(_pfwd_runtime_rules_to_parsed_tsv "$(_pfwd_state_runtime_rules_tsv "" "false")")
    fi

    _sync_managed_iptables_family iptables 4 "$parsed" || return 1
    _sync_managed_iptables_family ip6tables 6 "$parsed" || return 1
    return 0
}

# ensure_forward_accept - keep managed iptables ACCEPT rules in sync with current nft state
ensure_forward_accept() {
    sync_managed_iptables_accept_rules
}

_nft_resolve_targets() {
    local target="$1" ip_ver="${2:-46}"
    local target_type resolved_v4="" resolved_v6="" cache_key resolved_lines cached_status=0
    cache_key="${target}|${ip_ver}"
    if [[ -n "${_TARGET_RESOLVE_STATUS["$cache_key"]+_}" ]]; then
        cached_status="${_TARGET_RESOLVE_STATUS["$cache_key"]}"
        if (( cached_status == 0 )) && [[ -n "${_TARGET_RESOLVE_CACHE["$cache_key"]:-}" ]]; then
            printf '%s\n' "${_TARGET_RESOLVE_CACHE["$cache_key"]}"
        fi
        return "$cached_status"
    fi

    target_type=$(detect_ip_type "$target")

    case "$target_type" in
        ipv4)
            if [[ "$ip_ver" == "6" ]]; then
                _TARGET_RESOLVE_CACHE["$cache_key"]=""
                _TARGET_RESOLVE_STATUS["$cache_key"]=0
                return 0
            fi
            _TARGET_RESOLVE_CACHE["$cache_key"]="ip|4|$target"
            _TARGET_RESOLVE_STATUS["$cache_key"]=0
            printf 'ip|4|%s\n' "$target"
            ;;
        ipv6)
            if [[ "$ip_ver" == "4" ]]; then
                _TARGET_RESOLVE_CACHE["$cache_key"]=""
                _TARGET_RESOLVE_STATUS["$cache_key"]=0
                return 0
            fi
            _TARGET_RESOLVE_CACHE["$cache_key"]="ip6|6|$target"
            _TARGET_RESOLVE_STATUS["$cache_key"]=0
            printf 'ip6|6|%s\n' "$target"
            ;;
        domain)
            resolved_lines=$(getent ahosts "$target" 2>/dev/null || true)
            resolved_v4=$(awk '/STREAM/ && $1 ~ /^[0-9]+\./ { print $1; exit }' <<< "$resolved_lines")
            resolved_v6=$(awk '/STREAM/ && $1 ~ /:/ { print $1; exit }' <<< "$resolved_lines")
            if [[ -z "$resolved_v4" && -z "$resolved_v6" ]]; then
                _TARGET_RESOLVE_CACHE["$cache_key"]=""
                _TARGET_RESOLVE_STATUS["$cache_key"]=1
                msg_err "Cannot resolve domain: $target"
                msg_err "Use a literal IPv4/IPv6 address or fix DNS resolution"
                return 1
            fi
            _TARGET_RESOLVE_CACHE["$cache_key"]=""
            if [[ -n "$resolved_v4" && ( "$ip_ver" == "4" || "$ip_ver" == "46" ) ]]; then
                _TARGET_RESOLVE_CACHE["$cache_key"]+="ip|4|$resolved_v4"$'\n'
            fi
            if [[ -n "$resolved_v6" && ( "$ip_ver" == "6" || "$ip_ver" == "46" ) ]]; then
                _TARGET_RESOLVE_CACHE["$cache_key"]+="ip6|6|$resolved_v6"$'\n'
            fi
            _TARGET_RESOLVE_CACHE["$cache_key"]="${_TARGET_RESOLVE_CACHE["$cache_key"]%$'\n'}"
            _TARGET_RESOLVE_STATUS["$cache_key"]=0
            [[ -n "${_TARGET_RESOLVE_CACHE["$cache_key"]}" ]] && printf '%s\n' "${_TARGET_RESOLVE_CACHE["$cache_key"]}"
            ;;
        *)
            _TARGET_RESOLVE_CACHE["$cache_key"]=""
            _TARGET_RESOLVE_STATUS["$cache_key"]=1
            return 1
            ;;
    esac
}

_nft_delete_exact_rule() {
    local lport="$1" proto="$2" ip_ver="$3" target="$4" tport="$5"
    pfwd_state_delete_exact_rule "$proto" "$lport" "$ip_ver" "$target" "$tport"
}

_nft_collect_add_conflicts() {
    local target="$1" ip_ver="${2:-46}" proto="${3:-tcp}"
    NFT_ADD_CONFLICTS=()

    local existing_rules resolved_targets
    existing_rules=$(pfwd_state_rules_tsv)
    [[ -n "$existing_rules" ]] || return 0
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
                if _pfwd_state_find_conflict "$existing_rules" "$RULE_LPORT" "$p" "$effective_ipver"; then
                    NFT_ADD_CONFLICTS+=("${p}|${RULE_LPORT}|${effective_ipver}|${PFWD_STATE_CONFLICT_TARGET}|${PFWD_STATE_CONFLICT_TPORT}|${resolved_ip}|${RULE_TPORT}")
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
    local started_batch=false deleted=0

    if ! $_BATCH_MODE; then
        _BATCH_MODE=true
        started_batch=true
    fi

    if pfwd_state_delete_port_rules "$port" "$proto"; then
        deleted=${PFWD_STATE_DELETE_COUNT:-0}
        _traffic_delete_records nft_port "$port" "$proto"
        if $started_batch; then
            _BATCH_MODE=false
            if ! _batch_finalize nft; then
                msg_err "Failed to apply state-driven deletion batch for port $port"
                return 1
            fi
        fi
        local proto_msg=""
        [[ "$proto" != "both" ]] && proto_msg=" ($proto)"
        msg_ok "Deleted $deleted nftables rule(s) for port $port$proto_msg"
    else
        if $started_batch; then
            _BATCH_MODE=false
            _pfwd_state_discard_batch
        fi
        msg_warn "No nftables rules found for port $port"
    fi
}

# nft_delete_ports_batch <ports_array> <proto> - batch delete multiple ports efficiently
# Fetches chain data once, collects all handles, then deletes in bulk
nft_delete_ports_batch() {
    local -n _ports_ref=$1
    local proto="${2:-both}"
    local started_batch=false

    if ! $_BATCH_MODE; then
        _BATCH_MODE=true
        started_batch=true
    fi

    local total_deleted=0 port deleted

    for port in "${_ports_ref[@]}"; do
        if pfwd_state_delete_port_rules "$port" "$proto"; then
            deleted=${PFWD_STATE_DELETE_COUNT:-0}
            _traffic_delete_records nft_port "$port" "$proto"
            local proto_msg=""
            [[ "$proto" != "both" ]] && proto_msg=" ($proto)"
            msg_ok "Deleted $deleted nftables rule(s) for port $port$proto_msg"
            ((total_deleted += deleted)) || true
        else
            msg_warn "No nftables rules found for port $port"
        fi
    done

    if (( total_deleted > 0 )); then
        if $started_batch; then
            _BATCH_MODE=false
            if ! _batch_finalize nft; then
                msg_err "Failed to apply state-driven deletion batch"
                return 1
            fi
        fi
    elif $started_batch; then
        _BATCH_MODE=false
        _pfwd_state_discard_batch
    fi
}

_nft_prerouting_dnat_lines() {
    _nft_cached_chains_concat prerouting $(_pfwd_subchain_list prerouting) | grep "dnat" || true
}

# _parse_nft_prerouting_rules - parse nft prerouting output into structured data
# Output: proto<TAB>lport<TAB>ipver<TAB>target<TAB>tport<TAB>comment<TAB>bytes
# Args: [nft_output] - if empty, fetches from nft
_parse_nft_prerouting_rules() {
    local nft_output="${1-__PFWD_DEFAULT__}"
    if [[ "$nft_output" == "__PFWD_DEFAULT__" ]]; then
        _nft_prepare_snapshot
        nft_output="$_NFT_SNAPSHOT_PREROUTING"
    fi
    [[ -z "$nft_output" ]] && return 0

    echo "$nft_output" | awk '
    /dnat/ {
        proto=""; ipver=""; lport=""; target=""; tport=""; comment=""; bytes="0"

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

        if (match($0, /dport [0-9]+/)) {
            s = substr($0, RSTART, RLENGTH)
            sub(/dport /, "", s)
            lport = s
        }

        if (match($0, /dnat ip6 to /)) {
            rest = substr($0, RSTART + RLENGTH)
            p = index(rest, "]:")
            if (p > 1) {
                target = substr(rest, 2, p - 2)
                rest2 = substr(rest, p + 2)
                match(rest2, /[0-9]+/)
                tport = substr(rest2, RSTART, RLENGTH)
            }
        } else if (match($0, /dnat ip to /)) {
            rest = substr($0, RSTART + 11)
            if (match(rest, /[^ ]+/)) {
                s = substr(rest, RSTART, RLENGTH)
                n = split(s, parts, ":")
                target = parts[1]; tport = parts[n]
            }
        }

        if (match($0, /bytes [0-9]+/)) {
            s = substr($0, RSTART, RLENGTH)
            sub(/bytes /, "", s)
            bytes = s
        }

        if (match($0, /comment "/)) {
            rest = substr($0, RSTART + 9)
            escaped = 0
            for (i = 1; i <= length(rest); i++) {
                ch = substr(rest, i, 1)
                if (escaped) {
                    comment = comment ch
                    escaped = 0
                } else if (ch == "\\") {
                    escaped = 1
                } else if (ch == "\"") {
                    break
                } else {
                    comment = comment ch
                }
            }
            if (escaped) comment = comment "\\"
        }
        gsub(/[\t\r\n]/, " ", comment)

        if (lport != "" && proto != "") {
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", proto, lport, ipver, target, tport, comment, bytes
        }
    }
    '
}

# _parse_nft_export_rules - parse nft rules plus optional pfwd MSS/SNAT metadata
# Output: proto<TAB>lport<TAB>ipver<TAB>target<TAB>tport<TAB>comment<TAB>snat_mode<TAB>snat_source<TAB>mss_mode<TAB>mss_value
_parse_nft_export_rules() {
    local parsed="${1:-}"
    if [[ -z "$parsed" ]]; then
        _nft_prepare_snapshot
        parsed="$_NFT_SNAPSHOT_PARSED"
    fi
    [[ -z "$parsed" ]] && return 0

    local proto lport ipver target tport comment bytes
    while IFS=$'\t' read -r proto lport ipver target tport comment bytes; do
        [[ -z "$lport" ]] && continue

        local tag snat_mode="masquerade" snat_source="" mss_mode="" mss_value=""
        tag=$(_pfwd_rule_tag "$lport" "$ipver" "$proto" "$target" "$tport")
        [[ -n "${_NFT_SNAPSHOT_SNAT_MODE[$tag]:-}" ]] && snat_mode="${_NFT_SNAPSHOT_SNAT_MODE[$tag]}"
        [[ -n "${_NFT_SNAPSHOT_SNAT_SOURCE[$tag]:-}" ]] && snat_source="${_NFT_SNAPSHOT_SNAT_SOURCE[$tag]}"
        [[ -n "${_NFT_SNAPSHOT_MSS_MODE[${tag}:mss]:-}" ]] && mss_mode="${_NFT_SNAPSHOT_MSS_MODE[${tag}:mss]}"
        [[ -n "${_NFT_SNAPSHOT_MSS_VALUE[${tag}:mss]:-}" ]] && mss_value="${_NFT_SNAPSHOT_MSS_VALUE[${tag}:mss]}"

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
            "$snat_mode" "$snat_source" "$mss_mode" "$mss_value"
    done <<< "$parsed"
}

# _parse_nft_bidirectional_traffic - parse prerouting + forward chain for traffic stats
# Output: proto<TAB>lport<TAB>ipver<TAB>target<TAB>tport<TAB>comment<TAB>in_bytes<TAB>out_bytes<TAB>total_bytes
_parse_nft_bidirectional_traffic() {
    local parsed_prerouting="${1:-}"
    if [[ -z "$parsed_prerouting" ]]; then
        _nft_prepare_snapshot
        parsed_prerouting="$_NFT_SNAPSHOT_PARSED"
    fi
    [[ -z "$parsed_prerouting" ]] && return 0

    local proto lport ipver target tport comment in_bytes
    while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes; do
        [[ -z "$lport" ]] && continue
        local key="${proto}|${lport}|${ipver}"
        local out_bytes="${_NFT_SNAPSHOT_OUT_BYTES[$key]:-0}"
        local total_bytes=$(( in_bytes + out_bytes ))
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" "$in_bytes" "$out_bytes" "$total_bytes"
    done <<< "$parsed_prerouting"
}

# nft_list_rules - display all forwarding rules in a table
nft_list_rules() {
    local filter="${1:-}"
    local parsed="${2:-}"

    if [[ -z "$parsed" ]]; then
        parsed=$(_nft_rules_for_display)
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

    local idx=0
    local -a detail_lines=()
    local snat_mode snat_source mss_mode mss_value bytes
    while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value bytes; do
        [[ -z "$lport" ]] && continue
        bytes="${bytes:-0}"
        local target_label
        target_label=$(_pfwd_state_target_label "$target" "$ipver")
        # Apply filter if specified
        if [[ -n "$filter" ]]; then
            local opts_text
            opts_text=$(_nft_rule_option_summary "$snat_mode" "$snat_source" "$mss_mode" "$mss_value")
            local line_text=":$lport $proto IPv$ipver ${target_label}:${tport} ${comment:--} ${opts_text}"
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
        local target_display="${target_label}:$tport"
        local option_display
        option_display=$(_nft_rule_option_summary "$snat_mode" "$snat_source" "$mss_mode" "$mss_value")
        # Truncate target/options/comment to fit column widths
        local disp_target=" ${target_display}" disp_opts=" ${option_display}" disp_comment=" ${comment:--}"
        (( ${#disp_target} > 30 )) && disp_target="${disp_target:0:28}.."
        (( ${#disp_opts} > 18 )) && disp_opts="${disp_opts:0:16}.."
        (( ${#disp_comment} > 20 )) && disp_comment="${disp_comment:0:18}.."
        printf "  ${DIM}│${NC}%-4s${DIM}│${NC}%-8s${DIM}│${NC}${proto_color}%-6s${NC}${DIM}│${NC}${ipver_color}%-6s${NC}${DIM}│${NC}%-30s${DIM}│${NC}%-18s${DIM}│${NC}%-20s${DIM}│${NC}${traffic_color}%-10s${NC}${DIM}│${NC}\n" \
            " $idx" " :$lport" " $proto" " v$ipver" "$disp_target" "$disp_opts" "$disp_comment" " $traffic"
        if [[ "$snat_mode" == "snat" && -n "$snat_source" ]]; then
            detail_lines+=("#$idx fixed-snat: $snat_source")
        fi
    done <<< "$sorted_rules"
    echo -e "  ${DIM}└────┴────────┴──────┴──────┴──────────────────────────────┴──────────────────┴────────────────────┴──────────┘${NC}"
    if (( ${#detail_lines[@]} > 0 )); then
        echo ""
        echo -e "${DIM}Fixed SNAT details:${NC}"
        local detail_line
        for detail_line in "${detail_lines[@]}"; do
            echo -e "  ${DIM}${detail_line}${NC}"
        done
    fi
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

    if ! plat_nft_list_table $NFT_TABLE > "$tmp_file"; then
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
    ufw_status=$(plat_ufw_status_line)
    if [[ "$ufw_status" =~ "Status: active" ]]; then
        msg_dim "  Reloading ufw to apply nftables changes..."

        # 先验证规则文件语法
        if [[ -f "$UFW_BEFORE_RULES" ]]; then
            if ! plat_iptables_restore_test "$UFW_BEFORE_RULES"; then
                msg_err "UFW before.rules syntax error detected"
                msg_err "Please check $UFW_BEFORE_RULES manually"
                _DIRTY_UFW_RELOAD=false
                return 1
            fi
        fi

        if plat_ufw_reload; then
            msg_dim "  ufw reloaded successfully"
            # Re-add iptables ACCEPT rules after UFW reload (may have been flushed)
            ensure_forward_accept
        else
            msg_err "Failed to reload ufw"
            msg_err "Your firewall rules may be inconsistent"
            msg_err "Run 'ufw reload' manually to fix"
            _DIRTY_UFW_RELOAD=false
            return 1
        fi
    fi
    _DIRTY_UFW_RELOAD=false
}

# fix_ufw_loopback_rules - 手动修复 UFW loopback DNAT 规则
fix_ufw_loopback_rules() {
    require_root "$0 fix-ufw"
    msg_info "Fixing UFW loopback DNAT rules..."

    # 强制刷新缓存
    _nft_invalidate_cache

    # 执行同步
    ufw_sync_loopback_dnat_rules

    # 重新加载 UFW
    if ufw_reload_if_enabled; then
        msg_ok "UFW loopback DNAT rules fixed"
    else
        msg_err "Failed to fix UFW rules"
        return 1
    fi
}

# nft_flush_all - delete entire table and config files
nft_flush_all() {
    require_root "$0 uninstall nft"
    plat_nft_delete_table $NFT_TABLE || true
    _nft_invalidate_cache
    sync_managed_iptables_accept_rules ""
    ufw_sync_loopback_dnat_rules
    ufw_reload_if_enabled
    rm -f "$NFT_CONFIG"
    if [[ -f "$NFT_RESTORE_SERVICE" ]]; then
        plat_systemctl_disable pfwd-nft-restore
        rm -f "$NFT_RESTORE_SERVICE"
    fi
    _traffic_delete_records nft_all

    # Clean up traffic collector timer/service/script/data
    plat_systemctl_stop pfwd-traffic-save.timer
    plat_systemctl_disable pfwd-traffic-save.timer
    rm -f "$TRAFFIC_SAVE_SERVICE" "$TRAFFIC_SAVE_TIMER"
    rm -f "$TRAFFIC_DATA" "$TRAFFIC_FLOW_DATA" "$RULES_STATE_FILE"
    _pfwd_state_discard_batch
    plat_systemctl_daemon_reload
    msg_ok "nftables rules and persistence removed"
}

# nft_setup_persistence - create systemd units that call hidden pfwd entrypoints
nft_setup_persistence() {
    require_root "$0 start nft"
    mkdir -p "$DATA_DIR"
    mkdir -p "$(dirname "$NFT_CONFIG")"

    # nft_save already exports rules to NFT_CONFIG, only re-export if file missing
    if [[ ! -f "$NFT_CONFIG" || ! -s "$NFT_CONFIG" ]]; then
        nft_save "auto" >/dev/null 2>&1 || true
    fi

    detect_script_path
    if [[ -z "$SCRIPT_PATH" || ! -x "$SCRIPT_PATH" ]]; then
        msg_err "Cannot enable persistence from a transient script path."
        msg_err "Run pfwd from a persistent executable path and retry."
        return 1
    fi

    local script_path service_tmp
    script_path="$SCRIPT_PATH"

    # Create systemd service (with ExecStop to save traffic on shutdown)
    service_tmp=$(_mktemp_in_dir "$NFT_RESTORE_SERVICE") || return 1
    cat > "$service_tmp" << EOF
[Unit]
Description=pfwd nftables rules restore
After=network-online.target nftables.service systemd-sysctl.service ufw.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$script_path __restore-nft
ExecStop=$script_path __traffic-collector
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    _atomic_replace_file "$service_tmp" "$NFT_RESTORE_SERVICE" 0644

    # Create traffic save timer
    service_tmp=$(_mktemp_in_dir "$TRAFFIC_SAVE_SERVICE") || return 1
    cat > "$service_tmp" << EOF
[Unit]
Description=pfwd traffic data collector
After=pfwd-nft-restore.service

[Service]
Type=oneshot
ExecStart=$script_path __traffic-collector
EOF
    _atomic_replace_file "$service_tmp" "$TRAFFIC_SAVE_SERVICE" 0644

    traffic_write_timer_unit "$(traffic_current_interval)" || return 1

    plat_systemctl_daemon_reload
    plat_systemctl_enable pfwd-nft-restore
    plat_systemctl_enable_now pfwd-traffic-save.timer
}
#===============================================================================
#  Section 5: Traffic & Service Use Cases
#===============================================================================

cmd_internal_restore_nft() {
    require_root "$0 __restore-nft"
    _reset_change_flags
    pfwd_state_ensure_initialized

    if [[ -z "$(pfwd_state_rules_tsv)" ]]; then
        msg_warn "No saved pfwd state found"
        return 0
    fi

    if ! pfwd_apply_saved_state; then
        return 1
    fi

    nft_setup_persistence
    if ! _pfwd_enforce_runtime_health; then
        _reset_change_flags
        return 1
    fi
    _pfwd_collect_state
    _reset_change_flags
    return 0
}

_traffic_warn_incompatible_file() {
    local flag_name="$1" filepath="$2" expected_version="$3"
    if [[ "${!flag_name:-false}" != "true" ]]; then
        msg_warn "Ignoring incompatible traffic history in $filepath (expected v${expected_version})"
        printf -v "$flag_name" '%s' "true"
    fi
}

_traffic_file_format_state() {
    local filepath="$1" expected_version="$2"
    [[ -f "$filepath" ]] || { echo "missing"; return 0; }

    local first_token
    first_token=$(awk -F'|' 'NF > 0 && $1 != "" { print $1; exit }' "$filepath" 2>/dev/null || true)
    if [[ -z "$first_token" ]]; then
        echo "empty"
    elif [[ "$first_token" == "v${expected_version}" ]]; then
        echo "ok"
    elif [[ "$first_token" =~ ^v[0-9]+$ ]]; then
        echo "mismatch:${first_token}"
    else
        echo "legacy"
    fi
}

_traffic_file_age_seconds() {
    local filepath="$1"
    [[ -f "$filepath" ]] || { echo "-1"; return 0; }

    local now mtime
    now=$(date +%s 2>/dev/null || echo 0)
    mtime=$(stat -c %Y "$filepath" 2>/dev/null || echo 0)
    if [[ ! "$now" =~ ^[0-9]+$ || ! "$mtime" =~ ^[0-9]+$ || $mtime -le 0 ]]; then
        echo "-1"
        return 0
    fi
    echo $(( now - mtime ))
}

traffic_interval_seconds() {
    case "${1:-}" in
        30s) echo 30 ;;
        1m) echo 60 ;;
        5m) echo 300 ;;
        10m) echo 600 ;;
        30m) echo 1800 ;;
        1h) echo 3600 ;;
        *) echo 0 ;;
    esac
}

_pfwd_tsv_split_line() {
    local line="${1-}" field
    PFWD_TSV_FIELDS=()
    while true; do
        if [[ "$line" == *$'\t'* ]]; then
            field=${line%%$'\t'*}
            PFWD_TSV_FIELDS+=("$field")
            line=${line#*$'\t'}
        else
            PFWD_TSV_FIELDS+=("$line")
            break
        fi
    done
}

_traffic_rules_with_keys() {
    local rules="${1:-}"
    if [[ -z "$rules" ]]; then
        rules=$(pfwd_state_rules_tsv)
    fi
    [[ -n "$rules" ]] || return 0

    local runtime_rules
    runtime_rules=$(_pfwd_state_runtime_rules_tsv "$rules" "false")
    [[ -n "$runtime_rules" ]] || return 0

    local line proto lport ipver target_input resolved_target tport comment snat_mode snat_source mss_mode mss_value rule_key
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        _pfwd_tsv_split_line "$line"
        proto="${PFWD_TSV_FIELDS[0]:-}"
        lport="${PFWD_TSV_FIELDS[1]:-}"
        ipver="${PFWD_TSV_FIELDS[2]:-}"
        target_input="${PFWD_TSV_FIELDS[3]:-}"
        resolved_target="${PFWD_TSV_FIELDS[4]:-}"
        tport="${PFWD_TSV_FIELDS[5]:-}"
        comment="${PFWD_TSV_FIELDS[6]:-}"
        snat_mode="${PFWD_TSV_FIELDS[7]:-}"
        snat_source="${PFWD_TSV_FIELDS[8]:-}"
        mss_mode="${PFWD_TSV_FIELDS[9]:-}"
        mss_value="${PFWD_TSV_FIELDS[10]:-}"
        [[ -z "$lport" ]] && continue
        rule_key=$(_traffic_rule_key "$proto" "$lport" "$ipver" "$resolved_target" "$tport")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$rule_key" "$proto" "$lport" "$ipver" "$resolved_target" "$tport" "$comment" \
            "$snat_mode" "$snat_source" "$mss_mode" "$mss_value"
    done <<< "$runtime_rules"
}

_parse_rule_key_meta_tsv() {
    local line="${1:-}"
    _pfwd_tsv_split_line "$line"
    RULEKEY_ROW_KEY="${PFWD_TSV_FIELDS[0]:-}"
    RULEKEY_ROW_PROTO="${PFWD_TSV_FIELDS[1]:-}"
    RULEKEY_ROW_LPORT="${PFWD_TSV_FIELDS[2]:-}"
    RULEKEY_ROW_IPVER="${PFWD_TSV_FIELDS[3]:-}"
    RULEKEY_ROW_TARGET="${PFWD_TSV_FIELDS[4]:-}"
    RULEKEY_ROW_TPORT="${PFWD_TSV_FIELDS[5]:-}"
    RULEKEY_ROW_COMMENT="${PFWD_TSV_FIELDS[6]:-}"
    RULEKEY_ROW_SNAT_MODE="${PFWD_TSV_FIELDS[7]:-}"
    RULEKEY_ROW_SNAT_SOURCE="${PFWD_TSV_FIELDS[8]:-}"
    RULEKEY_ROW_MSS_MODE="${PFWD_TSV_FIELDS[9]:-}"
    RULEKEY_ROW_MSS_VALUE="${PFWD_TSV_FIELDS[10]:-}"
}

_parse_rule_key_totals_tsv() {
    local line="${1:-}"
    _pfwd_tsv_split_line "$line"
    RULETOTAL_ROW_KEY="${PFWD_TSV_FIELDS[0]:-}"
    RULETOTAL_ROW_PROTO="${PFWD_TSV_FIELDS[1]:-}"
    RULETOTAL_ROW_LPORT="${PFWD_TSV_FIELDS[2]:-}"
    RULETOTAL_ROW_IPVER="${PFWD_TSV_FIELDS[3]:-}"
    RULETOTAL_ROW_TARGET="${PFWD_TSV_FIELDS[4]:-}"
    RULETOTAL_ROW_TPORT="${PFWD_TSV_FIELDS[5]:-}"
    RULETOTAL_ROW_COMMENT="${PFWD_TSV_FIELDS[6]:-}"
    RULETOTAL_ROW_IN="${PFWD_TSV_FIELDS[7]:-}"
    RULETOTAL_ROW_OUT="${PFWD_TSV_FIELDS[8]:-}"
    RULETOTAL_ROW_TOTAL="${PFWD_TSV_FIELDS[9]:-}"
}

_traffic_collect_snapshot() {
    local rules="${1:-}"
    _TRAFFIC_SNAPSHOT_RULES=$(_traffic_rules_with_keys "$rules")
    if [[ -n "$_TRAFFIC_SNAPSHOT_RULES" ]]; then
        _TRAFFIC_SNAPSHOT_FLOWS=$(_traffic_active_flows_tsv "$_TRAFFIC_SNAPSHOT_RULES")
    else
        _TRAFFIC_SNAPSHOT_FLOWS=""
    fi
}

_traffic_saved_records_tsv() {
    [[ -f "$TRAFFIC_DATA" ]] || return 0
    while IFS='|' read -r f1 f2 f3 f4 f5 f6 f7 f8 f9 _rest; do
        [[ -z "${f1:-}" ]] && continue
        if [[ "$f1" == "v${TRAFFIC_DATA_VERSION}" && "$f2" == "nft_rule" ]]; then
            printf '%s\t%s\t%s\n' \
                "$(_traffic_rule_key "${f3:-}" "${f4:-}" "${f5:-}" "${f6:-}" "${f7:-}")" \
                "${f8:-0}" "${f9:-0}"
        else
            _traffic_warn_incompatible_file "_TRAFFIC_DATA_WARNED" "$TRAFFIC_DATA" "$TRAFFIC_DATA_VERSION"
            return 0
        fi
    done < "$TRAFFIC_DATA"
}

_traffic_saved_flow_records_tsv() {
    [[ -f "$TRAFFIC_FLOW_DATA" ]] || return 0
    while IFS='|' read -r f1 f2 f3 f4 f5 f6 f7 f8 f9 f10 _rest; do
        [[ -z "${f1:-}" ]] && continue
        if [[ "$f1" == "v${TRAFFIC_FLOW_VERSION}" && "$f2" == "nft_flow" ]]; then
            printf '%s\t%s\t%s\t%s\n' \
                "${f8:-}" \
                "$(_traffic_rule_key "${f3:-}" "${f4:-}" "${f5:-}" "${f6:-}" "${f7:-}")" \
                "${f9:-0}" "${f10:-0}"
        else
            _traffic_warn_incompatible_file "_TRAFFIC_FLOW_WARNED" "$TRAFFIC_FLOW_DATA" "$TRAFFIC_FLOW_VERSION"
            return 0
        fi
    done < "$TRAFFIC_FLOW_DATA"
}

_traffic_conntrack_dump() {
    if [[ $EUID -eq 0 ]] && command -v conntrack >/dev/null 2>&1; then
        local family line
        for family in ipv4 ipv6; do
            while IFS= read -r line; do
                [[ -n "$line" ]] || continue
                case "$line" in
                    ipv4\ *|ipv6\ *)
                        printf '%s\n' "$line"
                        ;;
                    *)
                        printf '%s %s\n' "$family" "$line"
                        ;;
                esac
            done < <(plat_conntrack_dump_family "$family" 2>/dev/null || true)
        done
        return 0
    fi

    if [[ -r /proc/net/nf_conntrack ]]; then
        cat /proc/net/nf_conntrack 2>/dev/null || true
    elif [[ -r /proc/net/ip_conntrack ]]; then
        cat /proc/net/ip_conntrack 2>/dev/null || true
    fi
}

_traffic_active_flows_tsv() {
    local rule_rows="${1:-}"
    if [[ -z "$rule_rows" ]]; then
        rule_rows=$(_traffic_rules_with_keys)
    fi
    [[ -n "$rule_rows" ]] || return 0

    awk '
        NR == FNR {
            split($0, f, "\t")
            if (length(f[1]) > 0) {
                rule[f[2] "|" f[4] "|" f[3] "|" f[5] "|" f[6]] = f[1]
            }
            next
        }
        {
            line = $0
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line == "") next

            proto = ""
            ipver = ""
            orig_src = orig_dst = orig_sport = orig_dport = ""
            reply_src = reply_dst = reply_sport = reply_dport = ""
            in_bytes = out_bytes = 0
            src_idx = dst_idx = sport_idx = dport_idx = bytes_idx = 0

            nf = split(line, fields, /[[:space:]]+/)
            if (fields[1] == "ipv4") {
                ipver = "4"
                if (fields[2] == "tcp" || fields[2] == "udp") proto = fields[2]
                else proto = fields[3]
            } else if (fields[1] == "ipv6") {
                ipver = "6"
                if (fields[2] == "tcp" || fields[2] == "udp") proto = fields[2]
                else proto = fields[3]
            } else {
                next
            }

            if (proto != "tcp" && proto != "udp") next

            for (i = 1; i <= nf; i++) {
                token = fields[i]
                if (token ~ /^src=/) {
                    src_idx++
                    value = substr(token, 5)
                    if (src_idx == 1) orig_src = value
                    else if (src_idx == 2) reply_src = value
                } else if (token ~ /^dst=/) {
                    dst_idx++
                    value = substr(token, 5)
                    if (dst_idx == 1) orig_dst = value
                    else if (dst_idx == 2) reply_dst = value
                } else if (token ~ /^sport=/) {
                    sport_idx++
                    value = substr(token, 7)
                    if (sport_idx == 1) orig_sport = value
                    else if (sport_idx == 2) reply_sport = value
                } else if (token ~ /^dport=/) {
                    dport_idx++
                    value = substr(token, 7)
                    if (dport_idx == 1) orig_dport = value
                    else if (dport_idx == 2) reply_dport = value
                } else if (token ~ /^bytes=/) {
                    bytes_idx++
                    value = substr(token, 7) + 0
                    if (bytes_idx == 1) in_bytes = value
                    else if (bytes_idx == 2) out_bytes = value
                }
            }

            if (orig_dport == "" || reply_src == "" || reply_sport == "") next

            rule_lookup = proto "|" ipver "|" orig_dport "|" reply_src "|" reply_sport
            rule_key = rule[rule_lookup]
            if (rule_key == "") next

            flow_id = ipver "|" proto "|" orig_src "|" orig_dst "|" orig_sport "|" orig_dport "|" reply_src "|" reply_dst "|" reply_sport "|" reply_dport
            printf "%s\t%s\t%s\t%s\n", flow_id, rule_key, in_bytes, out_bytes
        }
    ' <(printf '%s\n' "$rule_rows") <(_traffic_conntrack_dump)
}

_traffic_rule_totals_tsv() {
    local mode="${1:-merged}" rule_rows="${2:-}" flow_rows="${3:-}"
    [[ -n "$rule_rows" ]] || return 0

    declare -A acc_in=() acc_out=()
    declare -A prev_flow_in=() prev_flow_out=()
    declare -A live_in=() live_out=()

    local rule_key saved_in saved_out flow_id current_in current_out delta_in delta_out
    if [[ "$mode" == "merged" ]]; then
        while IFS=$'\t' read -r rule_key saved_in saved_out; do
            [[ -z "$rule_key" ]] && continue
            acc_in[$rule_key]="${saved_in:-0}"
            acc_out[$rule_key]="${saved_out:-0}"
        done < <(_traffic_saved_records_tsv)

        while IFS=$'\t' read -r flow_id rule_key saved_in saved_out; do
            [[ -z "$flow_id" || -z "$rule_key" ]] && continue
            prev_flow_in[$flow_id]="${saved_in:-0}"
            prev_flow_out[$flow_id]="${saved_out:-0}"
        done < <(_traffic_saved_flow_records_tsv)
    fi

    while IFS=$'\t' read -r flow_id rule_key current_in current_out; do
        [[ -z "$flow_id" || -z "$rule_key" ]] && continue
        if [[ "$mode" == "merged" ]]; then
            if (( current_in >= ${prev_flow_in[$flow_id]:-0} )); then
                delta_in=$(( current_in - ${prev_flow_in[$flow_id]:-0} ))
            else
                delta_in=$current_in
            fi
            if (( current_out >= ${prev_flow_out[$flow_id]:-0} )); then
                delta_out=$(( current_out - ${prev_flow_out[$flow_id]:-0} ))
            else
                delta_out=$current_out
            fi
        else
            delta_in=$current_in
            delta_out=$current_out
        fi
        live_in[$rule_key]=$(( ${live_in[$rule_key]:-0} + delta_in ))
        live_out[$rule_key]=$(( ${live_out[$rule_key]:-0} + delta_out ))
    done <<< "$flow_rows"

    local line merged_in merged_out
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        _parse_rule_key_meta_tsv "$line"
        [[ -n "$RULEKEY_ROW_KEY" ]] || continue
        if [[ "$mode" == "merged" ]]; then
            merged_in=$(( ${acc_in[$RULEKEY_ROW_KEY]:-0} + ${live_in[$RULEKEY_ROW_KEY]:-0} ))
            merged_out=$(( ${acc_out[$RULEKEY_ROW_KEY]:-0} + ${live_out[$RULEKEY_ROW_KEY]:-0} ))
        else
            merged_in="${live_in[$RULEKEY_ROW_KEY]:-0}"
            merged_out="${live_out[$RULEKEY_ROW_KEY]:-0}"
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$RULEKEY_ROW_KEY" "$RULEKEY_ROW_PROTO" "$RULEKEY_ROW_LPORT" "$RULEKEY_ROW_IPVER" "$RULEKEY_ROW_TARGET" "$RULEKEY_ROW_TPORT" "$RULEKEY_ROW_COMMENT" \
            "$merged_in" "$merged_out" "$(( merged_in + merged_out ))"
    done <<< "$rule_rows"
}

# _traffic_read_merged - read-only merge of saved totals + current flow deltas
# Output: proto<TAB>lport<TAB>ipver<TAB>target<TAB>tport<TAB>comment<TAB>in_bytes<TAB>out_bytes<TAB>total_bytes
_traffic_snapshot_strip_key() {
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        _parse_rule_key_totals_tsv "$line"
        [[ -n "$RULETOTAL_ROW_KEY" ]] || continue
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$RULETOTAL_ROW_PROTO" "$RULETOTAL_ROW_LPORT" "$RULETOTAL_ROW_IPVER" "$RULETOTAL_ROW_TARGET" "$RULETOTAL_ROW_TPORT" "$RULETOTAL_ROW_COMMENT" \
            "$RULETOTAL_ROW_IN" "$RULETOTAL_ROW_OUT" "$RULETOTAL_ROW_TOTAL"
    done
}

_traffic_live_rule_totals() {
    local rule_rows="${1:-}" flow_rows="${2:-}"
    if [[ -z "$rule_rows" ]]; then
        _traffic_collect_snapshot
        rule_rows="$_TRAFFIC_SNAPSHOT_RULES"
        flow_rows="$_TRAFFIC_SNAPSHOT_FLOWS"
    fi
    _traffic_rule_totals_tsv live "$rule_rows" "$flow_rows" | _traffic_snapshot_strip_key
}

_traffic_read_merged() {
    local rule_rows="${1:-}" flow_rows="${2:-}"
    if [[ -z "$rule_rows" ]]; then
        _traffic_collect_snapshot
        rule_rows="$_TRAFFIC_SNAPSHOT_RULES"
        flow_rows="$_TRAFFIC_SNAPSHOT_FLOWS"
    fi
    _traffic_rule_totals_tsv merged "$rule_rows" "$flow_rows" | _traffic_snapshot_strip_key
}

# _nft_rules_for_display - merge rule metadata with accumulated traffic totals
# Output: proto<TAB>lport<TAB>ipver<TAB>target<TAB>tport<TAB>comment<TAB>snat_mode<TAB>snat_source<TAB>mss_mode<TAB>mss_value<TAB>total_bytes
_nft_rules_for_display() {
    local rule_rows traffic
    _traffic_collect_snapshot
    rule_rows=$(pfwd_state_rules_tsv)
    [[ -z "$rule_rows" ]] && return 0

    traffic=$(_traffic_rule_totals_tsv merged "$_TRAFFIC_SNAPSHOT_RULES" "$_TRAFFIC_SNAPSHOT_FLOWS")
    declare -A traffic_total=()
    local line total_bytes resolved_target rule_key
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        _parse_rule_key_totals_tsv "$line"
        [[ -n "$RULETOTAL_ROW_KEY" ]] || continue
        traffic_total["$RULETOTAL_ROW_KEY"]="${RULETOTAL_ROW_TOTAL:-0}"
    done <<< "$traffic"

    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        _pfwd_tsv_split_line "$line"
        RULEKEY_ROW_PROTO="${PFWD_TSV_FIELDS[0]:-}"
        RULEKEY_ROW_LPORT="${PFWD_TSV_FIELDS[1]:-}"
        RULEKEY_ROW_IPVER="${PFWD_TSV_FIELDS[2]:-}"
        RULEKEY_ROW_TARGET="${PFWD_TSV_FIELDS[3]:-}"
        RULEKEY_ROW_TPORT="${PFWD_TSV_FIELDS[4]:-}"
        RULEKEY_ROW_COMMENT="${PFWD_TSV_FIELDS[5]:-}"
        RULEKEY_ROW_SNAT_MODE="${PFWD_TSV_FIELDS[6]:-}"
        RULEKEY_ROW_SNAT_SOURCE="${PFWD_TSV_FIELDS[7]:-}"
        RULEKEY_ROW_MSS_MODE="${PFWD_TSV_FIELDS[8]:-}"
        RULEKEY_ROW_MSS_VALUE="${PFWD_TSV_FIELDS[9]:-}"
        [[ -n "$RULEKEY_ROW_LPORT" ]] || continue
        resolved_target=$(_pfwd_state_resolved_target "$RULEKEY_ROW_TARGET" "$RULEKEY_ROW_IPVER" 2>/dev/null || true)
        rule_key=$(_traffic_rule_key "$RULEKEY_ROW_PROTO" "$RULEKEY_ROW_LPORT" "$RULEKEY_ROW_IPVER" "${resolved_target:-$RULEKEY_ROW_TARGET}" "$RULEKEY_ROW_TPORT")
        total_bytes="${traffic_total[$rule_key]:-0}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$RULEKEY_ROW_PROTO" "$RULEKEY_ROW_LPORT" "$RULEKEY_ROW_IPVER" "$RULEKEY_ROW_TARGET" "$RULEKEY_ROW_TPORT" "$RULEKEY_ROW_COMMENT" \
            "$RULEKEY_ROW_SNAT_MODE" "$RULEKEY_ROW_SNAT_SOURCE" "$RULEKEY_ROW_MSS_MODE" "$RULEKEY_ROW_MSS_VALUE" "$total_bytes"
    done <<< "$rule_rows"
}

cmd_internal_traffic_collector() {
    require_root "$0 __traffic-collector"
    _traffic_collect_snapshot
    local merged_rows="$_TRAFFIC_SNAPSHOT_RULES"
    [[ -n "$merged_rows" ]] && merged_rows=$(_traffic_rule_totals_tsv merged "$_TRAFFIC_SNAPSHOT_RULES" "$_TRAFFIC_SNAPSHOT_FLOWS")

    local traffic_tmp flow_tmp current_in current_out
    traffic_tmp=$(_mktemp_in_dir "$TRAFFIC_DATA") || return 1
    flow_tmp=$(_mktemp_in_dir "$TRAFFIC_FLOW_DATA") || return 1
    : > "$flow_tmp"

    local flow_id rule_key proto lport ipver target tport comment total_bytes
    while IFS=$'\t' read -r flow_id rule_key current_in current_out; do
        [[ -z "$flow_id" || -z "$rule_key" ]] && continue
        IFS='|' read -r proto lport ipver target tport <<< "$rule_key"
        printf 'v%s|nft_flow|%s|%s|%s|%s|%s|%s|%s|%s\n' \
            "$TRAFFIC_FLOW_VERSION" "$proto" "$lport" "$ipver" "$target" "$tport" "$flow_id" "$current_in" "$current_out" >> "$flow_tmp"
    done <<< "$_TRAFFIC_SNAPSHOT_FLOWS"

    : > "$traffic_tmp"
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        _parse_rule_key_totals_tsv "$line"
        [[ -n "$RULETOTAL_ROW_KEY" ]] || continue
        printf 'v%s|nft_rule|%s|%s|%s|%s|%s|%s|%s\n' \
            "$TRAFFIC_DATA_VERSION" "$RULETOTAL_ROW_PROTO" "$RULETOTAL_ROW_LPORT" "$RULETOTAL_ROW_IPVER" "$RULETOTAL_ROW_TARGET" "$RULETOTAL_ROW_TPORT" "$RULETOTAL_ROW_IN" "$RULETOTAL_ROW_OUT" >> "$traffic_tmp"
    done <<< "$merged_rows"

    _atomic_replace_file "$traffic_tmp" "$TRAFFIC_DATA" 0644
    _atomic_replace_file "$flow_tmp" "$TRAFFIC_FLOW_DATA" 0644
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
            while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
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

    local sample1
    sample1=$(_traffic_live_rule_totals)
    [[ -z "$sample1" ]] && { msg_dim "  No rules to measure"; return 0; }

    # Store first sample in associative array
    declare -A s1_in s1_out
    while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
        [[ -z "$lport" ]] && continue
        local key
        key=$(_traffic_rule_key "$proto" "$lport" "$ipver" "$target" "$tport")
        s1_in[$key]="$in_bytes"
        s1_out[$key]="$out_bytes"
    done <<< "$sample1"

    sleep 2

    local sample2
    sample2=$(_traffic_live_rule_totals)

    echo ""
    echo -e "${CYAN}nftables traffic rate:${NC}"
    printf "  ${BOLD}%-8s %-6s %-6s %-25s %-14s %-14s${NC}\n" "L.Port" "Proto" "IPver" "Target" "In Rate" "Out Rate"

    local sorted_s2
    sorted_s2=$(echo "$sample2" | _sort_parsed_rules)

    while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
        [[ -z "$lport" ]] && continue
        local key
        key=$(_traffic_rule_key "$proto" "$lport" "$ipver" "$target" "$tport")
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

show_traffic_interval() {
    local interval
    interval=$(traffic_current_interval)
    echo -e "${BOLD}Traffic Collector Interval${NC}"
    echo -e "${DIM}$SEP_EQ${NC}"
    echo -e "  Current interval: ${CYAN}${interval}${NC}"
    echo -e "  Allowed values : ${DIM}30s, 1m, 5m, 10m, 30m, 1h${NC}"
}

menu_traffic_stats() {
    while true; do
        echo ""
        echo -e "${BOLD}Traffic Statistics${NC}"
        echo -e "${DIM}$SEP_DASH_40${NC}"
        echo "  1) View accumulated traffic"
        echo "  2) View traffic rate"
        echo "  3) Show collector interval"
        echo "  4) Set collector interval"
        echo "  0) Back"
        echo ""
        read -rp "Select [0-4]: " traffic_choice

        case "$traffic_choice" in
            1) show_traffic_stats; wait_for_enter ;;
            2) show_traffic_rate; wait_for_enter ;;
            3) show_traffic_interval; wait_for_enter ;;
            4)
                echo ""
                echo "  Allowed values: 30s, 1m, 5m, 10m, 30m, 1h"
                read -rp "New interval: " new_interval
                [[ -z "$new_interval" ]] && { msg_info "Cancelled"; continue; }
                traffic_configure_interval "$new_interval"
                wait_for_enter
                ;;
            0) return ;;
            *) msg_warn "Invalid choice" ;;
        esac
    done
}

#===============================================================================
#  Section 6: Import / Export Use Cases
#===============================================================================

# cmd_export [filepath] - export all rules to JSON
cmd_export() {
    local default_dir="$DATA_DIR"
    if [[ $EUID -ne 0 ]]; then
        default_dir="$PWD"
    fi
    local filepath="${1:-$default_dir/backup_$(date '+%Y%m%d_%H%M%S').json}"

    ensure_jq || return 1
    mkdir -p "$(dirname "$filepath")"
    pfwd_state_ensure_initialized

    # Build nft rules JSON array in the v3 export shape.
    local nft_json="[]"
    local parsed_nft
    parsed_nft=$(pfwd_state_export_rows_tsv)
    if [[ -n "$parsed_nft" ]]; then
        nft_json=$(printf '%s\n' "$parsed_nft" | json_export_rules_from_tsv)
    fi

    jq -n \
        --argjson version_format "$EXPORT_FORMAT_VERSION" \
        --arg version "$VERSION" \
        --arg tool "pfwd" \
        --arg export_time "$(date '+%Y-%m-%dT%H:%M:%S')" \
        --arg source_ip "$(get_local_ip)" \
        --argjson nft "$nft_json" \
        '{
            export_info: {
                version_format: $version_format,
                version: $version,
                tool: $tool,
                export_time: $export_time,
                source_ip: $source_ip
            },
            forward_rules: $nft
        }' > "$filepath"

    msg_ok "Exported to: $filepath"

    local count
    count=$(json_forward_rules_count "$filepath")
    msg_info "Total rules exported: $count"

    # Show SCP hint
    local source_ip
    source_ip=$(get_local_ip)
    if [[ -n "$source_ip" ]]; then
        msg_dim "  To copy to another server:"
        msg_dim "  scp ${source_ip}:${filepath} /tmp/"
    fi
    if command -v base64 >/dev/null 2>&1; then
        local base64_payload
        base64_payload=$(base64 "$filepath" | tr -d '\n') || base64_payload=""
        if [[ -n "$base64_payload" ]]; then
            msg_dim "  Or use base64:"
            msg_dim "  echo '$base64_payload' | base64 -d > backup.json"
        fi
    fi

    return 0
}

    # cmd_import <filepath> [method] - import rules from JSON
cmd_import() {
    local filepath="$1"
    local override_method="${2:-}"

    if [[ "$filepath" =~ ^https?:// ]]; then
        msg_err "Remote URL import has been removed; download the JSON file locally first"
        return 1
    fi

    require_root "$0 import"
    ensure_jq || return 1

    if [[ ! -f "$filepath" ]]; then
        msg_err "File not found: $filepath"
        return 1
    fi

    # Validate JSON
    if ! jq '.' "$filepath" >/dev/null 2>&1; then
        msg_err "Invalid JSON file: $filepath"
        return 1
    fi
    if ! json_require_v3_backup "$filepath"; then
        msg_err "Unsupported backup format: expected v3 JSON with forward_rules"
        return 1
    fi

    local count
    count=$(json_forward_rules_count "$filepath")
    msg_info "Found $count rule(s) in backup"

    # Show rules summary
    json_forward_rules_summary "$filepath" "$override_method"

    local imported=0 failed=0 skipped=0
    local nft_batch_count=0

    _BATCH_MODE=true
    while IFS=$'\t' read -r method lport target tport proto ipver comment mss_mode mss_value snat_mode snat_source; do
        [[ -z "$method" ]] && continue
        if ! validate_comment "$comment"; then
            msg_warn "Skipping rule :$lport -> $target:$tport due to invalid multi-line/tab comment"
            ((failed++)) || true
            continue
        fi
        case "$method" in
            nft|nftables)
                if pfwd_state_add_rule "$lport" "$target" "$tport" "$ipver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "false"; then
                    ((imported++)) || true
                    ((nft_batch_count++)) || true
                else
                    msg_warn "Failed to import nft rule :$lport -> $target:$tport"
                    ((failed++)) || true
                fi
                ;;
            realm)
                ((skipped++)) || true
                ;;
            *)
                msg_warn "Unknown method '$method' for rule :$lport, skipping"
                ((failed++)) || true
                ;;
        esac
    done < <(json_forward_rules_tsv "$filepath" "$override_method")
    _BATCH_MODE=false

    if (( nft_batch_count > 0 )) && ! _batch_finalize nft; then
        msg_err "Failed to apply imported nftables batch"
        return 1
    elif (( nft_batch_count == 0 )); then
        _pfwd_state_discard_batch
    fi

    msg_ok "Import complete: $imported imported, $failed failed, $skipped skipped"
}

#===============================================================================
#  Section 7: Persistence Integration
#===============================================================================

# Persistence is intentionally kept inside the main script:
# nft_setup_persistence() writes lightweight systemd units that call the hidden
# CLI entrypoints below, instead of generating extra helper scripts on disk.

#===============================================================================
#  Section 8: CLI Entry Points
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
  verify      Verify forwarding rules validity
  fix-ufw     Fix UFW loopback DNAT rules
  start       Start forwarding (nft / all)
  stop        Stop forwarding (nft / all)
  restart     Restart forwarding (nft / all)
  refresh     Re-resolve targets and rebuild nftables from saved state
  stats       Traffic statistics
  export      Export config to JSON
  import      Import config from JSON
  uninstall   Uninstall (nftables / all)
  optimize    Run kernel optimization [balanced|gaming|lowmem|relay]
  help        Show this help

Quick syntax:
  pfwd <port> <target>                    Add single nft rule
  pfwd <port> <target> <tport>            Add single mapped nft rule
  pfwd -m nft -t <target> 80,443          Add multiple nft rules
  pfwd -m nft -t <target> --replace 443   Replace an existing nft rule explicitly

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
  pfwd doctor --tcp-probe
  pfwd doctor --tcp-probe --probe-timeout 5
  pfwd refresh
  pfwd stats
  pfwd stats --rate
  pfwd stats --interval
  pfwd stats --interval 1m

Import / export:
  pfwd export [filepath]
  pfwd import <filepath> [-m nft]
  Export and import use the current JSON v3 schema (forward_rules).
  Export/import preserves nft MSS and fixed-SNAT fields.

New examples:
  pfwd -m nft -t 10.0.0.2 --mss-clamp 443
  pfwd -m nft -t 10.0.0.2 --mss 1360 8443:443
  pfwd -m nft -t 10.0.0.2 --replace 8443:443
  pfwd -m nft -4 -t 10.0.0.2 --snat-source 192.168.1.2 9443:443
  pfwd -m nft -4 -t 10.0.0.2 --snat-source 192.168.1.2 --mss 1360 9443:443
  pfwd list -f snat
  pfwd export /tmp/pfwd-backup.json
  pfwd import /tmp/pfwd-backup.json
  Interactive add/delete/list/status also show MSS/SNAT options.

Common scenarios:
  pfwd 8080 1.2.3.4
  pfwd -m nft -t 1.2.3.4 --both 80,443
  pfwd -m nft -t 127.0.0.1 33389:3389
  pfwd doctor
  pfwd import backup.json
  pfwd optimize balanced
  pfwd optimize relay

Performance tips:
  - pfwd now treats $RULES_STATE_FILE as the source of truth.
  - refresh/start rebuild nftables atomically from saved state.
  - nft is the fastest path for fixed IP targets.
  - First root run from a persistent script path auto-installs /usr/local/bin/pfwd.
  - If using loopback DNAT (127.0.0.1 / ::1), verify UFW loopback exceptions stay synced.
  - optimize skips unsupported sysctl keys instead of failing the whole profile.

Options:
  -m, --method <nft>         Forwarding method (required)
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
  --snat-source <addr>       nft only: use fixed SNAT source instead of masquerade (auto-switches -46 to matching family)
  --masquerade               nft only: force default masquerade mode
  -c, --comment <text>       Add single-line comment to rule
  -q, --quiet                Quiet mode
  --no-color                 Disable colored output
  --no-clear                 Don't clear screen in interactive menu

Interactive note:
  After choosing fixed SNAT, the menu can suggest a fixed MSS from the
  smaller source/backend path metric it can observe, preferring route advmss,
  then route MTU, then link MTU.
  If IP version is left at dual-stack (-46), pfwd auto-switches to IPv4 or IPv6
  to match the fixed SNAT source address.
  The suggestion is informational; you still choose Off/Clamp/Fixed.
EOF
}

# cmd_add - add forwarding rules from CLI
cmd_add() {
    require_root "$0 add"
    local method="" ip_ver="46" proto="tcp" comment="" target="" rules_str=""
    local mss_mode="" mss_value="" snat_mode="masquerade" snat_source="" replace_mode="false"
    local -a positional_args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--method)  require_option_value "$1" "$@" || return 1; method="$2"; shift 2 ;;
            -t|--target)  require_option_value "$1" "$@" || return 1; target="$2"; shift 2 ;;
            -4)           ip_ver="4"; shift ;;
            -6)           ip_ver="6"; shift ;;
            -46)          ip_ver="46"; shift ;;
            --tcp)        proto="tcp"; shift ;;
            --udp)        proto="udp"; shift ;;
            --both)       proto="both"; shift ;;
            --mss-clamp)  mss_mode="clamp"; mss_value=""; shift ;;
            --mss)        require_option_value "$1" "$@" || return 1; mss_mode="set"; mss_value="$2"; shift 2 ;;
            --replace)    replace_mode="true"; shift ;;
            --snat-source) require_option_value "$1" "$@" || return 1; snat_mode="snat"; snat_source="$2"; shift 2 ;;
            --masquerade) snat_mode="masquerade"; snat_source=""; shift ;;
            -c|--comment) require_option_value "$1" "$@" || return 1; comment="$2"; shift 2 ;;
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

    if ! _prepare_add_request "$method" "$ip_ver" "$target" "$rules_str" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode"; then
        return 1
    fi
    ip_ver="${PFWD_REQUEST_IP_VER:-$ip_ver}"
    if [[ "$snat_mode" == "snat" ]]; then
        _pfwd_print_fixed_snat_notice "$snat_source"
    fi

    [[ "$method" == "realm" ]] && return 0

    if ! _execute_add_request "$method" "$ip_ver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode"; then
        return 1
    fi

    if (( PFWD_ADD_ADDED > 0 || PFWD_ADD_FAILED > 0 )); then
        msg_info "Result: $PFWD_ADD_ADDED added, $PFWD_ADD_FAILED failed"
    fi
}

# cmd_delete - delete forwarding rules
cmd_delete() {
    require_root "$0 del"
    local method="" ports_str="" proto="both"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--method) require_option_value "$1" "$@" || return 1; method="$2"; shift 2 ;;
            --tcp)       proto="tcp"; shift ;;
            --udp)       proto="udp"; shift ;;
            --both)      proto="both"; shift ;;
            -q|--quiet)  QUIET=true; shift ;;
            -*)          msg_err "Unknown option: $1"; return 1 ;;
            *)           ports_str="$1"; shift ;;
        esac
    done

    if [[ -z "$method" ]]; then
        msg_err "Method is required. Use -m nft"
        return 1
    fi

    if [[ "$method" == "realm" ]]; then
        return 0
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
            -f|--filter) require_option_value "$1" "$@" || return 1; filter="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    _pfwd_collect_state
    echo -e "${BOLD}Forwarding Rules${NC}"
    echo -e "${DIM}$SEP_EQ${NC}"
    [[ -n "$filter" ]] && echo -e "  ${DIM}Filter: $filter${NC}"
    echo ""
    nft_list_rules "$filter" "$(_nft_rules_for_display)"
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

# verify_forwarding_rules - 验证转发规则的有效性
verify_forwarding_rules() {
    msg_info "Verifying forwarding rules..."

    local parsed_rules
    parsed_rules=$(pfwd_state_rules_tsv)

    local errors=0
    local warnings=0

    while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value; do
        [[ -z "$lport" ]] && continue

        # 验证目标地址格式
        local target_type
        target_type=$(detect_ip_type "$target")
        if [[ "$target_type" == "unknown" ]]; then
            msg_err "Rule #$lport: Invalid target address '$target'"
            ((errors++))
            continue
        fi

        # 验证目标可达性（仅警告）
        local resolved_target=""
        if ! resolved_target=$(_pfwd_state_resolved_target "$target" "$ipver" 2>/dev/null); then
            msg_err "Rule #$lport: Target $target cannot be resolved for IPv${ipver}"
            ((errors++))
            continue
        fi
        if [[ "$target_type" == "ipv4" || "$target_type" == "ipv6" || "$target_type" == "domain" ]]; then
            if ! ping -c 1 -W 2 "$resolved_target" >/dev/null 2>&1; then
                msg_warn "Rule #$lport: Target $target ($resolved_target):$tport is not reachable"
                ((warnings++))
            fi
        fi

        # 验证端口范围
        if ! validate_port "$lport" || ! validate_port "$tport"; then
            msg_err "Rule #$lport: Invalid port number"
            ((errors++))
        fi

    done <<< "$parsed_rules"

    echo ""
    if (( errors > 0 )); then
        msg_err "Found $errors error(s) in forwarding rules"
        return 1
    elif (( warnings > 0 )); then
        msg_warn "Found $warnings warning(s) in forwarding rules"
        return 0
    else
        msg_ok "All forwarding rules are valid"
        return 0
    fi
}

_pfwd_fixed_snat_targets_ssh() {
    local expanded
    for expanded in "${EXPANDED_RULES[@]:-}"; do
        parse_rule "$expanded" || continue
        if [[ "$RULE_LPORT" == "22" || "$RULE_TPORT" == "22" ]]; then
            return 0
        fi
    done
    return 1
}

_pfwd_print_fixed_snat_notice() {
    local snat_source="$1"
    [[ -n "$snat_source" ]] || return 0

    msg_warn "Fixed SNAT enabled: backend hosts will only see source ${snat_source}"
    msg_warn "If the backend uses fail2ban, ACLs, or IP allowlists, explicitly allow ${snat_source}"
    if _pfwd_fixed_snat_targets_ssh; then
        msg_warn "SSH forwarding detected: backend sshd/fail2ban policy can block ${snat_source} and break forwarded SSH access"
    fi
}

_pfwd_tcp_probe_backend() {
    local host="$1" port="$2" probe_timeout="${3:-3}"
    local output="" status=0

    PFWD_TCP_PROBE_RESULT="error"
    PFWD_TCP_PROBE_DETAIL=""

    if command -v timeout >/dev/null 2>&1; then
        if output=$(timeout "${probe_timeout}s" bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$host" "$port" 2>&1); then
            PFWD_TCP_PROBE_RESULT="ok"
            return 0
        fi
        status=$?
        case "$status" in
            124)
                PFWD_TCP_PROBE_RESULT="timeout"
                return 124
                ;;
            *)
                if [[ "$output" == *"Connection refused"* ]]; then
                    PFWD_TCP_PROBE_RESULT="refused"
                    return 111
                fi
                PFWD_TCP_PROBE_DETAIL="$output"
                return "$status"
                ;;
        esac
    fi

    if command -v nc >/dev/null 2>&1; then
        if output=$(nc -z -w "$probe_timeout" "$host" "$port" 2>&1); then
            PFWD_TCP_PROBE_RESULT="ok"
            return 0
        fi
        status=$?
        if [[ "$output" == *"Connection refused"* ]]; then
            PFWD_TCP_PROBE_RESULT="refused"
            return 111
        fi
        if [[ "$output" == *"timed out"* || "$output" == *"timeout"* ]]; then
            PFWD_TCP_PROBE_RESULT="timeout"
            return 124
        fi
        PFWD_TCP_PROBE_DETAIL="$output"
        return "$status"
    fi

    PFWD_TCP_PROBE_RESULT="unavailable"
    PFWD_TCP_PROBE_DETAIL="need timeout(1) or nc"
    return 127
}

_pfwd_doctor_tcp_probe() {
    local probe_timeout="${1:-3}"
    local runtime_rules seen_unavailable=false
    runtime_rules=$(_pfwd_state_runtime_rules_tsv "$PFWD_NFT_RULES" "false")
    [[ -n "$runtime_rules" ]] || return 0

    local proto lport ipver target_input resolved_target tport comment snat_mode snat_source mss_mode mss_value
    while IFS=$'\t' read -r proto lport ipver target_input resolved_target tport comment snat_mode snat_source mss_mode mss_value; do
        [[ -z "$lport" || "$proto" != "tcp" || -z "$resolved_target" ]] && continue
        _pfwd_tcp_probe_backend "$resolved_target" "$tport" "$probe_timeout" || true
        case "$PFWD_TCP_PROBE_RESULT" in
            ok)
                _doctor_print_check OK "TCP probe connect ok" ":$lport IPv${ipver} -> ${resolved_target}:${tport}"
                ;;
            refused)
                _doctor_print_check WARN "TCP probe connection refused" ":$lport IPv${ipver} -> ${resolved_target}:${tport}"
                ;;
            timeout)
                _doctor_print_check WARN "TCP probe timeout" ":$lport IPv${ipver} -> ${resolved_target}:${tport}"
                ;;
            unavailable)
                if [[ "$seen_unavailable" == false ]]; then
                    _doctor_print_check WARN "TCP probe unavailable" "$PFWD_TCP_PROBE_DETAIL"
                    seen_unavailable=true
                fi
                return 0
                ;;
            *)
                _doctor_print_check WARN "TCP probe failed" ":$lport IPv${ipver} -> ${resolved_target}:${tport} ${PFWD_TCP_PROBE_DETAIL:+- $PFWD_TCP_PROBE_DETAIL}"
                ;;
        esac
    done <<< "$runtime_rules"
}

cmd_doctor() {
    local tcp_probe=false probe_timeout=3
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tcp-probe)
                tcp_probe=true
                shift
                ;;
            --probe-timeout)
                require_option_value "$1" "$@" || return 1
                probe_timeout="$2"
                [[ "$probe_timeout" =~ ^[0-9]+$ && "$probe_timeout" -ge 1 ]] || {
                    msg_err "Probe timeout must be a positive integer (seconds)"
                    return 1
                }
                shift 2
                ;;
            *)
                msg_err "Unknown doctor option: $1"
                return 1
                ;;
        esac
    done

    _pfwd_collect_state
    _pfwd_collect_runtime_health
    echo -e "${BOLD}pfwd Doctor${NC}"
    echo -e "${DIM}$SEP_EQ${NC}"

    local state_rules="$PFWD_NFT_COUNT"
    local running_groups=0 saved_groups saved_valid=false
    saved_groups=$(_nft_saved_rule_count)

    if command -v nft >/dev/null 2>&1; then
        _doctor_print_check OK "nft command available"
    else
        _doctor_print_check ERROR "nft command missing" "install nftables before using nft forwarding"
    fi

    if [[ -f "$RULES_STATE_FILE" ]]; then
        _doctor_print_check OK "state file present" "${state_rules} rule(s) in $RULES_STATE_FILE"
    else
        _doctor_print_check WARN "state file missing" "$RULES_STATE_FILE"
    fi

    local unresolved_count=0
    if [[ -n "$PFWD_NFT_RULES" ]]; then
        local rule_proto rule_lport rule_ipver rule_target rule_tport rule_comment rule_snat_mode rule_snat_source rule_mss_mode rule_mss_value
        while IFS=$'\t' read -r rule_proto rule_lport rule_ipver rule_target rule_tport rule_comment rule_snat_mode rule_snat_source rule_mss_mode rule_mss_value; do
            [[ -n "$rule_lport" ]] || continue
            if ! _pfwd_state_resolved_target "$rule_target" "$rule_ipver" >/dev/null 2>&1; then
                ((unresolved_count++)) || true
                _doctor_print_check WARN "unresolved target in state" ":${rule_lport} IPv${rule_ipver} -> ${rule_target}:${rule_tport}"
            fi
        done <<< "$PFWD_NFT_RULES"
    fi
    if (( unresolved_count == 0 )) && (( state_rules > 0 )); then
        _doctor_print_check OK "state targets resolve successfully"
    fi

    if _nft_table_exists; then
        running_groups=$(awk 'NF > 0 { count++ } END { print count+0 }' <<< "$(_nft_prerouting_dnat_lines)")
        _doctor_print_check OK "nft table loaded" "${state_rules} state rule(s), ${running_groups} rendered DNAT group(s) active"
        local chain
        for chain in prerouting postrouting forward input; do
            if _nft_cached_chain "$chain" >/dev/null; then
                _doctor_print_check OK "chain ${chain} present"
            else
                _doctor_print_check ERROR "chain ${chain} missing" "runtime table is incomplete"
            fi
        done
        for chain in $(_pfwd_subchain_list prerouting) $(_pfwd_subchain_list postrouting) $(_pfwd_subchain_list forward); do
            if _nft_cached_chain "$chain" >/dev/null; then
                _doctor_print_check OK "subchain ${chain} present"
            else
                _doctor_print_check WARN "subchain ${chain} missing" "will be recreated on next nft add"
            fi
        done
        local ft_mode ft_devices expected_ft_devices
        ft_mode=$(_nft_flowtable_mode)
        ft_devices=$(_nft_flowtable_devices)
        expected_ft_devices=$(_pfwd_collect_flowtable_devices "$(_pfwd_state_runtime_rules_tsv "$PFWD_NFT_RULES" "false")" || true)
        case "$ft_mode" in
            offload|counter|basic)
                if _nft_cached_chain forward | grep -q 'flow add @ft'; then
                    _doctor_print_check OK "flowtable fast path configured" "mode=${ft_mode}, devices=${ft_devices}"
                else
                    _doctor_print_check WARN "flowtable exists but fast-path rule missing" "mode=${ft_mode}, devices=${ft_devices}"
                fi
                ;;
            *)
                _doctor_print_check WARN "flowtable fast path unavailable"
                ;;
        esac
        if [[ -n "$expected_ft_devices" && "$ft_devices" != "-" && "$expected_ft_devices" != "$ft_devices" ]]; then
            _doctor_print_check WARN "flowtable devices differ from current routes" "expected=${expected_ft_devices}, runtime=${ft_devices}"
        fi
    elif (( state_rules > 0 )); then
        _doctor_print_check WARN "saved pfwd state exists but table is not loaded" "run 'pfwd start nft' or 'pfwd refresh'"
    else
        _doctor_print_check WARN "no active nft forwarding table"
    fi

    if [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]]; then
        if command -v nft >/dev/null 2>&1 && _pfwd_validate_rendered_nft "$NFT_CONFIG"; then
            saved_valid=true
            _doctor_print_check OK "persisted nft config is valid" "$saved_groups rendered DNAT group(s) saved"
        else
            _doctor_print_check ERROR "persisted nft config failed validation" "$NFT_CONFIG"
        fi
    else
        _doctor_print_check WARN "persisted nft config missing" "$NFT_CONFIG"
    fi

    if (( state_rules > 0 && running_groups == 0 )) && ! _nft_table_exists; then
        _doctor_print_check WARN "rules are saved but not running" "use 'pfwd start nft' or 'pfwd refresh'"
    elif (( running_groups > 0 && saved_groups == 0 )); then
        _doctor_print_check WARN "rules are running but not saved" "use 'pfwd refresh'"
    elif (( running_groups > 0 && running_groups != saved_groups )); then
        _doctor_print_check WARN "saved/runtime rendered group counts differ" "saved=${saved_groups}, running=${running_groups}"
    fi

    if (( state_rules > 0 && running_groups > 0 && running_groups < state_rules )); then
        _doctor_print_check OK "rule aggregation active" "state=${state_rules}, rendered=${running_groups}"
    fi

    local fwd4 fwd6
    fwd4=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    fwd6=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "0")
    [[ "$fwd4" == "1" ]] && _doctor_print_check OK "IPv4 forwarding enabled" || _doctor_print_check ERROR "IPv4 forwarding disabled" "run 'pfwd optimize balanced' or enable net.ipv4.ip_forward=1"
    [[ "$fwd6" == "1" ]] && _doctor_print_check OK "IPv6 forwarding enabled" || _doctor_print_check WARN "IPv6 forwarding disabled"
    local traffic_interval
    traffic_interval=$(traffic_current_interval)
    _doctor_print_check OK "traffic collector interval" "$traffic_interval"
    local traffic_backend traffic_acct
    traffic_backend=$(traffic_stats_backend)
    traffic_acct=$(plat_sysctl_get net.netfilter.nf_conntrack_acct 0)
    case "$traffic_backend" in
        conntrack) _doctor_print_check OK "traffic stats backend available" "conntrack" ;;
        conntrack\(root\)) _doctor_print_check WARN "traffic stats backend requires root" "conntrack is installed but current user cannot query it directly" ;;
        proc) _doctor_print_check OK "traffic stats backend available" "/proc/net/nf_conntrack" ;;
        *) _doctor_print_check WARN "traffic stats backend unavailable" "install conntrack-tools or expose /proc/net/nf_conntrack" ;;
    esac
    if [[ "$traffic_acct" == "1" ]]; then
        _doctor_print_check OK "nf_conntrack_acct enabled"
    else
        _doctor_print_check WARN "nf_conntrack_acct disabled" "traffic stats may stay at zero until enabled"
    fi

    local traffic_data_state traffic_flow_state
    traffic_data_state=$(_traffic_file_format_state "$TRAFFIC_DATA" "$TRAFFIC_DATA_VERSION")
    traffic_flow_state=$(_traffic_file_format_state "$TRAFFIC_FLOW_DATA" "$TRAFFIC_FLOW_VERSION")
    case "$traffic_data_state" in
        ok) _doctor_print_check OK "traffic totals state format" "v${TRAFFIC_DATA_VERSION}" ;;
        missing|empty) _doctor_print_check WARN "traffic totals state missing" "collector will recreate $TRAFFIC_DATA" ;;
        mismatch:*) _doctor_print_check WARN "traffic totals state version mismatch" "${traffic_data_state#mismatch:} -> v${TRAFFIC_DATA_VERSION}; next collector run resets history" ;;
        legacy) _doctor_print_check WARN "traffic totals state is legacy" "next collector run resets history" ;;
    esac
    case "$traffic_flow_state" in
        ok) _doctor_print_check OK "traffic flow snapshot format" "v${TRAFFIC_FLOW_VERSION}" ;;
        missing|empty) _doctor_print_check WARN "traffic flow snapshot missing" "collector will recreate $TRAFFIC_FLOW_DATA" ;;
        mismatch:*) _doctor_print_check WARN "traffic flow snapshot version mismatch" "${traffic_flow_state#mismatch:} -> v${TRAFFIC_FLOW_VERSION}; next collector run resets history" ;;
        legacy) _doctor_print_check WARN "traffic flow snapshot is legacy" "next collector run resets history" ;;
    esac

    if $PFWD_LOOPBACK_DNAT; then
        local route_all route_default
        route_all=$(plat_sysctl_get net.ipv4.conf.all.route_localnet 0)
        route_default=$(plat_sysctl_get net.ipv4.conf.default.route_localnet 0)
        if [[ "$route_all" == "1" && "$route_default" == "1" ]]; then
            _doctor_print_check OK "route_localnet enabled for loopback DNAT"
        else
            _doctor_print_check ERROR "route_localnet missing for loopback DNAT" "run 'pfwd optimize balanced' or re-add the loopback rule"
        fi

        if command -v ufw >/dev/null 2>&1; then
            case "$PFWD_UFW_PERSISTENCE_STATE" in
                ok) _doctor_print_check OK "UFW loopback DNAT exceptions synced" ;;
                degraded) _doctor_print_check ERROR "UFW loopback DNAT exceptions missing" "reload pfwd rules or run 'ufw reload'" ;;
                disabled) _doctor_print_check WARN "UFW disabled; loopback exception sync not needed" ;;
                *) _doctor_print_check WARN "UFW loopback state: $PFWD_UFW_LOOPBACK_STATE" ;;
            esac
        fi
    fi

    # 检查是否有 IPv4/IPv6 转发规则
    local parsed_rules has_ipv4_rules=false has_ipv6_rules=false has_loopback_rules=false
    parsed_rules=$(_pfwd_runtime_rules_to_parsed_tsv "$(_pfwd_state_runtime_rules_tsv "$PFWD_NFT_RULES" "false")")
    if [[ -n "$parsed_rules" ]]; then
        while IFS=$'\t' read -r proto lport ipver target tport comment bytes; do
            [[ -z "$lport" ]] && continue
            if [[ "$ipver" == "4" ]]; then
                has_ipv4_rules=true
                [[ "$target" =~ ^127\. ]] && has_loopback_rules=true
            elif [[ "$ipver" == "6" ]]; then
                has_ipv6_rules=true
                [[ "$target" == "::1" ]] && has_loopback_rules=true
            fi
        done <<< "$parsed_rules"
    fi

    if [[ -n "$PFWD_NFT_RULES" ]]; then
        local rule_key rule_proto rule_lport rule_ipver rule_target rule_tport rule_comment rule_snat_mode rule_snat_source rule_mss_mode rule_mss_value
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            _parse_rule_key_meta_tsv "$line"
            rule_key="$RULEKEY_ROW_KEY"
            rule_proto="$RULEKEY_ROW_PROTO"
            rule_lport="$RULEKEY_ROW_LPORT"
            rule_ipver="$RULEKEY_ROW_IPVER"
            rule_target="$RULEKEY_ROW_TARGET"
            rule_tport="$RULEKEY_ROW_TPORT"
            rule_comment="$RULEKEY_ROW_COMMENT"
            rule_snat_mode="$RULEKEY_ROW_SNAT_MODE"
            rule_snat_source="$RULEKEY_ROW_SNAT_SOURCE"
            rule_mss_mode="$RULEKEY_ROW_MSS_MODE"
            rule_mss_value="$RULEKEY_ROW_MSS_VALUE"
            [[ -z "$rule_lport" ]] && continue
            [[ "$rule_proto" == "tcp" ]] || continue
            [[ "$rule_snat_mode" == "snat" && -n "$rule_snat_source" && -z "$rule_mss_mode" ]] || continue
            if suggest_mss_for_snat_source "$rule_snat_source" "$rule_target"; then
                local default_mss=1460
                [[ "$rule_ipver" == "6" ]] && default_mss=1440
                if (( MSS_SUGGEST_VALUE < default_mss )); then
                    _doctor_print_check WARN "rule :$rule_lport fixed SNAT without MSS tuning" "suggest clamp or --mss ${MSS_SUGGEST_VALUE} for ${rule_target}:${rule_tport}"
                fi
            fi
        done <<< "$(_traffic_rules_with_keys "$PFWD_NFT_RULES")"
    fi

    case "$PFWD_IPTABLES_V4_FORWARD_STATE" in
        ok) _doctor_print_check OK "iptables FORWARD managed exceptions present" ;;
        missing) _doctor_print_check ERROR "iptables FORWARD policy is DROP but pfwd exceptions are missing" "run 'pfwd refresh' or 'pfwd start nft'" ;;
        not-needed) _doctor_print_check OK "iptables FORWARD policy needs no IPv4 exceptions" ;;
        policy-open) _doctor_print_check OK "iptables FORWARD policy is not DROP" ;;
        unavailable) _doctor_print_check WARN "iptables command unavailable for IPv4 FORWARD checks" ;;
    esac
    case "$PFWD_IPTABLES_V6_FORWARD_STATE" in
        ok) _doctor_print_check OK "ip6tables FORWARD managed exceptions present" ;;
        missing) _doctor_print_check ERROR "ip6tables FORWARD policy is DROP but pfwd exceptions are missing" "run 'pfwd refresh' or 'pfwd start nft'" ;;
        not-needed) _doctor_print_check OK "ip6tables FORWARD policy needs no IPv6 exceptions" ;;
        policy-open) _doctor_print_check OK "ip6tables FORWARD policy is not DROP" ;;
        unavailable) _doctor_print_check WARN "ip6tables command unavailable for IPv6 FORWARD checks" ;;
    esac
    case "$PFWD_IPTABLES_V4_INPUT_STATE" in
        ok) _doctor_print_check OK "iptables INPUT managed exception present for loopback DNAT" ;;
        missing) _doctor_print_check ERROR "iptables INPUT loopback DNAT exception missing" "run 'pfwd refresh' or 'pfwd start nft'" ;;
    esac
    case "$PFWD_IPTABLES_V6_INPUT_STATE" in
        ok) _doctor_print_check OK "ip6tables INPUT managed exception present for loopback DNAT" ;;
        missing) _doctor_print_check ERROR "ip6tables INPUT loopback DNAT exception missing" "run 'pfwd refresh' or 'pfwd start nft'" ;;
    esac

    if [[ -f "$NFT_RESTORE_SERVICE" ]]; then
        _doctor_print_check OK "boot restore service present" "$NFT_RESTORE_SERVICE"
    else
        _doctor_print_check WARN "boot restore service missing" "rules may not survive reboot"
    fi

    if [[ -f "$TRAFFIC_SAVE_TIMER" ]]; then
        _doctor_print_check OK "traffic collector timer present" "interval=$(traffic_current_interval)"
        local interval_seconds stale_after traffic_age
        interval_seconds=$(traffic_interval_seconds "$traffic_interval")
        stale_after=$(( interval_seconds * TRAFFIC_STALE_MULTIPLIER ))
        traffic_age=$(_traffic_file_age_seconds "$TRAFFIC_DATA")
        if (( interval_seconds > 0 && traffic_age >= 0 )); then
            if (( traffic_age > stale_after )); then
                _doctor_print_check WARN "traffic collector data looks stale" "last update ${traffic_age}s ago"
            else
                _doctor_print_check OK "traffic collector freshness" "last update ${traffic_age}s ago"
            fi
        fi
    else
        _doctor_print_check WARN "traffic collector timer missing" "background traffic stats will not persist"
    fi

    if $tcp_probe; then
        _doctor_print_check OK "active TCP probe enabled" "timeout=${probe_timeout}s"
        _pfwd_doctor_tcp_probe "$probe_timeout"
    fi
}

# cmd_stop - stop forwarding without removing config
# cmd_status - show running status and rule counts
cmd_status() {
    _pfwd_collect_state
    _pfwd_collect_runtime_health
    echo -e "${BOLD}pfwd Status${NC}"
    echo -e "${DIM}$SEP_EQ_40${NC}"

    local nft_status
    if $PFWD_NFT_RUNNING; then
        if $PFWD_RUNTIME_HEALTH_DEGRADED; then
            nft_status="${YELLOW}running (degraded)${NC}"
        else
            nft_status="${GREEN}running${NC}"
        fi
    else
        nft_status="${RED}stopped${NC}"
    fi
    echo -e "  nftables:  $nft_status  ($PFWD_NFT_COUNT rules)"
    if [[ -n "$PFWD_NFT_RULES" ]]; then
        local nft_mss_count=0 nft_snat_count=0
        local rule_key proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            _parse_rule_key_meta_tsv "$line"
            lport="$RULEKEY_ROW_LPORT"
            snat_mode="$RULEKEY_ROW_SNAT_MODE"
            mss_mode="$RULEKEY_ROW_MSS_MODE"
            [[ -z "$lport" ]] && continue
            [[ "$snat_mode" == "snat" ]] && ((nft_snat_count++)) || true
            [[ -n "$mss_mode" ]] && ((nft_mss_count++)) || true
        done <<< "$(_traffic_rules_with_keys "$PFWD_NFT_RULES")"
        if (( nft_mss_count > 0 || nft_snat_count > 0 )); then
            echo -e "  nft opts:  mss=${CYAN}${nft_mss_count}${NC}, fixed-snat=${CYAN}${nft_snat_count}${NC}"
        fi
    fi

    local iptables_forward_status=""
    case "$PFWD_IPTABLES_V4_FORWARD_STATE" in
        ok) iptables_forward_status+="IPv4 ${GREEN}ok${NC}" ;;
        missing) iptables_forward_status+="IPv4 ${RED}missing${NC}" ;;
        policy-open) iptables_forward_status+="IPv4 ${DIM}policy-open${NC}" ;;
        not-needed) iptables_forward_status+="IPv4 ${DIM}idle${NC}" ;;
        unavailable) iptables_forward_status+="IPv4 ${YELLOW}unknown${NC}" ;;
    esac
    if [[ -n "$iptables_forward_status" ]]; then
        iptables_forward_status+=", "
    fi
    case "$PFWD_IPTABLES_V6_FORWARD_STATE" in
        ok) iptables_forward_status+="IPv6 ${GREEN}ok${NC}" ;;
        missing) iptables_forward_status+="IPv6 ${RED}missing${NC}" ;;
        policy-open) iptables_forward_status+="IPv6 ${DIM}policy-open${NC}" ;;
        not-needed) iptables_forward_status+="IPv6 ${DIM}idle${NC}" ;;
        unavailable) iptables_forward_status+="IPv6 ${YELLOW}unknown${NC}" ;;
    esac
    [[ -n "$iptables_forward_status" ]] && echo -e "  iptables fwd: ${iptables_forward_status}"

    local ufw_persist_status=""
    case "$PFWD_UFW_PERSISTENCE_STATE" in
        ok) ufw_persist_status="${GREEN}ok${NC}" ;;
        degraded) ufw_persist_status="${RED}degraded${NC}" ;;
        idle) ufw_persist_status="${DIM}idle${NC}" ;;
        disabled) ufw_persist_status="${DIM}ufw off${NC}" ;;
        unavailable) ufw_persist_status="${DIM}n/a${NC}" ;;
        *) ufw_persist_status="${YELLOW}${PFWD_UFW_PERSISTENCE_STATE}${NC}" ;;
    esac
    echo -e "  UFW persist: ${ufw_persist_status}"

    echo -e "  traffic int: ${CYAN}${PFWD_TRAFFIC_INTERVAL}${NC}"
    local traffic_backend_label
    case "$PFWD_TRAFFIC_BACKEND" in
        conntrack) traffic_backend_label="${GREEN}${PFWD_TRAFFIC_BACKEND}${NC}" ;;
        proc) traffic_backend_label="${GREEN}${PFWD_TRAFFIC_BACKEND}${NC}" ;;
        conntrack\(root\)) traffic_backend_label="${YELLOW}${PFWD_TRAFFIC_BACKEND}${NC}" ;;
        *) traffic_backend_label="${RED}${PFWD_TRAFFIC_BACKEND}${NC}" ;;
    esac
    echo -e "  traffic src: ${traffic_backend_label}"

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
    require_root "$0 stop"
    local target="${1:-all}"
    case "$target" in
        nft|nftables)
            if _nft_table_exists; then
                nft_setup_persistence
                plat_nft_delete_table $NFT_TABLE || true
                _nft_invalidate_cache
                msg_ok "nftables forwarding stopped (config saved)"
            else
                msg_warn "nftables forwarding is not running"
            fi
            ;;
        all)
            cmd_stop nft
            ;;
        *)
            msg_err "Specify what to stop: nft or all"
            return 1
            ;;
    esac
}

# cmd_start - start forwarding from saved config
cmd_start() {
    require_root "$0 start"
    local target="${1:-all}"
    case "$target" in
        nft|nftables)
            if _nft_table_exists; then
                msg_warn "nftables forwarding is already running; validating guard state"
                if ! _pfwd_enforce_runtime_health; then
                    msg_err "nftables forwarding is running but degraded"
                    return 1
                fi
                msg_ok "nftables forwarding already running and healthy"
                return 0
            fi
            if cmd_internal_restore_nft; then
                _pfwd_collect_state
                if $PFWD_RUNTIME_HEALTH_DEGRADED; then
                    msg_err "nftables forwarding started but guard validation is degraded"
                    return 1
                fi
                msg_ok "nftables forwarding started ($PFWD_NFT_COUNT state rule(s) restored)"
            else
                msg_err "Failed to start nftables forwarding cleanly"
                return 1
            fi
            ;;
        all)
            cmd_start nft
            ;;
        *)
            msg_err "Specify what to start: nft or all"
            return 1
            ;;
    esac
}

cmd_refresh() {
    require_root "$0 refresh"
    _reset_change_flags
    pfwd_state_ensure_initialized
    if [[ -z "$(pfwd_state_rules_tsv)" ]]; then
        msg_warn "No saved pfwd state found"
        return 0
    fi
    if ! pfwd_apply_saved_state; then
        return 1
    fi
    nft_setup_persistence
    if ! _pfwd_enforce_runtime_health; then
        _reset_change_flags
        msg_err "pfwd state refreshed but guard validation failed"
        return 1
    fi
    _pfwd_collect_state
    _reset_change_flags
    msg_ok "pfwd state refreshed and nftables rules rebuilt"
}

# cmd_uninstall - uninstall components
cmd_uninstall() {
    require_root "$0 uninstall"
    local target="${1:-}"

    case "$target" in
        nft|nftables)
            nft_flush_all
            ;;
        all)
            nft_flush_all
            # Remove sysctl config
            if [[ -f "$SYSCTL_CONF" ]]; then
                local marker_start="# pfwd-managed-start"
                local marker_end="# pfwd-managed-end"
                sed -i "/$marker_start/,/$marker_end/d" "$SYSCTL_CONF"
                plat_sysctl_apply_file "$SYSCTL_CONF"
            fi
            rm -f "$SHORTCUT_LINK"
            rm -rf "$DATA_DIR"
            msg_ok "All pfwd components removed"
            ;;
        *)
            msg_err "Specify what to uninstall: nft or all"
            return 1
            ;;
    esac
}

_rewrite_shortcut_args() {
    PFWD_SHORTCUT_ARGS=()
    if [[ $# -lt 2 ]]; then
        return 1
    fi
    if [[ ! "$1" =~ ^[0-9] || "$2" =~ ^- ]]; then
        return 1
    fi

    local first="$1" second="$2" target_port="" extra_start=3 arg_index rewritten_ports
    if [[ "$1" =~ ^[0-9]+$ && $# -ge 3 && "${3:-}" =~ ^[0-9]+$ ]]; then
        target_port=":$3"
        extra_start=4
    fi

    if [[ -n "$target_port" ]]; then
        rewritten_ports="${first}${target_port}"
    else
        rewritten_ports="$first"
    fi

    PFWD_SHORTCUT_ARGS=("-m" "nft" "-t" "$second" "$rewritten_ports")
    for (( arg_index=extra_start; arg_index<=$#; arg_index++ )); do
        PFWD_SHORTCUT_ARGS+=("${!arg_index}")
    done
    return 0
}

_parse_import_args() {
    PFWD_IMPORT_PATH=""
    PFWD_IMPORT_METHOD=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--method)
                require_option_value "$1" "$@" || return 1
                PFWD_IMPORT_METHOD="$2"
                shift 2
                ;;
            -*)
                msg_err "Unknown option: $1"
                return 1
                ;;
            *)
                PFWD_IMPORT_PATH="$1"
                shift
                ;;
        esac
    done

    if [[ -z "$PFWD_IMPORT_PATH" ]]; then
        msg_err "Specify a local JSON file path"
        return 1
    fi
}

# parse_cli_args - main CLI entry point
parse_cli_args() {
    if [[ $# -eq 0 ]]; then
        interactive_menu
        return
    fi

    if _rewrite_shortcut_args "$@"; then
        cmd_add "${PFWD_SHORTCUT_ARGS[@]}"
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
            cmd_stop "$rt" || return 1
            cmd_start "$rt"
            ;;
        refresh)
            cmd_refresh
            ;;
        stats|traffic)
            shift
            if [[ "${1:-}" == "--rate" ]]; then
                show_traffic_rate
            elif [[ "${1:-}" == "--interval" ]]; then
                if [[ -n "${2:-}" ]]; then
                    traffic_configure_interval "$2"
                else
                    show_traffic_interval
                fi
            else
                show_traffic_stats
            fi
            ;;
        status)
            cmd_status
            ;;
        doctor|diagnose)
            shift
            cmd_doctor "$@"
            ;;
        verify)
            verify_forwarding_rules
            ;;
        fix-ufw)
            fix_ufw_loopback_rules
            ;;
        export)
            shift
            cmd_export "${1:-}"
            ;;
        import)
            shift
            _parse_import_args "$@" || return 1
            cmd_import "$PFWD_IMPORT_PATH" "$PFWD_IMPORT_METHOD"
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
        __restore-nft)
            QUIET=true
            cmd_internal_restore_nft
            ;;
        __traffic-collector)
            QUIET=true
            cmd_internal_traffic_collector
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
#  Section 9: Presenters & Interactive Menu
#===============================================================================

show_header() {
    $_NO_CLEAR || clear 2>/dev/null || true

    _pfwd_collect_state

    local rule_count=$PFWD_NFT_COUNT

    # Check running status (colored + plain text)
    local status_text status_plain
    if $PFWD_NFT_RUNNING; then
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
    perf_parts+=("stats:${PFWD_TRAFFIC_BACKEND}")
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
        local _nft_running=false
        _nft_running=$PFWD_NFT_RUNNING
        local _fwd_label
        if $_nft_running; then
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
        echo -e "  ${CYAN}7)${NC} Kernel optimization"
        echo -e "  ${CYAN}h)${NC} Help / CLI cheatsheet"
        echo ""
        echo -e "  ${DIM}── System ──${NC}"
        echo -e "  ${CYAN}8)${NC} ${RED}Uninstall${NC}"
        echo -e "  ${CYAN}0)${NC} ${DIM}Exit${NC}"
        echo ""
        read -rp "${CYAN}Select [0-8/s/d/h]:${NC} " choice

        case "$choice" in
            1) menu_add_rule || true ;;
            2) cmd_list; wait_for_enter ;;
            3) menu_delete_rule || true ;;
            4)
                if $_nft_running; then
                    menu_stop_forward || true
                else
                    menu_start_forward || true
                fi
                ;;
            5) menu_traffic_stats ;;
            s|S) cmd_status; wait_for_enter ;;
            d|D) cmd_doctor; wait_for_enter ;;
            6) menu_export_import || true ;;
            7)
                echo ""
                echo -e "  ${CYAN}1)${NC} balanced  (default, high bandwidth)"
                echo -e "  ${CYAN}2)${NC} gaming    (low latency, longer UDP timeout)"
                echo -e "  ${CYAN}3)${NC} lowmem    (for 512MB-1GB VPS)"
                echo -e "  ${CYAN}4)${NC} relay     (relay-focused forwarding tuning)"
                echo -e "  ${CYAN}5)${NC} ${YELLOW}Reset${NC}     (undo optimization, remove pfwd config)"
                echo -e "  ${CYAN}0)${NC} ${DIM}Back${NC}"
                echo ""
                read -rp "Select [0-5, default=1]: " _kp
                case "$_kp" in
                    0) continue ;;
                    2) optimize_kernel gaming; wait_for_enter ;;
                    3) optimize_kernel lowmem; wait_for_enter ;;
                    4) optimize_kernel relay; wait_for_enter ;;
                    5) reset_kernel_optimization; wait_for_enter ;;
                    *) optimize_kernel balanced; wait_for_enter ;;
                esac
                ;;
            h|H) show_help; wait_for_enter ;;
            8) menu_uninstall || true ;;
            0) echo "Bye."; exit 0 ;;
            *) msg_warn "Invalid choice"; sleep 1.5 ;;
        esac
    done
}

# menu_add_rule - interactive rule addition
menu_add_rule() {
    local mss_mode="" mss_value="" snat_mode="masquerade" snat_source="" replace_mode="false"
    local suggested_mss="" suggested_mss_iface="" suggested_mss_mtu="" suggested_mss_effective_mtu="" suggested_mss_family="" suggested_mss_logic=""
    local suggested_mss_side="" suggested_mss_source_iface="" suggested_mss_source_mtu="" suggested_mss_source_effective_mtu=""
    local suggested_mss_source_advmss="" suggested_mss_source_kind=""
    local suggested_mss_target_addr="" suggested_mss_target_iface="" suggested_mss_target_mtu="" suggested_mss_target_effective_mtu=""
    local suggested_mss_target_advmss="" suggested_mss_target_kind=""
    echo ""
    echo -e "${BOLD}Add Forwarding Rule${NC}"
    echo -e "${DIM}$SEP_DASH_40${NC}"

    local method="nft"

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

    # 6. Comment
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
                if ! validate_snat_request "$ip_ver" "$snat_mode" "$snat_source" "true"; then
                    wait_for_enter
                    return
                fi
                ip_ver="${PFWD_EFFECTIVE_IP_VER:-$ip_ver}"
                if [[ "$proto" != "udp" ]] && suggest_mss_for_snat_source "$snat_source" "$target"; then
                    suggested_mss="$MSS_SUGGEST_VALUE"
                    suggested_mss_iface="$MSS_SUGGEST_IFACE"
                    suggested_mss_mtu="$MSS_SUGGEST_MTU"
                    suggested_mss_effective_mtu="$MSS_SUGGEST_EFFECTIVE_MTU"
                    suggested_mss_family="$MSS_SUGGEST_FAMILY"
                    suggested_mss_logic="$MSS_SUGGEST_LOGIC"
                    suggested_mss_side="$MSS_SUGGEST_BOTTLENECK"
                    suggested_mss_source_iface="$MSS_SUGGEST_SOURCE_IFACE"
                    suggested_mss_source_mtu="$MSS_SUGGEST_SOURCE_MTU"
                    suggested_mss_source_effective_mtu="$MSS_SUGGEST_SOURCE_EFFECTIVE_MTU"
                    suggested_mss_source_advmss="$MSS_SUGGEST_SOURCE_ADVMSS"
                    suggested_mss_source_kind="$MSS_SUGGEST_SOURCE_KIND"
                    suggested_mss_target_addr="$MSS_SUGGEST_TARGET_ADDR"
                    suggested_mss_target_iface="$MSS_SUGGEST_TARGET_IFACE"
                    suggested_mss_target_mtu="$MSS_SUGGEST_TARGET_MTU"
                    suggested_mss_target_effective_mtu="$MSS_SUGGEST_TARGET_EFFECTIVE_MTU"
                    suggested_mss_target_advmss="$MSS_SUGGEST_TARGET_ADVMSS"
                    suggested_mss_target_kind="$MSS_SUGGEST_TARGET_KIND"
                    if [[ -n "$suggested_mss_source_iface" ]]; then
                        if [[ "$suggested_mss_source_kind" == "advmss" && -n "$suggested_mss_source_advmss" ]]; then
                            msg_dim "  Source-side path via ${suggested_mss_source_iface}: advmss ${suggested_mss_source_advmss}, link MTU ${suggested_mss_source_mtu}"
                        elif [[ "$suggested_mss_source_mtu" == "$suggested_mss_source_effective_mtu" ]]; then
                            msg_dim "  Source-side path via ${suggested_mss_source_iface}: MTU ${suggested_mss_source_mtu}"
                        else
                            msg_dim "  Source-side path via ${suggested_mss_source_iface}: MTU ${suggested_mss_source_mtu}, effective MTU ${suggested_mss_source_effective_mtu}"
                        fi
                    fi
                    if [[ -n "$suggested_mss_target_iface" ]]; then
                        if [[ "$suggested_mss_target_kind" == "advmss" && -n "$suggested_mss_target_advmss" ]]; then
                            msg_dim "  Backend path to ${suggested_mss_target_addr} via ${suggested_mss_target_iface}: advmss ${suggested_mss_target_advmss}, link MTU ${suggested_mss_target_mtu}"
                        elif [[ "$suggested_mss_target_mtu" == "$suggested_mss_target_effective_mtu" ]]; then
                            msg_dim "  Backend path to ${suggested_mss_target_addr} via ${suggested_mss_target_iface}: MTU ${suggested_mss_target_mtu}"
                        else
                            msg_dim "  Backend path to ${suggested_mss_target_addr} via ${suggested_mss_target_iface}: MTU ${suggested_mss_target_mtu}, effective MTU ${suggested_mss_target_effective_mtu}"
                        fi
                    fi
                    case "$suggested_mss_side" in
                        source) msg_dim "  Using smaller source-side path, suggested fixed MSS ${suggested_mss} (${suggested_mss_family})" ;;
                        target) msg_dim "  Using smaller backend-side path, suggested fixed MSS ${suggested_mss} (${suggested_mss_family})" ;;
                        both) msg_dim "  Both sides converge on MTU ${suggested_mss_effective_mtu}, suggested fixed MSS ${suggested_mss} (${suggested_mss_family})" ;;
                        *) msg_dim "  Suggested fixed MSS ${suggested_mss} (${suggested_mss_family})" ;;
                    esac
                    [[ -n "$suggested_mss_logic" ]] && msg_dim "  Logic: ${suggested_mss_logic}"
                    msg_dim "  Clamp to PMTU is safer when path MTU may vary; fixed MSS is only needed when you want to pin MSS explicitly."
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
                    if [[ -n "$suggested_mss" ]]; then
                        read -rp "MSS value [${suggested_mss}]: " mss_value
                        [[ -n "$mss_value" ]] || mss_value="$suggested_mss"
                    else
                        read -rp "MSS value: " mss_value
                    fi
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

    if ! _prepare_add_request "$method" "$ip_ver" "$target" "$port_spec" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode"; then
        msg_err "Failed to expand port spec"
        wait_for_enter
        return
    fi
    ip_ver="${PFWD_REQUEST_IP_VER:-$ip_ver}"
    if [[ "$snat_mode" == "snat" ]]; then
        echo ""
        _pfwd_print_fixed_snat_notice "$snat_source"
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
    if [[ "$method" == "nft" && "$target_type" == "domain" ]]; then
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

    if ! _execute_add_request "$method" "$ip_ver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode" "Adding" "true"; then
        wait_for_enter
        return
    fi

    echo ""
    msg_info "Result: $PFWD_ADD_ADDED rules added, $PFWD_ADD_FAILED failed"
    wait_for_enter
}

# menu_delete_rule - interactive rule deletion
menu_delete_rule() {
    echo ""
    echo -e "${BOLD}Delete Forwarding Rule${NC}"
    echo -e "${DIM}$SEP_DASH_40${NC}"

    local nft_parsed=""
    local merged_nft=""
    nft_parsed=$(pfwd_state_rules_tsv)
    if [[ -n "$nft_parsed" ]]; then
        merged_nft=$(_traffic_read_merged)
    fi

    local -a rule_methods=() rule_ports=() rule_labels=() rule_specs=()
    local -A nft_traffic_map=()
    local idx=0

    if [[ -n "$merged_nft" ]]; then
        while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
            [[ -z "$lport" ]] && continue
            nft_traffic_map["$(_traffic_rule_key "$proto" "$lport" "$ipver" "$target" "$tport")"]="${total_bytes:-0}"
        done <<< "$merged_nft"
    fi

    if [[ -n "$nft_parsed" ]]; then
        local rule_key resolved_target target_label
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            _pfwd_tsv_split_line "$line"
            proto="${PFWD_TSV_FIELDS[0]:-}"
            lport="${PFWD_TSV_FIELDS[1]:-}"
            ipver="${PFWD_TSV_FIELDS[2]:-}"
            target="${PFWD_TSV_FIELDS[3]:-}"
            tport="${PFWD_TSV_FIELDS[4]:-}"
            comment="${PFWD_TSV_FIELDS[5]:-}"
            snat_mode="${PFWD_TSV_FIELDS[6]:-}"
            snat_source="${PFWD_TSV_FIELDS[7]:-}"
            mss_mode="${PFWD_TSV_FIELDS[8]:-}"
            mss_value="${PFWD_TSV_FIELDS[9]:-}"
            [[ -z "$lport" ]] && continue
            ((idx++)) || true
            rule_methods+=("nft")
            rule_ports+=("$lport")
            rule_specs+=("${proto}|${lport}|${ipver}|${target}|${tport}")
            local option_label traffic_label
            resolved_target=$(_pfwd_state_resolved_target "$target" "$ipver" 2>/dev/null || true)
            target_label=$(_pfwd_state_target_label "$target" "$ipver")
            option_label=$(_nft_rule_option_summary "$snat_mode" "$snat_source" "$mss_mode" "$mss_value")
            traffic_label=$(format_bytes "${nft_traffic_map["$(_traffic_rule_key "$proto" "$lport" "$ipver" "${resolved_target:-$target}" "$tport")"]:-0}")
            rule_labels+=("$(printf "[nft] :%s %s IPv%s -> %s:%s [opts:%s] (%s)" "$lport" "$proto" "$ipver" "$target_label" "$tport" "$option_label" "$traffic_label")")
        done <<< "$(echo "$nft_parsed" | _sort_parsed_rules)"
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
    if (( ${#delete_port_numbers[@]} > 0 )); then
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

    local delete_count=0 nft_rule_deleted=0
    if (( ${#delete_rule_numbers[@]} > 0 )); then
        _BATCH_MODE=true
        for rnum in "${delete_rule_numbers[@]}"; do
            local ri=$((rnum - 1))
            local method="${rule_methods[$ri]}"
            case "$method" in
                nft)
                    local rule_proto rule_lport rule_ipver rule_target rule_tport
                    IFS='|' read -r rule_proto rule_lport rule_ipver rule_target rule_tport <<< "${rule_specs[$ri]}"
                    if _nft_delete_exact_rule "$rule_lport" "$rule_proto" "$rule_ipver" "$rule_target" "$rule_tport"; then
                        _traffic_delete_records nft_rule "$rule_proto" "$rule_lport" "$rule_ipver" "$rule_target" "$rule_tport"
                        ((nft_rule_deleted++)) || true
                        ((delete_count++)) || true
                    fi
                    ;;
            esac
        done
        _BATCH_MODE=false
        if (( nft_rule_deleted > 0 )); then
            if ! _batch_finalize nft; then
                msg_err "Failed to apply nftables deletion batch"
                wait_for_enter
                return
            fi
        else
            _pfwd_state_discard_batch
        fi
    fi

    if (( ${#delete_port_numbers[@]} > 0 )); then
        if (( ${#delete_port_numbers[@]} > 1 )); then
            nft_delete_ports_batch delete_port_numbers "$proto"
            delete_count=$(( delete_count + ${#delete_port_numbers[@]} ))
        else
            for port in "${delete_port_numbers[@]}"; do
                nft_delete_port "$port" "$proto"
                ((delete_count++)) || true
            done
        fi
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
    echo "  3) List backup files"
    echo "  0) Back"
    echo ""
    read -rp "Choice [0-3]: " ie_choice

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
            echo ""
            read -rp "Method [keep original]: " imethod
            cmd_import "$ipath" "$imethod"
            ;;
        3)
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
    echo "  1) Stop nftables"
    echo "  2) Stop all"
    echo "  0) Back"
    echo ""
    read -rp "Choice [0-2]: " schoice
    case "$schoice" in
        1) cmd_stop nft ;;
        2) cmd_stop all ;;
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
    echo "  1) Start nftables"
    echo "  2) Start all"
    echo "  0) Back"
    echo ""
    read -rp "Choice [0-2]: " schoice
    case "$schoice" in
        1) cmd_start nft ;;
        2) cmd_start all ;;
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
    echo "  1) Uninstall nftables rules"
    echo "  2) Uninstall everything"
    echo "  0) Back"
    echo ""
    read -rp "Choice [0-2]: " uchoice

    case "$uchoice" in
        1) cmd_uninstall nft ;;
        2)
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
#  Section 10: Main Entry
#===============================================================================

main() {
    init_runtime_flags "$@"
    detect_script_path
    ensure_shortcut_command "${PFWD_MAIN_ARGS[@]}"
    maybe_show_requirements_notice "${PFWD_MAIN_ARGS[@]}"
    if cli_requires_root "${PFWD_MAIN_ARGS[@]}"; then
        require_root "${PFWD_MAIN_ARGS[@]}"
    fi
    parse_cli_args "${PFWD_MAIN_ARGS[@]}"
}

# Initialize script path detection
SCRIPT_PATH=""

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
