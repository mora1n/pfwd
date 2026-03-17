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

readonly VERSION="1.9.4"

# Paths
readonly DATA_DIR="/var/lib/pfwd"
readonly NFT_CONFIG="/etc/nftables.d/port_forward.nft"
readonly NFT_BACKUP_DIR="/root/.pfwd_backup"
readonly NFT_RESTORE_SERVICE="/etc/systemd/system/pfwd-nft-restore.service"
readonly SYSCTL_CONF="/etc/sysctl.d/99-pfwd.conf"
readonly UFW_BEFORE_RULES="/etc/ufw/before.rules"
readonly UFW_BEFORE6_RULES="/etc/ufw/before6.rules"
readonly TRAFFIC_DATA="$DATA_DIR/traffic_stats.dat"
readonly TRAFFIC_LIMITS_DATA="$DATA_DIR/traffic_limits.json"
readonly TRAFFIC_SAVE_SERVICE="/etc/systemd/system/pfwd-traffic-save.service"
readonly TRAFFIC_SAVE_TIMER="/etc/systemd/system/pfwd-traffic-save.timer"
readonly TRAFFIC_DEFAULT_INTERVAL="1m"
readonly TRAFFIC_LIMITS_VERSION="2"

readonly INSTALLED_SCRIPT="/usr/local/bin/pfwd.sh"
readonly SHORTCUT_LINK="/usr/local/bin/pfwd"

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

json_forward_rules_summary() {
    local filepath="$1"
    while IFS=$'\t' read -r method lport target tport _proto _ipver _comment _mss_mode _mss_value _snat_mode _snat_source \
        _limit_in _limit_out _limit_total _limit_reset_every _limit_reset_at; do
        [[ -z "$method" ]] && continue
        printf '  [%s] :%s -> %s:%s\n' "$method" "$lport" "$target" "$tport"
    done < <(json_forward_rules_tsv "$filepath")
}

json_forward_rules_tsv() {
    local filepath="$1" override_method="${2:-}"
    jq -r --arg override "$override_method" '
        .forward_rules[] |
        [
            ($override | select(length > 0) // .kind // .type // "nft"),
            ((.local.port // .local_port) | tostring),
            ((.target.host // .target_ip) | tostring),
            ((.target.port // .target_port) | tostring),
            ((.network.protocol // .protocol // "tcp") | tostring),
            ((.network.ip_version // .ip_ver // "46") | tostring),
            ((.options.comment // .comment // "") | tostring),
            ((.options.mss_mode // .mss_mode // "") | tostring),
            ((.options.mss_value // .mss_value // "") | tostring),
            ((.options.snat_mode // .snat_mode // "masquerade") | tostring),
            ((.options.snat_source // .snat_source // "") | tostring),
            ((.limits.in // .traffic_limit.in // 0) | tostring),
            ((.limits.out // .traffic_limit.out // 0) | tostring),
            ((.limits.total // .traffic_limit.total // 0) | tostring),
            ((.limits.reset_every // .traffic_limit.reset_every // "") | tostring),
            ((.limits.reset_at // .traffic_limit.reset_at // 0) | tostring)
        ] | @tsv
    ' "$filepath"
}

json_forward_rules_count() {
    local filepath="$1"
    jq -r '(.forward_rules | length)' "$filepath"
}

json_require_v2_backup() {
    local filepath="$1"
    jq -e '
        has("forward_rules")
        and (.forward_rules | type == "array")
    ' "$filepath" >/dev/null 2>&1
}

json_export_rules_from_tsv() {
    local limit_map_json="$1"
    jq -Rn --argjson limit_map "$limit_map_json" '
        [
            inputs
            | select(length > 0)
            | split("\t") as $f
            | ($f[0] + "|" + ($f[1] // "") + "|" + ($f[2] // "")) as $key
            | {
                kind: "nft",
                local: {
                    port: (($f[1] // "0") | tonumber)
                },
                target: {
                    host: ($f[3] // ""),
                    port: (($f[4] // "0") | tonumber)
                },
                network: {
                    protocol: ($f[0] // "tcp"),
                    ip_version: ($f[2] // "46")
                },
                options: {
                    comment: ($f[5] // ""),
                    snat_mode: ($f[6] // "masquerade"),
                    snat_source: ($f[7] // ""),
                    mss_mode: ($f[8] // ""),
                    mss_value: ($f[9] // "")
                },
                limits: {
                    in: (($limit_map[$key].in // 0) | tonumber),
                    out: (($limit_map[$key].out // 0) | tonumber),
                    total: (($limit_map[$key].total // 0) | tonumber),
                    reset_every: ($limit_map[$key].reset_every // ""),
                    reset_at: (($limit_map[$key].reset_at // 0) | tonumber)
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
    local chain="$1" data
    data=$(_nft_cached_table)
    [[ -z "$data" ]] && return 1
    echo "$data" | awk -v c="$chain" '$0 ~ "chain "c" [{]",/^\t[}]/'
}

_nft_cached_chains_concat() {
    local chain
    for chain in "$@"; do
        _nft_cached_chain "$chain" || true
    done
}

_nft_invalidate_cache() { _NFT_CACHE="" _NFT_CACHE_TIME=0; }

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
    if [[ -n "$_LIMIT_PENDING_FILE" ]]; then
        rm -f "$_LIMIT_PENDING_FILE" 2>/dev/null || true
        _LIMIT_PENDING_FILE=""
    fi
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

traffic_limit_rule_key() {
    printf '%s|%s|%s' "$1" "$2" "$3"
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
            _pfwd_subchain_name "$section" "$proto" "$ipver"
        done
    done
}

_pfwd_rule_chain_candidates() {
    local section="$1" proto="$2" ipver="$3"
    _pfwd_subchain_name "$section" "$proto" "$ipver"
    echo "$section"
}

_pfwd_port_search_chains() {
    local section="$1" proto="${2:-both}" ipver
    case "$proto" in
        tcp|udp)
            for ipver in 4 6; do
                _pfwd_subchain_name "$section" "$proto" "$ipver"
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
    PFWD_NFT_RULES=$(_parse_nft_export_rules)
    PFWD_NFT_COUNT=$(_nft_count_rules "$(_parse_nft_prerouting_rules)")
    PFWD_NFT_RUNNING=false
    _nft_table_exists && PFWD_NFT_RUNNING=true

    local current_cc
    current_cc=$(plat_sysctl_get net.ipv4.tcp_congestion_control "")
    [[ "$current_cc" == "bbr" ]] && PFWD_BBR_ENABLED=true || PFWD_BBR_ENABLED=false

    PFWD_LOOPBACK_DNAT=false
    if [[ -n "$PFWD_NFT_RULES" ]] && awk -F'\t' '$4 ~ /^127\./ || $4 == "::1" { found=1 } END { exit(found ? 0 : 1) }' <<< "$PFWD_NFT_RULES"; then
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
    PFWD_LIMIT_COUNT=0
    PFWD_LIMIT_BLOCKED_COUNT=0
    if traffic_limit_file_ready && command -v jq >/dev/null 2>&1; then
        while IFS=$'\t' read -r _proto _lport _ipver _target _tport _comment _snat_mode _snat_source _mss_mode _mss_value \
            _limit_in _limit_out _limit_total _reset_every _reset_at_ts _cycle_start _next_reset _cycle_in _cycle_out disabled _reason _disabled_at; do
            [[ -z "$_lport" ]] && continue
            ((PFWD_LIMIT_COUNT++)) || true
            [[ "$disabled" == "true" ]] && ((PFWD_LIMIT_BLOCKED_COUNT++)) || true
        done < <(traffic_limit_records_tsv)
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
    local scope="$1" key1="${2:-}" key2="${3:-}" key3="${4:-}"
    [[ -f "$TRAFFIC_DATA" ]] || return 0

    local tmp_file
    tmp_file=$(_mktemp_in_dir "$TRAFFIC_DATA") || return 1

    awk -F'|' -v scope="$scope" -v key1="$key1" -v key2="$key2" -v key3="$key3" '
        function keep_line() {
            print $0
        }
        scope == "nft_rule" {
            if ($1 == "v2" && $2 == "nft_rule" && $3 == key1 && $4 == key2 && $5 == key3) next
            if ($1 == key1 && $2 == key2 && $3 == key3 && NF == 7) next
            keep_line()
            next
        }
        scope == "nft_port" {
            if ($1 == "v2" && $2 == "nft_rule" && $4 == key1 && (key2 == "both" || $3 == key2)) next
            if (NF == 7 && $2 == key1 && (key2 == "both" || $1 == key2)) next
            keep_line()
            next
        }
        scope == "nft_all" {
            if (($1 == "v2" && $2 == "nft_rule") || NF == 7) next
            keep_line()
            next
        }
        { keep_line() }
    ' "$TRAFFIC_DATA" > "$tmp_file"

    _atomic_replace_file "$tmp_file" "$TRAFFIC_DATA" 0644
}

traffic_limit_records_tsv() {
    if ! traffic_limit_file_ready; then
        return 0
    fi
    command -v jq >/dev/null 2>&1 || return 0
    jq -r '
        (.rules // [])[]? |
        [
            (.proto // ""),
            (.lport // ""),
            (.ipver // ""),
            (.target // ""),
            (.tport // ""),
            (.comment // ""),
            (.snat_mode // "masquerade"),
            (.snat_source // ""),
            (.mss_mode // ""),
            (.mss_value // ""),
            ((.limits.in // 0) | tostring),
            ((.limits.out // 0) | tostring),
            ((.limits.total // 0) | tostring),
            (.reset.every // ""),
            ((.reset.at_ts // 0) | tostring),
            ((.cycle.start_ts // 0) | tostring),
            ((.cycle.next_reset_ts // 0) | tostring),
            ((.cycle.in // 0) | tostring),
            ((.cycle.out // 0) | tostring),
            (if (.state.disabled // false) then "true" else "false" end),
            (.state.reason // ""),
            ((.state.disabled_at_ts // 0) | tostring)
        ] | @tsv
    ' "$TRAFFIC_LIMITS_DATA"
}

traffic_limit_make_tsv_line() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" \
        "${11}" "${12}" "${13}" "${14}" "${15}" "${16}" "${17}" "${18}" "${19}" "${20}" "${21}" "${22}"
}

traffic_limit_save_from_stream() {
    ensure_jq || return 1
    local tmp_file
    tmp_file=$(_mktemp_in_dir "$TRAFFIC_LIMITS_DATA") || return 1
    jq -Rn --arg version "$TRAFFIC_LIMITS_VERSION" '
        reduce inputs as $line (
            {version: ($version | tonumber), rules: []};
            if ($line | length) == 0 then
                .
            else
                ($line | split("\t")) as $f |
                .rules += [{
                    proto: ($f[0] // ""),
                    lport: ($f[1] // ""),
                    ipver: ($f[2] // ""),
                    target: ($f[3] // ""),
                    tport: ($f[4] // ""),
                    comment: ($f[5] // ""),
                    snat_mode: ($f[6] // "masquerade"),
                    snat_source: ($f[7] // ""),
                    mss_mode: ($f[8] // ""),
                    mss_value: ($f[9] // ""),
                    limits: {
                        in: (($f[10] // "0") | tonumber),
                        out: (($f[11] // "0") | tonumber),
                        total: (($f[12] // "0") | tonumber)
                    },
                    reset: {
                        every: ($f[13] // ""),
                        at_ts: (($f[14] // "0") | tonumber)
                    },
                    cycle: {
                        start_ts: (($f[15] // "0") | tonumber),
                        next_reset_ts: (($f[16] // "0") | tonumber),
                        in: (($f[17] // "0") | tonumber),
                        out: (($f[18] // "0") | tonumber)
                    },
                    state: {
                        disabled: (($f[19] // "false") == "true"),
                        reason: ($f[20] // ""),
                        disabled_at_ts: (($f[21] // "0") | tonumber)
                    }
                }]
            end
        )
    ' > "$tmp_file" || {
        rm -f "$tmp_file" 2>/dev/null || true
        return 1
    }
    _atomic_replace_file "$tmp_file" "$TRAFFIC_LIMITS_DATA" 0644
}

traffic_limit_delete_exact() {
    local proto="$1" lport="$2" ipver="$3"
    traffic_limit_file_ready || return 0
    ensure_jq || return 1
    local tmp_lines
    tmp_lines=$(_mktemp_in_dir "$TRAFFIC_LIMITS_DATA") || return 1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        IFS=$'\t' read -r r_proto r_lport r_ipver _rest <<< "$line"
        if [[ "$r_proto" == "$proto" && "$r_lport" == "$lport" && "$r_ipver" == "$ipver" ]]; then
            continue
        fi
        printf '%s\n' "$line" >> "$tmp_lines"
    done < <(traffic_limit_records_tsv)
    traffic_limit_save_from_stream < "$tmp_lines"
    rm -f "$tmp_lines" 2>/dev/null || true
}

traffic_limit_delete_port() {
    local lport="$1" proto_filter="${2:-both}"
    traffic_limit_file_ready || return 0
    ensure_jq || return 1
    local tmp_lines
    tmp_lines=$(_mktemp_in_dir "$TRAFFIC_LIMITS_DATA") || return 1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        IFS=$'\t' read -r r_proto r_lport _r_ipver _rest <<< "$line"
        if [[ "$r_lport" == "$lport" && ( "$proto_filter" == "both" || "$r_proto" == "$proto_filter" ) ]]; then
            continue
        fi
        printf '%s\n' "$line" >> "$tmp_lines"
    done < <(traffic_limit_records_tsv)
    traffic_limit_save_from_stream < "$tmp_lines"
    rm -f "$tmp_lines" 2>/dev/null || true
}

traffic_limit_delete_all() {
    rm -f "$TRAFFIC_LIMITS_DATA" 2>/dev/null || true
}

traffic_limit_upsert_rule() {
    local proto="$1" lport="$2" ipver="$3" target="$4" tport="$5" comment="${6:-}"
    local snat_mode="${7:-masquerade}" snat_source="${8:-}" mss_mode="${9:-}" mss_value="${10:-}"
    local limit_in="${11:-0}" limit_out="${12:-0}" limit_total="${13:-0}" reset_every="${14:-}" reset_at_ts="${15:-0}"
    ensure_jq || return 1
    traffic_limit_has_values "$limit_in" "$limit_out" "$limit_total" || {
        msg_err "At least one traffic limit must be greater than zero"
        return 1
    }
    if [[ -n "$reset_every" ]]; then
        traffic_limit_validate_reset_every "$reset_every" || {
            msg_err "Invalid limit reset cycle: $reset_every"
            return 1
        }
    fi
    [[ "$reset_at_ts" =~ ^[0-9]+$ ]] || reset_at_ts=0
    if [[ -z "$reset_every" && $reset_at_ts -le 0 ]]; then
        msg_err "Traffic limit requires --limit-reset-every and/or --limit-reset-at"
        return 1
    fi

    local now_ts next_reset_ts
    now_ts=$(date +%s)
    next_reset_ts=$(traffic_limit_compute_next_reset_ts "$now_ts" "$reset_every" "$reset_at_ts") || return 1

    local tmp_lines found=false
    tmp_lines=$(_mktemp_in_dir "$TRAFFIC_LIMITS_DATA") || return 1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        IFS=$'\t' read -r r_proto r_lport r_ipver _rest <<< "$line"
        if [[ "$r_proto" == "$proto" && "$r_lport" == "$lport" && "$r_ipver" == "$ipver" ]]; then
            found=true
            traffic_limit_make_tsv_line \
                "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
                "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" \
                "$limit_in" "$limit_out" "$limit_total" "$reset_every" "$reset_at_ts" \
                "$now_ts" "$next_reset_ts" "0" "0" "false" "" "0" >> "$tmp_lines"
        else
            printf '%s\n' "$line" >> "$tmp_lines"
        fi
    done < <(traffic_limit_records_tsv)

    if [[ "$found" == false ]]; then
        traffic_limit_make_tsv_line \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
            "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" \
            "$limit_in" "$limit_out" "$limit_total" "$reset_every" "$reset_at_ts" \
            "$now_ts" "$next_reset_ts" "0" "0" "false" "" "0" >> "$tmp_lines"
    fi

    traffic_limit_save_from_stream < "$tmp_lines"
    rm -f "$tmp_lines" 2>/dev/null || true
}

traffic_limit_sync_rule_definition() {
    local proto="$1" lport="$2" ipver="$3" target="$4" tport="$5" comment="${6:-}"
    local snat_mode="${7:-masquerade}" snat_source="${8:-}" mss_mode="${9:-}" mss_value="${10:-}" replace_mode="${11:-false}"
    traffic_limit_file_ready || return 0
    ensure_jq || return 1

    local now_ts tmp_lines changed=false
    now_ts=$(date +%s)
    tmp_lines=$(_mktemp_in_dir "$TRAFFIC_LIMITS_DATA") || return 1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        IFS=$'\t' read -r r_proto r_lport r_ipver _target _tport _comment _snat_mode _snat_source _mss_mode _mss_value \
            limit_in limit_out limit_total reset_every reset_at_ts cycle_start_ts next_reset_ts cycle_in cycle_out disabled reason disabled_at_ts <<< "$line"
        if [[ "$r_proto" == "$proto" && "$r_lport" == "$lport" && "$r_ipver" == "$ipver" ]]; then
            changed=true
            if [[ "$replace_mode" == "true" ]]; then
                cycle_start_ts="$now_ts"
                next_reset_ts=$(traffic_limit_compute_next_reset_ts "$now_ts" "$reset_every" "$reset_at_ts") || next_reset_ts=0
                cycle_in=0
                cycle_out=0
                disabled="false"
                reason=""
                disabled_at_ts=0
            fi
            traffic_limit_make_tsv_line \
                "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
                "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" \
                "$limit_in" "$limit_out" "$limit_total" "$reset_every" "$reset_at_ts" \
                "$cycle_start_ts" "$next_reset_ts" "$cycle_in" "$cycle_out" "$disabled" "$reason" "$disabled_at_ts" >> "$tmp_lines"
        else
            printf '%s\n' "$line" >> "$tmp_lines"
        fi
    done < <(traffic_limit_records_tsv)

    if [[ "$changed" == true ]]; then
        traffic_limit_save_from_stream < "$tmp_lines"
    fi
    rm -f "$tmp_lines" 2>/dev/null || true
}

traffic_limit_export_map_json() {
    if ! traffic_limit_file_ready || ! command -v jq >/dev/null 2>&1; then
        echo '{}'
        return 0
    fi
    jq -c '
        reduce (.rules // [])[] as $rule (
            {};
            .["\($rule.proto)|\($rule.lport)|\($rule.ipver)"] = {
                in: ($rule.limits.in // 0),
                out: ($rule.limits.out // 0),
                total: ($rule.limits.total // 0),
                reset_every: ($rule.reset.every // ""),
                reset_at: ($rule.reset.at_ts // 0)
            }
        )
    ' "$TRAFFIC_LIMITS_DATA"
}

traffic_limit_queue_pending() {
    local op="$1"
    shift
    if [[ -z "$_LIMIT_PENDING_FILE" ]]; then
        _LIMIT_PENDING_FILE=$(mktemp)
    fi
    printf '%s\t' "$op" >> "$_LIMIT_PENDING_FILE"
    printf '%s\t' "$@" >> "$_LIMIT_PENDING_FILE"
    printf '\n' >> "$_LIMIT_PENDING_FILE"
}

traffic_limit_apply_pending() {
    local pending_file="$1"
    [[ -f "$pending_file" ]] || return 0
    while IFS=$'\t' read -r op proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value \
        limit_in limit_out limit_total reset_every reset_at_ts replace_mode _rest; do
        [[ -z "$op" ]] && continue
        case "$op" in
            upsert)
                traffic_limit_upsert_rule \
                    "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
                    "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" \
                    "$limit_in" "$limit_out" "$limit_total" "$reset_every" "$reset_at_ts" || return 1
                ;;
            sync)
                traffic_limit_sync_rule_definition \
                    "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
                    "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" "$replace_mode" || return 1
                ;;
        esac
    done < "$pending_file"
}

traffic_limit_selector_matches() {
    local rule_proto="$1" rule_lport="$2" rule_ipver="$3" port_filter="$4" proto_filter="$5" ipver_filter="$6"
    [[ "$rule_lport" == "$port_filter" ]] || return 1
    [[ "$proto_filter" == "both" || "$rule_proto" == "$proto_filter" ]] || return 1
    [[ "$ipver_filter" == "46" || "$rule_ipver" == "$ipver_filter" ]] || return 1
    return 0
}

traffic_limit_collect_rule_defs() {
    local port_filter="$1" proto_filter="${2:-both}" ipver_filter="${3:-46}"
    declare -A seen=()
    local active_rules
    active_rules=$(_parse_nft_export_rules)

    if [[ -n "$active_rules" ]]; then
        while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value; do
            [[ -z "$lport" ]] && continue
            traffic_limit_selector_matches "$proto" "$lport" "$ipver" "$port_filter" "$proto_filter" "$ipver_filter" || continue
            local key
            key=$(traffic_limit_rule_key "$proto" "$lport" "$ipver")
            seen["$key"]=1
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" "$snat_mode" "$snat_source" "$mss_mode" "$mss_value"
        done <<< "$active_rules"
    fi

    while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value \
        limit_in limit_out limit_total reset_every reset_at_ts cycle_start_ts next_reset_ts cycle_in cycle_out disabled reason disabled_at_ts; do
        [[ -z "$lport" ]] && continue
        traffic_limit_selector_matches "$proto" "$lport" "$ipver" "$port_filter" "$proto_filter" "$ipver_filter" || continue
        local key
        key=$(traffic_limit_rule_key "$proto" "$lport" "$ipver")
        [[ -n "${seen[$key]:-}" ]] && continue
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" "$snat_mode" "$snat_source" "$mss_mode" "$mss_value"
    done < <(traffic_limit_records_tsv)
}

_backup_nft_config() {
    [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]] || return 0
    mkdir -p "$NFT_BACKUP_DIR"
    cp "$NFT_CONFIG" "$NFT_BACKUP_DIR/nftables_$(date +%Y%m%d_%H%M%S).nft" 2>/dev/null || true
    ls -t "$NFT_BACKUP_DIR"/nftables_*.nft 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
}

# nft batch file for atomic operations (Phase 2)
_NFT_BATCH_FILE=""
_LIMIT_PENDING_FILE=""

# No-clear flag for interactive menu
_NO_CLEAR=false

# Change tracking flags (coalesce save/reload/restart side effects)
_DIRTY_NFT=false
_DIRTY_UFW_SYNC=false
_DIRTY_UFW_RELOAD=false
_NFT_BACKUP_NEEDED=false
_UFW_FILES_CHANGED=false

# Cached state snapshot for UI/status views
PFWD_NFT_RULES=""
PFWD_NFT_COUNT=0
PFWD_NFT_RUNNING=false
PFWD_BBR_ENABLED=false
PFWD_LOOPBACK_DNAT=false
PFWD_UFW_LOOPBACK_STATE="n/a"
PFWD_TRAFFIC_INTERVAL="$TRAFFIC_DEFAULT_INTERVAL"
PFWD_LIMIT_COUNT=0
PFWD_LIMIT_BLOCKED_COUNT=0

# Network detection cache
_NET_CACHE_TIME=0
_AUTO_SHORTCUT_CHECKED=false
_TRAFFIC_LEGACY_WARNED=false

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
        limit)
            case "${2:-list}" in
                list|ls|"") return 1 ;;
                *) return 0 ;;
            esac
            ;;
        *)
            return 0
            ;;
    esac
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

# validate_mss_value <value> -> 0=valid, 1=invalid
validate_mss_value() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 536 && value <= 65535 ))
}

suggest_mss_for_snat_source() {
    local snat_source="$1"
    MSS_SUGGEST_IFACE=""
    MSS_SUGGEST_MTU=""
    MSS_SUGGEST_VALUE=""
    MSS_SUGGEST_FAMILY=""

    command -v ip >/dev/null 2>&1 || return 1

    local family family_flag iface mtu overhead suggested
    family=$(detect_ip_type "$snat_source")
    case "$family" in
        ipv4)
            family_flag="-4"
            overhead=40
            MSS_SUGGEST_FAMILY="IPv4"
            ;;
        ipv6)
            family_flag="-6"
            overhead=60
            MSS_SUGGEST_FAMILY="IPv6"
            ;;
        *)
            return 1
            ;;
    esac

    iface=$(ip -o "$family_flag" addr show 2>/dev/null | awk -v target="$snat_source" '
        {
            split($4, a, "/")
            if (a[1] == target) {
                print $2
                exit
            }
        }
    ') || true
    [[ -n "$iface" ]] || return 1

    mtu=$(ip -o link show dev "$iface" 2>/dev/null | awk '
        {
            for (i = 1; i <= NF; i++) {
                if ($i == "mtu") {
                    print $(i + 1)
                    exit
                }
            }
        }
    ') || true
    [[ "$mtu" =~ ^[0-9]+$ ]] || return 1

    suggested=$(( mtu - overhead ))
    validate_mss_value "$suggested" || return 1

    MSS_SUGGEST_IFACE="$iface"
    MSS_SUGGEST_MTU="$mtu"
    MSS_SUGGEST_VALUE="$suggested"
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

traffic_limit_format_reset_at() {
    local ts="${1:-0}"
    [[ "$ts" =~ ^[0-9]+$ ]] || { echo "-"; return; }
    (( ts > 0 )) || { echo "-"; return; }
    date -d "@$ts" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "-"
}

traffic_limit_parse_size() {
    local raw="${1:-}" value unit multiplier=1
    raw="${raw^^}"
    raw="${raw//[[:space:]]/}"
    [[ -n "$raw" ]] || return 1
    if [[ "$raw" =~ ^([0-9]+)([KMGT]?)B?$ ]]; then
        value="${BASH_REMATCH[1]}"
        unit="${BASH_REMATCH[2]}"
    else
        return 1
    fi

    case "$unit" in
        "") multiplier=1 ;;
        K) multiplier=1024 ;;
        M) multiplier=$((1024 * 1024)) ;;
        G) multiplier=$((1024 * 1024 * 1024)) ;;
        T) multiplier=$((1024 * 1024 * 1024 * 1024)) ;;
        *) return 1 ;;
    esac

    echo $(( value * multiplier ))
}

traffic_limit_validate_reset_every() {
    [[ "${1:-}" =~ ^[1-9][0-9]*(d|mo|y)$ ]]
}

traffic_limit_parse_reset_at_ts() {
    local raw="${1:-}"
    [[ -n "$raw" ]] || return 1
    date -d "$raw" +%s 2>/dev/null
}

traffic_limit_shift_timestamp() {
    local base_ts="$1" every="$2" count unit
    [[ "$base_ts" =~ ^[0-9]+$ ]] || return 1
    traffic_limit_validate_reset_every "$every" || return 1
    count="${every%[a-z]*}"
    unit="${every#$count}"
    case "$unit" in
        d)  date -d "@$base_ts + ${count} day" +%s 2>/dev/null ;;
        mo) date -d "@$base_ts + ${count} month" +%s 2>/dev/null ;;
        y)  date -d "@$base_ts + ${count} year" +%s 2>/dev/null ;;
        *) return 1 ;;
    esac
}

traffic_limit_compute_next_reset_ts() {
    local now_ts="$1" reset_every="${2:-}" reset_at_ts="${3:-0}" candidate=0
    [[ "$now_ts" =~ ^[0-9]+$ ]] || return 1
    [[ "$reset_at_ts" =~ ^[0-9]+$ ]] || reset_at_ts=0

    if (( reset_at_ts > 0 )); then
        if [[ -z "$reset_every" ]]; then
            if (( reset_at_ts > now_ts )); then
                echo "$reset_at_ts"
            else
                echo 0
            fi
            return 0
        fi
        candidate="$reset_at_ts"
        while (( candidate <= now_ts )); do
            candidate=$(traffic_limit_shift_timestamp "$candidate" "$reset_every") || return 1
        done
        echo "$candidate"
        return 0
    fi

    if [[ -n "$reset_every" ]]; then
        traffic_limit_shift_timestamp "$now_ts" "$reset_every"
    else
        echo 0
    fi
}

traffic_limit_file_ready() {
    [[ -f "$TRAFFIC_LIMITS_DATA" && -s "$TRAFFIC_LIMITS_DATA" ]]
}

traffic_limit_init_file() {
    local tmp_file
    tmp_file=$(_mktemp_in_dir "$TRAFFIC_LIMITS_DATA") || return 1
    cat > "$tmp_file" << EOF
{"version":$TRAFFIC_LIMITS_VERSION,"rules":[]}
EOF
    _atomic_replace_file "$tmp_file" "$TRAFFIC_LIMITS_DATA" 0644
}

traffic_limit_ensure_file() {
    traffic_limit_file_ready && return 0
    traffic_limit_init_file
}

traffic_limit_has_values() {
    local limit_in="${1:-0}" limit_out="${2:-0}" limit_total="${3:-0}"
    (( ${limit_in:-0} > 0 || ${limit_out:-0} > 0 || ${limit_total:-0} > 0 ))
}

traffic_limit_format_threshold() {
    local value="${1:-0}"
    [[ "$value" =~ ^[0-9]+$ ]] || value=0
    (( value > 0 )) && format_bytes "$value" || echo "-"
}

traffic_limit_format_reset_policy() {
    local reset_every="${1:-}" reset_at_ts="${2:-0}"
    local parts=()
    [[ -n "$reset_every" ]] && parts+=("every ${reset_every}")
    if [[ "$reset_at_ts" =~ ^[0-9]+$ ]] && (( reset_at_ts > 0 )); then
        parts+=("at $(traffic_limit_format_reset_at "$reset_at_ts")")
    fi
    if (( ${#parts[@]} == 0 )); then
        echo "-"
    else
        local IFS=', '
        echo "${parts[*]}"
    fi
}

# ensure_jq - require jq explicitly instead of installing it implicitly
ensure_jq() {
    if command -v jq >/dev/null 2>&1; then
        return 0
    fi
    msg_err "jq is required for this operation."
    msg_err "Install it with your package manager and retry."
    return 1
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

    # 强制刷新 nftables 缓存，确保获取最新规则
    _nft_invalidate_cache

    local marker_start="# pfwd-managed loopback dnat start"
    local marker_end="# pfwd-managed loopback dnat end"
    local block_v4="" block_v6=""
    local line proto tport
    local prerouting_lines
    prerouting_lines=$(_nft_prerouting_dnat_lines)

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
    require_root "$0 optimize $profile"
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

# _ensure_forward_counters - auto-migrate: add forward chain counter rules for existing rules
_ensure_forward_counters() {
    _nft_table_exists || return 0
    _ensure_nft_dispatch_chains

    local pre_output
    pre_output=$(_nft_prerouting_dnat_lines)
    [[ -z "$pre_output" ]] && return 0

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

        local scope ret_tag
        scope=$(_pfwd_rule_scope "$lport" "$ipver" "$proto" "$target" "$tport")
        ret_tag=$(_pfwd_forward_tag "ret" "$lport" "$ipver" "$proto" "$target" "$tport")

        # Already has forward counter
        if _pfwd_forward_handle_refs_by_rule "$lport" "$ipver" "$proto" "$target" "$tport" | grep -q .; then
            continue
        fi

        local ip_family="ip"
        [[ "$ipver" == "6" ]] && ip_family="ip6"

        plat_nft_quiet add rule $NFT_TABLE "$(_pfwd_subchain_name forward "$proto" "$ipver")" \
            $ip_family saddr "$target" "$proto" sport "$tport" counter comment "$ret_tag" || true
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

# _dispatch_add_rule <method> <lport> <target> <tport> <ip_ver> <proto> <comment> [mss_mode] [mss_value] [snat_mode] [snat_source] [replace_mode] [limit_in] [limit_out] [limit_total] [reset_every] [reset_at_ts]
# Unified add rule dispatcher for nft
_dispatch_add_rule() {
    local method="$1" lport="$2" target="$3" tport="$4" ip_ver="$5" proto="$6" comment="$7"
    local mss_mode="${8:-}" mss_value="${9:-}" snat_mode="${10:-}" snat_source="${11:-}" replace_mode="${12:-false}"
    local limit_in="${13:-0}" limit_out="${14:-0}" limit_total="${15:-0}" reset_every="${16:-}" reset_at_ts="${17:-0}"
    case "$method" in
        nft|nftables)
            nft_add_rule "$lport" "$target" "$tport" "$ip_ver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode" \
                "$limit_in" "$limit_out" "$limit_total" "$reset_every" "$reset_at_ts"
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
                if plat_nft_apply_file "$_NFT_BATCH_FILE"; then
                    msg_dim "  Atomic batch commit successful"
                    if [[ -n "$_LIMIT_PENDING_FILE" && -f "$_LIMIT_PENDING_FILE" ]]; then
                        traffic_limit_apply_pending "$_LIMIT_PENDING_FILE" || msg_warn "Failed to sync traffic limit state after batch add"
                    fi
                    _mark_nft_dirty
                else
                    msg_warn "Atomic batch failed"
                fi
                rm -f "$_NFT_BATCH_FILE"
                _NFT_BATCH_FILE=""
                rm -f "$_LIMIT_PENDING_FILE" 2>/dev/null || true
                _LIMIT_PENDING_FILE=""
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

    local changed=false section chain proto ipver tag match_tokens
    for section in prerouting postrouting forward; do
        while IFS= read -r chain; do
            [[ -n "$chain" ]] || continue
            if ! _nft_cached_chain "$chain" >/dev/null; then
                plat_nft_quiet add chain $NFT_TABLE "$chain"
                changed=true
            fi
        done < <(_pfwd_subchain_list "$section")
    done

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
            if [[ "$prerouting_data" != *"comment \"$tag\""* ]]; then
                plat_nft_quiet add rule $NFT_TABLE prerouting $match_tokens \
                    jump "$(_pfwd_subchain_name prerouting "$proto" "$ipver")" comment "$tag"
                changed=true
            fi

            tag=$(_pfwd_dispatch_tag postrouting "$proto" "$ipver")
            if [[ "$postrouting_data" != *"comment \"$tag\""* ]]; then
                plat_nft_quiet add rule $NFT_TABLE postrouting ct status dnat $match_tokens \
                    jump "$(_pfwd_subchain_name postrouting "$proto" "$ipver")" comment "$tag"
                changed=true
            fi

            tag=$(_pfwd_dispatch_tag forward "$proto" "$ipver")
            if [[ "$forward_data" != *"comment \"$tag\""* ]]; then
                if [[ -n "$forward_accept_handle" ]]; then
                    plat_nft_quiet insert rule $NFT_TABLE forward handle "$forward_accept_handle" $match_tokens \
                        jump "$(_pfwd_subchain_name forward "$proto" "$ipver")" comment "$tag"
                else
                    plat_nft_quiet add rule $NFT_TABLE forward $match_tokens \
                        jump "$(_pfwd_subchain_name forward "$proto" "$ipver")" comment "$tag"
                fi
                changed=true
            fi
        done
    done

    $changed && _nft_invalidate_cache
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
    while IFS=$'\t' read -r found_proto found_lport found_ipver found_target found_tport found_comment found_bytes; do
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
                msg_err "Use a literal IPv4/IPv6 address or fix DNS resolution"
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
    local chain line handle=""
    while IFS=$'\t' read -r chain line; do
        [[ -z "$chain" || -z "$line" ]] && continue
        _extract_nft_proto_ipver "$line"
        [[ "$_PROTO" == "$proto" && "$_IPVER" == "$ip_ver" ]] || continue
        [[ "$line" =~ dport\ ([0-9]+) ]] || continue
        [[ "${BASH_REMATCH[1]}" == "$lport" ]] || continue
        _extract_nft_dnat_target "$line"
        [[ "$_TARGET" == "$target" && "$_TPORT" == "$tport" ]] || continue
        handle=""
        [[ "$line" =~ handle\ ([0-9]+) ]] && handle="${BASH_REMATCH[1]}"
        [[ -n "$handle" ]] && printf '%s\t%s\n' "$chain" "$handle"
    done < <(_nft_prefixed_chain_handles_concat $(_pfwd_rule_chain_candidates prerouting "$proto" "$ip_ver"))
}

_nft_delete_exact_rule() {
    local lport="$1" proto="$2" ip_ver="$3" target="$4" tport="$5"
    local rule_tag deleted=0
    rule_tag=$(_pfwd_rule_tag "$lport" "$ip_ver" "$proto" "$target" "$tport")

    if $_BATCH_MODE && [[ -z "${_NFT_BATCH_FILE:-}" ]]; then
        _NFT_BATCH_FILE=$(mktemp)
    fi

    local prerouting_handles post_handles helper_handles chain h
    prerouting_handles=$(_nft_prerouting_handles_exact "$lport" "$proto" "$ip_ver" "$target" "$tport")
    post_handles=$(_pfwd_postrouting_handle_refs_by_tag "$rule_tag" "$proto" "$ip_ver")
    helper_handles=$(_pfwd_forward_handle_refs_by_rule "$lport" "$ip_ver" "$proto" "$target" "$tport")

    while IFS=$'\t' read -r chain h; do
        [[ -n "$chain" && -n "$h" ]] || continue
        if $_BATCH_MODE && [[ -n "${_NFT_BATCH_FILE:-}" ]]; then
            echo "delete rule $NFT_TABLE $chain handle $h" >> "$_NFT_BATCH_FILE"
            ((deleted++)) || true
        elif plat_nft_delete_rule_handle $NFT_TABLE "$chain" "$h"; then
            ((deleted++)) || true
        fi
    done <<< "$prerouting_handles"

    while IFS=$'\t' read -r chain h; do
        [[ -n "$chain" && -n "$h" ]] || continue
        if $_BATCH_MODE && [[ -n "${_NFT_BATCH_FILE:-}" ]]; then
            echo "delete rule $NFT_TABLE $chain handle $h" >> "$_NFT_BATCH_FILE"
            ((deleted++)) || true
        elif plat_nft_delete_rule_handle $NFT_TABLE "$chain" "$h"; then
            ((deleted++)) || true
        fi
    done <<< "$post_handles"

    while IFS=$'\t' read -r chain h; do
        [[ -n "$chain" && -n "$h" ]] || continue
        if $_BATCH_MODE && [[ -n "${_NFT_BATCH_FILE:-}" ]]; then
            echo "delete rule $NFT_TABLE $chain handle $h" >> "$_NFT_BATCH_FILE"
            ((deleted++)) || true
        elif plat_nft_delete_rule_handle $NFT_TABLE "$chain" "$h"; then
            ((deleted++)) || true
        fi
    done <<< "$helper_handles"

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
    local limit_in="${12:-0}" limit_out="${13:-0}" limit_total="${14:-0}" reset_every="${15:-}" reset_at_ts="${16:-0}"
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
    local rule_tag ret_tag
    local escaped_comment=""
    local prerouting_chain postrouting_chain forward_chain
    rule_tag=$(_pfwd_rule_tag "$lport" "$ipver" "$proto" "$target" "$tport")
    ret_tag=$(_pfwd_forward_tag "ret" "$lport" "$ipver" "$proto" "$target" "$tport")
    prerouting_chain=$(_pfwd_subchain_name prerouting "$proto" "$ipver")
    postrouting_chain=$(_pfwd_subchain_name postrouting "$proto" "$ipver")
    forward_chain=$(_pfwd_subchain_name forward "$proto" "$ipver")
    if [[ "$snat_mode" == "snat" && -n "$snat_source" ]]; then
        postrouting_action="snat to $snat_source"
    fi
    if [[ -n "$comment" ]]; then
        escaped_comment=$(nft_escape_string "$comment")
    fi
    if $_BATCH_MODE && [[ -n "$_NFT_BATCH_FILE" ]]; then
        # Append to batch file for atomic commit
        if [[ -n "$comment" ]]; then
            echo "add rule $NFT_TABLE $prerouting_chain $ip_match $proto $proto dport $lport counter dnat $dnat_keyword to $dnat_target comment \"$escaped_comment\"" >> "$_NFT_BATCH_FILE"
            echo "add rule $NFT_TABLE $postrouting_chain ct status dnat $ip_family daddr $target $proto dport $tport $postrouting_action comment \"$rule_tag\"" >> "$_NFT_BATCH_FILE"
        else
            echo "add rule $NFT_TABLE $prerouting_chain $ip_match $proto $proto dport $lport counter dnat $dnat_keyword to $dnat_target" >> "$_NFT_BATCH_FILE"
            echo "add rule $NFT_TABLE $postrouting_chain ct status dnat $ip_family daddr $target $proto dport $tport $postrouting_action comment \"$rule_tag\"" >> "$_NFT_BATCH_FILE"
        fi
        echo "add rule $NFT_TABLE $forward_chain $ip_family saddr $target $proto sport $tport counter comment \"$ret_tag\"" >> "$_NFT_BATCH_FILE"
        if [[ "$proto" == "tcp" ]]; then
            if [[ "$mss_mode" == "clamp" ]]; then
                echo "add rule $NFT_TABLE $forward_chain $ip_family daddr $target $proto dport $tport $proto flags syn / syn,rst tcp option maxseg size set rt mtu comment \"${rule_tag}:mss\"" >> "$_NFT_BATCH_FILE"
            elif [[ "$mss_mode" == "set" && -n "$mss_value" ]]; then
                echo "add rule $NFT_TABLE $forward_chain $ip_family daddr $target $proto dport $tport $proto flags syn / syn,rst tcp option maxseg size set $mss_value comment \"${rule_tag}:mss\"" >> "$_NFT_BATCH_FILE"
            fi
        fi
    else
        # Direct execution
        if [[ -n "$comment" ]]; then
            plat_nft_capture add rule $NFT_TABLE "$prerouting_chain" $ip_match "$proto" "$proto" dport "$lport" counter dnat $dnat_keyword to "$dnat_target" comment "$comment" && \
            plat_nft_capture add rule $NFT_TABLE "$postrouting_chain" ct status dnat $ip_family daddr "$target" "$proto" dport "$tport" $postrouting_action comment "$rule_tag"
            nft_result=$?
        else
            plat_nft_capture add rule $NFT_TABLE "$prerouting_chain" $ip_match "$proto" "$proto" dport "$lport" counter dnat $dnat_keyword to "$dnat_target" && \
            plat_nft_capture add rule $NFT_TABLE "$postrouting_chain" ct status dnat $ip_family daddr "$target" "$proto" dport "$tport" $postrouting_action comment "$rule_tag"
            nft_result=$?
        fi

        if (( nft_result == 0 )); then
            plat_nft_quiet add rule $NFT_TABLE "$forward_chain" \
                $ip_family saddr "$target" "$proto" sport "$tport" counter comment "$ret_tag" || true
            if [[ "$proto" == "tcp" ]]; then
                if [[ "$mss_mode" == "clamp" ]]; then
                    plat_nft_quiet add rule $NFT_TABLE "$forward_chain" \
                        $ip_family daddr "$target" tcp dport "$tport" tcp flags syn / syn,rst tcp option maxseg size set rt mtu comment "${rule_tag}:mss" || true
                elif [[ "$mss_mode" == "set" && -n "$mss_value" ]]; then
                    plat_nft_quiet add rule $NFT_TABLE "$forward_chain" \
                        $ip_family daddr "$target" tcp dport "$tport" tcp flags syn / syn,rst tcp option maxseg size set "$mss_value" comment "${rule_tag}:mss" || true
                fi
            fi
        else
            msg_err "Failed to add IPv$ipver $proto rule :$lport -> $dnat_target"
            # Rollback: remove prerouting rule if it was added but postrouting failed
            _nft_delete_exact_rule "$lport" "$proto" "$ipver" "$target" "$tport" >/dev/null 2>&1 || true
            return 1
        fi
    fi

    msg_dim "  Added IPv$ipver $proto :$lport -> $dnat_target"
    if traffic_limit_has_values "$limit_in" "$limit_out" "$limit_total"; then
        if $_BATCH_MODE; then
            traffic_limit_queue_pending \
                "upsert" "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
                "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" \
                "$limit_in" "$limit_out" "$limit_total" "$reset_every" "$reset_at_ts" "$replace_mode"
        else
            traffic_limit_upsert_rule \
                "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
                "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" \
                "$limit_in" "$limit_out" "$limit_total" "$reset_every" "$reset_at_ts" || return 1
        fi
    else
        if $_BATCH_MODE; then
            traffic_limit_queue_pending \
                "sync" "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
                "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" \
                "0" "0" "0" "" "0" "$replace_mode"
        else
            traffic_limit_sync_rule_definition \
                "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
                "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" "$replace_mode" || return 1
        fi
    fi
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
    local limit_in="${12:-0}" limit_out="${13:-0}" limit_total="${14:-0}" reset_every="${15:-}" reset_at_ts="${16:-0}"

    if ! validate_comment "$comment"; then
        msg_err "Comment must be a single line without tabs"
        return 1
    fi

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
            if _nft_add_single_rule "$family" "$p" "$lport" "$resolved_ip" "$tport" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode" \
                "$limit_in" "$limit_out" "$limit_total" "$reset_every" "$reset_at_ts"; then
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
    local prerouting_lines
    prerouting_lines=$(_nft_prefixed_chain_handles_concat $(_pfwd_port_search_chains prerouting "$proto"))

    local chain line h
    while IFS=$'\t' read -r chain line; do
        [[ -n "$line" ]] || continue
        case "$proto" in
            tcp) [[ "$line" =~ (ip\ protocol\ tcp|ip6\ nexthdr\ tcp).*dport\ $port($|[^0-9]) ]] || continue ;;
            udp) [[ "$line" =~ (ip\ protocol\ udp|ip6\ nexthdr\ udp).*dport\ $port($|[^0-9]) ]] || continue ;;
            both) [[ "$line" =~ dport\ $port($|[^0-9]) ]] || continue ;;
            *) msg_err "Invalid protocol: $proto"; return 1 ;;
        esac

        # Extract handle from prerouting rule
        local handle=""
        [[ "$line" =~ handle\ ([0-9]+) ]] && handle="${BASH_REMATCH[1]}"
        [[ -z "$handle" ]] && continue

        # Extract DNAT target address and port for postrouting matching
        local dnat_addr="" dnat_port="" rule_tag=""
        if [[ "$line" =~ dnat\ ip\ to\ ([0-9.]+):([0-9]+) ]]; then
            dnat_addr="${BASH_REMATCH[1]}"
            dnat_port="${BASH_REMATCH[2]}"
        elif [[ "$line" =~ dnat\ ip6\ to\ \[([^\]]+)\]:([0-9]+) ]]; then
            dnat_addr="${BASH_REMATCH[1]}"
            dnat_port="${BASH_REMATCH[2]}"
        fi
        _extract_nft_proto_ipver "$line"
        if [[ -n "$_PROTO" && -n "$_IPVER" && -n "$dnat_addr" && -n "$dnat_port" ]]; then
            rule_tag=$(_pfwd_rule_tag "$port" "$_IPVER" "$_PROTO" "$dnat_addr" "$dnat_port")
        fi

        # Delete the prerouting rule
        plat_nft_delete_rule_handle $NFT_TABLE "$chain" "$handle" && ((deleted++)) || true

        # Step 2: Delete matching postrouting SNAT/masquerade rule using managed tag when available
        if [[ -n "$rule_tag" ]]; then
            local tagged_post_handles
            tagged_post_handles=$(_pfwd_postrouting_handle_refs_by_tag "$rule_tag" "$_PROTO" "$_IPVER")
            while IFS=$'\t' read -r chain h; do
                [[ -n "$chain" && -n "$h" ]] || continue
                plat_nft_delete_rule_handle $NFT_TABLE "$chain" "$h" && ((deleted++)) || true
            done <<< "$tagged_post_handles"
        fi

        # Step 2b: Delete managed forward helper rules (including optional MSS rule)
        if [[ -n "$dnat_addr" && -n "$dnat_port" && -n "$_PROTO" && -n "$_IPVER" ]]; then
            local helper_handles
            helper_handles=$(_pfwd_forward_handle_refs_by_rule "$port" "$_IPVER" "$_PROTO" "$dnat_addr" "$dnat_port")
            while IFS=$'\t' read -r chain h; do
                [[ -n "$chain" && -n "$h" ]] || continue
                plat_nft_delete_rule_handle $NFT_TABLE "$chain" "$h" && ((deleted++)) || true
            done <<< "$helper_handles"
        fi
    done <<< "$prerouting_lines"

        if (( deleted > 0 )); then
            _traffic_delete_records nft_port "$port" "$proto"
            traffic_limit_delete_port "$port" "$proto"
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
    local pre_data
    pre_data=$(_nft_prefixed_chain_handles_concat $(_pfwd_port_search_chains prerouting "$proto"))

    local total_deleted=0
    local chain line h

    for port in "${_ports_ref[@]}"; do
        local deleted=0

        # Filter prerouting lines for this port
        local prerouting_lines=""
        case "$proto" in
            tcp) prerouting_lines=$(echo "$pre_data" | { grep -E $'\t.*(ip protocol tcp|ip6 nexthdr tcp).*dport '"$port"'($|[^0-9])' || true; }) ;;
            udp) prerouting_lines=$(echo "$pre_data" | { grep -E $'\t.*(ip protocol udp|ip6 nexthdr udp).*dport '"$port"'($|[^0-9])' || true; }) ;;
            both) prerouting_lines=$(echo "$pre_data" | { grep -E $'\t.*dport '"$port"'($|[^0-9])' || true; }) ;;
        esac

        while IFS=$'\t' read -r chain line; do
            [[ -z "$chain" || -z "$line" ]] && continue
            local handle=""
            [[ "$line" =~ handle\ ([0-9]+) ]] && handle="${BASH_REMATCH[1]}"
            [[ -z "$handle" ]] && continue

            local dnat_addr="" dnat_port="" rule_tag=""
            if [[ "$line" =~ dnat\ ip\ to\ ([0-9.]+):([0-9]+) ]]; then
                dnat_addr="${BASH_REMATCH[1]}"; dnat_port="${BASH_REMATCH[2]}"
            elif [[ "$line" =~ dnat\ ip6\ to\ \[([^\]]+)\]:([0-9]+) ]]; then
                dnat_addr="${BASH_REMATCH[1]}"; dnat_port="${BASH_REMATCH[2]}"
            fi
            _extract_nft_proto_ipver "$line"
            if [[ -n "$_PROTO" && -n "$_IPVER" && -n "$dnat_addr" && -n "$dnat_port" ]]; then
                rule_tag=$(_pfwd_rule_tag "$port" "$_IPVER" "$_PROTO" "$dnat_addr" "$dnat_port")
            fi

            plat_nft_delete_rule_handle $NFT_TABLE "$chain" "$handle" && ((deleted++)) || true

            if [[ -n "$rule_tag" ]]; then
                local post_handles
                post_handles=$(_pfwd_postrouting_handle_refs_by_tag "$rule_tag" "$_PROTO" "$_IPVER")
                while IFS=$'\t' read -r chain h; do
                    [[ -n "$chain" && -n "$h" ]] || continue
                    plat_nft_delete_rule_handle $NFT_TABLE "$chain" "$h" && ((deleted++)) || true
                done <<< "$post_handles"

                local helper_handles
                helper_handles=$(_pfwd_forward_handle_refs_by_rule "$port" "$_IPVER" "$_PROTO" "$dnat_addr" "$dnat_port")
                while IFS=$'\t' read -r chain h; do
                    [[ -n "$chain" && -n "$h" ]] || continue
                    plat_nft_delete_rule_handle $NFT_TABLE "$chain" "$h" && ((deleted++)) || true
                done <<< "$helper_handles"
            fi
        done <<< "$prerouting_lines"

        if (( deleted > 0 )); then
            _traffic_delete_records nft_port "$port" "$proto"
            traffic_limit_delete_port "$port" "$proto"
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

_nft_prerouting_dnat_lines() {
    _nft_cached_chains_concat prerouting $(_pfwd_subchain_list prerouting) | grep "dnat" || true
}

# _parse_nft_prerouting_rules - parse nft prerouting output into structured data
# Output: proto<TAB>lport<TAB>ipver<TAB>target<TAB>tport<TAB>comment<TAB>bytes
# Args: [nft_output] - if empty, fetches from nft
_parse_nft_prerouting_rules() {
    local nft_output="${1:-}"
    if [[ -z "$nft_output" ]]; then
        nft_output=$(_nft_prerouting_dnat_lines)
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
            rest = substr($0, RSTART + 13)
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
            p = index(rest, "\"")
            if (p > 1) comment = substr(rest, 1, p - 1)
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
    local parsed
    parsed=$(_parse_nft_prerouting_rules)
    [[ -z "$parsed" ]] && return 0

    local post_data forward_data
    post_data=$(_nft_cached_chains_concat postrouting $(_pfwd_subchain_list postrouting) || true)
    forward_data=$(_nft_cached_chains_concat forward $(_pfwd_subchain_list forward) || true)

    local proto lport ipver target tport comment bytes
    while IFS=$'\t' read -r proto lport ipver target tport comment bytes; do
        [[ -z "$lport" ]] && continue

        local tag snat_mode="masquerade" snat_source="" mss_mode="" mss_value=""
        local post_line="" mss_line=""
        tag=$(_pfwd_rule_tag "$lport" "$ipver" "$proto" "$target" "$tport")

        post_line=$(printf '%s\n' "$post_data" | grep -F "comment \"$tag\"" | head -1 || true)
        if [[ -n "$post_line" && "$post_line" =~ snat([[:space:]]+ip6?|[[:space:]]+ip)?[[:space:]]+to[[:space:]]+(\[[^]]+\]|[^[:space:]]+) ]]; then
            snat_mode="snat"
            snat_source="${BASH_REMATCH[2]}"
            snat_source="${snat_source#[}"
            snat_source="${snat_source%]}"
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

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
            "$snat_mode" "$snat_source" "$mss_mode" "$mss_value"
    done <<< "$parsed"
}

# _parse_nft_bidirectional_traffic - parse prerouting + forward chain for traffic stats
# Output: proto<TAB>lport<TAB>ipver<TAB>target<TAB>tport<TAB>comment<TAB>in_bytes<TAB>out_bytes<TAB>total_bytes
_parse_nft_bidirectional_traffic() {
    local parsed_prerouting
    parsed_prerouting=$(_parse_nft_prerouting_rules)
    [[ -z "$parsed_prerouting" ]] && return 0

    local forward_ret_output
    forward_ret_output=$(_nft_cached_chains_concat forward $(_pfwd_subchain_list forward) | grep "pfwd_ret:" || true)

    declare -A out_bytes_map=()
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$line" =~ pfwd_ret:([0-9]+):([46]):([a-z]+) ]]; then
            local key="${BASH_REMATCH[3]}|${BASH_REMATCH[1]}|${BASH_REMATCH[2]}"
            local out_bytes=0
            if [[ "$line" =~ bytes[[:space:]]+([0-9]+) ]]; then
                out_bytes="${BASH_REMATCH[1]}"
            fi
            out_bytes_map["$key"]="$out_bytes"
        fi
    done <<< "$forward_ret_output"

    local proto lport ipver target tport comment in_bytes
    while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes; do
        [[ -z "$lport" ]] && continue
        local key="${proto}|${lport}|${ipver}"
        local out_bytes="${out_bytes_map[$key]:-0}"
        local total_bytes=$(( in_bytes + out_bytes ))
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" "$in_bytes" "$out_bytes" "$total_bytes"
    done <<< "$parsed_prerouting"
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
    rm -f "$TRAFFIC_DATA"
    traffic_limit_delete_all
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
#  Section 5: Traffic, Limits & Service Use Cases
#===============================================================================

cmd_internal_restore_nft() {
    require_root "$0 __restore-nft"
    _reset_change_flags

    if [[ ! -f "$NFT_CONFIG" || ! -s "$NFT_CONFIG" ]]; then
        msg_warn "No saved nftables config found"
        return 0
    fi

    ensure_ip_forwarding 2>/dev/null || true
    apply_bql_limits 65536 >/dev/null 2>&1 || true

    plat_nft_delete_table $NFT_TABLE || true
    if ! plat_nft_apply_file "$NFT_CONFIG"; then
        msg_err "Failed to restore nftables rules from $NFT_CONFIG"
        return 1
    fi

    _nft_invalidate_cache
    if ! _nft_table_exists; then
        msg_err "Restored nftables config did not create the expected table"
        return 1
    fi

    _pfwd_collect_state
    if $PFWD_LOOPBACK_DNAT; then
        ensure_route_localnet
    fi

    _DIRTY_UFW_SYNC=true
    sync_managed_firewall_state
    if $_DIRTY_UFW_RELOAD; then
        ufw_reload_if_enabled
        sync_managed_iptables_accept_rules
    fi

    return 0
}

_traffic_saved_records_tsv() {
    [[ -f "$TRAFFIC_DATA" ]] || return 0
    while IFS='|' read -r f1 f2 f3 f4 f5 f6 f7 f8 f9; do
        [[ -z "${f1:-}" ]] && continue
        if [[ "$f1" == "v2" && "$f2" == "nft_rule" ]]; then
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "${f3:-}" "${f4:-}" "${f5:-}" "${f6:-0}" "${f7:-0}" "${f8:-0}" "${f9:-0}"
        elif [[ "$f1" != "v2" ]]; then
            if ! $_TRAFFIC_LEGACY_WARNED; then
                msg_warn "Ignoring legacy traffic data in $TRAFFIC_DATA; only v2 nft_rule records are supported"
                _TRAFFIC_LEGACY_WARNED=true
            fi
        fi
    done < "$TRAFFIC_DATA"
}

# _traffic_read_merged - read-only merge of saved data + live nft counters
# Output: same format as _parse_nft_bidirectional_traffic
_traffic_read_merged() {
    local parsed
    parsed=$(_parse_nft_bidirectional_traffic)
    [[ -z "$parsed" ]] && return 0

    # Load saved accumulated + snapshot data
    declare -A acc_in acc_out snap_in snap_out
    while IFS=$'\t' read -r proto lport ipver saved_acc_in saved_acc_out saved_snap_in saved_snap_out; do
        [[ -z "$lport" ]] && continue
        local key="${proto}|${lport}|${ipver}"
        acc_in[$key]="${saved_acc_in:-0}"
        acc_out[$key]="${saved_acc_out:-0}"
        snap_in[$key]="${saved_snap_in:-0}"
        snap_out[$key]="${saved_snap_out:-0}"
    done < <(_traffic_saved_records_tsv)

    # Merge: accumulated + (current - snapshot) for each rule
    while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
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
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" "$merged_in" "$merged_out" "$merged_total"
    done <<< "$parsed"
}

# _nft_rules_for_display - merge rule metadata with accumulated traffic totals
# Output: proto<TAB>lport<TAB>ipver<TAB>target<TAB>tport<TAB>comment<TAB>snat_mode<TAB>snat_source<TAB>mss_mode<TAB>mss_value<TAB>total_bytes
_nft_rules_for_display() {
    local rules traffic
    rules=$(_parse_nft_export_rules)
    [[ -z "$rules" ]] && return 0

    traffic=$(_traffic_read_merged)
    declare -A traffic_total=()
    local proto lport ipver target tport comment in_bytes out_bytes total_bytes
    while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
        [[ -z "$lport" ]] && continue
        traffic_total["${proto}|${lport}|${ipver}"]="${total_bytes:-0}"
    done <<< "$traffic"

    local snat_mode snat_source mss_mode mss_value
    while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value; do
        [[ -z "$lport" ]] && continue
        total_bytes="${traffic_total[${proto}|${lport}|${ipver}]:-0}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
            "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" "$total_bytes"
    done <<< "$rules"
}

traffic_limit_show_status_table() {
    if ! traffic_limit_file_ready || ! command -v jq >/dev/null 2>&1; then
        return 0
    fi

    local rows="" has_rows=false
    while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value \
        limit_in limit_out limit_total reset_every reset_at_ts cycle_start_ts next_reset_ts cycle_in cycle_out disabled reason disabled_at_ts; do
        [[ -z "$lport" ]] && continue
        has_rows=true
        rows+="${proto}"$'\t'"${lport}"$'\t'"${ipver}"$'\t'"${target}"$'\t'"${tport}"$'\t'"${limit_in}"$'\t'"${limit_out}"$'\t'"${limit_total}"$'\t'"${cycle_in}"$'\t'"${cycle_out}"$'\t'"$(( cycle_in + cycle_out ))"$'\t'"${disabled}"$'\t'"${next_reset_ts}"$'\n'
    done < <(traffic_limit_records_tsv)

    $has_rows || return 0

    echo ""
    echo -e "${CYAN}Traffic limits:${NC}"
    echo -e "  ${DIM}┌────────┬──────┬──────┬──────────────────┬────────────┬────────────┬────────────┬────────┬─────────────────────┐${NC}"
    printf "  ${DIM}│${NC}${BOLD}%-8s${NC}${DIM}│${NC}${BOLD}%-6s${NC}${DIM}│${NC}${BOLD}%-6s${NC}${DIM}│${NC}${BOLD}%-18s${NC}${DIM}│${NC}${BOLD}%-12s${NC}${DIM}│${NC}${BOLD}%-12s${NC}${DIM}│${NC}${BOLD}%-12s${NC}${DIM}│${NC}${BOLD}%-8s${NC}${DIM}│${NC}${BOLD}%-21s${NC}${DIM}│${NC}\n" \
        " L.Port" " Proto" " IPvr" " Cycle Use" " In / Limit" " Out / Limit" " Total / Limit" " State" " Next Reset"
    echo -e "  ${DIM}├────────┼──────┼──────┼──────────────────┼────────────┼────────────┼────────────┼────────┼─────────────────────┤${NC}"

    while IFS=$'\t' read -r proto lport ipver target tport limit_in limit_out limit_total cycle_in cycle_out cycle_total disabled next_reset_ts; do
        [[ -z "$lport" ]] && continue
        local cycle_label in_label out_label total_label state_label next_reset_label
        cycle_label="$(format_bytes "$cycle_total")"
        in_label="$(format_bytes "$cycle_in") / $(traffic_limit_format_threshold "$limit_in")"
        out_label="$(format_bytes "$cycle_out") / $(traffic_limit_format_threshold "$limit_out")"
        total_label="$(format_bytes "$cycle_total") / $(traffic_limit_format_threshold "$limit_total")"
        if [[ "$disabled" == "true" ]]; then
            state_label=" blocked"
        else
            state_label=" active"
        fi
        next_reset_label=" $(traffic_limit_format_reset_at "$next_reset_ts")"
        printf "  ${DIM}│${NC}%-8s${DIM}│${NC}%-6s${DIM}│${NC}%-6s${DIM}│${NC}%-18s${DIM}│${NC}%-12s${DIM}│${NC}%-12s${DIM}│${NC}%-12s${DIM}│${NC}%-8s${DIM}│${NC}%-21s${DIM}│${NC}\n" \
            " :$lport" " $proto" " v$ipver" " $cycle_label" " ${in_label:0:12}" " ${out_label:0:12}" " ${total_label:0:12}" "$state_label" "${next_reset_label:0:21}"
    done <<< "$(echo "$rows" | _sort_parsed_rules)"
    echo -e "  ${DIM}└────────┴──────┴──────┴──────────────────┴────────────┴────────────┴────────────┴────────┴─────────────────────┘${NC}"
}

cmd_internal_traffic_collector() {
    require_root "$0 __traffic-collector"
    _nft_table_exists || return 0

    local parsed current_data now_ts
    parsed=$(_parse_nft_bidirectional_traffic)
    now_ts=$(date +%s)

    declare -A nft_acc_in nft_acc_out nft_snap_in nft_snap_out
    declare -A live_in live_out delta_in_map delta_out_map

    if [[ -f "$TRAFFIC_DATA" ]]; then
        while IFS=$'\t' read -r proto lport ipver saved_acc_in saved_acc_out saved_snap_in saved_snap_out; do
            [[ -z "$lport" ]] && continue
            local key="${proto}|${lport}|${ipver}"
            nft_acc_in[$key]="${saved_acc_in:-0}"
            nft_acc_out[$key]="${saved_acc_out:-0}"
            nft_snap_in[$key]="${saved_snap_in:-0}"
            nft_snap_out[$key]="${saved_snap_out:-0}"
        done < <(_traffic_saved_records_tsv)
    fi

    if [[ -n "$parsed" ]]; then
        while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
            [[ -z "$lport" ]] && continue
            local key="${proto}|${lport}|${ipver}"
            local prev_snap_in="${nft_snap_in[$key]:-0}"
            local prev_snap_out="${nft_snap_out[$key]:-0}"
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
            live_in[$key]="$in_bytes"
            live_out[$key]="$out_bytes"
            delta_in_map[$key]="$delta_in"
            delta_out_map[$key]="$delta_out"
            nft_acc_in[$key]=$(( ${nft_acc_in[$key]:-0} + delta_in ))
            nft_acc_out[$key]=$(( ${nft_acc_out[$key]:-0} + delta_out ))
            nft_snap_in[$key]="$in_bytes"
            nft_snap_out[$key]="$out_bytes"
        done <<< "$parsed"
    fi

    local traffic_tmp
    traffic_tmp=$(_mktemp_in_dir "$TRAFFIC_DATA") || return 1
    : > "$traffic_tmp"
    for key in "${!nft_acc_in[@]}"; do
        IFS='|' read -r proto lport ipver <<< "$key"
        echo "v2|nft_rule|${proto}|${lport}|${ipver}|${nft_acc_in[$key]}|${nft_acc_out[$key]}|${nft_snap_in[$key]:-0}|${nft_snap_out[$key]:-0}" >> "$traffic_tmp"
    done
    _atomic_replace_file "$traffic_tmp" "$TRAFFIC_DATA" 0644

    if ! traffic_limit_file_ready || ! command -v jq >/dev/null 2>&1; then
        return 0
    fi

    local limit_tmp config_dirty=false
    limit_tmp=$(_mktemp_in_dir "$TRAFFIC_LIMITS_DATA") || return 1
    : > "$limit_tmp"

    local active_rules
    active_rules=$(_parse_nft_prerouting_rules)

    while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value \
        limit_in limit_out limit_total reset_every reset_at_ts cycle_start_ts next_reset_ts cycle_in cycle_out disabled reason disabled_at_ts; do
        [[ -z "$lport" ]] && continue
        local key="${proto}|${lport}|${ipver}"
        cycle_in=$(( ${cycle_in:-0} + ${delta_in_map[$key]:-0} ))
        cycle_out=$(( ${cycle_out:-0} + ${delta_out_map[$key]:-0} ))

        if [[ "$next_reset_ts" =~ ^[0-9]+$ ]] && (( next_reset_ts > 0 && now_ts >= next_reset_ts )); then
            cycle_start_ts="$now_ts"
            cycle_in=0
            cycle_out=0
            if [[ -n "$reset_every" ]]; then
                while (( next_reset_ts <= now_ts )); do
                    next_reset_ts=$(traffic_limit_shift_timestamp "$next_reset_ts" "$reset_every") || {
                        next_reset_ts=0
                        break
                    }
                done
            else
                next_reset_ts=0
            fi

            if [[ "$disabled" == "true" && "$reason" == "limit" ]]; then
                if ! nft_find_existing_rule "$lport" "$proto" "$ipver" "$active_rules"; then
                    local ip_family="ip"
                    [[ "$ipver" == "6" ]] && ip_family="ip6"
                    if _nft_add_single_rule "$ip_family" "$proto" "$lport" "$target" "$tport" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "false"; then
                        config_dirty=true
                        active_rules=$(_parse_nft_prerouting_rules)
                    fi
                fi
                disabled="false"
                reason=""
                disabled_at_ts=0
            fi
        fi

        local cycle_total=$(( cycle_in + cycle_out ))
        if [[ "$disabled" != "true" ]]; then
            if (( ${limit_in:-0} > 0 && cycle_in >= limit_in )) || \
               (( ${limit_out:-0} > 0 && cycle_out >= limit_out )) || \
               (( ${limit_total:-0} > 0 && cycle_total >= limit_total )); then
                if _nft_delete_exact_rule "$lport" "$proto" "$ipver" "$target" "$tport"; then
                    config_dirty=true
                    active_rules=$(_parse_nft_prerouting_rules)
                fi
                disabled="true"
                reason="limit"
                disabled_at_ts="$now_ts"
            fi
        fi

        traffic_limit_make_tsv_line \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
            "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" \
            "$limit_in" "$limit_out" "$limit_total" "$reset_every" "$reset_at_ts" \
            "$cycle_start_ts" "$next_reset_ts" "$cycle_in" "$cycle_out" "$disabled" "$reason" "$disabled_at_ts" >> "$limit_tmp"
    done < <(traffic_limit_records_tsv)

    traffic_limit_save_from_stream < "$limit_tmp"
    rm -f "$limit_tmp" 2>/dev/null || true

    if [[ "$config_dirty" == true ]]; then
        _mark_nft_dirty
        sync_managed_firewall_state
        nft_save "auto"
        nft_setup_persistence
    fi
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

    traffic_limit_show_status_table
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
    while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
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

    while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
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
        echo "  5) View traffic limits"
        echo "  0) Back"
        echo ""
        read -rp "Select [0-5]: " traffic_choice

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
            5) cmd_limit_list; wait_for_enter ;;
            0) return ;;
            *) msg_warn "Invalid choice" ;;
        esac
    done
}

cmd_limit_list() {
    echo -e "${BOLD}Traffic Limits${NC}"
    echo -e "${DIM}$SEP_EQ${NC}"
    if ! traffic_limit_file_ready; then
        msg_dim "  No traffic limits configured"
        return 0
    fi
    ensure_jq || return 1
    traffic_limit_show_status_table
}

cmd_limit_set() {
    require_root "$0 limit set"
    local proto_filter="both" ipver_filter="46" port="" limit_in_raw="" limit_out_raw="" limit_total_raw=""
    local reset_every="" reset_at_raw="" limit_in=0 limit_out=0 limit_total=0 reset_at_ts=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tcp) proto_filter="tcp"; shift ;;
            --udp) proto_filter="udp"; shift ;;
            --both) proto_filter="both"; shift ;;
            -4) ipver_filter="4"; shift ;;
            -6) ipver_filter="6"; shift ;;
            -46) ipver_filter="46"; shift ;;
            --limit-in) limit_in_raw="$2"; shift 2 ;;
            --limit-out) limit_out_raw="$2"; shift 2 ;;
            --limit-total) limit_total_raw="$2"; shift 2 ;;
            --limit-reset-every) reset_every="$2"; shift 2 ;;
            --limit-reset-at) reset_at_raw="$2"; shift 2 ;;
            -*) msg_err "Unknown limit option: $1"; return 1 ;;
            *) port="$1"; shift ;;
        esac
    done

    validate_port "$port" || { msg_err "Invalid port: $port"; return 1; }
    ensure_jq || return 1

    if [[ -n "$limit_in_raw" ]]; then
        limit_in=$(traffic_limit_parse_size "$limit_in_raw") || {
            msg_err "Invalid --limit-in value: $limit_in_raw"
            return 1
        }
    fi
    if [[ -n "$limit_out_raw" ]]; then
        limit_out=$(traffic_limit_parse_size "$limit_out_raw") || {
            msg_err "Invalid --limit-out value: $limit_out_raw"
            return 1
        }
    fi
    if [[ -n "$limit_total_raw" ]]; then
        limit_total=$(traffic_limit_parse_size "$limit_total_raw") || {
            msg_err "Invalid --limit-total value: $limit_total_raw"
            return 1
        }
    fi
    traffic_limit_has_values "$limit_in" "$limit_out" "$limit_total" || {
        msg_err "Provide at least one of --limit-in / --limit-out / --limit-total"
        return 1
    }
    if [[ -n "$reset_every" ]]; then
        traffic_limit_validate_reset_every "$reset_every" || {
            msg_err "Invalid --limit-reset-every value: $reset_every"
            return 1
        }
    fi
    if [[ -n "$reset_at_raw" ]]; then
        reset_at_ts=$(traffic_limit_parse_reset_at_ts "$reset_at_raw") || {
            msg_err "Invalid --limit-reset-at value: $reset_at_raw"
            return 1
        }
    fi
    if [[ -z "$reset_every" && $reset_at_ts -le 0 ]]; then
        msg_err "Traffic limit requires --limit-reset-every and/or --limit-reset-at"
        return 1
    fi

    local matched=0 defs
    defs=$(traffic_limit_collect_rule_defs "$port" "$proto_filter" "$ipver_filter")
    if [[ -z "$defs" ]]; then
        msg_err "No matching rules found for port $port"
        return 1
    fi

    while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value; do
        [[ -z "$lport" ]] && continue
        traffic_limit_upsert_rule \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
            "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" \
            "$limit_in" "$limit_out" "$limit_total" "$reset_every" "$reset_at_ts" || return 1
        ((matched++)) || true
    done <<< "$defs"

    msg_ok "Configured traffic limits for $matched rule(s)"
}

cmd_limit_unset() {
    require_root "$0 limit unset"
    local proto_filter="both" ipver_filter="46" port=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tcp) proto_filter="tcp"; shift ;;
            --udp) proto_filter="udp"; shift ;;
            --both) proto_filter="both"; shift ;;
            -4) ipver_filter="4"; shift ;;
            -6) ipver_filter="6"; shift ;;
            -46) ipver_filter="46"; shift ;;
            -*) msg_err "Unknown limit option: $1"; return 1 ;;
            *) port="$1"; shift ;;
        esac
    done

    validate_port "$port" || { msg_err "Invalid port: $port"; return 1; }
    traffic_limit_file_ready || { msg_warn "No traffic limits configured"; return 0; }
    ensure_jq || return 1

    local changed=0
    while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value \
        limit_in limit_out limit_total reset_every reset_at_ts cycle_start_ts next_reset_ts cycle_in cycle_out disabled reason disabled_at_ts; do
        [[ -z "$lport" ]] && continue
        traffic_limit_selector_matches "$proto" "$lport" "$ipver" "$port" "$proto_filter" "$ipver_filter" || continue
        if [[ "$disabled" == "true" && "$reason" == "limit" ]]; then
            if ! nft_find_existing_rule "$lport" "$proto" "$ipver" "$(_parse_nft_prerouting_rules)"; then
                local ip_family="ip"
                [[ "$ipver" == "6" ]] && ip_family="ip6"
                if _nft_add_single_rule "$ip_family" "$proto" "$lport" "$target" "$tport" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "false"; then
                    _mark_nft_dirty
                fi
            fi
        fi
        traffic_limit_delete_exact "$proto" "$lport" "$ipver"
        ((changed++)) || true
    done < <(traffic_limit_records_tsv)

    if (( changed == 0 )); then
        msg_warn "No matching traffic limits found"
        return 0
    fi
    if $_DIRTY_NFT; then
        _batch_finalize nft
    fi
    msg_ok "Removed traffic limits for $changed rule(s)"
}

cmd_limit_restore() {
    require_root "$0 limit restore"
    local proto_filter="both" ipver_filter="46" port=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tcp) proto_filter="tcp"; shift ;;
            --udp) proto_filter="udp"; shift ;;
            --both) proto_filter="both"; shift ;;
            -4) ipver_filter="4"; shift ;;
            -6) ipver_filter="6"; shift ;;
            -46) ipver_filter="46"; shift ;;
            -*) msg_err "Unknown limit option: $1"; return 1 ;;
            *) port="$1"; shift ;;
        esac
    done

    validate_port "$port" || { msg_err "Invalid port: $port"; return 1; }
    traffic_limit_file_ready || { msg_warn "No traffic limits configured"; return 0; }
    ensure_jq || return 1

    local now_ts tmp_lines restored=0
    now_ts=$(date +%s)
    tmp_lines=$(_mktemp_in_dir "$TRAFFIC_LIMITS_DATA") || return 1
    while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value \
        limit_in limit_out limit_total reset_every reset_at_ts cycle_start_ts next_reset_ts cycle_in cycle_out disabled reason disabled_at_ts; do
        [[ -z "$lport" ]] && continue
        if traffic_limit_selector_matches "$proto" "$lport" "$ipver" "$port" "$proto_filter" "$ipver_filter"; then
            if [[ "$disabled" == "true" ]] && ! nft_find_existing_rule "$lport" "$proto" "$ipver" "$(_parse_nft_prerouting_rules)"; then
                local ip_family="ip"
                [[ "$ipver" == "6" ]] && ip_family="ip6"
                if _nft_add_single_rule "$ip_family" "$proto" "$lport" "$target" "$tport" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "false"; then
                    _mark_nft_dirty
                fi
            fi
            cycle_start_ts="$now_ts"
            next_reset_ts=$(traffic_limit_compute_next_reset_ts "$now_ts" "$reset_every" "$reset_at_ts") || next_reset_ts=0
            cycle_in=0
            cycle_out=0
            disabled="false"
            reason=""
            disabled_at_ts=0
            ((restored++)) || true
        fi
        traffic_limit_make_tsv_line \
            "$proto" "$lport" "$ipver" "$target" "$tport" "$comment" \
            "$snat_mode" "$snat_source" "$mss_mode" "$mss_value" \
            "$limit_in" "$limit_out" "$limit_total" "$reset_every" "$reset_at_ts" \
            "$cycle_start_ts" "$next_reset_ts" "$cycle_in" "$cycle_out" "$disabled" "$reason" "$disabled_at_ts" >> "$tmp_lines"
    done < <(traffic_limit_records_tsv)

    traffic_limit_save_from_stream < "$tmp_lines"
    rm -f "$tmp_lines" 2>/dev/null || true
    if (( restored == 0 )); then
        msg_warn "No matching traffic limits found"
        return 0
    fi
    if $_DIRTY_NFT; then
        _batch_finalize nft
    fi
    msg_ok "Restored $restored limited rule(s) and reset cycle counters"
}

cmd_limit() {
    local action="${1:-list}"
    shift || true
    case "$action" in
        list|ls) cmd_limit_list "$@" ;;
        set) cmd_limit_set "$@" ;;
        unset|del|delete) cmd_limit_unset "$@" ;;
        restore) cmd_limit_restore "$@" ;;
        *)
            msg_err "Unknown limit action: $action"
            msg_err "Use: pfwd limit [list|set|unset|restore]"
            return 1
            ;;
    esac
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
    local limit_map_json
    limit_map_json=$(traffic_limit_export_map_json)

    # Build nft rules JSON array in the v2 export shape.
    local nft_json="[]"
    if _nft_table_exists; then
        local parsed_nft
        parsed_nft=$(_parse_nft_export_rules)
        if [[ -n "$parsed_nft" ]]; then
            nft_json=$(printf '%s\n' "$parsed_nft" | json_export_rules_from_tsv "$limit_map_json")
        fi
    fi

    jq -n \
        --arg version "$VERSION" \
        --arg tool "pfwd" \
        --arg export_time "$(date '+%Y-%m-%dT%H:%M:%S')" \
        --arg source_ip "$(get_local_ip)" \
        --argjson nft "$nft_json" \
        '{
            export_info: {
                version_format: 2,
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
    require_root "$0 import"
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
    if ! json_require_v2_backup "$filepath"; then
        msg_err "Unsupported backup format: expected v2 JSON with forward_rules[]"
        return 1
    fi

    local count
    count=$(json_forward_rules_count "$filepath")
    msg_info "Found $count rule(s) in backup"

    # Show rules summary
    json_forward_rules_summary "$filepath"

    local imported=0 failed=0 skipped=0
    local nft_batch_count=0

    _BATCH_MODE=true
    while IFS=$'\t' read -r method lport target tport proto ipver comment mss_mode mss_value snat_mode snat_source \
        limit_in limit_out limit_total limit_reset_every limit_reset_at; do
        [[ -z "$method" ]] && continue
        if ! validate_comment "$comment"; then
            msg_warn "Skipping rule :$lport -> $target:$tport due to invalid multi-line/tab comment"
            ((failed++)) || true
            continue
        fi
        case "$method" in
            nft|nftables)
                if nft_add_rule "$lport" "$target" "$tport" "$ipver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "false" \
                    "${limit_in:-0}" "${limit_out:-0}" "${limit_total:-0}" "${limit_reset_every:-}" "${limit_reset_at:-0}"; then
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

    (( nft_batch_count > 0 )) && _batch_finalize nft

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
  stats       Traffic statistics
  limit       Manage traffic limits
  export      Export config to JSON
  import      Import config from JSON
  uninstall   Uninstall (nftables / all)
  optimize    Run kernel optimization [balanced|gaming|lowmem]
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
  pfwd stats
  pfwd stats --rate
  pfwd stats --interval
  pfwd stats --interval 1m
  pfwd limit list
  pfwd limit set 443 --limit-total 100G --limit-reset-every 1mo
  pfwd limit restore 443

Import / export:
  pfwd export [filepath]
  pfwd import <filepath> [-m nft]
  pfwd import --url <URL> [-m nft]
  Export and import use the current JSON v2 schema (forward_rules).
  Export/import preserves nft MSS, fixed-SNAT and traffic-limit fields.

New examples:
  pfwd -m nft -t 10.0.0.2 --mss-clamp 443
  pfwd -m nft -t 10.0.0.2 --mss 1360 8443:443
  pfwd -m nft -t 10.0.0.2 --replace 8443:443
  pfwd -m nft -t 10.0.0.2 --snat-source 192.168.1.2 9443:443
  pfwd -m nft -t 10.0.0.2 --snat-source 192.168.1.2 --mss 1360 9443:443
  pfwd -m nft -t 10.0.0.2 --limit-total 100G --limit-reset-every 1mo 9443:443
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

Performance tips:
  - nft is the fastest path for fixed IP targets.
  - Batch add/delete/import now coalesces nft save and UFW reload.
  - First root run from a persistent script path auto-installs /usr/local/bin/pfwd.
  - If using loopback DNAT (127.0.0.1 / ::1), verify UFW loopback exceptions stay synced.

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
  --snat-source <addr>       nft only: use fixed SNAT source instead of masquerade
  --masquerade               nft only: force default masquerade mode
  --limit-in <size>          nft only: inbound traffic limit (for example 500M / 2G)
  --limit-out <size>         nft only: outbound traffic limit
  --limit-total <size>       nft only: combined inbound+outbound traffic limit
  --limit-reset-every <Nd|Nmo|Ny>
                             nft only: cycle reset period (for example 1d / 2mo / 1y)
  --limit-reset-at <time>    nft only: absolute reset time (YYYY-MM-DD[ HH:MM[:SS]])
  -c, --comment <text>       Add single-line comment to rule
  -q, --quiet                Quiet mode
  --no-color                 Disable colored output
  --no-clear                 Don't clear screen in interactive menu

Interactive note:
  After choosing fixed SNAT, the menu can suggest a fixed MSS from that source
  interface MTU. The suggestion is informational; you still choose Off/Clamp/Fixed.
EOF
}

# cmd_add - add forwarding rules from CLI
cmd_add() {
    require_root "$0 add"
    local method="" ip_ver="46" proto="tcp" comment="" target="" rules_str=""
    local mss_mode="" mss_value="" snat_mode="masquerade" snat_source="" replace_mode="false"
    local limit_in_raw="" limit_out_raw="" limit_total_raw="" limit_reset_every="" limit_reset_at_raw=""
    local limit_in=0 limit_out=0 limit_total=0 limit_reset_at_ts=0
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
            --limit-in)   limit_in_raw="$2"; shift 2 ;;
            --limit-out)  limit_out_raw="$2"; shift 2 ;;
            --limit-total) limit_total_raw="$2"; shift 2 ;;
            --limit-reset-every) limit_reset_every="$2"; shift 2 ;;
            --limit-reset-at) limit_reset_at_raw="$2"; shift 2 ;;
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
    if [[ -n "$limit_in_raw" ]]; then
        limit_in=$(traffic_limit_parse_size "$limit_in_raw") || {
            msg_err "Invalid --limit-in value: $limit_in_raw"
            return 1
        }
    fi
    if [[ -n "$limit_out_raw" ]]; then
        limit_out=$(traffic_limit_parse_size "$limit_out_raw") || {
            msg_err "Invalid --limit-out value: $limit_out_raw"
            return 1
        }
    fi
    if [[ -n "$limit_total_raw" ]]; then
        limit_total=$(traffic_limit_parse_size "$limit_total_raw") || {
            msg_err "Invalid --limit-total value: $limit_total_raw"
            return 1
        }
    fi
    if traffic_limit_has_values "$limit_in" "$limit_out" "$limit_total"; then
        ensure_jq || return 1
        if [[ -n "$limit_reset_every" ]]; then
            traffic_limit_validate_reset_every "$limit_reset_every" || {
                msg_err "Invalid --limit-reset-every value: $limit_reset_every"
                msg_err "Use Nd, Nmo or Ny (for example: 1d, 2mo, 1y)"
                return 1
            }
        fi
        if [[ -n "$limit_reset_at_raw" ]]; then
            limit_reset_at_ts=$(traffic_limit_parse_reset_at_ts "$limit_reset_at_raw") || {
                msg_err "Invalid --limit-reset-at value: $limit_reset_at_raw"
                return 1
            }
        fi
        if [[ -z "$limit_reset_every" && $limit_reset_at_ts -le 0 ]]; then
            msg_err "Traffic limit requires --limit-reset-every and/or --limit-reset-at"
            return 1
        fi
    elif [[ -n "$limit_reset_every" || -n "$limit_reset_at_raw" ]]; then
        msg_err "Traffic reset policy requires at least one limit (--limit-in/out/total)"
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
        if _dispatch_add_rule "$method" "$RULE_LPORT" "$RULE_TARGET" "$RULE_TPORT" "$ip_ver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode" \
            "$limit_in" "$limit_out" "$limit_total" "$limit_reset_every" "$limit_reset_at_ts"; then
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
    require_root "$0 del"
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
            -f|--filter) filter="$2"; shift 2 ;;
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
    parsed_rules=$(_parse_nft_prerouting_rules)

    local errors=0
    local warnings=0

    while IFS=$'\t' read -r proto lport ipver target tport comment bytes; do
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
        if [[ "$target_type" == "ipv4" || "$target_type" == "ipv6" ]]; then
            if ! ping -c 1 -W 2 "$target" >/dev/null 2>&1; then
                msg_warn "Rule #$lport: Target $target:$tport is not reachable"
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
        for chain in $(_pfwd_subchain_list prerouting) $(_pfwd_subchain_list postrouting) $(_pfwd_subchain_list forward); do
            if _nft_cached_chain "$chain" >/dev/null; then
                _doctor_print_check OK "subchain ${chain} present"
            else
                _doctor_print_check WARN "subchain ${chain} missing" "will be recreated on next nft add"
            fi
        done
        if _nft_cached_table | grep -q "flowtable ft"; then
            _doctor_print_check OK "flowtable fast path configured"
        else
            _doctor_print_check WARN "flowtable fast path unavailable"
        fi
    elif (( saved_rules > 0 )); then
        _doctor_print_check WARN "saved nft config exists but table is not loaded" "run 'pfwd start nft' or 'pfwd restart nft'"
    else
        _doctor_print_check WARN "no active nft forwarding table"
    fi

    if [[ -f "$NFT_CONFIG" && -s "$NFT_CONFIG" ]]; then
        if command -v nft >/dev/null 2>&1 && plat_nft_check_file "$NFT_CONFIG"; then
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
    _doctor_print_check OK "traffic collector interval" "$(traffic_current_interval)"

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
            case "$PFWD_UFW_LOOPBACK_STATE" in
                ok) _doctor_print_check OK "UFW loopback DNAT exceptions synced" ;;
                missing) _doctor_print_check ERROR "UFW loopback DNAT exceptions missing" "reload pfwd rules or run 'ufw reload'" ;;
                disabled) _doctor_print_check WARN "UFW disabled; loopback exception sync not needed" ;;
                *) _doctor_print_check WARN "UFW loopback state: $PFWD_UFW_LOOPBACK_STATE" ;;
            esac
        fi
    fi

    # 检查是否有 IPv4/IPv6 转发规则
    local parsed_rules has_ipv4_rules=false has_ipv6_rules=false has_loopback_rules=false
    parsed_rules=$(_parse_nft_prerouting_rules)
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

    if command -v iptables >/dev/null 2>&1; then
        local fwd_policy input_policy
        fwd_policy=$(plat_iptables_policy iptables FORWARD)
        input_policy=$(plat_iptables_policy iptables INPUT)
        if [[ "$fwd_policy" == "DROP" ]]; then
            if [[ "$has_ipv4_rules" == true ]]; then
                if _iptables_rule_present iptables FORWARD -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_FWD_DNAT_COMMENT" -j ACCEPT && \
                   _iptables_rule_present iptables FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$IPTABLES_FWD_EST_COMMENT" -j ACCEPT; then
                    _doctor_print_check OK "iptables FORWARD managed exceptions present"
                else
                    _doctor_print_check ERROR "iptables FORWARD policy is DROP but pfwd exceptions are missing" "run 'pfwd restart nft' or reload UFW"
                fi
            else
                _doctor_print_check OK "iptables FORWARD policy is DROP (no IPv4 rules, no exceptions needed)"
            fi
        else
            _doctor_print_check OK "iptables FORWARD policy is ${fwd_policy:-unset}"
        fi
        if [[ "$input_policy" == "DROP" && $PFWD_LOOPBACK_DNAT == true && "$has_loopback_rules" == true ]]; then
            if _iptables_rule_present iptables INPUT -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_INPUT_DNAT_COMMENT" -j ACCEPT; then
                _doctor_print_check OK "iptables INPUT managed exception present for loopback DNAT"
            else
                _doctor_print_check ERROR "iptables INPUT loopback DNAT exception missing" "run 'pfwd restart nft' or reload UFW"
            fi
        fi
    fi

    if command -v ip6tables >/dev/null 2>&1; then
        local fwd_policy6 input_policy6
        fwd_policy6=$(plat_iptables_policy ip6tables FORWARD)
        input_policy6=$(plat_iptables_policy ip6tables INPUT)
        if [[ "$fwd_policy6" == "DROP" ]]; then
            if [[ "$has_ipv6_rules" == true ]]; then
                if _iptables_rule_present ip6tables FORWARD -m conntrack --ctstate DNAT -m comment --comment "$IPTABLES_FWD_DNAT_COMMENT" -j ACCEPT && \
                   _iptables_rule_present ip6tables FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$IPTABLES_FWD_EST_COMMENT" -j ACCEPT; then
                    _doctor_print_check OK "ip6tables FORWARD managed exceptions present"
                else
                    _doctor_print_check ERROR "ip6tables FORWARD policy is DROP but pfwd exceptions are missing" "run 'pfwd restart nft'"
                fi
            else
                _doctor_print_check OK "ip6tables FORWARD policy is DROP (no IPv6 rules, no exceptions needed)"
            fi
        else
            _doctor_print_check OK "ip6tables FORWARD policy is ${fwd_policy6:-unset}"
        fi
        if [[ "$input_policy6" == "DROP" && $PFWD_LOOPBACK_DNAT == true && "$has_loopback_rules" == true ]]; then
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

    if [[ -f "$TRAFFIC_SAVE_TIMER" ]]; then
        _doctor_print_check OK "traffic collector timer present" "interval=$(traffic_current_interval)"
    else
        _doctor_print_check WARN "traffic collector timer missing" "background traffic stats will not persist"
    fi

    if traffic_limit_file_ready; then
        if command -v jq >/dev/null 2>&1 && jq '.' "$TRAFFIC_LIMITS_DATA" >/dev/null 2>&1; then
            _doctor_print_check OK "traffic limit state file is valid" "$TRAFFIC_LIMITS_DATA"
        else
            _doctor_print_check ERROR "traffic limit state file is invalid or jq missing" "$TRAFFIC_LIMITS_DATA"
        fi
    else
        _doctor_print_check WARN "traffic limit state file missing" "no per-rule traffic limits configured"
    fi
}

# cmd_stop - stop forwarding without removing config
# cmd_status - show running status and rule counts
cmd_status() {
    _pfwd_collect_state
    echo -e "${BOLD}pfwd Status${NC}"
    echo -e "${DIM}$SEP_EQ_40${NC}"

    local nft_status
    $PFWD_NFT_RUNNING && nft_status="${GREEN}running${NC}" || nft_status="${RED}stopped${NC}"
    echo -e "  nftables:  $nft_status  ($PFWD_NFT_COUNT rules)"
    if [[ -n "$PFWD_NFT_RULES" ]]; then
        local nft_mss_count=0 nft_snat_count=0
        while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value; do
            [[ -z "$lport" ]] && continue
            [[ "$snat_mode" == "snat" ]] && ((nft_snat_count++)) || true
            [[ -n "$mss_mode" ]] && ((nft_mss_count++)) || true
        done <<< "$PFWD_NFT_RULES"
        if (( nft_mss_count > 0 || nft_snat_count > 0 )); then
            echo -e "  nft opts:  mss=${CYAN}${nft_mss_count}${NC}, fixed-snat=${CYAN}${nft_snat_count}${NC}"
        fi
    fi

    echo -e "  traffic int: ${CYAN}${PFWD_TRAFFIC_INTERVAL}${NC}"
    if (( PFWD_LIMIT_COUNT > 0 )); then
        echo -e "  limits:     ${CYAN}${PFWD_LIMIT_COUNT}${NC} configured, ${CYAN}${PFWD_LIMIT_BLOCKED_COUNT}${NC} blocked"
    else
        echo -e "  limits:     ${DIM}none${NC}"
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
                msg_warn "nftables forwarding is already running"
                return 0
            fi
            if cmd_internal_restore_nft; then
                if _nft_table_exists; then
                    local _restored_count
                    _restored_count=$(_nft_cached_chain prerouting | grep -c 'dnat') || _restored_count=0
                    msg_ok "nftables forwarding started ($_restored_count rules restored)"
                fi
            else
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
            rm -rf "$DATA_DIR"
            msg_ok "All pfwd components removed"
            ;;
        *)
            msg_err "Specify what to uninstall: nft or all"
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
        limit)
            shift
            cmd_limit "$@"
            ;;
        status)
            cmd_status
            ;;
        doctor|diagnose)
            cmd_doctor
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
    (( PFWD_LIMIT_COUNT > 0 )) && perf_parts+=("limit:${PFWD_LIMIT_COUNT}/${PFWD_LIMIT_BLOCKED_COUNT}")
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
            8) menu_uninstall || true ;;
            0) echo "Bye."; exit 0 ;;
            *) msg_warn "Invalid choice"; sleep 1.5 ;;
        esac
    done
}

# menu_add_rule - interactive rule addition
menu_add_rule() {
    local mss_mode="" mss_value="" snat_mode="masquerade" snat_source="" replace_mode="false"
    local limit_in=0 limit_out=0 limit_total=0 limit_reset_every="" limit_reset_at_ts=0 limit_reset_at_raw=""
    local suggested_mss="" suggested_mss_iface="" suggested_mss_mtu="" suggested_mss_family=""
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
                local snat_type
                snat_type=$(detect_ip_type "$snat_source")
                if [[ "$snat_type" != "ipv4" && "$snat_type" != "ipv6" ]]; then
                    msg_err "Invalid SNAT source address: $snat_source"
                    wait_for_enter
                    return
                fi
                if [[ "$proto" != "udp" ]] && suggest_mss_for_snat_source "$snat_source"; then
                    suggested_mss="$MSS_SUGGEST_VALUE"
                    suggested_mss_iface="$MSS_SUGGEST_IFACE"
                    suggested_mss_mtu="$MSS_SUGGEST_MTU"
                    suggested_mss_family="$MSS_SUGGEST_FAMILY"
                    msg_dim "  Detected ${suggested_mss_iface} MTU ${suggested_mss_mtu}, suggested fixed MSS ${suggested_mss} (${suggested_mss_family})"
                    msg_dim "  Clamp to PMTU is safer when path MTU may vary; fixed MSS is useful for PPPoE/tunnel setups."
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

    echo ""
    read -rp "Enable traffic limits for these rule(s)? [y/N]: " enable_limit
    if [[ "$enable_limit" =~ ^[Yy]$ ]]; then
        ensure_jq || {
            wait_for_enter
            return
        }
        local limit_value
        echo ""
        read -rp "Inbound limit (optional, e.g. 500M): " limit_value
        if [[ -n "$limit_value" ]]; then
            limit_in=$(traffic_limit_parse_size "$limit_value") || {
                msg_err "Invalid inbound limit: $limit_value"
                wait_for_enter
                return
            }
        fi
        read -rp "Outbound limit (optional, e.g. 500M): " limit_value
        if [[ -n "$limit_value" ]]; then
            limit_out=$(traffic_limit_parse_size "$limit_value") || {
                msg_err "Invalid outbound limit: $limit_value"
                wait_for_enter
                return
            }
        fi
        read -rp "Total limit (optional, e.g. 2G): " limit_value
        if [[ -n "$limit_value" ]]; then
            limit_total=$(traffic_limit_parse_size "$limit_value") || {
                msg_err "Invalid total limit: $limit_value"
                wait_for_enter
                return
            }
        fi
        traffic_limit_has_values "$limit_in" "$limit_out" "$limit_total" || {
            msg_err "At least one traffic limit must be configured"
            wait_for_enter
            return
        }

        echo ""
        read -rp "Reset cycle (optional, Nd/Nmo/Ny, e.g. 1d 1mo 1y): " limit_reset_every
        if [[ -n "$limit_reset_every" ]] && ! traffic_limit_validate_reset_every "$limit_reset_every"; then
            msg_err "Invalid reset cycle: $limit_reset_every"
            wait_for_enter
            return
        fi
        read -rp "Absolute reset time (optional, YYYY-MM-DD[ HH:MM[:SS]]): " limit_reset_at_raw
        if [[ -n "$limit_reset_at_raw" ]]; then
            limit_reset_at_ts=$(traffic_limit_parse_reset_at_ts "$limit_reset_at_raw") || {
                msg_err "Invalid absolute reset time: $limit_reset_at_raw"
                wait_for_enter
                return
            }
        fi
        if [[ -z "$limit_reset_every" && $limit_reset_at_ts -le 0 ]]; then
            msg_err "Traffic limit requires a reset cycle and/or an absolute reset time"
            wait_for_enter
            return
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
        if traffic_limit_has_values "$limit_in" "$limit_out" "$limit_total"; then
            echo -e "  Limit In: ${CYAN}$(traffic_limit_format_threshold "$limit_in")${NC}"
            echo -e "  Limit Out:${CYAN} $(traffic_limit_format_threshold "$limit_out")${NC}"
            echo -e "  Limit Tot:${CYAN} $(traffic_limit_format_threshold "$limit_total")${NC}"
            echo -e "  Reset:    ${CYAN}$(traffic_limit_format_reset_policy "$limit_reset_every" "$limit_reset_at_ts")${NC}"
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
        if _dispatch_add_rule "$method" "$RULE_LPORT" "$RULE_TARGET" "$RULE_TPORT" "$ip_ver" "$proto" "$comment" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source" "$replace_mode" \
            "$limit_in" "$limit_out" "$limit_total" "$limit_reset_every" "$limit_reset_at_ts"; then
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

    local nft_parsed=""
    local merged_nft=""
    if _nft_table_exists; then
        nft_parsed=$(_parse_nft_export_rules)
        merged_nft=$(_traffic_read_merged)
    fi

    local -a rule_methods=() rule_ports=() rule_labels=() rule_specs=()
    local -A nft_traffic_map=()
    local idx=0

    if [[ -n "$merged_nft" ]]; then
        while IFS=$'\t' read -r proto lport ipver target tport comment in_bytes out_bytes total_bytes; do
            [[ -z "$lport" ]] && continue
            nft_traffic_map["${proto}|${lport}|${ipver}"]="${total_bytes:-0}"
        done <<< "$merged_nft"
    fi

    if [[ -n "$nft_parsed" ]]; then
        while IFS=$'\t' read -r proto lport ipver target tport comment snat_mode snat_source mss_mode mss_value; do
            [[ -z "$lport" ]] && continue
            ((idx++)) || true
            rule_methods+=("nft")
            rule_ports+=("$lport")
            rule_specs+=("${proto}|${lport}|${ipver}|${target}|${tport}")
            local option_label traffic_label
            option_label=$(_nft_rule_option_summary "$snat_mode" "$snat_source" "$mss_mode" "$mss_value")
            traffic_label=$(format_bytes "${nft_traffic_map["${proto}|${lport}|${ipver}"]:-0}")
            rule_labels+=("$(printf "[nft] :%s %s IPv%s -> %s:%s [opts:%s] (%s)" "$lport" "$proto" "$ipver" "$target" "$tport" "$option_label" "$traffic_label")")
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
        for rnum in "${delete_rule_numbers[@]}"; do
            local ri=$((rnum - 1))
            local method="${rule_methods[$ri]}"
            case "$method" in
                nft)
                    local rule_proto rule_lport rule_ipver rule_target rule_tport
                    IFS='|' read -r rule_proto rule_lport rule_ipver rule_target rule_tport <<< "${rule_specs[$ri]}"
                    if _nft_delete_exact_rule "$rule_lport" "$rule_proto" "$rule_ipver" "$rule_target" "$rule_tport"; then
                        traffic_limit_delete_exact "$rule_proto" "$rule_lport" "$rule_ipver"
                        ((nft_rule_deleted++)) || true
                        ((delete_count++)) || true
                    fi
                    ;;
            esac
        done
        if (( nft_rule_deleted > 0 )); then
            _mark_nft_dirty
            _batch_finalize nft
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

# Initialize script path detection
SCRIPT_PATH=""

detect_script_path
ensure_shortcut_command "$@"
if cli_requires_root "$@"; then
    require_root "$@"
fi
parse_cli_args "$@"
