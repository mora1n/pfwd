#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

export PFWD_ROOT_PREFIX="$TMP_DIR/root-prefix"
source "$REPO_ROOT/pfwd.sh"
disable_colors
QUIET=true
require_root() { return 0; }

assert_contains() {
    local haystack="$1" needle="$2" label="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        echo "ASSERT FAILED: $label" >&2
        echo "Expected substring: $needle" >&2
        echo "Actual output: $haystack" >&2
        exit 1
    fi
}

assert_not_contains() {
    local haystack="$1" needle="$2" label="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "ASSERT FAILED: $label" >&2
        echo "Unexpected substring: $needle" >&2
        echo "Actual output: $haystack" >&2
        exit 1
    fi
}

assert_eq() {
    local actual="$1" expected="$2" label="$3"
    if [[ "$actual" != "$expected" ]]; then
        echo "ASSERT FAILED: $label" >&2
        echo "Expected: $expected" >&2
        echo "Actual:   $actual" >&2
        exit 1
    fi
}

sample_runtime_rules=$'tcp\t443\t4\tbackend-a\t192.0.2.10\t8443\t\tmasquerade\t\t\t\n'
sample_runtime_rules+=$'tcp\t444\t4\tbackend-b\t192.0.2.20\t9443\t\tmasquerade\t\t\t\n'
sample_runtime_rules+=$'udp\t5353\t6\tbackend-v6\t2001:db8::10\t5353\t\tmasquerade\t\t\t'
sample_postrouting_rules=$'tcp\t443\t4\tbackend-a\t192.0.2.10\t8443\t\tsnat\t198.51.100.5\t\t\n'
sample_postrouting_rules+=$'tcp\t444\t4\tbackend-b\t192.0.2.20\t9443\t\tsnat\t198.51.100.5\t\t\n'
sample_postrouting_rules+=$'udp\t5353\t6\tbackend-v6\t2001:db8::10\t5353\t\tmasquerade\t\t\t'
sample_mss_rules=$'tcp\t443\t4\tbackend-a\t192.0.2.10\t8443\t\tmasquerade\t\tclamp\t\n'
sample_mss_rules+=$'tcp\t444\t4\tbackend-b\t192.0.2.20\t9443\t\tmasquerade\t\tclamp\t\n'
sample_mss_rules+=$'tcp\t445\t4\tbackend-c\t192.0.2.30\t10443\t\tmasquerade\t\tset\t1360\n'
sample_mss_rules+=$'tcp\t446\t4\tbackend-d\t192.0.2.40\t11443\t\tmasquerade\t\tset\t1360\n'
sample_mss_rules+=$'tcp\t5353\t6\tbackend-v6\t2001:db8::10\t5353\t\tmasquerade\t\tclamp\t'

assert_eq "$(_pfwd_dnat_map_name tcp 4)" "pfwd_dnat_v4_tcp" "dnat map name"
assert_eq "$(_pfwd_dnat_map_value_type 4)" "ipv4_addr . inet_service" "ipv4 dnat map value type"
assert_eq "$(_pfwd_dnat_map_value_type 6)" "ipv6_addr . inet_service" "ipv6 dnat map value type"
assert_eq "$(_pfwd_dnat_statement_prefix 4)" "dnat ip addr . port to" "ipv4 dnat statement prefix"
assert_eq "$(_pfwd_dnat_statement_prefix 6)" "dnat ip6 addr . port to" "ipv6 dnat statement prefix"
assert_eq "$(_pfwd_postrouting_renderer_mode_from_text '')" "none" "empty postrouting renderer detection"
assert_eq "$(_pfwd_mss_renderer_mode_from_text '')" "none" "empty mss renderer detection"

map_entries_v4=$(_pfwd_dnat_map_elements_tsv "$sample_runtime_rules" tcp 4)
assert_contains "$map_entries_v4" $'443\t192.0.2.10\t8443' "v4 dnat map element 443"
assert_contains "$map_entries_v4" $'444\t192.0.2.20\t9443' "v4 dnat map element 444"

map_entries_v6=$(_pfwd_dnat_map_elements_tsv "$sample_runtime_rules" udp 6)
assert_eq "$map_entries_v6" $'5353\t2001:db8::10\t5353' "v6 dnat map element"

_pfwd_render_nft_config "$sample_runtime_rules" "$TMP_DIR/render-map.nft" offload "eth0" map
render_map=$(<"$TMP_DIR/render-map.nft")
assert_contains "$render_map" "map pfwd_dnat_v4_tcp {" "map renderer creates v4 tcp map block"
assert_contains "$render_map" "type inet_service : ipv4_addr . inet_service;" "map renderer uses concatenated ipv4 value type"
assert_contains "$render_map" "443 : 192.0.2.10 . 8443" "map renderer emits v4 map element"
assert_contains "$render_map" "map pfwd_dnat_v6_udp {" "map renderer creates v6 udp map block"
assert_contains "$render_map" "type inet_service : ipv6_addr . inet_service;" "map renderer uses concatenated ipv6 value type"
assert_contains "$render_map" "dnat ip addr . port to tcp dport map @pfwd_dnat_v4_tcp" "map renderer emits compact v4 dnat rule"
assert_contains "$render_map" "dnat ip6 addr . port to udp dport map @pfwd_dnat_v6_udp" "map renderer emits compact v6 dnat rule"
assert_not_contains "$render_map" "tcp dport 443 dnat ip to 192.0.2.10:8443" "map renderer removes legacy per-backend v4 dnat rule"

_pfwd_render_nft_config "$sample_runtime_rules" "$TMP_DIR/render-legacy.nft" offload "eth0" legacy
render_legacy=$(<"$TMP_DIR/render-legacy.nft")
assert_not_contains "$render_legacy" "map pfwd_dnat_v4_tcp {" "legacy renderer omits dnat maps"
assert_contains "$render_legacy" "tcp dport 443 dnat ip to 192.0.2.10:8443" "legacy renderer keeps direct v4 dnat rule"
assert_contains "$render_legacy" "udp dport 5353 dnat ip6 to [2001:db8::10]:5353" "legacy renderer keeps direct v6 dnat rule"

assert_eq "$(_pfwd_dnat_renderer_mode_from_text "$render_map")" "map" "detect map renderer"
assert_eq "$(_pfwd_dnat_renderer_mode_from_text "$render_legacy")" "legacy" "detect legacy renderer"
assert_eq "$(_pfwd_saved_dnat_renderer)" "missing" "saved renderer missing without config"

postrouting_group_keys_v4=$(_pfwd_postrouting_group_keys_tsv "$sample_postrouting_rules" tcp 4)
assert_eq "$postrouting_group_keys_v4" $'snat\t198.51.100.5' "postrouting snat group key"
postrouting_group_keys_v6=$(_pfwd_postrouting_group_keys_tsv "$sample_postrouting_rules" udp 6)
assert_eq "$postrouting_group_keys_v6" $'masquerade\t' "postrouting masquerade group key"

postrouting_entries_v4=$(_pfwd_postrouting_group_elements_tsv "$sample_postrouting_rules" tcp 4 snat 198.51.100.5)
assert_contains "$postrouting_entries_v4" $'192.0.2.10\t8443' "postrouting snat grouped entry 1"
assert_contains "$postrouting_entries_v4" $'192.0.2.20\t9443' "postrouting snat grouped entry 2"
postrouting_entries_v6=$(_pfwd_postrouting_group_elements_tsv "$sample_postrouting_rules" udp 6 masquerade '')
assert_eq "$postrouting_entries_v6" $'2001:db8::10\t5353' "postrouting masquerade grouped entry"

_pfwd_render_nft_config "$sample_postrouting_rules" "$TMP_DIR/render-postrouting-grouped.nft" offload "eth0" map grouped
render_postrouting_grouped=$(<"$TMP_DIR/render-postrouting-grouped.nft")
assert_contains "$render_postrouting_grouped" "ct status dnat ip daddr . tcp dport { 192.0.2.10 . 8443, 192.0.2.20 . 9443 } snat to 198.51.100.5" "grouped postrouting snat rule"
assert_contains "$render_postrouting_grouped" "ct status dnat ip6 daddr . udp dport { 2001:db8::10 . 5353 } masquerade" "grouped postrouting masquerade rule"
assert_not_contains "$render_postrouting_grouped" "ct status dnat ip daddr 192.0.2.10 tcp dport 8443 snat to 198.51.100.5" "grouped postrouting removes legacy snat rule"
assert_eq "$(_pfwd_postrouting_renderer_mode_from_text "$render_postrouting_grouped")" "grouped" "detect grouped postrouting renderer"

_pfwd_render_nft_config "$sample_postrouting_rules" "$TMP_DIR/render-postrouting-legacy.nft" offload "eth0" map legacy
render_postrouting_legacy=$(<"$TMP_DIR/render-postrouting-legacy.nft")
assert_contains "$render_postrouting_legacy" "ct status dnat ip daddr 192.0.2.10 tcp dport 8443 snat to 198.51.100.5" "legacy postrouting keeps direct snat rule"
assert_contains "$render_postrouting_legacy" "ct status dnat ip6 daddr 2001:db8::10 udp dport 5353 masquerade" "legacy postrouting keeps direct masquerade rule"
assert_eq "$(_pfwd_postrouting_renderer_mode_from_text "$render_postrouting_legacy")" "legacy" "detect legacy postrouting renderer"
assert_eq "$(_pfwd_saved_postrouting_renderer)" "missing" "saved postrouting renderer missing without config"

mss_group_keys_v4=$(_pfwd_mss_group_keys_tsv "$sample_mss_rules" tcp 4)
assert_contains "$mss_group_keys_v4" $'clamp\t' "mss grouped clamp key"
assert_contains "$mss_group_keys_v4" $'set\t1360' "mss grouped fixed key"
mss_group_keys_v6=$(_pfwd_mss_group_keys_tsv "$sample_mss_rules" tcp 6)
assert_eq "$mss_group_keys_v6" $'clamp\t' "mss grouped ipv6 clamp key"

mss_entries_v4_clamp=$(_pfwd_mss_group_elements_tsv "$sample_mss_rules" tcp 4 clamp '')
assert_contains "$mss_entries_v4_clamp" $'192.0.2.10\t8443' "mss clamp grouped entry 1"
assert_contains "$mss_entries_v4_clamp" $'192.0.2.20\t9443' "mss clamp grouped entry 2"
mss_entries_v4_fixed=$(_pfwd_mss_group_elements_tsv "$sample_mss_rules" tcp 4 set 1360)
assert_contains "$mss_entries_v4_fixed" $'192.0.2.30\t10443' "mss fixed grouped entry 1"
assert_contains "$mss_entries_v4_fixed" $'192.0.2.40\t11443' "mss fixed grouped entry 2"

_pfwd_render_nft_config "$sample_mss_rules" "$TMP_DIR/render-mss-grouped.nft" offload "eth0" map grouped grouped
render_mss_grouped=$(<"$TMP_DIR/render-mss-grouped.nft")
assert_contains "$render_mss_grouped" "ip daddr . tcp dport { 192.0.2.10 . 8443, 192.0.2.20 . 9443 } tcp flags syn / syn,rst tcp option maxseg size set rt mtu" "grouped mss clamp rule"
assert_contains "$render_mss_grouped" "ip daddr . tcp dport { 192.0.2.30 . 10443, 192.0.2.40 . 11443 } tcp flags syn / syn,rst tcp option maxseg size set 1360" "grouped mss fixed rule"
assert_contains "$render_mss_grouped" "ip6 daddr . tcp dport { 2001:db8::10 . 5353 } tcp flags syn / syn,rst tcp option maxseg size set rt mtu" "grouped mss ipv6 clamp rule"
assert_not_contains "$render_mss_grouped" "ip daddr 192.0.2.10 tcp dport 8443 tcp flags syn / syn,rst tcp option maxseg size set rt mtu" "grouped mss removes legacy clamp rule"
assert_eq "$(_pfwd_mss_renderer_mode_from_text "$render_mss_grouped")" "grouped" "detect grouped mss renderer"

_pfwd_render_nft_config "$sample_mss_rules" "$TMP_DIR/render-mss-legacy.nft" offload "eth0" map grouped legacy
render_mss_legacy=$(<"$TMP_DIR/render-mss-legacy.nft")
assert_contains "$render_mss_legacy" "ip daddr 192.0.2.10 tcp dport 8443 tcp flags syn / syn,rst tcp option maxseg size set rt mtu" "legacy mss keeps direct clamp rule"
assert_contains "$render_mss_legacy" "ip daddr 192.0.2.30 tcp dport 10443 tcp flags syn / syn,rst tcp option maxseg size set 1360" "legacy mss keeps direct fixed rule"
assert_eq "$(_pfwd_mss_renderer_mode_from_text "$render_mss_legacy")" "legacy" "detect legacy mss renderer"
assert_eq "$(_pfwd_saved_mss_renderer)" "missing" "saved mss renderer missing without config"

_pfwd_render_nft_config "$sample_mss_rules" "$TMP_DIR/render-mss-recover.nft" offload "eth0" legacy grouped grouped
render_mss_recover=$(<"$TMP_DIR/render-mss-recover.nft")
_nft_reset_snapshot
_nft_index_forward_snapshot "$(_pfwd_chain_from_text "$render_mss_recover" "$(_pfwd_subchain_name forward tcp 4)")"$'\n'"$(_pfwd_chain_from_text "$render_mss_recover" "$(_pfwd_subchain_name forward tcp 6)")"
parsed_prerouting=$'tcp\t443\t4\t192.0.2.10\t8443\t\t0\n'
parsed_prerouting+=$'tcp\t444\t4\t192.0.2.20\t9443\t\t0\n'
parsed_prerouting+=$'tcp\t445\t4\t192.0.2.30\t10443\t\t0\n'
parsed_prerouting+=$'tcp\t446\t4\t192.0.2.40\t11443\t\t0\n'
parsed_prerouting+=$'tcp\t5353\t6\t2001:db8::10\t5353\t\t0'
recovered_mss_rules=$(_parse_nft_export_rules "$parsed_prerouting")
assert_contains "$recovered_mss_rules" $'tcp\t443\t4\t192.0.2.10\t8443\t0\tmasquerade\t\tclamp\t' "recover grouped clamp mss metadata"
assert_contains "$recovered_mss_rules" $'tcp\t445\t4\t192.0.2.30\t10443\t0\tmasquerade\t\tset\t1360' "recover grouped fixed mss metadata"

help_output=$("$REPO_ROOT/pfwd.sh" help 2>&1)
assert_contains "$help_output" "pfwd import <filepath>" "help import syntax"
assert_contains "$help_output" "Forwarding method (nft only)" "help nft-only method"

echo "pfwd_regression: OK"
