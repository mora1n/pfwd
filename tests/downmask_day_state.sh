#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_eq() {
    local expected="$1"
    local actual="$2"
    local label="$3"
    [ "$expected" = "$actual" ] || fail "$label: expected '$expected', got '$actual'"
}

assert_num_range() {
    local min="$1"
    local max="$2"
    local actual="$3"
    local label="$4"
    awk -v min="$min" -v max="$max" -v actual="$actual" 'BEGIN { exit !(actual >= min && actual <= max) }' ||
        fail "$label: expected $actual in [$min, $max]"
}

run_pfwd_in_root() {
    local root="$1"
    shift
    PFWD_ROOT_PREFIX="$root" PFWD_SKIP_SHORTCUT=1 bash "$ROOT_DIR/pfwd.sh" "$@"
}

write_downmask_config() {
    local root="$1"
    local min_ratio="${2:-1.5}"
    local max_ratio="${3:-2.8}"
    mkdir -p "$root/etc/pfwd"
    jq -n \
        --arg min_ratio "$min_ratio" \
        --arg max_ratio "$max_ratio" '
        {
          settings: {
            nft_family: "inet",
            nft_table: "pfwd",
            forward_table: "port_forward",
            domain_refresh_interval: "60s",
            tc_interface: "",
            forward: {interface: ""},
            default_listen_ip: "::",
            default_random_port_range: "20000-30000",
            guard: {
              enabled: false,
              tc_interface: "",
              block_http: false,
              block_tls: false,
              block_socks: false,
              protocol_skip_ports: []
            },
            whitelist: {
              enabled: false,
              include_cn: true,
              cn_mode: "all",
              cn_provinces: [],
              cn_city_codes: [],
              custom_cidrs: [],
              runtime_hash: ""
            },
            egress_whitelist: {
              enabled: false,
              include_cn: true,
              cn_mode: "all",
              cn_provinces: [],
              custom_cidrs: [],
              runtime_hash: ""
            },
            downmask: {
              iface: "lo",
              min_ratio: ($min_ratio | tonumber),
              max_ratio: ($max_ratio | tonumber),
              time_window_start: "",
              time_window_end: "",
              max_jitter_seconds: 60,
              min_deficit_bytes: 20971520,
              max_bytes_per_run: 524288000,
              pull_mode: "public",
              public: {
                active_source: "cloudflare_dynamic",
                speed_limit: "4M",
                custom_sources: []
              },
              ab_pull: {
                protocol: "tcp",
                protocol_mode: "parallel",
                tcp_enabled: true,
                udp_enabled: true,
                remote_host: "",
                remote_port: 0,
                local_ip: "",
                token: "",
                speed_limit: "4M",
                timeout_seconds: 300,
                parallel_limit: 2,
                speed_jitter_percent: 12,
                bytes_jitter_percent: 18,
                targets: []
              },
              ab_feed: {
                tcp_enabled: false,
                udp_enabled: false,
                bind_ip: "0.0.0.0",
                tcp_port: 0,
                udp_port: 0,
                token: "",
                seed_file: "/var/lib/pfwd/downmask/seed.bin",
                udp_payload_bytes: 1200
              }
            }
          },
          users: [],
          forwards: []
        }' > "$root/etc/pfwd/config.json"
}

test_new_day_refreshes_and_records_audit() {
    local tmp today yesterday state_file json ratio
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    today="$(date '+%Y-%m-%d')"
    yesterday="$(date -d 'yesterday' '+%Y-%m-%d')"
    write_downmask_config "$tmp"
    state_file="$tmp/var/lib/pfwd/downmask/day_state.json"
    mkdir -p "$(dirname "$state_file")"
    jq -n --arg yesterday "$yesterday" '{
      date: $yesterday,
      iface: "lo",
      target_ratio: 2.1451,
      rx_accum: 12345,
      tx_accum: 67890,
      last_rx_raw: 1,
      last_tx_raw: 2,
      next_eligible_at: 999,
      last_action: "skip",
      last_actual_bytes: 111,
      last_planned_bytes: 222,
      last_error: "old"
    }' > "$state_file"

    json="$(run_pfwd_in_root "$tmp" downmask status)"
    assert_eq "$today" "$(jq -r '.day_state.date' <<< "$json")" "new day date"
    assert_eq "new_day" "$(jq -r '.day_state.last_action' <<< "$json")" "new day action"
    assert_eq "$yesterday" "$(jq -r '.day_state.previous_date' <<< "$json")" "previous date audit"
    assert_eq "2.1451" "$(jq -r '.day_state.previous_target_ratio | tostring' <<< "$json")" "previous ratio audit"
    assert_eq "0" "$(jq -r '.day_state.rx_accum' <<< "$json")" "new day rx reset"
    assert_eq "0" "$(jq -r '.day_state.tx_accum' <<< "$json")" "new day tx reset"
    assert_eq "0" "$(jq -r '.day_state.next_eligible_at' <<< "$json")" "new day next eligible reset"
    assert_eq "0" "$(jq -r '.day_state.last_actual_bytes' <<< "$json")" "new day no pull actual"
    assert_eq "0" "$(jq -r '.day_state.last_planned_bytes' <<< "$json")" "new day no pull planned"
    ratio="$(jq -r '.day_state.target_ratio' <<< "$json")"
    assert_num_range "1.5" "2.8" "$ratio" "new day target ratio"
}

test_equal_random_ratio_is_adjusted_when_range_allows() {
    local tmp today yesterday state_file json
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    today="$(date '+%Y-%m-%d')"
    yesterday="$(date -d 'yesterday' '+%Y-%m-%d')"
    write_downmask_config "$tmp" "2.1451" "2.1452"
    state_file="$tmp/var/lib/pfwd/downmask/day_state.json"
    mkdir -p "$(dirname "$state_file")"
    jq -n --arg yesterday "$yesterday" '{
      date: $yesterday,
      iface: "lo",
      target_ratio: 2.1451,
      rx_accum: 100,
      tx_accum: 200,
      last_rx_raw: 1,
      last_tx_raw: 2,
      next_eligible_at: 999
    }' > "$state_file"

    json="$(run_pfwd_in_root "$tmp" downmask status)"
    assert_eq "$today" "$(jq -r '.day_state.date' <<< "$json")" "adjust date"
    assert_eq "2.1452" "$(jq -r '.day_state.target_ratio | tostring' <<< "$json")" "adjusted target ratio"
    assert_eq "2.1451" "$(jq -r '.day_state.previous_target_ratio | tostring' <<< "$json")" "adjust previous ratio"
}

test_same_day_keeps_ratio_and_accumulates() {
    local tmp today state_file json
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    today="$(date '+%Y-%m-%d')"
    write_downmask_config "$tmp"
    state_file="$tmp/var/lib/pfwd/downmask/day_state.json"
    mkdir -p "$(dirname "$state_file")"
    jq -n --arg today "$today" '{
      date: $today,
      iface: "lo",
      target_ratio: 2.1451,
      rx_accum: 123,
      tx_accum: 456,
      last_rx_raw: 999999999999999,
      last_tx_raw: 999999999999999,
      next_eligible_at: 321,
      last_action: "below_min_deficit",
      last_actual_bytes: 11,
      last_planned_bytes: 22,
      last_error: "existing"
    }' > "$state_file"

    json="$(run_pfwd_in_root "$tmp" downmask status)"
    assert_eq "$today" "$(jq -r '.day_state.date' <<< "$json")" "same day date"
    assert_eq "2.1451" "$(jq -r '.day_state.target_ratio | tostring' <<< "$json")" "same day ratio"
    assert_eq "below_min_deficit" "$(jq -r '.day_state.last_action' <<< "$json")" "same day action preserved"
    assert_eq "321" "$(jq -r '.day_state.next_eligible_at' <<< "$json")" "same day next eligible"
    assert_eq "11" "$(jq -r '.day_state.last_actual_bytes' <<< "$json")" "same day actual preserved"
    assert_eq "22" "$(jq -r '.day_state.last_planned_bytes' <<< "$json")" "same day planned preserved"
}

test_invalid_state_fails_loudly() {
    local tmp state_file output rc
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    write_downmask_config "$tmp"
    state_file="$tmp/var/lib/pfwd/downmask/day_state.json"
    mkdir -p "$(dirname "$state_file")"
    printf '{invalid json\n' > "$state_file"

    set +e
    output="$(run_pfwd_in_root "$tmp" downmask status 2>&1)"
    rc=$?
    set -e
    [ "$rc" -ne 0 ] || fail "invalid state should fail"
    grep -q "无效 downmask 日状态文件" <<< "$output" || fail "invalid state error message missing: $output"
}

test_new_day_refreshes_and_records_audit
test_equal_random_ratio_is_adjusted_when_range_allows
test_same_day_keeps_ratio_and_accumulates
test_invalid_state_fails_loudly

echo "downmask day state tests passed"
