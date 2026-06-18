#!/usr/bin/env bash

cmd_doctor_benchmark() {
    local label="$1"
    local command="$2"
    local loops="${3:-3}"
    local start_ns end_ns elapsed_ms total_ms=0 max_ms=0 run_ms loop
    for ((loop = 1; loop <= loops; loop++)); do
        start_ns="$(date +%s%N 2>/dev/null || true)"
        bash -lc "$command" >/dev/null 2>&1 || {
            echo "$label：n/a"
            return 0
        }
        end_ns="$(date +%s%N 2>/dev/null || true)"
        if [[ ! "$start_ns" =~ ^[0-9]+$ ]] || [[ ! "$end_ns" =~ ^[0-9]+$ ]]; then
            echo "$label：ok"
            return 0
        fi
        run_ms=$(( (end_ns - start_ns) / 1000000 ))
        total_ms=$((total_ms + run_ms))
        if [ "$run_ms" -gt "$max_ms" ]; then
            max_ms="$run_ms"
        fi
    done
    elapsed_ms=$(( total_ms / loops ))
    echo "$label：avg=${elapsed_ms}ms max=${max_ms}ms loops=${loops}"
}


cmd_doctor_runner() {
    local body="$1"
    local script_dir script_path
    script_dir="$(printf '%q' "$PFWD_SCRIPT_DIR")"
    script_path="$(printf '%q' "$PFWD_SCRIPT_DIR/pfwd.sh")"
    printf 'cd %s && tmp_root="$(mktemp -d /tmp/pfwd-bench.XXXXXX)" && trap '\''rm -rf "$tmp_root"'\'' EXIT && export PFWD_ROOT_PREFIX="$tmp_root" PFWD_SKIP_SHORTCUT=1 && { source %s help >/dev/null 2>&1 || true; config_init >/dev/null 2>&1; %s; }' "$script_dir" "$script_path" "$body"
}


cmd_doctor_benchmarks() {
    cmd_doctor_benchmark "benchmark.stats_current_snapshot" "$(cmd_doctor_runner 'stats_current_snapshot >/dev/null')"
    cmd_doctor_benchmark "benchmark.stats_rollup_current" "$(cmd_doctor_runner 'stats_rollup_current >/dev/null')"
    cmd_doctor_benchmark "benchmark.xdp_read_counters" "$(cmd_doctor_runner 'fw_read_counters >/dev/null')"
    cmd_doctor_benchmark "benchmark.xdp_runtime_json" "$(cmd_doctor_runner 'forwarder_runtime_json true >/dev/null')"
    cmd_doctor_benchmark "benchmark.ui_main_usage_json" "$(cmd_doctor_runner 'UI_COLOR_ENABLED=0; ui_main_usage_json >/dev/null')"
    cmd_doctor_benchmark "benchmark.main_page" "$(cmd_doctor_runner 'UI_COLOR_ENABLED=0; ui_render_main_menu_page >/dev/null')"
    cmd_doctor_benchmark "benchmark.forward_list" "$(cmd_doctor_runner 'UI_COLOR_ENABLED=0; ui_print_forward_list >/dev/null')"
}


cmd_doctor_usage() {
    cat <<'EOF'
用法：pfwd doctor [--bench]
EOF
}


cmd_doctor() {
    local include_bench="false"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --bench) include_bench="true"; shift ;;
            help|-h|--help)
                cmd_doctor_usage
                return 0
                ;;
            *)
                cmd_doctor_usage >&2
                pfwd_die "未知选项：$1"
                ;;
        esac
    done
    config_init >/dev/null
    local forwarder_status xdp_status doctor_status_fields backend fallback_reason hybrid_reason tc_iface tc_ifb tc_mode xdp_active_total xdp_tcp_prewarmed xdp_tcp_established xdp_udp_active
    local dataplane_version map_abi_version incremental_apply preserved_connections invalidated_connections profile_counts
    local refresh_mode refresh_total_ms refresh_reconcile_ms refresh_map_load_ms refresh_aux_actions refresh_attach_timings
    local refresh_rules_added refresh_rules_updated refresh_rules_deleted refresh_users_added refresh_users_updated refresh_users_deleted
    local refresh_counters_preserved refresh_counters_reset
    stats_runtime_cache_clear
    forwarder_status="$(forwarder_status_json)"
    xdp_status="$(forwarder_xdp_status_json)"
    doctor_status_fields="$(jq -rn --argjson f "$forwarder_status" --argjson x "$xdp_status" '
      def rr: ($f.xdp_status.refresh_report // $f.refresh_report // {});
      def profiles:
        (($f.profile_counts // $f.xdp_status.profile_counts // {}) | to_entries | sort_by(.key) | map("\(.key)=\(.value)") | join(", ")) as $items
        | if $items == "" then "-" else $items end;
      def aux_actions:
        ((rr.aux_actions // []) | map(.component + "=" + .action + (if ((.changed_items // 0) > 0) then "(" + ((.changed_items | tostring)) + ")" else "" end)) | join(", ")) as $items
        | if $items == "" then "-" else $items end;
      def attach_timings:
        ((rr.attach_timings // []) | map(.component + "=" + ((.duration_ms | tostring)) + "ms") | join(", ")) as $items
        | if $items == "" then "-" else $items end;
      [
        ($f.forwarding_backend // "none"),
        ($f.fallback_reason // ""),
        ($f.hybrid_reason // ""),
        ($x.active_summary.total // 0),
        ($x.active_summary.tcp_syn_pending // 0),
        ($x.active_summary.tcp_established // 0),
        ($x.active_summary.udp // 0),
        ($f.dataplane_version // $f.xdp_status.dataplane_version // "-"),
        ($f.map_abi_version // $f.xdp_status.map_abi_version // "-"),
        ($f.xdp_status.incremental_apply // $f.incremental_apply // false),
        ($f.xdp_status.preserved_connections // $f.preserved_connections // 0),
        ($f.xdp_status.invalidated_connections // $f.invalidated_connections // 0),
        profiles,
        (rr.mode // "-"),
        (rr.total_duration_ms // "-"),
        (rr.reconcile_duration_ms // "-"),
        (rr.map_load_duration_ms // "-"),
        aux_actions,
        attach_timings,
        (rr.rules_added // 0),
        (rr.rules_updated // 0),
        (rr.rules_deleted // 0),
        (rr.users_added // 0),
        (rr.users_updated // 0),
        (rr.users_deleted // 0),
        (rr.counters_preserved // 0),
        (rr.counters_reset // 0)
      ] | map(tostring) | join("\u001f")
    ')"
    IFS=$'\037' read -r backend fallback_reason hybrid_reason xdp_active_total xdp_tcp_prewarmed xdp_tcp_established xdp_udp_active dataplane_version map_abi_version incremental_apply preserved_connections invalidated_connections profile_counts refresh_mode refresh_total_ms refresh_reconcile_ms refresh_map_load_ms refresh_aux_actions refresh_attach_timings refresh_rules_added refresh_rules_updated refresh_rules_deleted refresh_users_added refresh_users_updated refresh_users_deleted refresh_counters_preserved refresh_counters_reset <<< "$doctor_status_fields"
    tc_iface="$(fw_tc_state_read_iface 2>/dev/null || true)"
    tc_ifb="$(fw_tc_ifb_name 2>/dev/null || true)"
    if [ -n "$tc_iface" ]; then
        tc_mode="bidirectional-ifb"
    elif [ "$(fw_effective_rate_count 2>/dev/null || echo 0)" -gt 0 ]; then
        tc_mode="configured-no-runtime"
    else
        tc_mode="disabled"
    fi
    echo "配置文件：$PFWD_CONFIG_FILE"
    jq -e . "$PFWD_CONFIG_FILE" >/dev/null && echo "配置 JSON：正常"
    echo "数据面：$backend"
    if [ -n "$fallback_reason" ]; then
        echo "回退原因：$fallback_reason"
    elif [ "$hybrid_reason" = "loopback-split" ]; then
        echo "混合原因：localhost 分流"
    fi
    echo "dataplane.version：$dataplane_version"
    echo "dataplane.map_abi：$map_abi_version"
    echo "xdp.incremental_apply：$incremental_apply"
    echo "xdp.preserved_connections：$preserved_connections"
    echo "xdp.invalidated_connections：$invalidated_connections"
    echo "xdp.refresh_mode：$refresh_mode"
    echo "xdp.refresh_total_ms：$refresh_total_ms"
    echo "xdp.refresh_map_load_ms：$refresh_map_load_ms"
    echo "xdp.refresh_reconcile_ms：$refresh_reconcile_ms"
    echo "xdp.refresh_aux_actions：$refresh_aux_actions"
    echo "xdp.refresh_attach_timings：$refresh_attach_timings"
    echo "xdp.rules_added：$refresh_rules_added"
    echo "xdp.rules_updated：$refresh_rules_updated"
    echo "xdp.rules_deleted：$refresh_rules_deleted"
    echo "xdp.users_added：$refresh_users_added"
    echo "xdp.users_updated：$refresh_users_updated"
    echo "xdp.users_deleted：$refresh_users_deleted"
    echo "xdp.counters_preserved：$refresh_counters_preserved"
    echo "xdp.counters_reset：$refresh_counters_reset"
    echo "xdp.profile_counts：${profile_counts:-"-"}"
    echo "运行态文件：$PFWD_FORWARDER_RUNTIME_FILE"
    if [ -x "$(forwarder_bin_path)" ]; then echo "pfwd-xdp：$(forwarder_bin_path)"; else echo "pfwd-xdp：缺失"; fi
    if command -v tc >/dev/null 2>&1; then echo "tc：$(command -v tc)"; else echo "tc：缺失"; fi
    echo "xdp.active_total：$xdp_active_total"
    echo "xdp.tcp_syn_pending：$xdp_tcp_prewarmed"
    echo "xdp.tcp_established：$xdp_tcp_established"
    echo "xdp.udp_active：$xdp_udp_active"
    echo "tc.mode：$tc_mode"
    if [ -n "$tc_iface" ]; then echo "tc.iface：$tc_iface"; fi
    if [ -n "$tc_ifb" ] && [ "$tc_mode" = "bidirectional-ifb" ]; then echo "tc.ifb：$tc_ifb"; fi
    if command -v systemctl >/dev/null 2>&1; then echo "systemctl：正常"; else echo "systemctl：缺失"; fi
    if guard_binary_exists; then echo "guard：$(guard_bin_path)"; else echo "guard：缺失"; fi
    echo "运行态安装：$(service_runtime_status_label)"
    if service_unit_exists pfwd.timer; then echo "pfwd.timer：已安装"; else echo "pfwd.timer：未安装"; fi
    if service_unit_exists pfwd-bbr.service; then echo "pfwd-bbr.service：已安装"; else echo "pfwd-bbr.service：未安装"; fi
    if service_unit_exists pfwd-xdp.service; then echo "pfwd-xdp.service：已安装"; else echo "pfwd-xdp.service：未安装"; fi
    if service_unit_exists pfwd-downmask-feed.service; then echo "pfwd-downmask-feed.service：已安装"; else echo "pfwd-downmask-feed.service：未安装"; fi
    if service_unit_exists pfwd-leaseweb.service; then echo "pfwd-leaseweb.service：已安装"; else echo "pfwd-leaseweb.service：未安装"; fi
    if [ -x "$PFWD_DOWNMASK_BIN_PATH" ]; then echo "pfwd-downmask：$PFWD_DOWNMASK_BIN_PATH"; else echo "pfwd-downmask：缺失"; fi
    if [ -x "$PFWD_LEASEWEB_BIN_PATH" ]; then echo "pfwd-leaseweb：$PFWD_LEASEWEB_BIN_PATH"; else echo "pfwd-leaseweb：缺失"; fi
    echo "转发数量：$(jq '.forwards | length' "$PFWD_CONFIG_FILE")"
    echo "用户数量：$(jq '.users | length' "$PFWD_CONFIG_FILE")"
    guard_render_status | while IFS=$'\t' read -r key value; do
        printf 'guard.%s：%s\n' "$key" "$value"
    done
    whitelist_render_status | while IFS=$'\t' read -r key value; do
        printf 'guard_whitelist.%s：%s\n' "$key" "$value"
    done
    egress_whitelist_render_status | while IFS=$'\t' read -r key value; do
        printf 'guard_egress_whitelist.%s：%s\n' "$key" "$value"
    done
    downmask_render_status | while IFS=$'\t' read -r key value; do
        printf 'downmask.%s：%s\n' "$key" "$value"
    done
    if [ "$include_bench" = "true" ]; then
        cmd_doctor_benchmarks
    else
        echo "benchmark：已省略（使用 pfwd doctor --bench 查看）"
    fi
}
