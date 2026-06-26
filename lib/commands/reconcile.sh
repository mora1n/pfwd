#!/usr/bin/env bash

cmd_reconcile_lease_state() {
    local leases_json
    leases_json="$(whitelist_lease_entries_json)"
    printf '%s\t%s\n' "$(jq -r 'length' <<< "$leases_json")" "$(printf '%s' "$leases_json" | pfwd_stdin_checksum)"
}

cmd_reconcile() {
    config_init >/dev/null
    local before after now_minute need_full_refresh=false need_aux_refresh=false sent activity_json refresh_action="reuse"
    local leases_before leases_after leases_hash_before leases_hash_after lease_state forwarder_bin
    local domain_rules_present domain_refresh_interval domain_refresh_due=false
    local current_runtime_hash candidate_runtime candidate_runtime_hash
    if stats_apply_due_resets; then
        need_full_refresh=true
    fi
    now_minute="$(pfwd_now_minute)"
    before="$(jq '[.forwards[]? | select(.enabled == true)] | length' "$PFWD_CONFIG_FILE")"
    lease_state="$(cmd_reconcile_lease_state)"
    leases_before="${lease_state%%	*}"
    leases_hash_before="${lease_state##*	}"
    config_disable_expired "$now_minute"
    config_disable_telegram_for_expired_users "$now_minute"
    activity_json='[]'
    forwarder_bin="$(forwarder_bin_path)"
    if [ -x "$forwarder_bin" ] && [ -f "$PFWD_XDP_RULE_COUNTER_PIN_PATH" ]; then
        activity_json="$("$forwarder_bin" whitelist-lease-activity \
          --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" \
          --user-counter-pin "$PFWD_XDP_USER_COUNTER_PIN_PATH" \
          --stats-pin "$PFWD_XDP_STATS_PIN_PATH" 2>/dev/null || printf '[]')"
    fi
    whitelist_lease_reconcile_activity "$activity_json"
    lease_state="$(cmd_reconcile_lease_state)"
    leases_after="${lease_state%%	*}"
    leases_hash_after="${lease_state##*	}"
    after="$(jq '[.forwards[]? | select(.enabled == true)] | length' "$PFWD_CONFIG_FILE")"
    if [ "$before" != "$after" ]; then
        need_full_refresh=true
    elif [ "$leases_hash_before" != "$leases_hash_after" ]; then
        need_aux_refresh=true
    else
        domain_rules_present="$(forwarder_domain_rules_present)"
        domain_refresh_interval="$(forwarder_domain_refresh_interval_seconds)"
        if [ "$domain_rules_present" = "true" ] && forwarder_domain_refresh_due "$domain_refresh_interval"; then
            domain_refresh_due=true
        fi
        if [ "$domain_refresh_due" = "true" ]; then
            current_runtime_hash="$(forwarder_domain_refresh_hash_file)"
            candidate_runtime="$(forwarder_runtime_json true)"
            candidate_runtime_hash="$(forwarder_domain_refresh_hash_from_runtime_json "$candidate_runtime")"
            if [ -z "$current_runtime_hash" ] || [ "$candidate_runtime_hash" != "$current_runtime_hash" ]; then
                need_full_refresh=true
                refresh_action="domain"
            else
                forwarder_update_domain_refresh_metadata "$(pfwd_now_iso)" "$domain_refresh_interval" true
            fi
        elif [ "$domain_rules_present" = "true" ]; then
            forwarder_update_domain_refresh_metadata "$(forwarder_domain_refresh_last_checked_at)" "$domain_refresh_interval" true
        else
            forwarder_update_domain_refresh_metadata "$(forwarder_domain_refresh_last_checked_at)" "$domain_refresh_interval" false
        fi
    fi
    if [ "$need_full_refresh" = "true" ]; then
        stats_rollup_current
        cmd_apply_forwarding_bundle
        if [ "$refresh_action" != "domain" ]; then
            refresh_action="full"
        fi
        if [ "$refresh_action" = "domain" ]; then
            forwarder_update_domain_refresh_metadata "$(pfwd_now_iso)" "$domain_refresh_interval" true
        fi
    elif [ "$need_aux_refresh" = "true" ]; then
        whitelist_apply_runtime
        if service_runtime_installed; then
            stats_runtime_cache_clear
            runtime_apply_xdp_aux_runtime
            stats_runtime_cache_clear
            refresh_action="xdp-aux"
        else
            refresh_action="skipped"
        fi
    fi
    sent="$(notify_reconcile_schedules)"
    downmask_reconcile_pull 2>/dev/null || true
    echo "已同步：active_before=$before active_after=$after leases_before=$leases_before leases_after=$leases_after refresh=$refresh_action notify_sent=$sent"
}
