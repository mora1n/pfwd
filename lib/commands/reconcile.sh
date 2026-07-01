#!/usr/bin/env bash

cmd_reconcile() {
    config_init >/dev/null
    local before after now_minute need_full_refresh=false sent refresh_action="reuse"
    local domain_rules_present domain_refresh_interval domain_refresh_due=false
    local current_runtime_hash candidate_runtime candidate_runtime_hash
    if stats_apply_due_resets; then
        need_full_refresh=true
    fi
    now_minute="$(pfwd_now_minute)"
    before="$(jq '[.forwards[]? | select(.enabled == true)] | length' "$PFWD_CONFIG_FILE")"
    config_disable_expired "$now_minute"
    config_disable_telegram_for_expired_users "$now_minute"
    after="$(jq '[.forwards[]? | select(.enabled == true)] | length' "$PFWD_CONFIG_FILE")"
    if [ "$before" != "$after" ]; then
        need_full_refresh=true
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
    fi
    sent="$(notify_reconcile_schedules)"
    echo "已同步：active_before=$before active_after=$after refresh=$refresh_action notify_sent=$sent"
}
