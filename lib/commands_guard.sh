#!/usr/bin/env bash

cmd_guard_compact_error() {
    local message="${1:-}"
    message="$(printf '%s' "$message" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//; s/^错误：[[:space:]]*//')"
    [ -n "$message" ] || message="未知错误"
    printf '%s\n' "$message"
}

cmd_guard_backup_file() {
    local source="$1" backup="$2"
    mkdir -p "$(dirname "$backup")"
    if [ -f "$source" ]; then
        cp "$source" "$backup"
    else
        : > "${backup}.missing"
    fi
}

cmd_guard_restore_file() {
    local target="$1" backup="$2"
    if [ -f "${backup}.missing" ]; then
        rm -f "$target"
        return 0
    fi
    if [ -f "$backup" ]; then
        mkdir -p "$(dirname "$target")"
        cp "$backup" "$target"
    else
        rm -f "$target"
    fi
}

cmd_guard_backup_state() {
    local backup_dir
    backup_dir="$(mktemp -d "${PFWD_RUN_DIR}/guard-apply.XXXXXX")"
    cmd_guard_backup_file "$PFWD_CONFIG_FILE" "$backup_dir/config.json"
    cmd_guard_backup_file "$PFWD_WHITELIST_LEASES_FILE" "$backup_dir/leases.json"
    cmd_guard_backup_file "$PFWD_WHITELIST_ALLOW_IPV4_FILE" "$backup_dir/allow_ipv4.txt"
    cmd_guard_backup_file "$PFWD_WHITELIST_ALLOW_IPV6_FILE" "$backup_dir/allow_ipv6.txt"
    cmd_guard_backup_file "${PFWD_WHITELIST_ALLOW_IPV4_FILE}.cn" "$backup_dir/allow_ipv4.cn"
    cmd_guard_backup_file "${PFWD_WHITELIST_ALLOW_IPV6_FILE}.cn" "$backup_dir/allow_ipv6.cn"
    cmd_guard_backup_file "$PFWD_WHITELIST_CITY_IPV4_FILE" "$backup_dir/city_ipv4.tsv"
    cmd_guard_backup_file "$PFWD_WHITELIST_TEMP_ALLOW_IPV4_FILE" "$backup_dir/temp_allow_ipv4.txt"
    cmd_guard_backup_file "$PFWD_WHITELIST_TEMP_ALLOW_IPV6_FILE" "$backup_dir/temp_allow_ipv6.txt"
    cmd_guard_backup_file "$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV4_FILE" "$backup_dir/egress_host_allow_ipv4.txt"
    cmd_guard_backup_file "$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV6_FILE" "$backup_dir/egress_host_allow_ipv6.txt"
    cmd_guard_backup_file "$PFWD_FORWARDER_RUNTIME_FILE" "$backup_dir/runtime.json"
    cmd_guard_backup_file "$PFWD_FORWARDER_XDP_RUNTIME_FILE" "$backup_dir/runtime.xdp.json"
    cmd_guard_backup_file "$PFWD_XDP_STATUS_FILE" "$backup_dir/xdp.status.json"
    cmd_guard_backup_file "$PFWD_FORWARDER_STATUS_FILE" "$backup_dir/forwarder.status.json"
    printf '%s\n' "$backup_dir"
}

cmd_guard_restore_state() {
    local backup_dir="$1"
    cmd_guard_restore_file "$PFWD_CONFIG_FILE" "$backup_dir/config.json"
    cmd_guard_restore_file "$PFWD_WHITELIST_LEASES_FILE" "$backup_dir/leases.json"
    cmd_guard_restore_file "$PFWD_WHITELIST_ALLOW_IPV4_FILE" "$backup_dir/allow_ipv4.txt"
    cmd_guard_restore_file "$PFWD_WHITELIST_ALLOW_IPV6_FILE" "$backup_dir/allow_ipv6.txt"
    cmd_guard_restore_file "${PFWD_WHITELIST_ALLOW_IPV4_FILE}.cn" "$backup_dir/allow_ipv4.cn"
    cmd_guard_restore_file "${PFWD_WHITELIST_ALLOW_IPV6_FILE}.cn" "$backup_dir/allow_ipv6.cn"
    cmd_guard_restore_file "$PFWD_WHITELIST_CITY_IPV4_FILE" "$backup_dir/city_ipv4.tsv"
    cmd_guard_restore_file "$PFWD_WHITELIST_TEMP_ALLOW_IPV4_FILE" "$backup_dir/temp_allow_ipv4.txt"
    cmd_guard_restore_file "$PFWD_WHITELIST_TEMP_ALLOW_IPV6_FILE" "$backup_dir/temp_allow_ipv6.txt"
    cmd_guard_restore_file "$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV4_FILE" "$backup_dir/egress_host_allow_ipv4.txt"
    cmd_guard_restore_file "$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV6_FILE" "$backup_dir/egress_host_allow_ipv6.txt"
    cmd_guard_restore_file "$PFWD_FORWARDER_RUNTIME_FILE" "$backup_dir/runtime.json"
    cmd_guard_restore_file "$PFWD_FORWARDER_XDP_RUNTIME_FILE" "$backup_dir/runtime.xdp.json"
    cmd_guard_restore_file "$PFWD_XDP_STATUS_FILE" "$backup_dir/xdp.status.json"
    cmd_guard_restore_file "$PFWD_FORWARDER_STATUS_FILE" "$backup_dir/forwarder.status.json"
}

cmd_guard_cleanup_state_backup() {
    local backup_dir="$1"
    rm -rf "$backup_dir"
}

cmd_guard_prepare_aux_runtime() {
    local scope="$1"
    case "$scope" in
        ingress) whitelist_apply_runtime ;;
        egress)
            egress_whitelist_apply_runtime
            if ! egress_whitelist_validate_config_file "$PFWD_CONFIG_FILE"; then
                pfwd_die "$EGRESS_WHITELIST_LAST_ERROR"
            fi
            ;;
        both)
            whitelist_apply_runtime
            egress_whitelist_apply_runtime
            if ! egress_whitelist_validate_config_file "$PFWD_CONFIG_FILE"; then
                pfwd_die "$EGRESS_WHITELIST_LAST_ERROR"
            fi
            ;;
        none) : ;;
        *) pfwd_die "未知 guard aux scope：$scope" ;;
    esac
}

cmd_guard_mutate_and_apply_aux() {
    local scope="$1"
    local mutation_fn="$2"
    local label="$3"
    local backup_dir mutation_output apply_output rollback_output
    shift 3

    backup_dir="$(cmd_guard_backup_state)"
    if ! mutation_output="$("$mutation_fn" "$@" 2>&1)"; then
        cmd_guard_cleanup_state_backup "$backup_dir"
        pfwd_die "$(cmd_guard_compact_error "$mutation_output")"
    fi
    if ! apply_output="$(cmd_guard_prepare_aux_runtime "$scope" 2>&1)"; then
        cmd_guard_restore_state "$backup_dir"
        cmd_guard_cleanup_state_backup "$backup_dir"
        pfwd_die "$label 运行态预处理失败，已回滚：$(cmd_guard_compact_error "$apply_output")"
    fi

    stats_runtime_cache_clear
    if ! cmd_runtime_ready; then
        cmd_guard_cleanup_state_backup "$backup_dir"
        return 0
    fi
    if apply_output="$(runtime_apply_xdp_aux_runtime 2>&1)"; then
        stats_runtime_cache_clear
        cmd_guard_cleanup_state_backup "$backup_dir"
        return 0
    fi

    stats_runtime_cache_clear
    cmd_guard_restore_state "$backup_dir"
    if rollback_output="$(runtime_apply_xdp_aux_runtime 2>&1)"; then
        stats_runtime_cache_clear
        cmd_guard_cleanup_state_backup "$backup_dir"
        pfwd_die "$label 增量应用失败，已回滚到变更前状态；未尝试全量 apply：$(cmd_guard_compact_error "$apply_output")"
    fi

    stats_runtime_cache_clear
    cmd_guard_restore_state "$backup_dir"
    cmd_guard_cleanup_state_backup "$backup_dir"
    pfwd_die "$label 增量应用失败，且回滚重新应用也失败；未尝试全量 apply，请视情况手动执行 pfwd restart。原始错误：$(cmd_guard_compact_error "$apply_output")；回滚错误：$(cmd_guard_compact_error "$rollback_output")"
}

cmd_guard_finish_aux_mutation() {
    local scope="$1"
    local label="$2"
    local backup_dir="$3"
    local apply_output rollback_output

    if ! apply_output="$(cmd_guard_prepare_aux_runtime "$scope" 2>&1)"; then
        cmd_guard_restore_state "$backup_dir"
        cmd_guard_cleanup_state_backup "$backup_dir"
        pfwd_die "$label 运行态预处理失败，已回滚：$(cmd_guard_compact_error "$apply_output")"
    fi

    stats_runtime_cache_clear
    if ! cmd_runtime_ready; then
        cmd_guard_cleanup_state_backup "$backup_dir"
        return 0
    fi
    if apply_output="$(runtime_apply_xdp_aux_runtime 2>&1)"; then
        stats_runtime_cache_clear
        cmd_guard_cleanup_state_backup "$backup_dir"
        return 0
    fi

    stats_runtime_cache_clear
    cmd_guard_restore_state "$backup_dir"
    if rollback_output="$(runtime_apply_xdp_aux_runtime 2>&1)"; then
        stats_runtime_cache_clear
        cmd_guard_cleanup_state_backup "$backup_dir"
        pfwd_die "$label 增量应用失败，已回滚到变更前状态；未尝试全量 apply：$(cmd_guard_compact_error "$apply_output")"
    fi

    stats_runtime_cache_clear
    cmd_guard_restore_state "$backup_dir"
    cmd_guard_cleanup_state_backup "$backup_dir"
    pfwd_die "$label 增量应用失败，且回滚重新应用也失败；未尝试全量 apply，请视情况手动执行 pfwd restart。原始错误：$(cmd_guard_compact_error "$apply_output")；回滚错误：$(cmd_guard_compact_error "$rollback_output")"
}

cmd_guard_whitelist_lease_mutate_and_apply() {
    local mutation_fn="$1"
    shift
    cmd_guard_mutate_and_apply_aux ingress "$mutation_fn" "入口临时白名单" "$@"
}

