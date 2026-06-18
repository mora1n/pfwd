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

cmd_guard() {
    config_init >/dev/null
    local sub="${1:-status}"
    shift || true
    case "$sub" in
        enable)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard enable"
            guard_config_set_enabled true
            cmd_apply_guard_runtime
            echo "guard 已启用"
            ;;
        disable)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard disable"
            guard_config_set_enabled false
            cmd_apply_guard_runtime
            echo "guard 已停用"
            ;;
        apply)
            local quiet="false"
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --quiet) quiet="true"; shift ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            cmd_apply_guard_runtime
            ;;
        remove)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard remove"
            guard_config_set_enabled false
            cmd_apply_guard_runtime
            echo "guard 已移除"
            ;;
        status)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard status"
            guard_render_status
            ;;
        protocols)
            local http="__KEEP__" https="__KEEP__" tls="__KEEP__" socks="__KEEP__"
            local skip_port="" replace_skip_ports="false" clear_skip_ports="false" tmp_ports skip_ports_input=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --http) http="${2:-}"; shift 2 ;;
                    --https) https="${2:-}"; shift 2 ;;
                    --tls) tls="${2:-}"; shift 2 ;;
                    --socks) socks="${2:-}"; shift 2 ;;
                    --skip-port)
                        skip_port="${2:-}"
                        shift 2
                        [ -n "$skip_port" ] || pfwd_die "缺少 --skip-port 值"
                        skip_ports_input+=$'\n'"$skip_port"
                        ;;
                    --replace-skip-ports) replace_skip_ports="true"; shift ;;
                    --clear-skip-ports) clear_skip_ports="true"; shift ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ "$http" = "__KEEP__" ] || validate_bool "$http"
            [ "$https" = "__KEEP__" ] || validate_bool "$https"
            [ "$tls" = "__KEEP__" ] || validate_bool "$tls"
            [ "$socks" = "__KEEP__" ] || validate_bool "$socks"
            if [ -n "$skip_ports_input" ]; then
                while IFS= read -r skip_port; do
                    [ -n "$skip_port" ] || continue
                    while IFS= read -r expanded_port; do
                        [ -n "$expanded_port" ] || continue
                        validate_port "$expanded_port"
                    done < <(expand_port_spec "$skip_port")
                done <<< "$skip_ports_input"
            fi
            if [ "$https" != "__KEEP__" ]; then
                http="$https"
                tls="$https"
            fi
            [ "$http" = "__KEEP__" ] && http="$(guard_block_http)"
            [ "$tls" = "__KEEP__" ] && tls="$(guard_block_tls)"
            [ "$socks" = "__KEEP__" ] && socks="$(guard_block_socks)"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            guard_config_set_protocols "$http" "$tls" "$socks"
            tmp_ports="$(mktemp)"
            if [ "$clear_skip_ports" != "true" ]; then
                if [ "$replace_skip_ports" != "true" ]; then
                    guard_protocol_skip_ports_tsv > "$tmp_ports"
                fi
                if [ -n "$skip_ports_input" ]; then
                    while IFS= read -r skip_port; do
                        [ -n "$skip_port" ] || continue
                        expand_port_spec "$skip_port" >> "$tmp_ports"
                    done <<< "$skip_ports_input"
                fi
            fi
            guard_config_set_protocol_skip_ports "$tmp_ports"
            rm -f "$tmp_ports"
            cmd_guard_finish_aux_mutation none "guard 配置" "$backup_dir"
            echo "guard 配置已更新"
            ;;
        whitelist)
            cmd_guard_whitelist "$@"
            ;;
        whitelist-cn)
            cmd_guard_whitelist_cn "$@"
            ;;
        whitelist-city)
            cmd_guard_whitelist_city "$@"
            ;;
        whitelist-port)
            cmd_guard_whitelist_port "$@"
            ;;
        whitelist-port-cn)
            cmd_guard_whitelist_port_cn "$@"
            ;;
        whitelist-port-city)
            cmd_guard_whitelist_port_city "$@"
            ;;
        whitelist-custom)
            cmd_guard_whitelist_custom "$@"
            ;;
        whitelist-lease)
            cmd_guard_whitelist_lease "$@"
            ;;
        egress-whitelist)
            cmd_guard_egress_whitelist "$@"
            ;;
        egress-whitelist-cn)
            cmd_guard_egress_whitelist_cn "$@"
            ;;
        egress-whitelist-custom)
            cmd_guard_egress_whitelist_custom "$@"
            ;;
        *)
            pfwd_die "用法：pfwd guard enable|disable|status|apply|remove|protocols|whitelist|whitelist-cn|whitelist-city|whitelist-port|whitelist-port-cn|whitelist-port-city|whitelist-custom|whitelist-lease|egress-whitelist|egress-whitelist-cn|egress-whitelist-custom"
            ;;
    esac
}


cmd_guard_whitelist() {
    config_init >/dev/null
    if [ "${1:-}" = "check" ]; then
        shift
        cmd_guard_whitelist_check "$@"
        return 0
    fi
    local enabled="__KEEP__" include_cn="__KEEP__" cidr="" replace_custom="false" clear_custom="false"
    local cn_mode="__KEEP__"
    local status_requested="false"
    local tmp_cidrs current_cidrs

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --enabled) enabled="${2:-}"; shift 2 ;;
            --include-cn) include_cn="${2:-}"; shift 2 ;;
            --cn-mode) cn_mode="${2:-}"; shift 2 ;;
            --cidr) cidr="${2:-}"; shift 2 ;;
            --replace-custom) replace_custom="true"; shift ;;
            --clear-custom) clear_custom="true"; shift ;;
            status) status_requested="true"; shift ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done

    if [ "$status_requested" = "true" ] && [ "$enabled" = "__KEEP__" ] && [ "$include_cn" = "__KEEP__" ] && [ "$cn_mode" = "__KEEP__" ] && [ -z "$cidr" ] && [ "$clear_custom" = "false" ]; then
        whitelist_render_status
        return 0
    fi

    [ "$enabled" = "__KEEP__" ] || validate_bool "$enabled"
    [ "$include_cn" = "__KEEP__" ] || validate_bool "$include_cn"
    if [ "$cn_mode" != "__KEEP__" ]; then
        whitelist_validate_cn_mode "$cn_mode"
    fi
    if [ -n "$cidr" ]; then
        cidr="$(normalize_ip_or_cidr "$cidr")"
    fi

    if [ "$enabled" = "__KEEP__" ]; then
        enabled="$(whitelist_enabled)"
    fi
    if [ "$include_cn" = "__KEEP__" ]; then
        :
    elif [ "$cn_mode" = "__KEEP__" ]; then
        if [ "$include_cn" = "true" ]; then
            cn_mode="all"
        else
            cn_mode="off"
        fi
    fi
    if [ "$cn_mode" = "__KEEP__" ]; then
        cn_mode="$(whitelist_cn_mode)"
    fi
    local backup_dir
    backup_dir="$(cmd_guard_backup_state)"
    whitelist_config_set_state "$enabled" "$cn_mode"

    tmp_cidrs="$(mktemp)"
    if [ "$clear_custom" != "true" ]; then
        if [ "$replace_custom" != "true" ]; then
            whitelist_custom_cidrs_tsv > "$tmp_cidrs"
        fi
        if [ -n "$cidr" ]; then
            printf '%s\n' "$cidr" >> "$tmp_cidrs"
        fi
    fi
    whitelist_config_set_custom_cidrs "$tmp_cidrs"
    rm -f "$tmp_cidrs"

    cmd_guard_finish_aux_mutation ingress "协议封锁 / 入口白名单" "$backup_dir"
    echo "协议封锁 / 入口白名单已更新"
}


cmd_guard_whitelist_check() {
    config_init >/dev/null
    local address="" listen_port="" protocol=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --address)
                address="${2:-}"
                shift 2
                ;;
            --listen-port)
                listen_port="${2:-}"
                shift 2
                ;;
            --protocol)
                protocol="${2:-}"
                shift 2
                ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -n "$address" ] || pfwd_die "用法：pfwd guard whitelist check --address IP [--listen-port PORT] [--protocol tcp|udp]"
    if [ -n "$listen_port" ]; then
        validate_port "$listen_port"
    fi
    case "$protocol" in
        ""|tcp|udp) ;;
        *) pfwd_die "无效协议：$protocol，必须是 tcp 或 udp" ;;
    esac

    local mode provinces files city_file bin output geo_status geo_error_file geo_error policy_source city_codes_json tmp_codes_file tmp_city_file
    mode="$(whitelist_effective_cn_mode_for_port "$listen_port")"
    provinces="$(whitelist_effective_cn_provinces_tsv_for_port "$listen_port" | paste -sd, -)"
    files="$(whitelist_allow_ipv4_file):$(whitelist_allow_ipv6_file)"
    city_file=""
    policy_source="$(if [ -n "$listen_port" ]; then whitelist_effective_policy_source_for_port "$listen_port"; else printf '全局默认'; fi)"
    city_codes_json="$(whitelist_effective_cn_city_codes_json_for_port "$listen_port")"
    bin="$(guard_bin_path)"
    [ -x "$bin" ] || pfwd_die "缺少 XDP 预编译二进制：$bin"
    if [ "$(jq -r 'length' <<< "$city_codes_json")" -gt 0 ]; then
        tmp_codes_file="$(mktemp)"
        tmp_city_file="$(mktemp)"
        jq -r '.[]' <<< "$city_codes_json" > "$tmp_codes_file"
        if ! "$bin" city-export \
          --asset-dir "$(whitelist_geo_asset_dir)" \
          --codes-file "$tmp_codes_file" > "$tmp_city_file"; then
            rm -f "$tmp_codes_file" "$tmp_city_file"
            pfwd_die "导出端口市白名单失败"
        fi
        city_file="$tmp_city_file"
    fi

    geo_error_file="$(mktemp)"
    if output="$("$bin" geo-check \
        --json \
        --asset-dir "$(whitelist_geo_asset_dir)" \
        --address "$address" \
        --mode "$mode" \
        --provinces "$provinces" \
        --city-file "$city_file" \
        --whitelist-file "$files" 2>"$geo_error_file")"; then
        geo_status=0
    else
        geo_status=$?
    fi
    geo_error="$(cat "$geo_error_file")"
    rm -f "$geo_error_file" "${tmp_codes_file:-}" "${tmp_city_file:-}"
    [ -n "$output" ] || pfwd_die "geo-check 未返回结果：$geo_error"
    jq -e . >/dev/null <<< "$output" || pfwd_die "geo-check 返回非 JSON：$output ${geo_error:+($geo_error)}"

    local wl_enabled skip_hit="false" rule_summary="-" rule_id="-" rule_flags="-" conclusion reason
    wl_enabled="$(whitelist_enabled)"
    if [ -n "$listen_port" ]; then
        if guard_protocol_skip_ports_tsv | grep -Fxq "$listen_port"; then
            skip_hit="true"
        fi
        if [ -f "$PFWD_FORWARDER_RUNTIME_FILE" ]; then
            if [ -n "$protocol" ]; then
                rule_summary="$(jq -r --argjson port "$listen_port" --arg proto "$protocol" '
                  (.rules // [])
                  | map(select((.listen_port // 0) == $port and (.protocol // "") == $proto and (.enabled // true)))
                  | first
                  | if . == null then "-" else
                      [(.id // "-"), (.protocol // "-"), ((.listen_ip // "::") + ":" + ((.listen_port // 0) | tostring)), ((.remote_host // "-") + ":" + ((.remote_port // 0) | tostring)), (.execution_class // "-")] | @tsv
                    end
                ' "$PFWD_FORWARDER_RUNTIME_FILE")"
            else
                rule_summary="$(jq -r --argjson port "$listen_port" '
                  (.rules // [])
                  | map(select((.listen_port // 0) == $port and (.enabled // true)))
                  | first
                  | if . == null then "-" else
                      [(.id // "-"), (.protocol // "-"), ((.listen_ip // "::") + ":" + ((.listen_port // 0) | tostring)), ((.remote_host // "-") + ":" + ((.remote_port // 0) | tostring)), (.execution_class // "-")] | @tsv
                    end
                ' "$PFWD_FORWARDER_RUNTIME_FILE")"
            fi
        fi
    fi

    local geo_allowed custom_allowed city_allowed allowed province matched_source city_label temp_lease_allowed="false" temp_lease_json="" temp_lease_cidr="-"
    geo_allowed="$(jq -r '.geo_allowed' <<< "$output")"
    custom_allowed="$(jq -r '.custom_allowed' <<< "$output")"
    city_allowed="$(jq -r '.city_allowed // false' <<< "$output")"
    allowed="$(jq -r '.allowed' <<< "$output")"
    province="$(jq -r '.province // "-"' <<< "$output")"
    matched_source="$(jq -r '.matched_source' <<< "$output")"
    city_label="$(jq -r 'if ((.city_province // "") != "") and ((.city // "") != "") then (.city_province + "/" + .city) else "-" end' <<< "$output")"
    temp_lease_json="$(whitelist_lease_find_by_address_json "$address")"
    if [ -n "$temp_lease_json" ]; then
        temp_lease_allowed="true"
        temp_lease_cidr="$(jq -r '.cidr // "-"' <<< "$temp_lease_json")"
    fi

    if [ "$skip_hit" = "true" ]; then
        conclusion="放行"
        reason="命中入口防护跳过端口；该监听端口跳过入口白名单和协议封锁"
    elif [ "$wl_enabled" != "true" ]; then
        conclusion="放行"
        reason="入口白名单未启用"
    elif [ "$temp_lease_allowed" = "true" ]; then
        conclusion="放行"
        reason="命中入口临时白名单租约：$temp_lease_cidr"
    elif [ "$allowed" = "true" ]; then
        conclusion="放行"
        if [ "$city_allowed" = "true" ]; then
            reason="命中入口市白名单：$city_label"
        elif [ "$custom_allowed" = "true" ]; then
            reason="命中入口自定义 CIDR"
        else
            reason="命中国内 IP 策略"
        fi
    else
        conclusion="应拦截"
        case "$matched_source" in
            province-deny) reason="省份未授权：$province" ;;
            not-cn) reason="未命中国内 IP 资产或自定义 CIDR" ;;
            mode-off) reason="国内 IP 策略已关闭且未命中自定义 CIDR" ;;
            *) reason="未命中入口白名单" ;;
        esac
    fi

    if [ "$rule_summary" != "-" ]; then
        rule_id="$(cut -f1 <<< "$rule_summary")"
        rule_flags="$(cut -f2- <<< "$rule_summary")"
    fi

    printf '地址\t%s\n' "$address"
    printf '省份\t%s\n' "$province"
    printf '城市\t%s\n' "$city_label"
    printf '入口白名单\t%s\n' "$(if [ "$wl_enabled" = "true" ]; then printf '开'; else printf '关'; fi)"
    printf '临时白名单\t%s\n' "$(if [ "$temp_lease_allowed" = "true" ]; then printf '命中'; else printf '未命中'; fi)"
    printf '临时白名单范围\t%s\n' "$temp_lease_cidr"
    printf '策略来源\t%s\n' "$policy_source"
    printf '国内 IP 策略\t%s\n' "$(if [ -n "$listen_port" ]; then whitelist_effective_cn_selection_summary_for_port "$listen_port"; else whitelist_cn_selection_summary; fi)"
    printf '市白名单\t%s\n' "$(if [ -n "$listen_port" ]; then whitelist_effective_city_selection_summary_for_port "$listen_port"; else whitelist_city_selection_summary; fi)"
    if [ -n "$listen_port" ]; then
        printf '监听端口\t%s%s\n' "$listen_port" "$(if [ -n "$protocol" ]; then printf '/%s' "$protocol"; fi)"
        printf '入口防护跳过\t%s\n' "$(if [ "$skip_hit" = "true" ]; then printf '是'; else printf '否'; fi)"
        printf '运行态规则\t%s\n' "$rule_id"
        printf '规则详情\t%s\n' "$rule_flags"
    fi
    printf 'geo-check\t%s\n' "$(if [ "$geo_status" -eq 0 ]; then printf 'allow'; else printf 'deny'; fi)"
    printf '结论\t%s\n' "$conclusion"
    printf '原因\t%s\n' "$reason"
}


cmd_guard_whitelist_lease() {
    config_init >/dev/null
    local sub="${1:-status}"
    shift || true
    case "$sub" in
        list)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-lease list"
            whitelist_lease_list_rows
            ;;
        status)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-lease status"
            whitelist_lease_status_json | jq '.'
            ;;
        add)
            local address="" idle_ttl_raw="30m" idle_ttl_sec note="" channel="manual" ipv4_prefix_len="32" ipv6_prefix_len="128"
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --address) address="${2:-}"; shift 2 ;;
                    --idle-ttl) idle_ttl_raw="${2:-}"; shift 2 ;;
                    --note) note="${2:-}"; shift 2 ;;
                    --channel) channel="${2:-}"; shift 2 ;;
                    --ipv4-prefix-len) ipv4_prefix_len="${2:-}"; shift 2 ;;
                    --ipv6-prefix-len) ipv6_prefix_len="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$address" ] || pfwd_die "用法：pfwd guard whitelist-lease add --address IP [--ipv4-prefix-len N] [--ipv6-prefix-len N] [--idle-ttl 30m|2h|1d] [--note TEXT] [--channel web|manual|ssh]"
            case "$channel" in
                web|manual|ssh) ;;
                *) pfwd_die "无效 channel：$channel；必须是 web/manual/ssh" ;;
            esac
            idle_ttl_sec="$(pfwd_parse_duration_seconds "$idle_ttl_raw")"
            local lease_cidr
            lease_cidr="$(whitelist_normalize_lease_cidr "$address" "$ipv4_prefix_len" "$ipv6_prefix_len")"
            cmd_guard_whitelist_lease_mutate_and_apply whitelist_lease_upsert "$address" "$idle_ttl_sec" "$note" "$channel" "$ipv4_prefix_len" "$ipv6_prefix_len"
            echo "入口临时白名单已添加：$lease_cidr idle_ttl=$(pfwd_format_duration_seconds "$idle_ttl_sec")"
            ;;
        delete)
            local address="" indexes=()
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --address) address="${2:-}"; shift 2 ;;
                    *)
                        indexes+=("$1")
                        shift
                        ;;
                esac
            done
            if [ -n "$address" ]; then
                cmd_guard_whitelist_lease_mutate_and_apply whitelist_lease_delete_by_address "$address"
            elif [ "${#indexes[@]}" -gt 0 ]; then
                cmd_guard_whitelist_lease_mutate_and_apply whitelist_lease_delete_by_indexes "$(printf '%s\n' "${indexes[@]}")"
            else
                pfwd_die "用法：pfwd guard whitelist-lease delete <index...>|--address IP"
            fi
            echo "入口临时白名单已删除"
            ;;
        clear)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-lease clear"
            cmd_guard_whitelist_lease_mutate_and_apply whitelist_lease_clear_all
            echo "入口临时白名单已清空"
            ;;
        *)
            pfwd_die "用法：pfwd guard whitelist-lease list|status|add|delete|clear"
            ;;
    esac
}


cmd_guard_whitelist_city() {
    config_init >/dev/null
    local sub="${1:-status}"
    shift || true
    case "$sub" in
        list)
            case "$#" in
                0)
                    whitelist_city_available_province_rows
                    ;;
                1)
                    local province_code
                    province_code="$(whitelist_city_province_code_by_selector "$1")"
                    whitelist_city_rows_by_province_code "$province_code"
                    ;;
                *)
                    pfwd_die "用法：pfwd guard whitelist-city list [省份序号|省份名|省份code]"
                    ;;
            esac
            ;;
        status)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-city status"
            whitelist_city_selected_rows
            ;;
        add)
            [ "$#" -ge 2 ] || pfwd_die "用法：pfwd guard whitelist-city add <省份序号|省份名|省份code> <城市序号|城市名|城市code...>"
            local province_selector="$1" city_selector code tmp backup_dir
            shift
            backup_dir="$(cmd_guard_backup_state)"
            tmp="$(mktemp)"
            whitelist_cn_city_codes_tsv > "$tmp"
            for city_selector in "$@"; do
                code="$(whitelist_city_code_by_selector "$province_selector" "$city_selector")"
                printf '%s\n' "$code" >> "$tmp"
            done
            whitelist_config_set_city_codes "$tmp"
            rm -f "$tmp"
            cmd_guard_finish_aux_mutation ingress "入口市白名单" "$backup_dir"
            echo "入口市白名单已更新"
            ;;
        delete)
            [ "$#" -ge 1 ] || pfwd_die "用法：pfwd guard whitelist-city delete <index...>"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_delete_city_codes_by_indexes "$(printf '%s\n' "$@")"
            cmd_guard_finish_aux_mutation ingress "入口市白名单" "$backup_dir"
            echo "入口市白名单已删除"
            ;;
        clear)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-city clear"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_clear_city_codes
            cmd_guard_finish_aux_mutation ingress "入口市白名单" "$backup_dir"
            echo "入口市白名单已清空"
            ;;
        *)
            pfwd_die "用法：pfwd guard whitelist-city list|status|add|delete|clear"
            ;;
    esac
}


cmd_guard_whitelist_port() {
    config_init >/dev/null
    local sub="${1:-list}"
    shift || true
    case "$sub" in
        list)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-port list"
            whitelist_port_policy_rows
            ;;
        status)
            local listen_port=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --listen-port) listen_port="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$listen_port" ] || pfwd_die "用法：pfwd guard whitelist-port status --listen-port PORT"
            validate_port "$listen_port"
            local status_json
            status_json="$(whitelist_port_policy_status_json "$listen_port")"
            jq -r '
              [
                ["监听端口", (.listen_port | tostring)],
                ["策略来源", .source],
                ["国内 IP 策略", .cn_summary],
                ["市白名单", .city_summary]
              ] | map(@tsv) | .[]
            ' <<< "$status_json"
            ;;
        clear)
            local listen_port=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --listen-port) listen_port="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$listen_port" ] || pfwd_die "用法：pfwd guard whitelist-port clear --listen-port PORT"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_clear_port_policy "$listen_port"
            cmd_guard_finish_aux_mutation ingress "入口白名单端口覆盖" "$backup_dir"
            echo "入口白名单端口覆盖已清除：$listen_port"
            ;;
        *)
            pfwd_die "用法：pfwd guard whitelist-port list|status|clear"
            ;;
    esac
}


cmd_guard_whitelist_port_cn() {
    config_init >/dev/null
    local listen_port="" sub=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --listen-port) listen_port="${2:-}"; shift 2 ;;
            all|off|select)
                sub="$1"
                shift
                break
                ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -n "$listen_port" ] || pfwd_die "用法：pfwd guard whitelist-port-cn --listen-port PORT all|off|select <省份...>"
    validate_port "$listen_port"
    case "$sub" in
        all)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-port-cn --listen-port PORT all"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_config_apply_port_cn_selection "$listen_port" all
            cmd_guard_finish_aux_mutation ingress "入口白名单端口 $listen_port 国内策略" "$backup_dir"
            echo "入口白名单端口 $listen_port 国内策略已更新为：国内IP"
            ;;
        off)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-port-cn --listen-port PORT off"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_config_apply_port_cn_selection "$listen_port" off
            cmd_guard_finish_aux_mutation ingress "入口白名单端口 $listen_port 国内策略" "$backup_dir"
            echo "入口白名单端口 $listen_port 国内策略已关闭"
            ;;
        select)
            [ "$#" -ge 1 ] || pfwd_die "用法：pfwd guard whitelist-port-cn --listen-port PORT select <省份...>"
            local tmp backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            tmp="$(mktemp)"
            printf '%s\n' "$@" > "$tmp"
            whitelist_config_apply_port_cn_selection "$listen_port" provinces "$tmp"
            rm -f "$tmp"
            cmd_guard_finish_aux_mutation ingress "入口白名单端口 $listen_port 国内策略" "$backup_dir"
            echo "入口白名单端口 $listen_port 国内策略已更新为省份选择"
            ;;
        *)
            pfwd_die "用法：pfwd guard whitelist-port-cn --listen-port PORT all|off|select <省份...>"
            ;;
    esac
}


cmd_guard_whitelist_port_city() {
    config_init >/dev/null
    local listen_port="" sub=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --listen-port) listen_port="${2:-}"; shift 2 ;;
            list|status|add|delete|clear)
                sub="$1"
                shift
                break
                ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -n "$listen_port" ] || pfwd_die "用法：pfwd guard whitelist-port-city --listen-port PORT list|status|add|delete|clear"
    validate_port "$listen_port"
    case "${sub:-status}" in
        list)
            case "$#" in
                0)
                    whitelist_city_available_province_rows
                    ;;
                1)
                    local province_code
                    province_code="$(whitelist_city_province_code_by_selector "$1")"
                    whitelist_city_rows_by_province_code "$province_code"
                    ;;
                *)
                    pfwd_die "用法：pfwd guard whitelist-port-city --listen-port PORT list [省份序号|省份名|省份code]"
                    ;;
            esac
            ;;
        status)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-port-city --listen-port PORT status"
            whitelist_city_selected_rows_from_codes_json "$(whitelist_effective_cn_city_codes_json_for_port "$listen_port")"
            ;;
        add)
            [ "$#" -ge 2 ] || pfwd_die "用法：pfwd guard whitelist-port-city --listen-port PORT add <省份序号|省份名|省份code> <城市序号|城市名|城市code...>"
            local province_selector="$1" city_selector code tmp backup_dir
            shift
            backup_dir="$(cmd_guard_backup_state)"
            tmp="$(mktemp)"
            whitelist_effective_cn_city_codes_tsv_for_port "$listen_port" > "$tmp"
            for city_selector in "$@"; do
                code="$(whitelist_city_code_by_selector "$province_selector" "$city_selector")"
                printf '%s\n' "$code" >> "$tmp"
            done
            whitelist_config_set_port_city_codes "$listen_port" "$tmp"
            rm -f "$tmp"
            cmd_guard_finish_aux_mutation ingress "入口白名单端口 $listen_port 市白名单" "$backup_dir"
            echo "入口白名单端口 $listen_port 市白名单已更新"
            ;;
        delete)
            [ "$#" -ge 1 ] || pfwd_die "用法：pfwd guard whitelist-port-city --listen-port PORT delete <index...>"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_delete_port_city_codes_by_indexes "$listen_port" "$(printf '%s\n' "$@")"
            cmd_guard_finish_aux_mutation ingress "入口白名单端口 $listen_port 市白名单" "$backup_dir"
            echo "入口白名单端口 $listen_port 市白名单已删除"
            ;;
        clear)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-port-city --listen-port PORT clear"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_clear_port_city_codes "$listen_port"
            cmd_guard_finish_aux_mutation ingress "入口白名单端口 $listen_port 市白名单" "$backup_dir"
            echo "入口白名单端口 $listen_port 市白名单已清空"
            ;;
        *)
            pfwd_die "用法：pfwd guard whitelist-port-city --listen-port PORT list|status|add|delete|clear"
            ;;
    esac
}


cmd_guard_whitelist_custom() {
    config_init >/dev/null
    local sub="${1:-}"
    shift || true
    case "$sub" in
        list)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-custom list"
            whitelist_custom_cidrs_tsv
            ;;
        add)
            local cidr="${1:-}" backup_dir
            [ -n "$cidr" ] || pfwd_die "用法：pfwd guard whitelist-custom add <IPv4/IPv6 CIDR 或单个 IP>"
            cidr="$(normalize_ip_or_cidr "$cidr")"
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_append_custom_cidr "$cidr"
            cmd_guard_finish_aux_mutation ingress "入口白名单自定义 CIDR" "$backup_dir"
            echo "入口白名单自定义 CIDR 已添加：$cidr"
            ;;
        clear)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-custom clear"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_clear_custom_cidrs
            cmd_guard_finish_aux_mutation ingress "入口白名单自定义 CIDR" "$backup_dir"
            echo "入口白名单自定义 CIDR 已清空"
            ;;
        delete)
            [ "$#" -ge 1 ] || pfwd_die "用法：pfwd guard whitelist-custom delete <index...>"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_delete_custom_cidrs_by_indexes "$(printf '%s\n' "$@")"
            cmd_guard_finish_aux_mutation ingress "入口白名单自定义 CIDR" "$backup_dir"
            echo "入口白名单自定义 CIDR 已删除"
            ;;
        update)
            local index="${1:-}" cidr="${2:-}" backup_dir
            [ -n "$index" ] && [ -n "$cidr" ] || pfwd_die "用法：pfwd guard whitelist-custom update <index> <IPv4/IPv6 CIDR 或单个 IP>"
            cidr="$(normalize_ip_or_cidr "$cidr")"
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_replace_custom_cidr_by_index "$index" "$cidr"
            cmd_guard_finish_aux_mutation ingress "入口白名单自定义 CIDR" "$backup_dir"
            echo "入口白名单自定义 CIDR 已更新：$index -> $cidr"
            ;;
        *)
            pfwd_die "用法：pfwd guard whitelist-custom list|add|clear|delete|update"
            ;;
    esac
}


cmd_guard_egress_whitelist() {
    config_init >/dev/null
    local enabled="__KEEP__" include_cn="__KEEP__" cidr="" replace_custom="false" clear_custom="false"
    local cn_mode="__KEEP__"
    local status_requested="false"
    local tmp_cidrs

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --enabled) enabled="${2:-}"; shift 2 ;;
            --include-cn) include_cn="${2:-}"; shift 2 ;;
            --cn-mode) cn_mode="${2:-}"; shift 2 ;;
            --cidr) cidr="${2:-}"; shift 2 ;;
            --replace-custom) replace_custom="true"; shift ;;
            --clear-custom) clear_custom="true"; shift ;;
            status) status_requested="true"; shift ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done

    if [ "$status_requested" = "true" ] && [ "$enabled" = "__KEEP__" ] && [ "$include_cn" = "__KEEP__" ] && [ "$cn_mode" = "__KEEP__" ] && [ -z "$cidr" ] && [ "$clear_custom" = "false" ]; then
        egress_whitelist_render_status
        return 0
    fi

    [ "$enabled" = "__KEEP__" ] || validate_bool "$enabled"
    [ "$include_cn" = "__KEEP__" ] || validate_bool "$include_cn"
    if [ "$cn_mode" != "__KEEP__" ]; then
        egress_whitelist_validate_cn_mode "$cn_mode"
    fi
    if [ -n "$cidr" ]; then
        cidr="$(normalize_ip_or_cidr "$cidr")"
    fi

    if [ "$enabled" = "__KEEP__" ]; then
        enabled="$(egress_whitelist_enabled)"
    fi
    if [ "$include_cn" = "__KEEP__" ]; then
        :
    elif [ "$cn_mode" = "__KEEP__" ]; then
        if [ "$include_cn" = "true" ]; then
            cn_mode="all"
        else
            cn_mode="off"
        fi
    fi
    if [ "$cn_mode" = "__KEEP__" ]; then
        cn_mode="$(egress_whitelist_cn_mode)"
    fi
    local backup_dir
    backup_dir="$(cmd_guard_backup_state)"
    egress_whitelist_config_set_state "$enabled" "$cn_mode"

    tmp_cidrs="$(mktemp)"
    if [ "$clear_custom" != "true" ]; then
        if [ "$replace_custom" != "true" ]; then
            egress_whitelist_custom_cidrs_tsv > "$tmp_cidrs"
        fi
        if [ -n "$cidr" ]; then
            printf '%s\n' "$cidr" >> "$tmp_cidrs"
        fi
    fi
    egress_whitelist_config_set_custom_cidrs "$tmp_cidrs"
    rm -f "$tmp_cidrs"

    cmd_guard_finish_aux_mutation egress "出口白名单" "$backup_dir"
    echo "出口白名单已更新"
}


cmd_guard_whitelist_cn() {
    config_init >/dev/null
    local sub="${1:-status}"
    shift || true
    case "$sub" in
        list)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-cn list"
            whitelist_geo_province_rows
            ;;
        status)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-cn status"
            printf 'mode=%s\n' "$(whitelist_cn_mode)"
            printf 'selection=%s\n' "$(whitelist_cn_selection_summary)"
            ;;
        all)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-cn all"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_config_apply_cn_selection all
            cmd_guard_finish_aux_mutation ingress "入口白名单国内策略" "$backup_dir"
            echo "入口白名单国内策略已更新为：国内IP"
            ;;
        off)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard whitelist-cn off"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            whitelist_config_apply_cn_selection off
            cmd_guard_finish_aux_mutation ingress "入口白名单国内策略" "$backup_dir"
            echo "入口白名单国内策略已关闭"
            ;;
        select)
            [ "$#" -ge 1 ] || pfwd_die "用法：pfwd guard whitelist-cn select <省份...>"
            local tmp backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            tmp="$(mktemp)"
            printf '%s\n' "$@" > "$tmp"
            whitelist_config_apply_cn_selection provinces "$tmp"
            rm -f "$tmp"
            cmd_guard_finish_aux_mutation ingress "入口白名单国内策略" "$backup_dir"
            echo "入口白名单国内策略已更新为省份选择"
            ;;
        *)
            pfwd_die "用法：pfwd guard whitelist-cn list|status|all|off|select"
            ;;
    esac
}


cmd_guard_egress_whitelist_cn() {
    config_init >/dev/null
    local sub="${1:-status}"
    shift || true
    case "$sub" in
        list)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-cn list"
            whitelist_geo_province_rows
            ;;
        status)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-cn status"
            printf 'mode=%s\n' "$(egress_whitelist_cn_mode)"
            printf 'selection=%s\n' "$(egress_whitelist_cn_selection_summary)"
            ;;
        all)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-cn all"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            egress_whitelist_config_apply_cn_selection all
            cmd_guard_finish_aux_mutation egress "出口白名单国内策略" "$backup_dir"
            echo "出口白名单国内策略已更新为：国内IP"
            ;;
        off)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-cn off"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            egress_whitelist_config_apply_cn_selection off
            cmd_guard_finish_aux_mutation egress "出口白名单国内策略" "$backup_dir"
            echo "出口白名单国内策略已关闭"
            ;;
        select)
            [ "$#" -ge 1 ] || pfwd_die "用法：pfwd guard egress-whitelist-cn select <省份...>"
            local tmp backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            tmp="$(mktemp)"
            printf '%s\n' "$@" > "$tmp"
            egress_whitelist_config_apply_cn_selection provinces "$tmp"
            rm -f "$tmp"
            cmd_guard_finish_aux_mutation egress "出口白名单国内策略" "$backup_dir"
            echo "出口白名单国内策略已更新为省份选择"
            ;;
        *)
            pfwd_die "用法：pfwd guard egress-whitelist-cn list|status|all|off|select"
            ;;
    esac
}


cmd_guard_egress_whitelist_custom() {
    config_init >/dev/null
    local sub="${1:-}"
    shift || true
    case "$sub" in
        list)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-custom list"
            egress_whitelist_custom_cidrs_tsv
            ;;
        add)
            local cidr="${1:-}" backup_dir
            [ -n "$cidr" ] || pfwd_die "用法：pfwd guard egress-whitelist-custom add <IPv4/IPv6 CIDR 或单个 IP>"
            cidr="$(normalize_ip_or_cidr "$cidr")"
            backup_dir="$(cmd_guard_backup_state)"
            egress_whitelist_append_custom_cidr "$cidr"
            cmd_guard_finish_aux_mutation egress "出口白名单自定义 CIDR" "$backup_dir"
            echo "出口白名单自定义 CIDR 已添加：$cidr"
            ;;
        clear)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd guard egress-whitelist-custom clear"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            egress_whitelist_clear_custom_cidrs
            cmd_guard_finish_aux_mutation egress "出口白名单自定义 CIDR" "$backup_dir"
            echo "出口白名单自定义 CIDR 已清空"
            ;;
        delete)
            [ "$#" -ge 1 ] || pfwd_die "用法：pfwd guard egress-whitelist-custom delete <index...>"
            local backup_dir
            backup_dir="$(cmd_guard_backup_state)"
            egress_whitelist_delete_custom_cidrs_by_indexes "$(printf '%s\n' "$@")"
            cmd_guard_finish_aux_mutation egress "出口白名单自定义 CIDR" "$backup_dir"
            echo "出口白名单自定义 CIDR 已删除"
            ;;
        update)
            local index="${1:-}" cidr="${2:-}" backup_dir
            [ -n "$index" ] && [ -n "$cidr" ] || pfwd_die "用法：pfwd guard egress-whitelist-custom update <index> <IPv4/IPv6 CIDR 或单个 IP>"
            cidr="$(normalize_ip_or_cidr "$cidr")"
            backup_dir="$(cmd_guard_backup_state)"
            egress_whitelist_replace_custom_cidr_by_index "$index" "$cidr"
            cmd_guard_finish_aux_mutation egress "出口白名单自定义 CIDR" "$backup_dir"
            echo "出口白名单自定义 CIDR 已更新：$index -> $cidr"
            ;;
        *)
            pfwd_die "用法：pfwd guard egress-whitelist-custom list|add|clear|delete|update"
            ;;
    esac
}
