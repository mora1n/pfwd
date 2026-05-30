#!/usr/bin/env bash

runtime_target_kind() {
    forwarder_target_kind "$@"
}

runtime_infer_ip_version() {
    forwarder_infer_ip_version "$@"
}

runtime_protocol_rows() {
    forwarder_protocol_rows "$@"
}

runtime_resolve_targets() {
    forwarder_resolve_targets "$@"
}

runtime_iface() {
    forwarder_iface
}

runtime_protocol_filters_enabled() {
    forwarder_protocol_filters_enabled
}

runtime_guard_ingress_mode() {
    forwarder_guard_ingress_mode
}

runtime_whitelist_files_json() {
    forwarder_whitelist_files_json
}

runtime_egress_whitelist_files_json() {
    forwarder_egress_whitelist_files_json
}

runtime_protocol_skip_ports_json() {
    forwarder_protocol_skip_ports_json
}

runtime_rule_execution_class() {
    local resolved_target="$1"
    case "$resolved_target" in
        127.0.0.1|::1) printf '%s\n' nft ;;
        *) printf '%s\n' xdp ;;
    esac
}

runtime_rule_backend_reason() {
    local resolved_target="$1"
    case "$resolved_target" in
        127.0.0.1|::1) printf '%s\n' "loopback-target" ;;
        *) printf '%s\n' "" ;;
    esac
}

runtime_rule_counter_owner() {
    local execution_class="$1"
    case "$execution_class" in
        nft) printf '%s\n' nft ;;
        *) printf '%s\n' xdp ;;
    esac
}

runtime_index_store_json() {
    local config_file="$1"
    local persist="${2:-false}"
    local existing='{"version":1,"rules":{},"users":{}}'
    local index_json persist_json

    if [ "$persist" = "true" ] && [ -f "$PFWD_XDP_INDEX_FILE" ]; then
        jq -e '
          type == "object"
          and ((.version // 1) == 1)
          and ((.rules // {}) | type == "object")
          and ((.users // {}) | type == "object")
          and all((.rules // {})[]?; (type == "number") and . >= 0)
          and all((.users // {})[]?; (type == "number") and . >= 0)
          and (((.rules // {}) | [.[]] | length) == ((.rules // {}) | [.[]] | unique | length))
          and (((.users // {}) | [.[]] | length) == ((.users // {}) | [.[]] | unique | length))
        ' "$PFWD_XDP_INDEX_FILE" >/dev/null || pfwd_die "XDP index 状态文件无效：$PFWD_XDP_INDEX_FILE"
        existing="$(jq -c '.' "$PFWD_XDP_INDEX_FILE")"
    fi

    index_json="$(jq -n \
      --slurpfile cfg "$config_file" \
      --argjson existing "$existing" '
      def clean_map($m):
        reduce (($m // {}) | to_entries[]) as $e ({};
          if (($e.value | type) == "number" and $e.value >= 0)
          then .[$e.key] = ($e.value | floor)
          else .
          end
        );
      def used_map($m):
        reduce ($m | to_entries[]) as $e ({};
          .[($e.value | tostring)] = true
        );
      def next_free($used):
        first(range(0; 4096) as $i | select((($used[($i | tostring)] // false) | not)) | $i);
      def unique_order:
        reduce .[] as $id ({seen: {}, out: []};
          if (.seen[$id] // false) then
            .
          else
            .seen[$id] = true
            | .out += [$id]
          end
        ) | .out;
      def assign($ids; $existing_map):
        reduce $ids[] as $id (
          {map: clean_map($existing_map), used: used_map(clean_map($existing_map))};
          if ((.map[$id] // null) != null) then
            .
          else
            (next_free(.used) // error("XDP index pool exhausted")) as $idx
            | .map[$id] = $idx
            | .used[($idx | tostring)] = true
          end
        ) | .map;

      ([$cfg[0].users[]?.id] | unique_order) as $user_ids
      | ([$cfg[0].forwards[]?.id] | unique_order) as $rule_ids
      | (assign($user_ids; ($existing.users // {}))) as $users
      | (assign($rule_ids; ($existing.rules // {}))) as $rules
      | {
          version: 1,
          users: $users,
          rules: $rules,
          current_users: (reduce $user_ids[] as $id ({}; .[$id] = $users[$id])),
          current_rules: (reduce $rule_ids[] as $id ({}; .[$id] = $rules[$id]))
        }
    ')"

    if [ "$persist" = "true" ]; then
        persist_json="$(jq '{version, users, rules}' <<< "$index_json")"
        printf '%s\n' "$persist_json" | jq '.' | pfwd_write_atomic "$PFWD_XDP_INDEX_FILE"
    fi

    printf '%s\n' "$index_json"
}

runtime_rule_json_line() {
    local id="$1"
    local index="$2"
    local user_id="$3"
    local user_index="$4"
    local listen_ip="$5"
    local listen_port="$6"
    local protocol="$7"
    local remote_input="$8"
    local resolved_target="$9"
    shift 9
    local remote_port="$1"
    local ip_version="$2"
    local comment="$3"
    local snat_mode="$4"
    local snat_source="$5"
    local mss_mode="$6"
    local mss_value="$7"
    local traffic_mode="$8"
    local traffic_ratio="$9"
    shift 9
    local execution_class="$1"
    local backend_reason="$2"
    local counter_owner="$3"
    local rule_limit="$4"
    local user_limit="$5"
    local billing_used="$6"
    local user_billing_used="$7"

    local comment_json snat_source_json mss_mode_json mss_value_json fallback_reason_json loopback_local
    comment_json="null"
    snat_source_json="null"
    mss_mode_json="null"
    mss_value_json="null"
    fallback_reason_json="null"
    loopback_local="false"

    [ -z "$comment" ] || comment_json="$(pfwd_json_escape "$comment")"
    [ -z "$snat_source" ] || snat_source_json="$(pfwd_json_escape "$snat_source")"
    [ -z "$mss_mode" ] || mss_mode_json="$(pfwd_json_escape "$mss_mode")"
    [ -z "$mss_value" ] || mss_value_json="$mss_value"
    [ -z "$backend_reason" ] || fallback_reason_json="$(pfwd_json_escape "$backend_reason")"
    [ "$execution_class" = "nft" ] && loopback_local="true"

    printf '{'
    printf '"id":%s,' "$(pfwd_json_escape "$id")"
    printf '"index":%s,' "$index"
    printf '"user_id":%s,' "$(pfwd_json_escape "$user_id")"
    printf '"user_index":%s,' "$user_index"
    printf '"listen_ip":%s,' "$(pfwd_json_escape "$listen_ip")"
    printf '"listen_port":%s,' "$listen_port"
    printf '"protocol":%s,' "$(pfwd_json_escape "$protocol")"
    printf '"remote_input":%s,' "$(pfwd_json_escape "$remote_input")"
    printf '"resolved_target":%s,' "$(pfwd_json_escape "$resolved_target")"
    printf '"remote_port":%s,' "$remote_port"
    printf '"ip_version":%s,' "$ip_version"
    printf '"comment":%s,' "$comment_json"
    printf '"snat_mode":%s,' "$(pfwd_json_escape "$snat_mode")"
    printf '"snat_source":%s,' "$snat_source_json"
    printf '"mss_mode":%s,' "$mss_mode_json"
    printf '"mss_value":%s,' "$mss_value_json"
    printf '"traffic_mode":%s,' "$(pfwd_json_escape "$traffic_mode")"
    printf '"traffic_ratio":%s,' "$traffic_ratio"
    printf '"traffic_limit_bytes":%s,' "$rule_limit"
    printf '"user_limit_bytes":%s,' "$user_limit"
    printf '"billing_used_base_bytes":%s,' "$billing_used"
    printf '"user_billing_used_base_bytes":%s,' "$user_billing_used"
    printf '"execution_class":%s,' "$(pfwd_json_escape "$execution_class")"
    printf '"fallback_reason":%s,' "$fallback_reason_json"
    printf '"counter_owner":%s,' "$(pfwd_json_escape "$counter_owner")"
    printf '"loopback_local":%s' "$loopback_local"
    printf '}\n'
}

runtime_compiled_json() {
    local strict="${1:-true}"
    config_init >/dev/null
    stats_init >/dev/null

    local config_file="$PFWD_CONFIG_FILE"
    if [ -n "${PFWD_CONFIG_SNAPSHOT_FILE:-}" ] && [ -f "$PFWD_CONFIG_SNAPSHOT_FILE" ]; then
        config_file="$PFWD_CONFIG_SNAPSHOT_FILE"
    fi

    local now_minute rows rules_json="[]" users_json settings_json rule_index_json user_index_json index_store_json persist_indexes="false"
    local rules_tmp=""
    local -A user_limit_by_id=() user_index_by_id=() rule_index_by_id=() rule_billing_by_id=() user_billing_by_id=()
    local -A resolve_rows_cache=() resolve_error_cache=() egress_allow_cache=() egress_error_cache=()
    now_minute="$(pfwd_now_minute)"

    rows="$(jq -r --arg now "$now_minute" '
      .forwards[]
      | select(.enabled == true and (.stop_at == null or .stop_at > $now))
      | [
          .id,
          .user_id,
          (.listen_ip // "::"),
          (.listen_port | tostring),
          .remote_host,
          (.remote_port | tostring),
          (.protocol // "tcp_udp"),
          (.comment // ""),
          (.net.snat_mode // "masquerade"),
          (.net.snat_source // ""),
          (.net.mss_mode // ""),
          (if (.net.mss_value // null) == null then "" else (.net.mss_value | tostring) end),
          (.traffic_mode // "two-way"),
          ((.traffic_ratio // 1) | tostring),
          (.limits.traffic_bytes // 0 | tostring)
        ] | @tsv
    ' "$config_file")"

    if [ "$config_file" = "$PFWD_CONFIG_FILE" ]; then
        persist_indexes="true"
    fi
    index_store_json="$(runtime_index_store_json "$config_file" "$persist_indexes")"
    user_index_json="$(jq '.current_users' <<< "$index_store_json")"
    rule_index_json="$(jq '.current_rules' <<< "$index_store_json")"

    while IFS=$'\t' read -r user_id user_index user_limit user_used; do
        [ -n "$user_id" ] || continue
        user_index_by_id["$user_id"]="$user_index"
        user_limit_by_id["$user_id"]="$user_limit"
        user_billing_by_id["$user_id"]="$user_used"
    done < <(jq -r --slurpfile stats "$PFWD_STATS_FILE" --argjson user_index "$user_index_json" '
      .users[]?
      | [
          .id,
          ($user_index[.id] // 0),
          (.limits.traffic_bytes // 0),
          ($stats[0].users[.id].billing_used_bytes // 0)
        ] | @tsv
    ' "$config_file")

    while IFS=$'\t' read -r rule_id rule_index rule_used; do
        [ -n "$rule_id" ] || continue
        rule_index_by_id["$rule_id"]="$rule_index"
        rule_billing_by_id["$rule_id"]="$rule_used"
    done < <(jq -r --slurpfile stats "$PFWD_STATS_FILE" --argjson rule_index "$rule_index_json" '
      .forwards[]?
      | [
          .id,
          ($rule_index[.id] // 0),
          ($stats[0].forwards[.id].billing_used_bytes // 0)
        ] | @tsv
    ' "$config_file")

    users_json="$(jq -n \
      --slurpfile cfg "$config_file" \
      --slurpfile stats "$PFWD_STATS_FILE" \
      --argjson user_index "$user_index_json" '
      [
        $cfg[0].users[]? |
        {
          id: .id,
          index: ($user_index[.id] // 0),
          traffic_limit_bytes: (.limits.traffic_bytes // 0),
          billing_used_base_bytes: ($stats[0].users[.id].billing_used_bytes // 0)
        }
      ]
    ')"

    local guard_enabled whitelist_state egress_whitelist_state host_egress_state protocol_filters_enabled
    guard_enabled="$(jq -r '.settings.guard.enabled // false' "$config_file")"
    whitelist_state="false"
    if [ "$guard_enabled" = "true" ] && command -v whitelist_enabled >/dev/null 2>&1 && [ "$(whitelist_enabled)" = "true" ]; then
        whitelist_state="true"
    fi
    egress_whitelist_state="false"
    host_egress_state="false"
    if command -v egress_whitelist_enabled >/dev/null 2>&1 && [ "$(egress_whitelist_enabled "$config_file")" = "true" ]; then
        egress_whitelist_state="true"
        egress_whitelist_prepare_runtime "$config_file"
        host_egress_state="true"
    fi
    protocol_filters_enabled="$(runtime_protocol_filters_enabled)"

    if [ -n "$rows" ]; then
        rules_tmp="$(mktemp "${PFWD_RUN_DIR}/compiled.rules.XXXXXX")"
        : > "$rules_tmp"
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            forwarder_split_tsv_line "$line"
            local id user_id listen_ip listen_port remote_host remote_port protocol comment snat_mode snat_source mss_mode mss_value traffic_mode traffic_ratio rule_limit
            id="${FORWARDER_TSV_FIELDS[0]:-}"
            user_id="${FORWARDER_TSV_FIELDS[1]:-}"
            listen_ip="${FORWARDER_TSV_FIELDS[2]:-}"
            listen_port="${FORWARDER_TSV_FIELDS[3]:-}"
            remote_host="${FORWARDER_TSV_FIELDS[4]:-}"
            remote_port="${FORWARDER_TSV_FIELDS[5]:-}"
            protocol="${FORWARDER_TSV_FIELDS[6]:-}"
            comment="${FORWARDER_TSV_FIELDS[7]:-}"
            snat_mode="${FORWARDER_TSV_FIELDS[8]:-}"
            snat_source="${FORWARDER_TSV_FIELDS[9]:-}"
            mss_mode="${FORWARDER_TSV_FIELDS[10]:-}"
            mss_value="${FORWARDER_TSV_FIELDS[11]:-}"
            traffic_mode="${FORWARDER_TSV_FIELDS[12]:-two-way}"
            traffic_ratio="${FORWARDER_TSV_FIELDS[13]:-1}"
            rule_limit="${FORWARDER_TSV_FIELDS[14]:-0}"
            [ -n "$listen_port" ] || continue

            local ip_versions target_rows ipver proto family resolved_ip family_ipver user_limit user_index rule_index billing_used user_billing_used
            local execution_class backend_reason counter_owner
            ip_versions="$(runtime_infer_ip_version "$listen_ip" "$snat_mode" "$snat_source")"
            user_limit="${user_limit_by_id[$user_id]:-0}"
            user_index="${user_index_by_id[$user_id]:-0}"
            rule_index="${rule_index_by_id[$id]:-0}"
            billing_used="${rule_billing_by_id[$id]:-0}"
            user_billing_used="${user_billing_by_id[$user_id]:-0}"

            while IFS= read -r ipver; do
                [ -n "$ipver" ] || continue
                local resolve_cache_key="${remote_host}|${ipver}"
                if [[ -v resolve_rows_cache["$resolve_cache_key"] ]]; then
                    target_rows="${resolve_rows_cache[$resolve_cache_key]}"
                    FORWARDER_LAST_RESOLVE_ERROR="${resolve_error_cache[$resolve_cache_key]:-}"
                else
                    target_rows="$(runtime_resolve_targets "$remote_host" "$ipver" || true)"
                    resolve_rows_cache["$resolve_cache_key"]="$target_rows"
                    resolve_error_cache["$resolve_cache_key"]="${FORWARDER_LAST_RESOLVE_ERROR:-}"
                fi
                if [ -z "$target_rows" ]; then
                    if [ "$strict" = "true" ] && [ "$(runtime_target_kind "$remote_host")" = "domain" ]; then
                        pfwd_die "无法解析目标地址：$remote_host (IPv$ipver)${FORWARDER_LAST_RESOLVE_ERROR:+：$FORWARDER_LAST_RESOLVE_ERROR}"
                    fi
                    continue
                fi
                if [ "$egress_whitelist_state" = "true" ]; then
                    if [[ ! -v egress_allow_cache["$resolve_cache_key"] ]]; then
                        if egress_whitelist_assert_target_rows_allowed "$remote_host" "$target_rows"; then
                            egress_allow_cache["$resolve_cache_key"]="true"
                            egress_error_cache["$resolve_cache_key"]=""
                        else
                            egress_allow_cache["$resolve_cache_key"]="false"
                            egress_error_cache["$resolve_cache_key"]="$EGRESS_WHITELIST_LAST_ERROR"
                        fi
                    fi
                    if [ "${egress_allow_cache[$resolve_cache_key]}" != "true" ]; then
                        pfwd_die "出口白名单拒绝转发规则：$id ${egress_error_cache[$resolve_cache_key]}"
                    fi
                fi

                while IFS= read -r proto; do
                    [ -n "$proto" ] || continue
                    while IFS='|' read -r family _ resolved_ip; do
                        [ -n "$resolved_ip" ] || continue
                        if [ "$family" = "ip6" ]; then
                            family_ipver=6
                        else
                            family_ipver=4
                        fi
                        execution_class="$(runtime_rule_execution_class "$resolved_ip")"
                        backend_reason="$(runtime_rule_backend_reason "$resolved_ip")"
                        counter_owner="$(runtime_rule_counter_owner "$execution_class")"
                        runtime_rule_json_line \
                          "$id" "$rule_index" "$user_id" "$user_index" \
                          "$listen_ip" "$listen_port" "$proto" "$remote_host" "$resolved_ip" \
                          "$remote_port" "$family_ipver" "$comment" "$snat_mode" "$snat_source" \
                          "$mss_mode" "$mss_value" "$traffic_mode" "$traffic_ratio" \
                          "$execution_class" "$backend_reason" "$counter_owner" \
                          "$rule_limit" "${user_limit:-0}" "$billing_used" "$user_billing_used" >> "$rules_tmp"
                    done <<< "$target_rows"
                done < <(runtime_protocol_rows "$protocol")
            done <<< "$ip_versions"
        done <<< "$rows"
        if [ -s "$rules_tmp" ]; then
            rules_json="$(jq -s '.' "$rules_tmp")"
        fi
        rm -f "$rules_tmp"
    fi

    settings_json="$(jq -n \
      --arg iface "$(runtime_iface)" \
      --arg guard_ingress_mode "$(runtime_guard_ingress_mode)" \
      --argjson guard_enabled "$guard_enabled" \
      --argjson whitelist_enabled "$whitelist_state" \
      --argjson egress_whitelist_enabled "$egress_whitelist_state" \
      --argjson block_http "$(if [ "$protocol_filters_enabled" = "true" ]; then jq -r '.settings.guard.block_http // false' "$config_file"; else echo false; fi)" \
      --argjson block_tls "$(if [ "$protocol_filters_enabled" = "true" ]; then jq -r '.settings.guard.block_tls // false' "$config_file"; else echo false; fi)" \
      --argjson block_socks "$(if [ "$protocol_filters_enabled" = "true" ]; then jq -r '.settings.guard.block_socks // false' "$config_file"; else echo false; fi)" \
      --argjson skip_ports "$(runtime_protocol_skip_ports_json)" \
      --argjson files "$(runtime_whitelist_files_json)" \
      --argjson egress_files "$(runtime_egress_whitelist_files_json)" \
      --arg host_egress_allow_ipv4_file "$(egress_whitelist_host_allow_ipv4_file)" \
      --arg host_egress_allow_ipv6_file "$(egress_whitelist_host_allow_ipv6_file)" \
      --argjson host_egress_enabled "$host_egress_state" '
      {
        interface: $iface,
        guard_ingress_mode: $guard_ingress_mode,
        guard_enabled: $guard_enabled,
        whitelist_enabled: $whitelist_enabled,
        egress_whitelist_enabled: $egress_whitelist_enabled,
        host_egress_enabled: $host_egress_enabled,
        block_http: $block_http,
        block_tls: $block_tls,
        block_socks: $block_socks,
        protocol_skip_ports: $skip_ports,
        whitelist_files: $files,
        egress_whitelist_files: $egress_files,
        host_egress_allow_ipv4_file: $host_egress_allow_ipv4_file,
        host_egress_allow_ipv6_file: $host_egress_allow_ipv6_file
      }
    ')"

    jq -n \
      --arg generated_at "$(pfwd_now_iso)" \
      --argjson settings "$settings_json" \
      --argjson users "$users_json" \
      --argjson rules "$rules_json" \
      --argjson rule_index "$rule_index_json" \
      --argjson user_index "$user_index_json" '
      {
        generated_at: $generated_at,
        settings: $settings,
        users: $users,
        rules: $rules,
        rule_index: $rule_index,
        user_index: $user_index
      }
    ' | runtime_attach_metadata
}

runtime_attach_metadata() {
    local runtime_json
    runtime_json="$(cat)"
    local config_hash
    runtime_json="$(jq '
      .dataplane_version = 2
      | .map_abi_version = 7
      | .rules = [
          .rules[]? as $rule
          | (
              [
                (if (($rule.snat_mode // "masquerade") == "snat") then "fixed_snat" else empty end),
                (if ((($rule.mss_mode // "") != "") and (($rule.mss_mode // "none") != "none")) then "mss" else empty end),
                (if (($rule.traffic_limit_bytes // 0) > 0 or ($rule.user_limit_bytes // 0) > 0) then "metered" else empty end),
                (if ((.settings.guard_enabled // false) == true and ($rule.protocol == "tcp")) then "guard" else empty end)
              ] | unique
            ) as $flags
          | $rule
          | .feature_flags = $flags
          | .feature_profile = (
              if ($flags | index("guard")) then "guarded_nat"
              elif (($flags | index("fixed_snat")) or ($flags | index("mss"))) then "rewrite_nat"
              elif ($flags | index("metered")) then "metered_nat"
              else "basic_nat"
              end
            )
        ]
      | .summary = (
        reduce (.rules[]?) as $rule (
          {rules: 0, xdp_rules: 0, nft_rules: 0, loopback_rules: 0, profile_counts: {}};
          .rules += 1
          | .xdp_rules += (if $rule.execution_class == "xdp" then 1 else 0 end)
          | .nft_rules += (if $rule.execution_class == "nft" then 1 else 0 end)
          | .loopback_rules += (if ($rule.loopback_local == true) then 1 else 0 end)
          | .profile_counts[$rule.feature_profile] = ((.profile_counts[$rule.feature_profile] // 0) + 1)
        )
      )
    ' <<< "$runtime_json")"
    config_hash="$(printf '%s' "$runtime_json" | pfwd_stdin_checksum)"
    jq --arg config_hash "$config_hash" '
      .config_hash = $config_hash
    ' <<< "$runtime_json"
}

runtime_write_compiled_file() {
    local runtime_json="$1"
    printf '%s\n' "$runtime_json" | jq '.' | pfwd_write_atomic "$PFWD_FORWARDER_RUNTIME_FILE"
}

runtime_backend_filter() {
    local backend="$1"
    case "$backend" in
        xdp)
            jq '
              .rules = [.rules[]? | select(.execution_class == "xdp")]
              | .rule_index = (reduce (.rules[]?) as $rule ({}; .[$rule.id] = $rule.index))
            '
            ;;
        nft)
            jq '
              .rules = [.rules[]? | select(.execution_class == "nft")]
              | .rule_index = (reduce (.rules[]?) as $rule ({}; .[$rule.id] = $rule.index))
            '
            ;;
        *)
            pfwd_die "未知 backend：$backend"
            ;;
    esac
}

runtime_backend_json() {
    local compiled_runtime="$1"
    local backend="$2"
    runtime_backend_filter "$backend" <<< "$compiled_runtime"
}

runtime_write_backend_file() {
    local backend="$1"
    local runtime_json="$2"
    local target=""
    case "$backend" in
        xdp) target="$PFWD_FORWARDER_XDP_RUNTIME_FILE" ;;
        nft) target="$PFWD_FORWARDER_NFT_RUNTIME_FILE" ;;
        *) pfwd_die "未知 backend：$backend" ;;
    esac
    printf '%s\n' "$runtime_json" | jq '.' | pfwd_write_atomic "$target"
}

runtime_xdp_guard_required() {
    local runtime_json="$1"
    jq -e '
      (.settings.guard_enabled == true)
      and ((.settings.whitelist_enabled == true) or (.settings.block_http == true) or (.settings.block_tls == true) or (.settings.block_socks == true))
    ' >/dev/null <<< "$runtime_json"
}

runtime_xdp_forward_rule_count() {
    local runtime_json="$1"
    jq '[.rules[]? | select(.execution_class == "xdp")] | length' <<< "$runtime_json"
}

forwarder_runtime_json() {
    runtime_compiled_json "$@"
}

forwarder_write_runtime_file() {
    runtime_write_compiled_file "$@"
}

forwarder_write_xdp_runtime_file() {
    runtime_write_backend_file xdp "$1"
}

forwarder_write_nft_runtime_file() {
    runtime_write_backend_file nft "$1"
}

forwarder_split_runtime_json() {
    local runtime_json="$1"
    FORWARDER_SPLIT_XDP_RUNTIME_JSON="$(runtime_backend_json "$runtime_json" xdp)"
    FORWARDER_SPLIT_NFT_RUNTIME_JSON="$(runtime_backend_json "$runtime_json" nft)"
}

forwarder_xdp_guard_required() {
    runtime_xdp_guard_required "$@"
}

forwarder_xdp_forward_rule_count() {
    runtime_xdp_forward_rule_count "$@"
}

RUNTIME_XDP_APPLIED="false"
RUNTIME_XDP_FORWARD_APPLIED="false"
RUNTIME_XDP_STATUS_JSON='{}'
RUNTIME_XDP_ERROR=""

runtime_reset_xdp_apply_state() {
    RUNTIME_XDP_APPLIED="false"
    RUNTIME_XDP_FORWARD_APPLIED="false"
    RUNTIME_XDP_STATUS_JSON='{}'
    RUNTIME_XDP_ERROR=""
}

runtime_remove_xdp_runtime() {
    if [ -x "$(forwarder_bin_path)" ]; then
        pfwd_run "$(forwarder_bin_path)" remove \
          --status-file "$PFWD_XDP_STATUS_FILE" \
          --xdp-pin "$PFWD_XDP_LINK_PIN_PATH" \
          --ingress-pin "$PFWD_XDP_INGRESS_PIN_PATH" \
          --host-egress-pin "$PFWD_XDP_HOST_EGRESS_PIN_PATH" \
          --loopback-pin "$PFWD_XDP_LOOPBACK_PIN_PATH" \
          --sk-lookup-pin "$PFWD_XDP_SK_LOOKUP_PIN_PATH" \
          --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" \
          --user-counter-pin "$PFWD_XDP_USER_COUNTER_PIN_PATH" \
          --stats-pin "$PFWD_XDP_STATS_PIN_PATH" || true
    fi
}

runtime_remove_link_pins() {
    rm -f "$PFWD_XDP_LINK_PIN_PATH" "$PFWD_XDP_INGRESS_PIN_PATH" \
          "$PFWD_XDP_HOST_EGRESS_PIN_PATH" "$PFWD_XDP_LOOPBACK_PIN_PATH" "$PFWD_XDP_SK_LOOKUP_PIN_PATH" || true
}

runtime_remove_pinned_state() {
    rm -f "$PFWD_XDP_SETTINGS_PIN_PATH" "$PFWD_XDP_RULES_PIN_PATH" "$PFWD_XDP_CONNECTIONS_PIN_PATH" \
          "$PFWD_XDP_REVERSE_PIN_PATH" "$PFWD_XDP_WHITELIST_V4_PIN_PATH" "$PFWD_XDP_WHITELIST_V6_PIN_PATH" \
          "$PFWD_XDP_WHITELIST_CACHE_V4_PIN_PATH" "$PFWD_XDP_WHITELIST_CACHE_V6_PIN_PATH" \
          "$PFWD_XDP_EGRESS_WHITELIST_V4_PIN_PATH" "$PFWD_XDP_EGRESS_WHITELIST_V6_PIN_PATH" \
          "$PFWD_XDP_EGRESS_WHITELIST_CACHE_V4_PIN_PATH" "$PFWD_XDP_EGRESS_WHITELIST_CACHE_V6_PIN_PATH" \
          "$PFWD_XDP_ALLOWED_FLOWS_PIN_PATH" "$PFWD_XDP_HOST_EGRESS_FLOWS_PIN_PATH" \
          "$PFWD_XDP_GUARD_PREFIXES_PIN_PATH" "$PFWD_XDP_SKIP_PORTS_PIN_PATH" \
          "$PFWD_XDP_RULE_COUNTER_PIN_PATH" "$PFWD_XDP_USER_COUNTER_PIN_PATH" "$PFWD_XDP_STATS_PIN_PATH" || true
}

runtime_remove_xdp_status_file() {
    rm -f "$PFWD_XDP_STATUS_FILE"
}

runtime_remove_runtime_files() {
    rm -f "$PFWD_FORWARDER_NFT_RENDER_FILE" \
          "$PFWD_FORWARDER_RUNTIME_FILE" \
          "$PFWD_FORWARDER_XDP_RUNTIME_FILE" \
          "$PFWD_FORWARDER_NFT_RUNTIME_FILE"
}

runtime_remove_forwarder_status_file() {
    rm -f "$PFWD_FORWARDER_STATUS_FILE"
}

runtime_remove_runtime_artifacts() {
    runtime_remove_xdp_status_file
    runtime_remove_forwarder_status_file
    runtime_remove_runtime_files
}

runtime_remove_whitelist_runtime_files() {
    rm -f "$PFWD_WHITELIST_ALLOW_IPV4_FILE" \
          "$PFWD_WHITELIST_ALLOW_IPV6_FILE" \
          "${PFWD_WHITELIST_ALLOW_IPV4_FILE}.cn" \
          "${PFWD_WHITELIST_ALLOW_IPV6_FILE}.cn" \
          "$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV4_FILE" \
          "$PFWD_EGRESS_WHITELIST_HOST_ALLOW_IPV6_FILE" || true
}

runtime_remove_runtime_state_dirs() {
    rm -rf "$PFWD_GUARD_STATE_DIR" "$PFWD_WHITELIST_STATE_DIR" "$PFWD_EGRESS_WHITELIST_STATE_DIR"
}

runtime_clear_nft_runtime() {
    if [ -f "$PFWD_CONFIG_FILE" ]; then
        fw_delete_forward_table || true
    fi
    mkdir -p "$(dirname "$PFWD_FORWARDER_NFT_RENDER_FILE")"
    : > "$PFWD_FORWARDER_NFT_RENDER_FILE"
}

runtime_clear_accounting_runtime() {
    if [ -f "$PFWD_CONFIG_FILE" ]; then
        fw_cleanup_nft_table "$(fw_family)" "$(fw_table)" || true
    fi
    mkdir -p "$(dirname "$FW_NFT_ACCOUNTING_RENDER_FILE")"
    : > "$FW_NFT_ACCOUNTING_RENDER_FILE"
}

runtime_reset_runtime_files() {
    printf '[]\n' | pfwd_write_atomic "$PFWD_FORWARDER_RUNTIME_FILE"
    printf '[]\n' | pfwd_write_atomic "$PFWD_FORWARDER_XDP_RUNTIME_FILE"
    printf '[]\n' | pfwd_write_atomic "$PFWD_FORWARDER_NFT_RUNTIME_FILE"
    : > "$PFWD_FORWARDER_NFT_RENDER_FILE"
}

runtime_write_stopped_status() {
    forwarder_write_status_file "$(jq -n '{applied:false,forwarding_backend:"none",xdp_applied:false,xdp_forward_applied:false,nft_applied:false,loopback_via_nft:false,loopback_split_active:false,rules:0,xdp_candidate_rules_count:0,xdp_rules_count:0,xdp_guard_rules_count:0,nft_rules_count:0,interface:"",protocol_guard:false,whitelist_enabled:false,egress_whitelist_enabled:false,host_egress_enabled:false,host_egress_backend:"off"}')"
}

runtime_stop_compiled_runtime() {
    runtime_remove_xdp_runtime
    runtime_remove_link_pins
    runtime_remove_pinned_state
    runtime_clear_nft_runtime
    runtime_clear_accounting_runtime
    fw_cleanup_legacy_nft || true
    runtime_reset_runtime_files
    runtime_write_stopped_status
}

runtime_merge_runtime_rules() {
    local base_runtime="$1"
    local extra_runtime="$2"
    jq \
      --argjson extra "$(jq '.rules // []' <<< "$extra_runtime")" \
      '.rules += $extra | .rule_index = (reduce (.rules[]?) as $rule ({}; .[$rule.id] = $rule.index))' <<< "$base_runtime"
}

runtime_apply_xdp_runtime() {
    local runtime_json="$1"
    local total_rules xdp_forward_rules guard_mode iface xdp_status host_egress_enabled

    runtime_reset_xdp_apply_state
    total_rules="$(jq '.rules | length' <<< "$runtime_json")"
    xdp_forward_rules="$(runtime_xdp_forward_rule_count "$runtime_json")"
    host_egress_enabled="$(jq -r '.settings.host_egress_enabled // false' <<< "$runtime_json")"
    if [ "$total_rules" = "0" ] && ! runtime_xdp_guard_required "$runtime_json" && [ "$host_egress_enabled" != "true" ]; then
        runtime_remove_xdp_runtime
        RUNTIME_XDP_STATUS_JSON='{"applied":false}'
        return 0
    fi

    iface="$(jq -r '.settings.interface // empty' <<< "$runtime_json")"
    [ -n "$iface" ] || iface="$(runtime_iface)"
    [ -n "$iface" ] || pfwd_die "无法确定转发网卡，请设置 settings.forward.interface 或 settings.tc_interface"

    if [ ! -x "$(forwarder_bin_path)" ]; then
        RUNTIME_XDP_ERROR="pfwd-xdp 不可执行：$(forwarder_bin_path)"
        return 1
    fi

    guard_mode="ingress"
    if [ "$xdp_forward_rules" -gt 0 ]; then
        guard_mode="full"
    fi

    xdp_status="$(
      "$(forwarder_bin_path)" apply \
        --runtime-file "$PFWD_FORWARDER_XDP_RUNTIME_FILE" \
        --state-file "$PFWD_STATS_FILE" \
        --status-file "$PFWD_XDP_STATUS_FILE" \
        --iface "$iface" \
        --xdp-pin "$PFWD_XDP_LINK_PIN_PATH" \
        --ingress-pin "$PFWD_XDP_INGRESS_PIN_PATH" \
        --host-egress-pin "$PFWD_XDP_HOST_EGRESS_PIN_PATH" \
        --loopback-pin "$PFWD_XDP_LOOPBACK_PIN_PATH" \
        --sk-lookup-pin "$PFWD_XDP_SK_LOOKUP_PIN_PATH" \
        --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" \
        --user-counter-pin "$PFWD_XDP_USER_COUNTER_PIN_PATH" \
        --stats-pin "$PFWD_XDP_STATS_PIN_PATH" \
        --guard-mode "$guard_mode" \
        --quiet 2>&1
    )" || {
        RUNTIME_XDP_ERROR="$xdp_status"
        runtime_remove_xdp_runtime
        return 1
    }

    RUNTIME_XDP_APPLIED="true"
    if [ "$xdp_forward_rules" -gt 0 ]; then
        RUNTIME_XDP_FORWARD_APPLIED="true"
    fi
    if [ -f "$PFWD_XDP_STATUS_FILE" ]; then
        RUNTIME_XDP_STATUS_JSON="$(jq '.' "$PFWD_XDP_STATUS_FILE")"
    else
        RUNTIME_XDP_STATUS_JSON='{"applied":true}'
    fi
}

runtime_backend_label() {
    local xdp_forward_applied="$1"
    local nft_applied="$2"
    local xdp_applied="$3"
    local xdp_error="$4"

    if [ "$xdp_forward_applied" = "true" ] && [ "$nft_applied" = "true" ]; then
        printf '%s\n' "hybrid"
    elif [ "$xdp_forward_applied" = "true" ]; then
        printf '%s\n' "xdp-only"
    elif [ "$nft_applied" = "true" ]; then
        if [ -n "$xdp_error" ]; then
            printf '%s\n' "nft-fallback"
        else
            printf '%s\n' "nft-only"
        fi
    elif [ "$xdp_applied" = "true" ]; then
        printf '%s\n' "guard-only"
    else
        printf '%s\n' "none"
    fi
}

runtime_host_egress_backend() {
    local backend="$1"
    local host_egress_enabled="$2"
    if [ "$host_egress_enabled" != "true" ]; then
        printf '%s\n' "off"
        return 0
    fi
    case "$backend" in
        xdp-only|hybrid|guard-only) printf '%s\n' "tc" ;;
        nft-only|nft-fallback|none) printf '%s\n' "nft" ;;
        *) printf '%s\n' "off" ;;
    esac
}

runtime_loopback_split_active() {
    local runtime_json="$1"
    local xdp_forward_applied="$2"
    local nft_applied="$3"
    local xdp_error="$4"

    [ "$xdp_forward_applied" = "true" ] || return 1
    [ "$nft_applied" = "true" ] || return 1
    [ -z "$xdp_error" ] || return 1
    jq -e '
      ([.rules[]? | select(.loopback_local == true)] | length) > 0
      and
      ([.rules[]? | select(.execution_class == "xdp")] | length) > 0
    ' >/dev/null <<< "$runtime_json"
}

runtime_apply_compiled_runtime() {
    local runtime_json="$1"
    local xdp_runtime_json nft_runtime_json nft_applied="false" backend fallback_reason=""
    local xdp_candidate_rules=0 total_rules=0 guard_required="false" host_egress_required="false" host_egress_backend="off"

    runtime_write_compiled_file "$runtime_json"
    forwarder_split_runtime_json "$runtime_json"
    xdp_runtime_json="$FORWARDER_SPLIT_XDP_RUNTIME_JSON"
    nft_runtime_json="$FORWARDER_SPLIT_NFT_RUNTIME_JSON"
    forwarder_write_xdp_runtime_file "$xdp_runtime_json"
    forwarder_write_nft_runtime_file "$nft_runtime_json"

    total_rules="$(jq '.rules | length' <<< "$runtime_json")"
    xdp_candidate_rules="$(runtime_xdp_forward_rule_count "$xdp_runtime_json")"
    if runtime_xdp_guard_required "$runtime_json"; then
        guard_required="true"
    fi
    if [ "$(jq -r '.settings.host_egress_enabled // false' <<< "$runtime_json")" = "true" ]; then
        host_egress_required="true"
    fi
    if [ "$total_rules" = "0" ] && [ "$guard_required" != "true" ] && [ "$host_egress_required" != "true" ]; then
        forwarder_stop_runtime
        return 0
    fi

    if [ "$total_rules" -gt 0 ]; then
        forwarder_ensure_ip_forwarding
    fi
    if [ "$total_rules" -gt 0 ] || [ "$guard_required" = "true" ] || [ "$host_egress_required" = "true" ]; then
        if ! runtime_apply_xdp_runtime "$xdp_runtime_json"; then
            if [ "$xdp_candidate_rules" -gt 0 ]; then
                nft_runtime_json="$(runtime_merge_runtime_rules "$nft_runtime_json" "$xdp_runtime_json")"
                forwarder_write_nft_runtime_file "$nft_runtime_json"
            fi
        fi
    else
        runtime_remove_xdp_runtime
        runtime_remove_link_pins
        runtime_remove_pinned_state
        runtime_remove_xdp_status_file
        runtime_reset_xdp_apply_state
    fi

    if [ "$total_rules" = "0" ]; then
        runtime_clear_nft_runtime
    elif [ "$(jq '.rules | length' <<< "$nft_runtime_json")" -gt 0 ]; then
        fw_apply_nft_runtime "$nft_runtime_json"
        nft_applied="true"
    else
        runtime_clear_nft_runtime
    fi

    backend="$(runtime_backend_label "$RUNTIME_XDP_FORWARD_APPLIED" "$nft_applied" "$RUNTIME_XDP_APPLIED" "$RUNTIME_XDP_ERROR")"
    host_egress_backend="$(runtime_host_egress_backend "$backend" "$host_egress_required")"
    runtime_json="$(jq --arg backend "$host_egress_backend" '.settings.host_egress_backend = $backend' <<< "$runtime_json")"

    if [ "$total_rules" -gt 0 ] || [ "$host_egress_backend" = "nft" ]; then
        fw_apply_accounting_runtime "$runtime_json"
    else
        runtime_clear_accounting_runtime
    fi
    fw_apply_tc

    if [ -n "$RUNTIME_XDP_ERROR" ] && [ "$nft_applied" = "true" ]; then
        fallback_reason="XDP 不可用，已自动切换到 nftables"
    fi
    local loopback_split_active="false"
    local hybrid_reason=""
    if runtime_loopback_split_active "$runtime_json" "$RUNTIME_XDP_FORWARD_APPLIED" "$nft_applied" "$RUNTIME_XDP_ERROR"; then
        loopback_split_active="true"
        hybrid_reason="loopback-split"
    fi
    forwarder_write_status_file "$(forwarder_runtime_status_json "$backend" "$runtime_json" "$xdp_runtime_json" "$nft_runtime_json" "$fallback_reason" "$RUNTIME_XDP_ERROR" "$RUNTIME_XDP_APPLIED" "$nft_applied" "${RUNTIME_XDP_STATUS_JSON:-{}}" "$RUNTIME_XDP_FORWARD_APPLIED" "$loopback_split_active" "$hybrid_reason")"
    fw_cleanup_legacy_nft
}

forwarder_render_xdp_config() {
    local runtime_json
    runtime_json="$(forwarder_runtime_json true)"
    runtime_backend_json "$runtime_json" xdp | jq '.'
}
