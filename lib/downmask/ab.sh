#!/usr/bin/env bash

downmask_ab_pull_targets_json() {
    config_init >/dev/null
    jq -c '
      def bool_or($value; $fallback):
        if $value == null then $fallback else $value end;
      def normalize_target($shared):
        {
          host: (.host // .remote_host // ""),
          port: (.port // .remote_port // ($shared.remote_port // 0)),
          token: (.token // ""),
          local_ip: (.local_ip // ""),
          weight: (.weight // 1),
          tcp_enabled: bool_or(.tcp_enabled; true),
          udp_enabled: bool_or(.udp_enabled; true)
        };
      (.settings.downmask.ab_pull // {}) as $ab
      | ($ab.targets // []) as $targets
      | if ($targets | length) > 0 then
          [$targets[] | normalize_target($ab)]
        elif (($ab.remote_host // "") != "" and (($ab.remote_port // 0) | tonumber) > 0) then
          [{
            host: ($ab.remote_host // ""),
            port: (($ab.remote_port // 0) | tonumber),
            token: ($ab.token // ""),
            local_ip: ($ab.local_ip // ""),
            weight: 1,
            tcp_enabled: (
              if ($ab.protocol_mode // "single") == "parallel"
              then bool_or($ab.tcp_enabled; true)
              else (($ab.protocol // "tcp") != "udp")
              end
            ),
            udp_enabled: (
              if ($ab.protocol_mode // "single") == "parallel"
              then bool_or($ab.udp_enabled; false)
              else (($ab.protocol // "tcp") == "udp")
              end
            )
          }]
        else
          []
        end
    ' "$PFWD_CONFIG_FILE"
}


downmask_ab_target_count() {
    jq 'length' <<< "$(downmask_ab_pull_targets_json)"
}


downmask_ab_protocol_enabled() {
    local proto="$1"
    local mode tcp_enabled udp_enabled legacy_protocol
    mode="$(downmask_config_get '.ab_pull.protocol_mode')"
    tcp_enabled="$(downmask_config_get '.ab_pull.tcp_enabled')"
    udp_enabled="$(downmask_config_get '.ab_pull.udp_enabled')"
    legacy_protocol="$(downmask_config_get '.ab_pull.protocol')"
    [ -n "$mode" ] || mode="single"
    [ -n "$tcp_enabled" ] || tcp_enabled="true"
    [ -n "$udp_enabled" ] || udp_enabled="false"
    [ -n "$legacy_protocol" ] || legacy_protocol="tcp"
    case "$mode:$proto" in
        parallel:tcp) [ "$tcp_enabled" = "true" ] ;;
        parallel:udp) [ "$udp_enabled" = "true" ] ;;
        *:tcp) [ "$legacy_protocol" = "tcp" ] ;;
        *:udp) [ "$legacy_protocol" = "udp" ] ;;
        *) return 1 ;;
    esac
}


downmask_random_protocol_split() {
    local total="$1"
    if [ "$total" -le 1 ]; then
        printf '1\t0\n'
        return 0
    fi
    awk -v total="$total" -v seed="$RANDOM$$" '
    BEGIN {
        srand(seed)
        ratio = 0.35 + rand() * 0.30
        tcp = int(total * ratio + 0.5)
        if (tcp < 1) tcp = 1
        if (tcp >= total) tcp = total - 1
        udp = total - tcp
        printf "%d\t%d\n", tcp, udp
    }'
}


downmask_protocol_targets_json() {
    local proto="$1"
    local items_json="${2:-}"
    if [ -n "$items_json" ]; then
        jq -rc --arg proto "$proto" '
          def bool_or($value; $fallback):
            if $value == null then $fallback else $value end;
          [ .[]
            | select((.host // "") != "" and ((.port // 0) | tonumber) > 0)
            | select(
                if $proto == "tcp" then bool_or(.tcp_enabled; true)
                else bool_or(.udp_enabled; true)
                end
              )
            | .weight = ((.weight // 1) | tonumber)
            | select(.weight >= 1)
          ]
        ' <<< "$items_json"
        return 0
    fi
    jq -rc --arg proto "$proto" '
      def bool_or($value; $fallback):
        if $value == null then $fallback else $value end;
      [ .[]
        | select((.host // "") != "" and ((.port // 0) | tonumber) > 0)
        | select(
            if $proto == "tcp" then bool_or(.tcp_enabled; true)
            else bool_or(.udp_enabled; true)
            end
          )
        | .weight = ((.weight // 1) | tonumber)
        | select(.weight >= 1)
      ]
    ' <<< "$(downmask_ab_pull_targets_json)"
}


downmask_pick_weighted_target() {
    local proto="$1"
    local items_json="${2:-}"
    local items total pick
    items="$(downmask_protocol_targets_json "$proto" "$items_json")"
    total="$(jq '[.[].weight] | add // 0' <<< "$items")"
    [ "$total" -gt 0 ] || return 1
    pick=$(( (RANDOM << 15 | RANDOM) % total ))
    jq -rc --argjson pick "$pick" '
      reduce .[] as $item (
        {acc: 0, selected: null};
        if .selected != null then .
        else
          .acc += ($item.weight | tonumber)
          | if $pick < .acc then .selected = $item else . end
        end
      ) | .selected
    ' <<< "$items" | head -n1
}


downmask_resolve_target_field() {
    local target_json="$1"
    local field="$2"
    jq -r --arg field "$field" '.[$field] // empty' <<< "$target_json"
}


downmask_ab_pull_effective_target_json() {
    local target_json="$1"
    local shared_port shared_token shared_local_ip
    shared_port="$(downmask_config_get '.ab_pull.remote_port')"
    shared_token="$(downmask_config_get '.ab_pull.token')"
    shared_local_ip="$(downmask_config_get '.ab_pull.local_ip')"
    jq -c \
        --arg shared_port "$shared_port" \
        --arg shared_token "$shared_token" \
        --arg shared_local_ip "$shared_local_ip" '
        . as $item
        | . + {
            effective_port: (
                if (($item.port // "") | tostring) != "" and (($item.port | tostring) != "0") then ($item.port | tostring)
                elif $shared_port != "" and $shared_port != "0" then $shared_port
                else ""
                end
            ),
            effective_port_source: (
                if (($item.port // "") | tostring) != "" and (($item.port | tostring) != "0") then "override"
                elif $shared_port != "" and $shared_port != "0" then "default"
                else "unset"
                end
            ),
            effective_token: (
                if ($item.token // "") != "" then ($item.token // "")
                elif $shared_token != "" then $shared_token
                else ""
                end
            ),
            effective_token_source: (
                if ($item.token // "") != "" then "override"
                elif $shared_token != "" then "default"
                else "unset"
                end
            ),
            effective_local_ip: (
                if ($item.local_ip // "") != "" then ($item.local_ip // "")
                elif $shared_local_ip != "" then $shared_local_ip
                else ""
                end
            ),
            effective_local_ip_source: (
                if ($item.local_ip // "") != "" then "override"
                elif $shared_local_ip != "" then "default"
                else "unset"
                end
            )
        }
    ' <<< "$target_json"
}


downmask_build_ab_pull_cmd() {
    local protocol="$1"
    local planned="$2"
    local target_json="$3"

    local shared_port shared_token shared_local_ip shared_speed shared_timeout speed_jitter bytes_jitter
    shared_port="$(downmask_config_get '.ab_pull.remote_port')"
    shared_token="$(downmask_config_get '.ab_pull.token')"
    shared_local_ip="$(downmask_config_get '.ab_pull.local_ip')"
    shared_speed="$(downmask_config_get '.ab_pull.speed_limit')"
    shared_timeout="$(downmask_config_get '.ab_pull.timeout_seconds')"
    speed_jitter="$(downmask_config_get '.ab_pull.speed_jitter_percent')"
    bytes_jitter="$(downmask_config_get '.ab_pull.bytes_jitter_percent')"
    [ -n "$shared_speed" ] || shared_speed="4M"
    [ -n "$shared_timeout" ] && [ "$shared_timeout" -gt 0 ] || shared_timeout=1200
    [ -n "$speed_jitter" ] || speed_jitter=0
    [ -n "$bytes_jitter" ] || bytes_jitter=0

    local resolved_target_json remote_host remote_port token local_ip wanted_bps rate_bps wanted_bytes
    resolved_target_json="$(downmask_ab_pull_effective_target_json "$target_json")"
    remote_host="$(downmask_resolve_target_field "$target_json" "host")"
    remote_port="$(downmask_resolve_target_field "$resolved_target_json" "effective_port")"
    token="$(downmask_resolve_target_field "$resolved_target_json" "effective_token")"
    local_ip="$(downmask_resolve_target_field "$resolved_target_json" "effective_local_ip")"

    [ -n "$remote_host" ] && [ -n "$remote_port" ] && [ "$remote_port" != "0" ] || return 1
    [ -n "$token" ] || return 1

    rate_bps="$(downmask_speed_to_bps "$shared_speed")"
    wanted_bytes="$planned"
    if [ "$bytes_jitter" -gt 0 ]; then
        wanted_bytes="$(downmask_apply_percent_jitter "$planned" "$bytes_jitter")"
    fi
    if [ "$wanted_bytes" -lt 1 ]; then
        wanted_bytes=1
    fi
    if [ "$speed_jitter" -gt 0 ] && [ "$rate_bps" -gt 0 ]; then
        wanted_bps="$(downmask_apply_percent_jitter "$rate_bps" "$speed_jitter")"
    else
        wanted_bps="$rate_bps"
    fi

    local -a cmd
    cmd=(
        "$PFWD_DOWNMASK_BIN_PATH"
        pull
        --protocol "$protocol"
        --remote-host "$remote_host"
        --remote-port "$remote_port"
        --token "$token"
        --wanted-bytes "$wanted_bytes"
        --speed-limit "$wanted_bps"
        --timeout "$shared_timeout"
    )
    if [ -n "$local_ip" ]; then
        cmd+=(--local-ip "$local_ip")
    fi
    printf '%s\0' "${cmd[@]}"
}


downmask_run_ab_pull_once() {
    local protocol="$1"
    local planned="$2"
    local target_json="$3"
    [ -x "$PFWD_DOWNMASK_BIN_PATH" ] || { echo 0; return 0; }

    local out
    local -a cmd=()
    while IFS= read -r -d '' arg; do
        cmd+=("$arg")
    done < <(downmask_build_ab_pull_cmd "$protocol" "$planned" "$target_json") || true
    [ "${#cmd[@]}" -gt 0 ] || { echo 0; return 0; }

    out="$("${cmd[@]}" 2>/dev/null || true)"
    jq -r '.actual_bytes // 0' <<< "$out" 2>/dev/null || echo 0
}


downmask_ab_pull_attempt_protocol() {
    local protocol="$1"
    local planned="$2"
    local items target_count target_json actual
    items="$(downmask_protocol_targets_json "$protocol")"
    target_count="$(jq 'length' <<< "$items")"
    [ "$target_count" -gt 0 ] || { echo 0; return 0; }

    actual=0
    while [ "$target_count" -gt 0 ]; do
        target_json="$(downmask_pick_weighted_target "$protocol" "$items")"
        [ -n "$target_json" ] || break
        actual="$(downmask_run_ab_pull_once "$protocol" "$planned" "$target_json")"
        [[ "$actual" =~ ^[0-9]+$ ]] || actual=0
        if [ "$actual" -gt 0 ]; then
            jq -n \
              --arg protocol "$protocol" \
              --argjson target "$target_json" \
              --argjson actual "$actual" '
              {
                protocol: $protocol,
                actual_bytes: $actual,
                target: $target
              }'
            return 0
        fi
        items="$(jq -c --arg host "$(jq -r '.host' <<< "$target_json")" '[.[] | select((.host // "") != $host)]' <<< "$items")"
        target_count="$(jq 'length' <<< "$items")"
    done
    echo "{}"
}


downmask_ab_pull_target_update() {
    local host="$1"
    local port="$2"
    local token="$3"
    local local_ip="$4"
    local weight="$5"
    local tcp_enabled="$6"
    local udp_enabled="$7"
    [ -n "$host" ] || pfwd_die "必须提供 --host"
    validate_downmask_target_host "$host"
    [ -z "$port" ] || validate_port "$port"
    [ -z "$token" ] || validate_downmask_token "$token"
    [ -z "$local_ip" ] || validate_downmask_local_ip "$local_ip"
    [ -z "$weight" ] || validate_downmask_weight "$weight"
    [ -z "$tcp_enabled" ] || validate_bool "$tcp_enabled"
    [ -z "$udp_enabled" ] || validate_bool "$udp_enabled"

    config_update \
      --arg host "$host" \
      --arg port "$port" \
      --arg token "$token" \
      --arg local_ip "$local_ip" \
      --arg weight "$weight" \
      --arg tcp_enabled "$tcp_enabled" \
      --arg udp_enabled "$udp_enabled" '
      def merged_target($existing):
        {
          host: $host,
          port: (if $port == "" then ($existing.port // null) else ($port | tonumber) end),
          token: (if $token == "" then ($existing.token // null) else $token end),
          local_ip: (if $local_ip == "" then ($existing.local_ip // null) else $local_ip end),
          weight: (if $weight == "" then ($existing.weight // 1) else ($weight | tonumber) end),
          tcp_enabled: (if $tcp_enabled == "" then ($existing.tcp_enabled // true) else ($tcp_enabled == "true") end),
          udp_enabled: (if $udp_enabled == "" then ($existing.udp_enabled // true) else ($udp_enabled == "true") end)
        };
      .settings.downmask.ab_pull.targets |= (
        (. // [])
        | ([ .[] | select((.host // "") == $host) ][0] // {}) as $existing
        | map(select((.host // "") != $host))
        + [merged_target($existing)]
      )
    '
}


downmask_ab_pull_target_delete() {
    local host="$1"
    [ -n "$host" ] || pfwd_die "必须提供 --host"
    config_update --arg host "$host" '
      .settings.downmask.ab_pull.targets |= ((. // []) | map(select((.host // "") != $host)))
    '
}


downmask_ab_pull_targets_clear() {
    config_update '.settings.downmask.ab_pull.targets = []'
}


downmask_ab_pull_targets_json_list() {
    jq -c '.settings.downmask.ab_pull.targets // []' "$PFWD_CONFIG_FILE"
}


downmask_ab_pull_target_count() {
    jq '.settings.downmask.ab_pull.targets // [] | length' "$PFWD_CONFIG_FILE"
}


downmask_ab_pull_targets_table_rows() {
    jq -r '
      (.settings.downmask.ab_pull.targets // [])
      | to_entries[]
      | .key as $idx
      | .value as $item
      | [
          (($idx + 1) | tostring),
          ($item.host // ""),
          (if ($item.port // null) == null then "-" else ($item.port | tostring) end),
          (($item.weight // 1) | tostring),
          (if ($item | has("tcp_enabled")) then (if $item.tcp_enabled then "true" else "false" end) else "true" end),
          (if ($item | has("udp_enabled")) then (if $item.udp_enabled then "true" else "false" end) else "true" end),
          ($item.local_ip // ""),
          (if ($item.token // "") == "" then "-" else "set" end)
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE"
}


downmask_ab_pull_target_by_index() {
    local index="$1"
    jq -c --argjson idx "$index" '.settings.downmask.ab_pull.targets[$idx - 1] // {}' "$PFWD_CONFIG_FILE"
}


downmask_ab_pull_target_field_by_index() {
    local index="$1"
    local field="$2"
    jq -r --argjson idx "$index" --arg field "$field" '.settings.downmask.ab_pull.targets[$idx - 1][$field] // empty' "$PFWD_CONFIG_FILE"
}


downmask_ab_pull_targets_list() {
    jq -r '
      (.settings.downmask.ab_pull.targets // [])[]?
      | [
          (.host // ""),
          (if (.port // null) == null then "-" else (.port | tostring) end),
          ((.weight // 1) | tostring),
          (if has("tcp_enabled") then (if .tcp_enabled then "true" else "false" end) else "true" end),
          (if has("udp_enabled") then (if .udp_enabled then "true" else "false" end) else "true" end),
          (.local_ip // ""),
          (if (.token // "") == "" then "-" else "set" end)
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE"
}


downmask_pull_ab() {
    local planned="$1"
    local mode parallel_limit tcp_enabled udp_enabled total_actual tcp_planned udp_planned
    mode="$(downmask_config_get '.ab_pull.protocol_mode')"
    parallel_limit="$(downmask_config_get '.ab_pull.parallel_limit')"
    [ -n "$mode" ] || mode="single"
    [ -n "$parallel_limit" ] && [ "$parallel_limit" -ge 1 ] || parallel_limit=2

    total_actual=0
    if [ "$mode" = "parallel" ]; then
        downmask_ab_protocol_enabled tcp && tcp_enabled=1 || tcp_enabled=0
        downmask_ab_protocol_enabled udp && udp_enabled=1 || udp_enabled=0
        if [ "$tcp_enabled" -eq 0 ] && [ "$udp_enabled" -eq 0 ]; then
            echo 0
            return 0
        fi
        if [ "$tcp_enabled" -eq 1 ] && [ "$udp_enabled" -eq 1 ]; then
            IFS=$'\t' read -r tcp_planned udp_planned <<< "$(downmask_random_protocol_split "$planned")"
        elif [ "$tcp_enabled" -eq 1 ]; then
            tcp_planned="$planned"
            udp_planned=0
        else
            tcp_planned=0
            udp_planned="$planned"
        fi
        if [ "$parallel_limit" -ge 2 ] && [ "$tcp_enabled" -eq 1 ] && [ "$udp_enabled" -eq 1 ] && [ "$udp_planned" -gt 0 ]; then
            local tcp_tmp udp_tmp tcp_json udp_json tcp_actual udp_actual
            tcp_tmp="$(mktemp)"
            udp_tmp="$(mktemp)"
            (
                downmask_ab_pull_attempt_protocol "tcp" "$tcp_planned" >"$tcp_tmp"
            ) &
            local tcp_pid=$!
            (
                downmask_ab_pull_attempt_protocol "udp" "$udp_planned" >"$udp_tmp"
            ) &
            local udp_pid=$!
            wait "$tcp_pid" || true
            wait "$udp_pid" || true
            tcp_json="$(cat "$tcp_tmp" 2>/dev/null || echo '{}')"
            udp_json="$(cat "$udp_tmp" 2>/dev/null || echo '{}')"
            rm -f "$tcp_tmp" "$udp_tmp"
            tcp_actual="$(jq -r '.actual_bytes // 0' <<< "$tcp_json" 2>/dev/null || echo 0)"
            udp_actual="$(jq -r '.actual_bytes // 0' <<< "$udp_json" 2>/dev/null || echo 0)"
            [[ "$tcp_actual" =~ ^[0-9]+$ ]] || tcp_actual=0
            [[ "$udp_actual" =~ ^[0-9]+$ ]] || udp_actual=0
            total_actual=$((tcp_actual + udp_actual))
        else
            if [ "$tcp_enabled" -eq 1 ] && [ "$tcp_planned" -gt 0 ]; then
                local tcp_json tcp_actual
                tcp_json="$(downmask_ab_pull_attempt_protocol "tcp" "$tcp_planned")"
                tcp_actual="$(jq -r '.actual_bytes // 0' <<< "$tcp_json" 2>/dev/null || echo 0)"
                [[ "$tcp_actual" =~ ^[0-9]+$ ]] || tcp_actual=0
                total_actual=$((total_actual + tcp_actual))
            fi
            if [ "$udp_enabled" -eq 1 ] && [ "$udp_planned" -gt 0 ]; then
                local udp_json udp_actual
                udp_json="$(downmask_ab_pull_attempt_protocol "udp" "$udp_planned")"
                udp_actual="$(jq -r '.actual_bytes // 0' <<< "$udp_json" 2>/dev/null || echo 0)"
                [[ "$udp_actual" =~ ^[0-9]+$ ]] || udp_actual=0
                total_actual=$((total_actual + udp_actual))
            fi
        fi
        echo "$total_actual"
        return 0
    fi

    local protocol single_json single_actual
    protocol="$(downmask_config_get '.ab_pull.protocol')"
    [ -n "$protocol" ] || protocol="tcp"
    single_json="$(downmask_ab_pull_attempt_protocol "$protocol" "$planned")"
    single_actual="$(jq -r '.actual_bytes // 0' <<< "$single_json" 2>/dev/null || echo 0)"
    [[ "$single_actual" =~ ^[0-9]+$ ]] || single_actual=0
    echo "$single_actual"
}
