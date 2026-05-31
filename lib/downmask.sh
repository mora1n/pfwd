#!/usr/bin/env bash

DOWNMASK_BUILTIN_SOURCES="cloudflare_dynamic linode_tokyo_100mb cachefly_100mb"

downmask_is_builtin_public_source() {
    local name="$1"
    case "$name" in
        cloudflare_dynamic|linode_tokyo_100mb|cachefly_100mb) return 0 ;;
        *) return 1 ;;
    esac
}

validate_downmask_public_source_name() {
    local value="$1"
    [ -n "$value" ] || pfwd_die "active_source 不能为空"
    downmask_is_builtin_public_source "$value" && return 0
    case "$value" in
        digitalocean_100mb|aliyun_ubuntu_iso)
            pfwd_die "内置公网源已移除：$value；请改用 cloudflare_dynamic、linode_tokyo_100mb、cachefly_100mb，或使用 public custom 自定义源"
            ;;
        *)
            pfwd_die "未知内置公网源：$value；请改用 cloudflare_dynamic、linode_tokyo_100mb、cachefly_100mb，或使用 public custom 自定义源"
            ;;
    esac
}

downmask_validate_configured_active_source() {
    local active custom
    active="$(downmask_config_get '.public.active_source')"
    [ -n "$active" ] || return 0
    if downmask_is_builtin_public_source "$active"; then
        return 0
    fi
    custom="$(jq -r --arg name "$active" '.settings.downmask.public.custom_sources[]? | select(.name == $name) | .name' "$PFWD_CONFIG_FILE" | head -n1)"
    [ -n "$custom" ] && return 0
    validate_downmask_public_source_name "$active"
}

downmask_config_get() {
    local subpath="$1"
    config_init >/dev/null
    jq -r ".settings.downmask$subpath // empty" "$PFWD_CONFIG_FILE"
}

downmask_config_get_raw() {
    local subpath="$1"
    config_init >/dev/null
    jq -c ".settings.downmask$subpath" "$PFWD_CONFIG_FILE"
}

downmask_iface() {
    local iface
    iface="$(downmask_config_get '.iface')"
    if [ -n "$iface" ]; then
        echo "$iface"
        return
    fi
    forwarder_iface
}

downmask_read_iface_bytes() {
    local iface="$1"
    local rx tx
    rx="$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo 0)"
    tx="$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo 0)"
    printf '%s\t%s\n' "$rx" "$tx"
}

downmask_state_file() {
    echo "$PFWD_DOWNMASK_STATE_DIR/day_state.json"
}

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

downmask_random_percent_factor() {
    local percent="$1"
    awk -v percent="$percent" -v seed="$RANDOM$$" '
    BEGIN {
        srand(seed)
        if (percent <= 0) {
            printf "1.000000"
            exit
        }
        span = percent / 100.0
        min = 1.0 - span
        max = 1.0 + span
        if (min < 0.05) min = 0.05
        printf "%.6f", min + rand() * (max - min)
    }'
}

downmask_apply_percent_jitter() {
    local base="$1"
    local percent="$2"
    awk -v base="$base" -v factor="$(downmask_random_percent_factor "$percent")" '
    BEGIN {
        value = base * factor
        if (value < 1) value = 1
        printf "%.0f", value
    }'
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

    local remote_host remote_port token local_ip wanted_bps rate_bps wanted_bytes
    remote_host="$(downmask_resolve_target_field "$target_json" "host")"
    remote_port="$(downmask_resolve_target_field "$target_json" "port")"
    token="$(downmask_resolve_target_field "$target_json" "token")"
    local_ip="$(downmask_resolve_target_field "$target_json" "local_ip")"
    [ -n "$remote_port" ] || remote_port="$shared_port"
    [ -n "$token" ] || token="$shared_token"
    [ -n "$local_ip" ] || local_ip="$shared_local_ip"

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

downmask_load_day_state() {
    local file
    file="$(downmask_state_file)"
    if [ -f "$file" ]; then
        cat "$file"
    else
        echo '{}'
    fi
}

downmask_save_day_state() {
    local payload="$1"
    local file
    file="$(downmask_state_file)"
    mkdir -p "$(dirname "$file")"
    printf '%s\n' "$payload" | jq '.' | pfwd_write_atomic "$file"
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
          (if ($item.tcp_enabled // null) == null then "true" elif $item.tcp_enabled then "true" else "false" end),
          (if ($item.udp_enabled // null) == null then "true" elif $item.udp_enabled then "true" else "false" end),
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
          (if (.tcp_enabled // null) == null then "true" elif .tcp_enabled then "true" else "false" end),
          (if (.udp_enabled // null) == null then "true" elif .udp_enabled then "true" else "false" end),
          (.local_ip // ""),
          (if (.token // "") == "" then "-" else "set" end)
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE"
}

downmask_random_ratio() {
    local min="$1"
    local max="$2"
    awk -v min="$min" -v max="$max" -v seed="$RANDOM$$" 'BEGIN { srand(seed); printf "%.4f", min + rand() * (max - min) }'
}

downmask_in_time_window() {
    local now start end
    now="$(date '+%H:%M')"
    start="$(downmask_config_get '.time_window_start')"
    end="$(downmask_config_get '.time_window_end')"
    [ -n "$start" ] && [ -n "$end" ] || return 0
    if [[ "$start" < "$end" || "$start" == "$end" ]]; then
        [[ "$now" > "$start" || "$now" == "$start" ]] && [[ "$now" < "$end" ]]
    else
        [[ "$now" > "$start" || "$now" == "$start" ]] || [[ "$now" < "$end" ]]
    fi
}

downmask_now_epoch() {
    date '+%s'
}

downmask_random_jitter_until() {
    local max_jitter="$1"
    local base
    base="$(downmask_now_epoch)"
    [ "$max_jitter" -gt 0 ] || { echo "$base"; return; }
    local offset=$((RANDOM % max_jitter))
    echo $((base + offset))
}

downmask_public_source_url() {
    local name="$1"
    local bytes="$2"
    case "$name" in
        cloudflare_dynamic)
            printf 'query|https://speed.cloudflare.com/__down?bytes=%s\n' "$bytes"
            ;;
        linode_tokyo_100mb)
            printf 'range|https://speedtest.tokyo2.linode.com/100MB-tokyo2.bin\n'
            ;;
        cachefly_100mb)
            printf 'range|http://cachefly.cachefly.net/100mb.test\n'
            ;;
        *)
            return 1
            ;;
    esac
}

downmask_resolve_active_source() {
    local active bytes
    active="$(downmask_config_get '.public.active_source')"
    bytes="$1"
    [ -n "$active" ] || active="cloudflare_dynamic"
    if downmask_is_builtin_public_source "$active" && downmask_public_source_url "$active" "$bytes" 2>/dev/null; then
        return 0
    fi
    local custom
    custom="$(jq -r --arg name "$active" '.settings.downmask.public.custom_sources[]? | select(.name == $name) | "\(.kind)|\(.url)"' "$PFWD_CONFIG_FILE" | head -n1)"
    if [ -n "$custom" ]; then
        local kind url
        kind="${custom%%|*}"
        url="${custom#*|}"
        case "$kind" in
            query)
                printf 'query|%s\n' "${url//\{bytes\}/$bytes}"
                return 0
                ;;
            range|*)
                printf 'range|%s\n' "$url"
                return 0
                ;;
        esac
    fi
    downmask_public_source_url "cloudflare_dynamic" "$bytes"
}

downmask_pull_public() {
    local planned="$1"
    local resolved kind url speed_limit
    speed_limit="$(downmask_config_get '.public.speed_limit')"
    [ -n "$speed_limit" ] || speed_limit="4M"
    resolved="$(downmask_resolve_active_source "$planned")" || return 1
    kind="${resolved%%|*}"
    url="${resolved#*|}"
    [ -n "$url" ] || return 1
    command -v curl >/dev/null 2>&1 || { echo 0; return 0; }
    local actual=0
    case "$kind" in
        query)
            local query_meta query_code
            query_meta="$(curl -fsSL --max-time 1800 --limit-rate "$speed_limit" -o /dev/null -w '%{http_code} %{size_download}' "$url" 2>/dev/null || echo '000 0')"
            query_code="${query_meta%% *}"
            actual="${query_meta##* }"
            if [ "$query_code" != "200" ] || ! [[ "$actual" =~ ^[0-9]+$ ]] || [ "$actual" -le 0 ]; then
                actual=0
            fi
            ;;
        range)
            local size probe_start probe_end content_length start_offset request_bytes range_meta range_code
            size="$(curl -fsSI --max-time 30 "$url" 2>/dev/null | awk 'BEGIN{IGNORECASE=1} /^content-length:/ {gsub("\r","",$2); print $2; exit}')"
            request_bytes="$planned"
            if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -gt 0 ]; then
                if [ "$planned" -ge "$size" ]; then
                    request_bytes="$size"
                fi
            fi
            if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -gt 0 ] && [ "$request_bytes" -lt "$size" ]; then
                start_offset="$(awk -v max="$size" -v want="$request_bytes" -v seed="$RANDOM$$" 'BEGIN { srand(seed); span = max - want; if (span < 1) span = 1; printf "%.0f", rand() * span }')"
                probe_start="$start_offset"
                probe_end=$((start_offset + request_bytes - 1))
            else
                probe_start=0
                probe_end=$((request_bytes - 1))
            fi
            range_meta="$(curl -fsSL --max-time 1800 --limit-rate "$speed_limit" -r "${probe_start}-${probe_end}" -o /dev/null -w '%{http_code} %{size_download}' "$url" 2>/dev/null || echo '000 0')"
            range_code="${range_meta%% *}"
            actual="${range_meta##* }"
            if ! [[ "$actual" =~ ^[0-9]+$ ]]; then
                actual=0
            fi
            if [ "$range_code" != "206" ] || [ "$actual" -ne "$request_bytes" ]; then
                actual=0
            fi
            ;;
    esac
    [[ "$actual" =~ ^[0-9]+$ ]] || actual=0
    echo "$actual"
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

downmask_speed_to_bps() {
    downmask_rate_to_bytes_per_second "$1" 2>/dev/null || echo 0
}

downmask_systemd_quote_arg() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//%/%%}"
    printf '"%s"' "$value"
}

downmask_systemd_join_exec() {
    local out="" arg
    for arg in "$@"; do
        out+=" $(downmask_systemd_quote_arg "$arg")"
    done
    printf '%s\n' "${out# }"
}

downmask_config_section() {
    local path="$1"
    jq -c "$path // {}" "$PFWD_CONFIG_FILE"
}

downmask_state_get_fields() {
    local state_json="$1"
    jq -r '[
        (.date // ""),
        (if .target_ratio == null then "" else (.target_ratio | tostring) end),
        (.rx_accum // 0),
        (.tx_accum // 0),
        (.last_rx_raw // 0),
        (.last_tx_raw // 0),
        (.next_eligible_at // 0)
    ] | @tsv' <<< "$state_json"
}

downmask_reconcile_pull() {
    config_init >/dev/null
    downmask_validate_configured_active_source
    local downmask_cfg pull_mode iface today state
    downmask_cfg="$(downmask_config_section '.settings.downmask')"
    pull_mode="$(jq -r '.pull_mode // "off"' <<< "$downmask_cfg")"
    [ -n "$pull_mode" ] && [ "$pull_mode" != "off" ] || return 0
    iface="$(downmask_iface)"
    [ -n "$iface" ] || return 0
    [ -d "/sys/class/net/$iface" ] || return 0

    today="$(pfwd_today)"
    state="$(downmask_load_day_state)"

    local raw_rx_tx raw_rx raw_tx
    raw_rx_tx="$(downmask_read_iface_bytes "$iface")"
    raw_rx="${raw_rx_tx%%$'\t'*}"
    raw_tx="${raw_rx_tx##*$'\t'}"

    local state_fields state_date target_ratio rx_accum tx_accum last_rx last_tx next_eligible
    state_fields="$(downmask_state_get_fields "$state")"
    IFS=$'\t' read -r state_date target_ratio rx_accum tx_accum last_rx last_tx next_eligible <<< "$state_fields"

    if [ "$state_date" != "$today" ] || [ -z "$target_ratio" ]; then
        local min_r max_r
        min_r="$(jq -r '.min_ratio // 1.5' <<< "$downmask_cfg")"
        max_r="$(jq -r '.max_ratio // 2.8' <<< "$downmask_cfg")"
        target_ratio="$(downmask_random_ratio "$min_r" "$max_r")"
        rx_accum=0
        tx_accum=0
        last_rx="$raw_rx"
        last_tx="$raw_tx"
        next_eligible=0
        state_date="$today"
    else
        local delta_rx delta_tx
        if [ "$raw_rx" -ge "$last_rx" ]; then
            delta_rx=$((raw_rx - last_rx))
        else
            delta_rx="$raw_rx"
        fi
        if [ "$raw_tx" -ge "$last_tx" ]; then
            delta_tx=$((raw_tx - last_tx))
        else
            delta_tx="$raw_tx"
        fi
        rx_accum=$((rx_accum + delta_rx))
        tx_accum=$((tx_accum + delta_tx))
        last_rx="$raw_rx"
        last_tx="$raw_tx"
    fi

    local now_epoch action="skip" reason="" actual=0 planned=0
    now_epoch="$(downmask_now_epoch)"

    local commit_state
    commit_state() {
        local last_action="${1:-$action}"
        local last_actual="${2:-$actual}"
        local last_planned="${3:-$planned}"
        local last_error="${4:-$reason}"
        local payload
        payload="$(jq -n \
            --arg date "$state_date" \
            --arg iface "$iface" \
            --arg target_ratio "$target_ratio" \
            --argjson rx_accum "$rx_accum" \
            --argjson tx_accum "$tx_accum" \
            --argjson last_rx_raw "$last_rx" \
            --argjson last_tx_raw "$last_tx" \
            --argjson next_eligible_at "$next_eligible" \
            --arg last_action "$last_action" \
            --argjson last_actual "$last_actual" \
            --argjson last_planned "$last_planned" \
            --arg last_error "$last_error" \
            --arg updated_at "$(pfwd_now_iso)" '
            {
                date: $date,
                iface: $iface,
                target_ratio: ($target_ratio | tonumber),
                rx_accum: $rx_accum,
                tx_accum: $tx_accum,
                last_rx_raw: $last_rx_raw,
                last_tx_raw: $last_tx_raw,
                next_eligible_at: $next_eligible_at,
                last_action: $last_action,
                last_actual_bytes: $last_actual,
                last_planned_bytes: $last_planned,
                last_error: $last_error,
                updated_at: $updated_at
            }')"
        downmask_save_day_state "$payload"
    }

    if ! downmask_in_time_window; then
        reason="out_of_window"
        commit_state
        return 0
    fi

    if [ "$now_epoch" -lt "$next_eligible" ]; then
        reason="waiting_jitter"
        commit_state
        return 0
    fi

    local debt
    debt="$(awk -v r="$target_ratio" -v tx="$tx_accum" -v rx="$rx_accum" 'BEGIN { d = (r * tx) - rx; if (d < 0) d = 0; printf "%.0f", d }')"

    local min_deficit max_per_run
    min_deficit="$(jq -r '.min_deficit_bytes // 0' <<< "$downmask_cfg")"
    max_per_run="$(jq -r '.max_bytes_per_run // 0' <<< "$downmask_cfg")"

    if [ "$debt" -lt "$min_deficit" ]; then
        reason="below_min_deficit"
        commit_state
        return 0
    fi

    planned="$debt"
    if [ "$max_per_run" -gt 0 ] && [ "$planned" -gt "$max_per_run" ]; then
        planned="$max_per_run"
    fi

    case "$pull_mode" in
        public)
            actual="$(downmask_pull_public "$planned" 2>/dev/null || echo 0)"
            action="public"
            ;;
        ab)
            actual="$(downmask_pull_ab "$planned" 2>/dev/null || echo 0)"
            action="ab"
            ;;
        *)
            reason="invalid_pull_mode"
            commit_state
            return 0
            ;;
    esac
    [[ "$actual" =~ ^[0-9]+$ ]] || actual=0

    if [ "$actual" -eq 0 ]; then
        reason="pull_failed"
    fi

    local jitter
    jitter="$(jq -r '.max_jitter_seconds // 0' <<< "$downmask_cfg")"
    next_eligible="$(downmask_random_jitter_until "$jitter")"

    commit_state
}

downmask_feed_unit_path() {
    echo "$PFWD_SYSTEMD_DIR/pfwd-downmask-feed.service"
}

downmask_write_feed_unit_if_needed() {
    config_init >/dev/null
    local tcp_enabled udp_enabled
    tcp_enabled="$(downmask_config_get '.ab_feed.tcp_enabled')"
    udp_enabled="$(downmask_config_get '.ab_feed.udp_enabled')"
    local unit_path
    unit_path="$(downmask_feed_unit_path)"

    if [ "$tcp_enabled" != "true" ] && [ "$udp_enabled" != "true" ]; then
        rm -f "$unit_path"
        return 0
    fi

    local bind_ip tcp_port udp_port token seed_file payload max_rate
    bind_ip="$(downmask_config_get '.ab_feed.bind_ip')"
    tcp_port="$(downmask_config_get '.ab_feed.tcp_port')"
    udp_port="$(downmask_config_get '.ab_feed.udp_port')"
    token="$(downmask_config_get '.ab_feed.token')"
    seed_file="$(downmask_config_get '.ab_feed.seed_file')"
    payload="$(downmask_config_get '.ab_feed.udp_payload_bytes')"
    max_rate=0

    [ -n "$bind_ip" ] || bind_ip="0.0.0.0"
    [ -n "$payload" ] || payload=1200

    local addr_prefix
    case "$bind_ip" in
        *:*) addr_prefix="[$bind_ip]" ;;
        *)   addr_prefix="$bind_ip" ;;
    esac
    local -a exec_args
    exec_args=(
        "$PFWD_DOWNMASK_BIN_PATH"
        "serve"
        "--token" "$token"
        "--status-file" "$PFWD_DOWNMASK_STATUS_FILE"
        "--max-rate" "$max_rate"
        "--udp-payload-bytes" "$payload"
    )
    if [ -n "$seed_file" ]; then
        exec_args+=("--seed-file" "$seed_file")
    fi
    if [ "$tcp_enabled" = "true" ] && [ -n "$tcp_port" ] && [ "$tcp_port" != "0" ]; then
        exec_args+=("--tcp-addr" "$addr_prefix:$tcp_port")
    fi
    if [ "$udp_enabled" = "true" ] && [ -n "$udp_port" ] && [ "$udp_port" != "0" ]; then
        exec_args+=("--udp-addr" "$addr_prefix:$udp_port")
    fi
    local exec_line
    exec_line="$(downmask_systemd_join_exec "${exec_args[@]}")"

    mkdir -p "$PFWD_SYSTEMD_DIR" "$PFWD_DOWNMASK_STATE_DIR"
    cat > "$unit_path" <<EOF
[Unit]
Description=pfwd downmask feeder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$exec_line
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

downmask_reload_feed_service() {
    command -v systemctl >/dev/null 2>&1 || return 0
    downmask_write_feed_unit_if_needed
    pfwd_run systemctl daemon-reload
    local tcp_enabled udp_enabled
    tcp_enabled="$(downmask_config_get '.ab_feed.tcp_enabled')"
    udp_enabled="$(downmask_config_get '.ab_feed.udp_enabled')"
    if [ "$tcp_enabled" = "true" ] || [ "$udp_enabled" = "true" ]; then
        pfwd_run systemctl enable pfwd-downmask-feed.service
        pfwd_run systemctl restart pfwd-downmask-feed.service
    else
        pfwd_run systemctl stop pfwd-downmask-feed.service || true
        pfwd_run systemctl disable pfwd-downmask-feed.service || true
        rm -f "$PFWD_DOWNMASK_STATUS_FILE"
    fi
}

downmask_status_json() {
    config_init >/dev/null
    downmask_validate_configured_active_source
    local cfg state feed ab_targets
    cfg="$(jq -c '.settings.downmask // {}' "$PFWD_CONFIG_FILE")"
    state="$(downmask_load_day_state)"
    ab_targets="$(downmask_ab_pull_targets_json)"
    if [ -f "$PFWD_DOWNMASK_STATUS_FILE" ]; then
        feed="$(cat "$PFWD_DOWNMASK_STATUS_FILE" 2>/dev/null || echo '{}')"
    else
        feed='{}'
    fi
    jq -n \
        --argjson config "$cfg" \
        --argjson state "$state" \
        --argjson ab_targets "$ab_targets" \
        --argjson feed "$feed" '
        {
            config: $config,
            day_state: $state,
            ab_targets: $ab_targets,
            feed: $feed
        }'
}

downmask_render_status() {
    local json pull_mode iface ratio rx tx debt action feed_tcp feed_udp ab_targets protocol_mode
    downmask_validate_configured_active_source
    json="$(downmask_status_json)"
    pull_mode="$(jq -r '.config.pull_mode // "off"' <<< "$json")"
    iface="$(jq -r '.day_state.iface // .config.iface // "-"' <<< "$json")"
    ratio="$(jq -r '.day_state.target_ratio // "-"' <<< "$json")"
    rx="$(jq -r '.day_state.rx_accum // 0' <<< "$json")"
    tx="$(jq -r '.day_state.tx_accum // 0' <<< "$json")"
    action="$(jq -r '.day_state.last_action // "-"' <<< "$json")"
    feed_tcp="$(jq -r '.feed.tcp_listening // false' <<< "$json")"
    feed_udp="$(jq -r '.feed.udp_listening // false' <<< "$json")"
    ab_targets="$(jq -r '.ab_targets | length' <<< "$json")"
    protocol_mode="$(jq -r '.config.ab_pull.protocol_mode // "single"' <<< "$json")"
    debt="$(awk -v r="$ratio" -v tx="$tx" -v rx="$rx" 'BEGIN { if (r == "-") { print "-" } else { d = (r * tx) - rx; if (d < 0) d = 0; printf "%.0f", d } }')"

    printf 'pull_mode\t%s\n' "$pull_mode"
    printf 'iface\t%s\n' "$iface"
    printf 'target_ratio\t%s\n' "$ratio"
    printf 'rx_accum\t%s\n' "$rx"
    printf 'tx_accum\t%s\n' "$tx"
    printf 'debt\t%s\n' "$debt"
    printf 'last_action\t%s\n' "$action"
    printf 'ab_protocol_mode\t%s\n' "$protocol_mode"
    printf 'ab_targets\t%s\n' "$ab_targets"
    printf 'feed_tcp\t%s\n' "$feed_tcp"
    printf 'feed_udp\t%s\n' "$feed_udp"
}

cmd_downmask() {
    config_init >/dev/null
    local sub="${1:-status}"
    shift || true
    case "$sub" in
        status) downmask_status_json | jq '.' ;;
        policy) cmd_downmask_policy "$@" ;;
        public) cmd_downmask_public "$@" ;;
        ab-pull) cmd_downmask_ab_pull "$@" ;;
        ab-feed) cmd_downmask_ab_feed "$@" ;;
        seed) cmd_downmask_seed "$@" ;;
        help|-h|--help)
            cat <<'EOF'
用法：
  pfwd downmask status
  pfwd downmask policy [--pull-mode off|public|ab] [--min-ratio N] [--max-ratio N] [--time-window-start HH:MM|empty=all-day] [--time-window-end HH:MM|empty=all-day] [--max-jitter SEC] [--min-deficit-bytes 20MB] [--max-bytes-per-run 800MB] [--iface NAME]
  pfwd downmask public [--active-source NAME(cloudflare_dynamic|linode_tokyo_100mb|cachefly_100mb)] [--speed-limit 4M(default, bytes/s; also 32Mbps/4MB/s)]
  pfwd downmask public custom add --name NAME --kind query|range --url URL(query 用 {bytes} 占位；range 需支持 Range 请求)
  pfwd downmask public custom delete --name NAME
  pfwd downmask public custom list
  pfwd downmask public custom clear
  pfwd downmask ab-pull [--protocol tcp|udp] [--protocol-mode single|parallel] [--tcp-enabled true|false] [--udp-enabled true|false] [--remote-host HOST(IP)] [--remote-port PORT] [--local-ip IP] [--token TOKEN(openssl rand -hex 16)] [--speed-limit 4M(default, bytes/s; also 32Mbps/4MB/s)] [--timeout SEC] [--parallel-limit N] [--speed-jitter-percent 12] [--bytes-jitter-percent 18]
  pfwd downmask ab-pull targets list|add|update|delete|clear ...
  pfwd downmask ab-feed [--tcp-enabled true|false] [--udp-enabled true|false] [--bind-ip IP] [--tcp-port PORT] [--udp-port PORT] [--token TOKEN(openssl rand -hex 16)] [--seed-file PATH] [--udp-payload-bytes 1200|1.2KB]
  pfwd downmask seed generate [--path PATH] [--size 1GB]   # 推荐 256MB-4GB
EOF
            ;;
        *) pfwd_die "未知 downmask 子命令：$sub" ;;
    esac
}

cmd_downmask_policy() {
    local pull_mode="" min_ratio="" max_ratio="" tws="" twe="" jitter="" mindef="" maxrun="" iface=""
    local tws_set=0 twe_set=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --pull-mode) pull_mode="$2"; shift 2 ;;
            --min-ratio) min_ratio="$2"; shift 2 ;;
            --max-ratio) max_ratio="$2"; shift 2 ;;
            --time-window-start) tws="$2"; tws_set=1; shift 2 ;;
            --time-window-end) twe="$2"; twe_set=1; shift 2 ;;
            --max-jitter) jitter="$2"; shift 2 ;;
            --min-deficit-bytes) mindef="$2"; shift 2 ;;
            --max-bytes-per-run) maxrun="$2"; shift 2 ;;
            --iface) iface="$2"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -z "$pull_mode" ] || validate_downmask_pull_mode "$pull_mode"
    [ -z "$min_ratio" ] || validate_downmask_ratio "$min_ratio"
    [ -z "$max_ratio" ] || validate_downmask_ratio "$max_ratio"
    [ -z "$tws" ] || validate_downmask_time_window "$tws"
    [ -z "$twe" ] || validate_downmask_time_window "$twe"
    [ -z "$jitter" ] || [[ "$jitter" =~ ^[0-9]+$ ]] || pfwd_die "max-jitter 必须是非负整数"
    [ -z "$mindef" ] || mindef="$(parse_downmask_size_bytes "$mindef")"
    [ -z "$maxrun" ] || maxrun="$(parse_downmask_size_bytes "$maxrun")"
    config_update \
        --arg pull_mode "$pull_mode" \
        --arg min_ratio "$min_ratio" \
        --arg max_ratio "$max_ratio" \
        --arg tws "$tws" \
        --arg twe "$twe" \
        --argjson tws_set "$tws_set" \
        --argjson twe_set "$twe_set" \
        --arg jitter "$jitter" \
        --arg mindef "$mindef" \
        --arg maxrun "$maxrun" \
        --arg iface "$iface" '
        .settings.downmask |= (
            (if $pull_mode == "" then . else .pull_mode = $pull_mode end)
            | (if $min_ratio == "" then . else .min_ratio = ($min_ratio | tonumber) end)
            | (if $max_ratio == "" then . else .max_ratio = ($max_ratio | tonumber) end)
            | (if $tws_set == 1 then .time_window_start = $tws else . end)
            | (if $twe_set == 1 then .time_window_end = $twe else . end)
            | (if $jitter == "" then . else .max_jitter_seconds = ($jitter | tonumber) end)
            | (if $mindef == "" then . else .min_deficit_bytes = ($mindef | tonumber) end)
            | (if $maxrun == "" then . else .max_bytes_per_run = ($maxrun | tonumber) end)
            | (if $iface == "" then . else .iface = $iface end)
        )'
    echo "已更新 downmask 策略"
}

cmd_downmask_public() {
    if [ "${1:-}" = "custom" ]; then
        shift
        cmd_downmask_public_custom "$@"
        return
    fi
    local active="" speed=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --active-source) active="$2"; shift 2 ;;
            --speed-limit) speed="$2"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -z "$active" ] || validate_downmask_public_source_name "$active"
    [ -z "$speed" ] || validate_downmask_speed_limit "$speed"
    config_update \
        --arg active "$active" \
        --arg speed "$speed" '
        .settings.downmask.public |= (
            (if $active == "" then . else .active_source = $active end)
            | (if $speed == "" then . else .speed_limit = $speed end)
        )'
    echo "已更新公网拉流配置"
}

cmd_downmask_public_custom() {
    local sub="${1:-list}"
    shift || true
    case "$sub" in
        list)
            jq -r '.settings.downmask.public.custom_sources[]? | "\(.name)\t\(.kind)\t\(.url)"' "$PFWD_CONFIG_FILE"
            ;;
        clear)
            config_update '.settings.downmask.public.custom_sources = []'
            echo "已清空自定义公网源"
            ;;
        add)
            local name="" kind="" url=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --name) name="$2"; shift 2 ;;
                    --kind) kind="$2"; shift 2 ;;
                    --url) url="$2"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$name" ] && [ -n "$url" ] || pfwd_die "--name 与 --url 必填"
            case "$kind" in query|range) ;; *) pfwd_die "--kind 必须是 query 或 range" ;; esac
            config_update --arg name "$name" --arg kind "$kind" --arg url "$url" '
                .settings.downmask.public.custom_sources |=
                  ((. // []) | map(select(.name != $name)) + [{name: $name, kind: $kind, url: $url}])
            '
            echo "已添加自定义源：$name"
            ;;
        delete)
            local name=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --name) name="$2"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$name" ] || pfwd_die "--name 必填"
            config_update --arg name "$name" '
                .settings.downmask.public.custom_sources |= ((. // []) | map(select(.name != $name)))
            '
            echo "已删除自定义源：$name"
            ;;
        *) pfwd_die "用法：pfwd downmask public custom list|clear|add|delete" ;;
    esac
}

cmd_downmask_ab_pull() {
    if [ "${1:-}" = "targets" ]; then
        shift
        local sub="${1:-list}"
        shift || true
        case "$sub" in
            list)
                downmask_ab_pull_targets_list
                ;;
            clear)
                downmask_ab_pull_targets_clear
                echo "已清空 AB 拉流 B机池"
                ;;
            add|update)
                local host="" port="" local_ip="" token="" weight="" tcp_enabled="" udp_enabled=""
                while [ "$#" -gt 0 ]; do
                    case "$1" in
                        --host) host="$2"; shift 2 ;;
                        --port) port="$2"; shift 2 ;;
                        --local-ip) local_ip="$2"; shift 2 ;;
                        --token) token="$2"; shift 2 ;;
                        --weight) weight="$2"; shift 2 ;;
                        --tcp-enabled) tcp_enabled="$2"; shift 2 ;;
                        --udp-enabled) udp_enabled="$2"; shift 2 ;;
                        *) pfwd_die "未知选项：$1" ;;
                    esac
                done
                downmask_ab_pull_target_update "$host" "$port" "$token" "$local_ip" "$weight" "$tcp_enabled" "$udp_enabled"
                echo "已更新 AB 拉流 B机：$host"
                ;;
            delete)
                local host=""
                while [ "$#" -gt 0 ]; do
                    case "$1" in
                        --host) host="$2"; shift 2 ;;
                        *) pfwd_die "未知选项：$1" ;;
                    esac
                done
                downmask_ab_pull_target_delete "$host"
                echo "已删除 AB 拉流 B机：$host"
                ;;
            *)
                pfwd_die "用法：pfwd downmask ab-pull targets list|add|update|delete|clear"
                ;;
        esac
        return 0
    fi

    local protocol="" protocol_mode="" tcp_enabled="" udp_enabled="" remote_host="" remote_port="" local_ip="" token="" speed="" timeout="" parallel_limit="" speed_jitter="" bytes_jitter=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --protocol) protocol="$2"; shift 2 ;;
            --protocol-mode) protocol_mode="$2"; shift 2 ;;
            --tcp-enabled) tcp_enabled="$2"; shift 2 ;;
            --udp-enabled) udp_enabled="$2"; shift 2 ;;
            --remote-host) remote_host="$2"; shift 2 ;;
            --remote-port) remote_port="$2"; shift 2 ;;
            --local-ip) local_ip="$2"; shift 2 ;;
            --token) token="$2"; shift 2 ;;
            --speed-limit) speed="$2"; shift 2 ;;
            --timeout) timeout="$2"; shift 2 ;;
            --parallel-limit) parallel_limit="$2"; shift 2 ;;
            --speed-jitter-percent) speed_jitter="$2"; shift 2 ;;
            --bytes-jitter-percent) bytes_jitter="$2"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -z "$protocol" ] || validate_downmask_protocol "$protocol"
    [ -z "$protocol_mode" ] || validate_downmask_protocol_mode "$protocol_mode"
    [ -z "$tcp_enabled" ] || validate_bool "$tcp_enabled"
    [ -z "$udp_enabled" ] || validate_bool "$udp_enabled"
    [ -z "$remote_host" ] || validate_downmask_target_host "$remote_host"
    [ -z "$remote_port" ] || validate_port "$remote_port"
    [ -z "$local_ip" ] || validate_downmask_local_ip "$local_ip"
    [ -z "$token" ] || validate_downmask_token "$token"
    [ -z "$speed" ] || validate_downmask_speed_limit "$speed"
    [ -z "$timeout" ] || [[ "$timeout" =~ ^[0-9]+$ ]] || pfwd_die "timeout 必须是非负整数"
    [ -z "$parallel_limit" ] || validate_downmask_parallel_limit "$parallel_limit"
    [ -z "$speed_jitter" ] || validate_downmask_percent "speed-jitter-percent" "$speed_jitter"
    [ -z "$bytes_jitter" ] || validate_downmask_percent "bytes-jitter-percent" "$bytes_jitter"
    config_update \
        --arg protocol "$protocol" \
        --arg protocol_mode "$protocol_mode" \
        --arg tcp_enabled "$tcp_enabled" \
        --arg udp_enabled "$udp_enabled" \
        --arg remote_host "$remote_host" \
        --arg remote_port "$remote_port" \
        --arg local_ip "$local_ip" \
        --arg token "$token" \
        --arg speed "$speed" \
        --arg timeout "$timeout" \
        --arg parallel_limit "$parallel_limit" \
        --arg speed_jitter "$speed_jitter" \
        --arg bytes_jitter "$bytes_jitter" '
        .settings.downmask.ab_pull |= (
            (if $protocol == "" then . else .protocol = $protocol end)
            | (if $protocol_mode == "" then . else .protocol_mode = $protocol_mode end)
            | (if $tcp_enabled == "" then . else .tcp_enabled = ($tcp_enabled == "true") end)
            | (if $udp_enabled == "" then . else .udp_enabled = ($udp_enabled == "true") end)
            | (if $remote_host == "" then . else .remote_host = $remote_host end)
            | (if $remote_port == "" then . else .remote_port = ($remote_port | tonumber) end)
            | (if $local_ip == "" then . else .local_ip = $local_ip end)
            | (if $token == "" then . else .token = $token end)
            | (if $speed == "" then . else .speed_limit = $speed end)
            | (if $timeout == "" then . else .timeout_seconds = ($timeout | tonumber) end)
            | (if $parallel_limit == "" then . else .parallel_limit = ($parallel_limit | tonumber) end)
            | (if $speed_jitter == "" then . else .speed_jitter_percent = ($speed_jitter | tonumber) end)
            | (if $bytes_jitter == "" then . else .bytes_jitter_percent = ($bytes_jitter | tonumber) end)
        )'
    echo "已更新 AB 拉流配置"
}

cmd_downmask_ab_feed() {
    local tcp="" udp="" bind="" tcp_port="" udp_port="" token="" seed_file="" payload=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --tcp-enabled) tcp="$2"; shift 2 ;;
            --udp-enabled) udp="$2"; shift 2 ;;
            --bind-ip) bind="$2"; shift 2 ;;
            --tcp-port) tcp_port="$2"; shift 2 ;;
            --udp-port) udp_port="$2"; shift 2 ;;
            --token) token="$2"; shift 2 ;;
            --seed-file) seed_file="$2"; shift 2 ;;
            --udp-payload-bytes) payload="$2"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -z "$tcp" ] || validate_bool "$tcp"
    [ -z "$udp" ] || validate_bool "$udp"
    [ -z "$bind" ] || validate_downmask_bind_ip "$bind"
    [ -z "$tcp_port" ] || validate_port "$tcp_port"
    [ -z "$udp_port" ] || validate_port "$udp_port"
    if [ -n "$payload" ]; then
        payload="$(parse_downmask_size_bytes "$payload")"
        validate_downmask_udp_payload_bytes "$payload"
    fi

    local cur_tcp cur_udp cur_tcp_port cur_udp_port cur_token
    cur_tcp="$(downmask_config_get '.ab_feed.tcp_enabled')"
    cur_udp="$(downmask_config_get '.ab_feed.udp_enabled')"
    cur_tcp_port="$(downmask_config_get '.ab_feed.tcp_port')"
    cur_udp_port="$(downmask_config_get '.ab_feed.udp_port')"
    cur_token="$(downmask_config_get '.ab_feed.token')"
    local eff_tcp eff_udp eff_tcp_port eff_udp_port eff_token
    eff_tcp="${tcp:-$cur_tcp}"
    eff_udp="${udp:-$cur_udp}"
    eff_tcp_port="${tcp_port:-$cur_tcp_port}"
    eff_udp_port="${udp_port:-$cur_udp_port}"
    eff_token="${token:-$cur_token}"

    if [ "$eff_tcp" = "true" ] && { [ -z "$eff_tcp_port" ] || [ "$eff_tcp_port" = "0" ]; }; then
        pfwd_die "启用 TCP 喂流必须设置有效的 --tcp-port"
    fi
    if [ "$eff_udp" = "true" ] && { [ -z "$eff_udp_port" ] || [ "$eff_udp_port" = "0" ]; }; then
        pfwd_die "启用 UDP 喂流必须设置有效的 --udp-port"
    fi

    if [ "$eff_tcp" = "true" ] || [ "$eff_udp" = "true" ]; then
        if [ -z "$eff_token" ]; then
            pfwd_die "启用 ab-feed 必须设置 --token"
        fi
    fi

    config_update \
        --arg tcp "$tcp" \
        --arg udp "$udp" \
        --arg bind "$bind" \
        --arg tcp_port "$tcp_port" \
        --arg udp_port "$udp_port" \
        --arg token "$token" \
        --arg seed_file "$seed_file" \
        --arg payload "$payload" '
        .settings.downmask.ab_feed |= (
            (if $tcp == "" then . else .tcp_enabled = ($tcp == "true") end)
            | (if $udp == "" then . else .udp_enabled = ($udp == "true") end)
            | (if $bind == "" then . else .bind_ip = $bind end)
            | (if $tcp_port == "" then . else .tcp_port = ($tcp_port | tonumber) end)
            | (if $udp_port == "" then . else .udp_port = ($udp_port | tonumber) end)
            | (if $token == "" then . else .token = $token end)
            | (if $seed_file == "" then . else .seed_file = $seed_file end)
            | (if $payload == "" then . else .udp_payload_bytes = ($payload | tonumber) end)
        )'
    downmask_reload_feed_service
    echo "已更新 AB 喂流配置"
}

cmd_downmask_seed() {
    local sub="${1:-generate}"
    shift || true
    [ "$sub" = "generate" ] || pfwd_die "用法：pfwd downmask seed generate [--path PATH] [--size 1GB]"
    local path="" size=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --path) path="$2"; shift 2 ;;
            --size) size="$2"; shift 2 ;;
            *) pfwd_die "未知选项：$1" ;;
        esac
    done
    [ -x "$PFWD_DOWNMASK_BIN_PATH" ] || pfwd_die "pfwd-downmask 二进制不存在：$PFWD_DOWNMASK_BIN_PATH"
    [ -z "$size" ] || size="$(parse_downmask_size_bytes "$size")"
    local args=("seed" "generate")
    [ -z "$path" ] || args+=("--path" "$path")
    [ -z "$size" ] || args+=("--size" "$size")
    "$PFWD_DOWNMASK_BIN_PATH" "${args[@]}"
}
