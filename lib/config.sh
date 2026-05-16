#!/usr/bin/env bash

config_default_json() {
    cat <<EOF
{
  "settings": {
    "nft_family": "inet",
    "nft_table": "pfwd",
    "forward_table": "port_forward",
    "domain_refresh_interval": "60s",
    "tc_interface": "",
    "forward": {
      "interface": ""
    },
    "default_listen_ip": "::",
    "default_random_port_range": "20000-30000",
    "guard": {
      "enabled": false,
      "tc_interface": "",
      "block_http": false,
      "block_tls": false,
      "block_socks": false,
      "protocol_skip_ports": []
    },
    "whitelist": {
      "enabled": false,
      "include_cn": true,
      "custom_cidrs": [],
      "source_url": "https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone",
      "last_good_source": "",
      "last_good_updated_at": null,
      "runtime_hash": ""
    }
  },
  "users": [],
  "forwards": []
}
EOF
}

PFWD_CONFIG_INITIALIZED=0

config_init() {
    [ "$PFWD_CONFIG_INITIALIZED" = "1" ] && [ -f "$PFWD_CONFIG_FILE" ] && return 0
    pfwd_require_jq
    pfwd_mkdirs
    if [ ! -f "$PFWD_CONFIG_FILE" ]; then
        config_default_json | jq '.' | pfwd_write_atomic "$PFWD_CONFIG_FILE"
    fi
    config_validate_file "$PFWD_CONFIG_FILE"
    PFWD_CONFIG_INITIALIZED=1
}

config_invalidate_cache() {
    PFWD_CONFIG_INITIALIZED=0
}

config_load() {
    config_init >/dev/null
    cat "$PFWD_CONFIG_FILE"
}

config_validate_file() {
    local file="$1"
    jq -e '
      type == "object"
      and (.users | type == "array")
      and (.forwards | type == "array")
      and (.settings | type == "object")
      and (.settings.forward | type == "object")
      and ((.settings.forward.interface // "") | type == "string")
      and all(.forwards[]?; (type == "object") and (.net | type == "object"))
    ' "$file" >/dev/null || pfwd_die "无效配置文件：$file"
}

config_export_bundle() {
    config_init >/dev/null
    stats_init >/dev/null
    jq -n \
      --slurpfile cfg "$PFWD_CONFIG_FILE" \
      --slurpfile stats "$PFWD_STATS_FILE" \
      --arg exported_at "$(pfwd_now_iso)" '
      {
        "exported_at": $exported_at,
        "config": $cfg[0],
        "stats": $stats[0]
      }
    '
}

config_validate_bundle_file() {
    local file="$1"
    [ -f "$file" ] || pfwd_die "导入文件不存在：$file"
    jq -e '
      type == "object"
      and (.config | type == "object")
      and (.stats | type == "object")
    ' "$file" >/dev/null || pfwd_die "无效导入文件：$file"

    local config_tmp stats_tmp
    config_tmp="$(mktemp)"
    stats_tmp="$(mktemp)"
    jq '.config' "$file" > "$config_tmp"
    jq '.stats' "$file" > "$stats_tmp"
    config_validate_file "$config_tmp"
    stats_validate_file "$stats_tmp"
    rm -f "$config_tmp" "$stats_tmp"
}

config_import_bundle() {
    local file="$1"
    local config_tmp stats_tmp

    config_validate_bundle_file "$file"
    pfwd_mkdirs

    config_tmp="$(mktemp)"
    stats_tmp="$(mktemp)"
    jq '.config' "$file" > "$config_tmp"
    jq '.stats' "$file" > "$stats_tmp"

    config_validate_file "$config_tmp"
    stats_validate_file "$stats_tmp"

    mv "$config_tmp" "$PFWD_CONFIG_FILE"
    mv "$stats_tmp" "$PFWD_STATS_FILE"
    PFWD_CONFIG_INITIALIZED=1
    config_disable_expired "$(pfwd_today)"
}

config_update() {
    [ "$#" -ge 1 ] || pfwd_die "config_update 需要 jq filter"
    pfwd_debug "config_update filter=${@: -1}"
    local args=("$@")
    local filter_index=$((${#args[@]} - 1))
    local filter="${args[$filter_index]}"
    unset 'args[$filter_index]'
    config_init >/dev/null
    local tmp
    tmp="$(mktemp "${PFWD_CONFIG_FILE}.tmp.XXXXXX")"
    jq "${args[@]}" "$filter" "$PFWD_CONFIG_FILE" > "$tmp"
    config_validate_file "$tmp"
    mv "$tmp" "$PFWD_CONFIG_FILE"
    PFWD_CONFIG_INITIALIZED=1
}

PFWD_CONFIG_SNAPSHOT=""
PFWD_CONFIG_SNAPSHOT_FILE=""

config_snapshot_load() {
    PFWD_CONFIG_SNAPSHOT="$(cat "$PFWD_CONFIG_FILE")"
    if [ -n "$PFWD_CONFIG_SNAPSHOT_FILE" ] && [ -f "$PFWD_CONFIG_SNAPSHOT_FILE" ]; then
        printf '%s' "$PFWD_CONFIG_SNAPSHOT" > "$PFWD_CONFIG_SNAPSHOT_FILE"
    else
        PFWD_CONFIG_SNAPSHOT_FILE="$(mktemp "${PFWD_RUN_DIR}/cfg_snap.XXXXXX")"
        printf '%s' "$PFWD_CONFIG_SNAPSHOT" > "$PFWD_CONFIG_SNAPSHOT_FILE"
    fi
}

config_snapshot_jq() {
    jq "$@" <<< "$PFWD_CONFIG_SNAPSHOT"
}

config_snapshot_file() {
    printf '%s' "$PFWD_CONFIG_SNAPSHOT_FILE"
}

config_snapshot_invalidate() {
    PFWD_CONFIG_SNAPSHOT=""
    if [ -n "$PFWD_CONFIG_SNAPSHOT_FILE" ]; then
        rm -f "$PFWD_CONFIG_SNAPSHOT_FILE"
        PFWD_CONFIG_SNAPSHOT_FILE=""
    fi
}

config_user_exists() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    jq -e --arg id "$user_id" '.users[]? | select(.id == $id)' "$PFWD_CONFIG_FILE" >/dev/null
}

config_forward_exists() {
    local forward_id="$1"
    jq -e --arg id "$forward_id" '.forwards[]? | select(.id == $id)' "$PFWD_CONFIG_FILE" >/dev/null
}

config_add_user() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    validate_user_id "$user_id"
    config_init >/dev/null
    if config_user_exists "$user_id"; then
        pfwd_die "用户已存在：$user_id"
    fi

    local now
    now="$(pfwd_now_iso)"
    config_update --arg id "$user_id" --arg now "$now" '
      .users += [{
        "id": $id,
        "created_at": $now,
        "telegram": {
          "enabled": false,
          "bot_token": "",
          "chat_id": "",
          "server_name": "",
          "schedule_interval_minutes": null,
          "schedule_daily_time": null,
          "last_interval_sent_at": null,
          "last_daily_sent_date": null
        },
        "limits": {
          "traffic_bytes": null,
          "rate": null,
          "traffic_mode": "two-way"
        }
      }]
    '
}

config_delete_user() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    validate_user_id "$user_id"
    config_init >/dev/null
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    local count
    count="$(jq --arg id "$user_id" '[.forwards[]? | select(.user_id == $id)] | length' "$PFWD_CONFIG_FILE")"
    [ "$count" = "0" ] || pfwd_die "该用户仍有转发规则，无法删除：$user_id"
    config_update --arg id "$user_id" '.users = [.users[] | select(.id != $id)]'
}

config_user_forward_count() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    validate_user_id "$user_id"
    config_init >/dev/null
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    jq -r --arg id "$user_id" '[.forwards[]? | select(.user_id == $id)] | length' "$PFWD_CONFIG_FILE"
}

config_user_forward_summary_tsv() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    validate_user_id "$user_id"
    config_init >/dev/null
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    jq -r --arg id "$user_id" '
      [.forwards[]? | select(.user_id == $id) | {
        listen_port,
        remote_host,
        remote_port,
        protocol: (.protocol // "tcp_udp"),
        enabled: (if .enabled then "true" else "false" end),
        stop_at: (.stop_at // "-"),
        sort_id: .id
      }]
      | sort_by(.listen_port, .sort_id)
      | .[]
      | [
          (.listen_port | tostring),
          .remote_host,
          (.remote_port | tostring),
          .protocol,
          .enabled,
          .stop_at
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE"
}

config_delete_user_cascade() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    validate_user_id "$user_id"
    config_init >/dev/null
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    config_update --arg id "$user_id" '
      .forwards = [.forwards[] | select(.user_id != $id)]
      | .users = [.users[] | select(.id != $id)]
    '
}

config_set_user_telegram() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local bot_token="$2"
    local chat_id="$3"
    local server_name="$4"
    local enabled="$5"

    validate_user_id "$user_id"
    validate_telegram_bot_token "$bot_token"
    validate_telegram_chat_id "$chat_id"
    validate_bool "$enabled"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"

    config_update \
      --arg id "$user_id" \
      --arg bot_token "$bot_token" \
      --arg chat_id "$chat_id" \
      --arg server_name "$server_name" \
      --argjson enabled "$enabled" '
      (.users[] | select(.id == $id) | .telegram) = {
        "enabled": $enabled,
        "bot_token": $bot_token,
        "chat_id": $chat_id,
        "server_name": $server_name,
        "schedule_interval_minutes": ((.users[]? | select(.id == $id) | .telegram.schedule_interval_minutes) // null),
        "schedule_daily_time": ((.users[]? | select(.id == $id) | .telegram.schedule_daily_time) // null),
        "last_interval_sent_at": ((.users[]? | select(.id == $id) | .telegram.last_interval_sent_at) // null),
        "last_daily_sent_date": ((.users[]? | select(.id == $id) | .telegram.last_daily_sent_date) // null)
      }
    '
}

config_set_all_users_telegram() {
    local bot_token="$1"
    local chat_id="$2"
    local server_name="$3"
    local enabled="$4"

    validate_telegram_bot_token "$bot_token"
    validate_telegram_chat_id "$chat_id"
    if [ "$enabled" != "__KEEP__" ]; then
        validate_bool "$enabled"
    fi
    config_init >/dev/null

    local user_count
    user_count="$(jq '.users | length' "$PFWD_CONFIG_FILE")"
    [ "$user_count" -gt 0 ] || pfwd_die "暂无用户，无法批量配置 Telegram"

    config_update \
      --arg bot_token "$bot_token" \
      --arg chat_id "$chat_id" \
      --arg server_name "$server_name" \
      --arg enabled "$enabled" '
      .users |= map(
        .telegram = {
          "enabled": (if $enabled == "__KEEP__" then (.telegram.enabled // false) else ($enabled == "true") end),
          "bot_token": $bot_token,
          "chat_id": $chat_id,
          "server_name": $server_name,
          "schedule_interval_minutes": (.telegram.schedule_interval_minutes // null),
          "schedule_daily_time": (.telegram.schedule_daily_time // null),
          "last_interval_sent_at": (.telegram.last_interval_sent_at // null),
          "last_daily_sent_date": (.telegram.last_daily_sent_date // null)
        }
      )
    '
}

config_set_user_telegram_schedule() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local interval_minutes="$2"
    local daily_time="$3"

    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    if [ "$interval_minutes" != "__KEEP__" ] && [ -n "$interval_minutes" ]; then
        validate_telegram_schedule_interval "$interval_minutes"
    fi
    if [ "$daily_time" != "__KEEP__" ] && [ -n "$daily_time" ]; then
        validate_hhmm_time "$daily_time"
    fi

    config_update \
      --arg id "$user_id" \
      --arg interval_raw "$interval_minutes" \
      --arg daily_time "$daily_time" '
      (if $interval_raw == "__KEEP__" then . else
            (.users[] | select(.id == $id) | .telegram.schedule_interval_minutes) =
              (if $interval_raw == "" then null else ($interval_raw | tonumber) end)
         end)
      | (if $daily_time == "__KEEP__" then . else
            (.users[] | select(.id == $id) | .telegram.schedule_daily_time) =
              (if $daily_time == "" then null else $daily_time end)
         end)
    '
}

config_user_telegram_is_configured() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    config_user_exists "$user_id" || return 1
    jq -e --arg id "$user_id" '
      .users[]?
      | select(.id == $id)
      | (.telegram.bot_token // "") != ""
      and (.telegram.chat_id // "") != ""
    ' "$PFWD_CONFIG_FILE" >/dev/null
}

config_enable_user_telegram() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    config_user_telegram_is_configured "$user_id" || pfwd_die "该用户尚未完整配置 Telegram，请先配置 Bot Token 和 Chat ID：$user_id"
    config_update --arg id "$user_id" '
      (.users[] | select(.id == $id) | .telegram.enabled) = true
    '
}

config_disable_user_telegram() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    config_update --arg id "$user_id" '
      (.users[] | select(.id == $id) | .telegram.enabled) = false
    '
}

config_delete_user_telegram() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    config_update --arg id "$user_id" '
      (.users[] | select(.id == $id) | .telegram) = {
        "enabled": false,
        "bot_token": "",
        "chat_id": "",
        "server_name": "",
        "schedule_interval_minutes": null,
        "schedule_daily_time": null,
        "last_interval_sent_at": null,
        "last_daily_sent_date": null
      }
    '
}

config_mark_user_telegram_interval_sent() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local sent_at="$2"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    [ -n "$sent_at" ] || pfwd_die "缺少发送时间"
    config_update --arg id "$user_id" --arg sent_at "$sent_at" '
      (.users[] | select(.id == $id) | .telegram.last_interval_sent_at) = $sent_at
    '
}

config_mark_user_telegram_daily_sent() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local sent_date="$2"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    [ -n "$sent_date" ] || pfwd_die "缺少发送日期"
    config_update --arg id "$user_id" --arg sent_date "$sent_date" '
      (.users[] | select(.id == $id) | .telegram.last_daily_sent_date) = $sent_date
    '
}

config_validate_new_forward() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local listen_ip="$2"
    local listen_port="$3"
    local remote="$4"
    local stop_at="$5"
    local traffic_mode="$6"
    local protocol="$7"
    local traffic_ratio="${8:-1.0}"
    local mss_mode="${9:-}"
    local mss_value="${10:-}"
    local snat_mode="${11:-masquerade}"
    local snat_source="${12:-}"

    validate_user_id "$user_id"
    validate_listen_ip "$listen_ip"
    validate_port "$listen_port"
    validate_host_port "$remote"
    validate_traffic_mode "$traffic_mode"
    validate_forward_protocol "$protocol"
    validate_traffic_ratio "$traffic_ratio"
    validate_mss_mode "$mss_mode"
    validate_snat_mode "$snat_mode"
    if [ "$mss_mode" = "set" ]; then
        validate_mss_value "$mss_value"
    elif [ -n "$mss_value" ]; then
        pfwd_die "仅在 --mss 模式下允许设置固定 MSS 值"
    fi
    if [ "$snat_mode" = "snat" ]; then
        [ -n "$snat_source" ] || pfwd_die "snat 模式必须提供源地址"
        validate_ip_literal "$snat_source"
    elif [ -n "$snat_source" ]; then
        pfwd_die "masquerade 模式不允许设置 snat_source"
    fi
    [ -z "$stop_at" ] || validate_date "$stop_at"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"

    local existing_protocols existing_protocol
    existing_protocols="$(jq -r --argjson port "$listen_port" '.forwards[]? | select(.listen_port == $port) | (.protocol // "tcp_udp")' "$PFWD_CONFIG_FILE")"
    while IFS= read -r existing_protocol; do
        [ -n "$existing_protocol" ] || continue
        if forward_protocols_conflict "$protocol" "$existing_protocol"; then
            pfwd_die "监听端口已配置冲突协议：$listen_port ($protocol vs $existing_protocol)"
        fi
    done <<< "$existing_protocols"
}

config_validate_forward_batch() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local listen_ip="$2"
    local listen_ports="$3"
    local remote_host="$4"
    local remote_ports="$5"
    local stop_at="$6"
    local traffic_mode="$7"
    local protocol="$8"
    local traffic_ratio="${9:-1.0}"
    local mss_mode="${10:-}"
    local mss_value="${11:-}"
    local snat_mode="${12:-masquerade}"
    local snat_source="${13:-}"

    validate_user_id "$user_id"
    validate_listen_ip "$listen_ip"
    validate_traffic_mode "$traffic_mode"
    validate_forward_protocol "$protocol"
    validate_traffic_ratio "$traffic_ratio"
    validate_mss_mode "$mss_mode"
    validate_snat_mode "$snat_mode"
    if [ "$mss_mode" = "set" ]; then
        validate_mss_value "$mss_value"
    elif [ -n "$mss_value" ]; then
        pfwd_die "仅在 --mss 模式下允许设置固定 MSS 值"
    fi
    if [ "$snat_mode" = "snat" ]; then
        [ -n "$snat_source" ] || pfwd_die "snat 模式必须提供源地址"
        validate_ip_literal "$snat_source"
    elif [ -n "$snat_source" ]; then
        pfwd_die "masquerade 模式不允许设置 snat_source"
    fi
    [ -z "$stop_at" ] || validate_date "$stop_at"
    [ -n "$remote_host" ] || pfwd_die "远端主机不能为空"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"

    local listen_count remote_count port seen_listen=""
    listen_count="$(printf '%s\n' "$listen_ports" | sed '/^$/d' | wc -l | tr -d ' ')"
    remote_count="$(printf '%s\n' "$remote_ports" | sed '/^$/d' | wc -l | tr -d ' ')"
    [ "$listen_count" = "$remote_count" ] || pfwd_die "监听端口数量和目标端口数量不一致：$listen_count != $remote_count"
    [ "$listen_count" -gt 0 ] || pfwd_die "端口不能为空"

    while IFS= read -r port; do
        [ -n "$port" ] || continue
        validate_port "$port"
        if [[ " $seen_listen " == *" $port "* ]]; then
            pfwd_die "监听端口重复：$port"
        fi
        seen_listen="$seen_listen $port"
        local existing_protocols existing_protocol
        existing_protocols="$(jq -r --argjson port "$port" '.forwards[]? | select(.listen_port == $port) | (.protocol // "tcp_udp")' "$PFWD_CONFIG_FILE")"
        while IFS= read -r existing_protocol; do
            [ -n "$existing_protocol" ] || continue
            if forward_protocols_conflict "$protocol" "$existing_protocol"; then
                pfwd_die "监听端口已配置冲突协议：$port ($protocol vs $existing_protocol)"
            fi
        done <<< "$existing_protocols"
    done <<< "$listen_ports"

    while IFS= read -r port; do
        [ -n "$port" ] || continue
        validate_port "$port"
    done <<< "$remote_ports"
}

config_add_forward() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local listen_ip="$2"
    local listen_port="$3"
    local remote="$4"
    local stop_at="$5"
    local traffic_mode="$6"
    local protocol="$7"
    local traffic_ratio="${8:-1.0}"
    local comment="${9:-}"
    local mss_mode="${10:-}"
    local mss_value="${11:-}"
    local snat_mode="${12:-masquerade}"
    local snat_source="${13:-}"

    [ -z "$stop_at" ] || stop_at="$(normalize_date_input "$stop_at")"
    traffic_ratio="$(normalize_traffic_ratio_input "$traffic_ratio")"
    config_validate_new_forward "$user_id" "$listen_ip" "$listen_port" "$remote" "$stop_at" "$traffic_mode" "$protocol" "$traffic_ratio" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source"

    local id now remote_host remote_port parsed
    id="$(pfwd_id fwd)"
    now="$(pfwd_now_iso)"
    parsed="$(parse_host_port "$remote")"
    remote_host="${parsed%	*}"
    remote_port="${parsed##*	}"

    config_update \
      --arg id "$id" \
      --arg user_id "$user_id" \
      --arg listen_ip "$listen_ip" \
      --argjson listen_port "$listen_port" \
      --arg remote_host "$remote_host" \
      --argjson remote_port "$remote_port" \
      --arg stop_at "$stop_at" \
      --arg traffic_mode "$traffic_mode" \
      --arg protocol "$protocol" \
      --arg traffic_ratio "$traffic_ratio" \
      --arg comment "$comment" \
      --arg mss_mode "$mss_mode" \
      --arg mss_value "$mss_value" \
      --arg snat_mode "$snat_mode" \
      --arg snat_source "$snat_source" \
      --arg now "$now" '
      .forwards += [{
        "id": $id,
        "user_id": $user_id,
        "listen_ip": $listen_ip,
        "listen_port": $listen_port,
        "remote_host": $remote_host,
        "remote_port": $remote_port,
        "protocol": $protocol,
        "enabled": true,
        "stop_at": (if $stop_at == "" then null else $stop_at end),
        "traffic_mode": $traffic_mode,
        "traffic_ratio": ($traffic_ratio | tonumber),
        "comment": (if $comment == "" then null else $comment end),
        "net": {
          "mss_mode": (if $mss_mode == "" then null else $mss_mode end),
          "mss_value": (if $mss_value == "" then null else ($mss_value | tonumber) end),
          "snat_mode": $snat_mode,
          "snat_source": (if $snat_source == "" then null else $snat_source end)
        },
        "limits": {
          "traffic_bytes": null,
          "rate": null
        },
        "created_at": $now
      }]
    '
    echo "$id"
}

config_add_forward_batch() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local listen_ip="$2"
    local listen_ports="$3"
    local remote_host="$4"
    local remote_ports="$5"
    local stop_at="$6"
    local traffic_mode="$7"
    local protocol="$8"
    local traffic_ratio="${9:-1.0}"
    local comment="${10:-}"
    local mss_mode="${11:-}"
    local mss_value="${12:-}"
    local snat_mode="${13:-masquerade}"
    local snat_source="${14:-}"

    [ -z "$stop_at" ] || stop_at="$(normalize_date_input "$stop_at")"
    traffic_ratio="$(normalize_traffic_ratio_input "$traffic_ratio")"
    config_validate_forward_batch "$user_id" "$listen_ip" "$listen_ports" "$remote_host" "$remote_ports" "$stop_at" "$traffic_mode" "$protocol" "$traffic_ratio" "$mss_mode" "$mss_value" "$snat_mode" "$snat_source"

    local count id now jq_forwards="[]" listen_port remote_port
    count="$(printf '%s\n' "$listen_ports" | sed '/^$/d' | wc -l | tr -d ' ')"
    now="$(pfwd_now_iso)"

    while IFS=$'\t' read -r listen_port remote_port; do
        [ -n "$listen_port" ] || continue
        id="$(pfwd_id fwd)"
        jq_forwards="$(jq -c \
          --argjson forwards "$jq_forwards" \
          --arg id "$id" \
          --arg user_id "$user_id" \
          --arg listen_ip "$listen_ip" \
          --argjson listen_port "$listen_port" \
          --arg remote_host "$remote_host" \
          --argjson remote_port "$remote_port" \
          --arg stop_at "$stop_at" \
          --arg traffic_mode "$traffic_mode" \
          --arg protocol "$protocol" \
          --arg traffic_ratio "$traffic_ratio" \
          --arg comment "$comment" \
          --arg mss_mode "$mss_mode" \
          --arg mss_value "$mss_value" \
          --arg snat_mode "$snat_mode" \
          --arg snat_source "$snat_source" \
          --arg now "$now" '
          $forwards + [{
            "id": $id,
            "user_id": $user_id,
            "listen_ip": $listen_ip,
            "listen_port": $listen_port,
            "remote_host": $remote_host,
            "remote_port": $remote_port,
            "protocol": $protocol,
            "enabled": true,
            "stop_at": (if $stop_at == "" then null else $stop_at end),
            "traffic_mode": $traffic_mode,
            "traffic_ratio": ($traffic_ratio | tonumber),
            "comment": (if $comment == "" then null else $comment end),
            "net": {
              "mss_mode": (if $mss_mode == "" then null else $mss_mode end),
              "mss_value": (if $mss_value == "" then null else ($mss_value | tonumber) end),
              "snat_mode": $snat_mode,
              "snat_source": (if $snat_source == "" then null else $snat_source end)
            },
            "limits": {
              "traffic_bytes": null,
              "rate": null
            },
            "created_at": $now
          }]
        ' <<< '{}')"
        echo "$id"
    done < <(paste <(printf '%s\n' "$listen_ports") <(printf '%s\n' "$remote_ports"))

    config_update --argjson new_forwards "$jq_forwards" '.forwards += $new_forwards' >/dev/null
}

config_set_forward_enabled() {
    local forward_id="$1"
    local enabled="$2"
    validate_bool "$enabled"
    config_forward_exists "$forward_id" || pfwd_die "转发规则不存在：$forward_id"
    config_update --arg id "$forward_id" --argjson enabled "$enabled" '
      (.forwards[] | select(.id == $id) | .enabled) = $enabled
    '
}

config_delete_forward() {
    local forward_id="$1"
    config_forward_exists "$forward_id" || pfwd_die "转发规则不存在：$forward_id"
    config_update --arg id "$forward_id" '.forwards = [.forwards[] | select(.id != $id)]'
}

config_clear_forward_expire() {
    local forward_id="$1"
    config_forward_exists "$forward_id" || pfwd_die "转发规则不存在：$forward_id"
    config_update --arg id "$forward_id" '
      (.forwards[] | select(.id == $id) | .stop_at) = null
    '
}

config_set_forward_expire() {
    local forward_id="$1"
    local stop_at
    stop_at="$(normalize_date_input "$2")"
    local now_minute
    now_minute="$(pfwd_now_minute)"
    config_forward_exists "$forward_id" || pfwd_die "转发规则不存在：$forward_id"
    config_update --arg id "$forward_id" --arg stop_at "$stop_at" --arg now "$now_minute" '
      (.forwards[] | select(.id == $id)) |= (
        .stop_at = $stop_at
        | if $stop_at > $now then .enabled = true else . end
      )
    '
}

config_set_user_forwards_expire() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local stop_at
    stop_at="$(normalize_date_input "$2")"
    local now_minute
    now_minute="$(pfwd_now_minute)"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    config_update --arg id "$user_id" --arg stop_at "$stop_at" --arg now "$now_minute" '
      .forwards |= map(
        if .user_id == $id then
          .stop_at = $stop_at
          | if $stop_at > $now then .enabled = true else . end
        else
          .
        end
      )
    '
}

config_clear_user_forwards_expire() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    config_update --arg id "$user_id" '
      .forwards |= map(
        if .user_id == $id then .stop_at = null else . end
      )
    '
}

config_set_forward_limit() {
    local forward_id="$1"
    local traffic_bytes="$2"
    local rate="$3"
    local traffic_mode="$4"
    config_forward_exists "$forward_id" || pfwd_die "转发规则不存在：$forward_id"
    [ -z "$traffic_mode" ] || validate_traffic_mode "$traffic_mode"

    config_update \
      --arg id "$forward_id" \
      --arg traffic_raw "$traffic_bytes" \
      --arg rate "$rate" \
      --arg traffic_mode "$traffic_mode" '
      (if $traffic_raw == "__KEEP__" then . else
            (.forwards[] | select(.id == $id) | .limits.traffic_bytes) = ($traffic_raw | fromjson)
         end)
      | (if $rate == "__KEEP__" then . else
            (.forwards[] | select(.id == $id) | .limits.rate) = (if $rate == "" then null else $rate end)
         end)
      | (if $traffic_mode == "" or $traffic_mode == "__KEEP__" then . else
            (.forwards[] | select(.id == $id) | .traffic_mode) = $traffic_mode
         end)
    '
}

config_set_user_limit() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local traffic_bytes="$2"
    local rate="$3"
    local traffic_mode="$4"
    validate_user_id "$user_id"
    [ -z "$traffic_mode" ] || validate_traffic_mode "$traffic_mode"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"

    config_update \
      --arg id "$user_id" \
      --arg traffic_raw "$traffic_bytes" \
      --arg rate "$rate" \
      --arg traffic_mode "$traffic_mode" '
      (if $traffic_raw == "__KEEP__" then . else
            (.users[] | select(.id == $id) | .limits.traffic_bytes) = ($traffic_raw | fromjson)
         end)
      | (if $rate == "__KEEP__" then . else
            (.users[] | select(.id == $id) | .limits.rate) = (if $rate == "" then null else $rate end)
         end)
      | (if $traffic_mode == "" or $traffic_mode == "__KEEP__" then . else
            (.users[] | select(.id == $id) | .limits.traffic_mode) = $traffic_mode
         end)
    '
}

config_set_user_forward_limits() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local traffic_bytes="$2"
    local rate="$3"
    local traffic_mode="$4"

    validate_user_id "$user_id"
    [ -z "$traffic_mode" ] || validate_traffic_mode "$traffic_mode"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"

    config_update \
      --arg id "$user_id" \
      --arg traffic_raw "$traffic_bytes" \
      --arg rate "$rate" \
      --arg traffic_mode "$traffic_mode" '
      .forwards |= map(
        if .user_id != $id then . else
          (if $traffic_raw == "__KEEP__" then . else
                .limits.traffic_bytes = ($traffic_raw | fromjson)
           end)
          | (if $rate == "__KEEP__" then . else
                .limits.rate = (if $rate == "" then null else $rate end)
             end)
          | (if $traffic_mode == "" or $traffic_mode == "__KEEP__" then . else
                .traffic_mode = $traffic_mode
             end)
        end
      )
    '
}

config_set_user_forwards_traffic_mode() {
    local user_id
    user_id="$(normalize_user_id "$1")"
    local traffic_mode="$2"
    validate_user_id "$user_id"
    validate_traffic_mode "$traffic_mode"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"

    config_update \
      --arg id "$user_id" \
      --arg traffic_mode "$traffic_mode" '
      .forwards |= map(
        if .user_id == $id then .traffic_mode = $traffic_mode else . end
      )
    '
}

config_keep_or_apply() {
    local raw="$1"
    local current="$2"
    local apply_mode="${3:-raw}"
    local apply_func="${4:-}"

    if [ "$raw" = "__KEEP__" ] || [ -z "$raw" ]; then
        printf '%s\n' "$current"
        return 0
    fi
    if [ -n "$apply_func" ]; then
        if [ "$apply_mode" = "transform" ]; then
            "$apply_func" "$raw"
        else
            "$apply_func" "$raw" >/dev/null
            printf '%s\n' "$raw"
        fi
        return 0
    fi
    printf '%s\n' "$raw"
}

config_keep_or_clear_or_apply() {
    local raw="$1"
    local current="$2"
    local apply_mode="${3:-raw}"
    local apply_func="${4:-}"

    case "$raw" in
        __KEEP__)
            printf '%s\n' "$current"
            ;;
        __CLEAR__|"")
            printf '\n'
            ;;
        *)
            if [ -n "$apply_func" ]; then
                if [ "$apply_mode" = "transform" ]; then
                    "$apply_func" "$raw"
                else
                    "$apply_func" "$raw" >/dev/null
                    printf '%s\n' "$raw"
                fi
            else
                printf '%s\n' "$raw"
            fi
            ;;
    esac
}

config_update_forward() {
    local forward_id="$1"
    local listen_ip_raw="$2"
    local listen_port_raw="$3"
    local remote_host_raw="$4"
    local remote_port_raw="$5"
    local stop_at_raw="$6"
    local protocol_raw="$7"
    local traffic_mode_raw="$8"
    local traffic_ratio_raw="${9:-__KEEP__}"
    local comment_raw="${10:-__KEEP__}"
    local mss_mode_raw="${11:-__KEEP__}"
    local mss_value_raw="${12:-__KEEP__}"
    local snat_mode_raw="${13:-__KEEP__}"
    local snat_source_raw="${14:-__KEEP__}"

    config_forward_exists "$forward_id" || pfwd_die "转发规则不存在：$forward_id"

    local current
    current="$(jq -c --arg id "$forward_id" '.forwards[] | select(.id == $id)' "$PFWD_CONFIG_FILE")"

    local current_listen_ip current_listen_port current_remote_host current_remote_port current_stop_at current_protocol current_traffic_mode current_traffic_ratio
    current_listen_ip="$(jq -r '.listen_ip // ""' <<< "$current")"
    current_listen_port="$(jq -r '.listen_port' <<< "$current")"
    current_remote_host="$(jq -r '.remote_host' <<< "$current")"
    current_remote_port="$(jq -r '.remote_port' <<< "$current")"
    current_stop_at="$(jq -r '.stop_at // ""' <<< "$current")"
    current_protocol="$(jq -r '.protocol // "tcp_udp"' <<< "$current")"
    current_traffic_mode="$(jq -r '.traffic_mode // "two-way"' <<< "$current")"
    current_traffic_ratio="$(jq -r '(.traffic_ratio // 1) | tostring' <<< "$current")"

    local new_listen_ip new_listen_port new_remote_host new_remote_port new_stop_at new_protocol new_traffic_mode new_traffic_ratio remote_spec
    local current_comment current_mss_mode current_mss_value current_snat_mode current_snat_source
    local new_comment new_mss_mode new_mss_value new_snat_mode new_snat_source
    local now_minute
    current_comment="$(jq -r '.comment // ""' <<< "$current")"
    current_mss_mode="$(jq -r '.net.mss_mode // ""' <<< "$current")"
    current_mss_value="$(jq -r '.net.mss_value // ""' <<< "$current")"
    current_snat_mode="$(jq -r '.net.snat_mode // "masquerade"' <<< "$current")"
    current_snat_source="$(jq -r '.net.snat_source // ""' <<< "$current")"
    now_minute="$(pfwd_now_minute)"

    new_listen_ip="$(config_keep_or_apply "$listen_ip_raw" "$current_listen_ip")"
    if [ "$listen_ip_raw" != "__KEEP__" ]; then
        validate_listen_ip "$listen_ip_raw"
    fi

    new_listen_port="$(config_keep_or_apply "$listen_port_raw" "$current_listen_port")"
    if [ "$listen_port_raw" != "__KEEP__" ]; then
        validate_port "$listen_port_raw"
    fi

    new_remote_host="$(config_keep_or_apply "$remote_host_raw" "$current_remote_host")"

    new_remote_port="$(config_keep_or_apply "$remote_port_raw" "$current_remote_port")"
    if [ "$remote_port_raw" != "__KEEP__" ]; then
        validate_port "$remote_port_raw"
    fi

    if [[ "$new_remote_host" == *:* ]]; then
        remote_spec="[$new_remote_host]:$new_remote_port"
    else
        remote_spec="$new_remote_host:$new_remote_port"
    fi
    validate_host_port "$remote_spec"

    case "$stop_at_raw" in
        __KEEP__)
            new_stop_at="$current_stop_at"
            ;;
        __CLEAR__)
            new_stop_at=""
            ;;
        *)
            new_stop_at="$(normalize_date_input "$stop_at_raw")"
            ;;
    esac

    new_protocol="$(config_keep_or_apply "$protocol_raw" "$current_protocol" validate validate_forward_protocol)"
    new_traffic_mode="$(config_keep_or_apply "$traffic_mode_raw" "$current_traffic_mode" validate validate_traffic_mode)"
    new_traffic_ratio="$(config_keep_or_apply "$traffic_ratio_raw" "$current_traffic_ratio" transform normalize_traffic_ratio_input)"
    new_comment="$(config_keep_or_clear_or_apply "$comment_raw" "$current_comment")"
    new_mss_mode="$(config_keep_or_clear_or_apply "$mss_mode_raw" "$current_mss_mode" validate validate_mss_mode)"
    new_mss_value="$(config_keep_or_clear_or_apply "$mss_value_raw" "$current_mss_value" validate validate_mss_value)"
    new_snat_mode="$(config_keep_or_apply "$snat_mode_raw" "$current_snat_mode" validate validate_snat_mode)"
    new_snat_source="$(config_keep_or_clear_or_apply "$snat_source_raw" "$current_snat_source" validate validate_ip_literal)"

    if [ "$new_mss_mode" = "set" ]; then
        [ -n "$new_mss_value" ] || pfwd_die "固定 MSS 模式必须提供 mss_value"
    elif [ -n "$new_mss_value" ]; then
        pfwd_die "仅在 mss_mode=set 时允许保留固定 MSS 值"
    fi
    if [ "$new_snat_mode" = "snat" ]; then
        [ -n "$new_snat_source" ] || pfwd_die "snat 模式必须提供 snat_source"
    elif [ -n "$new_snat_source" ]; then
        pfwd_die "masquerade 模式不允许设置 snat_source"
    fi

    local conflict_rows conflict_port conflict_protocol
    conflict_rows="$(jq -r --arg id "$forward_id" --argjson port "$new_listen_port" '
      .forwards[]?
      | select(.id != $id and .listen_port == $port)
      | [(.listen_port | tostring), (.protocol // "tcp_udp")] | @tsv
    ' "$PFWD_CONFIG_FILE")"
    while IFS=$'\t' read -r conflict_port conflict_protocol; do
        [ -n "$conflict_port" ] || continue
        if forward_protocols_conflict "$new_protocol" "$conflict_protocol"; then
            pfwd_die "监听端口已配置冲突协议：$new_listen_port ($new_protocol vs $conflict_protocol)"
        fi
    done <<< "$conflict_rows"

    config_update \
      --arg id "$forward_id" \
      --arg listen_ip "$new_listen_ip" \
      --argjson listen_port "$new_listen_port" \
      --arg remote_host "$new_remote_host" \
      --argjson remote_port "$new_remote_port" \
      --arg stop_at "$new_stop_at" \
      --arg protocol "$new_protocol" \
      --arg traffic_mode "$new_traffic_mode" \
      --arg traffic_ratio "$new_traffic_ratio" \
      --arg comment "$new_comment" \
      --arg mss_mode "$new_mss_mode" \
      --arg mss_value "$new_mss_value" \
      --arg snat_mode "$new_snat_mode" \
      --arg snat_source "$new_snat_source" \
      --arg now "$now_minute" '
      .forwards |= map(
        if .id == $id then
          .listen_ip = $listen_ip
          | .listen_port = $listen_port
          | .remote_host = $remote_host
          | .remote_port = $remote_port
          | .stop_at = (if $stop_at == "" then null else $stop_at end)
          | if $stop_at != "" and $stop_at > $now then .enabled = true else . end
          | .protocol = $protocol
          | .traffic_mode = $traffic_mode
          | .traffic_ratio = ($traffic_ratio | tonumber)
          | .comment = (if $comment == "" then null else $comment end)
          | .net = {
              "mss_mode": (if $mss_mode == "" then null else $mss_mode end),
              "mss_value": (if $mss_value == "" then null else ($mss_value | tonumber) end),
              "snat_mode": $snat_mode,
              "snat_source": (if $snat_source == "" then null else $snat_source end)
            }
        else
          .
        end
      )
    '
}

config_disable_expired() {
    local now_minute="$1"
    config_update --arg now "$now_minute" '
      .forwards |= map(
        if .enabled == true and .stop_at != null and .stop_at <= $now
        then .enabled = false
        else .
        end
      )
    '
}

config_disable_telegram_for_expired_users() {
    config_init >/dev/null
    local now_minute="$1"
    config_update --arg now "$now_minute" '
      . as $cfg
      | .users |= map(
          . as $user
          | if (($user.telegram.enabled // false) != true) then
            .
          else
            ([ $cfg.forwards[]? | select(.user_id == $user.id) ]) as $forwards
            | ([ $forwards[] | select(.enabled == true and (.stop_at == null or .stop_at > $now)) ] | length) as $active_count
            | ([ $forwards[] | select(.stop_at != null and .stop_at <= $now) ] | length) as $expired_count
            | if (($forwards | length) > 0 and $active_count == 0 and $expired_count > 0) then
                .telegram.enabled = false
              else
                .
              end
          end
        )
    '
}
