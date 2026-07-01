#!/usr/bin/env bash

ui_format_bytes_or_dash() {
    local value="$1"
    if [ "$value" = "-" ] || [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "-"
    else
        format_bytes "$value"
    fi
}


ui_display_or_dash() {
    local value="$1"
    case "$value" in
        ""|"-"|"null"|"不限"|"不自动重置"|"未设置") echo "-" ;;
        *) echo "$value" ;;
    esac
}


ui_progress_bar() {
    local used="$1" limit="$2" width="${3:-10}"
    local pct i bar=""
    if [ "$limit" = "null" ] || [ -z "$limit" ] || [ "$limit" = "0" ] || [ "$limit" = "-" ]; then
        printf '[%s]' "$(printf '%*s' "$width" '' | tr ' ' '-')"
        return
    fi
    pct=$((used * 100 / limit))
    [ "$pct" -le 100 ] || pct=100
    local filled=$((pct * width / 100))
    for ((i = 0; i < width; i++)); do
        if [ "$i" -lt "$filled" ]; then
            bar+="="
        else
            bar+="-"
        fi
    done
    printf '[%s] %d%%' "$bar" "$pct"
}


ui_format_limit() {
    local value="$1"
    if [ "$value" = "-" ] || [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "-"
    else
        format_bytes "$value"
    fi
}


ui_format_rate() {
    local value="$1"
    if [ "$value" = "-" ] || [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "-"
    else
        echo "$value"
    fi
}


ui_format_reset_day() {
    local value="$1"
    reset_day_display "$value"
}


ui_main_usage_config_file() {
    if [ -n "$PFWD_CONFIG_SNAPSHOT_FILE" ] && [ -f "$PFWD_CONFIG_SNAPSHOT_FILE" ]; then
        printf '%s\n' "$PFWD_CONFIG_SNAPSHOT_FILE"
    else
        printf '%s\n' "$PFWD_CONFIG_FILE"
    fi
}


ui_main_usage_stats_json() {
    local stats_json="${1:-}"
    [ -n "$stats_json" ] || stats_json="$(fw_read_counters 2>/dev/null || true)"
    if [ -z "$stats_json" ] || ! jq -e '
      type == "object"
      and ((.users // null) | type == "array")
      and ((.forwards // null) | type == "array")
    ' >/dev/null 2>&1 <<< "$stats_json"; then
        printf '%s\n' '{"users":[],"forwards":[]}'
        return 0
    fi
    printf '%s\n' "$stats_json"
}


ui_main_usage_build_json() {
    local cfg_file stats_json
    cfg_file="$(ui_main_usage_config_file)"
    stats_json="$(ui_main_usage_stats_json)"

    jq -n \
      --slurpfile cfg "$cfg_file" \
      --argjson stats "$stats_json" '
      def user_stats($id):
        ($stats.users // [] | map(select(.id == $id)) | .[0] // {});
      def forward_stats($id):
        ($stats.forwards // [] | map(select(.id == $id)) | .[0] // {});
      {
        users: [
          $cfg[0].users[]? as $u
          | $u + {
              input_bytes: ((user_stats($u.id).input_bytes // 0) | tonumber),
              output_bytes: ((user_stats($u.id).output_bytes // 0) | tonumber),
              one_way_bytes: ((user_stats($u.id).one_way_bytes // 0) | tonumber),
              two_way_bytes: ((user_stats($u.id).two_way_bytes // 0) | tonumber),
              billing_used_bytes: ((user_stats($u.id).billing_used_bytes // 0) | tonumber),
              reset_day: (user_stats($u.id).reset_day // null)
            }
        ],
        forwards: [
          $cfg[0].forwards[]? as $f
          | $f + {
              input_bytes: ((forward_stats($f.id).input_bytes // 0) | tonumber),
              output_bytes: ((forward_stats($f.id).output_bytes // 0) | tonumber),
              one_way_bytes: ((forward_stats($f.id).one_way_bytes // 0) | tonumber),
              two_way_bytes: ((forward_stats($f.id).two_way_bytes // 0) | tonumber),
              total_bytes: (
                if (forward_stats($f.id) | has("total_bytes")) then
                  ((forward_stats($f.id).total_bytes // 0) | tonumber)
                else
                  (((forward_stats($f.id).one_way_bytes // 0) | tonumber) + ((forward_stats($f.id).two_way_bytes // 0) | tonumber))
                end
              ),
              billing_used_bytes: ((forward_stats($f.id).billing_used_bytes // 0) | tonumber)
            }
        ]
      }'
}


ui_main_usage_json() {
    ui_cached_data "main_usage_json" ui_main_usage_build_json
}


ui_forward_usage_json() {
    ui_main_usage_json
}


ui_load_user_config_tsv() {
    jq -r --arg id "$1" '
      .users[]? | select(.id == $id) |
      [
        (.limits.traffic_bytes // "null"),
        (.limits.rate // "null"),
        ([.id] | .[0])
      ] | @tsv
    ' "$PFWD_CONFIG_FILE"
}


ui_user_forward_count() {
    jq -r --arg id "$1" '[.forwards[]? | select(.user_id == $id)] | length' "$PFWD_CONFIG_FILE"
}


ui_main_user_rows() {
    local data="$1"
    jq -r '
      . as $data
      | .users[]? as $u
      | ($data.forwards | map(select(.user_id == $u.id)) | length) as $count
      | [
          $u.id,
          ($count | tostring),
          (($u.billing_used_bytes // 0) | tostring),
          (($u.two_way_bytes // 0) | tostring),
          (($u.one_way_bytes // 0) | tostring),
          (($u.limits.traffic_bytes // "null") | tostring),
          (($u.reset_day // "-") | tostring)
        ]
      | @tsv
    ' <<< "$data"
}


ui_main_forward_count() {
    local data="$1"
    jq -r '.forwards | length' <<< "$data"
}


ui_main_forward_rows() {
    local data="$1"
    local limit="${2:-0}"
    [[ "$limit" =~ ^[0-9]+$ ]] || limit=0
    jq -r --argjson limit "$limit" '
      . as $data
      | .forwards
      | sort_by(.user_id, .listen_port, .id)
      | (if $limit > 0 then .[:$limit] else . end)
      | .[]?
      | . as $forward
      | (($data.users | map(select(.id == $forward.user_id)) | .[0].limits.rate) // null) as $user_rate
      | [
          (if $forward.enabled then "true" else "false" end),
          $forward.user_id,
          ($forward.listen_ip // "::"),
          ($forward.listen_port | tostring),
          $forward.remote_host,
          ($forward.remote_port | tostring),
          ($forward.input_bytes // "0"),
          ($forward.output_bytes // "0"),
          ($forward.stop_at // "-"),
          (($forward.traffic_ratio // 1) | tostring),
          (($forward.limits.rate // $user_rate) // "null"),
          (if ($forward.comment // "") == "" then "-" else $forward.comment end)
        ]
      | @tsv
    ' <<< "$data"
}


ui_user_list_rows() {
    local allow_zero="${1:-false}"
    local rows=""
    local index=1
    local user_id
    if [ "$allow_zero" = "true" ]; then
        rows+=$'0\t返回\n'
    fi
    while IFS= read -r user_id; do
        rows+="$index"$'\t'"$user_id"$'\n'
        index=$((index + 1))
    done < <(jq -r '.users[]?.id' "$PFWD_CONFIG_FILE")
    printf '%s' "${rows%$'\n'}"
}


ui_forward_list_rows() {
    local rows=""
    while IFS=$'\t' read -r index user enabled listen_ip listen_port remote_host remote_port protocol stop_at mode ratio mss_display snat_display comment; do
        local listen remote
        listen="$(ui_format_listen_compact "$listen_ip" "$listen_port")"
        remote="$(ui_format_remote "$remote_host" "$remote_port")"
        rows+="$index"$'\t'"$user"$'\t'"$listen"$'\t'"$remote"$'\t'"$(ui_protocol_label "$protocol")"$'\t'"$enabled"$'\t'"$stop_at"$'\t'"$mode"$'\t'"$(format_ratio "$ratio")"$'\t'"$mss_display"$'\t'"$snat_display"$'\t'"$(ui_display_or_dash "$comment")"$'\n'
    done < <(jq -r '
      (.forwards | sort_by(.user_id, .listen_port, .id))
      | to_entries[]
      | [
          ((.key + 1) | tostring),
          .value.user_id,
          (if .value.enabled then "启用" else "停用" end),
          (.value.listen_ip // "::"),
          (.value.listen_port | tostring),
          .value.remote_host,
          (.value.remote_port | tostring),
          (.value.protocol // "tcp_udp"),
          (.value.stop_at // "-"),
          (if (.value.traffic_mode // "two-way") == "one-way" then "单向" else "双向" end),
          ((.value.traffic_ratio // 1) | tostring),
          (
            if (.value.net.mss_mode // "") == "set" then
              ((.value.net.mss_value // "-") | tostring)
            elif (.value.net.mss_mode // "") == "clamp" then
              "clamp"
            else
              "-"
            end
          ),
          (
            if (.value.net.snat_mode // "masquerade") == "snat" and (.value.net.snat_source // "") != "" then
              .value.net.snat_source
            else
              "masquerade"
            end
          ),
          (if (.value.comment // "") == "" then "-" else .value.comment end)
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE")
    printf '%s' "${rows%$'\n'}"
}


ui_telegram_configured_user_rows() {
    jq -r '
      .users[]?
      | select((.telegram.bot_token // "") != "" and (.telegram.chat_id // "") != "")
      | [
          .id,
          (if (.telegram.enabled // false) then "已启用" else "已停用" end),
          (
            [
              (if (.telegram.schedule_interval_minutes // null) == null
               then "间隔 -"
               else "间隔 " + ((.telegram.schedule_interval_minutes | tostring) + "m")
               end),
              (if (.telegram.schedule_daily_time // null) == null
               then "每日 -"
               else "每日 " + .telegram.schedule_daily_time
               end)
            ] | join(" | ")
          )
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE"
}


ui_forward_select_rows() {
    local allow_zero="${1:-false}"
    local rows=""
    if [ "$allow_zero" = "true" ]; then
        rows+=$'0\t返回\t-\t-\t-\t-\t-\n'
    fi
    while IFS=$'\t' read -r index user listen_port remote_host remote_port protocol enabled stop_at; do
        local remote_text
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        rows+="$index"$'\t'"$user"$'\t'"$listen_port"$'\t'"$remote_text"$'\t'"$(ui_protocol_label "$protocol")"$'\t'"$enabled"$'\t'"$stop_at"$'\n'
    done < <(jq -r '
      (.forwards | sort_by(.user_id, .listen_port, .id))
      | to_entries[]
      | [
          ((.key + 1) | tostring),
          .value.user_id,
          (.value.listen_port | tostring),
          .value.remote_host,
          (.value.remote_port | tostring),
          (.value.protocol // "tcp_udp"),
          (if .value.enabled then "启用" else "停用" end),
          (.value.stop_at // "-")
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE")
    printf '%s' "${rows%$'\n'}"
}


ui_user_forward_select_rows() {
    local user_id="$1"
    local allow_zero="${2:-false}"
    local include_all="${3:-false}"
    local rows="" aggregate_state
    if [ "$allow_zero" = "true" ]; then
        rows+=$'0\t返回\t-\t-\t-\t-\n'
    fi
    if [ "$include_all" = "true" ]; then
        aggregate_state="$(ui_forward_aggregate_state "$user_id")"
        rows+="1"$'\t'"全部端口"$'\t'"-"$'\t'"-"$'\t'"$aggregate_state"$'\t'"-"$'\n'
    fi
    while IFS=$'\t' read -r index listen_port remote_host remote_port protocol enabled stop_at; do
        local remote_text
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        rows+="$index"$'\t'"$listen_port"$'\t'"$remote_text"$'\t'"$(ui_protocol_label "$protocol")"$'\t'"$enabled"$'\t'"$stop_at"$'\n'
    done < <(jq -r --arg id "$user_id" --argjson start_index "$( [ "$include_all" = "true" ] && echo 2 || echo 1 )" '
      ([.forwards[] | select(.user_id == $id)] | sort_by(.listen_port, .id))
      | to_entries[]
      | [
          ((.key + $start_index) | tostring),
          (.value.listen_port | tostring),
          .value.remote_host,
          (.value.remote_port | tostring),
          (.value.protocol // "tcp_udp"),
          (if .value.enabled then "启用" else "停用" end),
          (.value.stop_at // "-")
        ]
      | @tsv
    ' "$PFWD_CONFIG_FILE")
    printf '%s' "${rows%$'\n'}"
}


ui_user_forward_summary_rows() {
    local user_id="$1"
    local rows=""
    local listen_port remote_host remote_port protocol enabled stop_at remote_text
    while IFS=$'\t' read -r listen_port remote_host remote_port protocol enabled stop_at; do
        [ -n "$listen_port" ] || continue
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        rows+="$listen_port"$'\t'"$remote_text"$'\t'"$(ui_protocol_label "$protocol")"$'\t'"$enabled"$'\t'"$stop_at"$'\n'
    done < <(config_user_forward_summary_tsv "$user_id")
    printf '%s' "${rows%$'\n'}"
}


ui_user_delete_forward_rows() {
    local user_id="$1"
    local rows=""
    local listen_port remote_host remote_port protocol enabled stop_at remote_text
    while IFS=$'\t' read -r listen_port remote_host remote_port protocol enabled stop_at; do
        [ -n "$listen_port" ] || continue
        remote_text="$(ui_format_remote "$remote_host" "$remote_port")"
        rows+="$listen_port"$'\t'"$remote_text"$'\t'"$(ui_protocol_label "$protocol")"$'\t'"$enabled"$'\n'
    done < <(config_user_forward_summary_tsv "$user_id")
    printf '%s' "${rows%$'\n'}"
}
