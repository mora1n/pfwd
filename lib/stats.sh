#!/usr/bin/env bash

stats_default_json() {
    cat <<'EOF'
{
  "users": {},
  "forwards": {}
}
EOF
}

stats_init() {
    pfwd_require_jq
    pfwd_mkdirs
    if [ ! -f "$PFWD_STATS_FILE" ]; then
        stats_default_json | jq '.' | pfwd_write_atomic "$PFWD_STATS_FILE"
    fi
    stats_validate_file "$PFWD_STATS_FILE"
}

stats_validate_file() {
    local file="$1"
    jq -e '
      type == "object"
      and (.users | type == "object")
      and (.forwards | type == "object")
    ' "$file" >/dev/null || pfwd_die "无效流量状态文件：$file"
}

stats_update() {
    [ "$#" -ge 1 ] || pfwd_die "stats_update 需要 jq filter"
    local args=("$@")
    local filter_index=$((${#args[@]} - 1))
    local filter="${args[$filter_index]}"
    unset 'args[$filter_index]'
    stats_init >/dev/null
    local tmp
    tmp="$(mktemp "${PFWD_STATS_FILE}.tmp.XXXXXX")"
    jq "${args[@]}" "$filter" "$PFWD_STATS_FILE" > "$tmp"
    stats_validate_file "$tmp"
    mv "$tmp" "$PFWD_STATS_FILE"
}

stats_forward_snapshot_json() {
    local nft_text="$1"
    jq -n --arg text "$nft_text" --slurpfile cfg "$PFWD_CONFIG_FILE" '
      def counter_bytes($name):
        reduce ($text | split("\n")[]) as $line (
          {in_block: false, value: null};
          if ($line | test("^\\s*counter " + $name + " \\{$")) then
            .in_block = true
          elif .in_block and ($line | test("bytes [0-9]+")) then
            .value = (($line | capture("bytes (?<b>[0-9]+)").b) | tonumber)
          elif .in_block and ($line | test("^\\s*\\}$")) then
            .in_block = false
          else
            .
          end
        ) | (.value // 0);
      [
        $cfg[0].forwards[]? |
        . as $f |
        ($f.id | gsub("-"; "_")) as $safe |
        {
          id: $f.id,
          user_id: $f.user_id,
          traffic_mode: ($f.traffic_mode // "two-way"),
          input_bytes: counter_bytes("fwd_" + $safe + "_in"),
          output_bytes: counter_bytes("fwd_" + $safe + "_out")
        }
      ]
    '
}

stats_rollup_counters() {
    local snapshot="$1"
    stats_init >/dev/null
    local tmp
    tmp="$(mktemp "${PFWD_RUN_DIR}/stats-rollup.XXXXXX")"
    printf '%s\n' "$snapshot" > "$tmp"
    stats_update --slurpfile snap "$tmp" --slurpfile cfg "$PFWD_CONFIG_FILE" '
      def usage($mode; $in_delta; $out_delta):
        # 双向延续监听端口收发总和语义；单向取上下行较大值。
        if $mode == "one-way" then ([ $in_delta, $out_delta ] | max) else ($in_delta + $out_delta) end;
      def user_forward_sum($state; $user_id):
        [ $cfg[0].forwards[]? | select(.user_id == $user_id) | ($state.forwards[.id].billing_used_bytes // 0) ]
        | add // 0;

      . as $state
      | reduce $snap[0][] as $f (.;
          ($state.forwards[$f.id] // {
            billing_used_bytes: 0,
            input_base_bytes: 0,
            output_base_bytes: 0,
            reset_day: null,
            last_reset_month: null
          }) as $old |
          (($f.input_bytes - ($old.input_base_bytes // 0)) | if . < 0 then $f.input_bytes else . end) as $in_delta |
          (($f.output_bytes - ($old.output_base_bytes // 0)) | if . < 0 then $f.output_bytes else . end) as $out_delta |
          .forwards[$f.id] = ($old + {
            billing_used_bytes: (($old.billing_used_bytes // 0) + usage($f.traffic_mode; $in_delta; $out_delta)),
            input_base_bytes: $f.input_bytes,
            output_base_bytes: $f.output_bytes
          })
        )
      | reduce ($snap[0] | group_by(.user_id)[]?) as $group (.;
          ($group[0].user_id) as $user_id |
          ($state.users[$user_id] // {
            billing_used_bytes: 0,
            billing_offset_bytes: 0,
            input_base_bytes: 0,
            output_base_bytes: 0,
            reset_day: null,
            last_reset_month: null
          }) as $old |
          ($group | map(.input_bytes) | add // 0) as $input |
          ($group | map(.output_bytes) | add // 0) as $output |
          (user_forward_sum(.; $user_id)) as $forward_used |
          ($old.billing_offset_bytes // 0) as $offset |
          .users[$user_id] = ($old + {
            billing_offset_bytes: $offset,
            billing_used_bytes: (($forward_used + $offset) | if . < 0 then 0 else . end),
            input_base_bytes: $input,
            output_base_bytes: $output
          })
        )
    '
    rm -f "$tmp"
}

stats_current_snapshot() {
    config_init >/dev/null
    local family table nft_output
    family="$(fw_family)"
    table="$(fw_table)"
    nft_output="$(nft list counters "$family" "$table" 2>/dev/null || true)"
    stats_forward_snapshot_json "$nft_output"
}

stats_rollup_current() {
    command -v nft >/dev/null 2>&1 || return 0
    stats_rollup_counters "$(stats_current_snapshot)"
}

stats_set_user_used() {
    local user_id used snapshot tmp
    user_id="$(normalize_user_id "$1")"
    used="$2"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    snapshot="$(stats_current_snapshot)"
    tmp="$(mktemp "${PFWD_RUN_DIR}/stats-user.XXXXXX")"
    printf '%s\n' "$snapshot" > "$tmp"
    stats_update --arg id "$user_id" --argjson used "$used" --slurpfile snap "$tmp" '
      ($snap[0] | map(select(.user_id == $id)) | map(.input_bytes) | add // 0) as $input |
      ($snap[0] | map(select(.user_id == $id)) | map(.output_bytes) | add // 0) as $output |
      ([ $snap[0][] | select(.user_id == $id) | .id ]) as $forward_ids |
      ([ $forward_ids[] as $fid | (.forwards[$fid].billing_used_bytes // 0) ] | add // 0) as $forward_used |
      (.users[$id] // {}) as $old |
      .users[$id] = ($old + {
        billing_used_bytes: $used,
        billing_offset_bytes: ($used - $forward_used),
        input_base_bytes: $input,
        output_base_bytes: $output
      })
    '
    rm -f "$tmp"
}

stats_set_forward_used() {
    local forward_id="$1"
    local used="$2"
    local snapshot tmp
    config_forward_exists "$forward_id" || pfwd_die "转发规则不存在：$forward_id"
    snapshot="$(stats_current_snapshot)"
    tmp="$(mktemp "${PFWD_RUN_DIR}/stats-forward.XXXXXX")"
    printf '%s\n' "$snapshot" > "$tmp"
    stats_update --arg id "$forward_id" --argjson used "$used" --slurpfile snap "$tmp" '
      ($snap[0] | map(select(.id == $id)) | .[0] // {input_bytes: 0, output_bytes: 0}) as $f |
      (.forwards[$id] // {}) as $old |
      .forwards[$id] = ($old + {
        billing_used_bytes: $used,
        input_base_bytes: ($f.input_bytes // 0),
        output_base_bytes: ($f.output_bytes // 0)
      })
    '
    rm -f "$tmp"
}

stats_reset_user_cycle() {
    local user_id snapshot tmp
    user_id="$(normalize_user_id "$1")"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    snapshot="$(stats_current_snapshot)"
    tmp="$(mktemp "${PFWD_RUN_DIR}/stats-user-reset.XXXXXX")"
    printf '%s\n' "$snapshot" > "$tmp"
    stats_update --arg id "$user_id" --slurpfile snap "$tmp" '
      [ $snap[0][] | select(.user_id == $id) ] as $rows |
      .forwards |= (
        . as $forwards_state
        | reduce $rows[] as $row ($forwards_state;
            .[$row.id] = ((.[$row.id] // {}) + {
              billing_used_bytes: 0,
              input_base_bytes: ($row.input_bytes // 0),
              output_base_bytes: ($row.output_bytes // 0)
            })
          )
      )
      | (.users[$id] // {}) as $old
      | .users[$id] = ($old + {
          billing_used_bytes: 0,
          billing_offset_bytes: 0,
          input_base_bytes: ($rows | map(.input_bytes) | add // 0),
          output_base_bytes: ($rows | map(.output_bytes) | add // 0)
        })
    '
    rm -f "$tmp"
}

stats_set_user_reset_day() {
    local user_id day
    user_id="$(normalize_user_id "$1")"
    day="$2"
    validate_user_id "$user_id"
    validate_reset_day "$day"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    if [ "$day" = "0" ]; then
        stats_update --arg id "$user_id" '(.users[$id] //= {}) | (.users[$id].reset_day) = null'
    else
        stats_update --arg id "$user_id" --argjson day "$day" '(.users[$id] //= {}) | (.users[$id].reset_day) = $day'
    fi
}

stats_set_forward_reset_day() {
    local forward_id="$1"
    local day="$2"
    validate_reset_day "$day"
    config_forward_exists "$forward_id" || pfwd_die "转发规则不存在：$forward_id"
    if [ "$day" = "0" ]; then
        stats_update --arg id "$forward_id" '(.forwards[$id] //= {}) | (.forwards[$id].reset_day) = null'
    else
        stats_update --arg id "$forward_id" --argjson day "$day" '(.forwards[$id] //= {}) | (.forwards[$id].reset_day) = $day'
    fi
}

stats_apply_due_resets() {
    stats_rollup_current
    local today day month changed="false"
    today="$(pfwd_today)"
    day="$(date -d "$today" '+%-d')"
    month="$(date -d "$today" '+%Y-%m')"

    local state line kind id reset_day last_month
    state="$(jq -r --argjson day "$day" --arg month "$month" '
      (.users // {} | to_entries[] | select((.value.reset_day // null) != null and (.value.reset_day <= $day) and (.value.last_reset_month // "") != $month) | ["user", .key, (.value.reset_day | tostring), (.value.last_reset_month // "")] | @tsv),
      (.forwards // {} | to_entries[] | select((.value.reset_day // null) != null and (.value.reset_day <= $day) and (.value.last_reset_month // "") != $month) | ["forward", .key, (.value.reset_day | tostring), (.value.last_reset_month // "")] | @tsv)
    ' "$PFWD_STATS_FILE")"

    while IFS=$'\t' read -r kind id reset_day last_month; do
        [ -n "$kind" ] || continue
        case "$kind" in
            user) stats_reset_user_cycle "$id" ;;
            forward) stats_set_forward_used "$id" 0 ;;
        esac
        stats_update --arg kind "$kind" --arg id "$id" --arg month "$month" '
          if $kind == "user" then .users[$id].last_reset_month = $month
          else .forwards[$id].last_reset_month = $month
          end
        '
        changed="true"
    done <<< "$state"

    [ "$changed" = "true" ]
}
