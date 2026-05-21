#!/usr/bin/env bash

stats_default_json() {
    cat <<'EOF'
{
  "users": {},
  "forwards": {}
}
EOF
}

PFWD_STATS_INITIALIZED=0
PFWD_STATS_SNAPSHOT_CACHE=""
PFWD_STATS_USAGE_CACHE=""
PFWD_STATS_FORWARDER_STATUS_CACHE=""
PFWD_STATS_XDP_STATUS_CACHE=""
PFWD_STATS_RUNTIME_XDP_CACHE=""
PFWD_STATS_RUNTIME_NFT_CACHE=""

stats_init() {
    [ "$PFWD_STATS_INITIALIZED" = "1" ] && [ -f "$PFWD_STATS_FILE" ] && return 0
    pfwd_require_jq
    pfwd_mkdirs
    if [ ! -f "$PFWD_STATS_FILE" ]; then
        stats_default_json | jq '.' | pfwd_write_atomic "$PFWD_STATS_FILE"
    fi
    stats_validate_file "$PFWD_STATS_FILE"
    PFWD_STATS_INITIALIZED=1
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
    PFWD_STATS_INITIALIZED=1
}

stats_billing_jq_defs() {
    cat <<'EOF'
def mode_factor($mode):
  if $mode == "one-way" then 1 else 2 end;
def billed_usage($mode; $ratio; $in_bytes; $out_bytes):
  ((((($in_bytes * $ratio) | floor) + (($out_bytes * $ratio) | floor))) * mode_factor($mode));
def seeded_one_way_display($old; $mode; $ratio):
  if ($old | has("one_way_display_bytes")) then
    ($old.one_way_display_bytes // 0)
  elif ($mode == "one-way") then
    billed_usage("one-way"; $ratio; ($old.input_total_bytes // 0); ($old.output_total_bytes // 0))
  else
    0
  end;
def seeded_two_way_display($old; $mode; $ratio):
  if ($old | has("two_way_display_bytes")) then
    ($old.two_way_display_bytes // 0)
  elif ($mode == "two-way") then
    billed_usage("two-way"; $ratio; ($old.input_total_bytes // 0); ($old.output_total_bytes // 0))
  else
    0
  end;
EOF
}

PFWD_STATS_LAST_SNAPSHOT_ERROR=""

stats_runtime_cache_clear() {
    PFWD_STATS_SNAPSHOT_CACHE=""
    PFWD_STATS_USAGE_CACHE=""
    PFWD_STATS_FORWARDER_STATUS_CACHE=""
    PFWD_STATS_XDP_STATUS_CACHE=""
    PFWD_STATS_RUNTIME_XDP_CACHE=""
    PFWD_STATS_RUNTIME_NFT_CACHE=""
}

stats_forwarder_status_cached() {
    if [ -n "$PFWD_STATS_FORWARDER_STATUS_CACHE" ]; then
        printf '%s\n' "$PFWD_STATS_FORWARDER_STATUS_CACHE"
        return 0
    fi
    if [ -f "$PFWD_FORWARDER_STATUS_FILE" ]; then
        PFWD_STATS_FORWARDER_STATUS_CACHE="$(forwarder_status_json)"
    else
        PFWD_STATS_FORWARDER_STATUS_CACHE='{}'
    fi
    printf '%s\n' "$PFWD_STATS_FORWARDER_STATUS_CACHE"
}

stats_runtime_file_cached() {
    local which="$1"
    local file cache_var_name cache_var_value
    case "$which" in
        xdp)
            file="$PFWD_FORWARDER_XDP_RUNTIME_FILE"
            cache_var_name="PFWD_STATS_RUNTIME_XDP_CACHE"
            ;;
        nft)
            file="$PFWD_FORWARDER_NFT_RUNTIME_FILE"
            cache_var_name="PFWD_STATS_RUNTIME_NFT_CACHE"
            ;;
        *)
            pfwd_die "未知 runtime cache 类型：$which"
            ;;
    esac
    cache_var_value="${!cache_var_name:-}"
    if [ -n "$cache_var_value" ]; then
        printf '%s\n' "$cache_var_value"
        return 0
    fi
    if [ -f "$file" ]; then
        printf -v "$cache_var_name" '%s' "$(cat "$file")"
    else
        if [ "$which" = "xdp" ]; then
            printf -v "$cache_var_name" '%s' '{"rules":[]}'
        else
            printf -v "$cache_var_name" '%s' '{"rules":[]}'
        fi
    fi
    printf '%s\n' "${!cache_var_name}"
}

stats_xdp_status_cached() {
    if [ -n "$PFWD_STATS_XDP_STATUS_CACHE" ]; then
        printf '%s\n' "$PFWD_STATS_XDP_STATUS_CACHE"
        return 0
    fi
    PFWD_STATS_XDP_STATUS_CACHE="$(forwarder_xdp_status_json)"
    printf '%s\n' "$PFWD_STATS_XDP_STATUS_CACHE"
}

stats_zero_snapshot_json() {
    local cfg_file="${1:-$PFWD_CONFIG_FILE}"
    jq -r '
      [
        .forwards[]? |
        {
          id: .id,
          user_id: .user_id,
          traffic_mode: (.traffic_mode // "two-way"),
          traffic_ratio: (.traffic_ratio // 1),
          input_bytes: 0,
          output_bytes: 0,
          input_packets: 0,
          output_packets: 0,
          dropped_bytes: 0,
          dropped_packets: 0
        }
      ]
    ' "$cfg_file"
}

stats_merge_snapshots_json() {
    local xdp_snapshot="$1"
    local nft_snapshot="$2"
    jq -n \
      --argjson xdp "$xdp_snapshot" \
      --argjson nft "$nft_snapshot" '
      (($xdp + $nft) | group_by(.id) | map(
        reduce .[] as $row (
          {
            id: .[0].id,
            user_id: .[0].user_id,
            traffic_mode: .[0].traffic_mode,
            traffic_ratio: (. [0].traffic_ratio // 1),
            input_bytes: 0,
            output_bytes: 0,
            input_packets: 0,
            output_packets: 0,
            dropped_bytes: 0,
            dropped_packets: 0
          };
          .input_bytes += ($row.input_bytes // 0)
          | .output_bytes += ($row.output_bytes // 0)
          | .input_packets += ($row.input_packets // 0)
          | .output_packets += ($row.output_packets // 0)
          | .dropped_bytes += ($row.dropped_bytes // 0)
          | .dropped_packets += ($row.dropped_packets // 0)
        )
      ))'
}

stats_snapshot_from_nft_runtime() {
    local runtime_json="$1"
    local nft_json
    nft_json="$(fw_read_nft_counters 2>/dev/null || true)"
    if [ -z "$nft_json" ]; then
        jq -n --argjson runtime "$runtime_json" '
          [
            $runtime.rules[]? |
            {
              id: .id,
              user_id: .user_id,
              traffic_mode: (.traffic_mode // "two-way"),
              traffic_ratio: (.traffic_ratio // 1),
              input_bytes: 0,
              output_bytes: 0,
              input_packets: 0,
              output_packets: 0,
              dropped_bytes: 0,
              dropped_packets: 0
            }
          ]'
        return 0
    fi

    jq -n \
      --argjson runtime "$runtime_json" \
      --argjson nft "$nft_json" '
      ($nft.nftables | map(select(.counter?)) | map({key: .counter.name, value: (.counter.bytes // 0)}) | from_entries) as $counters
      | [
          $runtime.rules[]? |
          (.id | gsub("-"; "_")) as $safe |
          {
            id: .id,
            user_id: .user_id,
            traffic_mode: (.traffic_mode // "two-way"),
            traffic_ratio: (.traffic_ratio // 1),
            input_bytes: ($counters["fwd_" + $safe + "_in"] // 0),
            output_bytes: ($counters["fwd_" + $safe + "_out"] // 0),
            input_packets: 0,
            output_packets: 0,
            dropped_bytes: 0,
            dropped_packets: 0
          }
        ]'
}

stats_usage_from_snapshot() {
    local snapshot="$1"
    local cfg_file="${2:-$PFWD_CONFIG_FILE}"
    local stats_file="${3:-$PFWD_STATS_FILE}"
    local jq_filter
    jq_filter="$(cat <<'EOF'
      def fstate($id): $state[0].forwards[$id] // {};
      def ustate($id): $state[0].users[$id] // {};
      def snap_forward($id): ($snap | map(select(.id == $id)) | .[0] // {input_bytes: 0, output_bytes: 0});
      def current_seeded_one_way_display($f):
        seeded_one_way_display((fstate($f.id)); ($f.traffic_mode // "two-way"); ($f.traffic_ratio // 1));
      def current_seeded_two_way_display($f):
        seeded_two_way_display((fstate($f.id)); ($f.traffic_mode // "two-way"); ($f.traffic_ratio // 1));
      def pending_input_bytes($id):
        (fstate($id)) as $s |
        (snap_forward($id)) as $c |
        (($c.input_bytes - ($s.input_base_bytes // 0)) | if . < 0 then $c.input_bytes else . end);
      def pending_output_bytes($id):
        (fstate($id)) as $s |
        (snap_forward($id)) as $c |
        (($c.output_bytes - ($s.output_base_bytes // 0)) | if . < 0 then $c.output_bytes else . end);
      def forward_totals($id):
        (fstate($id)) as $s |
        {
          input_bytes: (($s.input_total_bytes // 0) + pending_input_bytes($id)),
          output_bytes: (($s.output_total_bytes // 0) + pending_output_bytes($id))
        };
      def current_forward_billing($f):
        (fstate($f.id)) as $s |
        (($s.billing_used_bytes // 0) + billed_usage(($f.traffic_mode // "two-way"); ($f.traffic_ratio // 1); pending_input_bytes($f.id); pending_output_bytes($f.id)));
      def current_forward_one_way_display($f):
        current_seeded_one_way_display($f) + (if ($f.traffic_mode // "two-way") == "one-way" then billed_usage("one-way"; ($f.traffic_ratio // 1); pending_input_bytes($f.id); pending_output_bytes($f.id)) else 0 end);
      def current_forward_two_way_display($f):
        current_seeded_two_way_display($f) + (if ($f.traffic_mode // "two-way") == "two-way" then billed_usage("two-way"; ($f.traffic_ratio // 1); pending_input_bytes($f.id); pending_output_bytes($f.id)) else 0 end);
      def user_snapshot($id):
        ($cfg[0].forwards | map(select(.user_id == $id))) as $items |
        {
          input_bytes: ($items | map(forward_totals(.id).input_bytes) | add // 0),
          output_bytes: ($items | map(forward_totals(.id).output_bytes) | add // 0)
        };
      def user_one_way_display($user_id):
        [ $cfg[0].forwards[] | select(.user_id == $user_id) | current_forward_one_way_display(.) ] | add // 0;
      def user_two_way_display($user_id):
        [ $cfg[0].forwards[] | select(.user_id == $user_id) | current_forward_two_way_display(.) ] | add // 0;
      def user_billing($u):
        (ustate($u.id)) as $s |
        ([ $cfg[0].forwards[] | select(.user_id == $u.id) | current_forward_billing(.) ] | add // 0) as $forward_used |
        ($s.billing_offset_bytes // 0) as $offset |
        (($forward_used + $offset) | if . < 0 then 0 else . end);
      {
        forwards: [
          $cfg[0].forwards[] |
          . as $f |
          (forward_totals($f.id)) as $t |
          . + {
            input_bytes: $t.input_bytes,
            output_bytes: $t.output_bytes,
            one_way_bytes: current_forward_one_way_display($f),
            two_way_bytes: current_forward_two_way_display($f),
            total_bytes: (current_forward_one_way_display($f) + current_forward_two_way_display($f)),
            billing_used_bytes: current_forward_billing($f)
          }
        ],
        users: [
          $cfg[0].users[] |
          . as $u |
          (user_snapshot($u.id)) as $c |
          (user_one_way_display($u.id)) as $one_way_used |
          (user_two_way_display($u.id)) as $two_way_used |
          . + {
            input_bytes: $c.input_bytes,
            output_bytes: $c.output_bytes,
            one_way_bytes: $one_way_used,
            two_way_bytes: $two_way_used,
            billing_used_bytes: user_billing($u),
            reset_day: (ustate($u.id).reset_day // null)
          }
        ]
      }
EOF
)"
    jq -n --slurpfile cfg "$cfg_file" --slurpfile state "$stats_file" --argjson snap "$snapshot" "$(stats_billing_jq_defs)
$jq_filter"
}

stats_rollup_counters() {
    local snapshot="$1"
    stats_init >/dev/null
    local jq_filter
    jq_filter="$(cat <<'EOF'
      def current_seeded_one_way_display($old; $f):
        seeded_one_way_display($old; ($f.traffic_mode // "two-way"); ($f.traffic_ratio // 1));
      def current_seeded_two_way_display($old; $f):
        seeded_two_way_display($old; ($f.traffic_mode // "two-way"); ($f.traffic_ratio // 1));
      def user_forward_sum($state; $user_id):
        [ $cfg[0].forwards[]? | select(.user_id == $user_id) | ($state.forwards[.id].billing_used_bytes // 0) ]
        | add // 0;

      . as $state
      | reduce $snap[] as $f (.;
          ($state.forwards[$f.id] // {
            billing_used_bytes: 0,
            input_total_bytes: 0,
            output_total_bytes: 0,
            input_base_bytes: 0,
            output_base_bytes: 0,
            reset_day: null,
            last_reset_month: null
          }) as $old |
          (($f.input_bytes - ($old.input_base_bytes // 0)) | if . < 0 then $f.input_bytes else . end) as $in_delta |
          (($f.output_bytes - ($old.output_base_bytes // 0)) | if . < 0 then $f.output_bytes else . end) as $out_delta |
          .forwards[$f.id] = ($old + {
            billing_used_bytes: (($old.billing_used_bytes // 0) + billed_usage($f.traffic_mode; ($f.traffic_ratio // 1); $in_delta; $out_delta)),
            one_way_display_bytes: (current_seeded_one_way_display($old; $f) + (if $f.traffic_mode == "one-way" then billed_usage("one-way"; ($f.traffic_ratio // 1); $in_delta; $out_delta) else 0 end)),
            two_way_display_bytes: (current_seeded_two_way_display($old; $f) + (if $f.traffic_mode == "two-way" then billed_usage("two-way"; ($f.traffic_ratio // 1); $in_delta; $out_delta) else 0 end)),
            input_total_bytes: (($old.input_total_bytes // 0) + $in_delta),
            output_total_bytes: (($old.output_total_bytes // 0) + $out_delta),
            input_base_bytes: $f.input_bytes,
            output_base_bytes: $f.output_bytes
          })
        )
      | reduce ($snap | group_by(.user_id)[]?) as $group (.;
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
EOF
)"
    stats_update --argjson snap "$snapshot" --slurpfile cfg "$PFWD_CONFIG_FILE" "$(stats_billing_jq_defs)
$jq_filter"
}

stats_current_snapshot() {
    config_init >/dev/null
    stats_init >/dev/null
    local cfg_file xdp_snapshot nft_snapshot forwarder_status xdp_runtime nft_runtime
    if [ -n "$PFWD_STATS_SNAPSHOT_CACHE" ]; then
        printf '%s\n' "$PFWD_STATS_SNAPSHOT_CACHE"
        return 0
    fi
    cfg_file="$PFWD_CONFIG_FILE"
    if [ -n "$PFWD_CONFIG_SNAPSHOT_FILE" ] && [ -f "$PFWD_CONFIG_SNAPSHOT_FILE" ]; then
        cfg_file="$PFWD_CONFIG_SNAPSHOT_FILE"
    fi
    PFWD_STATS_LAST_SNAPSHOT_ERROR=""
    forwarder_status="$(stats_forwarder_status_cached)"
    xdp_runtime="$(stats_runtime_file_cached xdp)"
    nft_runtime="$(stats_runtime_file_cached nft)"

    xdp_snapshot='[]'
    nft_snapshot='[]'

    if [ "$(jq -r '.xdp_applied // false' <<< "$forwarder_status")" = "true" ] && [ -x "$(forwarder_bin_path)" ] && [ -f "$PFWD_FORWARDER_XDP_RUNTIME_FILE" ]; then
        local snapshot_error snapshot_status=0
        snapshot_error="$(mktemp "${PFWD_RUN_DIR}/snapshot.err.XXXXXX")"
        xdp_snapshot="$("$(forwarder_bin_path)" snapshot \
          --runtime-file "$PFWD_FORWARDER_XDP_RUNTIME_FILE" \
          --state-file "$PFWD_STATS_FILE" \
          --status-file "$PFWD_XDP_STATUS_FILE" \
          --rule-counter-pin "$PFWD_XDP_RULE_COUNTER_PIN_PATH" 2>"$snapshot_error")" || snapshot_status=$?
        if [ -n "$xdp_snapshot" ] && jq -e 'type == "array"' >/dev/null 2>&1 <<< "$xdp_snapshot"; then
            :
        else
            xdp_snapshot='[]'
        fi
        PFWD_STATS_LAST_SNAPSHOT_ERROR="$(tr '\n' ' ' < "$snapshot_error" | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')"
        rm -f "$snapshot_error"
        if [ "$snapshot_status" -ne 0 ] && [ -f "$PFWD_XDP_STATUS_FILE" ] && [ "$(jq -r '.applied // false' "$PFWD_XDP_STATUS_FILE" 2>/dev/null || echo false)" = "true" ]; then
            pfwd_die "读取 XDP 计数失败：${PFWD_STATS_LAST_SNAPSHOT_ERROR:-pfwd-xdp snapshot exit=$snapshot_status}"
        fi
    fi

    if [ "$(jq -r '.nft_applied // false' <<< "$forwarder_status")" = "true" ] && [ -f "$PFWD_FORWARDER_NFT_RUNTIME_FILE" ]; then
        nft_snapshot="$(stats_snapshot_from_nft_runtime "$nft_runtime")"
    fi

    if jq -e 'length > 0' >/dev/null 2>&1 <<< "$xdp_snapshot" || jq -e 'length > 0' >/dev/null 2>&1 <<< "$nft_snapshot"; then
        PFWD_STATS_SNAPSHOT_CACHE="$(stats_merge_snapshots_json "$xdp_snapshot" "$nft_snapshot")"
        printf '%s\n' "$PFWD_STATS_SNAPSHOT_CACHE"
        return 0
    fi
    PFWD_STATS_SNAPSHOT_CACHE="$(stats_zero_snapshot_json "$cfg_file")"
    printf '%s\n' "$PFWD_STATS_SNAPSHOT_CACHE"
}

stats_usage_json() {
    stats_init >/dev/null
    local cfg_file stats_file
    if [ -n "$PFWD_STATS_USAGE_CACHE" ]; then
        printf '%s\n' "$PFWD_STATS_USAGE_CACHE"
        return 0
    fi
    cfg_file="$PFWD_CONFIG_FILE"
    stats_file="$PFWD_STATS_FILE"
    if [ -n "$PFWD_CONFIG_SNAPSHOT_FILE" ] && [ -f "$PFWD_CONFIG_SNAPSHOT_FILE" ]; then
        cfg_file="$PFWD_CONFIG_SNAPSHOT_FILE"
    fi
    PFWD_STATS_USAGE_CACHE="$(stats_usage_from_snapshot "$(stats_current_snapshot)" "$cfg_file" "$stats_file")"
    printf '%s\n' "$PFWD_STATS_USAGE_CACHE"
}

stats_rollup_needed() {
    local snapshot="$1"
    stats_init >/dev/null
    jq -n --argjson snap "$snapshot" --slurpfile state "$PFWD_STATS_FILE" '
      any($snap[]?;
        (
          (($state[0].forwards[.id].input_base_bytes // 0) != (.input_bytes // 0)) or
          (($state[0].forwards[.id].output_base_bytes // 0) != (.output_bytes // 0))
        )
      )
    ' | grep -qx 'true'
}

stats_rollup_current() {
    pfwd_debug "stats_rollup_current start"
    stats_init >/dev/null
    local snapshot
    snapshot="$(stats_current_snapshot)"
    stats_rollup_needed "$snapshot" || return 0
    stats_rollup_counters "$snapshot"
    stats_runtime_cache_clear
}

stats_set_user_used() {
    local user_id used snapshot
    user_id="$(normalize_user_id "$1")"
    used="$2"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    snapshot="$(stats_current_snapshot)"
    local jq_filter
    jq_filter="$(cat <<'EOF'
      def current_seeded_one_way_display($old; $f):
        seeded_one_way_display($old; ($f.traffic_mode // "two-way"); ($f.traffic_ratio // 1));
      def current_seeded_two_way_display($old; $f):
        seeded_two_way_display($old; ($f.traffic_mode // "two-way"); ($f.traffic_ratio // 1));
      def snap_forward($fid):
        ($snap | map(select(.id == $fid)) | .[0] // {id: $fid, traffic_mode: "two-way", traffic_ratio: 1, input_bytes: 0, output_bytes: 0});
      ($snap | map(select(.user_id == $id)) | map(.input_bytes) | add // 0) as $input |
      ($snap | map(select(.user_id == $id)) | map(.output_bytes) | add // 0) as $output |
      ([ $snap[] | select(.user_id == $id) | .id ]) as $forward_ids |
      .forwards |= (
        . as $forwards_state
        | reduce $forward_ids[] as $fid ($forwards_state;
            (snap_forward($fid)) as $f |
            (.[$fid] // {}) as $old |
            (($f.input_bytes - ($old.input_base_bytes // 0)) | if . < 0 then $f.input_bytes else . end) as $in_delta |
            (($f.output_bytes - ($old.output_base_bytes // 0)) | if . < 0 then $f.output_bytes else . end) as $out_delta |
            .[$fid] = ($old + {
              billing_used_bytes: (($old.billing_used_bytes // 0) + billed_usage(($f.traffic_mode // "two-way"); ($f.traffic_ratio // 1); $in_delta; $out_delta)),
              one_way_display_bytes: (current_seeded_one_way_display($old; $f) + (if ($f.traffic_mode // "two-way") == "one-way" then billed_usage("one-way"; ($f.traffic_ratio // 1); $in_delta; $out_delta) else 0 end)),
              two_way_display_bytes: (current_seeded_two_way_display($old; $f) + (if ($f.traffic_mode // "two-way") == "two-way" then billed_usage("two-way"; ($f.traffic_ratio // 1); $in_delta; $out_delta) else 0 end)),
              input_total_bytes: (($old.input_total_bytes // 0) + $in_delta),
              output_total_bytes: (($old.output_total_bytes // 0) + $out_delta),
              input_base_bytes: ($f.input_bytes // 0),
              output_base_bytes: ($f.output_bytes // 0)
            })
          )
      )
      | ([ $forward_ids[] as $fid | (.forwards[$fid].billing_used_bytes // 0) ] | add // 0) as $forward_used
      | (.users[$id] // {}) as $old
      | .users[$id] = ($old + {
        billing_used_bytes: $used,
        billing_offset_bytes: ($used - $forward_used),
        input_base_bytes: $input,
        output_base_bytes: $output
      })
EOF
)"
    stats_update --arg id "$user_id" --argjson used "$used" --argjson snap "$snapshot" "$(stats_billing_jq_defs)
$jq_filter"
}

stats_set_forward_used() {
    local forward_id="$1"
    local used="$2"
    local snapshot
    config_forward_exists "$forward_id" || pfwd_die "转发规则不存在：$forward_id"
    snapshot="$(stats_current_snapshot)"
    local jq_filter
    jq_filter="$(cat <<'EOF'
      def current_seeded_one_way_display($old; $f):
        seeded_one_way_display($old; ($f.traffic_mode // "two-way"); ($f.traffic_ratio // 1));
      def current_seeded_two_way_display($old; $f):
        seeded_two_way_display($old; ($f.traffic_mode // "two-way"); ($f.traffic_ratio // 1));
      ($snap | map(select(.id == $id)) | .[0] // {input_bytes: 0, output_bytes: 0}) as $f |
      (.forwards[$id] // {}) as $old |
      (($f.input_bytes - ($old.input_base_bytes // 0)) | if . < 0 then $f.input_bytes else . end) as $in_delta |
      (($f.output_bytes - ($old.output_base_bytes // 0)) | if . < 0 then $f.output_bytes else . end) as $out_delta |
      .forwards[$id] = ($old + {
        billing_used_bytes: $used,
        one_way_display_bytes: (current_seeded_one_way_display($old; $f) + (if ($f.traffic_mode // "two-way") == "one-way" then billed_usage("one-way"; ($f.traffic_ratio // 1); $in_delta; $out_delta) else 0 end)),
        two_way_display_bytes: (current_seeded_two_way_display($old; $f) + (if ($f.traffic_mode // "two-way") == "two-way" then billed_usage("two-way"; ($f.traffic_ratio // 1); $in_delta; $out_delta) else 0 end)),
        input_total_bytes: (($old.input_total_bytes // 0) + $in_delta),
        output_total_bytes: (($old.output_total_bytes // 0) + $out_delta),
        input_base_bytes: ($f.input_bytes // 0),
        output_base_bytes: ($f.output_bytes // 0)
      })
EOF
)"
    stats_update --arg id "$forward_id" --argjson used "$used" --argjson snap "$snapshot" "$(stats_billing_jq_defs)
$jq_filter"
}

stats_reset_forward_cycle() {
    local forward_id="$1"
    local snapshot
    config_forward_exists "$forward_id" || pfwd_die "转发规则不存在：$forward_id"
    snapshot="$(stats_current_snapshot)"
    stats_update --arg id "$forward_id" --argjson snap "$snapshot" '
      ($snap | map(select(.id == $id)) | .[0] // {input_bytes: 0, output_bytes: 0}) as $f |
      (.forwards[$id] // {}) as $old |
      .forwards[$id] = ($old + {
        billing_used_bytes: 0,
        one_way_display_bytes: 0,
        two_way_display_bytes: 0,
        input_total_bytes: 0,
        output_total_bytes: 0,
        input_base_bytes: ($f.input_bytes // 0),
        output_base_bytes: ($f.output_bytes // 0)
      })
    '
}

stats_reset_user_cycle() {
    local user_id snapshot
    user_id="$(normalize_user_id "$1")"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    snapshot="$(stats_current_snapshot)"
    stats_update --arg id "$user_id" --argjson snap "$snapshot" --slurpfile cfg "$PFWD_CONFIG_FILE" '
      def row_for($fid):
        ($snap | map(select(.id == $fid)) | .[0] // {id: $fid, input_bytes: 0, output_bytes: 0});
      ([ $cfg[0].forwards[]? | select(.user_id == $id) | .id ]) as $forward_ids |
      ([ $forward_ids[] | row_for(.) ]) as $rows |
      .forwards |= (
        . as $forwards_state
        | reduce $rows[] as $row ($forwards_state;
            .[$row.id] = ((.[$row.id] // {}) + {
              billing_used_bytes: 0,
              one_way_display_bytes: 0,
              two_way_display_bytes: 0,
              input_total_bytes: 0,
              output_total_bytes: 0,
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
}

stats_set_user_reset_day() {
    local user_id day
    user_id="$(normalize_user_id "$1")"
    day="$2"
    validate_user_id "$user_id"
    config_user_exists "$user_id" || pfwd_die "用户不存在：$user_id"
    day="$(normalize_reset_day_input "$day")"
    if [ "$day" = "0" ]; then
        stats_update --arg id "$user_id" '(.users[$id] //= {}) | (.users[$id].reset_day) = null'
    else
        stats_update --arg id "$user_id" --arg day "$day" '(.users[$id] //= {}) | (.users[$id].reset_day) = $day'
    fi
}

stats_set_forward_reset_day() {
    local forward_id="$1"
    local day="$2"
    config_forward_exists "$forward_id" || pfwd_die "转发规则不存在：$forward_id"
    day="$(normalize_reset_day_input "$day")"
    if [ "$day" = "0" ]; then
        stats_update --arg id "$forward_id" '(.forwards[$id] //= {}) | (.forwards[$id].reset_day) = null'
    else
        stats_update --arg id "$forward_id" --arg day "$day" '(.forwards[$id] //= {}) | (.forwards[$id].reset_day) = $day'
    fi
}

stats_apply_due_resets() {
    stats_rollup_current
    local now_minute month days_in_month changed="false"
    now_minute="$(pfwd_now_minute)"
    month="$(date -d "$now_minute" '+%Y-%m')"
    days_in_month="$(date -d "$(date -d "$now_minute" '+%Y-%m-01') +1 month -1 day" '+%d')"

    local state line kind id reset_day last_month
    state="$(jq -r --arg now "$now_minute" --arg month "$month" --argjson dim "$days_in_month" '
      def schedule_due($reset_day; $now; $month; $dim):
        (if ($reset_day | type) == "number" then
          (($reset_day | tostring) + " 00:00")
        else
          $reset_day
        end) as $normalized
        | ($normalized | capture("^(?<day>[0-9]{2}) (?<time>[0-9]{2}:[0-9]{2})$")) as $parts
        | (($parts.day | tonumber) as $configured_day
        | (($configured_day | if . > $dim then $dim else . end) | tostring | if length == 1 then "0" + . else . end) as $effective_day
        | ($month + "-" + $effective_day + " " + $parts.time)) <= $now;
      (.users // {} | to_entries[] | select((.value.reset_day // null) != null and schedule_due(.value.reset_day; $now; $month; $dim) and (.value.last_reset_month // "") != $month) | ["user", .key, (.value.reset_day | tostring), (.value.last_reset_month // "")] | @tsv),
      (.forwards // {} | to_entries[] | select((.value.reset_day // null) != null and schedule_due(.value.reset_day; $now; $month; $dim) and (.value.last_reset_month // "") != $month) | ["forward", .key, (.value.reset_day | tostring), (.value.last_reset_month // "")] | @tsv)
    ' "$PFWD_STATS_FILE")"

    while IFS=$'\t' read -r kind id reset_day last_month; do
        [ -n "$kind" ] || continue
        case "$kind" in
            user) stats_reset_user_cycle "$id" ;;
            forward) stats_reset_forward_cycle "$id" ;;
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
