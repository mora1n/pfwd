#!/usr/bin/env bash

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


downmask_resolve_source_request() {
    local active="$1"
    local bytes="$2"
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


downmask_resolve_active_source() {
    local active bytes
    active="$(downmask_config_get '.public.active_source')"
    bytes="$1"
    [ -n "$active" ] || active="cloudflare_dynamic"
    downmask_resolve_source_request "$active" "$bytes" || downmask_resolve_source_request "cloudflare_dynamic" "$bytes"
}


downmask_pull_public_query_url() {
    local source_name="$1"
    local planned="$2"
    local speed_limit="$3"
    local remaining chunk_size query_meta query_code chunk_actual total_actual chunk_resolved chunk_url
    remaining="$planned"
    total_actual=0
    while [ "$remaining" -gt 0 ]; do
        chunk_size="$remaining"
        if [ "$chunk_size" -gt "$DOWNMASK_QUERY_PULL_CHUNK_BYTES" ]; then
            chunk_size="$DOWNMASK_QUERY_PULL_CHUNK_BYTES"
        fi
        chunk_resolved="$(downmask_resolve_source_request "$source_name" "$chunk_size")" || break
        chunk_url="${chunk_resolved#*|}"
        [ -n "$chunk_url" ] || break
        query_meta="$(curl -fsSL --max-time 1800 --limit-rate "$speed_limit" -o /dev/null -w '%{http_code} %{size_download}' "$chunk_url" 2>/dev/null || echo '000 0')"
        query_code="${query_meta%% *}"
        chunk_actual="${query_meta##* }"
        if [ "$query_code" != "200" ] || ! [[ "$chunk_actual" =~ ^[0-9]+$ ]] || [ "$chunk_actual" -le 0 ]; then
            break
        fi
        total_actual=$((total_actual + chunk_actual))
        if [ "$chunk_actual" -lt "$chunk_size" ]; then
            break
        fi
        remaining=$((remaining - chunk_actual))
    done
    echo "$total_actual"
}


downmask_pull_public_range_url() {
    local url="$1"
    local planned="$2"
    local speed_limit="$3"
    local size remaining request_bytes probe_start probe_end start_offset range_meta range_code actual total_actual
    size="$(curl -sSI --max-time 30 "$url" 2>/dev/null | awk 'BEGIN{IGNORECASE=1} /^content-length:/ {gsub("\r","",$2); print $2; exit}')"
    remaining="$planned"
    total_actual=0
    while [ "$remaining" -gt 0 ]; do
        request_bytes="$remaining"
        if [ "$request_bytes" -gt "$DOWNMASK_RANGE_PULL_CHUNK_BYTES" ]; then
            request_bytes="$DOWNMASK_RANGE_PULL_CHUNK_BYTES"
        fi
        if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -gt 0 ] && [ "$request_bytes" -gt "$size" ]; then
            request_bytes="$size"
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
            break
        fi
        if [ "$actual" -ne "$request_bytes" ]; then
            break
        fi
        if [ "$range_code" != "206" ] && [ "$range_code" != "200" ]; then
            break
        fi
        total_actual=$((total_actual + actual))
        remaining=$((remaining - actual))
    done
    echo "$total_actual"
}


downmask_pull_public() {
    local planned="$1"
    local resolved kind url speed_limit active actual fallback_resolved fallback_kind fallback_url
    speed_limit="$(downmask_config_get '.public.speed_limit')"
    [ -n "$speed_limit" ] || speed_limit="4M"
    active="$(downmask_config_get '.public.active_source')"
    [ -n "$active" ] || active="cloudflare_dynamic"
    resolved="$(downmask_resolve_source_request "$active" "$planned" 2>/dev/null || downmask_resolve_source_request "cloudflare_dynamic" "$planned")" || return 1
    kind="${resolved%%|*}"
    url="${resolved#*|}"
    [ -n "$url" ] || return 1
    command -v curl >/dev/null 2>&1 || { echo 0; return 0; }

    if [ "$active" = "cloudflare_dynamic" ] && [ "$kind" = "query" ] && [ "$planned" -gt "$DOWNMASK_QUERY_PULL_CHUNK_BYTES" ]; then
        fallback_resolved="$(downmask_resolve_source_request "$DOWNMASK_QUERY_LARGE_PULL_RANGE_SOURCE" "$planned" 2>/dev/null || true)"
        fallback_kind="${fallback_resolved%%|*}"
        fallback_url="${fallback_resolved#*|}"
        if [ -n "$fallback_url" ] && [ "$fallback_kind" = "range" ]; then
            actual="$(downmask_pull_public_range_url "$fallback_url" "$planned" "$speed_limit")"
            [[ "$actual" =~ ^[0-9]+$ ]] || actual=0
            if [ "$actual" -gt 0 ]; then
                echo "$actual"
                return 0
            fi
        fi
    fi

    case "$kind" in
        query)
            actual="$(downmask_pull_public_query_url "$active" "$planned" "$speed_limit")"
            ;;
        range)
            actual="$(downmask_pull_public_range_url "$url" "$planned" "$speed_limit")"
            ;;
        *)
            actual=0
            ;;
    esac
    [[ "$actual" =~ ^[0-9]+$ ]] || actual=0
    echo "$actual"
}
