#!/usr/bin/env bash

whitelist_web_asset_name() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "pfwd-whitelist-web-linux-amd64" ;;
        aarch64|arm64) echo "pfwd-whitelist-web-linux-arm64" ;;
        *) return 1 ;;
    esac
}

whitelist_web_local_asset_path() {
    local asset
    asset="$(whitelist_web_asset_name)" || return 1
    printf '%s/assets/%s\n' "$PFWD_SCRIPT_DIR" "$asset"
}

whitelist_web_bin_path() {
    if [ -x "$PFWD_WHITELIST_WEB_BIN_PATH" ]; then
        printf '%s\n' "$PFWD_WHITELIST_WEB_BIN_PATH"
        return 0
    fi
    local local_asset=""
    local_asset="$(whitelist_web_local_asset_path 2>/dev/null || true)"
    if [ -n "$local_asset" ] && [ -x "$local_asset" ]; then
        printf '%s\n' "$local_asset"
        return 0
    fi
    printf '%s\n' "$PFWD_WHITELIST_WEB_BIN_PATH"
}

whitelist_web_service_unit() {
    cat <<EOF
[Unit]
Description=pfwd whitelist web controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$(whitelist_web_bin_path) run --config $PFWD_WHITELIST_WEB_CONFIG_FILE
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
}

whitelist_web_restricted_command_script_name() {
    printf '%s\n' "pfwd-whitelist-lease-command"
}

whitelist_web_restricted_command_install_path() {
    printf '%s/%s\n' "$PFWD_INSTALL_DIR/bin" "$(whitelist_web_restricted_command_script_name)"
}

whitelist_web_default_config_json() {
    jq -n '
      {
        listen_host: "127.0.0.1",
        listen_port: 18080,
        trusted_proxy_cidrs: [],
        request_timeout_sec: 30,
        routes: []
      }
    '
}

whitelist_web_init_config_if_missing() {
    mkdir -p "$(dirname "$PFWD_WHITELIST_WEB_CONFIG_FILE")"
    if [ ! -f "$PFWD_WHITELIST_WEB_CONFIG_FILE" ]; then
        whitelist_web_default_config_json | pfwd_write_atomic "$PFWD_WHITELIST_WEB_CONFIG_FILE"
    fi
}

whitelist_web_validate_config_file() {
    local file="$1"
    [ -f "$file" ] || pfwd_die "whitelist-web 配置文件不存在：$file"
    jq -e '
      type == "object"
      and ((.listen_host // "") | type == "string")
      and ((.listen_host // "") != "")
      and ((.listen_port // 0) | type == "number")
      and ((.listen_port // 0) >= 1)
      and ((.listen_port // 0) <= 65535)
      and ((.request_timeout_sec // 0) | type == "number")
      and ((.request_timeout_sec // 0) >= 1)
      and ((.trusted_proxy_cidrs // []) | type == "array")
      and ((.routes // []) | type == "array")
    ' "$file" >/dev/null 2>&1 || pfwd_die "无效 whitelist-web 配置文件：$file"
}

whitelist_web_reset_config() {
    mkdir -p "$(dirname "$PFWD_WHITELIST_WEB_CONFIG_FILE")"
    whitelist_web_default_config_json | pfwd_write_atomic "$PFWD_WHITELIST_WEB_CONFIG_FILE"
}

whitelist_web_config_json() {
    whitelist_web_init_config_if_missing
    whitelist_web_validate_config_file "$PFWD_WHITELIST_WEB_CONFIG_FILE"
    jq '
      .listen_host = ((.listen_host // "") | tostring | if . == "" then "127.0.0.1" else . end)
      | .listen_port = ((.listen_port // 18080) | tonumber)
      | .request_timeout_sec = ((.request_timeout_sec // 30) | tonumber)
      | .trusted_proxy_cidrs = ((.trusted_proxy_cidrs // []) | map(tostring))
      | .routes = (
          (.routes // [])
          | map(
              .secret = ((.secret // "") | tostring)
              | .label = (
                  (.label // "") | tostring
                  | if . == "" then ((.note // "") | tostring) else . end
                )
              | .ssh_target = ((.ssh_target // "") | tostring)
              | .idle_ttl = ((.idle_ttl // "") | tostring)
              | .ssh_options = ((.ssh_options // []) | map(tostring))
              | del(.note)
            )
        )
    ' "$PFWD_WHITELIST_WEB_CONFIG_FILE"
}

whitelist_web_write_config_json() {
    local payload="$1"
    mkdir -p "$(dirname "$PFWD_WHITELIST_WEB_CONFIG_FILE")"
    [ -n "$payload" ] || pfwd_die "whitelist-web 配置写入内容为空"
    payload="$(pfwd_require_json_output "whitelist-web 配置" "$payload")"
    printf '%s\n' "$payload" | jq '.' | pfwd_write_atomic "$PFWD_WHITELIST_WEB_CONFIG_FILE"
}

whitelist_web_write_config_from_stdin() {
    local payload
    payload="$(cat)"
    [ -n "$payload" ] || pfwd_die "whitelist-web 配置写入内容为空"
    whitelist_web_write_config_json "$payload"
}

whitelist_web_validate_label() {
    local value="$1"
    [ -n "$value" ] || pfwd_die "label 不能为空"
}

whitelist_web_validate_secret() {
    local value="$1"
    [ -n "$value" ] || pfwd_die "secret 不能为空"
    [[ "$value" =~ ^[A-Za-z0-9._~-]+$ ]] || pfwd_die "secret 仅允许字母、数字、点、下划线、短横线和波浪线"
}

whitelist_web_validate_listen_host() {
    local value="$1"
    [ -n "$value" ] || pfwd_die "listen_host 不能为空"
}

whitelist_web_validate_timeout() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] || pfwd_die "request_timeout_sec 必须是正整数"
    [ "$value" -ge 1 ] || pfwd_die "request_timeout_sec 必须大于 0"
}

whitelist_web_validate_ssh_port() {
    local value="$1"
    [ -n "$value" ] || return 0
    [[ "$value" =~ ^[0-9]+$ ]] || pfwd_die "ssh_port 必须是 1-65535 的整数"
    [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || pfwd_die "ssh_port 必须是 1-65535 的整数"
}

whitelist_web_validate_route() {
    local secret="$1" label="$2" ssh_target="$3" idle_ttl="$4"
    whitelist_web_validate_secret "$secret"
    whitelist_web_validate_label "$label"
    [ -n "$ssh_target" ] || pfwd_die "ssh_target 不能为空"
    pfwd_parse_duration_seconds "$idle_ttl" >/dev/null
}

whitelist_web_validate_trusted_proxy_list() {
    local file="$1"
    local raw
    [ -f "$file" ] || return 0
    while IFS= read -r raw; do
        raw="$(printf '%s' "$raw" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -n "$raw" ] || continue
        normalize_ip_or_cidr "$raw" >/dev/null
    done < "$file"
}

whitelist_web_config_show() {
    whitelist_web_config_json | jq '.'
}

whitelist_web_status_json() {
    local config_json active_state enabled_state service_present bin_path route_count
    config_json="$(whitelist_web_config_json)" || return 1
    config_json="$(pfwd_require_json_output "whitelist-web 配置" "$config_json")" || return 1
    route_count="$(jq -r '(.routes // []) | length' <<< "$config_json")"
    bin_path="$(whitelist_web_bin_path)"
    service_present="false"
    active_state="unknown"
    enabled_state="unknown"

    if service_unit_exists pfwd-whitelist-web.service; then
        service_present="true"
        if command -v systemctl >/dev/null 2>&1; then
            active_state="$(systemctl is-active pfwd-whitelist-web.service 2>/dev/null || true)"
            enabled_state="$(systemctl is-enabled pfwd-whitelist-web.service 2>/dev/null || true)"
            [ -n "$active_state" ] || active_state="unknown"
            [ -n "$enabled_state" ] || enabled_state="unknown"
        fi
    fi

    jq -n \
      --arg config_file "$PFWD_WHITELIST_WEB_CONFIG_FILE" \
      --arg bin_path "$bin_path" \
      --arg restricted_command "$(whitelist_web_restricted_command_install_path)" \
      --argjson config "$config_json" \
      --argjson route_count "$route_count" \
      --arg service_present "$service_present" \
      --arg active_state "$active_state" \
      --arg enabled_state "$enabled_state" '
      {
        config_file: $config_file,
        bin_path: $bin_path,
        restricted_command: $restricted_command,
        service_present: ($service_present == "true"),
        service_active: $active_state,
        service_enabled: $enabled_state,
        route_count: $route_count,
        config: $config
      }
    '
}

whitelist_web_status_rows() {
    whitelist_web_status_json | jq -r '
      [
        ["监听地址", (.config.listen_host + ":" + ((.config.listen_port // 0) | tostring))],
        ["请求超时", ((.config.request_timeout_sec // 0) | tostring) + "s"],
        ["可信反代 CIDR", (((.config.trusted_proxy_cidrs // []) | length) | tostring)],
        ["规则数", (.route_count | tostring)],
        ["服务文件", (if .service_present then "已安装" else "未安装" end)],
        ["服务状态", .service_active],
        ["开机自启", .service_enabled],
        ["配置文件", .config_file],
        ["二进制", .bin_path],
        ["受限命令脚本", .restricted_command]
      ]
      | map(@tsv)
      | .[]
    '
}

whitelist_web_config_set_globals() {
    local listen_host="$1" listen_port="$2" request_timeout_sec="$3"
    [ -n "$listen_host" ] && whitelist_web_validate_listen_host "$listen_host"
    [ -n "$listen_port" ] && validate_port "$listen_port"
    [ -n "$request_timeout_sec" ] && whitelist_web_validate_timeout "$request_timeout_sec"
    whitelist_web_config_json | jq \
      --arg listen_host "$listen_host" \
      --argjson listen_port "${listen_port:-0}" \
      --argjson request_timeout_sec "${request_timeout_sec:-0}" '
      if $listen_host != "" then .listen_host = $listen_host else . end
      | if $listen_port > 0 then .listen_port = $listen_port else . end
      | if $request_timeout_sec > 0 then .request_timeout_sec = $request_timeout_sec else . end
    ' | whitelist_web_write_config_from_stdin
}

whitelist_web_trusted_proxy_list() {
    whitelist_web_config_json | jq -r '
      (.trusted_proxy_cidrs // [])
      | to_entries[]
      | [((.key + 1) | tostring), .value]
      | @tsv
    '
}

whitelist_web_trusted_proxy_clear() {
    whitelist_web_config_json | jq '.trusted_proxy_cidrs = []' | whitelist_web_write_config_from_stdin
}

whitelist_web_trusted_proxy_add() {
    local cidr
    cidr="$(normalize_ip_or_cidr "$1")"
    whitelist_web_config_json | jq --arg cidr "$cidr" '
      .trusted_proxy_cidrs = (((.trusted_proxy_cidrs // []) + [$cidr]) | unique)
    ' | whitelist_web_write_config_from_stdin
}

whitelist_web_trusted_proxy_delete_by_indexes() {
    local indexes="$1" count raw
    [ -n "$indexes" ] || pfwd_die "缺少可信反代 CIDR 序号"
    count="$(whitelist_web_trusted_proxy_list | sed '/^$/d' | wc -l | tr -d ' ')"
    [ "$count" -gt 0 ] || pfwd_die "暂无可信反代 CIDR"
    while IFS= read -r raw; do
        [ -n "$raw" ] || continue
        [[ "$raw" =~ ^[0-9]+$ ]] || pfwd_die "可信反代 CIDR 序号必须是正整数：$raw"
        [ "$raw" -ge 1 ] && [ "$raw" -le "$count" ] || pfwd_die "可信反代 CIDR 序号不存在：$raw"
    done <<< "$indexes"
    whitelist_web_config_json | jq --arg raw "$indexes" '
      ($raw | split("\n") | map(select(length > 0) | tonumber)) as $wanted
      | .trusted_proxy_cidrs = (
          (.trusted_proxy_cidrs // [])
          | to_entries
          | map(select((((.key + 1) as $idx | ($wanted | index($idx))) | not)))
          | map(.value)
        )
    ' | whitelist_web_write_config_from_stdin
}

whitelist_web_route_count() {
    local config_json
    config_json="$(whitelist_web_config_json)" || return 1
    jq -r '(.routes // []) | length' <<< "$config_json"
}

whitelist_web_route_rows() {
    local config_json
    config_json="$(whitelist_web_config_json)" || return 1
    jq -r '
      (.routes // [])
      | to_entries[]
      | [
          ((.key + 1) | tostring),
          (.value.label // "-"),
          (.value.secret // "-"),
          (.value.ssh_target // "-"),
          (.value.idle_ttl // "-"),
          ((.value.ssh_options // []) | join(" "))
        ]
      | @tsv
    ' <<< "$config_json"
}

whitelist_web_route_ui_rows() {
    local count index label secret ssh_target idle_ttl ssh_port ssh_options
    count="$(whitelist_web_route_count)"
    for ((index = 1; index <= count; index++)); do
        label="$(whitelist_web_route_field "$index" label)"
        secret="$(whitelist_web_route_field "$index" secret)"
        ssh_target="$(whitelist_web_route_field "$index" ssh_target)"
        idle_ttl="$(whitelist_web_route_field "$index" idle_ttl)"
        ssh_port="$(whitelist_web_route_ssh_port "$index")"
        ssh_options="$(whitelist_web_route_ssh_options_text_without_port "$index")"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$index" \
            "${label:--}" \
            "${secret:--}" \
            "${ssh_target:--}" \
            "${ssh_port:--}" \
            "${idle_ttl:--}" \
            "${ssh_options:--}"
    done
}

whitelist_web_route_json_by_index() {
    local index="$1"
    local config_json
    config_json="$(whitelist_web_config_json)" || return 1
    jq -c --argjson index "$index" '
      (.routes // [])[$index - 1] // empty
    ' <<< "$config_json"
}

whitelist_web_ssh_port_from_options_json() {
    local options_json="${1:-[]}"
    jq -r '
      . as $options
      | (
          reduce range(0; ($options | length)) as $i (null;
            if . != null then
              .
            elif ($options[$i] == "-p") then
              ($options[$i + 1] // "")
            elif (($options[$i] // "") | startswith("-p")) and ($options[$i] != "-p") then
              ($options[$i][2:])
            else
              null
            end
          )
        ) // ""
    ' <<< "$options_json"
}

whitelist_web_ssh_options_without_port_json() {
    local options_json="${1:-[]}"
    jq -c '
      . as $options
      | reduce range(0; ($options | length)) as $i ([];
          if ($options[$i] == "-p") then
            .
          elif ($i > 0) and ($options[$i - 1] == "-p") then
            .
          elif (($options[$i] // "") | startswith("-p")) and ($options[$i] != "-p") then
            .
          else
            . + [$options[$i]]
          end
        )
    ' <<< "$options_json"
}

whitelist_web_route_ssh_options_json() {
    local index="$1"
    whitelist_web_route_json_by_index "$index" | jq -c '(.ssh_options // [])'
}

whitelist_web_route_ssh_port() {
    local index="$1"
    whitelist_web_ssh_port_from_options_json "$(whitelist_web_route_ssh_options_json "$index")"
}

whitelist_web_route_ssh_options_text_without_port() {
    local index="$1"
    whitelist_web_ssh_options_without_port_json "$(whitelist_web_route_ssh_options_json "$index")" | jq -r 'join(" ")'
}

whitelist_web_build_ssh_options_json() {
    local ssh_port="${1:-}" raw="${2:-}" parsed_json effective_port normalized_json
    parsed_json="$(whitelist_web_parse_ssh_options_json "$raw")"
    if jq -e '
        . as $options
        | any(range(0; ($options | length)); ($options[.] == "-p") and (($options[. + 1] // "") == ""))
      ' >/dev/null 2>&1 <<< "$parsed_json"; then
        pfwd_die "ssh_options 中的 -p 缺少端口值，请改用 --ssh-port PORT 或补齐端口"
    fi
    effective_port="$ssh_port"
    if [ -z "$effective_port" ]; then
        effective_port="$(whitelist_web_ssh_port_from_options_json "$parsed_json")"
    fi
    whitelist_web_validate_ssh_port "$effective_port"
    normalized_json="$(whitelist_web_ssh_options_without_port_json "$parsed_json")"
    if [ -n "$effective_port" ]; then
        jq -c --arg port "$effective_port" '
          ["-p", $port] + .
        ' <<< "$normalized_json"
        return 0
    fi
    printf '%s\n' "$normalized_json"
}

whitelist_web_route_add() {
    local secret="$1" label="$2" ssh_target="$3" idle_ttl="$4" ssh_options_json="$5"
    whitelist_web_validate_route "$secret" "$label" "$ssh_target" "$idle_ttl"
    whitelist_web_config_json | jq \
      --arg secret "$secret" \
      --arg route_label "$label" \
      --arg ssh_target "$ssh_target" \
      --arg idle_ttl "$idle_ttl" \
      --argjson ssh_options "$ssh_options_json" '
      if any((.routes // [])[]; (.secret // "") == $secret) then
        error("route.secret 已存在")
      else
        .routes = ((.routes // []) + [{
          "secret": $secret,
          "label": $route_label,
          "ssh_target": $ssh_target,
          "idle_ttl": $idle_ttl,
          "ssh_options": $ssh_options
        }])
      end
    ' | whitelist_web_write_config_from_stdin
}

whitelist_web_route_update() {
    local index="$1" secret="$2" label="$3" ssh_target="$4" idle_ttl="$5" ssh_options_json="$6"
    whitelist_web_validate_route "$secret" "$label" "$ssh_target" "$idle_ttl"
    whitelist_web_config_json | jq \
      --argjson index "$index" \
      --arg secret "$secret" \
      --arg route_label "$label" \
      --arg ssh_target "$ssh_target" \
      --arg idle_ttl "$idle_ttl" \
      --argjson ssh_options "$ssh_options_json" '
      . as $config
      | if (($index - 1) < 0) or (($index - 1) >= (($config.routes // []) | length)) then
        error("route 序号不存在")
      elif any(($config.routes // [])[]; (.secret // "") == $secret and (.secret // "") != (($config.routes[$index - 1].secret // ""))) then
        error("route.secret 已存在")
      else
        .routes[$index - 1] = {
          "secret": $secret,
          "label": $route_label,
          "ssh_target": $ssh_target,
          "idle_ttl": $idle_ttl,
          "ssh_options": $ssh_options
        }
      end
    ' | whitelist_web_write_config_from_stdin
}

whitelist_web_route_delete_by_indexes() {
    local indexes="$1" count raw
    [ -n "$indexes" ] || pfwd_die "缺少规则序号"
    count="$(whitelist_web_route_count)"
    [ "$count" -gt 0 ] || pfwd_die "暂无规则"
    while IFS= read -r raw; do
        [ -n "$raw" ] || continue
        [[ "$raw" =~ ^[0-9]+$ ]] || pfwd_die "规则序号必须是正整数：$raw"
        [ "$raw" -ge 1 ] && [ "$raw" -le "$count" ] || pfwd_die "route 序号不存在：$raw"
    done <<< "$indexes"
    whitelist_web_config_json | jq --arg raw "$indexes" '
      ($raw | split("\n") | map(select(length > 0) | tonumber)) as $wanted
      | .routes = (
          (.routes // [])
          | to_entries
          | map(select((((.key + 1) as $idx | ($wanted | index($idx))) | not)))
          | map(.value)
        )
    ' | whitelist_web_write_config_from_stdin
}

whitelist_web_route_field() {
    local index="$1" field="$2"
    whitelist_web_route_json_by_index "$index" | jq -r --arg field "$field" '.[$field] // ""'
}

whitelist_web_route_ssh_options_text() {
    local index="$1"
    whitelist_web_route_json_by_index "$index" | jq -r '(.ssh_options // []) | join(" ")'
}

whitelist_web_parse_ssh_options_json() {
    local raw="${1:-}"
    if [ -z "$raw" ]; then
        printf '[]\n'
        return 0
    fi
    printf '%s\n' "$raw" | jq -Rc '
      split(" ")
      | map(select(length > 0))
    '
}

whitelist_web_service_action() {
    local action="$1"
    command -v systemctl >/dev/null 2>&1 || pfwd_die "缺少 systemctl"
    case "$action" in
        status)
            systemctl status pfwd-whitelist-web.service --no-pager
            ;;
        start|stop|restart|enable|disable)
            pfwd_run systemctl "$action" pfwd-whitelist-web.service
            ;;
        *)
            pfwd_die "未知 whitelist-web service 动作：$action"
            ;;
    esac
}

cmd_whitelist_web() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        run)
            local bin config_path="$PFWD_WHITELIST_WEB_CONFIG_FILE"
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --config) config_path="${2:-}"; shift 2 ;;
                    *) pfwd_die "未知选项：$1" ;;
                esac
            done
            [ -n "$config_path" ] || pfwd_die "必须提供 --config"
            [ -f "$config_path" ] || pfwd_die "whitelist-web 配置文件不存在：$config_path"
            bin="$(whitelist_web_bin_path)"
            [ -x "$bin" ] || pfwd_die "pfwd-whitelist-web 二进制不存在：$bin"
            exec "$bin" run --config "$config_path"
            ;;
        init)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd whitelist-web init"
            whitelist_web_init_config_if_missing
            echo "whitelist-web 配置已就绪：$PFWD_WHITELIST_WEB_CONFIG_FILE"
            ;;
        status)
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd whitelist-web status"
            whitelist_web_status_rows
            ;;
        config)
            local action="${1:-show}"
            shift || true
            case "$action" in
                show)
                    [ "$#" -eq 0 ] || pfwd_die "用法：pfwd whitelist-web config show"
                    whitelist_web_config_show
                    ;;
                reset)
                    [ "$#" -eq 0 ] || pfwd_die "用法：pfwd whitelist-web config reset"
                    whitelist_web_reset_config
                    echo "whitelist-web 配置已重置"
                    ;;
                set)
                    local listen_host="" listen_port="" request_timeout_sec=""
                    while [ "$#" -gt 0 ]; do
                        case "$1" in
                            --listen-host) listen_host="${2:-}"; shift 2 ;;
                            --listen-port) listen_port="${2:-}"; shift 2 ;;
                            --request-timeout-sec) request_timeout_sec="${2:-}"; shift 2 ;;
                            *) pfwd_die "未知选项：$1" ;;
                        esac
                    done
                    [ -n "$listen_host$listen_port$request_timeout_sec" ] || pfwd_die "用法：pfwd whitelist-web config set [--listen-host HOST] [--listen-port PORT] [--request-timeout-sec SEC]"
                    whitelist_web_config_set_globals "$listen_host" "$listen_port" "$request_timeout_sec"
                    echo "whitelist-web 配置已更新"
                    ;;
                *)
                    pfwd_die "用法：pfwd whitelist-web config show|reset|set ..."
                    ;;
            esac
            ;;
        trusted-proxy)
            local action="${1:-list}"
            shift || true
            case "$action" in
                list)
                    [ "$#" -eq 0 ] || pfwd_die "用法：pfwd whitelist-web trusted-proxy list"
                    whitelist_web_trusted_proxy_list
                    ;;
                add)
                    [ "$#" -eq 1 ] || pfwd_die "用法：pfwd whitelist-web trusted-proxy add <CIDR|IP>"
                    whitelist_web_trusted_proxy_add "$1"
                    echo "可信反代 CIDR 已添加"
                    ;;
                delete)
                    [ "$#" -ge 1 ] || pfwd_die "用法：pfwd whitelist-web trusted-proxy delete <index...>"
                    whitelist_web_trusted_proxy_delete_by_indexes "$(printf '%s\n' "$@")"
                    echo "可信反代 CIDR 已删除"
                    ;;
                clear)
                    [ "$#" -eq 0 ] || pfwd_die "用法：pfwd whitelist-web trusted-proxy clear"
                    whitelist_web_trusted_proxy_clear
                    echo "可信反代 CIDR 已清空"
                    ;;
                *)
                    pfwd_die "用法：pfwd whitelist-web trusted-proxy list|add|delete|clear"
                    ;;
            esac
            ;;
        route)
            local action="${1:-list}"
            shift || true
            case "$action" in
                list)
                    [ "$#" -eq 0 ] || pfwd_die "用法：pfwd whitelist-web route list"
                    whitelist_web_route_rows
                    ;;
                add)
                    local secret="" label="" ssh_target="" idle_ttl="" ssh_port="" ssh_options_raw="" ssh_options_json='[]'
                    while [ "$#" -gt 0 ]; do
                        case "$1" in
                            --secret) secret="${2:-}"; shift 2 ;;
                            --label) label="${2:-}"; shift 2 ;;
                            --ssh-target) ssh_target="${2:-}"; shift 2 ;;
                            --idle-ttl) idle_ttl="${2:-}"; shift 2 ;;
                            --ssh-port) ssh_port="${2:-}"; shift 2 ;;
                            --ssh-options) ssh_options_raw="${2:-}"; shift 2 ;;
                            *) pfwd_die "未知选项：$1" ;;
                        esac
                    done
                    ssh_options_json="$(whitelist_web_build_ssh_options_json "$ssh_port" "$ssh_options_raw")"
                    whitelist_web_route_add "$secret" "$label" "$ssh_target" "$idle_ttl" "$ssh_options_json"
                    echo "whitelist-web 规则已添加"
                    ;;
                update)
                    local index="" secret="" label="" ssh_target="" idle_ttl="" ssh_port="" ssh_options_raw="" ssh_options_json='[]'
                    while [ "$#" -gt 0 ]; do
                        case "$1" in
                            --index) index="${2:-}"; shift 2 ;;
                            --secret) secret="${2:-}"; shift 2 ;;
                            --label) label="${2:-}"; shift 2 ;;
                            --ssh-target) ssh_target="${2:-}"; shift 2 ;;
                            --idle-ttl) idle_ttl="${2:-}"; shift 2 ;;
                            --ssh-port) ssh_port="${2:-}"; shift 2 ;;
                            --ssh-options) ssh_options_raw="${2:-}"; shift 2 ;;
                            *) pfwd_die "未知选项：$1" ;;
                        esac
                    done
                    ssh_options_json="$(whitelist_web_build_ssh_options_json "$ssh_port" "$ssh_options_raw")"
                    [[ "$index" =~ ^[0-9]+$ ]] || pfwd_die "用法：pfwd whitelist-web route update --index N --secret SECRET --label LABEL --ssh-target TARGET --idle-ttl TTL [--ssh-port PORT] [--ssh-options '...']"
                    whitelist_web_route_update "$index" "$secret" "$label" "$ssh_target" "$idle_ttl" "$ssh_options_json"
                    echo "whitelist-web 规则已更新"
                    ;;
                delete)
                    [ "$#" -ge 1 ] || pfwd_die "用法：pfwd whitelist-web route delete <index...>"
                    whitelist_web_route_delete_by_indexes "$(printf '%s\n' "$@")"
                    echo "whitelist-web 规则已删除"
                    ;;
                *)
                    pfwd_die "用法：pfwd whitelist-web route list|add|update|delete"
                    ;;
            esac
            ;;
        service)
            local action="${1:-status}"
            shift || true
            [ "$#" -eq 0 ] || pfwd_die "用法：pfwd whitelist-web service status|start|stop|restart|enable|disable"
            whitelist_web_service_action "$action"
            ;;
        *)
            pfwd_die "用法：pfwd whitelist-web run|init|status|config|trusted-proxy|route|service ..."
            ;;
    esac
}
