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
        request_timeout_sec: 8,
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

whitelist_web_config_json() {
    whitelist_web_init_config_if_missing
    jq '
      .listen_host = ((.listen_host // "") | tostring | if . == "" then "127.0.0.1" else . end)
      | .listen_port = ((.listen_port // 18080) | tonumber)
      | .request_timeout_sec = ((.request_timeout_sec // 8) | tonumber)
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
    printf '%s\n' "$payload" | jq '.' | pfwd_write_atomic "$PFWD_WHITELIST_WEB_CONFIG_FILE"
}

whitelist_web_write_config_from_stdin() {
    local payload
    payload="$(cat)"
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
    config_json="$(whitelist_web_config_json)"
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
    local indexes="$1"
    [ -n "$indexes" ] || pfwd_die "缺少可信反代 CIDR 序号"
    whitelist_web_config_json | jq --arg raw "$indexes" '
      ($raw | split("\n") | map(select(length > 0) | tonumber)) as $wanted
      | .trusted_proxy_cidrs = (
          (.trusted_proxy_cidrs // [])
          | to_entries
          | map(select((($wanted | index(.key + 1)) | not)))
          | map(.value)
        )
    ' | whitelist_web_write_config_from_stdin
}

whitelist_web_route_count() {
    whitelist_web_config_json | jq -r '(.routes // []) | length'
}

whitelist_web_route_rows() {
    whitelist_web_config_json | jq -r '
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
    '
}

whitelist_web_route_json_by_index() {
    local index="$1"
    whitelist_web_config_json | jq -c --argjson index "$index" '
      (.routes // [])[$index - 1] // empty
    '
}

whitelist_web_route_add() {
    local secret="$1" label="$2" ssh_target="$3" idle_ttl="$4" ssh_options_json="$5"
    whitelist_web_validate_route "$secret" "$label" "$ssh_target" "$idle_ttl"
    whitelist_web_config_json | jq \
      --arg secret "$secret" \
      --arg label "$label" \
      --arg ssh_target "$ssh_target" \
      --arg idle_ttl "$idle_ttl" \
      --argjson ssh_options "$ssh_options_json" '
      if any((.routes // [])[]; (.secret // "") == $secret) then
        error("route.secret 已存在")
      else
        .routes = ((.routes // []) + [{
          secret: $secret,
          label: $label,
          ssh_target: $ssh_target,
          idle_ttl: $idle_ttl,
          ssh_options: $ssh_options
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
      --arg label "$label" \
      --arg ssh_target "$ssh_target" \
      --arg idle_ttl "$idle_ttl" \
      --argjson ssh_options "$ssh_options_json" '
      if (($index - 1) < 0) or (($index - 1) >= ((.routes // []) | length)) then
        error("route 序号不存在")
      elif any((.routes // [])[]; (.secret // "") == $secret and (.secret // "") != ((.routes[$index - 1].secret // ""))) then
        error("route.secret 已存在")
      else
        .routes[$index - 1] = {
          secret: $secret,
          label: $label,
          ssh_target: $ssh_target,
          idle_ttl: $idle_ttl,
          ssh_options: $ssh_options
        }
      end
    ' | whitelist_web_write_config_from_stdin
}

whitelist_web_route_delete_by_indexes() {
    local indexes="$1"
    [ -n "$indexes" ] || pfwd_die "缺少规则序号"
    whitelist_web_config_json | jq --arg raw "$indexes" '
      ($raw | split("\n") | map(select(length > 0) | tonumber)) as $wanted
      | .routes = (
          (.routes // [])
          | to_entries
          | map(select((($wanted | index(.key + 1)) | not)))
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
                    pfwd_die "用法：pfwd whitelist-web config show|set ..."
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
                    local secret="" label="" ssh_target="" idle_ttl="" ssh_options_json='[]'
                    while [ "$#" -gt 0 ]; do
                        case "$1" in
                            --secret) secret="${2:-}"; shift 2 ;;
                            --label) label="${2:-}"; shift 2 ;;
                            --ssh-target) ssh_target="${2:-}"; shift 2 ;;
                            --idle-ttl) idle_ttl="${2:-}"; shift 2 ;;
                            --ssh-options) ssh_options_json="$(whitelist_web_parse_ssh_options_json "${2:-}")"; shift 2 ;;
                            *) pfwd_die "未知选项：$1" ;;
                        esac
                    done
                    whitelist_web_route_add "$secret" "$label" "$ssh_target" "$idle_ttl" "$ssh_options_json"
                    echo "whitelist-web 规则已添加"
                    ;;
                update)
                    local index="" secret="" label="" ssh_target="" idle_ttl="" ssh_options_json='[]'
                    while [ "$#" -gt 0 ]; do
                        case "$1" in
                            --index) index="${2:-}"; shift 2 ;;
                            --secret) secret="${2:-}"; shift 2 ;;
                            --label) label="${2:-}"; shift 2 ;;
                            --ssh-target) ssh_target="${2:-}"; shift 2 ;;
                            --idle-ttl) idle_ttl="${2:-}"; shift 2 ;;
                            --ssh-options) ssh_options_json="$(whitelist_web_parse_ssh_options_json "${2:-}")"; shift 2 ;;
                            *) pfwd_die "未知选项：$1" ;;
                        esac
                    done
                    [[ "$index" =~ ^[0-9]+$ ]] || pfwd_die "用法：pfwd whitelist-web route update --index N --secret SECRET --label LABEL --ssh-target TARGET --idle-ttl TTL [--ssh-options '...']"
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
