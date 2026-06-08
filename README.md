# pfwd

`pfwd` 是一个 XDP 优先的端口转发管理工具，负责转发规则、用户流量统计、限速限量、入口/出口白名单、协议封锁、下行伪装和系统调优。非 localhost 规则优先走 XDP；XDP 不可用时按规则回退到 `nftables`，速率限制由 `tc` 执行。

完整命令面以 `pfwd help` 为准。

## 功能

- TCP / UDP / TCP+UDP 端口转发，支持 IPv4、IPv6、域名目标和运行时解析。
- 用户与规则级流量统计，支持单向/双向计费、倍率、总量限制和限速。
- 入口白名单、出口白名单、TCP 首包协议封锁和入口跳过端口。
- 入口白名单支持全局策略，也支持按监听端口覆盖国内 IP / 省份 / 市策略。
- 下行伪装支持公网下载源和 A/B 机拉流 / 喂流。
- `pfwd-bbr` 独立管理 BBR、sysctl、BQL、RPS/XPS 和 tc shaping。

## 安装

运行环境需要 `jq`、`iproute2` / `ip` / `tc`、`systemd`、`curl` 或 `wget`，以及挂载在 `/sys/fs/bpf` 的 bpffs。只有自己构建资产时才需要 Go、clang 和 eBPF 工具链。

在线安装：

```bash
wget -qO- https://raw.githubusercontent.com/mora1n/pfwd/main/pfwd.sh | bash -s -- install
```

安装后检查：

```bash
pfwd doctor
/usr/local/lib/pfwd/bin/pfwd-xdp version
/usr/local/lib/pfwd/bin/pfwd-downmask version
```

离线安装时，安装包至少需要包含：

- `pfwd.sh`、`bbr.sh`、`lib/`
- `scripts/pfwd_whitelist_lease_command.sh`
- `assets/pfwd-xdp-linux-amd64` 或 `assets/pfwd-xdp-linux-arm64`
- `assets/pfwd-downmask-linux-amd64` 或 `assets/pfwd-downmask-linux-arm64`
- `assets/pfwd-geo-cn-v4.bin`、`assets/pfwd-geo-cn-v6.bin`、`assets/pfwd-geo-meta.json`
- `assets/pfwd-city-cn-meta.json`、`assets/pfwd-city-cn-v4.bin`

如果还要在控制机上启用临时白名单 Web 入口，离线包另外加入：

- `assets/pfwd-whitelist-web-linux-amd64` 或 `assets/pfwd-whitelist-web-linux-arm64`

构建资产：

```bash
./xdp/build.sh
./downmask/build.sh
./whitelist_web/build.sh
```

打包（以 amd64 为例，arm64 替换为对应文件名）：

```bash
tar -czf pfwd.tar.gz \
  pfwd.sh bbr.sh lib/ scripts/ \
  assets/pfwd-xdp-linux-amd64 \
  assets/pfwd-downmask-linux-amd64 \
  assets/pfwd-geo-cn-v4.bin assets/pfwd-geo-cn-v6.bin assets/pfwd-geo-meta.json \
  assets/pfwd-city-cn-meta.json assets/pfwd-city-cn-v4.bin
```

如需控制机 Web 入口，再追加 `assets/pfwd-whitelist-web-linux-amd64` 或对应 arm64 产物。

目标机器解压后运行：

```bash
tar -xzf pfwd.tar.gz
bash ./pfwd.sh install
```

## 快速开始

```bash
pfwd init
pfwd user add alice
pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol tcp
pfwd refresh
pfwd stats --user-id alice
```

带 MSS / 固定 SNAT 的规则：

```bash
pfwd add \
  --user-id alice \
  --remote 198.51.100.20:443 \
  --listen-port 25002 \
  --protocol tcp \
  --mss 1360 \
  --snat-source 198.51.100.10
```

## 流量防护

`pfwd guard` 管理入口白名单、出口白名单和协议封锁。

```bash
pfwd guard enable
pfwd guard protocols --https true --socks true --skip-port 25001

pfwd guard whitelist --enabled true
pfwd guard whitelist-cn all
pfwd guard whitelist-cn select 广东省 江苏省
pfwd guard whitelist-city add 湖南省 长沙市
pfwd guard whitelist-custom add 203.0.113.5
pfwd guard whitelist-lease add --address 198.51.100.8 --idle-ttl 2h --channel manual --note phone
pfwd guard whitelist-lease list

pfwd guard whitelist-port status --listen-port 41423
pfwd guard whitelist-port-cn --listen-port 41423 select 浙江省
pfwd guard whitelist-port-city --listen-port 41423 add 浙江省 杭州市
pfwd guard whitelist-port clear --listen-port 41423

pfwd guard whitelist check --address 61.187.9.117 --listen-port 41422 --protocol tcp

pfwd guard egress-whitelist --enabled true
pfwd guard egress-whitelist-cn all
pfwd guard egress-whitelist-custom add 204.0.113.0/24
```

入口白名单的 `enabled` 是总开关。未配置端口覆盖时，端口继承全局国内 IP / 省份 / 市策略；配置端口覆盖后，仅该监听端口使用自己的国内 IP / 省份 / 市选择。入口自定义 CIDR 始终全局共享。`guard whitelist-lease` 维护的是全局临时 IP 白名单，对所有启用入口白名单的端口统一生效。`guard protocols --skip-port` 优先级更高，命中后跳过入口白名单和协议封锁。

## 临时白名单 Web 入口

控制机可以运行一个轻量 Web 服务：收到私密 URL 请求后，读取服务端观测到的来源公网 IP，并通过 SSH 调目标机上的 `pfwd guard whitelist-lease add` 添加全局临时入口白名单。

最小使用流程：

```bash
./whitelist_web/build.sh
pfwd whitelist-web init
pfwd whitelist-web config set --listen-host your-host-ip --listen-port 18080 --request-timeout-sec 30
pfwd whitelist-web trusted-proxy add 127.0.0.1/32
pfwd whitelist-web trusted-proxy add ::1/128
pfwd whitelist-web route add --secret '<随机secret>' --label your-label --ssh-target 'root@target-host' --ssh-port 22 --idle-ttl 4h --ssh-options '-i /root/.ssh/pfwd-whitelist-web -o IdentitiesOnly=yes'
pfwd whitelist-web service enable
pfwd whitelist-web service start
pfwd whitelist-web run --config /etc/pfwd/whitelist-web.json
```

常用检查命令：

```bash
pfwd whitelist-web status
pfwd whitelist-web config show
pfwd whitelist-web config reset
pfwd whitelist-web route list
pfwd whitelist-web service status
```

如果前面有反代，只有当 TCP peer 命中 `trusted_proxy_cidrs` 时才会信任 `X-Real-IP` / `X-Forwarded-For`；否则一律使用直连 peer IP。控制机走 systemd 时通常只需要 `service enable/start`；前台调试时才直接执行 `pfwd whitelist-web run --config ...`。如果规则里不配置 `SSH 端口` / `SSH 选项`，`whitelist-web` 会直接依赖控制机系统 `ssh` 的默认行为与外部 `ssh_config`，需自行保证 SSH 已可连通。

如果 `/etc/pfwd/whitelist-web.json` 为空或损坏，`pfwd whitelist-web config show/set` 与 TUI 会显式报错；可先执行 `pfwd whitelist-web config reset` 重建默认 skeleton，再重新配置。

推荐把配置和服务管理直接放到 `pfwd` TUI：

- `流量防护 -> 临时白名单 Web`
- 可查看状态、修改监听地址/端口/超时、维护“可信反代 CIDR”、管理规则，以及启动/停止/重启/启停自启服务。

SSH 权限边界建议收窄到只允许临时白名单租约命令。安装后的受限命令脚本路径为：

```bash
/usr/local/lib/pfwd/bin/pfwd-whitelist-lease-command
```

目标机 `authorized_keys` 示例：

```text
command="/usr/local/lib/pfwd/bin/pfwd-whitelist-lease-command",no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding ssh-ed25519 AAAA... control-host
```

控制机 `ssh_options` 推荐指向专用 key / config，例如：

```json
["-F", "/home/user/.ssh/config", "-i", "/home/user/.ssh/pfwd-whitelist-web"]
```

规则中的 `label` 是唯一文本标识，会同时用于：

- TUI 和配置展示
- Web 接口返回 JSON 的 `label`
- 目标机 `pfwd guard whitelist-lease add --note <label>` 的备注文本

出口白名单限制转发目标解析出的 IP，同时限制宿主机全部非 loopback 出口流量。

## 下行伪装

`pfwd downmask` 按日内收发比例补下行流量，支持公网下载源和 A/B 机模式。

```bash
pfwd downmask policy --pull-mode public --iface eth0
pfwd downmask public --active-source cloudflare_dynamic --speed-limit 4M

TOKEN="$(openssl rand -hex 16)"
pfwd downmask policy --pull-mode ab --iface eth0
pfwd downmask ab-pull --protocol-mode parallel --remote-port 5301 --token "$TOKEN" --speed-limit 4M
pfwd downmask ab-pull targets add --host 10.0.0.2 --weight 3 --tcp-enabled true --udp-enabled true
pfwd downmask ab-feed --tcp-enabled true --bind-ip 10.0.0.2 --tcp-port 5301 --token "$TOKEN"
pfwd downmask seed generate --size 1GB
pfwd downmask status
```

A/B 两端 `token` 必须一致。`speed_limit` 支持 `4M`、`4MB/s`、`32Mbps`、`1GB/s` 等格式。

## 常用命令

| 场景 | 命令 |
| --- | --- |
| 进入菜单 | `pfwd` |
| 添加用户 | `pfwd user add alice` |
| 添加转发 | `pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol tcp` |
| 查看转发 | `pfwd list` |
| 查看统计 | `pfwd stats --user-id alice` |
| 刷新运行态 | `pfwd refresh` |
| 重启运行态 | `pfwd restart` |
| 查看状态 | `pfwd render status` |
| 查看防护 | `pfwd guard status` |
| 查看下行伪装 | `pfwd downmask status` |
| 诊断 | `pfwd doctor` |

## 规则说明

- 端口支持单个端口、逗号列表和范围，例如 `443`、`443,8443`、`10000-10010`。
- 监听 IP 默认 `::`；当前 XDP 正向转发只支持通配监听地址 `::` / `0.0.0.0`。
- 远端地址支持域名、IPv4 和 `[IPv6]:PORT`。
- 同一监听端口可拆分为一条 TCP 和一条 UDP 转发。
- localhost / `127.0.0.1` / `::1` 目标固定走 `nftables`。
- localhost 与非 localhost 规则并存时，状态显示为 `hybrid`，这是正常规则级分流。

## 路径

- 主配置：`/etc/pfwd/config.json`
- 主脚本、库和资产：`/usr/local/lib/pfwd/`
- CLI 入口：`/usr/local/bin/pfwd`、`/usr/local/bin/pfwd-bbr`
- 统计和状态：`/var/lib/pfwd/`
- 运行态 JSON：`/run/pfwd/`
- eBPF pin：`/sys/fs/bpf/`

## BBR / 系统调优

```bash
pfwd-bbr status
pfwd-bbr optimize relay --egress-rate 100mbit --ingress-rate 100mbit --tc-iface eth0
pfwd-bbr reset
```

## 卸载

```bash
pfwd uninstall
pfwd-bbr uninstall
```

## 许可证

本项目使用 [MIT License](LICENSE)。
