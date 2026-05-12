# pfwd

`pfwd` 是一个基于 `nftables` 的轻量端口转发管理脚本。  
`pfwd` 负责用户、转发规则、到期停转、流量统计、限速限量、Telegram 通知和 systemd 同步；`nftables` 负责实际转发。  

## Overview

| Item | Description |
|------|-------------|
| Interface | 交互式终端 UI，直接执行 `pfwd` 进入 |
| Forwarding | 支持单端口、端口列表、端口范围、随机端口 |
| Protocol | 支持 `TCP`、`UDP`、`TCP+UDP`，默认 `TCP+UDP` |
| nft Options | 支持 `MSS clamp`、固定 `MSS`、`masquerade`、固定 `SNAT` |
| Traffic | 支持到期日、流量统计、总流量限制、速率限制 |
| Guard | eBPF 流量防护：XDP 白名单、TC 协议封锁（`HTTP`/`TLS`/`SOCKS`） |
| Notify | 支持 Telegram 通知与定时发送 |
| Ops | 支持安装、更新、刷新、排查、导出、导入、卸载 |
| Tuning | `pfwd-bbr` 负责 BBR、sysctl、tc shaping、BQL、RPS/XPS |

## Access Control

`pfwd` 的入口侧访问控制统一收口到 `流量防护`（guard eBPF）：

- 协议封锁：由 guard TC ingress 负责，按 TCP 首包拒绝 `HTTP`、`TLS ClientHello`、`SOCKS4/5`，适合中转机快速拦截特征明显的高风险流量。
- 白名单：由 guard XDP 负责，限制入站来源 IPv4 / IPv6 CIDR。默认可直接启用国内 IP 白名单，也可额外追加自定义 CIDR。非白名单 IP 在 XDP 层直接丢弃，白名单 IP 继续进入 TC 协议检测。
- 当前边界：协议封锁仅覆盖 TCP 首包识别；白名单支持 IPv4 / IPv6 CIDR。

常用命令：

```bash
pfwd guard enable
pfwd guard protocols --https true --socks true
pfwd guard whitelist --enabled true --include-cn true
pfwd guard whitelist --cidr 203.0.113.0/24
pfwd guard status
pfwd guard whitelist status
```

## Requirements

| Dependency | Purpose |
|------------|---------|
| Linux | 运行环境 |
| `bash` | 脚本执行入口 |
| `jq` | 配置与状态 JSON 处理 |
| `nftables` / `nft` | 端口转发、流量统计、限额控制 |
| `iproute2` / `ip` / `tc` | 路由探测与速率限制 |
| `systemd` / `systemctl` | 服务管理与定时同步 |
| `getent` | 域名解析 |

## Install

```bash
wget -qO- https://raw.githubusercontent.com/mora1n/pfwd/main/pfwd.sh | bash -s -- install
```

安装完成后(root权限下)直接运行：

```bash
pfwd
```

### Offline Install

适用于目标机器无法直接访问 GitHub 的场景。离线包需要同时包含 `pfwd.sh`、`bbr.sh`、`lib/` 和 `assets/`；其中 `assets/` 除了 guard 预编译二进制，还包含国内 IPv4 / IPv6 白名单种子 `cn-aggregated.zone` 和 `cn-aggregated-v6.zone`。

离线安装完成后，系统文件结构如下：

```text
系统文件
├── /usr/local/bin/
│   ├── pfwd                    # 管理脚本快捷入口
│   ├── bbr.sh                  # 兼容快捷入口
│   └── pfwd-bbr                # BBR / optimize 管理脚本快捷入口
│
├── /usr/local/lib/pfwd/
│   ├── pfwd.sh                 # pfwd 主脚本
│   ├── bbr.sh                  # BBR / optimize 主脚本
│   ├── bin/
│   │   └── pfwd-guard          # 流量防护预编译 guard (eBPF)
│   ├── assets/
│   │   ├── cn-aggregated.zone     # 国内 IPv4 白名单离线种子
│   │   └── cn-aggregated-v6.zone  # 国内 IPv6 白名单离线种子
│   └── lib/
│       ├── core.sh             # 核心路径、通用工具、文件写入
│       ├── config.sh           # 配置读写、导入导出、规则持久化
│       ├── validate.sh         # 参数校验、端口/地址/速率解析
│       ├── whitelist.sh        # 白名单数据准备与状态展示
│       ├── forwarder.sh        # nft 转发表运行态解析与渲染
│       ├── firewall.sh         # 流量统计、限额、tc 渲染
│       ├── stats.sh            # 流量状态快照与汇总
│       ├── notify.sh           # Telegram 通知
│       ├── service.sh          # 安装、更新、systemd 管理
│       ├── commands.sh         # CLI 命令实现
│       └── ui.sh               # 交互菜单与状态显示
│
├── /etc/pfwd/
│   └── config.json             # 主配置文件（`pfwd init` 或 `pfwd install` 后生成）
│
├── /var/lib/pfwd/
│   ├── stats.json              # 流量统计状态文件
│   ├── bbr-state.env           # BBR / optimize 状态文件
│   ├── whitelist/
│   │   ├── allow_ipv4.txt      # 入站来源 IPv4 白名单运行态
│   │   └── allow_ipv6.txt      # 入站来源 IPv6 白名单运行态
│   └── guard/
│       └── status.json         # guard 运行状态
│
├── /run/pfwd/
│   ├── runtime.json            # 当前解析后的运行态
│   └── forwarder.nft           # 当前渲染出的 nft 转发表
│
└── /etc/systemd/system/
    ├── pfwd-forward.service    # 开机恢复转发运行态
    ├── pfwd.service            # 到期停转、通知、状态同步
    ├── pfwd.timer              # 定时触发 pfwd.service
    ├── pfwd-bbr.service        # 开机恢复 BBR / optimize 运行态
    └── pfwd-guard.service      # 开机恢复流量防护运行态
```

建议的离线安装步骤：

1. 在可联网机器准备离线包：

```bash
tar czf pfwd-offline.tar.gz pfwd.sh bbr.sh lib/ assets/
```

2. 把 `pfwd-offline.tar.gz` 拷贝到目标机器并解压：

```bash
tar xzf pfwd-offline.tar.gz
```

3. 安装脚本和模块文件：

```bash
install -d /usr/local/lib/pfwd/lib /usr/local/lib/pfwd/bin /usr/local/lib/pfwd/assets /usr/local/bin
install -m 755 pfwd.sh /usr/local/lib/pfwd/pfwd.sh
install -m 755 bbr.sh /usr/local/lib/pfwd/bbr.sh
install -m 755 assets/pfwd-guard-linux-amd64 /usr/local/lib/pfwd/bin/pfwd-guard
install -m 644 assets/cn-aggregated.zone /usr/local/lib/pfwd/assets/cn-aggregated.zone
install -m 644 assets/cn-aggregated-v6.zone /usr/local/lib/pfwd/assets/cn-aggregated-v6.zone
install -m 644 lib/*.sh /usr/local/lib/pfwd/lib/
ln -sf /usr/local/lib/pfwd/pfwd.sh /usr/local/bin/pfwd
ln -sf /usr/local/lib/pfwd/bbr.sh /usr/local/bin/pfwd-bbr
```

4. 生成 systemd unit、初始化目录并启用服务：

```bash
/usr/local/bin/pfwd install
```

5. 如需离线启用国内 IP 白名单，可直接执行：

```bash
pfwd guard whitelist --enabled true --include-cn true
```

后续机器具备外网时，再执行：

```bash
pfwd guard whitelist refresh
```

6. 完成后可先检查：

```bash
pfwd doctor
pfwd-bbr status
```

## Quick Start

```bash
pfwd init
pfwd user add alice

pfwd add \
  --user-id alice \
  --remote example.com:443 \
  --listen-port 25001 \
  --protocol tcp \
  --mss-clamp

pfwd list
pfwd stats --user-id alice
```

## Common Commands

| Task | Command | Notes |
|------|---------|-------|
| Start UI | `pfwd` | 无参数默认进入交互界面 |
| Init config | `pfwd init` | 初始化 `/etc/pfwd/config.json` |
| Add user | `pfwd user add alice` | 用户名支持中文和空格 |
| Add forward | `pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol tcp` | 协议可选 `tcp` / `udp` / `tcp_udp` |
| Random port | `pfwd add --user-id alice --remote example.com:443 --random-port 20000-30000` | 按远端端口数量自动分配监听端口 |
| List forwards | `pfwd list` | 查看所有转发 |
| User traffic | `pfwd stats --user-id alice` | 查看用户统计 |
| Set expire date | `pfwd expire user-set --user-id alice --stop-at +30` | 支持 `YYYYMMDD`、`+7`、`7d` |
| Set port limit | `pfwd limit set --forward-id <forward_id> --traffic 100GB --rate 50Mbps` | 端口级限额和速率 |
| Set user total limit | `pfwd limit set --user-id alice --traffic 1TB` | 用户总流量限制 |
| Set user port defaults | `pfwd user-forwards-limit --user-id alice --rate 50Mbps --traffic-mode one-way` | 批量设置用户下全部端口 |
| Pause forward | `pfwd stop <forward_id>` | 暂停单条转发 |
| Resume forward | `pfwd start <forward_id>` | 恢复单条转发 |
| Delete forward | `pfwd delete <forward_id>` | 删除单条转发 |
| Configure Telegram | `pfwd user telegram alice --bot-token '123456789:AA_example_token_value_replace_me' --chat-id '-1001234567890' --server-name 'relay-1'` | 配置单个用户通知 |
| Refresh runtime | `pfwd refresh` | 重新解析配置、渲染并应用 nft 运行态 |
| Reconcile state | `pfwd reconcile` | 到期停转、重置日、定时通知 |
| Diagnose | `pfwd doctor` | 检查依赖、服务、配置状态 |
| Render forward table | `pfwd render forwarder` | 查看当前端口转发表 |
| Render quota table | `pfwd render nft` | 查看统计/限额表 |
| Check update | `pfwd update --check` | 检查远端更新 |
| Update now | `pfwd update --yes` | 直接更新到最新版本 |
| Export config | `pfwd export ~/pfwd-export.json` | 导出配置和状态 |
| Import config | `pfwd import ~/pfwd-export.json` | 导入配置和状态 |

## Examples

### Port Ranges and Multi-Port

```bash
pfwd add --user-id alice --remote example.com:443,553 --listen-port 25001,25002
pfwd add --user-id alice --remote example.com:443-445 --listen-port 25001-25003
```

### Split TCP and UDP on the Same Port

```bash
pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol tcp
pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol udp
```

### nft Options

```bash
pfwd add \
  --user-id alice \
  --remote 203.0.113.10:8443 \
  --listen-port 25001 \
  --protocol tcp \
  --mss 1360 \
  --snat-source 198.51.100.10
```

| Option | Default | Notes |
|--------|---------|-------|
| `MSS` | 不设置 | 常规公网转发一般不需要；`MSS clamp` 适合 PPPoE、VPN、隧道、跨境链路；固定 `MSS` 适合已知 MTU 或上游有统一要求时 |
| `SNAT` | `masquerade` | 普通单出口、动态公网 IP 直接用默认值；固定 `SNAT` 适合本机有额外内网 IP、多地址出口或后端只接受特定来源 IP |

## pfwd-bbr

```bash
pfwd-bbr
pfwd-bbr status
pfwd-bbr optimize balanced
pfwd-bbr optimize relay --egress-rate 100mbit --ingress-rate 100mbit --tc-iface eth0
pfwd-bbr optimize gaming --nic-steering
pfwd-bbr reset
pfwd-bbr install
pfwd-bbr uninstall
```

`pfwd-bbr` 独立维护 BBR / sysctl / tc / BQL / RPS/XPS，并通过 `pfwd-bbr.service` 恢复运行态。

## Paths

| Path | Purpose |
|------|---------|
| `/etc/pfwd/config.json` | 主配置 |
| `/usr/local/bin/pfwd` | 命令入口 |
| `/usr/local/bin/bbr.sh` | 兼容调优入口 |
| `/usr/local/bin/pfwd-bbr` | 主调优入口 |
| `/usr/local/lib/pfwd` | 安装目录 |
| `/var/lib/pfwd/stats.json` | 流量状态 |
| `/var/lib/pfwd/bbr-state.env` | BBR / optimize 状态 |
| `/run/pfwd/runtime.json` | 当前解析后的运行态 |
| `/run/pfwd/forwarder.nft` | 当前渲染出的转发表 |

## Uninstall

```bash
pfwd uninstall
```

该命令只卸载 `pfwd` 本体及其转发运行态，不会删除 BBR 调优。

如需一并清理 BBR / sysctl / tc / `pfwd-bbr.service`，再执行：

```bash
pfwd-bbr uninstall
```

## Star History

[![Star History Chart](https://api.star-history.com/chart?repos=mora1n/pfwd&type=date&legend=top-left)](https://www.star-history.com/?repos=mora1n%2Fpfwd&type=date&legend=top-left)
