# pfwd

`pfwd` 是一个轻量端口转发管理脚本。
它负责用户、转发规则、到期停转、流量统计、限速限量、Telegram 通知、白名单和协议封锁；数据面优先使用内置 `pfwd-xdp`，必要时自动回退到 `nftables`，速率限制仍由 `tc` 执行。

## 功能

| 功能 | 说明 |
| --- | --- |
| 转发 | TCP / UDP / TCP+UDP 端口转发，支持 IPv4 / IPv6 和域名运行时解析 |
| 数据面选路 | 非 localhost 规则优先走 XDP；localhost / `127.0.0.1` / `::1` 走 `nftables`；XDP 不可用时自动 fallback |
| XDP 选项 | 支持 `MSS clamp`、固定 `MSS`、`masquerade`、固定 `SNAT` |
| Traffic | 按用户和转发规则统计流量，支持单向/双向计费、倍率、总量限制 |
| Rate | 使用 `tc` 做端口级或用户级双向速率限制 |
| Guard | 入口侧白名单和 TCP 首包协议封锁，运行在 XDP / ingress 分层数据面 |
| Notify | Telegram 定时通知和手动通知 |
| Tuning | `pfwd-bbr` 负责 BBR、sysctl、tc shaping、BQL、RPS/XPS |

## 流量防护

`pfwd guard` 管理入口侧访问控制：

- 白名单：限制入站来源 IPv4 / IPv6 CIDR，可启用国内 IP 白名单，也可追加自定义 CIDR。
- 协议封锁：按 TCP 首包拒绝 `HTTP`、`TLS ClientHello`、`SOCKS4/5`。

常用命令：

```bash
pfwd guard enable
pfwd guard protocols --https true --socks true
pfwd guard whitelist --enabled true --include-cn true
pfwd guard whitelist --cidr 203.0.113.0/24
pfwd guard status
pfwd guard whitelist status
```

## 依赖

| 依赖 | 用途 |
| --- | --- |
| `jq` | JSON 配置处理 |
| `iproute2` / `ip` / `tc` | 网卡探测和速率限制 |
| `systemd` | 开机恢复、定时同步 |
| `curl` 或 `wget` | bootstrap / update 下载 |
| `bpffs` | eBPF link/map pinning，通常挂载在 `/sys/fs/bpf` |

构建 `pfwd-xdp` 还需要 Go、clang 和可用的 eBPF 工具链；普通安装使用预编译 assets。

## 源码构建

需要预编译 `pfwd-xdp` 时，直接在仓库根目录执行：

```bash
./xdp/build.sh
```

构建脚本会重建 `xdp/xdp_bpfel.o`，并把目标架构二进制输出到：

- `assets/pfwd-xdp-linux-amd64`
- `assets/pfwd-xdp-linux-arm64`

## 安装

> 以下操作默认root权限下进行

在线安装：

```bash
wget -qO- https://raw.githubusercontent.com/mora1n/pfwd/main/pfwd.sh | bash -s -- install
```

离线安装时，在仓库根目录打包脚本、模块、白名单种子和目标架构的 `pfwd-xdp` 二进制即可。这里以 `amd64` 为例；`arm64` 主机把 `pfwd-xdp-linux-amd64` 换成 `pfwd-xdp-linux-arm64`。

```bash
tar -czf pfwd.tar.gz \
  pfwd.sh \
  bbr.sh \
  lib/ \
  assets/pfwd-xdp-linux-amd64 \
  assets/cn-aggregated.zone \
  assets/cn-aggregated-v6.zone
```

将 `pfwd.tar.gz` 复制到目标机器后解压并安装：

```bash
tar -xzf pfwd.tar.gz
bash ./pfwd.sh install
```

安装后做一次基础检查：

```bash
pfwd doctor
pfwd render units
/usr/local/lib/pfwd/bin/pfwd-xdp version
```

如果需要完全手工复制文件，可以使用下面的命令。这里以 `amd64` 为例；`arm64` 主机把 `pfwd-xdp-linux-amd64` 换成 `pfwd-xdp-linux-arm64`。

```bash
install -d \
  /usr/local/lib/pfwd/bin \
  /usr/local/lib/pfwd/lib \
  /usr/local/lib/pfwd/assets \
  /usr/local/bin

install -m 755 pfwd.sh /usr/local/lib/pfwd/pfwd.sh
install -m 755 bbr.sh /usr/local/lib/pfwd/bbr.sh
install -m 644 lib/*.sh /usr/local/lib/pfwd/lib/
install -m 755 assets/pfwd-xdp-linux-amd64 /usr/local/lib/pfwd/bin/pfwd-xdp
install -m 644 assets/cn-aggregated.zone /usr/local/lib/pfwd/assets/cn-aggregated.zone
install -m 644 assets/cn-aggregated-v6.zone /usr/local/lib/pfwd/assets/cn-aggregated-v6.zone

ln -sf /usr/local/lib/pfwd/pfwd.sh /usr/local/bin/pfwd
ln -sf /usr/local/lib/pfwd/bbr.sh /usr/local/bin/pfwd-bbr
ln -sf /usr/local/lib/pfwd/bbr.sh /usr/local/bin/bbr.sh

pfwd install
```

## 路径

```text
/usr/local/
├── bin/
│   ├── pfwd -> /usr/local/lib/pfwd/pfwd.sh
│   ├── pfwd-bbr -> /usr/local/lib/pfwd/bbr.sh
│   └── bbr.sh -> /usr/local/lib/pfwd/bbr.sh
└── lib/
    └── pfwd/
        ├── pfwd.sh
        ├── bbr.sh
        ├── bin/
        │   └── pfwd-xdp
        ├── assets/
        │   ├── cn-aggregated.zone
        │   └── cn-aggregated-v6.zone
        └── lib/
            ├── core.sh
            ├── forwarder.sh
            ├── stats.sh
            └── ...

/etc/
├── pfwd/
│   └── config.json
└── systemd/system/
    ├── pfwd.service
    ├── pfwd.timer
    ├── pfwd-xdp.service
    └── pfwd-bbr.service

/var/lib/pfwd/
├── stats.json
├── whitelist/
└── xdp/
    └── status.json

/run/pfwd/
└── runtime.json

/sys/fs/bpf/
├── pfwd_xdp_link
├── pfwd_xdp_ingress
├── pfwd_rule_counters
├── pfwd_user_counters
└── pfwd_stats
```

## Quickstart

```bash
pfwd init
pfwd user add alice
pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol tcp
pfwd refresh
pfwd stats --user-id alice
```

添加带 MSS / SNAT 的规则：

```bash
pfwd add \
  --user-id alice \
  --remote 198.51.100.20:443 \
  --listen-port 25002 \
  --protocol tcp \
  --mss 1360 \
  --snat-source 198.51.100.10
```

## 常用命令

| 场景 | 命令 | 说明 |
| --- | --- | --- |
| 初始化 | `pfwd init` | 初始化 `/etc/pfwd/config.json` |
| 进入菜单 | `pfwd` | 无参数进入交互界面 |
| 添加用户 | `pfwd user add alice` | 新增用户 |
| 添加转发 | `pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol tcp` | 协议可选 `tcp` / `udp` / `tcp_udp` |
| 查看转发 | `pfwd list` | 输出转发规则列表 |
| 查看统计 | `pfwd stats --user-id alice` | 查看用户统计 |
| 设置端口限制 | `pfwd limit set --forward-id <forward_id> --traffic 100GB --rate 50Mbps` | 端口级总量和速率 |
| 设置用户总量 | `pfwd limit set --user-id alice --traffic 1TB` | 用户级总量限制 |
| 批量限制 | `pfwd user-forwards-limit --user-id alice --rate 50Mbps --traffic-mode one-way` | 批量设置用户下全部端口 |
| 刷新运行态 | `pfwd refresh` | 重新解析配置并应用当前数据面 |
| 渲染数据面 | `pfwd render xdp` | 查看 XDP 候选 runtime JSON |
| 渲染速率 | `pfwd render tc` | 查看速率限制命令 |
| 诊断 | `pfwd doctor` | 查看配置、二进制、systemd 和 benchmark |

## 配置语义

- 监听 IP 默认 `::`；当前 XDP 正向转发只支持通配监听地址 `::` / `0.0.0.0`。
- 远端地址支持域名、IPv4 和 `[IPv6]:PORT`。
- 同一监听端口可拆分为一条 TCP 和一条 UDP 转发。
- 非 localhost 规则优先走 XDP；localhost / `127.0.0.1` / `::1` 固定走 `nftables`。
- 当 XDP 不可用时，符合条件的规则会自动回退到 `nftables`。
- MSS 和固定 SNAT 持久化在 `.forwards[].net`；转发网卡通过 `.settings.forward.interface` 指定。
- 总量限制仍按现有 `traffic_mode` / `traffic_ratio` 语义计算。
- 速率限制由 `tc` 执行；单个 `rate` 同时作用于上下行，入口方向通过 IFB 做整形；转发、计数和 guard 由 XDP / `nftables` 组合数据面共同完成。

## BBR / 系统调优

```bash
pfwd-bbr status
pfwd-bbr optimize relay --egress-rate 100mbit --ingress-rate 100mbit --tc-iface eth0
pfwd-bbr reset
```

`pfwd-bbr` 独立维护 BBR / sysctl / tc / BQL / RPS/XPS，并通过 `pfwd-bbr.service` 恢复运行态。

## 卸载

卸载 pfwd：

```bash
pfwd uninstall
```

如需一并清理 BBR / sysctl / tc / `pfwd-bbr.service`：

```bash
pfwd-bbr uninstall
```
