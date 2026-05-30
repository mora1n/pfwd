# pfwd

`pfwd` 是一个轻量端口转发管理脚本。
它负责用户、转发规则、到期停转、流量统计、限速限量、Telegram 通知、白名单和协议封锁；数据面优先使用内置 `pfwd-xdp`，必要时自动回退到 `nftables`，速率限制仍由 `tc` 执行。

## 功能

| 功能 | 说明 |
| --- | --- |
| 转发 | TCP / UDP / TCP+UDP 端口转发，支持 IPv4 / IPv6 和域名运行时解析 |
| 数据面选路 | 非 localhost 规则优先走 XDP；localhost / `127.0.0.1` / `::1` 走 `nftables`；两类规则并存时显示为 `hybrid`，仅 XDP 真失败时才是 fallback |
| XDP 选项 | 支持 `MSS clamp`、固定 `MSS`、`masquerade`、固定 `SNAT` |
| Traffic | 按用户和转发规则统计流量，支持单向/双向计费、倍率、总量限制 |
| Rate | 使用 `tc` 做端口级或用户级双向速率限制 |
| Guard | 入口白名单、出口白名单和 TCP 首包协议封锁；入口规则运行在 XDP / ingress 分层数据面，出口白名单同时做规则目标校验和宿主机出口限制 |
| Downmask | 按日内收发比补下行流量，支持公网下载源和 A/B 机拉流 / 喂流 |
| Notify | Telegram 定时通知和手动通知 |
| Tuning | `pfwd-bbr` 负责 BBR、sysctl、tc shaping、BQL、RPS/XPS |

## 流量防护

`pfwd guard` 管理流量防护：

- 入口白名单：限制入站来源 IPv4 / IPv6 CIDR，可启用国内 IP 白名单，也可追加自定义 CIDR；自定义项支持直接输入单个 IP，系统会规范成 `/32` 或 `/128`。
- 出口白名单：限制转发目标解析出的 IPv4 / IPv6 CIDR；规则目标仍可填写域名，但编译时解析出的每个目标 IP 都必须命中白名单；同时会对宿主机全部非 loopback 出口流量生效，默认自动包含私网/链路本地/默认网关/本机直连网段；自定义项同样支持单个 IP 输入。
- 协议封锁：按 TCP 首包拒绝 `HTTP`、`TLS ClientHello`、`SOCKS4/5`。

常用命令：

```bash
pfwd guard enable
pfwd guard protocols --https true --socks true
pfwd guard whitelist --enabled true --include-cn true
pfwd guard whitelist --cidr 203.0.113.0/24
pfwd guard whitelist-custom add 203.0.113.5
pfwd guard egress-whitelist --enabled true --include-cn true
pfwd guard egress-whitelist-custom add 203.0.113.0/24
pfwd guard status
pfwd guard whitelist status
pfwd guard egress-whitelist status
```

## 下行伪装

`pfwd downmask` 用于按日内收发比例补下行流量，适合把机器的下行流量做成更接近目标比值。当前支持两种补流来源：

- `public`：从公网测速源或大文件源下载。
- `ab`：A/B 机模式。A 机执行 `ab-pull` 主动拉流，B 机执行 `ab-feed` 返回高熵内容。

关键语义：

- `ab-pull --local-ip IP` / `settings.downmask.ab_pull.local_ip`：A 机拉流时绑定本地源 IP，可填额外内网 IP；TCP / UDP 都会绑定该源地址，且必须和远端地址族匹配。
- `ab-pull --remote-host HOST`：建议直接填写 B 机的 IPv4 / IPv6 地址，避免 DNS 变化影响 A/B 拉流链路。
- `ab-feed --bind-ip IP` / `settings.downmask.ab_feed.bind_ip`：B 机监听并从该 IP 返回内容；UI 中对应文案是“B机返回/监听 IP”。
- `--token` / `settings.downmask.ab_pull.token` / `settings.downmask.ab_feed.token`：A/B 两端必须完全一致；建议使用随机值，例如 `openssl rand -hex 16`。
- 启用 `ab-feed` 的 TCP 或 UDP 时，必须同时配置对应端口和 `token`，否则命令会直接失败，不会生成一个看似启用但实际无法启动的服务。
- `pfwd-downmask-feed.service` 仅在 `ab-feed` 启用时生成并启动；关闭后会同步清理旧状态文件。
- `min_deficit_bytes`、`max_bytes_per_run`、`ab_feed.udp_payload_bytes` 和 `seed generate --size` 支持 `B/KB/MB/GB/TB`；裸数字继续按字节解释，兼容现有配置。
- `ab_feed.udp_payload_bytes` 最终必须位于 `17-65507` 字节；超出范围时命令或服务会直接报错，不会静默回退。
- `ab_feed.seed_file` 的常规默认生成路径是 `/var/lib/pfwd/downmask/seed.bin`；B 机喂流界面会按这个路径提示默认值。
- `public.active_source` 可选内置源：
  `cloudflare_dynamic` 按目标字节数动态下载，最适合精确补量；
  `cachefly_100mb` / `digitalocean_100mb` 是固定 100MB 测速文件；
  `aliyun_ubuntu_iso` 适合大缺口或长时间稳定补流。
- `public.custom_sources` 中：
  `query` 类型的 URL 需要使用 `{bytes}` 占位，例如 `https://example.com/file?bytes={bytes}`；
  `range` 类型需要目标源支持 HTTP Range 请求。
- `public.speed_limit` 建议设置为略低于机器实际可用出口带宽，避免补流把正常业务出口打满。

常用命令：

```bash
pfwd downmask policy --pull-mode public --iface eth0
pfwd downmask policy --min-deficit-bytes 20MB --max-bytes-per-run 800MB
pfwd downmask public --active-source cloudflare_dynamic --speed-limit 4M
pfwd downmask policy --pull-mode ab --iface eth0
TOKEN="$(openssl rand -hex 16)"
pfwd downmask ab-pull --protocol tcp --remote-host 10.0.0.2 --remote-port 5301 --local-ip 10.0.0.10 --token "$TOKEN" --speed-limit 4M
pfwd downmask ab-feed --tcp-enabled true --udp-enabled true --bind-ip 10.0.0.2 --tcp-port 5301 --udp-port 5301 --udp-payload-bytes 1.2KB --token "$TOKEN"
pfwd downmask seed generate --size 256MB
pfwd downmask status
pfwd render downmask
```

## 依赖

| 依赖 | 用途 |
| --- | --- |
| `jq` | JSON 配置处理 |
| `iproute2` / `ip` / `tc` | 网卡探测和速率限制 |
| `systemd` | 开机恢复、定时同步 |
| `curl` 或 `wget` | bootstrap / update 下载 |
| `bpffs` | eBPF link/map pinning，通常挂载在 `/sys/fs/bpf` |

构建 `pfwd-xdp` 还需要 Go、clang 和可用的 eBPF 工具链；构建 `pfwd-downmask` 需要 Go；普通安装使用预编译 assets。

## 源码构建

需要预编译 `pfwd-xdp` / `pfwd-downmask` 时，直接在仓库根目录执行：

```bash
./xdp/build.sh
./downmask/build.sh
```

构建脚本会重建 `xdp/xdp_bpfel.o`，并把目标架构二进制输出到：

- `assets/pfwd-xdp-linux-amd64`
- `assets/pfwd-xdp-linux-arm64`
- `assets/pfwd-downmask-linux-amd64`
- `assets/pfwd-downmask-linux-arm64`

如果你是直接从源码仓库离线打包或执行本地 `pfwd install`，上述 `assets/pfwd-xdp-linux-*` 与 `assets/pfwd-downmask-linux-*` 都必须实际存在；缺失时安装和打包会直接失败。

## 安装

> 以下操作默认root权限下进行

在线安装：

```bash
wget -qO- https://raw.githubusercontent.com/mora1n/pfwd/main/pfwd.sh | bash -s -- install
```

在线安装和 `pfwd update` 同样要求更新源提供完整的 `pfwd-xdp` / `pfwd-downmask` 预编译资产；缺少任一必需资产时会直接失败，而不会静默跳过。

离线安装时，在仓库根目录打包脚本、模块、白名单种子，以及目标架构的 `pfwd-xdp` / `pfwd-downmask` 二进制即可。这里以 `amd64` 为例；`arm64` 主机把对应文件名替换成 `*-linux-arm64`。

如果提示 `assets/pfwd-downmask-linux-amd64` 或 `assets/pfwd-xdp-linux-amd64` 不存在，请先执行对应的构建脚本：

```bash
./xdp/build.sh
./downmask/build.sh
```

```bash
tar -czf pfwd.tar.gz \
  pfwd.sh \
  bbr.sh \
  lib/ \
  assets/pfwd-xdp-linux-amd64 \
  assets/pfwd-downmask-linux-amd64 \
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
pfwd doctor --bench
pfwd render units
/usr/local/lib/pfwd/bin/pfwd-xdp version
/usr/local/lib/pfwd/bin/pfwd-downmask version
```

如果需要完全手工复制文件，可以使用下面的命令。这里以 `amd64` 为例；`arm64` 主机把对应文件名替换成 `*-linux-arm64`。

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
install -m 755 assets/pfwd-downmask-linux-amd64 /usr/local/lib/pfwd/bin/pfwd-downmask
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
        │   ├── pfwd-xdp
        │   └── pfwd-downmask
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
    ├── pfwd-bbr.service
    └── pfwd-downmask-feed.service

/var/lib/pfwd/
├── stats.json
├── downmask/
│   ├── day_state.json
│   └── status.json
├── whitelist/
└── xdp/
    ├── indexes.json
    └── status.json

/run/pfwd/
├── runtime.json
├── runtime.xdp.json
└── runtime.nft.json

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
| 渲染状态 | `pfwd render status` | 查看已应用数据面状态 JSON |
| 渲染速率 | `pfwd render tc` | 查看速率限制命令 |
| 下行伪装状态 | `pfwd downmask status` | 查看策略、日内统计和 AB feed 监听状态 |
| 渲染下行伪装 | `pfwd render downmask` | 输出 downmask JSON 状态 |
| 诊断 | `pfwd doctor` | 查看配置、二进制、systemd 和运行态摘要；`--bench` 显示 benchmark |

## 配置语义

- 监听 IP 默认 `::`；当前 XDP 正向转发只支持通配监听地址 `::` / `0.0.0.0`。
- 远端地址支持域名、IPv4 和 `[IPv6]:PORT`。
- 同一监听端口可拆分为一条 TCP 和一条 UDP 转发。
- 非 localhost 规则优先走 XDP；localhost / `127.0.0.1` / `::1` 固定走 `nftables`。
- localhost 规则与非 localhost 规则并存时，状态显示为 `hybrid`；这是正常规则级分流，不表示 XDP 故障。
- 当 XDP 不可用时，原本应走 XDP 的规则才会自动回退到 `nftables`，此时状态才是 `nft-fallback`。
- XDP runtime 使用稳定的 user/rule index，索引状态保存在 `/var/lib/pfwd/xdp/indexes.json`；`pfwd refresh` 会尽量增量刷新 pinned maps，并保留仍匹配新规则语义的活动连接。
- `pfwd render status` / `pfwd doctor` 会显示 `dataplane.version`、`map_abi`、`xdp.incremental_apply`、保留/失效连接数和规则 profile 分布，便于区分普通增量刷新与 full reattach。
- MSS 和固定 SNAT 持久化在 `.forwards[].net`；转发网卡通过 `.settings.forward.interface` 指定。
- `settings.whitelist` 只限制入站来源；`settings.egress_whitelist` 一方面限制转发目标，另一方面限制宿主机全部非 loopback 出口流量，默认内置国内 IPv4/IPv6 段能力且默认包含国内 IP。
- 出口白名单只接受 CIDR，不接受域名条目；当规则目标是域名时，`add` / `update` / `refresh` / `reconcile` 会按当前解析结果做白名单校验。
- 当 XDP / hybrid / guard-only 数据面生效时，宿主机出口白名单走 tc egress；当运行态是 nft-only / nft-fallback / none 时，宿主机出口白名单走 nftables output hook。
- `settings.downmask` 控制下行伪装；`ab_pull.local_ip` 用于 A 机显式绑定拉流源 IP，`ab_feed.bind_ip` 用于 B 机监听并从指定 IP 返回内容。
- `ab-feed` 启用某个协议时，必须同时配置该协议对应的端口和 `token`；`pfwd render units` 会在启用时渲染 `pfwd-downmask-feed.service`。
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
