# pfwd

`pfwd` 是一个 XDP 优先的端口转发管理脚本，负责用户、转发规则、流量统计、限速限量、协议封锁、白名单和下行伪装；当 XDP 不可用时，会按规则自动回退到 `nftables`，速率限制仍由 `tc` 执行。

## 核心特性

| 能力 | 说明 |
| --- | --- |
| 转发 | TCP / UDP / TCP+UDP，支持 IPv4 / IPv6 和域名运行时解析 |
| 数据面 | 非 localhost 规则优先走 XDP；localhost 固定走 `nftables` |
| 流量统计 | 按用户和转发规则统计，支持单向/双向计费、倍率、总量限制 |
| 速率限制 | 使用 `tc` 做端口级或用户级双向限速 |
| 流量防护 | 入口白名单、出口白名单、TCP 首包协议封锁 |
| 下行伪装 | 支持公网下载源和 A/B 机拉流 / 喂流 |
| 调优 | `pfwd-bbr` 管理 BBR、sysctl、BQL、RPS/XPS 和 tc shaping |

## 安装

运行环境依赖：

- `jq`
- `iproute2` / `ip` / `tc`
- `systemd`
- `curl` 或 `wget`
- `bpffs`，通常挂载在 `/sys/fs/bpf`

如需构建预编译资产：

- `pfwd-xdp` 需要 Go、clang 和可用的 eBPF 工具链
- `pfwd-downmask` 需要 Go

### 在线安装

```bash
wget -qO- https://raw.githubusercontent.com/mora1n/pfwd/main/pfwd.sh | bash -s -- install
```

安装后做一次基础检查：

```bash
pfwd doctor
pfwd render units
/usr/local/lib/pfwd/bin/pfwd-xdp version
/usr/local/lib/pfwd/bin/pfwd-downmask version
```

### 离线打包

先准备预编译资产：

```bash
./xdp/build.sh
./downmask/build.sh
```

然后在源码仓库根目录打包。这里以 `amd64` 为例；`arm64` 主机把文件名替换成 `*-linux-arm64`。

```bash
tar -czf pfwd.tar.gz \
  pfwd.sh \
  bbr.sh \
  lib/ \
  assets/pfwd-xdp-linux-amd64 \
  assets/pfwd-downmask-linux-amd64 \
  assets/pfwd-geo-cn-v4.bin \
  assets/pfwd-geo-cn-v6.bin \
  assets/pfwd-geo-meta.json \
  assets/pfwd-city-cn-meta.json \
  assets/pfwd-city-cn-v4.bin
```

目标机器上解压并安装：

```bash
tar -xzf pfwd.tar.gz
bash ./pfwd.sh install
```

如果提示缺少 `assets/pfwd-xdp-linux-*` 或 `assets/pfwd-downmask-linux-*`，先执行对应构建脚本再打包。

## Quick Start

```bash
pfwd init
pfwd user add alice
pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol tcp
pfwd refresh
pfwd stats --user-id alice
```

添加带 MSS / 固定 SNAT 的规则：

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

`pfwd guard` 负责三类能力：

- 入口白名单：限制入站来源 IPv4 / IPv6 CIDR，支持关闭国内段、允许全部国内 IP、按省份或按市允许 IPv4；
- 出口白名单：限制转发目标解析出的 IP，同时限制宿主机全部非 loopback 出口流量；国内 IP / 省份策略与目标校验、宿主机出口共用一套配置
- 协议封锁：按 TCP 首包拒绝 `HTTP`、`TLS ClientHello`、`SOCKS4/5`
- 入口防护跳过端口：指定公网监听端口可绕过入口白名单和协议封锁；不影响出口白名单

国内 IP / 省份策略会在加载期从 geo 资产编译进入口或出口白名单 LPM map，XDP 热路径只做一次白名单查询，不在包处理路径里读取 xdb 或独立 geo map。

常用命令：

```bash
pfwd guard enable
pfwd guard protocols --https true --socks true --skip-port 25001
pfwd guard whitelist --enabled true
pfwd guard whitelist-cn all
pfwd guard whitelist-cn select 广东省 江苏省
pfwd guard whitelist-city list 湖南省
pfwd guard whitelist-city add 湖南省 长沙市
pfwd guard whitelist-custom add 203.0.113.5
pfwd guard whitelist check --address 61.187.9.117 --listen-port 41422 --protocol tcp
pfwd guard egress-whitelist --enabled true
pfwd guard egress-whitelist-cn all
pfwd guard egress-whitelist-cn select 浙江省 上海市
pfwd guard egress-whitelist-custom add 203.0.113.0/24
pfwd guard status
```

## 下行伪装

`pfwd downmask` 用于按日内收发比例补下行流量，支持两种模式：

- `public`：从公网下载源补流
- `ab`：A/B 机模式，A 机拉流，B 机喂流

关键点：

- `ab_pull.local_ip` 用于 A 机显式绑定拉流源 IP
- `ab_pull.targets` 支持配置多个 B 机，A 机会按权重随机选择
- `ab_pull.protocol_mode=parallel` 时可并行发起 TCP/UDP 拉流，并允许两路随机命中不同 B 机
- `ab_feed.bind_ip` 用于 B 机监听并从指定 IP 返回内容
- A/B 两端 `token` 必须完全一致；可用 `openssl rand -hex 16`
- `seed generate` 默认生成 `1GB` 高熵种子文件，推荐大小 `256MB-4GB`
- `public.speed_limit` / `ab-pull --speed-limit` 支持 `4M`、`4MB/s`、`32Mbps`、`1GB/s`
- `ab_pull.speed_jitter_percent` / `bytes_jitter_percent` 用于给限速和单次拉流字节做抖动，减少固定模式特征

常用命令：

```bash
pfwd downmask policy --pull-mode public --iface eth0
pfwd downmask public --active-source cloudflare_dynamic --speed-limit 4M
pfwd downmask policy --pull-mode ab --iface eth0
TOKEN="$(openssl rand -hex 16)"
pfwd downmask ab-pull --protocol-mode parallel --tcp-enabled true --udp-enabled true --remote-port 5301 --token "$TOKEN" --speed-limit 4M --speed-jitter-percent 12 --bytes-jitter-percent 18
pfwd downmask ab-pull targets add --host 10.0.0.2 --weight 3 --tcp-enabled true --udp-enabled true
pfwd downmask ab-pull targets add --host 10.0.0.3 --port 5302 --weight 1 --token "$TOKEN"
pfwd downmask ab-feed --tcp-enabled true --udp-enabled false --bind-ip 10.0.0.2 --tcp-port 5301 --token "$TOKEN"
pfwd downmask seed generate --size 1GB
pfwd downmask status
```

## 常用命令

| 场景 | 命令 |
| --- | --- |
| 初始化 | `pfwd init` |
| 进入菜单 | `pfwd` |
| 添加用户 | `pfwd user add alice` |
| 添加转发 | `pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol tcp` |
| 查看转发 | `pfwd list` |
| 查看统计 | `pfwd stats --user-id alice` |
| 刷新运行态 | `pfwd refresh` |
| 渲染状态 | `pfwd render status` |
| 查看下行伪装状态 | `pfwd downmask status` |
| 诊断 | `pfwd doctor` |

完整命令面以 `pfwd help` 为准。

## 端口格式

- 单个端口：`443`
- 逗号列表：`443,8443`
- 连续范围：`10000-10010`

## 进阶说明

- 监听 IP 默认 `::`；当前 XDP 正向转发只支持通配监听地址 `::` / `0.0.0.0`
- 远端地址支持域名、IPv4 和 `[IPv6]:PORT`
- 同一监听端口可拆分为一条 TCP 和一条 UDP 转发
- 非 localhost 规则优先走 XDP；localhost / `127.0.0.1` / `::1` 固定走 `nftables`
- localhost 与非 localhost 规则并存时，状态显示为 `hybrid`；这属于正常规则级分流
- 当 XDP 不可用时，原本应走 XDP 的规则才会回退到 `nftables`，此时状态才是 `nft-fallback`
- `settings.egress_whitelist` 同时限制转发目标和宿主机全部非 loopback 出口流量
- `ab-feed` 启用某个协议时，必须同时配置对应端口和 `token`；启用后 `pfwd render units` 会渲染 `pfwd-downmask-feed.service`
- 总量限制仍按现有 `traffic_mode` / `traffic_ratio` 语义计算，速率限制由 `tc` 执行

## 关键路径

- 主配置：`/etc/pfwd/config.json`
- 主脚本与二进制：`/usr/local/lib/pfwd/`
- XDP / downmask 二进制：`/usr/local/lib/pfwd/bin/`
- 统计与 downmask 状态：`/var/lib/pfwd/`
- 运行态 JSON：`/run/pfwd/runtime.json`、`/run/pfwd/runtime.xdp.json`、`/run/pfwd/runtime.nft.json`
- eBPF pin 路径：`/sys/fs/bpf/`

## 高级安装

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
install -m 644 assets/pfwd-geo-cn-v4.bin /usr/local/lib/pfwd/assets/pfwd-geo-cn-v4.bin
install -m 644 assets/pfwd-geo-cn-v6.bin /usr/local/lib/pfwd/assets/pfwd-geo-cn-v6.bin
install -m 644 assets/pfwd-geo-meta.json /usr/local/lib/pfwd/assets/pfwd-geo-meta.json
install -m 644 assets/pfwd-city-cn-meta.json /usr/local/lib/pfwd/assets/pfwd-city-cn-meta.json
install -m 644 assets/pfwd-city-cn-v4.bin /usr/local/lib/pfwd/assets/pfwd-city-cn-v4.bin

ln -sf /usr/local/lib/pfwd/pfwd.sh /usr/local/bin/pfwd
ln -sf /usr/local/lib/pfwd/bbr.sh /usr/local/bin/pfwd-bbr
ln -sf /usr/local/lib/pfwd/bbr.sh /usr/local/bin/bbr.sh

pfwd install
```

## BBR / 系统调优

```bash
pfwd-bbr status
pfwd-bbr optimize relay --egress-rate 100mbit --ingress-rate 100mbit --tc-iface eth0
pfwd-bbr reset
```

`pfwd-bbr` 独立维护 BBR / sysctl / tc / BQL / RPS/XPS，并通过 `pfwd-bbr.service` 恢复运行态。

## 卸载

卸载 `pfwd`：

```bash
pfwd uninstall
```

如需一并清理 BBR / sysctl / tc / `pfwd-bbr.service`：

```bash
pfwd-bbr uninstall
```

## 许可证

本项目使用 [MIT License](LICENSE)。
