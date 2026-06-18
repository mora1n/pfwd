# pfwd

`pfwd` 是一个 XDP 优先的端口转发管理工具，覆盖转发规则、流量统计、入口/出口白名单、协议封锁、下行伪装和系统调优。

完整命令面以 `pfwd help` 为准。

## 安装

运行环境需要 `jq`、`iproute2` / `ip` / `tc`、`systemd`、`curl` 或 `wget`，以及挂载在 `/sys/fs/bpf` 的 bpffs。只有自己构建资产时才需要 Go、clang 和 eBPF 工具链。

### 在线安装

```bash
wget -qO- https://raw.githubusercontent.com/mora1n/pfwd/main/pfwd.sh | bash -s -- install
```

安装后检查：

```bash
pfwd doctor
/usr/local/lib/pfwd/bin/pfwd-xdp version
/usr/local/lib/pfwd/bin/pfwd-downmask version
```

### 离线安装（amd64 示例）

先在打包机生成资产：

```bash
./xdp/build.sh
./downmask/build.sh
./leaseweb/build.sh  # 仅控制机需要 leaseweb 时再构建
```

打包基础离线包：

```bash
tar -czf pfwd-amd64.tar.gz \
  pfwd.sh bbr.sh lib/ scripts/ \
  assets/pfwd-xdp-linux-amd64 \
  assets/pfwd-downmask-linux-amd64 \
  assets/pfwd-geo-cn-v4.bin assets/pfwd-geo-cn-v6.bin assets/pfwd-geo-meta.json \
  assets/pfwd-city-cn-meta.json assets/pfwd-city-cn-v4.bin
```

如果控制机还要启用 leaseweb，再额外带上：

```bash
assets/pfwd-leaseweb-linux-amd64
```

目标机安装：

```bash
tar -xzf pfwd-amd64.tar.gz
bash ./pfwd.sh install
```

`arm64` 只需要把上面的 `amd64` 资产文件名替换成对应的 `arm64` 文件名。

## 快速开始

```bash
pfwd init
pfwd user add alice
pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol tcp
pfwd refresh
pfwd list
pfwd stats --user-id alice
```

带 MSS / 固定 SNAT 的规则示例：

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

```bash
pfwd guard enable
pfwd guard protocols --https true --socks true --skip-port 25001

pfwd guard whitelist --enabled true
pfwd guard whitelist-cn all
pfwd guard whitelist-city add 湖南省 长沙市
pfwd guard whitelist-custom add 203.0.113.5
pfwd guard whitelist-lease add --address 198.51.100.8 --ipv4-prefix-len 24 --idle-ttl 2h --channel manual --note phone
pfwd guard whitelist check --address 61.187.9.117 --listen-port 41423 --protocol tcp

pfwd guard whitelist-port-cn --listen-port 41423 select 浙江省
pfwd guard whitelist-port-city --listen-port 41423 add 浙江省 杭州市
pfwd guard whitelist-port clear --listen-port 41423

pfwd guard egress-whitelist --enabled true
pfwd guard egress-whitelist-cn all
```

## leaseweb

```bash
./leaseweb/build.sh
pfwd leaseweb init
pfwd leaseweb config set --listen-host your-host-ip --listen-port 18080 --request-timeout-sec 10
pfwd leaseweb trusted-proxy add 127.0.0.1/32
pfwd leaseweb trusted-proxy add ::1/128
pfwd leaseweb route add --secret '<随机secret>' --label your-label --ssh-target 'root@target-host' --ssh-port 22 --ipv4-prefix-len 24 --ipv6-prefix-len 128 --idle-ttl 4h --ssh-options '-i /root/.ssh/pfwd-leaseweb -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1 -o ServerAliveInterval=5 -o ServerAliveCountMax=1 -o ControlMaster=auto -o ControlPersist=60s -o ControlPath=/run/pfwd/ssh-control-%C'
pfwd leaseweb service enable
pfwd leaseweb service start
pfwd leaseweb route check 1
pfwd leaseweb status
```

要点：

- `SSH 目标` 建议填写 `user@host`。
- `放行范围` 基于当前访问来源 IP 计算；例如 `IPv4 /24` 会把 `203.0.113.27` 放宽成 `203.0.113.0/24`。
- 目标机首次接入前，先让控制机信任对应 host key；可用 `pfwd leaseweb route check <index>` 检查 `known_hosts` 状态。
- TUI 入口：`流量防护 -> leaseweb`。

## 下行伪装

公网下载模式：

```bash
pfwd downmask policy --pull-mode public --iface eth0
pfwd downmask public --active-source cloudflare_dynamic --speed-limit 4M
pfwd downmask status
```

A/B 机模式：

```bash
TOKEN="$(openssl rand -hex 16)"

pfwd downmask policy --pull-mode ab --iface eth0
pfwd downmask ab-pull --protocol-mode parallel --remote-port 5301 --token "$TOKEN" --speed-limit 4M
pfwd downmask ab-pull targets add --host 10.0.0.2 --weight 3 --tcp-enabled true --udp-enabled true

pfwd downmask ab-feed --tcp-enabled true --bind-ip 10.0.0.2 --tcp-port 5301 --token "$TOKEN"
pfwd downmask seed generate --size 1GB
pfwd downmask status
```

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
| 查看防护 | `pfwd guard status` |
| 查看下行伪装 | `pfwd downmask status` |
| 诊断 | `pfwd doctor` |

## 系统调优

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

## Star History

<a href="https://www.star-history.com/?type=date&repos=mora1n/pfwd">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=mora1n/pfwd&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=mora1n/pfwd&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=mora1n/pfwd&type=date&legend=top-left" />
 </picture>
</a>
