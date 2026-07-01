# pfwd

`pfwd` 是一个 XDP 优先的端口转发管理工具，覆盖用户、转发规则、流量统计、到期/限额管理和 Telegram 通知。

完整命令面以 `pfwd help` 为准。

## 安装

运行环境需要：

- `jq`
- `iproute2` / `ip` / `tc`
- `nftables`
- `systemd`
- `curl` 或 `wget`
- 挂载在 `/sys/fs/bpf` 的 bpffs

在线安装会从 GitHub Release 下载当前架构的 `pfwd-xdp` 和 `pfwd-service` 产物。只有自己构建或发布产物时才需要 Go、clang 和 eBPF 工具链。

### 在线安装

```bash
wget -qO- https://raw.githubusercontent.com/mora1n/pfwd/main/pfwd.sh | bash -s -- install
```

安装后检查：

```bash
pfwd doctor
/usr/local/lib/pfwd/bin/pfwd-xdp version
/usr/local/lib/pfwd/bin/pfwd-service version
```

### 离线安装

先在打包机生成产物：

```bash
./xdp/build.sh
./service/build.sh
```

构建结果会写入本地 `dist/`，该目录不进入源码仓。打包 amd64 离线包：

```bash
tar -czf pfwd-amd64.tar.gz \
  pfwd.sh lib/ service/ xdp/ \
  dist/pfwd-xdp-linux-amd64 \
  dist/pfwd-service-linux-amd64
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

## 常用命令

| 场景 | 命令 |
| --- | --- |
| 进入 TUI | `pfwd` |
| 初始化本机状态 | `pfwd init` |
| 添加用户 | `pfwd user add alice` |
| 删除用户 | `pfwd user delete alice` |
| 添加转发 | `pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol tcp` |
| 查看转发 | `pfwd list` |
| 暂停转发 | `pfwd stop <forward-id>` |
| 恢复转发 | `pfwd start <forward-id>` |
| 删除转发 | `pfwd delete <forward-id>` |
| 查看统计 | `pfwd stats --user-id alice` |
| 设置到期时间 | `pfwd expire set --forward-id <forward-id> --stop-at 2026-08-01` |
| 设置限额 | `pfwd limit set --forward-id <forward-id> --traffic 100GB` |
| 刷新运行态 | `pfwd refresh` |
| 重启运行态 | `pfwd restart` |
| 查看运行态 | `pfwd render status` |
| 查看本地服务 | `pfwd service status` |
| 诊断 | `pfwd doctor` |
| 卸载 | `pfwd uninstall` |

## 运行时状态

pfwd 使用单一 SQLite 数据库保存控制面配置和统计状态：

```text
/var/lib/pfwd/sqlite.db
```

本地 daemon 默认监听 Unix socket：

```text
/run/pfwd/pfwd.sock
```

shell 命令会从 SQLite 同步出运行时缓存文件，再生成 XDP/nft/tc 运行态。这些缓存文件位于 `/run/pfwd/`，重启后可由数据库重新生成。

主要路径：

| 路径 | 用途 |
| --- | --- |
| `/usr/local/bin/pfwd` | 命令入口 |
| `/usr/local/lib/pfwd/` | 安装目录 |
| `/usr/local/lib/pfwd/bin/pfwd-xdp` | XDP helper |
| `/usr/local/lib/pfwd/bin/pfwd-service` | SQLite/socket daemon |
| `/var/lib/pfwd/sqlite.db` | 单一持久化数据库 |
| `/run/pfwd/pfwd.sock` | 本地 Unix socket |
| `/run/pfwd/config.json` | 运行时配置缓存 |
| `/run/pfwd/stats.json` | 运行时统计缓存 |
| `/run/pfwd/runtime.json` | 已编译转发运行态 |

## systemd

安装后只写入一个长驻服务：

| Unit | 作用 |
| --- | --- |
| `pfwd.service` | 本地 SQLite/socket daemon；启动时恢复转发运行态；每 60 秒执行 reconcile |

查看服务：

```bash
systemctl status pfwd.service
pfwd service status
```

## 开发验证

常用本地验证：

```bash
bash -n pfwd.sh lib/*.sh lib/commands/*.sh lib/ui/*.sh
./service/build.sh
cd service && GOFLAGS='' CGO_ENABLED=0 go test .
./xdp/build.sh
cd xdp && GOFLAGS='' CGO_ENABLED=0 go test .
git diff --check
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
