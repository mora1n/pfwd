# pfwd

`pfwd` 是一个 Go 单二进制端口转发管理工具，覆盖用户、转发规则、运行态编译、XDP 优先转发、nft loopback 分流、流量统计和本地 daemon。

完整命令面以 `pfwd help` 为准。

## 安装

依赖：`iproute2` / `ip` / `tc`、`nftables`、`systemd`、`bpffs`。

root 下执行：

```bash
curl -fsSL https://raw.githubusercontent.com/mora1n/pfwd/main/install.sh | sh
```

## 快速开始

打开交互界面：

```bash
pfwd
```

也可以显式执行 `pfwd tui`。

CLI：

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
| 打开交互界面 | `pfwd` 或 `pfwd tui` |
| 初始化本机状态 | `pfwd init` |
| 添加用户 | `pfwd user add alice` |
| 删除用户 | `pfwd user delete alice` |
| 添加转发 | `pfwd add --user-id alice --remote example.com:443 --listen-port 25001 --protocol tcp` |
| 查看转发 | `pfwd list` |
| 暂停转发 | `pfwd stop <forward-id>` |
| 恢复转发 | `pfwd start <forward-id>` |
| 删除转发 | `pfwd delete <forward-id>` |
| 查看统计 | `pfwd stats --user-id alice` |
| 刷新运行态 | `pfwd refresh` |
| 重启运行态 | `pfwd restart` |
| 查看运行态 | `pfwd render status` |
| 查看 systemd unit | `pfwd render units` |
| 查看本地 daemon | `pfwd service status` |
| 诊断 | `pfwd doctor` |
| 卸载 | `pfwd uninstall` |

## 运行时状态

pfwd 使用单一 SQLite 数据库保存配置、统计、运行态和状态：

```text
/var/lib/pfwd/pfwd.db
```

本地 daemon 默认监听 Unix socket：

```text
/run/pfwd/pfwd.sock
```

`/run/pfwd/` 不再保存 JSON 文件。配置、统计、compiled runtime、XDP runtime、nft runtime、rendered nft、forwarder status 和 XDP status 都写入 `pfwd.db`。

主要路径：

| 路径 | 用途 |
| --- | --- |
| `/usr/local/bin/pfwd` | 单二进制命令入口 |
| `/var/lib/pfwd/pfwd.db` | 单一持久化数据库 |
| `/run/pfwd/pfwd.sock` | 本地 Unix socket |
| `/etc/systemd/system/pfwd.service` | 唯一 systemd unit |

## systemd

安装后只写入一个长驻服务：

| Unit | 作用 |
| --- | --- |
| `pfwd.service` | 本地 SQLite/socket daemon；启动时执行 refresh；每 60 秒执行 reconcile |

查看服务：

```bash
systemctl status pfwd.service
pfwd service status
```

## 开发验证

常用本地验证：

```bash
go test ./...
go build ./cmd/pfwd
VERSION=v0.3.0 ./build.sh
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
