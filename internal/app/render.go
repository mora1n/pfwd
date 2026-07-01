package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mora1n/pfwd/service"
)

func (a *App) runRender(args []string) error {
	target := "forwarder"
	if len(args) > 1 {
		return fmt.Errorf("用法：pfwd render [config|stats|forwarder|xdp|nft|status|units]")
	}
	if len(args) == 1 {
		target = args[0]
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		switch target {
		case "config":
			var cfg Config
			_, err := store.GetJSON(ctx, keyConfig, &cfg)
			return printJSON(cfg, err)
		case "stats":
			var stats StatsState
			_, err := store.GetJSON(ctx, keyStats, &stats)
			return printJSON(stats, err)
		case "forwarder":
			var runtimeData CompiledRuntime
			if ok, err := store.GetJSON(ctx, keyRuntime, &runtimeData); err != nil {
				return err
			} else if !ok {
				cfg, err := loadConfig(ctx, store)
				if err != nil {
					return err
				}
				stats, err := loadStats(ctx, store)
				if err != nil {
					return err
				}
				runtimeData, err = compileRuntime(cfg, stats)
				if err != nil {
					return err
				}
			}
			return printJSON(runtimeData, nil)
		case "xdp":
			var runtimeData CompiledRuntime
			_, err := store.GetJSON(ctx, keyRuntimeXDP, &runtimeData)
			return printJSON(runtimeData, err)
		case "nft":
			raw, ok, err := store.GetRaw(ctx, keyRenderedNFT)
			if err != nil {
				return err
			}
			if !ok {
				cfg, err := loadConfig(ctx, store)
				if err != nil {
					return err
				}
				stats, err := loadStats(ctx, store)
				if err != nil {
					return err
				}
				runtimeData, err := compileRuntime(cfg, stats)
				if err != nil {
					return err
				}
				fmt.Print(renderNFT(cfg, filterRuntime(runtimeData, "nft")))
				return nil
			}
			var text string
			if err := json.Unmarshal([]byte(raw), &text); err != nil {
				return err
			}
			fmt.Print(text)
			return nil
		case "status":
			var status ForwarderStatus
			_, err := store.GetJSON(ctx, keyForwarderStatus, &status)
			return printJSON(status, err)
		case "units":
			fmt.Println("# pfwd.service")
			fmt.Print(a.serviceUnit())
			return nil
		default:
			return fmt.Errorf("用法：pfwd render [config|stats|forwarder|xdp|nft|status|units]")
		}
	})
}

func printJSON(value any, err error) error {
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func renderNFT(cfg Config, runtimeData CompiledRuntime) string {
	if len(runtimeData.Rules) == 0 {
		return ""
	}
	family := cfg.Settings.NFTFamily
	if family == "" {
		family = "inet"
	}
	table := cfg.Settings.ForwardTable
	if table == "" {
		table = "port_forward"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table %s %s {\n", family, table)
	b.WriteString("    chain prerouting {\n")
	b.WriteString("        type nat hook prerouting priority dstnat; policy accept;\n")
	for _, rule := range runtimeData.Rules {
		targetKind := "ip"
		target := rule.ResolvedTarget
		if rule.IPVersion == 6 {
			targetKind = "ip6"
			target = "[" + target + "]"
		}
		fmt.Fprintf(&b, "        %s dport %d dnat %s to %s:%d comment \"pfwd %s\"\n", rule.Protocol, rule.ListenPort, targetKind, target, rule.RemotePort, rule.ID)
	}
	b.WriteString("    }\n\n")
	b.WriteString("    chain postrouting {\n")
	b.WriteString("        type nat hook postrouting priority srcnat; policy accept;\n")
	for _, rule := range runtimeData.Rules {
		addrKind := "ip"
		if rule.IPVersion == 6 {
			addrKind = "ip6"
		}
		if rule.SNATMode == "snat" && rule.SNATSource != "" {
			fmt.Fprintf(&b, "        ct status dnat %s daddr %s %s dport %d snat to %s comment \"pfwd %s\"\n", addrKind, rule.ResolvedTarget, rule.Protocol, rule.RemotePort, rule.SNATSource, rule.ID)
		} else {
			fmt.Fprintf(&b, "        ct status dnat %s daddr %s %s dport %d masquerade comment \"pfwd %s\"\n", addrKind, rule.ResolvedTarget, rule.Protocol, rule.RemotePort, rule.ID)
		}
	}
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}

func (a *App) runDoctor(args []string) error {
	if len(args) > 1 || (len(args) == 1 && args[0] != "--bench") {
		return fmt.Errorf("用法：pfwd doctor [--bench]")
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		version, err := store.SchemaVersion(ctx)
		if err != nil {
			return err
		}
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		stats, err := loadStats(ctx, store)
		if err != nil {
			return err
		}
		fmt.Printf("pfwd: %s\n", a.Build.Version)
		fmt.Printf("db: %s\n", a.Paths.DBPath)
		fmt.Printf("schema: %s\n", version)
		fmt.Printf("socket: %s\n", a.Paths.SocketPath)
		fmt.Printf("users: %d\n", len(cfg.Users))
		fmt.Printf("forwards: %d\n", len(cfg.Forwards))
		fmt.Printf("stats_users: %d\n", len(stats.Users))
		fmt.Printf("stats_forwards: %d\n", len(stats.Forwards))
		fmt.Println("runtime_state: db")
		for _, key := range []string{keyConfig, keyStats, keyRuntime, keyRuntimeXDP, keyRuntimeNFT, keyRenderedNFT, keyForwarderStatus, keyXDPStatus} {
			_, ok, err := store.GetRaw(ctx, key)
			if err != nil {
				return err
			}
			status := "missing"
			if ok {
				status = "present"
			}
			fmt.Printf("%s: %s\n", key, status)
		}
		return nil
	})
}

func (a *App) serviceUnit() string {
	return fmt.Sprintf(`[Unit]
Description=pfwd local daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s daemon --socket %s --db %s
Restart=on-failure
RestartSec=2s
RuntimeDirectory=pfwd
RuntimeDirectoryMode=0750
StateDirectory=pfwd
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
`, a.Paths.BinPath, a.Paths.SocketPath, a.Paths.DBPath)
}

func (a *App) runService(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法：pfwd service status|reload [--socket PATH]")
	}
	return service.Run(args)
}

func (a *App) runDaemon(args []string) error {
	socketPath := a.Paths.SocketPath
	dbPath := a.Paths.DBPath
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--socket":
			i++
			if i >= len(args) {
				return fmt.Errorf("--socket 需要路径")
			}
			socketPath = args[i]
		case "--db":
			i++
			if i >= len(args) {
				return fmt.Errorf("--db 需要路径")
			}
			dbPath = args[i]
		default:
			return fmt.Errorf("未知 daemon 参数：%s", args[i])
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	daemonApp := *a
	daemonApp.Paths.DBPath = dbPath
	daemonApp.Paths.SocketPath = socketPath
	return service.Serve(ctx, service.DaemonConfig{
		SocketPath:        socketPath,
		DBPath:            dbPath,
		ReconcileInterval: 60 * time.Second,
		CommandRunner: func(ctx context.Context, args ...string) (string, error) {
			if len(args) == 0 {
				return "", nil
			}
			switch args[0] {
			case "refresh":
				err := daemonApp.withStore(func(_ context.Context, store *Store) error {
					return daemonApp.refresh(ctx, store, true)
				})
				if err != nil {
					return "", err
				}
				return "已刷新", nil
			case "reconcile":
				if err := daemonApp.reconcileInternal(ctx); err != nil {
					return "", err
				}
				return "已同步", nil
			default:
				return "", fmt.Errorf("daemon 不支持内部命令：%s", args[0])
			}
		},
	})
}

func (a *App) runInstall(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("用法：pfwd install")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if dryRun() {
		fmt.Printf("DRY-RUN: install -m 755 %s %s\n", exe, a.Paths.BinPath)
		fmt.Printf("DRY-RUN: write %s\n", filepath.Join(a.Paths.SystemdDir, "pfwd.service"))
		fmt.Println("DRY-RUN: systemctl daemon-reload")
		fmt.Println("DRY-RUN: systemctl enable --now pfwd.service")
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(a.Paths.BinPath), 0o755); err != nil {
		return err
	}
	if err := copyFile(exe, a.Paths.BinPath, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(a.Paths.SystemdDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.Paths.SystemdDir, "pfwd.service"), []byte(a.serviceUnit()), 0o644); err != nil {
		return err
	}
	_ = runCommand("systemctl", "daemon-reload")
	_ = runCommand("systemctl", "enable", "--now", "pfwd.service")
	fmt.Printf("已安装：%s\n", a.Paths.BinPath)
	return nil
}

func (a *App) runUpdate(args []string) error {
	yes := false
	for _, arg := range args {
		switch arg {
		case "--yes":
			yes = true
		case "--check":
			fmt.Printf("当前版本：%s\n", a.Build.Version)
			return nil
		default:
			return fmt.Errorf("用法：pfwd update [--check|--yes]")
		}
	}
	if !yes {
		return fmt.Errorf("Go 单二进制更新需要显式 --yes")
	}
	return fmt.Errorf("在线 update 尚未实现；请从 GitHub Release 下载 pfwd 单二进制后替换 %s", a.Paths.BinPath)
}

func (a *App) runUninstall(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("用法：pfwd uninstall")
	}
	if dryRun() {
		fmt.Println("DRY-RUN: systemctl stop pfwd.service")
		fmt.Println("DRY-RUN: systemctl disable pfwd.service")
		fmt.Printf("DRY-RUN: rm -f %s\n", a.Paths.BinPath)
		fmt.Printf("DRY-RUN: rm -f %s\n", filepath.Join(a.Paths.SystemdDir, "pfwd.service"))
		return nil
	}
	_ = runCommand("systemctl", "stop", "pfwd.service")
	_ = runCommand("systemctl", "disable", "pfwd.service")
	_ = os.Remove(filepath.Join(a.Paths.SystemdDir, "pfwd.service"))
	_ = os.Remove(a.Paths.BinPath)
	_ = runCommand("systemctl", "daemon-reload")
	fmt.Println("已卸载 pfwd")
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
