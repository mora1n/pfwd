package app

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/mora1n/pfwd/service"
	"github.com/mora1n/pfwd/xdp"
)

type App struct {
	Build BuildInfo
	Paths Paths
}

func Run(args []string, build BuildInfo) error {
	app := &App{Build: build, Paths: LoadPaths()}
	return app.run(args)
}

func (a *App) run(args []string) error {
	if len(args) == 0 {
		return a.runMenu()
	}
	cmd := args[0]
	args = args[1:]
	switch cmd {
	case "help", "-h", "--help":
		a.printHelp(os.Stdout)
		return nil
	case "version", "--version":
		return a.runVersion()
	case "init":
		return a.withStore(func(ctx context.Context, store *Store) error {
			if _, err := loadConfig(ctx, store); err != nil {
				return err
			}
			if _, err := loadStats(ctx, store); err != nil {
				return err
			}
			fmt.Printf("已初始化：%s\n", a.Paths.DBPath)
			return nil
		})
	case "user":
		return a.runUser(args)
	case "add":
		return a.runAdd(args)
	case "list":
		return a.runList(args)
	case "start":
		return a.runToggle(args, true)
	case "stop":
		return a.runToggle(args, false)
	case "delete":
		return a.runDelete(args)
	case "forward":
		return a.runForward(args)
	case "expire":
		return a.runExpire(args)
	case "limit":
		return a.runLimit(args)
	case "user-forwards-limit":
		return a.runUserForwardsLimit(args)
	case "traffic":
		return a.runTraffic(args)
	case "export":
		return a.runExport(args)
	case "import":
		return a.runImport(args)
	case "stats":
		return a.runStats(args)
	case "render":
		return a.runRender(args)
	case "refresh":
		return a.runRefresh(args)
	case "restart":
		return a.runRestart(args)
	case "reconcile":
		return a.runReconcile(args)
	case "doctor":
		return a.runDoctor(args)
	case "daemon":
		return a.runDaemon(args)
	case "service":
		return a.runService(args)
	case "store":
		return service.Run(append([]string{"store"}, args...))
	case "xdp":
		return xdp.Run(args)
	case "install":
		return a.runInstall(args)
	case "update":
		return a.runUpdate(args)
	case "uninstall":
		return a.runUninstall(args)
	case "notify-test", "notify-enable", "notify-schedule", "notify-disable", "notify-delete":
		return a.runNotify(cmd, args)
	default:
		return fmt.Errorf("未知命令：%s", cmd)
	}
}

func (a *App) withStore(fn func(context.Context, *Store) error) error {
	store, err := OpenStore(a.Paths.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	return fn(context.Background(), store)
}

func (a *App) runVersion() error {
	fmt.Printf("pfwd %s\ncommit: %s\nbuild_date: %s\n", a.Build.Version, a.Build.Commit, a.Build.BuildDate)
	return nil
}

func (a *App) runMenu() error {
	if !isTerminal(os.Stdin.Fd()) {
		return fmt.Errorf("请在交互式终端运行 pfwd，或使用 pfwd help 查看命令")
	}
	return a.runList(nil)
}

func isTerminal(fd uintptr) bool {
	info, err := os.Stdin.Stat()
	return err == nil && (info.Mode()&os.ModeCharDevice) != 0
}

func (a *App) printHelp(w io.Writer) {
	fmt.Fprintln(w, `pfwd - Go 单二进制端口转发管理工具

用法：
  pfwd
  pfwd init
  pfwd user add <username>
  pfwd user list
  pfwd user delete <username> [--cascade]
  pfwd add --user-id ID --remote HOST:PORT[,PORT]|HOST:START-END --listen-port PORT[,PORT]|START-END [--listen-ip IP] [--protocol tcp|udp|tcp_udp] [--traffic-mode one-way|two-way] [--traffic-ratio 1.0] [--comment TEXT] [--mss-clamp|--mss VALUE] [--masquerade|--snat-source IP]
  pfwd list [--user-id ID]
  pfwd start <forward_id>
  pfwd stop <forward_id>
  pfwd delete <forward_id>
  pfwd stats [--user-id ID|--forward-id ID]
  pfwd export [file]
  pfwd import <file>
  pfwd render [config|stats|forwarder|xdp|nft|status|units]
  pfwd refresh
  pfwd restart
  pfwd reconcile
  pfwd daemon [--socket PATH] [--db PATH]
  pfwd service status|reload [--socket PATH]
  pfwd store get|put [--socket PATH|--db PATH] --key KEY
  pfwd xdp apply|remove|status|snapshot|stats ...
  pfwd doctor
  pfwd install
  pfwd update [--yes]
  pfwd uninstall

环境变量：
  PFWD_ROOT_PREFIX       测试/安装根目录前缀。默认：/
  PFWD_DB_FILE           覆盖 SQLite 数据库路径。默认：/var/lib/pfwd/pfwd.db
  PFWD_SERVICE_SOCKET    覆盖本地 Unix socket 路径。默认：/run/pfwd/pfwd.sock
  PFWD_RELEASE_ASSET_BASE_URL 覆盖 GitHub Release 下载基址。
  PFWD_DRY_RUN           设置为 1 时只打印会修改系统的命令。

运行时不再写入 /run/pfwd/*.json；配置、统计、运行态和状态都保存在 pfwd.db。`)
}

func (a *App) runUser(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法：pfwd user add|list|delete")
	}
	switch args[0] {
	case "add":
		if len(args) != 2 {
			return fmt.Errorf("用法：pfwd user add <username>")
		}
		userID := normalizeUserID(args[1])
		if err := validateUserID(userID); err != nil {
			return err
		}
		return a.withStore(func(ctx context.Context, store *Store) error {
			cfg, err := loadConfig(ctx, store)
			if err != nil {
				return err
			}
			if _, ok := findUser(cfg, userID); ok {
				return fmt.Errorf("用户已存在：%s", userID)
			}
			cfg.Users = append(cfg.Users, User{
				ID:              userID,
				CreatedAt:       nowISO(),
				ForwardDefaults: ForwardDefaults{},
				Telegram:        TelegramConfig{},
				Limits: Limits{
					TrafficMode: "two-way",
				},
			})
			if err := saveConfig(ctx, store, cfg); err != nil {
				return err
			}
			fmt.Printf("用户已添加：%s\n", userID)
			return nil
		})
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("用法：pfwd user list")
		}
		return a.withStore(func(ctx context.Context, store *Store) error {
			cfg, err := loadConfig(ctx, store)
			if err != nil {
				return err
			}
			for _, user := range sortedUsers(cfg) {
				fmt.Println(user.ID)
			}
			return nil
		})
	case "delete":
		return a.runUserDelete(args[1:])
	case "telegram":
		return a.runUserTelegram(args[1:])
	default:
		return fmt.Errorf("用法：pfwd user add|list|delete")
	}
}

func (a *App) runUserDelete(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("用法：pfwd user delete <username> [--cascade]")
	}
	userID := normalizeUserID(args[0])
	cascade := false
	for _, arg := range args[1:] {
		if arg != "--cascade" {
			return fmt.Errorf("用法：pfwd user delete <username> [--cascade]")
		}
		cascade = true
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findUser(cfg, userID)
		if !ok {
			return fmt.Errorf("用户不存在：%s", userID)
		}
		var kept []Forward
		deleted := 0
		for _, fwd := range cfg.Forwards {
			if fwd.UserID == userID {
				deleted++
				if !cascade {
					return fmt.Errorf("该用户仍有转发规则，无法删除：%s；如需连带删除请加 --cascade", userID)
				}
				continue
			}
			kept = append(kept, fwd)
		}
		cfg.Users = append(cfg.Users[:idx], cfg.Users[idx+1:]...)
		cfg.Forwards = kept
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		if deleted > 0 {
			fmt.Printf("用户已删除：%s（同时删除 %d 条转发）\n", userID, deleted)
		} else {
			fmt.Printf("用户已删除：%s\n", userID)
		}
		return nil
	})
}
