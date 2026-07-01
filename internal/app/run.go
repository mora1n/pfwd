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
	Build          BuildInfo
	Paths          Paths
	telegramSender telegramSender
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
	case "tui":
		if len(args) != 0 {
			return fmt.Errorf("用法：pfwd tui")
		}
		return a.runMenu()
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
	case "notify-send", "notify-test", "notify-enable", "notify-schedule", "notify-disable", "notify-delete":
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
	return a.runTUI()
}

func isTerminal(fd uintptr) bool {
	info, err := os.Stdin.Stat()
	return err == nil && (info.Mode()&os.ModeCharDevice) != 0
}

func (a *App) printHelp(w io.Writer) {
	fmt.Fprintln(w, "pfwd - Go 单二进制端口转发管理工具")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "用法：pfwd [command] [options]")
	fmt.Fprintln(w)
	for _, section := range helpSections() {
		fmt.Fprintln(w, section.title+"：")
		for _, row := range section.rows {
			fmt.Fprintf(w, "  %-64s %s\n", row.command, row.detail)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "运行时不再写入 /run/pfwd/*.json；配置、统计、运行态和状态都保存在 pfwd.db。")
}

type helpSection struct {
	title string
	rows  []helpRow
}

type helpRow struct {
	command string
	detail  string
}

func helpSections() []helpSection {
	return []helpSection{
		{title: "基础", rows: []helpRow{
			{command: "pfwd", detail: "打开交互式 TUI。"},
			{command: "pfwd tui", detail: "显式打开交互式 TUI。"},
			{command: "pfwd init", detail: "初始化 SQLite 数据库和默认配置。"},
			{command: "pfwd version", detail: "显示版本、commit 和构建时间。"},
			{command: "pfwd help|-h|--help", detail: "显示本帮助。"},
		}},
		{title: "用户", rows: []helpRow{
			{command: "pfwd user add <username>", detail: "创建用户。"},
			{command: "pfwd user list", detail: "列出用户。"},
			{command: "pfwd user delete <username> [--cascade]", detail: "删除用户；有关联转发时需 --cascade。"},
			{command: "pfwd user telegram <username>|--all --bot-token TOKEN --chat-id CHAT_ID [--server-name NAME] [--enabled true|false]", detail: "配置 Telegram 通知。"},
			{command: "pfwd user-forwards-limit --user-id ID [--traffic BYTES|--traffic-mode MODE|--rate RATE]", detail: "设置用户级转发默认限制。"},
		}},
		{title: "转发", rows: []helpRow{
			{command: "pfwd add --user-id ID --remote HOST:PORT --listen-port PORT [options]", detail: "添加转发；支持端口列表/范围。"},
			{command: "pfwd forward set <forward_id> [options]", detail: "编辑转发规则字段。"},
			{command: "pfwd list [--user-id ID]", detail: "列出转发规则。"},
			{command: "pfwd start <forward_id>", detail: "启用转发规则并刷新运行态。"},
			{command: "pfwd stop <forward_id>", detail: "停用转发规则并刷新运行态。"},
			{command: "pfwd delete <forward_id>", detail: "删除转发规则并刷新运行态。"},
			{command: "pfwd expire <forward_id> [--stop-at TIME|--clear]", detail: "设置或清除规则到期时间。"},
			{command: "pfwd limit <forward_id> [--traffic BYTES|--traffic-mode MODE|--traffic-ratio N|--rate RATE]", detail: "设置规则流量统计、倍率和限速。"},
		}},
		{title: "统计和流量", rows: []helpRow{
			{command: "pfwd stats [--user-id ID|--forward-id ID]", detail: "查看用户或规则流量统计。"},
			{command: "pfwd traffic reset [--user-id ID|--forward-id ID] [--used BYTES]", detail: "重置或写入统计用量。"},
		}},
		{title: "Telegram 通知", rows: []helpRow{
			{command: "pfwd notify-send --user-id ID --text TEXT", detail: "向用户配置的 Telegram chat 主动发送一条消息。"},
			{command: "pfwd notify-test --user-id ID", detail: "发送测试通知。"},
			{command: "pfwd notify-enable --user-id ID", detail: "启用该用户通知。"},
			{command: "pfwd notify-disable --user-id ID", detail: "停用该用户通知。"},
			{command: "pfwd notify-delete --user-id ID", detail: "删除该用户 Telegram 配置。"},
			{command: "pfwd notify-schedule --user-id ID [--interval-minutes N|--clear-interval] [--daily-time HH:MM|--clear-daily]", detail: "配置计划通知。"},
		}},
		{title: "运行态和服务", rows: []helpRow{
			{command: "pfwd render [config|stats|forwarder|xdp|nft|status|units]", detail: "渲染配置、运行态、nftables 或 systemd unit。"},
			{command: "pfwd refresh", detail: "编译并应用当前运行态。"},
			{command: "pfwd restart", detail: "重新应用运行态。"},
			{command: "pfwd reconcile", detail: "执行守护进程周期 reconcile。"},
			{command: "pfwd daemon [--socket PATH] [--db PATH]", detail: "以前台方式运行单进程守护服务。"},
			{command: "pfwd service status|reload [--socket PATH]", detail: "通过 Unix socket 查询或触发服务动作。"},
			{command: "pfwd store get|put [--socket PATH|--db PATH] --key KEY", detail: "读写 SQLite runtime_state 键。"},
			{command: "pfwd xdp apply|remove|status|snapshot|stats ...", detail: "XDP helper 子命令。"},
			{command: "pfwd doctor", detail: "运行本地诊断。"},
		}},
		{title: "导入导出和安装", rows: []helpRow{
			{command: "pfwd export [file]", detail: "导出配置和统计。"},
			{command: "pfwd import <file>", detail: "导入配置和统计。"},
			{command: "pfwd install", detail: "安装二进制、state dir 和 pfwd.service。"},
			{command: "pfwd update [--yes]", detail: "从 GitHub Release 更新当前安装。"},
			{command: "pfwd uninstall", detail: "卸载服务和运行时文件。"},
		}},
		{title: "环境变量", rows: []helpRow{
			{command: "PFWD_ROOT_PREFIX", detail: "测试/安装根目录前缀；默认 /。"},
			{command: "PFWD_DB_FILE", detail: "覆盖 SQLite 数据库路径；默认 /var/lib/pfwd/pfwd.db。"},
			{command: "PFWD_SERVICE_SOCKET", detail: "覆盖 Unix socket 路径；默认 /run/pfwd/pfwd.sock。"},
			{command: "PFWD_RELEASE_ASSET_BASE_URL", detail: "覆盖 GitHub Release 下载基址。"},
			{command: "PFWD_DRY_RUN", detail: "设置为 1 时只打印会修改系统的命令。"},
		}},
	}
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
