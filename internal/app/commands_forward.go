package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
)

func (a *App) runAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	userID := fs.String("user-id", "", "user id")
	remote := fs.String("remote", "", "remote host:port")
	listenIP := fs.String("listen-ip", "", "listen ip")
	listenPort := fs.String("listen-port", "", "listen port")
	randomPort := fs.String("random-port", "", "random listen port range")
	protocol := fs.String("protocol", "tcp_udp", "protocol")
	trafficMode := fs.String("traffic-mode", "two-way", "traffic mode")
	trafficRatio := fs.Float64("traffic-ratio", 1, "traffic ratio")
	comment := fs.String("comment", "", "comment")
	mssClamp := fs.Bool("mss-clamp", false, "mss clamp")
	mssValue := fs.String("mss", "", "mss value")
	snatSource := fs.String("snat-source", "", "snat source")
	masquerade := fs.Bool("masquerade", false, "masquerade")
	stopAtRaw := fs.String("stop-at", "", "stop at")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("add 不接受额外参数")
	}
	if strings.TrimSpace(*userID) == "" {
		return fmt.Errorf("必须提供 --user-id")
	}
	if strings.TrimSpace(*remote) == "" {
		return fmt.Errorf("必须提供 --remote")
	}
	if *listenPort == "" && *randomPort == "" {
		return fmt.Errorf("必须提供 --listen-port 或 --random-port")
	}
	if *listenPort != "" && *randomPort != "" {
		return fmt.Errorf("--listen-port 和 --random-port 不能同时使用")
	}
	if err := validateProtocol(*protocol); err != nil {
		return err
	}
	if err := validateTrafficMode(*trafficMode); err != nil {
		return err
	}
	if *trafficRatio <= 0 {
		return fmt.Errorf("流量倍率必须大于 0：%s", strconv.FormatFloat(*trafficRatio, 'f', -1, 64))
	}
	remoteHost, remotePorts, err := parseHostPortSpec(*remote)
	if err != nil {
		return err
	}
	var listenPorts []uint16
	if *listenPort != "" {
		listenPorts, err = expandPortSpec(*listenPort)
	} else {
		listenPorts, err = pickSequentialPorts(*randomPort, len(remotePorts))
	}
	if err != nil {
		return err
	}
	if len(listenPorts) != len(remotePorts) {
		return fmt.Errorf("监听端口数量和目标端口数量不一致：%d != %d", len(listenPorts), len(remotePorts))
	}
	stopAt, err := normalizeStopAt(*stopAtRaw)
	if err != nil {
		return err
	}
	mssMode := ""
	var mssPtr *uint16
	if *mssClamp {
		mssMode = "clamp"
	}
	if strings.TrimSpace(*mssValue) != "" {
		mssMode = "set"
		parsed, err := parsePort(*mssValue)
		if err != nil {
			return fmt.Errorf("无效 MSS 值：%s", *mssValue)
		}
		if parsed < 536 {
			return fmt.Errorf("MSS 超出范围：%d", parsed)
		}
		mssPtr = &parsed
	}
	snatMode := "masquerade"
	var snatPtr *string
	if *snatSource != "" {
		snatMode = "snat"
		snatPtr = ptrString(*snatSource)
	}
	if *masquerade {
		snatMode = "masquerade"
		snatPtr = nil
	}
	snatText := ""
	if snatPtr != nil {
		snatText = *snatPtr
	}
	if err := validateSNAT(snatMode, snatText); err != nil {
		return err
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		if *listenIP == "" {
			*listenIP = cfg.Settings.DefaultListenIP
		}
		if err := validateListenIP(*listenIP); err != nil {
			return err
		}
		if _, ok := findUser(cfg, normalizeUserID(*userID)); !ok {
			return fmt.Errorf("用户不存在：%s", normalizeUserID(*userID))
		}
		for _, lp := range listenPorts {
			for _, existing := range cfg.Forwards {
				if existing.ListenPort == lp && protocolsConflict(*protocol, existing.Protocol) {
					return fmt.Errorf("监听端口已配置冲突协议：%d (%s vs %s)", lp, *protocol, existing.Protocol)
				}
			}
		}
		ids := make([]string, 0, len(listenPorts))
		for i, lp := range listenPorts {
			id, err := randomID("fwd")
			if err != nil {
				return err
			}
			fwd := Forward{
				ID:           id,
				UserID:       normalizeUserID(*userID),
				ListenIP:     *listenIP,
				ListenPort:   lp,
				RemoteHost:   remoteHost,
				RemotePort:   remotePorts[i],
				Protocol:     *protocol,
				Enabled:      true,
				StopAt:       stopAt,
				TrafficMode:  *trafficMode,
				TrafficRatio: *trafficRatio,
				Comment:      ptrString(*comment),
				Net: NetConfig{
					MSSMode:    ptrString(mssMode),
					MSSValue:   mssPtr,
					SNATMode:   snatMode,
					SNATSource: snatPtr,
				},
				Limits:    ForwardLimits{},
				CreatedAt: nowISO(),
			}
			cfg.Forwards = append(cfg.Forwards, fwd)
			ids = append(ids, id)
		}
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		fmt.Printf("转发已添加：%d 条\n", len(ids))
		for _, id := range ids {
			fmt.Printf("  %s\n", id)
		}
		return a.refresh(ctx, store, false)
	})
}

func pickSequentialPorts(spec string, count int) ([]uint16, error) {
	ports, err := expandPortSpec(spec)
	if err != nil {
		return nil, err
	}
	if len(ports) < count {
		return nil, fmt.Errorf("随机端口范围可用数量不足：%d < %d", len(ports), count)
	}
	return ports[:count], nil
}

func (a *App) runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	userID := fs.String("user-id", "", "user id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tUSER\tENABLED\tLISTEN\tREMOTE\tPROTO\tSTOP_AT\tMODE\tRATIO\tNET")
		for _, fwd := range sortedForwards(cfg) {
			if *userID != "" && fwd.UserID != *userID {
				continue
			}
			stopAt := "-"
			if fwd.StopAt != nil {
				stopAt = *fwd.StopAt
			}
			netLabel := fwd.Net.SNATMode
			if fwd.Net.SNATSource != nil {
				netLabel = *fwd.Net.SNATSource
			}
			if fwd.Net.MSSMode != nil && *fwd.Net.MSSMode != "" {
				netLabel += ",mss=" + *fwd.Net.MSSMode
			}
			fmt.Fprintf(w, "%s\t%s\t%v\t%s:%d\t%s\t%s\t%s\t%s\t%.3g\t%s\n",
				fwd.ID, fwd.UserID, fwd.Enabled, fwd.ListenIP, fwd.ListenPort,
				formatRemote(fwd.RemoteHost, fwd.RemotePort), fwd.Protocol, stopAt, fwd.TrafficMode, fwd.TrafficRatio, netLabel)
		}
		return w.Flush()
	})
}

func formatRemote(host string, port uint16) string {
	if strings.Contains(host, ":") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (a *App) runToggle(args []string, enabled bool) error {
	if len(args) != 1 {
		return fmt.Errorf("用法：pfwd start|stop <forward_id>")
	}
	id := args[0]
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findForward(cfg, id)
		if !ok {
			return fmt.Errorf("转发规则不存在：%s", id)
		}
		cfg.Forwards[idx].Enabled = enabled
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		fmt.Printf("转发状态已更新：%s enabled=%v\n", id, enabled)
		return a.refresh(ctx, store, false)
	})
}

func (a *App) runDelete(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("用法：pfwd delete <forward_id>")
	}
	id := args[0]
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findForward(cfg, id)
		if !ok {
			return fmt.Errorf("转发规则不存在：%s", id)
		}
		cfg.Forwards = append(cfg.Forwards[:idx], cfg.Forwards[idx+1:]...)
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		fmt.Printf("转发已删除：%s\n", id)
		return a.refresh(ctx, store, false)
	})
}

func (a *App) runExport(args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("用法：pfwd export [file]")
	}
	path := ""
	if len(args) == 1 {
		path = args[0]
	} else {
		path = filepath.Join(".", "pfwd-export.json")
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		stats, err := loadStats(ctx, store)
		if err != nil {
			return err
		}
		payload := map[string]any{"exported_at": nowISO(), "config": cfg, "stats": stats}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
			return err
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
			return err
		}
		fmt.Printf("配置已导出：%s\n", path)
		return nil
	})
}

func (a *App) runImport(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("用法：pfwd import <file>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var payload struct {
		Config Config     `json:"config"`
		Stats  StatsState `json:"stats"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("无效导入文件：%w", err)
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		if err := saveConfig(ctx, store, payload.Config); err != nil {
			return err
		}
		if err := saveStats(ctx, store, payload.Stats); err != nil {
			return err
		}
		fmt.Printf("配置已导入：%s\n", args[0])
		return a.refresh(ctx, store, true)
	})
}

func (a *App) runStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	userID := fs.String("user-id", "", "user id")
	forwardID := fs.String("forward-id", "", "forward id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		stats, err := loadStats(ctx, store)
		if err != nil {
			return err
		}
		type row struct {
			ID      string `json:"id"`
			UserID  string `json:"user_id"`
			Listen  uint16 `json:"listen_port"`
			Remote  string `json:"remote"`
			Enabled bool   `json:"enabled"`
			Total   uint64 `json:"total_bytes"`
			Billing uint64 `json:"billing_used_bytes"`
		}
		rows := []row{}
		var total uint64
		for _, fwd := range sortedForwards(cfg) {
			if *userID != "" && fwd.UserID != *userID {
				continue
			}
			if *forwardID != "" && fwd.ID != *forwardID {
				continue
			}
			usage := stats.Forwards[fwd.ID]
			bytes := usage.InputTotalBytes + usage.OutputTotalBytes
			total += bytes
			rows = append(rows, row{
				ID: fwd.ID, UserID: fwd.UserID, Listen: fwd.ListenPort,
				Remote:  formatRemote(fwd.RemoteHost, fwd.RemotePort),
				Enabled: fwd.Enabled, Total: bytes, Billing: usage.BillingUsedBytes,
			})
		}
		payload := map[string]any{"total_bytes": total, "forwards": rows}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	})
}

func (a *App) runForward(args []string) error {
	if len(args) == 0 || args[0] != "update" {
		return fmt.Errorf("用法：pfwd forward update --forward-id ID [--listen-ip IP] [--listen-port PORT] [--remote-host HOST] [--remote-port PORT] [--stop-at DATE|--clear-stop-at] [--protocol tcp|udp|tcp_udp] [--traffic-mode one-way|two-way] [--traffic-ratio 1.0] [--comment TEXT|--clear-comment] [--mss-clamp|--mss VALUE|--clear-mss] [--masquerade|--snat-source IP]")
	}
	return a.runForwardUpdate(args[1:])
}

func (a *App) runForwardUpdate(args []string) error {
	fs := flag.NewFlagSet("forward update", flag.ContinueOnError)
	id := fs.String("forward-id", "", "forward id")
	listenIP := fs.String("listen-ip", "__KEEP__", "listen ip")
	listenPort := fs.String("listen-port", "__KEEP__", "listen port")
	remoteHost := fs.String("remote-host", "__KEEP__", "remote host")
	remotePort := fs.String("remote-port", "__KEEP__", "remote port")
	stopAtRaw := fs.String("stop-at", "__KEEP__", "stop at")
	clearStopAt := fs.Bool("clear-stop-at", false, "clear stop at")
	protocol := fs.String("protocol", "__KEEP__", "protocol")
	trafficMode := fs.String("traffic-mode", "__KEEP__", "traffic mode")
	trafficRatio := fs.String("traffic-ratio", "__KEEP__", "traffic ratio")
	comment := fs.String("comment", "__KEEP__", "comment")
	clearComment := fs.Bool("clear-comment", false, "clear comment")
	mssClamp := fs.Bool("mss-clamp", false, "mss clamp")
	mssValue := fs.String("mss", "__KEEP__", "mss value")
	clearMSS := fs.Bool("clear-mss", false, "clear mss")
	snatSource := fs.String("snat-source", "__KEEP__", "snat source")
	masquerade := fs.Bool("masquerade", false, "masquerade")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("必须提供 --forward-id")
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findForward(cfg, *id)
		if !ok {
			return fmt.Errorf("转发规则不存在：%s", *id)
		}
		fwd := cfg.Forwards[idx]
		if *listenIP != "__KEEP__" {
			if err := validateListenIP(*listenIP); err != nil {
				return err
			}
			fwd.ListenIP = *listenIP
		}
		if *listenPort != "__KEEP__" {
			port, err := parsePort(*listenPort)
			if err != nil {
				return err
			}
			for _, existing := range cfg.Forwards {
				if existing.ID != fwd.ID && existing.ListenPort == port && protocolsConflict(fwd.Protocol, existing.Protocol) {
					return fmt.Errorf("监听端口已配置冲突协议：%d", port)
				}
			}
			fwd.ListenPort = port
		}
		if *remoteHost != "__KEEP__" {
			if strings.TrimSpace(*remoteHost) == "" {
				return fmt.Errorf("远端主机不能为空")
			}
			fwd.RemoteHost = *remoteHost
		}
		if *remotePort != "__KEEP__" {
			port, err := parsePort(*remotePort)
			if err != nil {
				return err
			}
			fwd.RemotePort = port
		}
		if *clearStopAt {
			fwd.StopAt = nil
		} else if *stopAtRaw != "__KEEP__" {
			stopAt, err := normalizeStopAt(*stopAtRaw)
			if err != nil {
				return err
			}
			fwd.StopAt = stopAt
			if stopAt != nil && *stopAt > nowMinute() {
				fwd.Enabled = true
			}
		}
		if *protocol != "__KEEP__" {
			if err := validateProtocol(*protocol); err != nil {
				return err
			}
			for _, existing := range cfg.Forwards {
				if existing.ID != fwd.ID && existing.ListenPort == fwd.ListenPort && protocolsConflict(*protocol, existing.Protocol) {
					return fmt.Errorf("监听端口已配置冲突协议：%d", fwd.ListenPort)
				}
			}
			fwd.Protocol = *protocol
		}
		if *trafficMode != "__KEEP__" {
			if err := validateTrafficMode(*trafficMode); err != nil {
				return err
			}
			fwd.TrafficMode = *trafficMode
		}
		if *trafficRatio != "__KEEP__" {
			ratio, err := strconv.ParseFloat(*trafficRatio, 64)
			if err != nil || ratio <= 0 {
				return fmt.Errorf("无效流量倍率：%s", *trafficRatio)
			}
			fwd.TrafficRatio = ratio
		}
		if *clearComment {
			fwd.Comment = nil
		} else if *comment != "__KEEP__" {
			fwd.Comment = ptrString(*comment)
		}
		if *clearMSS {
			fwd.Net.MSSMode = nil
			fwd.Net.MSSValue = nil
		}
		if *mssClamp {
			fwd.Net.MSSMode = ptrString("clamp")
			fwd.Net.MSSValue = nil
		}
		if *mssValue != "__KEEP__" {
			port, err := parsePort(*mssValue)
			if err != nil || port < 536 {
				return fmt.Errorf("无效 MSS 值：%s", *mssValue)
			}
			fwd.Net.MSSMode = ptrString("set")
			fwd.Net.MSSValue = &port
		}
		if *masquerade {
			fwd.Net.SNATMode = "masquerade"
			fwd.Net.SNATSource = nil
		}
		if *snatSource != "__KEEP__" {
			fwd.Net.SNATMode = "snat"
			fwd.Net.SNATSource = ptrString(*snatSource)
		}
		snat := ""
		if fwd.Net.SNATSource != nil {
			snat = *fwd.Net.SNATSource
		}
		if err := validateSNAT(fwd.Net.SNATMode, snat); err != nil {
			return err
		}
		cfg.Forwards[idx] = fwd
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		fmt.Printf("转发已更新：%s\n", *id)
		return a.refresh(ctx, store, false)
	})
}

func (a *App) runExpire(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法：pfwd expire set|clear|user-set|user-clear")
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		switch args[0] {
		case "set":
			if len(args) < 2 {
				return fmt.Errorf("用法：pfwd expire set <forward_id> --stop-at DATE")
			}
			stopAt, err := parseStopAtFlag(args[2:])
			if err != nil {
				return err
			}
			idx, ok := findForward(cfg, args[1])
			if !ok {
				return fmt.Errorf("转发规则不存在：%s", args[1])
			}
			cfg.Forwards[idx].StopAt = stopAt
			if stopAt != nil && *stopAt > nowMinute() {
				cfg.Forwards[idx].Enabled = true
			}
			fmt.Printf("转发到期时间已更新：%s\n", args[1])
		case "clear":
			if len(args) != 2 {
				return fmt.Errorf("用法：pfwd expire clear <forward_id>")
			}
			idx, ok := findForward(cfg, args[1])
			if !ok {
				return fmt.Errorf("转发规则不存在：%s", args[1])
			}
			cfg.Forwards[idx].StopAt = nil
			fmt.Printf("转发到期时间已清空：%s\n", args[1])
		case "user-set":
			userID, stopAt, err := parseUserStopAtFlags(args[1:])
			if err != nil {
				return err
			}
			if _, ok := findUser(cfg, userID); !ok {
				return fmt.Errorf("用户不存在：%s", userID)
			}
			for i := range cfg.Forwards {
				if cfg.Forwards[i].UserID == userID {
					cfg.Forwards[i].StopAt = stopAt
					if stopAt != nil && *stopAt > nowMinute() {
						cfg.Forwards[i].Enabled = true
					}
				}
			}
			fmt.Printf("用户全部转发到期时间已更新：%s\n", userID)
		case "user-clear":
			userID, err := parseUserIDFlag(args[1:])
			if err != nil {
				return err
			}
			if _, ok := findUser(cfg, userID); !ok {
				return fmt.Errorf("用户不存在：%s", userID)
			}
			for i := range cfg.Forwards {
				if cfg.Forwards[i].UserID == userID {
					cfg.Forwards[i].StopAt = nil
				}
			}
			fmt.Printf("用户全部转发到期时间已清空：%s\n", userID)
		default:
			return fmt.Errorf("用法：pfwd expire set|clear|user-set|user-clear")
		}
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		return a.refresh(ctx, store, false)
	})
}

func parseStopAtFlag(args []string) (*string, error) {
	fs := flag.NewFlagSet("stop-at", flag.ContinueOnError)
	stopAtRaw := fs.String("stop-at", "", "stop at")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *stopAtRaw == "" {
		return nil, fmt.Errorf("必须提供 --stop-at")
	}
	return normalizeStopAt(*stopAtRaw)
}

func parseUserStopAtFlags(args []string) (string, *string, error) {
	fs := flag.NewFlagSet("user-stop-at", flag.ContinueOnError)
	userID := fs.String("user-id", "", "user id")
	stopAtRaw := fs.String("stop-at", "", "stop at")
	if err := fs.Parse(args); err != nil {
		return "", nil, err
	}
	if *userID == "" || *stopAtRaw == "" {
		return "", nil, fmt.Errorf("必须提供 --user-id 和 --stop-at")
	}
	stopAt, err := normalizeStopAt(*stopAtRaw)
	return normalizeUserID(*userID), stopAt, err
}

func parseUserIDFlag(args []string) (string, error) {
	fs := flag.NewFlagSet("user-id", flag.ContinueOnError)
	userID := fs.String("user-id", "", "user id")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if *userID == "" {
		return "", fmt.Errorf("必须提供 --user-id")
	}
	return normalizeUserID(*userID), nil
}

func (a *App) runLimit(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return fmt.Errorf("用法：pfwd limit set --forward-id ID|--user-id ID [--traffic 100GB] [--rate 50Mbps] [--traffic-mode one-way|two-way]")
	}
	fs := flag.NewFlagSet("limit set", flag.ContinueOnError)
	forwardID := fs.String("forward-id", "", "forward id")
	userID := fs.String("user-id", "", "user id")
	traffic := fs.String("traffic", "__KEEP__", "traffic")
	rate := fs.String("rate", "__KEEP__", "rate")
	mode := fs.String("traffic-mode", "__KEEP__", "traffic mode")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	return a.updateLimits(*forwardID, normalizeUserID(*userID), *traffic, *rate, *mode, false)
}

func (a *App) runUserForwardsLimit(args []string) error {
	fs := flag.NewFlagSet("user-forwards-limit", flag.ContinueOnError)
	userID := fs.String("user-id", "", "user id")
	traffic := fs.String("traffic", "__KEEP__", "traffic")
	rate := fs.String("rate", "__KEEP__", "rate")
	mode := fs.String("traffic-mode", "__KEEP__", "traffic mode")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *userID == "" {
		return fmt.Errorf("必须提供 --user-id")
	}
	return a.updateLimits("", normalizeUserID(*userID), *traffic, *rate, *mode, true)
}

func (a *App) updateLimits(forwardID, userID, traffic, rate, mode string, userForwards bool) error {
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		var parsedTraffic uint64
		if traffic != "__KEEP__" {
			parsed, err := parseSizeBytes(traffic)
			if err != nil {
				return err
			}
			parsedTraffic = parsed
		}
		if mode != "__KEEP__" {
			if err := validateTrafficMode(mode); err != nil {
				return err
			}
		}
		ratePtr := func() *string {
			if rate == "__KEEP__" {
				return nil
			}
			return ptrString(rate)
		}()
		if forwardID != "" && userID == "" {
			idx, ok := findForward(cfg, forwardID)
			if !ok {
				return fmt.Errorf("转发规则不存在：%s", forwardID)
			}
			if traffic != "__KEEP__" {
				cfg.Forwards[idx].Limits.TrafficBytes = &parsedTraffic
			}
			if rate != "__KEEP__" {
				cfg.Forwards[idx].Limits.Rate = ratePtr
			}
			if mode != "__KEEP__" {
				cfg.Forwards[idx].TrafficMode = mode
			}
			fmt.Printf("转发限制已更新：%s\n", forwardID)
		} else if userID != "" && forwardID == "" {
			idx, ok := findUser(cfg, userID)
			if !ok {
				return fmt.Errorf("用户不存在：%s", userID)
			}
			if userForwards {
				for i := range cfg.Forwards {
					if cfg.Forwards[i].UserID == userID {
						if traffic != "__KEEP__" {
							cfg.Forwards[i].Limits.TrafficBytes = &parsedTraffic
						}
						if rate != "__KEEP__" {
							cfg.Forwards[i].Limits.Rate = ratePtr
						}
						if mode != "__KEEP__" {
							cfg.Forwards[i].TrafficMode = mode
						}
					}
				}
				fmt.Printf("用户全部转发限制已更新：%s\n", userID)
			} else {
				if traffic != "__KEEP__" {
					cfg.Users[idx].Limits.TrafficBytes = &parsedTraffic
				}
				if rate != "__KEEP__" {
					cfg.Users[idx].Limits.Rate = ratePtr
				}
				if mode != "__KEEP__" {
					cfg.Users[idx].Limits.TrafficMode = mode
				}
				fmt.Printf("用户限制已更新：%s\n", userID)
			}
		} else {
			return fmt.Errorf("只能设置 --user-id 或 --forward-id 其中一个")
		}
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		return a.refresh(ctx, store, false)
	})
}

func (a *App) runTraffic(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法：pfwd traffic used|reset-day|reset-now")
	}
	switch args[0] {
	case "used":
		if len(args) < 2 || args[1] != "set" {
			return fmt.Errorf("用法：pfwd traffic used set --user-id ID|--forward-id ID --used 100GB")
		}
		fs := flag.NewFlagSet("traffic used set", flag.ContinueOnError)
		userID := fs.String("user-id", "", "user id")
		forwardID := fs.String("forward-id", "", "forward id")
		used := fs.String("used", "", "used")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *used == "" {
			return fmt.Errorf("必须提供 --used")
		}
		bytes, err := parseSizeBytes(*used)
		if err != nil {
			return err
		}
		return a.setUsed(normalizeUserID(*userID), *forwardID, bytes)
	case "reset-now":
		fs := flag.NewFlagSet("traffic reset-now", flag.ContinueOnError)
		userID := fs.String("user-id", "", "user id")
		forwardID := fs.String("forward-id", "", "forward id")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return a.setUsed(normalizeUserID(*userID), *forwardID, 0)
	case "reset-day":
		if len(args) < 2 || args[1] != "set" {
			return fmt.Errorf("用法：pfwd traffic reset-day set --user-id ID|--forward-id ID --day 0|15|15T09:30")
		}
		fs := flag.NewFlagSet("traffic reset-day set", flag.ContinueOnError)
		userID := fs.String("user-id", "", "user id")
		forwardID := fs.String("forward-id", "", "forward id")
		day := fs.String("day", "", "day")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *day == "" {
			return fmt.Errorf("必须提供 --day")
		}
		return a.setResetDay(normalizeUserID(*userID), *forwardID, *day)
	default:
		return fmt.Errorf("用法：pfwd traffic used|reset-day|reset-now")
	}
}

func (a *App) setUsed(userID, forwardID string, bytes uint64) error {
	return a.withStore(func(ctx context.Context, store *Store) error {
		stats, err := loadStats(ctx, store)
		if err != nil {
			return err
		}
		if userID != "" && forwardID == "" {
			usage := stats.Users[userID]
			usage.BillingUsedBytes = bytes
			stats.Users[userID] = usage
			fmt.Printf("用户已用流量已更新：%s\n", userID)
		} else if forwardID != "" && userID == "" {
			usage := stats.Forwards[forwardID]
			usage.BillingUsedBytes = bytes
			stats.Forwards[forwardID] = usage
			fmt.Printf("转发已用流量已更新：%s\n", forwardID)
		} else {
			return fmt.Errorf("只能设置 --user-id 或 --forward-id 其中一个")
		}
		if err := saveStats(ctx, store, stats); err != nil {
			return err
		}
		return a.refresh(ctx, store, false)
	})
}

func (a *App) setResetDay(userID, forwardID, day string) error {
	normalized := strings.TrimSpace(strings.ReplaceAll(day, "T", " "))
	if normalized == "0" {
		normalized = ""
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		stats, err := loadStats(ctx, store)
		if err != nil {
			return err
		}
		if userID != "" && forwardID == "" {
			usage := stats.Users[userID]
			usage.ResetDay = ptrString(normalized)
			stats.Users[userID] = usage
			fmt.Printf("用户流量重置日已更新：%s\n", userID)
		} else if forwardID != "" && userID == "" {
			usage := stats.Forwards[forwardID]
			usage.ResetDay = ptrString(normalized)
			stats.Forwards[forwardID] = usage
			fmt.Printf("转发流量重置日已更新：%s\n", forwardID)
		} else {
			return fmt.Errorf("只能设置 --user-id 或 --forward-id 其中一个")
		}
		return saveStats(ctx, store, stats)
	})
}
