package app

import (
	"context"
	"fmt"
	"sort"
)

const (
	keyConfig          = "config_json"
	keyStats           = "stats_json"
	keyRuntime         = "runtime"
	keyRuntimeXDP      = "runtime_xdp"
	keyRuntimeNFT      = "runtime_nft"
	keyRenderedNFT     = "rendered_nft"
	keyForwarderStatus = "forwarder_status"
	keyXDPStatus       = "xdp_status"
)

func loadConfig(ctx context.Context, store *Store) (Config, error) {
	cfg := defaultConfig()
	ok, err := store.GetJSON(ctx, keyConfig, &cfg)
	if err != nil {
		return cfg, err
	}
	if !ok {
		if err := store.PutJSON(ctx, keyConfig, cfg); err != nil {
			return cfg, err
		}
	}
	return normalizeConfig(cfg), nil
}

func saveConfig(ctx context.Context, store *Store, cfg Config) error {
	cfg = normalizeConfig(cfg)
	if err := validateConfig(cfg); err != nil {
		return err
	}
	return store.PutJSON(ctx, keyConfig, cfg)
}

func normalizeConfig(cfg Config) Config {
	if cfg.Settings.NFTFamily == "" {
		cfg.Settings.NFTFamily = "inet"
	}
	if cfg.Settings.NFTTable == "" {
		cfg.Settings.NFTTable = "pfwd"
	}
	if cfg.Settings.ForwardTable == "" {
		cfg.Settings.ForwardTable = "port_forward"
	}
	if cfg.Settings.DomainRefreshInterval == "" {
		cfg.Settings.DomainRefreshInterval = "60s"
	}
	if cfg.Settings.DefaultListenIP == "" {
		cfg.Settings.DefaultListenIP = "::"
	}
	if cfg.Settings.DefaultRandomPortRange == "" {
		cfg.Settings.DefaultRandomPortRange = "20000-30000"
	}
	if cfg.Users == nil {
		cfg.Users = []User{}
	}
	if cfg.Forwards == nil {
		cfg.Forwards = []Forward{}
	}
	for i := range cfg.Users {
		if cfg.Users[i].Limits.TrafficMode == "" {
			cfg.Users[i].Limits.TrafficMode = "two-way"
		}
	}
	for i := range cfg.Forwards {
		if cfg.Forwards[i].ListenIP == "" {
			cfg.Forwards[i].ListenIP = "::"
		}
		if cfg.Forwards[i].Protocol == "" {
			cfg.Forwards[i].Protocol = "tcp_udp"
		}
		if cfg.Forwards[i].TrafficMode == "" {
			cfg.Forwards[i].TrafficMode = "two-way"
		}
		if cfg.Forwards[i].TrafficRatio <= 0 {
			cfg.Forwards[i].TrafficRatio = 1
		}
		if cfg.Forwards[i].Net.SNATMode == "" {
			cfg.Forwards[i].Net.SNATMode = "masquerade"
		}
	}
	return cfg
}

func validateConfig(cfg Config) error {
	if cfg.Users == nil || cfg.Forwards == nil {
		return fmt.Errorf("无效配置：users/forwards 不能为空")
	}
	seenUsers := map[string]bool{}
	for _, user := range cfg.Users {
		if err := validateUserID(user.ID); err != nil {
			return err
		}
		if seenUsers[user.ID] {
			return fmt.Errorf("用户重复：%s", user.ID)
		}
		seenUsers[user.ID] = true
	}
	seenForwards := map[string]bool{}
	for _, fwd := range cfg.Forwards {
		if fwd.ID == "" {
			return fmt.Errorf("转发 id 不能为空")
		}
		if seenForwards[fwd.ID] {
			return fmt.Errorf("转发 id 重复：%s", fwd.ID)
		}
		seenForwards[fwd.ID] = true
		if !seenUsers[fwd.UserID] {
			return fmt.Errorf("用户不存在：%s", fwd.UserID)
		}
		if err := validateListenIP(fwd.ListenIP); err != nil {
			return err
		}
		if err := validatePort(int(fwd.ListenPort)); err != nil {
			return err
		}
		if fwd.RemoteHost == "" {
			return fmt.Errorf("远端主机不能为空")
		}
		if err := validatePort(int(fwd.RemotePort)); err != nil {
			return err
		}
		if err := validateProtocol(fwd.Protocol); err != nil {
			return err
		}
		if err := validateTrafficMode(fwd.TrafficMode); err != nil {
			return err
		}
		snatSource := ""
		if fwd.Net.SNATSource != nil {
			snatSource = *fwd.Net.SNATSource
		}
		if err := validateSNAT(fwd.Net.SNATMode, snatSource); err != nil {
			return err
		}
	}
	return nil
}

func loadStats(ctx context.Context, store *Store) (StatsState, error) {
	stats := defaultStats()
	ok, err := store.GetJSON(ctx, keyStats, &stats)
	if err != nil {
		return stats, err
	}
	if stats.Users == nil {
		stats.Users = map[string]UsageState{}
	}
	if stats.Forwards == nil {
		stats.Forwards = map[string]UsageState{}
	}
	if !ok {
		if err := store.PutJSON(ctx, keyStats, stats); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

func saveStats(ctx context.Context, store *Store, stats StatsState) error {
	if stats.Users == nil {
		stats.Users = map[string]UsageState{}
	}
	if stats.Forwards == nil {
		stats.Forwards = map[string]UsageState{}
	}
	return store.PutJSON(ctx, keyStats, stats)
}

func findUser(cfg Config, id string) (int, bool) {
	for i, user := range cfg.Users {
		if user.ID == id {
			return i, true
		}
	}
	return -1, false
}

func findForward(cfg Config, id string) (int, bool) {
	for i, fwd := range cfg.Forwards {
		if fwd.ID == id {
			return i, true
		}
	}
	return -1, false
}

func sortedUsers(cfg Config) []User {
	users := append([]User(nil), cfg.Users...)
	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	return users
}

func sortedForwards(cfg Config) []Forward {
	forwards := append([]Forward(nil), cfg.Forwards...)
	sort.Slice(forwards, func(i, j int) bool {
		if forwards[i].ListenPort == forwards[j].ListenPort {
			return forwards[i].ID < forwards[j].ID
		}
		return forwards[i].ListenPort < forwards[j].ListenPort
	})
	return forwards
}
