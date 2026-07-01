package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"github.com/mora1n/pfwd/xdp"
)

const (
	dataplaneVersion = 2
	mapABIVersion    = 17
)

type CompiledRuntime struct {
	Generated        string            `json:"generated_at,omitempty"`
	Settings         RuntimeSettings   `json:"settings"`
	Users            []RuntimeUser     `json:"users"`
	Rules            []RuntimeRule     `json:"rules"`
	RuleIndex        map[string]uint32 `json:"rule_index,omitempty"`
	UserIndex        map[string]uint32 `json:"user_index,omitempty"`
	DataplaneVersion int               `json:"dataplane_version,omitempty"`
	MapABIVersion    int               `json:"map_abi_version,omitempty"`
	ConfigHash       string            `json:"config_hash,omitempty"`
	Summary          RuntimeSummary    `json:"summary,omitempty"`
}

type RuntimeSettings struct {
	Interface string `json:"interface"`
}

type RuntimeUser struct {
	ID              string `json:"id"`
	Index           uint32 `json:"index"`
	TrafficLimit    uint64 `json:"traffic_limit_bytes"`
	BillingUsedBase uint64 `json:"billing_used_base_bytes"`
}

type RuntimeRule struct {
	ID                  string   `json:"id"`
	Index               uint32   `json:"index"`
	UserID              string   `json:"user_id"`
	UserIndex           uint32   `json:"user_index"`
	ListenIP            string   `json:"listen_ip"`
	ListenPort          uint16   `json:"listen_port"`
	Protocol            string   `json:"protocol"`
	IPVersion           uint8    `json:"ip_version"`
	ResolvedTarget      string   `json:"resolved_target"`
	RemotePort          uint16   `json:"remote_port"`
	SNATMode            string   `json:"snat_mode"`
	SNATSource          string   `json:"snat_source,omitempty"`
	MSSMode             string   `json:"mss_mode,omitempty"`
	MSSValue            uint16   `json:"mss_value,omitempty"`
	TrafficMode         string   `json:"traffic_mode"`
	TrafficRatio        float64  `json:"traffic_ratio"`
	RuleLimit           uint64   `json:"traffic_limit_bytes"`
	UserLimit           uint64   `json:"user_limit_bytes"`
	BillingUsedBase     uint64   `json:"billing_used_base_bytes"`
	UserBillingUsedBase uint64   `json:"user_billing_used_base_bytes"`
	FeatureProfile      string   `json:"feature_profile,omitempty"`
	FeatureFlags        []string `json:"feature_flags,omitempty"`
	XDPDisabled         bool     `json:"xdp_disabled,omitempty"`
	RemoteInput         string   `json:"remote_input,omitempty"`
	Comment             string   `json:"comment,omitempty"`
	ExecutionClass      string   `json:"execution_class,omitempty"`
	BackendReason       string   `json:"backend_reason,omitempty"`
	CounterOwner        string   `json:"counter_owner,omitempty"`
	LoopbackLocal       bool     `json:"loopback_local,omitempty"`
}

type RuntimeSummary struct {
	Rules         int            `json:"rules"`
	XDPRules      int            `json:"xdp_rules"`
	NFTRules      int            `json:"nft_rules"`
	LoopbackRules int            `json:"loopback_rules"`
	ProfileCounts map[string]int `json:"profile_counts,omitempty"`
}

type ForwarderStatus struct {
	Applied                bool            `json:"applied"`
	GeneratedAt            string          `json:"generated_at"`
	ForwardingBackend      string          `json:"forwarding_backend"`
	XDPApplied             bool            `json:"xdp_applied"`
	XDPForwardApplied      bool            `json:"xdp_forward_applied"`
	NFTApplied             bool            `json:"nft_applied"`
	LoopbackViaNFT         bool            `json:"loopback_via_nft"`
	LoopbackSplitActive    bool            `json:"loopback_split_active"`
	FallbackReason         *string         `json:"fallback_reason"`
	XDPError               *string         `json:"xdp_error"`
	Rules                  int             `json:"rules"`
	XDPCandidateRulesCount int             `json:"xdp_candidate_rules_count"`
	XDPRulesCount          int             `json:"xdp_rules_count"`
	NFTRulesCount          int             `json:"nft_rules_count"`
	Interface              string          `json:"interface"`
	DataplaneVersion       int             `json:"dataplane_version"`
	MapABIVersion          int             `json:"map_abi_version"`
	ProfileCounts          map[string]int  `json:"profile_counts,omitempty"`
	XDPStatus              json.RawMessage `json:"xdp_status,omitempty"`
}

func (a *App) runRefresh(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("用法：pfwd refresh")
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		if err := a.refresh(ctx, store, true); err != nil {
			return err
		}
		fmt.Println("已刷新")
		return nil
	})
}

func (a *App) runRestart(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("用法：pfwd restart")
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		_ = xdp.Run([]string{"remove", "--status-file", tempStatePath("xdp-status.tmp"), "--xdp-pin", "/sys/fs/bpf/pfwd_xdp_link", "--rule-counter-pin", "/sys/fs/bpf/pfwd_rule_counters", "--user-counter-pin", "/sys/fs/bpf/pfwd_user_counters", "--stats-pin", "/sys/fs/bpf/pfwd_stats"})
		if err := a.refresh(ctx, store, true); err != nil {
			return err
		}
		fmt.Println("已重启运行态")
		return nil
	})
}

func (a *App) runReconcile(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("用法：pfwd reconcile")
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		changed, err := a.reconcileStore(ctx, store)
		if err != nil {
			return err
		}
		if changed {
			fmt.Println("已同步：refresh=changed")
		} else {
			fmt.Println("已同步：refresh=reuse")
		}
		return nil
	})
}

func (a *App) reconcileInternal(ctx context.Context) error {
	return a.withStore(func(_ context.Context, store *Store) error {
		_, err := a.reconcileStore(ctx, store)
		return err
	})
}

func (a *App) reconcileStore(ctx context.Context, store *Store) (bool, error) {
	cfg, err := loadConfig(ctx, store)
	if err != nil {
		return false, err
	}
	now := nowMinute()
	changed := false
	for i := range cfg.Forwards {
		if cfg.Forwards[i].Enabled && cfg.Forwards[i].StopAt != nil && *cfg.Forwards[i].StopAt <= now {
			cfg.Forwards[i].Enabled = false
			changed = true
		}
	}
	if changed {
		if err := saveConfig(ctx, store, cfg); err != nil {
			return false, err
		}
		if err := a.refresh(ctx, store, true); err != nil {
			return false, err
		}
	}
	return changed, nil
}

func (a *App) refresh(ctx context.Context, store *Store, apply bool) error {
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
	if err := store.PutJSON(ctx, keyRuntime, runtimeData); err != nil {
		return err
	}
	xdpRuntime := filterRuntime(runtimeData, "xdp")
	nftRuntime := filterRuntime(runtimeData, "nft")
	if err := store.PutJSON(ctx, keyRuntimeXDP, xdpRuntime); err != nil {
		return err
	}
	if err := store.PutJSON(ctx, keyRuntimeNFT, nftRuntime); err != nil {
		return err
	}
	renderedNFT := renderNFT(cfg, nftRuntime)
	if err := store.PutRaw(ctx, keyRenderedNFT, mustJSONString(renderedNFT)); err != nil {
		return err
	}
	var xdpStatus json.RawMessage = json.RawMessage(`{}`)
	xdpApplied := false
	var xdpErr *string
	if apply && len(xdpRuntime.Rules) > 0 {
		status, err := applyXDPFromDB(xdpRuntime)
		if err != nil {
			msg := err.Error()
			xdpErr = &msg
		} else {
			xdpStatus = status
			xdpApplied = true
			if err := store.PutRaw(ctx, keyXDPStatus, string(status)); err != nil {
				return err
			}
		}
	}
	status := buildForwarderStatus(runtimeData, xdpRuntime, nftRuntime, xdpStatus, xdpApplied, len(nftRuntime.Rules) > 0, xdpErr)
	return store.PutJSON(ctx, keyForwarderStatus, status)
}

func compileRuntime(cfg Config, stats StatsState) (CompiledRuntime, error) {
	cfg = normalizeConfig(cfg)
	userIndex := map[string]uint32{}
	ruleIndex := map[string]uint32{}
	users := sortedUsers(cfg)
	runtimeUsers := make([]RuntimeUser, 0, len(users))
	for i, user := range users {
		idx := uint32(i + 1)
		userIndex[user.ID] = idx
		usage := stats.Users[user.ID]
		var limit uint64
		if user.Limits.TrafficBytes != nil {
			limit = *user.Limits.TrafficBytes
		}
		runtimeUsers = append(runtimeUsers, RuntimeUser{
			ID: user.ID, Index: idx, TrafficLimit: limit, BillingUsedBase: usage.BillingUsedBytes,
		})
	}
	var rules []RuntimeRule
	now := nowMinute()
	nextRuleIndex := uint32(1)
	for _, fwd := range sortedForwards(cfg) {
		if !fwd.Enabled || (fwd.StopAt != nil && *fwd.StopAt <= now) {
			continue
		}
		protos := []string{fwd.Protocol}
		if fwd.Protocol == "tcp_udp" {
			protos = []string{"tcp", "udp"}
		}
		targets, err := resolveTargets(fwd.RemoteHost, fwd.ListenIP, fwd.Net)
		if err != nil {
			return CompiledRuntime{}, err
		}
		for _, target := range targets {
			for _, proto := range protos {
				idx := nextRuleIndex
				nextRuleIndex++
				ruleIndex[fwd.ID] = idx
				ruleLimit := uint64(0)
				if fwd.Limits.TrafficBytes != nil {
					ruleLimit = *fwd.Limits.TrafficBytes
				}
				userLimit := uint64(0)
				if uidx, ok := findUser(cfg, fwd.UserID); ok && cfg.Users[uidx].Limits.TrafficBytes != nil {
					userLimit = *cfg.Users[uidx].Limits.TrafficBytes
				}
				mssMode := ""
				if fwd.Net.MSSMode != nil {
					mssMode = *fwd.Net.MSSMode
				}
				mssValue := uint16(0)
				if fwd.Net.MSSValue != nil {
					mssValue = *fwd.Net.MSSValue
				}
				snatSource := ""
				if fwd.Net.SNATSource != nil {
					snatSource = *fwd.Net.SNATSource
				}
				comment := ""
				if fwd.Comment != nil {
					comment = *fwd.Comment
				}
				usage := stats.Forwards[fwd.ID]
				userUsage := stats.Users[fwd.UserID]
				rule := RuntimeRule{
					ID: fwd.ID, Index: idx, UserID: fwd.UserID, UserIndex: userIndex[fwd.UserID],
					ListenIP: fwd.ListenIP, ListenPort: fwd.ListenPort, Protocol: proto,
					IPVersion: target.version, ResolvedTarget: target.addr.String(), RemotePort: fwd.RemotePort,
					SNATMode: fwd.Net.SNATMode, SNATSource: snatSource, MSSMode: mssMode, MSSValue: mssValue,
					TrafficMode: fwd.TrafficMode, TrafficRatio: fwd.TrafficRatio,
					RuleLimit: ruleLimit, UserLimit: userLimit, BillingUsedBase: usage.BillingUsedBytes,
					UserBillingUsedBase: userUsage.BillingUsedBytes, RemoteInput: fwd.RemoteHost, Comment: comment,
				}
				rule.ExecutionClass = executionClass(target.addr)
				rule.CounterOwner = rule.ExecutionClass
				rule.BackendReason = backendReason(target.addr)
				rule.LoopbackLocal = target.addr.IsLoopback()
				rule.FeatureFlags, rule.FeatureProfile = featureFlags(rule)
				rules = append(rules, rule)
			}
		}
	}
	iface := cfg.Settings.Forward.Interface
	if iface == "" {
		iface = cfg.Settings.TCInterface
	}
	out := CompiledRuntime{
		Generated: nowISO(), Settings: RuntimeSettings{Interface: iface}, Users: runtimeUsers, Rules: rules,
		RuleIndex: ruleIndex, UserIndex: userIndex, DataplaneVersion: dataplaneVersion, MapABIVersion: mapABIVersion,
		Summary: summarizeRuntime(rules),
	}
	data, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	sum := sha256.Sum256(data)
	out.ConfigHash = hex.EncodeToString(sum[:])
	return out, nil
}

type resolvedTarget struct {
	addr    netip.Addr
	version uint8
}

func resolveTargets(host, listenIP string, netCfg NetConfig) ([]resolvedTarget, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []resolvedTarget{{addr: addr, version: addrVersion(addr)}}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("无法解析目标地址：%s：%w", host, err)
	}
	out := make([]resolvedTarget, 0, len(ips))
	seen := map[string]bool{}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		key := addr.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, resolvedTarget{addr: addr, version: addrVersion(addr)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].addr.String() < out[j].addr.String() })
	if len(out) == 0 {
		return nil, fmt.Errorf("无法解析目标地址：%s", host)
	}
	return out, nil
}

func addrVersion(addr netip.Addr) uint8 {
	if addr.Is4() {
		return 4
	}
	return 6
}

func executionClass(addr netip.Addr) string {
	if addr.IsLoopback() {
		return "nft"
	}
	return "xdp"
}

func backendReason(addr netip.Addr) string {
	if addr.IsLoopback() {
		return "loopback-local"
	}
	return "xdp-fast-path"
}

func featureFlags(rule RuntimeRule) ([]string, string) {
	flags := []string{}
	if rule.SNATMode == "snat" {
		flags = append(flags, "fixed_snat")
	}
	if rule.MSSMode != "" && rule.MSSMode != "none" {
		flags = append(flags, "mss")
	}
	if rule.RuleLimit > 0 || rule.UserLimit > 0 {
		flags = append(flags, "metered")
	}
	sort.Strings(flags)
	for _, flag := range flags {
		if flag == "fixed_snat" || flag == "mss" {
			return flags, "rewrite_nat"
		}
	}
	for _, flag := range flags {
		if flag == "metered" {
			return flags, "metered_nat"
		}
	}
	return flags, "basic_nat"
}

func summarizeRuntime(rules []RuntimeRule) RuntimeSummary {
	s := RuntimeSummary{Rules: len(rules), ProfileCounts: map[string]int{}}
	for _, rule := range rules {
		switch rule.ExecutionClass {
		case "xdp":
			s.XDPRules++
		case "nft":
			s.NFTRules++
		}
		if rule.LoopbackLocal {
			s.LoopbackRules++
		}
		s.ProfileCounts[rule.FeatureProfile]++
	}
	return s
}

func filterRuntime(runtimeData CompiledRuntime, class string) CompiledRuntime {
	out := runtimeData
	out.Rules = nil
	for _, rule := range runtimeData.Rules {
		if rule.ExecutionClass == class {
			out.Rules = append(out.Rules, rule)
		}
	}
	out.Summary = summarizeRuntime(out.Rules)
	return out
}

func mustJSONString(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func tempStatePath(name string) string {
	return filepath.Join(os.TempDir(), "pfwd-"+name)
}

func applyXDPFromDB(runtimeData CompiledRuntime) (json.RawMessage, error) {
	dir, err := os.MkdirTemp("", "pfwd-xdp-tmp-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	runtimePath := filepath.Join(dir, "runtime.tmp")
	statePath := filepath.Join(dir, "state.tmp")
	statusPath := filepath.Join(dir, "status.tmp")
	data, err := json.Marshal(runtimeData)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(runtimePath, data, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(statePath, []byte(`{"users":{},"forwards":{}}`), 0o600); err != nil {
		return nil, err
	}
	args := []string{
		"apply",
		"--runtime-file", runtimePath,
		"--state-file", statePath,
		"--status-file", statusPath,
		"--xdp-pin", "/sys/fs/bpf/pfwd_xdp_link",
		"--rule-counter-pin", "/sys/fs/bpf/pfwd_rule_counters",
		"--user-counter-pin", "/sys/fs/bpf/pfwd_user_counters",
		"--stats-pin", "/sys/fs/bpf/pfwd_stats",
		"--quiet",
	}
	if runtimeData.Settings.Interface != "" {
		args = append(args, "--iface", runtimeData.Settings.Interface)
	}
	if err := xdp.Run(args); err != nil {
		return nil, err
	}
	status, err := os.ReadFile(statusPath)
	if err != nil {
		return nil, err
	}
	if !json.Valid(status) {
		return nil, fmt.Errorf("XDP status 不是 JSON")
	}
	return status, nil
}

func buildForwarderStatus(runtimeData, xdpRuntime, nftRuntime CompiledRuntime, xdpStatus json.RawMessage, xdpApplied, nftApplied bool, xdpErr *string) ForwarderStatus {
	backend := "none"
	switch {
	case xdpApplied && nftApplied:
		backend = "hybrid"
	case xdpApplied:
		backend = "xdp-only"
	case nftApplied:
		backend = "nft-only"
	case len(runtimeData.Rules) > 0:
		backend = "pending"
	}
	return ForwarderStatus{
		Applied:     len(runtimeData.Rules) > 0 && (xdpApplied || nftApplied),
		GeneratedAt: nowISO(), ForwardingBackend: backend,
		XDPApplied: xdpApplied, XDPForwardApplied: xdpApplied,
		NFTApplied: nftApplied, LoopbackViaNFT: nftRuntime.Summary.LoopbackRules > 0,
		LoopbackSplitActive: len(xdpRuntime.Rules) > 0 && len(nftRuntime.Rules) > 0,
		XDPError:            xdpErr, Rules: len(runtimeData.Rules),
		XDPCandidateRulesCount: xdpRuntime.Summary.Rules, XDPRulesCount: len(xdpRuntime.Rules), NFTRulesCount: len(nftRuntime.Rules),
		Interface: runtimeData.Settings.Interface, DataplaneVersion: dataplaneVersion, MapABIVersion: mapABIVersion,
		ProfileCounts: runtimeData.Summary.ProfileCounts, XDPStatus: xdpStatus,
	}
}
