package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed xdp_bpfel.o
var xdpBPFEL []byte

const binaryVersion = "0.2.0"
const ratioScale = uint64(1_000_000)
const maxRules = 4096
const maxUsers = 4096

type bpfObjects struct {
	PFWDXDP         *ebpf.Program `ebpf:"pfwd_xdp"`
	PFWDIngress     *ebpf.Program `ebpf:"pfwd_ingress"`
	PFWDSettings    *ebpf.Map     `ebpf:"pfwd_settings"`
	PFWDRules       *ebpf.Map     `ebpf:"pfwd_rules"`
	PFWDConnections *ebpf.Map     `ebpf:"pfwd_connections"`
	PFWDReverse     *ebpf.Map     `ebpf:"pfwd_reverse"`
	PFWDRuleCounter *ebpf.Map     `ebpf:"pfwd_rule_counters"`
	PFWDUserCounter *ebpf.Map     `ebpf:"pfwd_user_counters"`
	PFWDStats       *ebpf.Map     `ebpf:"pfwd_stats"`
	PFWDWhitelistV4 *ebpf.Map     `ebpf:"pfwd_whitelist_v4"`
	PFWDWhitelistV6 *ebpf.Map     `ebpf:"pfwd_whitelist_v6"`
	PFWDFlows       *ebpf.Map     `ebpf:"pfwd_allowed_flows"`
	PFWDSkipPorts   *ebpf.Map     `ebpf:"pfwd_protocol_skip_ports"`
	PFWDScratch     *ebpf.Map     `ebpf:"pfwd_scratch"`
}

func (o *bpfObjects) Close() {
	if o == nil {
		return
	}
	for _, closer := range []interface{ Close() error }{
		o.PFWDXDP, o.PFWDIngress, o.PFWDSettings, o.PFWDRules, o.PFWDConnections, o.PFWDReverse,
		o.PFWDRuleCounter, o.PFWDUserCounter, o.PFWDStats, o.PFWDWhitelistV4, o.PFWDWhitelistV6, o.PFWDFlows, o.PFWDSkipPorts, o.PFWDScratch,
	} {
		if closer != nil {
			_ = closer.Close()
		}
	}
}

type applyOptions struct {
	Iface          string
	Mode           string
	RuntimeFile    string
	StateFile      string
	StatusFile     string
	XDPPin         string
	IngressPin     string
	RuleCounterPin string
	UserCounterPin string
	StatsPin       string
	WhitelistFile  string
	Quiet          bool
}

type removeOptions struct {
	StatusFile     string
	XDPPin         string
	IngressPin     string
	RuleCounterPin string
	UserCounterPin string
	StatsPin       string
}

type snapshotOptions struct {
	StateFile      string
	RuntimeFile    string
	StatusFile     string
	RuleCounterPin string
}

type statsOptions struct {
	StatusFile string
	StatsPin   string
}

type runtimeFile struct {
	Rules      []runtimeRule     `json:"rules"`
	Users      []runtimeUser     `json:"users"`
	Settings   runtimeSettings   `json:"settings"`
	Generated  string            `json:"generated_at,omitempty"`
	RuleIndex  map[string]uint32 `json:"rule_index,omitempty"`
	UserIndex  map[string]uint32 `json:"user_index,omitempty"`
	ConfigHash string            `json:"config_hash,omitempty"`
}

type runtimeSettings struct {
	XDPMode           string   `json:"xdp_mode"`
	Interface         string   `json:"interface"`
	GuardEnabled      bool     `json:"guard_enabled"`
	WhitelistEnabled  bool     `json:"whitelist_enabled"`
	BlockHTTP         bool     `json:"block_http"`
	BlockTLS          bool     `json:"block_tls"`
	BlockSOCKS        bool     `json:"block_socks"`
	ProtocolSkipPorts []uint16 `json:"protocol_skip_ports,omitempty"`
	WhitelistFiles    []string `json:"whitelist_files,omitempty"`
	GuardIngressMode  string   `json:"guard_ingress_mode,omitempty"`
}

type runtimeUser struct {
	ID              string `json:"id"`
	Index           uint32 `json:"index"`
	TrafficLimit    uint64 `json:"traffic_limit_bytes"`
	BillingUsedBase uint64 `json:"billing_used_base_bytes"`
}

type runtimeRule struct {
	ID                  string  `json:"id"`
	Index               uint32  `json:"index"`
	UserID              string  `json:"user_id"`
	UserIndex           uint32  `json:"user_index"`
	ListenIP            string  `json:"listen_ip"`
	ListenPort          uint16  `json:"listen_port"`
	Protocol            string  `json:"protocol"`
	IPVersion           uint8   `json:"ip_version"`
	ResolvedTarget      string  `json:"resolved_target"`
	RemotePort          uint16  `json:"remote_port"`
	SNATMode            string  `json:"snat_mode"`
	SNATSource          string  `json:"snat_source,omitempty"`
	MSSMode             string  `json:"mss_mode,omitempty"`
	MSSValue            uint16  `json:"mss_value,omitempty"`
	TrafficMode         string  `json:"traffic_mode"`
	TrafficRatio        float64 `json:"traffic_ratio"`
	RuleLimit           uint64  `json:"traffic_limit_bytes"`
	UserLimit           uint64  `json:"user_limit_bytes"`
	BillingUsedBase     uint64  `json:"billing_used_base_bytes"`
	UserBillingUsedBase uint64  `json:"user_billing_used_base_bytes"`
	RemoteInput         string  `json:"remote_input,omitempty"`
	Comment             string  `json:"comment,omitempty"`
}

type statusPayload struct {
	Applied        bool   `json:"applied"`
	BinaryVersion  string `json:"binary_version"`
	AppliedAt      string `json:"applied_at,omitempty"`
	Interface      string `json:"interface,omitempty"`
	InterfaceIndex int    `json:"interface_index,omitempty"`
	XDPMode        string `json:"xdp_mode,omitempty"`
	XDPEffective   string `json:"xdp_effective,omitempty"`
	XDPAttachKind  string `json:"xdp_attach_kind,omitempty"`
	XDPReason      string `json:"xdp_reason,omitempty"`
	IngressKind    string `json:"ingress_kind,omitempty"`
	ProtocolGuard  bool   `json:"protocol_guard,omitempty"`
	RuntimeFile    string `json:"runtime_file,omitempty"`
	StateFile      string `json:"state_file,omitempty"`
	ConfigHash     string `json:"config_hash,omitempty"`
	Rules          int    `json:"rules,omitempty"`
	Users          int    `json:"users,omitempty"`
	XDPPin         string `json:"xdp_pin,omitempty"`
	IngressPin     string `json:"ingress_pin,omitempty"`
	RuleCounterPin string `json:"rule_counter_pin,omitempty"`
	UserCounterPin string `json:"user_counter_pin,omitempty"`
	StatsPin       string `json:"stats_pin,omitempty"`
}

type xdpSettings struct {
	WhitelistEnabled uint8
	BlockHTTP        uint8
	BlockTLS         uint8
	BlockSOCKS       uint8
	GuardEnabled     uint8
	Pad              [3]uint8
}

type ruleKey struct {
	Family     uint8
	Protocol   uint8
	ListenPort uint16
	ListenAddr [16]byte
}

type ruleVal struct {
	RuleID                   uint32
	UserID                   uint32
	TargetAddr               [16]byte
	TargetPort               uint16
	SNATMode                 uint8
	MSSMode                  uint8
	SNATAddr                 [16]byte
	MSSValue                 uint16
	Flags                    uint16
	RuleLimitBytes           uint64
	UserLimitBytes           uint64
	TrafficRatioScaled       uint64
	RuleBillingUsedBaseBytes uint64
	UserBillingUsedBaseBytes uint64
	TrafficMode              uint8
	Pad                      [7]uint8
}

type counterVal struct {
	InputBytes     uint64 `json:"input_bytes"`
	OutputBytes    uint64 `json:"output_bytes"`
	InputPackets   uint64 `json:"input_packets"`
	OutputPackets  uint64 `json:"output_packets"`
	DroppedBytes   uint64 `json:"dropped_bytes"`
	DroppedPackets uint64 `json:"dropped_packets"`
	BillingBytes   uint64 `json:"billing_bytes"`
}

type connVal struct {
	RuleID             uint32
	UserID             uint32
	ClientAddr         [16]byte
	ListenAddr         [16]byte
	SourceAddr         [16]byte
	ClientPort         uint16
	SourcePort         uint16
	ListenPort         uint16
	Pad16              uint16
	TrafficRatioScaled uint64
	TrafficMode        uint8
	Pad8               [7]uint8
	Packets            uint64
	Bytes              uint64
}

type whitelistKeyV4 struct {
	PrefixLen uint32
	Addr      uint32
}

type whitelistKeyV6 struct {
	PrefixLen uint32
	Addr      [16]byte
}

type portKey struct {
	Port uint16
	Pad  [4]byte
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pfwd-xdp: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "apply":
		return runApply(args[1:])
	case "remove":
		return runRemove(args[1:])
	case "status":
		return runStatus(args[1:])
	case "snapshot":
		return runSnapshot(args[1:])
	case "stats":
		return runStats(args[1:])
	case "version", "--version":
		fmt.Println(binaryVersion)
		return nil
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("未知子命令：%s", args[0])
	}
}

func runApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts applyOptions
	fs.StringVar(&opts.Iface, "iface", "", "network interface")
	fs.StringVar(&opts.Mode, "xdp-mode", "auto", "off|auto|force")
	fs.StringVar(&opts.RuntimeFile, "runtime-file", "", "runtime json")
	fs.StringVar(&opts.StateFile, "state-file", "", "state json")
	fs.StringVar(&opts.StatusFile, "status-file", "", "status json")
	fs.StringVar(&opts.XDPPin, "xdp-pin", "", "bpffs xdp link pin")
	fs.StringVar(&opts.IngressPin, "ingress-pin", "", "bpffs ingress link pin")
	fs.StringVar(&opts.RuleCounterPin, "rule-counter-pin", "/sys/fs/bpf/pfwd_rule_counters", "bpffs rule counter map pin")
	fs.StringVar(&opts.UserCounterPin, "user-counter-pin", "/sys/fs/bpf/pfwd_user_counters", "bpffs user counter map pin")
	fs.StringVar(&opts.StatsPin, "stats-pin", "/sys/fs/bpf/pfwd_stats", "bpffs stats map pin")
	fs.StringVar(&opts.WhitelistFile, "whitelist-file", "", "colon separated cidr files")
	fs.BoolVar(&opts.Quiet, "quiet", false, "suppress non-error output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("apply 不接受额外参数")
	}
	return applyRuntime(opts)
}

func runRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts removeOptions
	fs.StringVar(&opts.StatusFile, "status-file", "", "status json")
	fs.StringVar(&opts.XDPPin, "xdp-pin", "", "bpffs xdp link pin")
	fs.StringVar(&opts.IngressPin, "ingress-pin", "", "bpffs ingress link pin")
	fs.StringVar(&opts.RuleCounterPin, "rule-counter-pin", "", "bpffs rule counter map pin")
	fs.StringVar(&opts.UserCounterPin, "user-counter-pin", "", "bpffs user counter map pin")
	fs.StringVar(&opts.StatsPin, "stats-pin", "", "bpffs stats map pin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("remove 不接受额外参数")
	}
	return removeRuntime(opts)
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var statusFile string
	fs.StringVar(&statusFile, "status-file", "", "status json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("status 不接受额外参数")
	}
	if statusFile == "" {
		return fmt.Errorf("status 缺少 --status-file")
	}
	payload, err := readStatus(statusFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			payload = statusPayload{Applied: false, BinaryVersion: binaryVersion}
		} else {
			return err
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func runSnapshot(args []string) error {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts snapshotOptions
	fs.StringVar(&opts.StateFile, "state-file", "", "state json")
	fs.StringVar(&opts.RuntimeFile, "runtime-file", "", "runtime json")
	fs.StringVar(&opts.StatusFile, "status-file", "", "status json")
	fs.StringVar(&opts.RuleCounterPin, "rule-counter-pin", "", "bpffs rule counter map pin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("snapshot 不接受额外参数")
	}
	return snapshotCounters(opts)
}

func runStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts statsOptions
	fs.StringVar(&opts.StatusFile, "status-file", "", "status json")
	fs.StringVar(&opts.StatsPin, "stats-pin", "", "bpffs stats map pin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("stats 不接受额外参数")
	}
	return dumpStats(opts)
}

func applyRuntime(opts applyOptions) error {
	if opts.RuntimeFile == "" {
		return fmt.Errorf("缺少 --runtime-file")
	}
	if opts.StateFile == "" {
		return fmt.Errorf("缺少 --state-file")
	}
	if opts.StatusFile == "" {
		return fmt.Errorf("缺少 --status-file")
	}
	runtimeData, err := loadRuntime(opts.RuntimeFile)
	if err != nil {
		return err
	}
	if opts.Iface == "" {
		opts.Iface = runtimeData.Settings.Interface
	}
	if opts.Mode == "" {
		opts.Mode = runtimeData.Settings.XDPMode
	}
	if opts.Mode == "" {
		opts.Mode = "auto"
	}
	if opts.Iface == "" && opts.Mode != "off" {
		return fmt.Errorf("缺少 --iface")
	}
	switch opts.Mode {
	case "off", "auto", "force":
	default:
		return fmt.Errorf("无效 xdp-mode：%s", opts.Mode)
	}
	if opts.Mode != "off" && opts.XDPPin == "" {
		return fmt.Errorf("缺少 --xdp-pin")
	}
	if opts.IngressPin == "" {
		return fmt.Errorf("缺少 --ingress-pin")
	}
	if opts.RuleCounterPin == "" {
		return fmt.Errorf("缺少 --rule-counter-pin")
	}
	if opts.UserCounterPin == "" {
		return fmt.Errorf("缺少 --user-counter-pin")
	}
	if opts.StatsPin == "" {
		return fmt.Errorf("缺少 --stats-pin")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("移除 memlock 限制失败: %w", err)
	}
	if err := removeRuntime(removeOptions{
		StatusFile:     opts.StatusFile,
		XDPPin:         opts.XDPPin,
		IngressPin:     opts.IngressPin,
		RuleCounterPin: opts.RuleCounterPin,
		UserCounterPin: opts.UserCounterPin,
		StatsPin:       opts.StatsPin,
	}); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("清理旧运行态失败: %w", err)
	}
	if opts.Mode == "off" {
		payload := statusPayload{Applied: false, BinaryVersion: binaryVersion, XDPMode: opts.Mode, RuntimeFile: opts.RuntimeFile, StateFile: opts.StateFile}
		return writeStatus(opts.StatusFile, payload)
	}
	iface, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return fmt.Errorf("查找网卡 %q 失败: %w", opts.Iface, err)
	}
	objs, err := loadObjects()
	if err != nil {
		return err
	}
	defer objs.Close()
	if err := loadMaps(objs, runtimeData, opts); err != nil {
		return err
	}
	if err := pinRuntimeMaps(objs, opts); err != nil {
		return err
	}
	protocolGuard := protocolGuardEnabled(runtimeData.Settings)
	xdpEffective, xdpKind, xdpReason, err := attachXDP(iface, objs.PFWDXDP, opts)
	if err != nil {
		return err
	}
	ingressKind := ""
	if protocolGuard && guardIngressEnabled(runtimeData.Settings) {
		ingressKind, err = attachIngress(iface, objs.PFWDIngress, opts.IngressPin)
		if err != nil {
			return err
		}
	} else if err := removeIngressRuntime(opts.IngressPin, iface.Name); err != nil {
		return err
	}
	if ingressKind != "" && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "pfwd-xdp: tc ingress attached via %s\n", ingressKind)
	}
	payload := statusPayload{
		Applied:        true,
		BinaryVersion:  binaryVersion,
		AppliedAt:      time.Now().UTC().Format(time.RFC3339),
		Interface:      iface.Name,
		InterfaceIndex: iface.Index,
		XDPMode:        opts.Mode,
		XDPEffective:   xdpEffective,
		XDPAttachKind:  xdpKind,
		XDPReason:      xdpReason,
		IngressKind:    ingressKind,
		ProtocolGuard:  protocolGuard,
		RuntimeFile:    opts.RuntimeFile,
		StateFile:      opts.StateFile,
		ConfigHash:     runtimeData.ConfigHash,
		Rules:          len(runtimeData.Rules),
		Users:          len(runtimeData.Users),
		XDPPin:         opts.XDPPin,
		IngressPin:     opts.IngressPin,
		RuleCounterPin: opts.RuleCounterPin,
		UserCounterPin: opts.UserCounterPin,
		StatsPin:       opts.StatsPin,
	}
	return writeStatus(opts.StatusFile, payload)
}

func loadObjects() (*bpfObjects, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpBPFEL))
	if err != nil {
		return nil, fmt.Errorf("加载 eBPF spec 失败: %w", err)
	}
	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch},
	}); err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			return nil, fmt.Errorf("加载 eBPF 对象失败: %+v", verifierErr)
		}
		return nil, fmt.Errorf("加载 eBPF 对象失败: %+v", err)
	}
	return &objs, nil
}

func loadRuntime(path string) (*runtimeFile, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 runtime 失败: %w", err)
	}
	var runtimeData runtimeFile
	if err := json.Unmarshal(content, &runtimeData); err != nil {
		return nil, fmt.Errorf("解析 runtime 失败: %w", err)
	}
	if runtimeData.ConfigHash == "" {
		sum := sha256.Sum256(content)
		runtimeData.ConfigHash = hex.EncodeToString(sum[:])
	}
	if len(runtimeData.Rules) > maxRules {
		return nil, fmt.Errorf("规则数量超过上限：%d > %d", len(runtimeData.Rules), maxRules)
	}
	if len(runtimeData.Users) > maxUsers {
		return nil, fmt.Errorf("用户数量超过上限：%d > %d", len(runtimeData.Users), maxUsers)
	}
	return &runtimeData, nil
}

func loadMaps(objs *bpfObjects, runtimeData *runtimeFile, opts applyOptions) error {
	if objs.PFWDSettings == nil || objs.PFWDRules == nil || objs.PFWDRuleCounter == nil || objs.PFWDUserCounter == nil {
		return fmt.Errorf("关键 BPF map 未加载")
	}
	settings := xdpSettings{
		WhitelistEnabled: boolToUint8(runtimeData.Settings.WhitelistEnabled),
		BlockHTTP:        boolToUint8(runtimeData.Settings.BlockHTTP),
		BlockTLS:         boolToUint8(runtimeData.Settings.BlockTLS),
		BlockSOCKS:       boolToUint8(runtimeData.Settings.BlockSOCKS),
		GuardEnabled:     boolToUint8(runtimeData.Settings.GuardEnabled),
	}
	key := uint32(0)
	if err := objs.PFWDSettings.Update(&key, &settings, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("写入 settings 失败: %w", err)
	}
	if err := loadProtocolSkipPorts(objs.PFWDSkipPorts, runtimeData.Settings.ProtocolSkipPorts); err != nil {
		return err
	}
	files := runtimeData.Settings.WhitelistFiles
	if opts.WhitelistFile != "" {
		files = splitFiles(opts.WhitelistFile)
	}
	if runtimeData.Settings.WhitelistEnabled {
		if err := loadWhitelistFiles(objs.PFWDWhitelistV4, objs.PFWDWhitelistV6, files); err != nil {
			return err
		}
	}
	for _, user := range runtimeData.Users {
		zero := counterVal{}
		if err := objs.PFWDUserCounter.Update(&user.Index, &zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("初始化用户计数失败 (%s): %w", user.ID, err)
		}
	}
	for _, rule := range runtimeData.Rules {
		if err := putRule(objs, rule); err != nil {
			return err
		}
	}
	return nil
}

func pinRuntimeMaps(objs *bpfObjects, opts applyOptions) error {
	pins := map[string]*ebpf.Map{
		opts.RuleCounterPin: objs.PFWDRuleCounter,
		opts.UserCounterPin: objs.PFWDUserCounter,
		opts.StatsPin:       objs.PFWDStats,
	}
	for path, m := range pins {
		if m == nil {
			return fmt.Errorf("缺少 map，无法 pin：%s", path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		_ = os.Remove(path)
		if err := m.Pin(path); err != nil {
			return fmt.Errorf("pin map 失败 (%s): %w", path, err)
		}
	}
	return nil
}

func protocolGuardEnabled(settings runtimeSettings) bool {
	return settings.GuardEnabled && (settings.BlockHTTP || settings.BlockTLS || settings.BlockSOCKS)
}

func guardIngressEnabled(settings runtimeSettings) bool {
	return strings.EqualFold(strings.TrimSpace(settings.GuardIngressMode), "tc")
}

func loadProtocolSkipPorts(skipMap *ebpf.Map, ports []uint16) error {
	if skipMap == nil {
		return fmt.Errorf("协议封锁 skip-port map 未加载")
	}
	value := uint8(1)
	for _, port := range ports {
		if port == 0 {
			return fmt.Errorf("无效协议封锁跳过端口：%d", port)
		}
		key := portKey{Port: htons(port)}
		if err := skipMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("写入协议封锁跳过端口失败 (%d): %w", port, err)
		}
	}
	return nil
}

func putRule(objs *bpfObjects, rule runtimeRule) error {
	key, err := makeRuleKey(rule)
	if err != nil {
		return fmt.Errorf("生成规则 key 失败 (%s): %w", rule.ID, err)
	}
	value, err := makeRuleVal(rule)
	if err != nil {
		return fmt.Errorf("生成规则 value 失败 (%s): %w", rule.ID, err)
	}
	if err := objs.PFWDRules.Update(&key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("写入规则失败 (%s): %w", rule.ID, err)
	}
	zero := counterVal{}
	if err := objs.PFWDRuleCounter.Update(&rule.Index, &zero, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("初始化规则计数失败 (%s): %w", rule.ID, err)
	}
	return nil
}

func makeRuleKey(rule runtimeRule) (ruleKey, error) {
	var key ruleKey
	key.Family = rule.IPVersion
	proto, err := protocolNumber(rule.Protocol)
	if err != nil {
		return key, err
	}
	key.Protocol = proto
	key.ListenPort = htons(rule.ListenPort)
	if rule.ListenIP == "" || rule.ListenIP == "::" || rule.ListenIP == "0.0.0.0" {
		return key, nil
	}
	addr, err := netip.ParseAddr(rule.ListenIP)
	if err != nil {
		return key, err
	}
	key.ListenAddr = addrTo16(addr)
	return key, nil
}

func makeRuleVal(rule runtimeRule) (ruleVal, error) {
	var value ruleVal
	target, err := netip.ParseAddr(rule.ResolvedTarget)
	if err != nil {
		return value, err
	}
	value.RuleID = rule.Index
	value.UserID = rule.UserIndex
	value.TargetAddr = addrTo16(target)
	value.TargetPort = htons(rule.RemotePort)
	switch rule.SNATMode {
	case "", "masquerade":
		value.SNATMode = 0
	case "snat":
		value.SNATMode = 1
		addr, err := netip.ParseAddr(rule.SNATSource)
		if err != nil {
			return value, err
		}
		value.SNATAddr = addrTo16(addr)
	default:
		return value, fmt.Errorf("无效 SNAT 模式：%s", rule.SNATMode)
	}
	switch rule.MSSMode {
	case "", "none":
		value.MSSMode = 0
	case "clamp":
		value.MSSMode = 1
	case "set":
		value.MSSMode = 2
		value.MSSValue = rule.MSSValue
	default:
		return value, fmt.Errorf("无效 MSS 模式：%s", rule.MSSMode)
	}
	value.RuleLimitBytes = rule.RuleLimit
	value.UserLimitBytes = rule.UserLimit
	value.TrafficRatioScaled = uint64(rule.TrafficRatio * float64(ratioScale))
	if value.TrafficRatioScaled == 0 {
		value.TrafficRatioScaled = ratioScale
	}
	value.RuleBillingUsedBaseBytes = rule.BillingUsedBase
	value.UserBillingUsedBaseBytes = rule.UserBillingUsedBase
	if rule.TrafficMode == "one-way" {
		value.TrafficMode = 1
	}
	return value, nil
}

func attachXDP(iface *net.Interface, prog *ebpf.Program, opts applyOptions) (string, string, string, error) {
	if prog == nil {
		return "", "", "", fmt.Errorf("pfwd_xdp program 未加载")
	}
	if err := features.HaveProgramType(ebpf.XDP); err != nil {
		return "", "", "", fmt.Errorf("XDP 不可用: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(opts.XDPPin), 0o755); err != nil {
		return "", "", "", fmt.Errorf("创建 XDP pin 目录失败: %w", err)
	}
	_ = removePinnedLink(opts.XDPPin)
	tryAttach := func(flags link.XDPAttachFlags, kind string) (string, string, string, error) {
		attached, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index, Flags: flags})
		if err != nil {
			return "", "", "", err
		}
		defer attached.Close()
		if err := attached.Pin(opts.XDPPin); err != nil {
			return "", "", "", fmt.Errorf("pin xdp link 失败: %w", err)
		}
		if err := attached.Close(); err != nil {
			return "", "", "", fmt.Errorf("关闭 xdp link fd 失败: %w", err)
		}
		return "enabled", kind, "", nil
	}
	if opts.Mode != "force" {
		if effective, kind, reason, err := tryAttach(link.XDPDriverMode, "driver"); err == nil {
			return effective, kind, reason, nil
		} else {
			driverErr := err
			if effective, kind, reason, err := tryAttach(link.XDPGenericMode, "generic"); err == nil {
				return effective, kind, reason, nil
			} else {
				return "", "", "", fmt.Errorf("XDP auto attach 失败：driver=%v; generic=%w", driverErr, err)
			}
		}
	}
	if effective, kind, reason, err := tryAttach(link.XDPDriverMode, "driver"); err == nil {
		return effective, kind, reason, nil
	} else {
		return "", "", "", fmt.Errorf("XDP force attach 失败: %w", err)
	}
}

func attachIngress(iface *net.Interface, prog *ebpf.Program, pin string) (string, error) {
	if prog == nil {
		return "", fmt.Errorf("pfwd_ingress program 未加载")
	}
	if err := os.MkdirAll(filepath.Dir(pin), 0o755); err != nil {
		return "", fmt.Errorf("创建 ingress pin 目录失败: %w", err)
	}
	_ = removePinnedLink(pin)
	if attached, err := link.AttachTCX(link.TCXOptions{Program: prog, Interface: iface.Index, Attach: ebpf.AttachTCXIngress}); err == nil {
		defer attached.Close()
		if err := attached.Pin(pin); err != nil {
			return "", fmt.Errorf("pin tcx link 失败: %w", err)
		}
		return "tcx", attached.Close()
	}
	if err := runTC("qdisc", "replace", "dev", iface.Name, "clsact"); err != nil {
		return "", err
	}
	if err := prog.Pin(pin); err != nil {
		return "", fmt.Errorf("pin ingress program 失败: %w", err)
	}
	if err := runTC("filter", "replace", "dev", iface.Name, "ingress", "bpf", "direct-action", "object-pinned", pin); err != nil {
		return "", err
	}
	return "tc", nil
}

func removeIngressRuntime(pin string, ifaceName string) error {
	if pin != "" {
		_ = removePinnedLink(pin)
		_ = removePinnedProgram(pin)
	}
	if ifaceName != "" {
		_ = runTC("filter", "delete", "dev", ifaceName, "ingress")
		_ = runTC("qdisc", "delete", "dev", ifaceName, "clsact")
	}
	return nil
}

func removeRuntime(opts removeOptions) error {
	payload, _ := readStatus(opts.StatusFile)
	xdpPin := firstNonEmpty(opts.XDPPin, payload.XDPPin)
	ingressPin := firstNonEmpty(opts.IngressPin, payload.IngressPin)
	ruleCounterPin := firstNonEmpty(opts.RuleCounterPin, payload.RuleCounterPin)
	userCounterPin := firstNonEmpty(opts.UserCounterPin, payload.UserCounterPin)
	statsPin := firstNonEmpty(opts.StatsPin, payload.StatsPin)
	if xdpPin != "" {
		_ = removePinnedLink(xdpPin)
	}
	if ingressPin != "" {
		_ = removeIngressRuntime(ingressPin, payload.Interface)
	} else if payload.Interface != "" {
		_ = removeIngressRuntime("", payload.Interface)
	}
	if opts.StatusFile != "" {
		if err := os.Remove(opts.StatusFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if ruleCounterPin != "" {
		_ = os.Remove(ruleCounterPin)
	}
	if userCounterPin != "" {
		_ = os.Remove(userCounterPin)
	}
	if statsPin != "" {
		_ = os.Remove(statsPin)
	}
	return nil
}

func snapshotCounters(opts snapshotOptions) error {
	if opts.RuntimeFile == "" {
		return fmt.Errorf("缺少 --runtime-file")
	}
	runtimeData, err := loadRuntime(opts.RuntimeFile)
	if err != nil {
		return err
	}
	type row struct {
		ID             string  `json:"id"`
		UserID         string  `json:"user_id"`
		TrafficMode    string  `json:"traffic_mode"`
		TrafficRatio   float64 `json:"traffic_ratio"`
		InputBytes     uint64  `json:"input_bytes"`
		OutputBytes    uint64  `json:"output_bytes"`
		InputPackets   uint64  `json:"input_packets"`
		OutputPackets  uint64  `json:"output_packets"`
		DroppedBytes   uint64  `json:"dropped_bytes"`
		DroppedPackets uint64  `json:"dropped_packets"`
	}
	rows := make([]row, 0, len(runtimeData.Rules))
	applied := false
	if opts.StatusFile != "" {
		payload, err := readStatus(opts.StatusFile)
		if err == nil {
			applied = payload.Applied
			if opts.RuleCounterPin == "" {
				opts.RuleCounterPin = payload.RuleCounterPin
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("读取 status 失败: %w", err)
		}
	}
	if opts.RuleCounterPin == "" {
		opts.RuleCounterPin = "/sys/fs/bpf/pfwd_rule_counters"
	}
	counterMap, err := ebpf.LoadPinnedMap(opts.RuleCounterPin, nil)
	if err != nil {
		if applied {
			return fmt.Errorf("读取 XDP 计数 map 失败 (%s): %w", opts.RuleCounterPin, err)
		}
		for _, rule := range runtimeData.Rules {
			rows = append(rows, row{ID: rule.ID, UserID: rule.UserID, TrafficMode: rule.TrafficMode, TrafficRatio: nonzeroRatio(rule.TrafficRatio)})
		}
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	defer counterMap.Close()
	for _, rule := range runtimeData.Rules {
		var counter counterVal
		_ = counterMap.Lookup(rule.Index, &counter)
		rows = append(rows, row{
			ID: rule.ID, UserID: rule.UserID, TrafficMode: rule.TrafficMode, TrafficRatio: nonzeroRatio(rule.TrafficRatio),
			InputBytes: counter.InputBytes, OutputBytes: counter.OutputBytes,
			InputPackets: counter.InputPackets, OutputPackets: counter.OutputPackets,
			DroppedBytes: counter.DroppedBytes, DroppedPackets: counter.DroppedPackets,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}

func dumpStats(opts statsOptions) error {
	if opts.StatusFile != "" {
		payload, err := readStatus(opts.StatusFile)
		if err == nil && opts.StatsPin == "" {
			opts.StatsPin = payload.StatsPin
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("读取 status 失败: %w", err)
		}
	}
	if opts.StatsPin == "" {
		opts.StatsPin = "/sys/fs/bpf/pfwd_stats"
	}
	statsMap, err := ebpf.LoadPinnedMap(opts.StatsPin, nil)
	if err != nil {
		return fmt.Errorf("读取 XDP stats map 失败 (%s): %w", opts.StatsPin, err)
	}
	defer statsMap.Close()

	var payload struct {
		Passed           uint64 `json:"passed"`
		Dropped          uint64 `json:"dropped"`
		Forwarded        uint64 `json:"forwarded"`
		QuotaDropped     uint64 `json:"quota_dropped"`
		WhitelistDropped uint64 `json:"whitelist_dropped"`
		ProtocolDropped  uint64 `json:"protocol_dropped"`
		ParseSkipped     uint64 `json:"parse_skipped"`
	}
	values := []*uint64{
		&payload.Passed,
		&payload.Dropped,
		&payload.Forwarded,
		&payload.QuotaDropped,
		&payload.WhitelistDropped,
		&payload.ProtocolDropped,
		&payload.ParseSkipped,
	}
	for i, dst := range values {
		key := uint32(i)
		total, err := lookupPerCPUUint64(statsMap, key)
		if err != nil {
			return fmt.Errorf("读取 XDP stats 失败 (key=%d): %w", key, err)
		}
		*dst = total
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func lookupPerCPUUint64(m *ebpf.Map, key uint32) (uint64, error) {
	var values []uint64
	if err := m.Lookup(&key, &values); err != nil {
		return 0, err
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return total, nil
}

func loadWhitelistFiles(mapV4 *ebpf.Map, mapV6 *ebpf.Map, files []string) error {
	for _, filePath := range files {
		filePath = strings.TrimSpace(filePath)
		if filePath == "" {
			continue
		}
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("打开白名单文件失败: %w", err)
		}
		scanner := bufio.NewScanner(file)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			prefix, err := netip.ParsePrefix(line)
			if err != nil {
				_ = file.Close()
				return fmt.Errorf("解析白名单失败 (%s:%d): %w", filePath, lineNo, err)
			}
			prefix = prefix.Masked()
			value := uint8(1)
			if prefix.Addr().Is4() {
				addr := prefix.Addr().As4()
				key := whitelistKeyV4{PrefixLen: uint32(prefix.Bits()), Addr: ipv4LPMTrieAddr(addr)}
				if err := mapV4.Update(&key, &value, ebpf.UpdateAny); err != nil {
					_ = file.Close()
					return fmt.Errorf("写入 IPv4 白名单失败: %w", err)
				}
			} else {
				key := whitelistKeyV6{PrefixLen: uint32(prefix.Bits()), Addr: prefix.Addr().As16()}
				if err := mapV6.Update(&key, &value, ebpf.UpdateAny); err != nil {
					_ = file.Close()
					return fmt.Errorf("写入 IPv6 白名单失败: %w", err)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}

func protocolNumber(value string) (uint8, error) {
	switch value {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	default:
		return 0, fmt.Errorf("无效协议：%s", value)
	}
}

func addrTo16(addr netip.Addr) [16]byte {
	if addr.Is4() {
		v4 := addr.As4()
		var out [16]byte
		copy(out[:4], v4[:])
		return out
	}
	return addr.As16()
}

func ipv4LPMTrieAddr(addr [4]byte) uint32 {
	// The XDP side looks up ip4->saddr directly, so the key bytes after prefixlen
	// must stay in network order when marshaled as a uint32 on little-endian hosts.
	return binary.LittleEndian.Uint32(addr[:])
}

func htons(value uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], value)
	return binary.LittleEndian.Uint16(b[:])
}

func boolToUint8(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func splitFiles(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ":")
	out := parts[:0]
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func nonzeroRatio(value float64) float64 {
	if value <= 0 {
		return 1
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func readStatus(filePath string) (statusPayload, error) {
	var payload statusPayload
	content, err := os.ReadFile(filePath)
	if err != nil {
		return payload, err
	}
	if err := json.Unmarshal(content, &payload); err != nil {
		return payload, err
	}
	return payload, nil
}

func writeStatus(filePath string, payload statusPayload) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(filePath), ".xdp-status-*.tmp")
	if err != nil {
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), filePath)
}

func removePinnedLink(pin string) error {
	if pin == "" {
		return nil
	}
	pinned, err := link.LoadPinnedLink(pin, nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		_ = os.Remove(pin)
		return nil
	}
	defer pinned.Close()
	_ = pinned.Unpin()
	return os.Remove(pin)
}

func removePinnedProgram(pin string) error {
	if pin == "" {
		return nil
	}
	prog, err := ebpf.LoadPinnedProgram(pin, nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		_ = os.Remove(pin)
		return nil
	}
	defer prog.Close()
	_ = prog.Unpin()
	return os.Remove(pin)
}

func runTC(args ...string) error {
	cmd := exec.Command("tc", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func usageError() error {
	printUsage(os.Stderr)
	return fmt.Errorf("缺少子命令")
}

func printUsage(file *os.File) {
	_, _ = fmt.Fprintln(file, "用法：")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp apply --runtime-file FILE --state-file FILE --status-file FILE --iface IFACE --xdp-mode off|auto|force --xdp-pin PATH --ingress-pin PATH [--rule-counter-pin PATH --user-counter-pin PATH --stats-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp remove --status-file FILE --xdp-pin PATH --ingress-pin PATH [--rule-counter-pin PATH --user-counter-pin PATH --stats-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp status --status-file FILE")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp snapshot --runtime-file FILE --state-file FILE [--status-file FILE --rule-counter-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp stats [--status-file FILE --stats-pin PATH]")
}
