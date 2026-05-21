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

const binaryVersion = "0.2.3"
const dataplaneVersion = 2
const mapABIVersion = 1
const ratioScale = uint64(1_000_000)
const maxRules = 4096
const maxUsers = 4096
const (
	ruleFlagXDPDisabled  = uint16(1 << 0)
	ruleFlagNeedsCounter = uint16(1 << 1)
	ruleFlagNeedsQuota   = uint16(1 << 2)
	ruleFlagNeedsGuard   = uint16(1 << 3)
	ruleFlagNeedsAllow   = uint16(1 << 4)
	ruleFlagSNATFixed    = uint16(1 << 5)
	ruleFlagMSSEnabled   = uint16(1 << 6)
)
const ruleCounterPinSuffix = "_rule_counters"
const tcPrefBPFIngress = "10"
const tcPrefBPFEgress = "10"
const connStateTCPSynPending = uint8(1)
const connStateTCPEstablished = uint8(2)
const statsEntryCount = 9

type bpfObjects struct {
	PFWDXDP              *ebpf.Program `ebpf:"pfwd_xdp"`
	PFWDIngress          *ebpf.Program `ebpf:"pfwd_ingress"`
	PFWDLoopbackEgress   *ebpf.Program `ebpf:"pfwd_loopback_egress"`
	PFWDSkLookup         *ebpf.Program `ebpf:"pfwd_sk_lookup"`
	PFWDSettings         *ebpf.Map     `ebpf:"pfwd_settings"`
	PFWDRules            *ebpf.Map     `ebpf:"pfwd_rules"`
	PFWDConnections      *ebpf.Map     `ebpf:"pfwd_connections"`
	PFWDReverse          *ebpf.Map     `ebpf:"pfwd_reverse"`
	PFWDRuleCounter      *ebpf.Map     `ebpf:"pfwd_rule_counters"`
	PFWDUserCounter      *ebpf.Map     `ebpf:"pfwd_user_counters"`
	PFWDStats            *ebpf.Map     `ebpf:"pfwd_stats"`
	PFWDWhitelistV4      *ebpf.Map     `ebpf:"pfwd_whitelist_v4"`
	PFWDWhitelistV6      *ebpf.Map     `ebpf:"pfwd_whitelist_v6"`
	PFWDWhitelistCacheV4 *ebpf.Map     `ebpf:"pfwd_whitelist_cache_v4"`
	PFWDWhitelistCacheV6 *ebpf.Map     `ebpf:"pfwd_whitelist_cache_v6"`
	PFWDFlows            *ebpf.Map     `ebpf:"pfwd_allowed_flows"`
	PFWDGuardPrefixes    *ebpf.Map     `ebpf:"pfwd_guard_prefixes"`
	PFWDSkipPorts        *ebpf.Map     `ebpf:"pfwd_protocol_skip_ports"`
	PFWDScratch          *ebpf.Map     `ebpf:"pfwd_scratch"`
}

func (o *bpfObjects) Close() {
	if o == nil {
		return
	}
	for _, closer := range []interface{ Close() error }{
		o.PFWDXDP, o.PFWDIngress, o.PFWDLoopbackEgress, o.PFWDSkLookup, o.PFWDSettings, o.PFWDRules, o.PFWDConnections, o.PFWDReverse,
		o.PFWDRuleCounter, o.PFWDUserCounter, o.PFWDStats, o.PFWDWhitelistV4, o.PFWDWhitelistV6,
		o.PFWDWhitelistCacheV4, o.PFWDWhitelistCacheV6, o.PFWDFlows, o.PFWDGuardPrefixes, o.PFWDSkipPorts, o.PFWDScratch,
	} {
		if closer != nil {
			_ = closer.Close()
		}
	}
}

type applyOptions struct {
	Iface          string
	GuardMode      string
	RuntimeFile    string
	StateFile      string
	StatusFile     string
	XDPPin         string
	IngressPin     string
	LoopbackPin    string
	SkLookupPin    string
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
	LoopbackPin    string
	SkLookupPin    string
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

type connSummary struct {
	Total          uint64 `json:"total"`
	TCPSynPending  uint64 `json:"tcp_syn_pending"`
	TCPEstablished uint64 `json:"tcp_established"`
	UDP            uint64 `json:"udp"`
}

type runtimeFile struct {
	Rules            []runtimeRule     `json:"rules"`
	Users            []runtimeUser     `json:"users"`
	Settings         runtimeSettings   `json:"settings"`
	Generated        string            `json:"generated_at,omitempty"`
	DataplaneVersion int               `json:"dataplane_version,omitempty"`
	MapABIVersion    int               `json:"map_abi_version,omitempty"`
	Summary          runtimeSummary    `json:"summary,omitempty"`
	RuleIndex        map[string]uint32 `json:"rule_index,omitempty"`
	UserIndex        map[string]uint32 `json:"user_index,omitempty"`
	ConfigHash       string            `json:"config_hash,omitempty"`
}

type runtimeSummary struct {
	ProfileCounts map[string]int `json:"profile_counts,omitempty"`
}

type whitelistContentHash struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

type runtimeSemanticSettings struct {
	Interface         string   `json:"interface"`
	GuardEnabled      bool     `json:"guard_enabled"`
	WhitelistEnabled  bool     `json:"whitelist_enabled"`
	BlockHTTP         bool     `json:"block_http"`
	BlockTLS          bool     `json:"block_tls"`
	BlockSOCKS        bool     `json:"block_socks"`
	ProtocolSkipPorts []uint16 `json:"protocol_skip_ports,omitempty"`
	GuardIngressMode  string   `json:"guard_ingress_mode,omitempty"`
}

type runtimeSemanticRule struct {
	Index               uint32  `json:"index"`
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
	BillingUsedBase     uint64  `json:"billing_used_base_bytes,omitempty"`
	UserBillingUsedBase uint64  `json:"user_billing_used_base_bytes,omitempty"`
	XDPDisabled         bool    `json:"xdp_disabled,omitempty"`
}

type runtimeSettings struct {
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
}

type statusPayload struct {
	Applied                bool           `json:"applied"`
	BinaryVersion          string         `json:"binary_version"`
	AppliedAt              string         `json:"applied_at,omitempty"`
	Interface              string         `json:"interface,omitempty"`
	InterfaceIndex         int            `json:"interface_index,omitempty"`
	GuardMode              string         `json:"guard_mode,omitempty"`
	XDPEffective           string         `json:"xdp_effective,omitempty"`
	XDPAttachKind          string         `json:"xdp_attach_kind,omitempty"`
	XDPReason              string         `json:"xdp_reason,omitempty"`
	IngressKind            string         `json:"ingress_kind,omitempty"`
	LoopbackKind           string         `json:"loopback_kind,omitempty"`
	SkLookupKind           string         `json:"sk_lookup_kind,omitempty"`
	ProtocolGuard          bool           `json:"protocol_guard,omitempty"`
	RuntimeFile            string         `json:"runtime_file,omitempty"`
	StateFile              string         `json:"state_file,omitempty"`
	ConfigHash             string         `json:"config_hash,omitempty"`
	RuntimeEpoch           string         `json:"runtime_epoch,omitempty"`
	DataplaneVersion       int            `json:"dataplane_version,omitempty"`
	MapABIVersion          int            `json:"map_abi_version,omitempty"`
	IncrementalApply       bool           `json:"incremental_apply,omitempty"`
	ReattachReason         string         `json:"reattach_reason,omitempty"`
	PreservedConnections   uint64         `json:"preserved_connections,omitempty"`
	InvalidatedConnections uint64         `json:"invalidated_connections,omitempty"`
	ProfileCounts          map[string]int `json:"profile_counts,omitempty"`
	Rules                  int            `json:"rules,omitempty"`
	Users                  int            `json:"users,omitempty"`
	XDPPin                 string         `json:"xdp_pin,omitempty"`
	IngressPin             string         `json:"ingress_pin,omitempty"`
	LoopbackPin            string         `json:"loopback_pin,omitempty"`
	SkLookupPin            string         `json:"sk_lookup_pin,omitempty"`
	RuleCounterPin         string         `json:"rule_counter_pin,omitempty"`
	UserCounterPin         string         `json:"user_counter_pin,omitempty"`
	StatsPin               string         `json:"stats_pin,omitempty"`
	ActiveSummary          *connSummary   `json:"active_summary,omitempty"`
	RefreshReport          *refreshReport `json:"refresh_report,omitempty"`
}

type refreshReport struct {
	Mode                    string `json:"mode"`
	Reason                  string `json:"reason,omitempty"`
	StartedAt               string `json:"started_at,omitempty"`
	CompletedAt             string `json:"completed_at,omitempty"`
	TotalDurationMillis     int64  `json:"total_duration_ms"`
	LoadDurationMillis      int64  `json:"load_duration_ms"`
	MapLoadDurationMillis   int64  `json:"map_load_duration_ms"`
	ReconcileDurationMillis int64  `json:"reconcile_duration_ms"`
	StatusDurationMillis    int64  `json:"status_duration_ms"`
	PreservedConnections    uint64 `json:"preserved_connections"`
	InvalidatedConnections  uint64 `json:"invalidated_connections"`
	RulesAdded              uint64 `json:"rules_added"`
	RulesUpdated            uint64 `json:"rules_updated"`
	RulesDeleted            uint64 `json:"rules_deleted"`
	UsersAdded              uint64 `json:"users_added"`
	UsersUpdated            uint64 `json:"users_updated"`
	UsersDeleted            uint64 `json:"users_deleted"`
	CountersPreserved       uint64 `json:"counters_preserved"`
	CountersReset           uint64 `json:"counters_reset"`
	Rules                   int    `json:"rules"`
	Users                   int    `json:"users"`
}

type mapReconcileReport struct {
	RulesAdded        uint64
	RulesUpdated      uint64
	RulesDeleted      uint64
	UsersAdded        uint64
	UsersUpdated      uint64
	UsersDeleted      uint64
	CountersPreserved uint64
	CountersReset     uint64
}

type runtimeMapPins struct {
	Settings         string
	Rules            string
	Connections      string
	Reverse          string
	RuleCounter      string
	UserCounter      string
	Stats            string
	WhitelistV4      string
	WhitelistV6      string
	WhitelistCacheV4 string
	WhitelistCacheV6 string
	AllowedFlows     string
	GuardPrefixes    string
	SkipPorts        string
}

type xdpSettings struct {
	WhitelistEnabled uint8
	BlockHTTP        uint8
	BlockTLS         uint8
	BlockSOCKS       uint8
	GuardEnabled     uint8
	HasSkipPorts     uint8
	Pad              [2]uint8
	ExternalIfindex  uint32
	LoopbackIfindex  uint32
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
	UserLimitEnabled         uint8
	BillingEnabled           uint8
	Pad                      [5]uint8
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

func (c *counterVal) add(other counterVal) {
	c.InputBytes += other.InputBytes
	c.OutputBytes += other.OutputBytes
	c.InputPackets += other.InputPackets
	c.OutputPackets += other.OutputPackets
	c.DroppedBytes += other.DroppedBytes
	c.DroppedPackets += other.DroppedPackets
	c.BillingBytes += other.BillingBytes
}

type snapshotRow struct {
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

type connKey struct {
	Family     uint8
	Protocol   uint8
	ClientPort uint16
	ListenPort uint16
	TargetPort uint16
	ClientAddr [16]byte
	ListenAddr [16]byte
	TargetAddr [16]byte
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
	UserLimitEnabled   uint8
	BillingEnabled     uint8
	State              uint8
	Pad8               [4]uint8
	Packets            uint64
	Bytes              uint64
}

type reverseKey struct {
	Family     uint8
	Protocol   uint8
	SourcePort uint16
	TargetPort uint16
	ClientPort uint16
	SourceAddr [16]byte
	TargetAddr [16]byte
	ClientAddr [16]byte
}

type whitelistKeyV4 struct {
	PrefixLen uint32
	Addr      uint32
}

type whitelistKeyV6 struct {
	PrefixLen uint32
	Addr      [16]byte
}

type whitelistCacheKeyV6 struct {
	Addr [16]byte
}

type portKey struct {
	Port uint16
	Pad  [4]byte
}

type flowKey struct {
	Family   uint8
	Protocol uint8
	Sport    uint16
	Dport    uint16
	Saddr    [16]byte
	Daddr    [16]byte
}

type guardPrefixVal struct {
	SeenLen uint8
	Pad     [7]byte
	Prefix  [8]byte
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
	fs.StringVar(&opts.GuardMode, "guard-mode", "full", "off|ingress|full")
	fs.StringVar(&opts.RuntimeFile, "runtime-file", "", "runtime json")
	fs.StringVar(&opts.StateFile, "state-file", "", "state json")
	fs.StringVar(&opts.StatusFile, "status-file", "", "status json")
	fs.StringVar(&opts.XDPPin, "xdp-pin", "", "bpffs xdp link pin")
	fs.StringVar(&opts.IngressPin, "ingress-pin", "", "bpffs ingress link pin")
	fs.StringVar(&opts.LoopbackPin, "loopback-pin", "", "bpffs loopback egress link pin")
	fs.StringVar(&opts.SkLookupPin, "sk-lookup-pin", "", "bpffs sk_lookup link pin")
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
	fs.StringVar(&opts.LoopbackPin, "loopback-pin", "", "bpffs loopback egress link pin")
	fs.StringVar(&opts.SkLookupPin, "sk-lookup-pin", "", "bpffs sk_lookup link pin")
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
	if payload.Applied {
		if summary, err := loadConnectionSummaryFromStatus(payload); err == nil {
			payload.ActiveSummary = summary
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
	if opts.GuardMode == "" {
		opts.GuardMode = "full"
	}
	if opts.Iface == "" && opts.GuardMode != "off" {
		return fmt.Errorf("缺少 --iface")
	}
	switch opts.GuardMode {
	case "off", "ingress", "full":
	default:
		return fmt.Errorf("无效 guard-mode：%s", opts.GuardMode)
	}
	if opts.GuardMode == "full" && opts.XDPPin == "" {
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
	if opts.GuardMode == "off" {
		if err := removeRuntime(removeOptions{
			StatusFile:     opts.StatusFile,
			XDPPin:         opts.XDPPin,
			IngressPin:     opts.IngressPin,
			LoopbackPin:    opts.LoopbackPin,
			SkLookupPin:    opts.SkLookupPin,
			RuleCounterPin: opts.RuleCounterPin,
			UserCounterPin: opts.UserCounterPin,
			StatsPin:       opts.StatsPin,
		}); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("清理旧运行态失败: %w", err)
		}
		payload := statusPayload{Applied: false, BinaryVersion: binaryVersion, GuardMode: opts.GuardMode, RuntimeFile: opts.RuntimeFile, StateFile: opts.StateFile}
		return writeStatus(opts.StatusFile, payload)
	}
	iface, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return fmt.Errorf("查找网卡 %q 失败: %w", opts.Iface, err)
	}
	currentStatus, _ := readStatus(opts.StatusFile)
	protocolGuard := protocolGuardEnabled(runtimeData.Settings)
	needIngress := opts.GuardMode == "ingress" || (protocolGuard && guardIngressEnabled(runtimeData.Settings))
	runtimeSemanticConfigHash, err := runtimeSemanticHash(runtimeData)
	if err != nil {
		return err
	}
	if currentStatus.Applied &&
		currentStatus.BinaryVersion == binaryVersion &&
		currentStatus.ConfigHash == runtimeSemanticConfigHash &&
		currentStatus.GuardMode == opts.GuardMode &&
		currentStatus.Interface == iface.Name &&
		pinnedRuntimeMapsCompatible(opts) {
		return nil
	}
	if canIncrementalApply(currentStatus, runtimeData, opts, iface, needIngress) {
		if err := applyIncrementalRuntime(currentStatus, runtimeData, opts, iface, protocolGuard); err == nil {
			return nil
		} else if !opts.Quiet {
			fmt.Fprintf(os.Stderr, "pfwd-xdp: incremental apply 失败，回退到 full reattach: %v\n", err)
		}
	}
	fullStartedAt := time.Now().UTC()
	fullStartedAtText := fullStartedAt.Format(time.RFC3339)
	if err := removeRuntime(removeOptions{
		StatusFile:     opts.StatusFile,
		XDPPin:         opts.XDPPin,
		IngressPin:     opts.IngressPin,
		LoopbackPin:    opts.LoopbackPin,
		SkLookupPin:    opts.SkLookupPin,
		RuleCounterPin: opts.RuleCounterPin,
		UserCounterPin: opts.UserCounterPin,
		StatsPin:       opts.StatsPin,
	}); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("清理旧运行态失败: %w", err)
	}
	objs, err := loadObjects(opts.GuardMode)
	if err != nil {
		return err
	}
	defer objs.Close()
	mapLoadStart := time.Now()
	if err := loadMaps(objs, runtimeData, opts); err != nil {
		return err
	}
	mapLoadDuration := elapsedMillis(mapLoadStart)
	if err := pinRuntimeMaps(objs, opts); err != nil {
		return err
	}
	xdpEffective := "disabled"
	xdpKind := ""
	xdpReason := ""
	if opts.GuardMode == "full" {
		xdpEffective, xdpKind, xdpReason, err = attachXDP(iface, objs.PFWDXDP, opts)
		if err != nil {
			return err
		}
	} else if err := removeXDPLink(opts.XDPPin); err != nil {
		return err
	}
	ingressKind := ""
	if needIngress {
		ingressKind, err = attachIngress(iface, objs.PFWDIngress, opts.IngressPin)
		if err != nil {
			return err
		}
	} else if err := removeIngressRuntime(opts.IngressPin, iface.Name); err != nil {
		return err
	}
	loopbackKind := ""
	skLookupKind := ""
	if err := removeSkLookupRuntime(opts.SkLookupPin); err != nil {
		return err
	}
	if err := removeLoopbackRuntime(opts.LoopbackPin, "lo"); err != nil {
		return err
	}
	if ingressKind != "" && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "pfwd-xdp: tc ingress attached via %s\n", ingressKind)
	}
	if loopbackKind != "" && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "pfwd-xdp: loopback egress attached via %s\n", loopbackKind)
	}
	if skLookupKind != "" && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "pfwd-xdp: sk_lookup attached via %s\n", skLookupKind)
	}
	statusStart := time.Now()
	payload := statusPayload{
		Applied:          true,
		BinaryVersion:    binaryVersion,
		AppliedAt:        time.Now().UTC().Format(time.RFC3339),
		Interface:        iface.Name,
		InterfaceIndex:   iface.Index,
		GuardMode:        opts.GuardMode,
		XDPEffective:     xdpEffective,
		XDPAttachKind:    xdpKind,
		XDPReason:        xdpReason,
		IngressKind:      ingressKind,
		LoopbackKind:     loopbackKind,
		SkLookupKind:     skLookupKind,
		ProtocolGuard:    protocolGuard,
		RuntimeFile:      opts.RuntimeFile,
		StateFile:        opts.StateFile,
		ConfigHash:       runtimeSemanticConfigHash,
		RuntimeEpoch:     runtimeSemanticConfigHash,
		DataplaneVersion: dataplaneVersion,
		MapABIVersion:    mapABIVersion,
		IncrementalApply: false,
		ReattachReason:   "full-reattach",
		ProfileCounts:    profileCounts(runtimeData),
		Rules:            len(runtimeData.Rules),
		Users:            len(runtimeData.Users),
		XDPPin:           opts.XDPPin,
		IngressPin:       opts.IngressPin,
		LoopbackPin:      opts.LoopbackPin,
		SkLookupPin:      opts.SkLookupPin,
		RuleCounterPin:   opts.RuleCounterPin,
		UserCounterPin:   opts.UserCounterPin,
		StatsPin:         opts.StatsPin,
	}
	if summary, err := summarizeConnections(objs.PFWDConnections); err == nil {
		payload.ActiveSummary = summary
	}
	payload.RefreshReport = &refreshReport{
		Mode:                  "full-reattach",
		Reason:                payload.ReattachReason,
		StartedAt:             fullStartedAtText,
		CompletedAt:           time.Now().UTC().Format(time.RFC3339),
		TotalDurationMillis:   elapsedMillis(fullStartedAt),
		MapLoadDurationMillis: mapLoadDuration,
		StatusDurationMillis:  elapsedMillis(statusStart),
		Rules:                 len(runtimeData.Rules),
		Users:                 len(runtimeData.Users),
	}
	return writeStatus(opts.StatusFile, payload)
}

func loadObjects(guardMode string) (*bpfObjects, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpBPFEL))
	if err != nil {
		return nil, fmt.Errorf("加载 eBPF spec 失败: %w", err)
	}
	delete(spec.Programs, "pfwd_loopback_egress")
	delete(spec.Programs, "pfwd_sk_lookup")
	if guardMode != "full" {
		delete(spec.Programs, "pfwd_xdp")
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch},
	})
	if err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			return nil, fmt.Errorf("加载 eBPF 对象失败: %+v", verifierErr)
		}
		return nil, fmt.Errorf("加载 eBPF 对象失败: %+v", err)
	}
	objs := &bpfObjects{
		PFWDXDP:              coll.Programs["pfwd_xdp"],
		PFWDIngress:          coll.Programs["pfwd_ingress"],
		PFWDLoopbackEgress:   coll.Programs["pfwd_loopback_egress"],
		PFWDSkLookup:         coll.Programs["pfwd_sk_lookup"],
		PFWDSettings:         coll.Maps["pfwd_settings"],
		PFWDRules:            coll.Maps["pfwd_rules"],
		PFWDConnections:      coll.Maps["pfwd_connections"],
		PFWDReverse:          coll.Maps["pfwd_reverse"],
		PFWDRuleCounter:      coll.Maps["pfwd_rule_counters"],
		PFWDUserCounter:      coll.Maps["pfwd_user_counters"],
		PFWDStats:            coll.Maps["pfwd_stats"],
		PFWDWhitelistV4:      coll.Maps["pfwd_whitelist_v4"],
		PFWDWhitelistV6:      coll.Maps["pfwd_whitelist_v6"],
		PFWDWhitelistCacheV4: coll.Maps["pfwd_whitelist_cache_v4"],
		PFWDWhitelistCacheV6: coll.Maps["pfwd_whitelist_cache_v6"],
		PFWDFlows:            coll.Maps["pfwd_allowed_flows"],
		PFWDGuardPrefixes:    coll.Maps["pfwd_guard_prefixes"],
		PFWDSkipPorts:        coll.Maps["pfwd_protocol_skip_ports"],
		PFWDScratch:          coll.Maps["pfwd_scratch"],
	}
	return objs, nil
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
	if runtimeData.DataplaneVersion != 0 && runtimeData.DataplaneVersion != dataplaneVersion {
		return nil, fmt.Errorf("不支持的 dataplane_version：%d", runtimeData.DataplaneVersion)
	}
	if runtimeData.MapABIVersion != 0 && runtimeData.MapABIVersion != mapABIVersion {
		return nil, fmt.Errorf("不支持的 map_abi_version：%d", runtimeData.MapABIVersion)
	}
	return &runtimeData, nil
}

func runtimeSemanticHash(runtimeData *runtimeFile) (string, error) {
	if runtimeData == nil {
		return "", fmt.Errorf("runtime 为空")
	}
	hashes, err := whitelistFileHashes(runtimeData.Settings.WhitelistFiles)
	if err != nil {
		return "", err
	}
	settings := runtimeSemanticSettings{
		Interface:         runtimeData.Settings.Interface,
		GuardEnabled:      runtimeData.Settings.GuardEnabled,
		WhitelistEnabled:  runtimeData.Settings.WhitelistEnabled,
		BlockHTTP:         runtimeData.Settings.BlockHTTP,
		BlockTLS:          runtimeData.Settings.BlockTLS,
		BlockSOCKS:        runtimeData.Settings.BlockSOCKS,
		ProtocolSkipPorts: runtimeData.Settings.ProtocolSkipPorts,
		GuardIngressMode:  runtimeData.Settings.GuardIngressMode,
	}
	rules := make([]runtimeSemanticRule, 0, len(runtimeData.Rules))
	for _, rule := range runtimeData.Rules {
		semanticRule := runtimeSemanticRule{
			Index:          rule.Index,
			UserIndex:      rule.UserIndex,
			ListenIP:       rule.ListenIP,
			ListenPort:     rule.ListenPort,
			Protocol:       rule.Protocol,
			IPVersion:      rule.IPVersion,
			ResolvedTarget: rule.ResolvedTarget,
			RemotePort:     rule.RemotePort,
			SNATMode:       rule.SNATMode,
			SNATSource:     rule.SNATSource,
			MSSMode:        rule.MSSMode,
			MSSValue:       rule.MSSValue,
			TrafficMode:    rule.TrafficMode,
			TrafficRatio:   rule.TrafficRatio,
			RuleLimit:      rule.RuleLimit,
			UserLimit:      rule.UserLimit,
			XDPDisabled:    rule.XDPDisabled,
		}
		if rule.RuleLimit > 0 || rule.UserLimit > 0 {
			semanticRule.BillingUsedBase = rule.BillingUsedBase
			semanticRule.UserBillingUsedBase = rule.UserBillingUsedBase
		}
		rules = append(rules, semanticRule)
	}
	payload := struct {
		Settings        runtimeSemanticSettings `json:"settings"`
		Rules           []runtimeSemanticRule   `json:"rules"`
		WhitelistHashes []whitelistContentHash  `json:"whitelist_hashes"`
	}{
		Settings:        settings,
		Rules:           rules,
		WhitelistHashes: hashes,
	}
	content, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("序列化 runtime 语义 hash 失败: %w", err)
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}

func runtimePinNamespace(ruleCounterPin string) string {
	base := filepath.Base(strings.TrimSpace(ruleCounterPin))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "pfwd"
	}
	if strings.HasSuffix(base, ruleCounterPinSuffix) {
		base = strings.TrimSuffix(base, ruleCounterPinSuffix)
	}
	base = strings.Trim(base, "_- ")
	if base == "" {
		return "pfwd"
	}
	return base
}

func runtimeMapPinsFromPaths(ruleCounterPin, userCounterPin, statsPin string) runtimeMapPins {
	dir := filepath.Dir(ruleCounterPin)
	namespace := runtimePinNamespace(ruleCounterPin)
	return runtimeMapPins{
		Settings:         filepath.Join(dir, namespace+"_settings"),
		Rules:            filepath.Join(dir, namespace+"_rules"),
		Connections:      filepath.Join(dir, namespace+"_connections"),
		Reverse:          filepath.Join(dir, namespace+"_reverse"),
		RuleCounter:      ruleCounterPin,
		UserCounter:      userCounterPin,
		Stats:            statsPin,
		WhitelistV4:      filepath.Join(dir, namespace+"_whitelist_v4"),
		WhitelistV6:      filepath.Join(dir, namespace+"_whitelist_v6"),
		WhitelistCacheV4: filepath.Join(dir, namespace+"_whitelist_cache_v4"),
		WhitelistCacheV6: filepath.Join(dir, namespace+"_whitelist_cache_v6"),
		AllowedFlows:     filepath.Join(dir, namespace+"_allowed_flows"),
		GuardPrefixes:    filepath.Join(dir, namespace+"_guard_prefixes"),
		SkipPorts:        filepath.Join(dir, namespace+"_protocol_skip_ports"),
	}
}

func runtimeMapPinsFromApplyOptions(opts applyOptions) runtimeMapPins {
	return runtimeMapPinsFromPaths(opts.RuleCounterPin, opts.UserCounterPin, opts.StatsPin)
}

func runtimeMapPinsFromRemoveOptions(opts removeOptions, payload statusPayload) runtimeMapPins {
	ruleCounterPin := firstNonEmpty(opts.RuleCounterPin, payload.RuleCounterPin, "/sys/fs/bpf/pfwd_rule_counters")
	userCounterPin := firstNonEmpty(opts.UserCounterPin, payload.UserCounterPin, "/sys/fs/bpf/pfwd_user_counters")
	statsPin := firstNonEmpty(opts.StatsPin, payload.StatsPin, "/sys/fs/bpf/pfwd_stats")
	return runtimeMapPinsFromPaths(ruleCounterPin, userCounterPin, statsPin)
}

func zeroPerCPUCounterValues() ([]counterVal, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("获取 PossibleCPU 失败: %w", err)
	}
	return make([]counterVal, cpus), nil
}

func loadMaps(objs *bpfObjects, runtimeData *runtimeFile, opts applyOptions) error {
	if objs.PFWDSettings == nil || objs.PFWDRules == nil || objs.PFWDRuleCounter == nil || objs.PFWDUserCounter == nil {
		return fmt.Errorf("关键 BPF map 未加载")
	}
	var externalIfindex uint32
	if opts.Iface != "" {
		iface, err := net.InterfaceByName(opts.Iface)
		if err != nil {
			return fmt.Errorf("查找外部网卡失败: %w", err)
		}
		externalIfindex = uint32(iface.Index)
	}
	settings := xdpSettings{
		WhitelistEnabled: boolToUint8(runtimeData.Settings.WhitelistEnabled),
		BlockHTTP:        boolToUint8(runtimeData.Settings.BlockHTTP),
		BlockTLS:         boolToUint8(runtimeData.Settings.BlockTLS),
		BlockSOCKS:       boolToUint8(runtimeData.Settings.BlockSOCKS),
		GuardEnabled:     boolToUint8(runtimeData.Settings.GuardEnabled),
		HasSkipPorts:     boolToUint8(len(runtimeData.Settings.ProtocolSkipPorts) > 0),
		ExternalIfindex:  externalIfindex,
		LoopbackIfindex:  0,
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
	zeroCounter, err := zeroPerCPUCounterValues()
	if err != nil {
		return err
	}
	for _, user := range runtimeData.Users {
		if err := objs.PFWDUserCounter.Update(&user.Index, zeroCounter, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("初始化用户计数失败 (%s): %w", user.ID, err)
		}
	}
	for _, rule := range runtimeData.Rules {
		if err := putRule(objs, rule, runtimeData.Settings); err != nil {
			return err
		}
	}
	return nil
}

func pinRuntimeMaps(objs *bpfObjects, opts applyOptions) error {
	pinLayout := runtimeMapPinsFromApplyOptions(opts)
	pins := map[string]*ebpf.Map{
		pinLayout.Settings:         objs.PFWDSettings,
		pinLayout.Rules:            objs.PFWDRules,
		pinLayout.Connections:      objs.PFWDConnections,
		pinLayout.Reverse:          objs.PFWDReverse,
		pinLayout.RuleCounter:      objs.PFWDRuleCounter,
		pinLayout.UserCounter:      objs.PFWDUserCounter,
		pinLayout.Stats:            objs.PFWDStats,
		pinLayout.WhitelistV4:      objs.PFWDWhitelistV4,
		pinLayout.WhitelistV6:      objs.PFWDWhitelistV6,
		pinLayout.WhitelistCacheV4: objs.PFWDWhitelistCacheV4,
		pinLayout.WhitelistCacheV6: objs.PFWDWhitelistCacheV6,
		pinLayout.AllowedFlows:     objs.PFWDFlows,
		pinLayout.GuardPrefixes:    objs.PFWDGuardPrefixes,
		pinLayout.SkipPorts:        objs.PFWDSkipPorts,
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

func loadPinnedRuntimeMaps(pinLayout runtimeMapPins) (*bpfObjects, error) {
	load := func(path string) (*ebpf.Map, error) {
		return ebpf.LoadPinnedMap(path, nil)
	}
	settings, err := load(pinLayout.Settings)
	if err != nil {
		return nil, fmt.Errorf("加载 pinned settings map 失败: %w", err)
	}
	rules, err := load(pinLayout.Rules)
	if err != nil {
		settings.Close()
		return nil, fmt.Errorf("加载 pinned rules map 失败: %w", err)
	}
	connections, err := load(pinLayout.Connections)
	if err != nil {
		settings.Close()
		rules.Close()
		return nil, fmt.Errorf("加载 pinned connections map 失败: %w", err)
	}
	reverse, err := load(pinLayout.Reverse)
	if err != nil {
		settings.Close()
		rules.Close()
		connections.Close()
		return nil, fmt.Errorf("加载 pinned reverse map 失败: %w", err)
	}
	ruleCounter, err := load(pinLayout.RuleCounter)
	if err != nil {
		settings.Close()
		rules.Close()
		connections.Close()
		reverse.Close()
		return nil, fmt.Errorf("加载 pinned rule counter map 失败: %w", err)
	}
	userCounter, err := load(pinLayout.UserCounter)
	if err != nil {
		settings.Close()
		rules.Close()
		connections.Close()
		reverse.Close()
		ruleCounter.Close()
		return nil, fmt.Errorf("加载 pinned user counter map 失败: %w", err)
	}
	stats, err := load(pinLayout.Stats)
	if err != nil {
		settings.Close()
		rules.Close()
		connections.Close()
		reverse.Close()
		ruleCounter.Close()
		userCounter.Close()
		return nil, fmt.Errorf("加载 pinned stats map 失败: %w", err)
	}
	whitelistV4, err := load(pinLayout.WhitelistV4)
	if err != nil {
		return closePinnedMapsOnError(settings, rules, connections, reverse, ruleCounter, userCounter, stats, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("加载 pinned whitelist_v4 map 失败: %w", err))
	}
	whitelistV6, err := load(pinLayout.WhitelistV6)
	if err != nil {
		return closePinnedMapsOnError(settings, rules, connections, reverse, ruleCounter, userCounter, stats, whitelistV4, nil, nil, nil, nil, nil, nil, fmt.Errorf("加载 pinned whitelist_v6 map 失败: %w", err))
	}
	whitelistCacheV4, err := load(pinLayout.WhitelistCacheV4)
	if err != nil {
		return closePinnedMapsOnError(settings, rules, connections, reverse, ruleCounter, userCounter, stats, whitelistV4, whitelistV6, nil, nil, nil, nil, nil, fmt.Errorf("加载 pinned whitelist_cache_v4 map 失败: %w", err))
	}
	whitelistCacheV6, err := load(pinLayout.WhitelistCacheV6)
	if err != nil {
		return closePinnedMapsOnError(settings, rules, connections, reverse, ruleCounter, userCounter, stats, whitelistV4, whitelistV6, whitelistCacheV4, nil, nil, nil, nil, fmt.Errorf("加载 pinned whitelist_cache_v6 map 失败: %w", err))
	}
	allowedFlows, err := load(pinLayout.AllowedFlows)
	if err != nil {
		return closePinnedMapsOnError(settings, rules, connections, reverse, ruleCounter, userCounter, stats, whitelistV4, whitelistV6, whitelistCacheV4, whitelistCacheV6, nil, nil, nil, fmt.Errorf("加载 pinned allowed_flows map 失败: %w", err))
	}
	guardPrefixes, err := load(pinLayout.GuardPrefixes)
	if err != nil {
		return closePinnedMapsOnError(settings, rules, connections, reverse, ruleCounter, userCounter, stats, whitelistV4, whitelistV6, whitelistCacheV4, whitelistCacheV6, allowedFlows, nil, nil, fmt.Errorf("加载 pinned guard_prefixes map 失败: %w", err))
	}
	skipPorts, err := load(pinLayout.SkipPorts)
	if err != nil {
		return closePinnedMapsOnError(settings, rules, connections, reverse, ruleCounter, userCounter, stats, whitelistV4, whitelistV6, whitelistCacheV4, whitelistCacheV6, allowedFlows, guardPrefixes, nil, fmt.Errorf("加载 pinned skip_ports map 失败: %w", err))
	}
	return &bpfObjects{
		PFWDSettings:         settings,
		PFWDRules:            rules,
		PFWDConnections:      connections,
		PFWDReverse:          reverse,
		PFWDRuleCounter:      ruleCounter,
		PFWDUserCounter:      userCounter,
		PFWDStats:            stats,
		PFWDWhitelistV4:      whitelistV4,
		PFWDWhitelistV6:      whitelistV6,
		PFWDWhitelistCacheV4: whitelistCacheV4,
		PFWDWhitelistCacheV6: whitelistCacheV6,
		PFWDFlows:            allowedFlows,
		PFWDGuardPrefixes:    guardPrefixes,
		PFWDSkipPorts:        skipPorts,
	}, nil
}

func closePinnedMapsOnError(settings, rules, connections, reverse, ruleCounter, userCounter, stats, whitelistV4, whitelistV6, whitelistCacheV4, whitelistCacheV6, allowedFlows, guardPrefixes, skipPorts *ebpf.Map, err error) (*bpfObjects, error) {
	for _, m := range []*ebpf.Map{settings, rules, connections, reverse, ruleCounter, userCounter, stats, whitelistV4, whitelistV6, whitelistCacheV4, whitelistCacheV6, allowedFlows, guardPrefixes, skipPorts} {
		if m != nil {
			_ = m.Close()
		}
	}
	return nil, err
}

func clearMap[K comparable, V any](m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	it := m.Iterate()
	var key K
	var value V
	for it.Next(&key, &value) {
		keyCopy := key
		if err := m.Delete(&keyCopy); err != nil {
			return fmt.Errorf("删除 map entry 失败: %w", err)
		}
	}
	return it.Err()
}

func clearPerCPUCounterMap(m *ebpf.Map, maxEntries uint32) error {
	if m == nil {
		return nil
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("获取 PossibleCPU 失败: %w", err)
	}
	zero := make([]counterVal, cpus)
	for i := uint32(0); i < maxEntries; i++ {
		key := i
		if err := m.Update(&key, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("重置 percpu counter 失败 (key=%d): %w", i, err)
		}
	}
	return nil
}

func clearPerCPUStatsMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("获取 PossibleCPU 失败: %w", err)
	}
	zero := make([]uint64, cpus)
	for i := uint32(0); i < statsEntryCount; i++ {
		key := i
		if err := m.Update(&key, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("重置 percpu stats 失败 (key=%d): %w", i, err)
		}
	}
	return nil
}

func clearRuntimeMaps(objs *bpfObjects) error {
	if err := clearMap[ruleKey, ruleVal](objs.PFWDRules); err != nil {
		return err
	}
	if err := clearMap[connKey, connVal](objs.PFWDConnections); err != nil {
		return err
	}
	if err := clearMap[reverseKey, connVal](objs.PFWDReverse); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV4, uint8](objs.PFWDWhitelistV4); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV6, uint8](objs.PFWDWhitelistV6); err != nil {
		return err
	}
	if err := clearMap[uint32, uint8](objs.PFWDWhitelistCacheV4); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV6, uint8](objs.PFWDWhitelistCacheV6); err != nil {
		return err
	}
	if err := clearMap[flowKey, uint8](objs.PFWDFlows); err != nil {
		return err
	}
	if err := clearMap[flowKey, guardPrefixVal](objs.PFWDGuardPrefixes); err != nil {
		return err
	}
	if err := clearMap[portKey, uint8](objs.PFWDSkipPorts); err != nil {
		return err
	}
	if err := clearPerCPUCounterMap(objs.PFWDRuleCounter, maxRules); err != nil {
		return err
	}
	if err := clearPerCPUCounterMap(objs.PFWDUserCounter, maxUsers); err != nil {
		return err
	}
	if err := clearPerCPUStatsMap(objs.PFWDStats); err != nil {
		return err
	}
	return nil
}

func clearMutableConfigMaps(objs *bpfObjects) error {
	if err := clearMap[ruleKey, ruleVal](objs.PFWDRules); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV4, uint8](objs.PFWDWhitelistV4); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV6, uint8](objs.PFWDWhitelistV6); err != nil {
		return err
	}
	if err := clearMap[uint32, uint8](objs.PFWDWhitelistCacheV4); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV6, uint8](objs.PFWDWhitelistCacheV6); err != nil {
		return err
	}
	if err := clearMap[flowKey, uint8](objs.PFWDFlows); err != nil {
		return err
	}
	if err := clearMap[flowKey, guardPrefixVal](objs.PFWDGuardPrefixes); err != nil {
		return err
	}
	if err := clearMap[portKey, uint8](objs.PFWDSkipPorts); err != nil {
		return err
	}
	if err := clearPerCPUCounterMap(objs.PFWDRuleCounter, maxRules); err != nil {
		return err
	}
	if err := clearPerCPUCounterMap(objs.PFWDUserCounter, maxUsers); err != nil {
		return err
	}
	return nil
}

func clearIncrementalAuxMaps(objs *bpfObjects) error {
	if err := clearMap[whitelistKeyV4, uint8](objs.PFWDWhitelistV4); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV6, uint8](objs.PFWDWhitelistV6); err != nil {
		return err
	}
	if err := clearMap[uint32, uint8](objs.PFWDWhitelistCacheV4); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV6, uint8](objs.PFWDWhitelistCacheV6); err != nil {
		return err
	}
	if err := clearMap[flowKey, uint8](objs.PFWDFlows); err != nil {
		return err
	}
	if err := clearMap[flowKey, guardPrefixVal](objs.PFWDGuardPrefixes); err != nil {
		return err
	}
	if err := clearMap[portKey, uint8](objs.PFWDSkipPorts); err != nil {
		return err
	}
	return nil
}

func pinnedPathExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func pinnedRuntimeMapsCompatible(opts applyOptions) bool {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpBPFEL))
	if err != nil {
		return false
	}
	pinLayout := runtimeMapPinsFromApplyOptions(opts)
	pins := map[string]string{
		"pfwd_settings":            pinLayout.Settings,
		"pfwd_rules":               pinLayout.Rules,
		"pfwd_connections":         pinLayout.Connections,
		"pfwd_reverse":             pinLayout.Reverse,
		"pfwd_rule_counters":       pinLayout.RuleCounter,
		"pfwd_user_counters":       pinLayout.UserCounter,
		"pfwd_stats":               pinLayout.Stats,
		"pfwd_whitelist_v4":        pinLayout.WhitelistV4,
		"pfwd_whitelist_v6":        pinLayout.WhitelistV6,
		"pfwd_whitelist_cache_v4":  pinLayout.WhitelistCacheV4,
		"pfwd_whitelist_cache_v6":  pinLayout.WhitelistCacheV6,
		"pfwd_allowed_flows":       pinLayout.AllowedFlows,
		"pfwd_guard_prefixes":      pinLayout.GuardPrefixes,
		"pfwd_protocol_skip_ports": pinLayout.SkipPorts,
	}
	for name, path := range pins {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			return false
		}
		pinnedMap, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			return false
		}
		err = mapSpec.Compatible(pinnedMap)
		_ = pinnedMap.Close()
		if err != nil {
			return false
		}
	}
	return true
}

func canIncrementalApply(payload statusPayload, runtimeData *runtimeFile, opts applyOptions, iface *net.Interface, needIngress bool) bool {
	if !payload.Applied {
		return false
	}
	if payload.BinaryVersion != "" && payload.BinaryVersion != binaryVersion {
		return false
	}
	if payload.MapABIVersion != 0 && payload.MapABIVersion != mapABIVersion {
		return false
	}
	if payload.Interface != "" && iface != nil && payload.Interface != iface.Name {
		return false
	}
	if payload.GuardMode != opts.GuardMode {
		return false
	}
	if (payload.IngressKind != "") != needIngress {
		return false
	}
	if opts.GuardMode == "full" && payload.XDPEffective != "enabled" {
		return false
	}
	if opts.GuardMode == "full" && !pinnedPathExists(firstNonEmpty(opts.XDPPin, payload.XDPPin)) {
		return false
	}
	if needIngress && !pinnedPathExists(firstNonEmpty(opts.IngressPin, payload.IngressPin)) {
		return false
	}
	pinLayout := runtimeMapPinsFromApplyOptions(opts)
	requiredMapPins := []string{
		pinLayout.Settings,
		pinLayout.Rules,
		pinLayout.Connections,
		pinLayout.Reverse,
		pinLayout.RuleCounter,
		pinLayout.UserCounter,
		pinLayout.Stats,
		pinLayout.WhitelistV4,
		pinLayout.WhitelistV6,
		pinLayout.WhitelistCacheV4,
		pinLayout.WhitelistCacheV6,
		pinLayout.AllowedFlows,
		pinLayout.GuardPrefixes,
		pinLayout.SkipPorts,
	}
	for _, path := range requiredMapPins {
		if !pinnedPathExists(path) {
			return false
		}
	}
	return runtimeData != nil && pinnedRuntimeMapsCompatible(opts)
}

func elapsedMillis(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

type ruleSemantics struct {
	RuleID             uint32
	UserID             uint32
	TargetAddr         [16]byte
	TargetPort         uint16
	SourceAddr         [16]byte
	SourceAddrFromRule bool
	TrafficRatioScaled uint64
	TrafficMode        uint8
	UserLimitEnabled   uint8
	BillingEnabled     uint8
}

func ruleSemanticsFromRule(rule runtimeRule) (ruleSemantics, error) {
	value, err := makeRuleVal(rule, runtimeSettings{})
	if err != nil {
		return ruleSemantics{}, err
	}
	return ruleSemantics{
		RuleID:             value.RuleID,
		UserID:             value.UserID,
		TargetAddr:         value.TargetAddr,
		TargetPort:         value.TargetPort,
		SourceAddr:         value.SNATAddr,
		SourceAddrFromRule: value.SNATMode == 1,
		TrafficRatioScaled: value.TrafficRatioScaled,
		TrafficMode:        value.TrafficMode,
		UserLimitEnabled:   value.UserLimitEnabled,
		BillingEnabled:     value.BillingEnabled,
	}, nil
}

func connectionRuleSignature(key connKey, value connVal) ruleSemantics {
	return ruleSemantics{
		RuleID:             value.RuleID,
		UserID:             value.UserID,
		TargetAddr:         key.TargetAddr,
		TargetPort:         key.TargetPort,
		TrafficRatioScaled: value.TrafficRatioScaled,
		TrafficMode:        value.TrafficMode,
		UserLimitEnabled:   value.UserLimitEnabled,
		BillingEnabled:     value.BillingEnabled,
	}
}

func connectionMatchesRule(key connKey, value connVal, expected ruleSemantics) bool {
	actual := connectionRuleSignature(key, value)
	if actual.RuleID != expected.RuleID ||
		actual.UserID != expected.UserID ||
		actual.TargetAddr != expected.TargetAddr ||
		actual.TargetPort != expected.TargetPort ||
		actual.TrafficRatioScaled != expected.TrafficRatioScaled ||
		actual.TrafficMode != expected.TrafficMode ||
		actual.UserLimitEnabled != expected.UserLimitEnabled ||
		actual.BillingEnabled != expected.BillingEnabled {
		return false
	}
	if expected.SourceAddrFromRule {
		return value.SourceAddr == expected.SourceAddr
	}
	return value.SourceAddr == key.ListenAddr
}

func runtimeConnectionSemantics(runtimeData *runtimeFile) (map[ruleKey]ruleSemantics, error) {
	allowed := make(map[ruleKey]ruleSemantics, len(runtimeData.Rules))
	for _, rule := range runtimeData.Rules {
		key, err := makeRuleKey(rule)
		if err != nil {
			return nil, fmt.Errorf("生成规则 key 失败 (%s): %w", rule.ID, err)
		}
		signature, err := ruleSemanticsFromRule(rule)
		if err != nil {
			return nil, fmt.Errorf("生成规则连接语义失败 (%s): %w", rule.ID, err)
		}
		allowed[key] = signature
	}
	return allowed, nil
}

func connectionAllowedByRuntime(key connKey, value connVal, allowed map[ruleKey]ruleSemantics) bool {
	ruleLookup := ruleKey{
		Family:     key.Family,
		Protocol:   key.Protocol,
		ListenPort: key.ListenPort,
		ListenAddr: key.ListenAddr,
	}
	expected, ok := allowed[ruleLookup]
	if !ok {
		ruleLookup.ListenAddr = [16]byte{}
		expected, ok = allowed[ruleLookup]
	}
	return ok && connectionMatchesRule(key, value, expected)
}

func runtimeRuleEntries(runtimeData *runtimeFile) (map[ruleKey]ruleVal, error) {
	entries := make(map[ruleKey]ruleVal, len(runtimeData.Rules))
	for _, rule := range runtimeData.Rules {
		key, err := makeRuleKey(rule)
		if err != nil {
			return nil, fmt.Errorf("生成规则 key 失败 (%s): %w", rule.ID, err)
		}
		value, err := makeRuleVal(rule, runtimeData.Settings)
		if err != nil {
			return nil, fmt.Errorf("生成规则 value 失败 (%s): %w", rule.ID, err)
		}
		entries[key] = value
	}
	return entries, nil
}

func runtimeUserLimits(runtimeData *runtimeFile) map[uint32]uint64 {
	limits := make(map[uint32]uint64, len(runtimeData.Rules))
	for _, rule := range runtimeData.Rules {
		limits[rule.UserIndex] = rule.UserLimit
	}
	return limits
}

func currentRuleUserLimits(objs *bpfObjects) (map[uint32]uint64, error) {
	users := map[uint32]uint64{}
	it := objs.PFWDRules.Iterate()
	var key ruleKey
	var value ruleVal
	for it.Next(&key, &value) {
		users[value.UserID] = value.UserLimitBytes
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("遍历旧规则用户失败: %w", err)
	}
	return users, nil
}

func zeroRuleCounter(objs *bpfObjects, key uint32, zeroCounter []counterVal) error {
	if err := objs.PFWDRuleCounter.Update(&key, zeroCounter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("重置规则计数失败 (key=%d): %w", key, err)
	}
	return nil
}

func zeroUserCounter(objs *bpfObjects, key uint32, zeroCounter []counterVal) error {
	if err := objs.PFWDUserCounter.Update(&key, zeroCounter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("重置用户计数失败 (key=%d): %w", key, err)
	}
	return nil
}

func zeroRuleCounterOnce(objs *bpfObjects, key uint32, zeroCounter []counterVal, resetKeys map[uint32]struct{}) (bool, error) {
	if _, ok := resetKeys[key]; ok {
		return false, nil
	}
	if err := zeroRuleCounter(objs, key, zeroCounter); err != nil {
		return false, err
	}
	resetKeys[key] = struct{}{}
	return true, nil
}

func ruleValEquivalentForRefresh(current ruleVal, expected ruleVal) bool {
	current.RuleBillingUsedBaseBytes = expected.RuleBillingUsedBaseBytes
	current.UserBillingUsedBaseBytes = expected.UserBillingUsedBaseBytes
	return current == expected
}

func reconcileRuleMap(objs *bpfObjects, expected map[ruleKey]ruleVal) (mapReconcileReport, error) {
	var report mapReconcileReport
	zeroCounter, err := zeroPerCPUCounterValues()
	if err != nil {
		return report, err
	}
	seen := make(map[ruleKey]struct{}, len(expected))
	resetKeys := map[uint32]struct{}{}
	it := objs.PFWDRules.Iterate()
	var key ruleKey
	var current ruleVal
	for it.Next(&key, &current) {
		expectedValue, ok := expected[key]
		if !ok {
			keyCopy := key
			if err := objs.PFWDRules.Delete(&keyCopy); err != nil {
				return report, fmt.Errorf("删除旧规则失败: %w", err)
			}
			reset, err := zeroRuleCounterOnce(objs, current.RuleID, zeroCounter, resetKeys)
			if err != nil {
				return report, err
			}
			if reset {
				report.CountersReset++
			}
			report.RulesDeleted++
			continue
		}
		seen[key] = struct{}{}
		if ruleValEquivalentForRefresh(current, expectedValue) {
			report.CountersPreserved++
			continue
		}
		keyCopy := key
		valueCopy := expectedValue
		if err := objs.PFWDRules.Update(&keyCopy, &valueCopy, ebpf.UpdateAny); err != nil {
			return report, fmt.Errorf("更新规则失败: %w", err)
		}
		reset, err := zeroRuleCounterOnce(objs, expectedValue.RuleID, zeroCounter, resetKeys)
		if err != nil {
			return report, err
		}
		if reset {
			report.CountersReset++
		}
		if current.RuleID != expectedValue.RuleID {
			reset, err := zeroRuleCounterOnce(objs, current.RuleID, zeroCounter, resetKeys)
			if err != nil {
				return report, err
			}
			if reset {
				report.CountersReset++
			}
		}
		report.RulesUpdated++
	}
	if err := it.Err(); err != nil {
		return report, fmt.Errorf("遍历规则 map 失败: %w", err)
	}
	for key, value := range expected {
		if _, ok := seen[key]; ok {
			continue
		}
		keyCopy := key
		valueCopy := value
		if err := objs.PFWDRules.Update(&keyCopy, &valueCopy, ebpf.UpdateAny); err != nil {
			return report, fmt.Errorf("新增规则失败: %w", err)
		}
		reset, err := zeroRuleCounterOnce(objs, value.RuleID, zeroCounter, resetKeys)
		if err != nil {
			return report, err
		}
		if reset {
			report.CountersReset++
		}
		report.RulesAdded++
	}
	return report, nil
}

func reconcileUserCounters(objs *bpfObjects, oldUsers map[uint32]uint64, expected map[uint32]uint64) (mapReconcileReport, error) {
	var report mapReconcileReport
	zeroCounter, err := zeroPerCPUCounterValues()
	if err != nil {
		return report, err
	}
	for index, limit := range expected {
		oldLimit, ok := oldUsers[index]
		if ok && oldLimit == limit {
			report.CountersPreserved++
			continue
		}
		if err := zeroUserCounter(objs, index, zeroCounter); err != nil {
			return report, err
		}
		if ok {
			report.UsersUpdated++
		} else {
			report.UsersAdded++
		}
		report.CountersReset++
	}
	for index := range oldUsers {
		if _, ok := expected[index]; ok {
			continue
		}
		if err := zeroUserCounter(objs, index, zeroCounter); err != nil {
			return report, err
		}
		report.UsersDeleted++
		report.CountersReset++
	}
	return report, nil
}

func (r *mapReconcileReport) add(other mapReconcileReport) {
	r.RulesAdded += other.RulesAdded
	r.RulesUpdated += other.RulesUpdated
	r.RulesDeleted += other.RulesDeleted
	r.UsersAdded += other.UsersAdded
	r.UsersUpdated += other.UsersUpdated
	r.UsersDeleted += other.UsersDeleted
	r.CountersPreserved += other.CountersPreserved
	r.CountersReset += other.CountersReset
}

func reconcileRuntimeMaps(objs *bpfObjects, runtimeData *runtimeFile, opts applyOptions) (mapReconcileReport, error) {
	if objs.PFWDSettings == nil || objs.PFWDRules == nil || objs.PFWDRuleCounter == nil || objs.PFWDUserCounter == nil {
		return mapReconcileReport{}, fmt.Errorf("关键 BPF map 未加载")
	}
	oldUsers, err := currentRuleUserLimits(objs)
	if err != nil {
		return mapReconcileReport{}, err
	}
	if err := clearIncrementalAuxMaps(objs); err != nil {
		return mapReconcileReport{}, fmt.Errorf("清理辅助 pinned maps 失败: %w", err)
	}
	var externalIfindex uint32
	if opts.Iface != "" {
		iface, err := net.InterfaceByName(opts.Iface)
		if err != nil {
			return mapReconcileReport{}, fmt.Errorf("查找外部网卡失败: %w", err)
		}
		externalIfindex = uint32(iface.Index)
	}
	settings := xdpSettings{
		WhitelistEnabled: boolToUint8(runtimeData.Settings.WhitelistEnabled),
		BlockHTTP:        boolToUint8(runtimeData.Settings.BlockHTTP),
		BlockTLS:         boolToUint8(runtimeData.Settings.BlockTLS),
		BlockSOCKS:       boolToUint8(runtimeData.Settings.BlockSOCKS),
		GuardEnabled:     boolToUint8(runtimeData.Settings.GuardEnabled),
		HasSkipPorts:     boolToUint8(len(runtimeData.Settings.ProtocolSkipPorts) > 0),
		ExternalIfindex:  externalIfindex,
		LoopbackIfindex:  0,
	}
	key := uint32(0)
	if err := objs.PFWDSettings.Update(&key, &settings, ebpf.UpdateAny); err != nil {
		return mapReconcileReport{}, fmt.Errorf("写入 settings 失败: %w", err)
	}
	if err := loadProtocolSkipPorts(objs.PFWDSkipPorts, runtimeData.Settings.ProtocolSkipPorts); err != nil {
		return mapReconcileReport{}, err
	}
	files := runtimeData.Settings.WhitelistFiles
	if opts.WhitelistFile != "" {
		files = splitFiles(opts.WhitelistFile)
	}
	if runtimeData.Settings.WhitelistEnabled {
		if err := loadWhitelistFiles(objs.PFWDWhitelistV4, objs.PFWDWhitelistV6, files); err != nil {
			return mapReconcileReport{}, err
		}
	}
	rules, err := runtimeRuleEntries(runtimeData)
	if err != nil {
		return mapReconcileReport{}, err
	}
	report, err := reconcileRuleMap(objs, rules)
	if err != nil {
		return report, err
	}
	userReport, err := reconcileUserCounters(objs, oldUsers, runtimeUserLimits(runtimeData))
	if err != nil {
		return report, err
	}
	report.add(userReport)
	return report, nil
}

func reverseKeyFromConn(key connKey, value connVal) reverseKey {
	return reverseKey{
		Family:     key.Family,
		Protocol:   key.Protocol,
		SourcePort: value.SourcePort,
		TargetPort: key.TargetPort,
		ClientPort: key.ClientPort,
		SourceAddr: value.SourceAddr,
		TargetAddr: key.TargetAddr,
		ClientAddr: key.ClientAddr,
	}
}

func reconcileConnections(objs *bpfObjects, runtimeData *runtimeFile) (uint64, uint64, error) {
	if objs.PFWDConnections == nil || objs.PFWDReverse == nil {
		return 0, 0, fmt.Errorf("连接 map 未加载")
	}
	allowed, err := runtimeConnectionSemantics(runtimeData)
	if err != nil {
		return 0, 0, err
	}
	var preserved uint64
	var invalidated uint64
	it := objs.PFWDConnections.Iterate()
	var key connKey
	var value connVal
	for it.Next(&key, &value) {
		if connectionAllowedByRuntime(key, value, allowed) {
			preserved++
			continue
		}
		keyCopy := key
		reverseCopy := reverseKeyFromConn(key, value)
		if err := objs.PFWDConnections.Delete(&keyCopy); err != nil {
			return preserved, invalidated, fmt.Errorf("删除失效 connection 失败: %w", err)
		}
		if err := objs.PFWDReverse.Delete(&reverseCopy); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return preserved, invalidated, fmt.Errorf("删除失效 reverse 失败: %w", err)
		}
		invalidated++
	}
	if err := it.Err(); err != nil {
		return preserved, invalidated, fmt.Errorf("遍历 connection map 失败: %w", err)
	}
	return preserved, invalidated, nil
}

func profileCounts(runtimeData *runtimeFile) map[string]int {
	counts := map[string]int{}
	if runtimeData == nil {
		return counts
	}
	for name, value := range runtimeData.Summary.ProfileCounts {
		counts[name] = value
	}
	for _, rule := range runtimeData.Rules {
		if rule.FeatureProfile == "" {
			continue
		}
		if _, ok := counts[rule.FeatureProfile]; !ok {
			counts[rule.FeatureProfile] = 0
		}
	}
	return counts
}

func applyIncrementalRuntime(payload statusPayload, runtimeData *runtimeFile, opts applyOptions, iface *net.Interface, protocolGuard bool) error {
	startedAt := time.Now().UTC()
	startedAtText := startedAt.Format(time.RFC3339)
	runtimeSemanticConfigHash, err := runtimeSemanticHash(runtimeData)
	if err != nil {
		return err
	}
	loadStart := time.Now()
	objs, err := loadPinnedRuntimeMaps(runtimeMapPinsFromApplyOptions(opts))
	if err != nil {
		return err
	}
	loadDuration := elapsedMillis(loadStart)
	defer objs.Close()
	mapLoadStart := time.Now()
	mapReport, err := reconcileRuntimeMaps(objs, runtimeData, opts)
	if err != nil {
		return fmt.Errorf("reconcile pinned maps 失败: %w", err)
	}
	mapLoadDuration := elapsedMillis(mapLoadStart)
	reconcileStart := time.Now()
	preservedConnections, invalidatedConnections, err := reconcileConnections(objs, runtimeData)
	if err != nil {
		return fmt.Errorf("reconcile active connections 失败: %w", err)
	}
	reconcileDuration := elapsedMillis(reconcileStart)
	statusStart := time.Now()
	appliedAt := time.Now().UTC().Format(time.RFC3339)
	updated := payload
	updated.Applied = true
	updated.BinaryVersion = binaryVersion
	updated.AppliedAt = appliedAt
	updated.Interface = iface.Name
	updated.InterfaceIndex = iface.Index
	updated.GuardMode = opts.GuardMode
	updated.ProtocolGuard = protocolGuard
	updated.RuntimeFile = opts.RuntimeFile
	updated.StateFile = opts.StateFile
	updated.ConfigHash = runtimeSemanticConfigHash
	updated.RuntimeEpoch = runtimeSemanticConfigHash
	updated.DataplaneVersion = dataplaneVersion
	updated.MapABIVersion = mapABIVersion
	updated.IncrementalApply = true
	updated.ReattachReason = ""
	updated.PreservedConnections = preservedConnections
	updated.InvalidatedConnections = invalidatedConnections
	updated.ProfileCounts = profileCounts(runtimeData)
	updated.Rules = len(runtimeData.Rules)
	updated.Users = len(runtimeData.Users)
	updated.XDPPin = opts.XDPPin
	updated.IngressPin = opts.IngressPin
	updated.LoopbackPin = opts.LoopbackPin
	updated.SkLookupPin = opts.SkLookupPin
	updated.RuleCounterPin = opts.RuleCounterPin
	updated.UserCounterPin = opts.UserCounterPin
	updated.StatsPin = opts.StatsPin
	if summary, err := summarizeConnections(objs.PFWDConnections); err == nil {
		updated.ActiveSummary = summary
	}
	updated.RefreshReport = &refreshReport{
		Mode:                    "incremental",
		StartedAt:               startedAtText,
		CompletedAt:             time.Now().UTC().Format(time.RFC3339),
		TotalDurationMillis:     elapsedMillis(startedAt),
		LoadDurationMillis:      loadDuration,
		MapLoadDurationMillis:   mapLoadDuration,
		ReconcileDurationMillis: reconcileDuration,
		StatusDurationMillis:    elapsedMillis(statusStart),
		PreservedConnections:    preservedConnections,
		InvalidatedConnections:  invalidatedConnections,
		RulesAdded:              mapReport.RulesAdded,
		RulesUpdated:            mapReport.RulesUpdated,
		RulesDeleted:            mapReport.RulesDeleted,
		UsersAdded:              mapReport.UsersAdded,
		UsersUpdated:            mapReport.UsersUpdated,
		UsersDeleted:            mapReport.UsersDeleted,
		CountersPreserved:       mapReport.CountersPreserved,
		CountersReset:           mapReport.CountersReset,
		Rules:                   len(runtimeData.Rules),
		Users:                   len(runtimeData.Users),
	}
	return writeStatus(opts.StatusFile, updated)
}

func protocolGuardEnabled(settings runtimeSettings) bool {
	return settings.GuardEnabled && (settings.BlockHTTP || settings.BlockTLS || settings.BlockSOCKS)
}

func guardIngressEnabled(settings runtimeSettings) bool {
	return strings.EqualFold(strings.TrimSpace(settings.GuardIngressMode), "tc")
}

func runtimeHasLoopbackBackend(runtimeData *runtimeFile) bool {
	if runtimeData == nil {
		return false
	}
	for _, rule := range runtimeData.Rules {
		if !isLoopbackResolvedTarget(rule.ResolvedTarget) {
			continue
		}
		switch rule.IPVersion {
		case 4, 6:
			return true
		}
	}
	return false
}

func removeXDPLink(pin string) error {
	if pin == "" {
		return nil
	}
	return removePinnedLink(pin)
}

func isLoopbackResolvedTarget(raw string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return addr.IsLoopback()
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

func putRule(objs *bpfObjects, rule runtimeRule, settings runtimeSettings) error {
	key, err := makeRuleKey(rule)
	if err != nil {
		return fmt.Errorf("生成规则 key 失败 (%s): %w", rule.ID, err)
	}
	value, err := makeRuleVal(rule, settings)
	if err != nil {
		return fmt.Errorf("生成规则 value 失败 (%s): %w", rule.ID, err)
	}
	if err := objs.PFWDRules.Update(&key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("写入规则失败 (%s): %w", rule.ID, err)
	}
	zeroCounter, err := zeroPerCPUCounterValues()
	if err != nil {
		return err
	}
	if err := objs.PFWDRuleCounter.Update(&rule.Index, zeroCounter, ebpf.UpdateAny); err != nil {
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

func makeRuleVal(rule runtimeRule, settings runtimeSettings) (ruleVal, error) {
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
		value.Flags |= ruleFlagSNATFixed
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
		value.Flags |= ruleFlagMSSEnabled
	case "set":
		value.MSSMode = 2
		value.MSSValue = rule.MSSValue
		value.Flags |= ruleFlagMSSEnabled
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
	if rule.UserLimit > 0 {
		value.UserLimitEnabled = 1
	}
	if rule.RuleLimit > 0 || rule.UserLimit > 0 {
		value.BillingEnabled = 1
	}
	if value.BillingEnabled != 0 {
		value.Flags |= ruleFlagNeedsCounter
	}
	if rule.RuleLimit > 0 || rule.UserLimit > 0 {
		value.Flags |= ruleFlagNeedsQuota
	}
	if settings.GuardEnabled && (settings.BlockHTTP || settings.BlockTLS || settings.BlockSOCKS) && strings.Contains(rule.Protocol, "tcp") {
		value.Flags |= ruleFlagNeedsGuard
	}
	if settings.WhitelistEnabled {
		value.Flags |= ruleFlagNeedsAllow
	}
	if rule.XDPDisabled {
		value.Flags |= ruleFlagXDPDisabled
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
	if opts.GuardMode != "full" {
		return "disabled", "", "guard-only", nil
	}
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

func attachTCProgram(iface *net.Interface, prog *ebpf.Program, pin string, attach ebpf.AttachType, direction string) (string, error) {
	if prog == nil {
		return "", fmt.Errorf("tc program 未加载")
	}
	if err := os.MkdirAll(filepath.Dir(pin), 0o755); err != nil {
		return "", fmt.Errorf("创建 tc pin 目录失败: %w", err)
	}
	_ = removePinnedLink(pin)
	if err := runTC("qdisc", "replace", "dev", iface.Name, "clsact"); err != nil {
		return "", err
	}
	if err := prog.Pin(pin); err != nil {
		return "", fmt.Errorf("pin tc program 失败: %w", err)
	}
	pref := tcPrefBPFIngress
	if direction == "egress" {
		pref = tcPrefBPFEgress
	}
	if err := runTC("filter", "replace", "dev", iface.Name, direction, "pref", pref, "bpf", "direct-action", "object-pinned", pin); err != nil {
		return "", err
	}
	return "tc", nil
}

func attachIngress(iface *net.Interface, prog *ebpf.Program, pin string) (string, error) {
	return attachTCProgram(iface, prog, pin, ebpf.AttachTCXIngress, "ingress")
}

func attachLoopbackEgress(iface *net.Interface, prog *ebpf.Program, pin string) (string, error) {
	return attachTCProgram(iface, prog, pin, ebpf.AttachTCXEgress, "egress")
}

func attachSkLookup(prog *ebpf.Program, pin string) (string, error) {
	if prog == nil {
		return "", fmt.Errorf("sk_lookup program 未加载")
	}
	if err := features.HaveProgramType(ebpf.SkLookup); err != nil {
		return "", fmt.Errorf("检测到 localhost 后端，但当前内核不支持 sk_lookup: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(pin), 0o755); err != nil {
		return "", fmt.Errorf("创建 sk_lookup pin 目录失败: %w", err)
	}
	_ = removePinnedLink(pin)
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return "", fmt.Errorf("打开当前 netns 失败: %w", err)
	}
	defer netns.Close()
	attached, err := link.AttachNetNs(int(netns.Fd()), prog)
	if err != nil {
		return "", fmt.Errorf("附加 sk_lookup 失败: %w", err)
	}
	defer attached.Close()
	if err := attached.Pin(pin); err != nil {
		return "", fmt.Errorf("pin sk_lookup link 失败: %w", err)
	}
	if err := attached.Close(); err != nil {
		return "", fmt.Errorf("关闭 sk_lookup link fd 失败: %w", err)
	}
	return "netns", nil
}

func removeTCRuntime(pin string, ifaceName string, direction string) error {
	if pin != "" {
		_ = removePinnedLink(pin)
		_ = removePinnedProgram(pin)
	}
	if ifaceName != "" {
		pref := tcPrefBPFIngress
		if direction == "egress" {
			pref = tcPrefBPFEgress
		}
		_ = runTC("filter", "delete", "dev", ifaceName, direction, "pref", pref)
	}
	return nil
}

func removeIngressRuntime(pin string, ifaceName string) error {
	if err := removeTCRuntime(pin, ifaceName, "ingress"); err != nil {
		return err
	}
	if pin != "/sys/fs/bpf/pfwd_ingress_link" {
		_ = removeTCRuntime("/sys/fs/bpf/pfwd_ingress_link", "", "ingress")
	}
	return nil
}

func removeLoopbackRuntime(pin string, ifaceName string) error {
	return removeTCRuntime(pin, ifaceName, "egress")
}

func removeSkLookupRuntime(pin string) error {
	if pin == "" {
		return nil
	}
	_ = removePinnedLink(pin)
	return nil
}

func removeRuntime(opts removeOptions) error {
	payload, _ := readStatus(opts.StatusFile)
	xdpPin := firstNonEmpty(opts.XDPPin, payload.XDPPin)
	ingressPin := firstNonEmpty(opts.IngressPin, payload.IngressPin)
	loopbackPin := firstNonEmpty(opts.LoopbackPin, payload.LoopbackPin)
	skLookupPin := firstNonEmpty(opts.SkLookupPin, payload.SkLookupPin)
	pinLayout := runtimeMapPinsFromRemoveOptions(opts, payload)
	if xdpPin != "" {
		_ = removePinnedLink(xdpPin)
	}
	if ingressPin != "" {
		_ = removeIngressRuntime(ingressPin, payload.Interface)
	} else if payload.Interface != "" {
		_ = removeIngressRuntime("", payload.Interface)
	}
	if loopbackPin != "" {
		_ = removeLoopbackRuntime(loopbackPin, "lo")
	}
	if skLookupPin != "" {
		_ = removeSkLookupRuntime(skLookupPin)
	}
	if opts.StatusFile != "" {
		if err := os.Remove(opts.StatusFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, path := range []string{
		pinLayout.Settings,
		pinLayout.Rules,
		pinLayout.Connections,
		pinLayout.Reverse,
		pinLayout.RuleCounter,
		pinLayout.UserCounter,
		pinLayout.Stats,
		pinLayout.WhitelistV4,
		pinLayout.WhitelistV6,
		pinLayout.WhitelistCacheV4,
		pinLayout.WhitelistCacheV6,
		pinLayout.AllowedFlows,
		pinLayout.GuardPrefixes,
		pinLayout.SkipPorts,
	} {
		if path != "" {
			_ = os.Remove(path)
		}
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
	rows := make([]snapshotRow, 0, len(runtimeData.Rules))
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
			rows = append(rows, snapshotRow{ID: rule.ID, UserID: rule.UserID, TrafficMode: rule.TrafficMode, TrafficRatio: nonzeroRatio(rule.TrafficRatio)})
		}
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	defer counterMap.Close()
	enc := json.NewEncoder(os.Stdout)
	for _, rule := range runtimeData.Rules {
		counter, err := lookupPerCPUCounter(counterMap, rule.Index)
		if err != nil {
			return fmt.Errorf("读取规则计数失败 (%s): %w", rule.ID, err)
		}
		rows = append(rows, snapshotRow{
			ID: rule.ID, UserID: rule.UserID, TrafficMode: rule.TrafficMode, TrafficRatio: nonzeroRatio(rule.TrafficRatio),
			InputBytes: counter.InputBytes, OutputBytes: counter.OutputBytes,
			InputPackets: counter.InputPackets, OutputPackets: counter.OutputPackets,
			DroppedBytes: counter.DroppedBytes, DroppedPackets: counter.DroppedPackets,
		})
	}
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
		Passed           uint64       `json:"passed"`
		Dropped          uint64       `json:"dropped"`
		Forwarded        uint64       `json:"forwarded"`
		QuotaDropped     uint64       `json:"quota_dropped"`
		WhitelistDropped uint64       `json:"whitelist_dropped"`
		ProtocolDropped  uint64       `json:"protocol_dropped"`
		ParseSkipped     uint64       `json:"parse_skipped"`
		TCPPrewarmed     uint64       `json:"tcp_prewarmed"`
		TCPEstablished   uint64       `json:"tcp_established"`
		ActiveSummary    *connSummary `json:"active_summary,omitempty"`
	}
	values := []*uint64{
		&payload.Passed,
		&payload.Dropped,
		&payload.Forwarded,
		&payload.QuotaDropped,
		&payload.WhitelistDropped,
		&payload.ProtocolDropped,
		&payload.ParseSkipped,
		&payload.TCPPrewarmed,
		&payload.TCPEstablished,
	}
	for i, dst := range values {
		key := uint32(i)
		total, err := lookupPerCPUUint64(statsMap, key)
		if err != nil {
			return fmt.Errorf("读取 XDP stats 失败 (key=%d): %w", key, err)
		}
		*dst = total
	}
	if opts.StatusFile != "" {
		status, err := readStatus(opts.StatusFile)
		if err == nil {
			summary, summaryErr := loadConnectionSummaryFromStatus(status)
			if summaryErr == nil {
				payload.ActiveSummary = summary
			} else {
				payload.ActiveSummary = status.ActiveSummary
			}
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func summarizeConnections(m *ebpf.Map) (*connSummary, error) {
	if m == nil {
		return nil, nil
	}
	summary := &connSummary{}
	it := m.Iterate()
	var key connKey
	var value connVal
	for it.Next(&key, &value) {
		summary.Total++
		switch key.Protocol {
		case 6:
			switch value.State {
			case connStateTCPSynPending:
				summary.TCPSynPending++
			case connStateTCPEstablished:
				summary.TCPEstablished++
			default:
				summary.TCPEstablished++
			}
		case 17:
			summary.UDP++
		}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("遍历 connection map 失败: %w", err)
	}
	if summary.Total == 0 {
		return &connSummary{}, nil
	}
	return summary, nil
}

func loadConnectionSummaryFromStatus(payload statusPayload) (*connSummary, error) {
	pinLayout := runtimeMapPinsFromPaths(
		firstNonEmpty(payload.RuleCounterPin, "/sys/fs/bpf/pfwd_rule_counters"),
		firstNonEmpty(payload.UserCounterPin, "/sys/fs/bpf/pfwd_user_counters"),
		firstNonEmpty(payload.StatsPin, "/sys/fs/bpf/pfwd_stats"),
	)
	if !pinnedPathExists(pinLayout.Connections) {
		return payload.ActiveSummary, nil
	}
	connMap, err := ebpf.LoadPinnedMap(pinLayout.Connections, nil)
	if err != nil {
		return payload.ActiveSummary, err
	}
	defer connMap.Close()
	return summarizeConnections(connMap)
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

func lookupPerCPUCounter(m *ebpf.Map, key uint32) (counterVal, error) {
	var values []counterVal
	if err := m.Lookup(&key, &values); err != nil {
		return counterVal{}, err
	}
	var total counterVal
	for _, value := range values {
		total.add(value)
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

func whitelistFileHashes(files []string) ([]whitelistContentHash, error) {
	if len(files) == 0 {
		return nil, nil
	}
	hashes := make([]whitelistContentHash, 0, len(files))
	for _, filePath := range files {
		filePath = strings.TrimSpace(filePath)
		if filePath == "" {
			continue
		}
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("读取白名单文件失败 (%s): %w", filePath, err)
		}
		sum := sha256.Sum256(content)
		hashes = append(hashes, whitelistContentHash{
			Path: filePath,
			Hash: hex.EncodeToString(sum[:]),
		})
	}
	return hashes, nil
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
			return nil
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
			return nil
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
	_, _ = fmt.Fprintln(file, "  pfwd-xdp apply --runtime-file FILE --state-file FILE --status-file FILE --iface IFACE --guard-mode off|ingress|full --xdp-pin PATH --ingress-pin PATH [--loopback-pin PATH --rule-counter-pin PATH --user-counter-pin PATH --stats-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp remove --status-file FILE --xdp-pin PATH --ingress-pin PATH [--loopback-pin PATH --rule-counter-pin PATH --user-counter-pin PATH --stats-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp status --status-file FILE")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp snapshot --runtime-file FILE --state-file FILE [--status-file FILE --rule-counter-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp stats [--status-file FILE --stats-pin PATH]")
}
