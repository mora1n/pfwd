package xdp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "embed"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed xdp_bpfel.o
var xdpBPFEL []byte

const (
	binaryVersion    = "0.3.0"
	dataplaneVersion = 2
	mapABIVersion    = 17
	ratioScale       = uint64(1_000_000)
	maxRules         = 4096
	maxUsers         = 4096
	statsEntryCount  = 7
)

const (
	ruleFlagXDPDisabled  = uint16(1 << 0)
	ruleFlagNeedsCounter = uint16(1 << 1)
	ruleFlagNeedsQuota   = uint16(1 << 2)
	ruleFlagSNATFixed    = uint16(1 << 3)
	ruleFlagMSSEnabled   = uint16(1 << 4)
)

const (
	connStateTCPSynPending  = uint8(1)
	connStateTCPEstablished = uint8(2)
)

type tcxCapabilityKey struct {
	ifindex int
	attach  ebpf.AttachType
}

type tcxCapabilityResult struct {
	supported bool
	err       error
}

var (
	tcxAttachFunc = func(opts link.TCXOptions) (link.Link, error) {
		return link.AttachTCX(opts)
	}
	tcxCapabilityCacheMu sync.Mutex
	tcxCapabilityCache   = map[tcxCapabilityKey]tcxCapabilityResult{}
)

type applyOptions struct {
	Iface          string
	RuntimeFile    string
	StateFile      string
	StatusFile     string
	XDPPin         string
	LoopbackPin    string
	SkLookupPin    string
	RuleCounterPin string
	UserCounterPin string
	StatsPin       string
	Quiet          bool
}

type removeOptions struct {
	StatusFile     string
	XDPPin         string
	LoopbackPin    string
	SkLookupPin    string
	RuleCounterPin string
	UserCounterPin string
	StatsPin       string
}

type snapshotOptions struct {
	RuntimeFile    string
	StatusFile     string
	RuleCounterPin string
}

type statsOptions struct {
	StatusFile string
	StatsPin   string
}

type bpfObjects struct {
	PFWDXDP              *ebpf.Program `ebpf:"pfwd_xdp"`
	PFWDSettings         *ebpf.Map     `ebpf:"pfwd_settings"`
	PFWDRules            *ebpf.Map     `ebpf:"pfwd_rules"`
	PFWDConnections      *ebpf.Map     `ebpf:"pfwd_connections"`
	PFWDReverse          *ebpf.Map     `ebpf:"pfwd_reverse"`
	PFWDRuleCounter      *ebpf.Map     `ebpf:"pfwd_rule_counters"`
	PFWDRuleReplyCounter *ebpf.Map     `ebpf:"pfwd_rule_reply_counters"`
	PFWDRuleDropCounter  *ebpf.Map     `ebpf:"pfwd_rule_drop_counters"`
	PFWDUserCounter      *ebpf.Map     `ebpf:"pfwd_user_counters"`
	PFWDStats            *ebpf.Map     `ebpf:"pfwd_stats"`
	PFWDScratch          *ebpf.Map     `ebpf:"pfwd_scratch"`
}

func (o *bpfObjects) Close() {
	if o == nil {
		return
	}
	for _, closer := range []interface{ Close() error }{
		o.PFWDXDP, o.PFWDSettings, o.PFWDRules, o.PFWDConnections, o.PFWDReverse,
		o.PFWDRuleCounter, o.PFWDRuleReplyCounter, o.PFWDRuleDropCounter, o.PFWDUserCounter,
		o.PFWDStats, o.PFWDScratch,
	} {
		if closer != nil {
			_ = closer.Close()
		}
	}
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

type runtimeSettings struct {
	Interface string `json:"interface"`
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
	XDPEffective           string         `json:"xdp_effective,omitempty"`
	XDPAttachKind          string         `json:"xdp_attach_kind,omitempty"`
	XDPReason              string         `json:"xdp_reason,omitempty"`
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
	LoopbackPin            string         `json:"loopback_pin,omitempty"`
	SkLookupPin            string         `json:"sk_lookup_pin,omitempty"`
	RuleCounterPin         string         `json:"rule_counter_pin,omitempty"`
	UserCounterPin         string         `json:"user_counter_pin,omitempty"`
	StatsPin               string         `json:"stats_pin,omitempty"`
	ActiveSummary          *connSummary   `json:"active_summary,omitempty"`
	RefreshReport          *refreshReport `json:"refresh_report,omitempty"`
}

type refreshReport struct {
	Mode                    string         `json:"mode"`
	Reason                  string         `json:"reason,omitempty"`
	StartedAt               string         `json:"started_at,omitempty"`
	CompletedAt             string         `json:"completed_at,omitempty"`
	TotalDurationMillis     int64          `json:"total_duration_ms"`
	LoadDurationMillis      int64          `json:"load_duration_ms"`
	MapLoadDurationMillis   int64          `json:"map_load_duration_ms"`
	ReconcileDurationMillis int64          `json:"reconcile_duration_ms"`
	StatusDurationMillis    int64          `json:"status_duration_ms"`
	PreservedConnections    uint64         `json:"preserved_connections"`
	InvalidatedConnections  uint64         `json:"invalidated_connections"`
	RulesAdded              uint64         `json:"rules_added"`
	RulesUpdated            uint64         `json:"rules_updated"`
	RulesDeleted            uint64         `json:"rules_deleted"`
	UsersAdded              uint64         `json:"users_added"`
	UsersUpdated            uint64         `json:"users_updated"`
	UsersDeleted            uint64         `json:"users_deleted"`
	CountersPreserved       uint64         `json:"counters_preserved"`
	CountersReset           uint64         `json:"counters_reset"`
	Rules                   int            `json:"rules"`
	Users                   int            `json:"users"`
	AttachTimings           []attachTiming `json:"attach_timings,omitempty"`
}

type attachTiming struct {
	Component      string `json:"component"`
	DurationMillis int64  `json:"duration_ms"`
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
	RuleReplyCounter string
	RuleDropCounter  string
	UserCounter      string
	Stats            string
}

type xdpSettings struct {
	ExternalIfindex uint32
	Pad             [3]uint32
}

type ruleKey struct {
	Family     uint8
	Protocol   uint8
	ListenPort uint16
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
	PadRule                  [4]uint8
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
	InputBytes    uint64 `json:"input_bytes"`
	OutputBytes   uint64 `json:"output_bytes"`
	InputPackets  uint64 `json:"input_packets"`
	OutputPackets uint64 `json:"output_packets"`
	BillingBytes  uint64 `json:"billing_bytes"`
}

type userCounterVal struct {
	BillingBytes uint64 `json:"billing_bytes"`
}

type replyCounterVal struct {
	OutputBytes   uint64 `json:"output_bytes"`
	OutputPackets uint64 `json:"output_packets"`
	BillingBytes  uint64 `json:"billing_bytes"`
}

type dropCounterVal struct {
	DroppedBytes   uint64 `json:"dropped_bytes"`
	DroppedPackets uint64 `json:"dropped_packets"`
}

type connCounter struct {
	Bytes   uint64
	Packets uint64
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

type connSummary struct {
	Total          uint64 `json:"total"`
	TCPSynPending  uint64 `json:"tcp_syn_pending"`
	TCPEstablished uint64 `json:"tcp_established"`
	UDP            uint64 `json:"udp"`
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
	LastSeenNS         uint64
}

type reverseKey struct {
	Family     uint8
	Protocol   uint8
	SourcePort uint16
	TargetPort uint16
	Pad16      uint16
	SourceAddr [16]byte
	TargetAddr [16]byte
}

func Run(args []string) error {
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
	fs.StringVar(&opts.RuntimeFile, "runtime-file", "", "runtime json")
	fs.StringVar(&opts.StateFile, "state-file", "", "state json")
	fs.StringVar(&opts.StatusFile, "status-file", "", "status json")
	fs.StringVar(&opts.XDPPin, "xdp-pin", "", "bpffs xdp link pin")
	fs.StringVar(&opts.LoopbackPin, "loopback-pin", "", "legacy bpffs loopback link pin")
	fs.StringVar(&opts.SkLookupPin, "sk-lookup-pin", "", "legacy bpffs sk_lookup link pin")
	fs.StringVar(&opts.RuleCounterPin, "rule-counter-pin", "/sys/fs/bpf/pfwd_rule_counters", "bpffs rule counter map pin")
	fs.StringVar(&opts.UserCounterPin, "user-counter-pin", "/sys/fs/bpf/pfwd_user_counters", "bpffs user counter map pin")
	fs.StringVar(&opts.StatsPin, "stats-pin", "/sys/fs/bpf/pfwd_stats", "bpffs stats map pin")
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
	fs.StringVar(&opts.LoopbackPin, "loopback-pin", "", "legacy bpffs loopback link pin")
	fs.StringVar(&opts.SkLookupPin, "sk-lookup-pin", "", "legacy bpffs sk_lookup link pin")
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
	var ignored string
	fs.StringVar(&ignored, "state-file", "", "removed compatibility option")
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
	if opts.XDPPin == "" {
		return fmt.Errorf("缺少 --xdp-pin")
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
	runtimeData, err := loadRuntime(opts.RuntimeFile)
	if err != nil {
		return err
	}
	if opts.Iface == "" {
		opts.Iface = runtimeData.Settings.Interface
	}
	if opts.Iface == "" {
		return fmt.Errorf("缺少 --iface")
	}
	if len(runtimeData.Rules) == 0 {
		return removeRuntime(removeOptions{
			StatusFile:     opts.StatusFile,
			XDPPin:         opts.XDPPin,
			LoopbackPin:    opts.LoopbackPin,
			SkLookupPin:    opts.SkLookupPin,
			RuleCounterPin: opts.RuleCounterPin,
			UserCounterPin: opts.UserCounterPin,
			StatsPin:       opts.StatsPin,
		})
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("移除 memlock 限制失败: %w", err)
	}
	iface, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return fmt.Errorf("查找网卡 %q 失败: %w", opts.Iface, err)
	}
	currentStatus, _ := readStatus(opts.StatusFile)
	configHash, err := runtimeSemanticHash(runtimeData)
	if err != nil {
		return err
	}
	if runtimeStatusReusable(currentStatus, opts, iface.Name, configHash) && pinnedRuntimeMapsCompatible(opts) {
		return nil
	}
	if canIncrementalApply(currentStatus, runtimeData, opts, iface) {
		if err := applyIncrementalRuntime(currentStatus, runtimeData, opts, iface, configHash); err == nil {
			return nil
		} else if !opts.Quiet {
			fmt.Fprintf(os.Stderr, "pfwd xdp: incremental apply 失败，执行 full reattach: %v\n", err)
		}
	}
	fullStartedAt := time.Now().UTC()
	fullStartedAtText := fullStartedAt.Format(time.RFC3339)
	if err := removeRuntime(removeOptions{
		StatusFile:     opts.StatusFile,
		XDPPin:         opts.XDPPin,
		LoopbackPin:    opts.LoopbackPin,
		SkLookupPin:    opts.SkLookupPin,
		RuleCounterPin: opts.RuleCounterPin,
		UserCounterPin: opts.UserCounterPin,
		StatsPin:       opts.StatsPin,
	}); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("清理旧运行态失败: %w", err)
	}
	objs, err := loadObjects()
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
	attachTimings := make([]attachTiming, 0, 1)
	xdpAttachStart := time.Now()
	xdpEffective, xdpKind, xdpReason, err := attachXDP(iface, objs.PFWDXDP, opts)
	if err != nil {
		return err
	}
	recordAttachTiming(&attachTimings, "xdp", xdpAttachStart)
	statusStart := time.Now()
	payload := statusPayload{
		Applied:                true,
		BinaryVersion:          binaryVersion,
		AppliedAt:              time.Now().UTC().Format(time.RFC3339),
		Interface:              iface.Name,
		InterfaceIndex:         iface.Index,
		XDPEffective:           xdpEffective,
		XDPAttachKind:          xdpKind,
		XDPReason:              xdpReason,
		RuntimeFile:            opts.RuntimeFile,
		StateFile:              opts.StateFile,
		ConfigHash:             configHash,
		RuntimeEpoch:           configHash,
		DataplaneVersion:       dataplaneVersion,
		MapABIVersion:          mapABIVersion,
		IncrementalApply:       false,
		ReattachReason:         "full-reattach",
		ProfileCounts:          profileCounts(runtimeData),
		Rules:                  len(runtimeData.Rules),
		Users:                  len(runtimeData.Users),
		XDPPin:                 opts.XDPPin,
		LoopbackPin:            opts.LoopbackPin,
		SkLookupPin:            opts.SkLookupPin,
		RuleCounterPin:         opts.RuleCounterPin,
		UserCounterPin:         opts.UserCounterPin,
		StatsPin:               opts.StatsPin,
		ActiveSummary:          &connSummary{},
		PreservedConnections:   0,
		InvalidatedConnections: 0,
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
		AttachTimings:         attachTimings,
	}
	return writeStatus(opts.StatusFile, payload)
}

func removeRuntime(opts removeOptions) error {
	payload, _ := readStatus(opts.StatusFile)
	_ = removeXDPLink(firstNonEmpty(opts.XDPPin, payload.XDPPin))
	_ = removePinnedLink(firstNonEmpty(opts.LoopbackPin, payload.LoopbackPin))
	_ = removePinnedLink(firstNonEmpty(opts.SkLookupPin, payload.SkLookupPin))
	pinLayout := runtimeMapPinsFromRemoveOptions(opts, payload)
	for _, path := range []string{
		pinLayout.Settings,
		pinLayout.Rules,
		pinLayout.Connections,
		pinLayout.Reverse,
		pinLayout.RuleCounter,
		pinLayout.RuleReplyCounter,
		pinLayout.RuleDropCounter,
		pinLayout.UserCounter,
		pinLayout.Stats,
	} {
		if strings.TrimSpace(path) != "" {
			_ = os.Remove(path)
		}
	}
	_ = cleanupLegacyPins(pinLayout)
	if opts.StatusFile != "" {
		stopped := statusPayload{
			Applied:          false,
			BinaryVersion:    binaryVersion,
			RuntimeFile:      payload.RuntimeFile,
			StateFile:        payload.StateFile,
			DataplaneVersion: dataplaneVersion,
			MapABIVersion:    mapABIVersion,
		}
		return writeStatus(opts.StatusFile, stopped)
	}
	return nil
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

func loadObjects() (*bpfObjects, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpBPFEL))
	if err != nil {
		return nil, fmt.Errorf("加载 eBPF spec 失败: %w", err)
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
	return &bpfObjects{
		PFWDXDP:              coll.Programs["pfwd_xdp"],
		PFWDSettings:         coll.Maps["pfwd_settings"],
		PFWDRules:            coll.Maps["pfwd_rules"],
		PFWDConnections:      coll.Maps["pfwd_connections"],
		PFWDReverse:          coll.Maps["pfwd_reverse"],
		PFWDRuleCounter:      coll.Maps["pfwd_rule_counters"],
		PFWDRuleReplyCounter: coll.Maps["pfwd_rule_reply_counters"],
		PFWDRuleDropCounter:  coll.Maps["pfwd_rule_drop_counters"],
		PFWDUserCounter:      coll.Maps["pfwd_user_counters"],
		PFWDStats:            coll.Maps["pfwd_stats"],
		PFWDScratch:          coll.Maps["pfwd_scratch"],
	}, nil
}

func loadMaps(objs *bpfObjects, runtimeData *runtimeFile, opts applyOptions) error {
	if objs.PFWDSettings == nil || objs.PFWDRules == nil || objs.PFWDRuleCounter == nil || objs.PFWDRuleReplyCounter == nil || objs.PFWDRuleDropCounter == nil || objs.PFWDUserCounter == nil {
		return fmt.Errorf("关键 BPF map 未加载")
	}
	iface, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return fmt.Errorf("查找外部网卡失败: %w", err)
	}
	settings := xdpSettings{ExternalIfindex: uint32(iface.Index)}
	key := uint32(0)
	if err := objs.PFWDSettings.Update(&key, &settings, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("写入 settings 失败: %w", err)
	}
	zeroCounter, err := zeroPerCPUCounterValues()
	if err != nil {
		return err
	}
	zeroReplyCounter, err := zeroPerCPUReplyCounterValues()
	if err != nil {
		return err
	}
	zeroUserCounter, err := zeroPerCPUUserCounterValues()
	if err != nil {
		return err
	}
	zeroDropCounter, err := zeroPerCPUDropCounterValues()
	if err != nil {
		return err
	}
	for _, user := range runtimeData.Users {
		if err := objs.PFWDUserCounter.Update(&user.Index, zeroUserCounter, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("初始化用户计数失败 (%s): %w", user.ID, err)
		}
	}
	for _, rule := range runtimeData.Rules {
		if err := putRule(objs, rule, zeroCounter, zeroReplyCounter, zeroDropCounter); err != nil {
			return err
		}
	}
	return nil
}

func putRule(objs *bpfObjects, rule runtimeRule, zeroCounter []counterVal, zeroReplyCounter []replyCounterVal, zeroDropCounter []dropCounterVal) error {
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
	if err := objs.PFWDRuleCounter.Update(&rule.Index, zeroCounter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("初始化规则计数失败 (%s): %w", rule.ID, err)
	}
	if err := objs.PFWDRuleReplyCounter.Update(&rule.Index, zeroReplyCounter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("初始化规则 reply 计数失败 (%s): %w", rule.ID, err)
	}
	if err := objs.PFWDRuleDropCounter.Update(&rule.Index, zeroDropCounter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("初始化规则丢弃计数失败 (%s): %w", rule.ID, err)
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
	listenIP := strings.TrimSpace(rule.ListenIP)
	if listenIP != "" && listenIP != "::" && listenIP != "0.0.0.0" {
		return key, fmt.Errorf("当前 XDP rule key 仅支持通配监听地址，不支持具体 listen_ip：%s", rule.ListenIP)
	}
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
		value.Flags |= ruleFlagNeedsQuota
	}
	if value.BillingEnabled != 0 {
		value.Flags |= ruleFlagNeedsCounter
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
	_ = removePinnedProgram(opts.XDPPin)
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
	failures := make([]string, 0, 3)
	for _, attempt := range []struct {
		flags link.XDPAttachFlags
		kind  string
	}{
		{flags: link.XDPOffloadMode, kind: "offload"},
		{flags: link.XDPDriverMode, kind: "driver"},
		{flags: link.XDPGenericMode, kind: "generic"},
	} {
		effective, kind, reason, err := tryAttach(attempt.flags, attempt.kind)
		if err == nil {
			if len(failures) > 0 {
				reason = strings.Join(failures, "; ")
			}
			return effective, kind, reason, nil
		}
		failures = append(failures, fmt.Sprintf("%s=%v", attempt.kind, err))
	}
	return "", "", "", fmt.Errorf("XDP auto attach 失败：%s", strings.Join(failures, "; "))
}

func runtimeSemanticHash(runtimeData *runtimeFile) (string, error) {
	if runtimeData == nil {
		return "", fmt.Errorf("runtime 为空")
	}
	settings := runtimeData.Settings
	rules := make([]runtimeRule, 0, len(runtimeData.Rules))
	for _, rule := range runtimeData.Rules {
		semanticRule := rule
		semanticRule.FeatureFlags = nil
		semanticRule.FeatureProfile = ""
		semanticRule.RemoteInput = ""
		semanticRule.Comment = ""
		if rule.RuleLimit == 0 && rule.UserLimit == 0 {
			semanticRule.BillingUsedBase = 0
			semanticRule.UserBillingUsedBase = 0
		}
		rules = append(rules, semanticRule)
	}
	payload := struct {
		Settings runtimeSettings `json:"settings"`
		Rules    []runtimeRule   `json:"rules"`
	}{
		Settings: settings,
		Rules:    rules,
	}
	content, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("序列化 runtime 语义 hash 失败: %w", err)
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}

func runtimeStatusReusable(currentStatus statusPayload, opts applyOptions, ifaceName string, runtimeSemanticConfigHash string) bool {
	return currentStatus.Applied &&
		currentStatus.BinaryVersion == binaryVersion &&
		currentStatus.MapABIVersion == mapABIVersion &&
		currentStatus.ConfigHash == runtimeSemanticConfigHash &&
		currentStatus.Interface == ifaceName
}

func canIncrementalApply(payload statusPayload, runtimeData *runtimeFile, opts applyOptions, iface *net.Interface) bool {
	if runtimeData == nil || !payload.Applied {
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
	if !pinnedPathExists(firstNonEmpty(opts.XDPPin, payload.XDPPin)) {
		return false
	}
	pinLayout := runtimeMapPinsFromApplyOptions(opts)
	requiredMapPins := []string{
		pinLayout.Settings,
		pinLayout.Rules,
		pinLayout.Connections,
		pinLayout.Reverse,
		pinLayout.RuleCounter,
		pinLayout.RuleReplyCounter,
		pinLayout.RuleDropCounter,
		pinLayout.UserCounter,
		pinLayout.Stats,
	}
	for _, path := range requiredMapPins {
		if !pinnedPathExists(path) {
			return false
		}
	}
	return pinnedRuntimeMapsCompatible(opts)
}

func applyIncrementalRuntime(payload statusPayload, runtimeData *runtimeFile, opts applyOptions, iface *net.Interface, runtimeSemanticConfigHash string) error {
	startedAt := time.Now().UTC()
	loadStarted := time.Now()
	pinLayout := runtimeMapPinsFromApplyOptions(opts)
	objs, err := loadPinnedRuntimeMaps(pinLayout)
	if err != nil {
		return err
	}
	defer objs.Close()
	loadDuration := elapsedMillis(loadStarted)
	reconcileStarted := time.Now()
	report, err := reconcileRuntimeMaps(objs, runtimeData, opts)
	if err != nil {
		return err
	}
	summary, _ := summarizeConnections(objs.PFWDConnections)
	updated := payload
	updated.Applied = true
	updated.BinaryVersion = binaryVersion
	updated.AppliedAt = time.Now().UTC().Format(time.RFC3339)
	updated.Interface = iface.Name
	updated.InterfaceIndex = iface.Index
	updated.ConfigHash = runtimeSemanticConfigHash
	updated.RuntimeEpoch = runtimeSemanticConfigHash
	updated.DataplaneVersion = dataplaneVersion
	updated.MapABIVersion = mapABIVersion
	updated.IncrementalApply = true
	updated.ReattachReason = ""
	updated.ProfileCounts = profileCounts(runtimeData)
	updated.Rules = len(runtimeData.Rules)
	updated.Users = len(runtimeData.Users)
	updated.XDPPin = opts.XDPPin
	updated.RuleCounterPin = opts.RuleCounterPin
	updated.UserCounterPin = opts.UserCounterPin
	updated.StatsPin = opts.StatsPin
	updated.RuntimeFile = opts.RuntimeFile
	updated.StateFile = opts.StateFile
	updated.ActiveSummary = summary
	updated.RefreshReport = &refreshReport{
		Mode:                    "incremental",
		StartedAt:               startedAt.Format(time.RFC3339),
		CompletedAt:             time.Now().UTC().Format(time.RFC3339),
		TotalDurationMillis:     elapsedMillis(startedAt),
		LoadDurationMillis:      loadDuration,
		ReconcileDurationMillis: elapsedMillis(reconcileStarted),
		PreservedConnections:    report.CountersPreserved,
		RulesAdded:              report.RulesAdded,
		RulesUpdated:            report.RulesUpdated,
		RulesDeleted:            report.RulesDeleted,
		UsersAdded:              report.UsersAdded,
		UsersUpdated:            report.UsersUpdated,
		UsersDeleted:            report.UsersDeleted,
		CountersPreserved:       report.CountersPreserved,
		CountersReset:           report.CountersReset,
		Rules:                   len(runtimeData.Rules),
		Users:                   len(runtimeData.Users),
	}
	return writeStatus(opts.StatusFile, updated)
}

func reconcileRuntimeMaps(objs *bpfObjects, runtimeData *runtimeFile, opts applyOptions) (mapReconcileReport, error) {
	if objs.PFWDSettings == nil || objs.PFWDRules == nil || objs.PFWDRuleCounter == nil || objs.PFWDRuleReplyCounter == nil || objs.PFWDRuleDropCounter == nil || objs.PFWDUserCounter == nil {
		return mapReconcileReport{}, fmt.Errorf("关键 BPF map 未加载")
	}
	iface, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return mapReconcileReport{}, err
	}
	settings := xdpSettings{ExternalIfindex: uint32(iface.Index)}
	key := uint32(0)
	if err := objs.PFWDSettings.Update(&key, &settings, ebpf.UpdateAny); err != nil {
		return mapReconcileReport{}, fmt.Errorf("写入 settings 失败: %w", err)
	}
	expectedRules, err := runtimeRuleEntries(runtimeData)
	if err != nil {
		return mapReconcileReport{}, err
	}
	oldUsers, err := currentRuleUserLimits(objs)
	if err != nil {
		return mapReconcileReport{}, err
	}
	userLimits := runtimeUserLimits(runtimeData)
	ruleReport, err := reconcileRuleMap(objs, expectedRules)
	if err != nil {
		return mapReconcileReport{}, err
	}
	userReport, err := reconcileUserCounters(objs, oldUsers, userLimits)
	if err != nil {
		return mapReconcileReport{}, err
	}
	ruleReport.add(userReport)
	return ruleReport, nil
}

func runtimeRuleEntries(runtimeData *runtimeFile) (map[ruleKey]ruleVal, error) {
	entries := make(map[ruleKey]ruleVal, len(runtimeData.Rules))
	for _, rule := range runtimeData.Rules {
		key, err := makeRuleKey(rule)
		if err != nil {
			return nil, fmt.Errorf("生成规则 key 失败 (%s): %w", rule.ID, err)
		}
		value, err := makeRuleVal(rule)
		if err != nil {
			return nil, fmt.Errorf("生成规则 value 失败 (%s): %w", rule.ID, err)
		}
		entries[key] = value
	}
	return entries, nil
}

func reconcileRuleMap(objs *bpfObjects, expected map[ruleKey]ruleVal) (mapReconcileReport, error) {
	var report mapReconcileReport
	zeroCounter, err := zeroPerCPUCounterValues()
	if err != nil {
		return report, err
	}
	zeroReplyCounter, err := zeroPerCPUReplyCounterValues()
	if err != nil {
		return report, err
	}
	zeroDropCounter, err := zeroPerCPUDropCounterValues()
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
			reset, err := zeroRuleCounterOnce(objs, current.RuleID, zeroCounter, zeroReplyCounter, zeroDropCounter, resetKeys)
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
		reset, err := zeroRuleCounterOnce(objs, expectedValue.RuleID, zeroCounter, zeroReplyCounter, zeroDropCounter, resetKeys)
		if err != nil {
			return report, err
		}
		if reset {
			report.CountersReset++
		}
		if current.RuleID != expectedValue.RuleID {
			reset, err := zeroRuleCounterOnce(objs, current.RuleID, zeroCounter, zeroReplyCounter, zeroDropCounter, resetKeys)
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
		reset, err := zeroRuleCounterOnce(objs, value.RuleID, zeroCounter, zeroReplyCounter, zeroDropCounter, resetKeys)
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
	zeroCounter, err := zeroPerCPUUserCounterValues()
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
	pinLayout := runtimeMapPinsFromPaths(opts.RuleCounterPin, "/sys/fs/bpf/pfwd_user_counters", "/sys/fs/bpf/pfwd_stats")
	reverseCounters := map[uint32]connCounter{}
	reverseMap, reverseErr := ebpf.LoadPinnedMap(pinLayout.Reverse, nil)
	if reverseErr == nil {
		reverseCounters, reverseErr = collectBasicReverseCounters(reverseMap)
		_ = reverseMap.Close()
	}
	if reverseErr != nil && applied {
		return fmt.Errorf("读取 XDP reverse 连接计数失败 (%s): %w", pinLayout.Reverse, reverseErr)
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
	replyCounterMap, err := ebpf.LoadPinnedMap(pinLayout.RuleReplyCounter, nil)
	if err != nil {
		if applied {
			return fmt.Errorf("读取 XDP reply 计数 map 失败 (%s): %w", pinLayout.RuleReplyCounter, err)
		}
		replyCounterMap = nil
	}
	if replyCounterMap != nil {
		defer replyCounterMap.Close()
	}
	dropCounterMap, err := ebpf.LoadPinnedMap(pinLayout.RuleDropCounter, nil)
	if err != nil && applied {
		return fmt.Errorf("读取 XDP drop 计数 map 失败 (%s): %w", pinLayout.RuleDropCounter, err)
	}
	if dropCounterMap != nil {
		defer dropCounterMap.Close()
	}
	enc := json.NewEncoder(os.Stdout)
	for _, rule := range runtimeData.Rules {
		counter, err := lookupPerCPUCounter(counterMap, rule.Index)
		if err != nil {
			return fmt.Errorf("读取规则计数失败 (%s): %w", rule.ID, err)
		}
		replyCounter := replyCounterVal{}
		if replyCounterMap != nil {
			replyCounter, err = lookupPerCPUReplyCounter(replyCounterMap, rule.Index)
			if err != nil {
				return fmt.Errorf("读取规则 reply 计数失败 (%s): %w", rule.ID, err)
			}
		}
		dropCounter := dropCounterVal{}
		if dropCounterMap != nil {
			var dropErr error
			dropCounter, dropErr = lookupPerCPUDropCounter(dropCounterMap, rule.Index)
			if dropErr != nil {
				return fmt.Errorf("读取规则丢弃计数失败 (%s): %w", rule.ID, dropErr)
			}
		}
		counter.OutputBytes += replyCounter.OutputBytes
		counter.OutputPackets += replyCounter.OutputPackets
		counter.BillingBytes += replyCounter.BillingBytes
		counter.addConnOutput(reverseCounters[rule.Index])
		rows = append(rows, snapshotRow{
			ID: rule.ID, UserID: rule.UserID, TrafficMode: rule.TrafficMode, TrafficRatio: nonzeroRatio(rule.TrafficRatio),
			InputBytes: counter.InputBytes, OutputBytes: counter.OutputBytes,
			InputPackets: counter.InputPackets, OutputPackets: counter.OutputPackets,
			DroppedBytes: dropCounter.DroppedBytes, DroppedPackets: dropCounter.DroppedPackets,
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
		Passed         uint64       `json:"passed"`
		Dropped        uint64       `json:"dropped"`
		Forwarded      uint64       `json:"forwarded"`
		QuotaDropped   uint64       `json:"quota_dropped"`
		ParseSkipped   uint64       `json:"parse_skipped"`
		TCPPrewarmed   uint64       `json:"tcp_prewarmed"`
		TCPEstablished uint64       `json:"tcp_established"`
		ActiveSummary  *connSummary `json:"active_summary,omitempty"`
	}
	values := []*uint64{
		&payload.Passed,
		&payload.Dropped,
		&payload.Forwarded,
		&payload.QuotaDropped,
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

func runtimeMapPinsFromPaths(ruleCounterPin, userCounterPin, statsPin string) runtimeMapPins {
	dir := filepath.Dir(ruleCounterPin)
	namespace := runtimePinNamespace(ruleCounterPin)
	return runtimeMapPins{
		Settings:         filepath.Join(dir, namespace+"_settings"),
		Rules:            filepath.Join(dir, namespace+"_rules"),
		Connections:      filepath.Join(dir, namespace+"_connections"),
		Reverse:          filepath.Join(dir, namespace+"_reverse"),
		RuleCounter:      ruleCounterPin,
		RuleReplyCounter: filepath.Join(dir, namespace+"_rule_reply_counters"),
		RuleDropCounter:  filepath.Join(dir, namespace+"_rule_drop_counters"),
		UserCounter:      userCounterPin,
		Stats:            statsPin,
	}
}

func runtimePinNamespace(ruleCounterPin string) string {
	base := filepath.Base(strings.TrimSpace(ruleCounterPin))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "pfwd"
	}
	if strings.HasSuffix(base, "_rule_counters") {
		base = strings.TrimSuffix(base, "_rule_counters")
	}
	base = strings.Trim(base, "_- ")
	if base == "" {
		return "pfwd"
	}
	return base
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

func pinRuntimeMaps(objs *bpfObjects, opts applyOptions) error {
	pinLayout := runtimeMapPinsFromApplyOptions(opts)
	pins := map[string]*ebpf.Map{
		pinLayout.Settings:         objs.PFWDSettings,
		pinLayout.Rules:            objs.PFWDRules,
		pinLayout.Connections:      objs.PFWDConnections,
		pinLayout.Reverse:          objs.PFWDReverse,
		pinLayout.RuleCounter:      objs.PFWDRuleCounter,
		pinLayout.RuleReplyCounter: objs.PFWDRuleReplyCounter,
		pinLayout.RuleDropCounter:  objs.PFWDRuleDropCounter,
		pinLayout.UserCounter:      objs.PFWDUserCounter,
		pinLayout.Stats:            objs.PFWDStats,
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
	cleanupLegacyPins(pinLayout)
	return nil
}

func loadPinnedRuntimeMaps(pinLayout runtimeMapPins) (*bpfObjects, error) {
	closeMaps := func(maps ...*ebpf.Map) {
		for _, m := range maps {
			if m != nil {
				_ = m.Close()
			}
		}
	}
	opened := make([]*ebpf.Map, 0, 9)
	load := func(path string, message string) (*ebpf.Map, error) {
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			closeMaps(opened...)
			return nil, fmt.Errorf("%s: %w", message, err)
		}
		opened = append(opened, m)
		return m, nil
	}
	settings, err := load(pinLayout.Settings, "加载 pinned settings map 失败")
	if err != nil {
		return nil, err
	}
	rules, err := load(pinLayout.Rules, "加载 pinned rules map 失败")
	if err != nil {
		return nil, err
	}
	connections, err := load(pinLayout.Connections, "加载 pinned connections map 失败")
	if err != nil {
		return nil, err
	}
	reverse, err := load(pinLayout.Reverse, "加载 pinned reverse map 失败")
	if err != nil {
		return nil, err
	}
	ruleCounter, err := load(pinLayout.RuleCounter, "加载 pinned rule counter map 失败")
	if err != nil {
		return nil, err
	}
	ruleReplyCounter, err := load(pinLayout.RuleReplyCounter, "加载 pinned rule reply counter map 失败")
	if err != nil {
		return nil, err
	}
	ruleDropCounter, err := load(pinLayout.RuleDropCounter, "加载 pinned rule drop counter map 失败")
	if err != nil {
		return nil, err
	}
	userCounter, err := load(pinLayout.UserCounter, "加载 pinned user counter map 失败")
	if err != nil {
		return nil, err
	}
	stats, err := load(pinLayout.Stats, "加载 pinned stats map 失败")
	if err != nil {
		return nil, err
	}
	return &bpfObjects{
		PFWDSettings:         settings,
		PFWDRules:            rules,
		PFWDConnections:      connections,
		PFWDReverse:          reverse,
		PFWDRuleCounter:      ruleCounter,
		PFWDRuleReplyCounter: ruleReplyCounter,
		PFWDRuleDropCounter:  ruleDropCounter,
		PFWDUserCounter:      userCounter,
		PFWDStats:            stats,
	}, nil
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
		"pfwd_rule_reply_counters": pinLayout.RuleReplyCounter,
		"pfwd_rule_drop_counters":  pinLayout.RuleDropCounter,
		"pfwd_user_counters":       pinLayout.UserCounter,
		"pfwd_stats":               pinLayout.Stats,
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

func cleanupLegacyPins(pinLayout runtimeMapPins) error {
	_ = pinLayout
	return nil
}

func collectBasicReverseCounters(reverseMap *ebpf.Map) (map[uint32]connCounter, error) {
	counters := map[uint32]connCounter{}
	if reverseMap == nil {
		return counters, nil
	}
	it := reverseMap.Iterate()
	var key reverseKey
	var value connVal
	for it.Next(&key, &value) {
		if value.BillingEnabled != 0 || value.UserLimitEnabled != 0 {
			continue
		}
		current := counters[value.RuleID]
		current.Bytes += value.Bytes
		current.Packets += value.Packets
		counters[value.RuleID] = current
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("遍历 reverse map 失败: %w", err)
	}
	return counters, nil
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
	pinLayout := runtimeMapPinsFromPaths(firstNonEmpty(payload.RuleCounterPin, "/sys/fs/bpf/pfwd_rule_counters"), firstNonEmpty(payload.UserCounterPin, "/sys/fs/bpf/pfwd_user_counters"), firstNonEmpty(payload.StatsPin, "/sys/fs/bpf/pfwd_stats"))
	connMap, err := ebpf.LoadPinnedMap(pinLayout.Connections, nil)
	if err != nil {
		return nil, err
	}
	defer connMap.Close()
	return summarizeConnections(connMap)
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

func zeroPerCPUCounterValues() ([]counterVal, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("获取 PossibleCPU 失败: %w", err)
	}
	return make([]counterVal, cpus), nil
}

func zeroPerCPUReplyCounterValues() ([]replyCounterVal, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("获取 PossibleCPU 失败: %w", err)
	}
	return make([]replyCounterVal, cpus), nil
}

func zeroPerCPUUserCounterValues() ([]userCounterVal, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("获取 PossibleCPU 失败: %w", err)
	}
	return make([]userCounterVal, cpus), nil
}

func zeroPerCPUDropCounterValues() ([]dropCounterVal, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("获取 PossibleCPU 失败: %w", err)
	}
	return make([]dropCounterVal, cpus), nil
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

func lookupPerCPUReplyCounter(m *ebpf.Map, key uint32) (replyCounterVal, error) {
	var values []replyCounterVal
	if err := m.Lookup(&key, &values); err != nil {
		return replyCounterVal{}, err
	}
	var total replyCounterVal
	for _, value := range values {
		total.add(value)
	}
	return total, nil
}

func lookupPerCPUDropCounter(m *ebpf.Map, key uint32) (dropCounterVal, error) {
	var values []dropCounterVal
	if err := m.Lookup(&key, &values); err != nil {
		return dropCounterVal{}, err
	}
	var total dropCounterVal
	for _, value := range values {
		total.add(value)
	}
	return total, nil
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

func htons(value uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], value)
	return binary.LittleEndian.Uint16(b[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func pinnedPathExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func removeXDPLink(pin string) error {
	return removePinnedLink(pin)
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

func zeroRuleCounter(objs *bpfObjects, key uint32, zeroCounter []counterVal, zeroReplyCounter []replyCounterVal, zeroDropCounter []dropCounterVal) error {
	if err := objs.PFWDRuleCounter.Update(&key, zeroCounter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("重置规则计数失败 (key=%d): %w", key, err)
	}
	if err := objs.PFWDRuleReplyCounter.Update(&key, zeroReplyCounter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("重置规则 reply 计数失败 (key=%d): %w", key, err)
	}
	if err := objs.PFWDRuleDropCounter.Update(&key, zeroDropCounter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("重置规则丢弃计数失败 (key=%d): %w", key, err)
	}
	return nil
}

func zeroUserCounter(objs *bpfObjects, key uint32, zeroCounter []userCounterVal) error {
	if err := objs.PFWDUserCounter.Update(&key, zeroCounter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("重置用户计数失败 (key=%d): %w", key, err)
	}
	return nil
}

func zeroRuleCounterOnce(objs *bpfObjects, key uint32, zeroCounter []counterVal, zeroReplyCounter []replyCounterVal, zeroDropCounter []dropCounterVal, resetKeys map[uint32]struct{}) (bool, error) {
	if _, ok := resetKeys[key]; ok {
		return false, nil
	}
	if err := zeroRuleCounter(objs, key, zeroCounter, zeroReplyCounter, zeroDropCounter); err != nil {
		return false, err
	}
	resetKeys[key] = struct{}{}
	return true, nil
}

func ruleValEquivalentForRefresh(current ruleVal, expected ruleVal) bool {
	if current.BillingEnabled == 0 && expected.BillingEnabled == 0 {
		current.RuleBillingUsedBaseBytes = expected.RuleBillingUsedBaseBytes
		current.UserBillingUsedBaseBytes = expected.UserBillingUsedBaseBytes
	}
	return current == expected
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

func runtimeUserLimits(runtimeData *runtimeFile) map[uint32]uint64 {
	limits := make(map[uint32]uint64, len(runtimeData.Rules))
	for _, rule := range runtimeData.Rules {
		limits[rule.UserIndex] = rule.UserLimit
	}
	return limits
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

func (c *counterVal) add(other counterVal) {
	c.InputBytes += other.InputBytes
	c.OutputBytes += other.OutputBytes
	c.InputPackets += other.InputPackets
	c.OutputPackets += other.OutputPackets
	c.BillingBytes += other.BillingBytes
}

func (c *counterVal) addConnOutput(other connCounter) {
	c.OutputBytes += other.Bytes
	c.OutputPackets += other.Packets
}

func (c *userCounterVal) add(other userCounterVal) {
	c.BillingBytes += other.BillingBytes
}

func (c *replyCounterVal) add(other replyCounterVal) {
	c.OutputBytes += other.OutputBytes
	c.OutputPackets += other.OutputPackets
	c.BillingBytes += other.BillingBytes
}

func (c *dropCounterVal) add(other dropCounterVal) {
	c.DroppedBytes += other.DroppedBytes
	c.DroppedPackets += other.DroppedPackets
}

func profileCounts(runtimeData *runtimeFile) map[string]int {
	counts := map[string]int{}
	for _, rule := range runtimeData.Rules {
		profile := rule.FeatureProfile
		if strings.TrimSpace(profile) == "" {
			profile = "xdp"
		}
		counts[profile]++
	}
	return counts
}

func nonzeroRatio(value float64) float64 {
	if value <= 0 {
		return 1
	}
	return value
}

func recordAttachTiming(timings *[]attachTiming, component string, start time.Time) {
	*timings = append(*timings, attachTiming{Component: component, DurationMillis: elapsedMillis(start)})
}

func elapsedMillis(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

func usageError() error {
	printUsage(os.Stderr)
	return fmt.Errorf("缺少子命令")
}

func printUsage(file *os.File) {
	_, _ = fmt.Fprintln(file, "用法：")
	_, _ = fmt.Fprintln(file, "  pfwd xdp apply --runtime-file FILE --state-file FILE --status-file FILE --iface IFACE --xdp-pin PATH [--rule-counter-pin PATH --user-counter-pin PATH --stats-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd xdp remove --status-file FILE --xdp-pin PATH [--rule-counter-pin PATH --user-counter-pin PATH --stats-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd xdp status --status-file FILE")
	_, _ = fmt.Fprintln(file, "  pfwd xdp snapshot --runtime-file FILE [--status-file FILE --rule-counter-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd xdp stats [--status-file FILE --stats-pin PATH]")
}
