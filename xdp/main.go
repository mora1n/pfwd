//go:build !geobuild

package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed xdp_bpfel.o
var xdpBPFEL []byte

const binaryVersion = "0.2.8"
const dataplaneVersion = 2
const mapABIVersion = 16
const auxStateVersion = 1
const ratioScale = uint64(1_000_000)
const maxRules = 4096
const maxUsers = 4096
const protocolSkipPortEntries = 1 << 16
const (
	ruleFlagXDPDisabled  = uint16(1 << 0)
	ruleFlagNeedsCounter = uint16(1 << 1)
	ruleFlagNeedsQuota   = uint16(1 << 2)
	ruleFlagNeedsGuard   = uint16(1 << 3)
	ruleFlagNeedsAllow   = uint16(1 << 4)
	ruleFlagSNATFixed    = uint16(1 << 5)
	ruleFlagMSSEnabled   = uint16(1 << 6)
	ruleFlagHasSkipPorts = uint16(1 << 7)
	ruleFlagBlockHTTP    = uint16(1 << 8)
	ruleFlagBlockTLS     = uint16(1 << 9)
	ruleFlagBlockSOCKS   = uint16(1 << 10)
	ruleFlagAllowCustom  = uint16(1 << 11)
	ruleFlagAllowGeo     = uint16(1 << 12)
)
const (
	whitelistCNModeOff       = uint8(0)
	whitelistCNModeAll       = uint8(1)
	whitelistCNModeProvinces = uint8(2)
)
const ruleCounterPinSuffix = "_rule_counters"
const tcPrefBPFIngress = "10"
const tcPrefBPFEgress = "10"
const tcLegacyDefaultBPFPreference = "49152"
const connStateTCPSynPending = uint8(1)
const connStateTCPEstablished = uint8(2)
const statsEntryCount = 10
const cacheVerdictAllow = uint8(1)
const cacheVerdictDrop = uint8(2)

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

type bpfObjects struct {
	PFWDXDP                    *ebpf.Program `ebpf:"pfwd_xdp"`
	PFWDIngress                *ebpf.Program `ebpf:"pfwd_ingress"`
	PFWDHostEgress             *ebpf.Program `ebpf:"pfwd_host_egress"`
	PFWDLoopbackEgress         *ebpf.Program `ebpf:"pfwd_loopback_egress"`
	PFWDSkLookup               *ebpf.Program `ebpf:"pfwd_sk_lookup"`
	PFWDSettings               *ebpf.Map     `ebpf:"pfwd_settings"`
	PFWDRules                  *ebpf.Map     `ebpf:"pfwd_rules"`
	PFWDConnections            *ebpf.Map     `ebpf:"pfwd_connections"`
	PFWDReverse                *ebpf.Map     `ebpf:"pfwd_reverse"`
	PFWDRuleCounter            *ebpf.Map     `ebpf:"pfwd_rule_counters"`
	PFWDRuleReplyCounter       *ebpf.Map     `ebpf:"pfwd_rule_reply_counters"`
	PFWDRuleDropCounter        *ebpf.Map     `ebpf:"pfwd_rule_drop_counters"`
	PFWDUserCounter            *ebpf.Map     `ebpf:"pfwd_user_counters"`
	PFWDStats                  *ebpf.Map     `ebpf:"pfwd_stats"`
	PFWDWhitelistV4            *ebpf.Map     `ebpf:"pfwd_whitelist_v4"`
	PFWDWhitelistV6            *ebpf.Map     `ebpf:"pfwd_whitelist_v6"`
	PFWDWhitelistCacheV4       *ebpf.Map     `ebpf:"pfwd_whitelist_cache_v4"`
	PFWDWhitelistCacheV6       *ebpf.Map     `ebpf:"pfwd_whitelist_cache_v6"`
	PFWDIngressGeoV4           *ebpf.Map     `ebpf:"pfwd_ingress_geo_v4"`
	PFWDIngressGeoV6           *ebpf.Map     `ebpf:"pfwd_ingress_geo_v6"`
	PFWDIngressCityV4          *ebpf.Map     `ebpf:"pfwd_ingress_city_v4"`
	PFWDIngressPolicyModes     *ebpf.Map     `ebpf:"pfwd_ingress_policy_modes"`
	PFWDIngressPolicyProvinces *ebpf.Map     `ebpf:"pfwd_ingress_policy_provinces"`
	PFWDIngressPolicyCities    *ebpf.Map     `ebpf:"pfwd_ingress_policy_cities"`
	PFWDEgressWhitelistV4      *ebpf.Map     `ebpf:"pfwd_egress_whitelist_v4"`
	PFWDEgressWhitelistV6      *ebpf.Map     `ebpf:"pfwd_egress_whitelist_v6"`
	PFWDEgressWhitelistCacheV4 *ebpf.Map     `ebpf:"pfwd_egress_whitelist_cache_v4"`
	PFWDEgressWhitelistCacheV6 *ebpf.Map     `ebpf:"pfwd_egress_whitelist_cache_v6"`
	PFWDFlows                  *ebpf.Map     `ebpf:"pfwd_allowed_flows"`
	PFWDFlowsV4                *ebpf.Map     `ebpf:"pfwd_allowed_flows_v4"`
	PFWDHostEgressFlows        *ebpf.Map     `ebpf:"pfwd_host_egress_flows"`
	PFWDSkipPorts              *ebpf.Map     `ebpf:"pfwd_protocol_skip_ports"`
	PFWDScratch                *ebpf.Map     `ebpf:"pfwd_scratch"`
}

func (o *bpfObjects) Close() {
	if o == nil {
		return
	}
	for _, closer := range []interface{ Close() error }{
		o.PFWDXDP, o.PFWDIngress, o.PFWDHostEgress, o.PFWDLoopbackEgress, o.PFWDSkLookup, o.PFWDSettings, o.PFWDRules, o.PFWDConnections, o.PFWDReverse,
		o.PFWDRuleCounter, o.PFWDRuleReplyCounter, o.PFWDRuleDropCounter, o.PFWDUserCounter, o.PFWDStats, o.PFWDWhitelistV4, o.PFWDWhitelistV6,
		o.PFWDWhitelistCacheV4, o.PFWDWhitelistCacheV6, o.PFWDIngressGeoV4, o.PFWDIngressGeoV6, o.PFWDIngressCityV4,
		o.PFWDIngressPolicyModes, o.PFWDIngressPolicyProvinces, o.PFWDIngressPolicyCities, o.PFWDEgressWhitelistV4, o.PFWDEgressWhitelistV6,
		o.PFWDEgressWhitelistCacheV4, o.PFWDEgressWhitelistCacheV6, o.PFWDFlows, o.PFWDFlowsV4, o.PFWDHostEgressFlows, o.PFWDSkipPorts, o.PFWDScratch,
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
	HostEgressPin  string
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
	HostEgressPin  string
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

type runtimeAuxState struct {
	GuardEnabled          bool                   `json:"guard_enabled,omitempty"`
	WhitelistEnabled      bool                   `json:"whitelist_enabled,omitempty"`
	HostEgressEnabled     bool                   `json:"host_egress_enabled,omitempty"`
	BlockHTTP             bool                   `json:"block_http,omitempty"`
	BlockTLS              bool                   `json:"block_tls,omitempty"`
	BlockSOCKS            bool                   `json:"block_socks,omitempty"`
	ProtocolSkipPorts     []uint16               `json:"protocol_skip_ports,omitempty"`
	WhitelistHashes       []whitelistContentHash `json:"whitelist_hashes,omitempty"`
	EgressWhitelistHashes []whitelistContentHash `json:"egress_whitelist_hashes,omitempty"`
	GeoAssetHashes        []whitelistContentHash `json:"geo_asset_hashes,omitempty"`
	IngressCNMode         string                 `json:"ingress_cn_mode,omitempty"`
	EgressCNMode          string                 `json:"egress_cn_mode,omitempty"`
	IngressCNProvinces    []string               `json:"ingress_cn_provinces,omitempty"`
	IngressPolicies       []ingressPolicy        `json:"ingress_whitelist_policies,omitempty"`
	EgressCNProvinces     []string               `json:"egress_cn_provinces,omitempty"`
}

type auxActionSummary struct {
	Component    string `json:"component"`
	Action       string `json:"action"`
	ChangedItems int    `json:"changed_items,omitempty"`
}

type attachTiming struct {
	Component      string `json:"component"`
	DurationMillis int64  `json:"duration_ms"`
}

type runtimeSemanticSettings struct {
	Interface          string          `json:"interface"`
	GuardEnabled       bool            `json:"guard_enabled"`
	WhitelistEnabled   bool            `json:"whitelist_enabled"`
	HostEgressEnabled  bool            `json:"host_egress_enabled"`
	BlockHTTP          bool            `json:"block_http"`
	BlockTLS           bool            `json:"block_tls"`
	BlockSOCKS         bool            `json:"block_socks"`
	ProtocolSkipPorts  []uint16        `json:"protocol_skip_ports,omitempty"`
	GuardIngressMode   string          `json:"guard_ingress_mode,omitempty"`
	IngressCNMode      string          `json:"ingress_cn_mode,omitempty"`
	EgressCNMode       string          `json:"egress_cn_mode,omitempty"`
	IngressCNProvinces []string        `json:"ingress_cn_provinces,omitempty"`
	IngressPolicies    []ingressPolicy `json:"ingress_whitelist_policies,omitempty"`
	EgressCNProvinces  []string        `json:"egress_cn_provinces,omitempty"`
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
	WhitelistPolicyID   uint16  `json:"whitelist_policy_id,omitempty"`
}

type runtimeSettings struct {
	Interface            string          `json:"interface"`
	GuardEnabled         bool            `json:"guard_enabled"`
	WhitelistEnabled     bool            `json:"whitelist_enabled"`
	HostEgressEnabled    bool            `json:"host_egress_enabled"`
	BlockHTTP            bool            `json:"block_http"`
	BlockTLS             bool            `json:"block_tls"`
	BlockSOCKS           bool            `json:"block_socks"`
	ProtocolSkipPorts    []uint16        `json:"protocol_skip_ports,omitempty"`
	WhitelistFiles       []string        `json:"whitelist_files,omitempty"`
	EgressWhitelistFiles []string        `json:"egress_whitelist_files,omitempty"`
	GuardIngressMode     string          `json:"guard_ingress_mode,omitempty"`
	GeoAssetDir          string          `json:"geo_asset_dir,omitempty"`
	IngressCNMode        string          `json:"ingress_cn_mode,omitempty"`
	IngressCNProvinces   []string        `json:"ingress_cn_provinces,omitempty"`
	IngressPolicies      []ingressPolicy `json:"ingress_whitelist_policies,omitempty"`
	EgressCNMode         string          `json:"egress_cn_mode,omitempty"`
	EgressCNProvinces    []string        `json:"egress_cn_provinces,omitempty"`
}

type ingressPolicy struct {
	ID          uint16   `json:"id"`
	Source      string   `json:"source,omitempty"`
	ListenPort  uint16   `json:"listen_port,omitempty"`
	CNMode      string   `json:"cn_mode,omitempty"`
	CNProvinces []string `json:"cn_provinces,omitempty"`
	CNCityCodes []string `json:"cn_city_codes,omitempty"`
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
	WhitelistPolicyID   uint16   `json:"whitelist_policy_id,omitempty"`
	RemoteInput         string   `json:"remote_input,omitempty"`
	Comment             string   `json:"comment,omitempty"`
}

type statusPayload struct {
	Applied                bool            `json:"applied"`
	BinaryVersion          string          `json:"binary_version"`
	AppliedAt              string          `json:"applied_at,omitempty"`
	Interface              string          `json:"interface,omitempty"`
	InterfaceIndex         int             `json:"interface_index,omitempty"`
	GuardMode              string          `json:"guard_mode,omitempty"`
	XDPEffective           string          `json:"xdp_effective,omitempty"`
	XDPAttachKind          string          `json:"xdp_attach_kind,omitempty"`
	XDPReason              string          `json:"xdp_reason,omitempty"`
	IngressKind            string          `json:"ingress_kind,omitempty"`
	HostEgressEnabled      bool            `json:"host_egress_enabled,omitempty"`
	HostEgressInterfaces   []string        `json:"host_egress_interfaces,omitempty"`
	LoopbackKind           string          `json:"loopback_kind,omitempty"`
	SkLookupKind           string          `json:"sk_lookup_kind,omitempty"`
	ProtocolGuard          bool            `json:"protocol_guard,omitempty"`
	RuntimeFile            string          `json:"runtime_file,omitempty"`
	StateFile              string          `json:"state_file,omitempty"`
	ConfigHash             string          `json:"config_hash,omitempty"`
	RuntimeEpoch           string          `json:"runtime_epoch,omitempty"`
	DataplaneVersion       int             `json:"dataplane_version,omitempty"`
	MapABIVersion          int             `json:"map_abi_version,omitempty"`
	IncrementalApply       bool            `json:"incremental_apply,omitempty"`
	ReattachReason         string          `json:"reattach_reason,omitempty"`
	PreservedConnections   uint64          `json:"preserved_connections,omitempty"`
	InvalidatedConnections uint64          `json:"invalidated_connections,omitempty"`
	ProfileCounts          map[string]int  `json:"profile_counts,omitempty"`
	Rules                  int             `json:"rules,omitempty"`
	Users                  int             `json:"users,omitempty"`
	XDPPin                 string          `json:"xdp_pin,omitempty"`
	IngressPin             string          `json:"ingress_pin,omitempty"`
	HostEgressPin          string          `json:"host_egress_pin,omitempty"`
	LoopbackPin            string          `json:"loopback_pin,omitempty"`
	SkLookupPin            string          `json:"sk_lookup_pin,omitempty"`
	RuleCounterPin         string          `json:"rule_counter_pin,omitempty"`
	UserCounterPin         string          `json:"user_counter_pin,omitempty"`
	StatsPin               string          `json:"stats_pin,omitempty"`
	AuxStateVersion        int             `json:"aux_state_version,omitempty"`
	AuxState               runtimeAuxState `json:"aux_state,omitempty"`
	ActiveSummary          *connSummary    `json:"active_summary,omitempty"`
	RefreshReport          *refreshReport  `json:"refresh_report,omitempty"`
}

type refreshReport struct {
	Mode                    string             `json:"mode"`
	Reason                  string             `json:"reason,omitempty"`
	StartedAt               string             `json:"started_at,omitempty"`
	CompletedAt             string             `json:"completed_at,omitempty"`
	TotalDurationMillis     int64              `json:"total_duration_ms"`
	LoadDurationMillis      int64              `json:"load_duration_ms"`
	MapLoadDurationMillis   int64              `json:"map_load_duration_ms"`
	ReconcileDurationMillis int64              `json:"reconcile_duration_ms"`
	StatusDurationMillis    int64              `json:"status_duration_ms"`
	PreservedConnections    uint64             `json:"preserved_connections"`
	InvalidatedConnections  uint64             `json:"invalidated_connections"`
	RulesAdded              uint64             `json:"rules_added"`
	RulesUpdated            uint64             `json:"rules_updated"`
	RulesDeleted            uint64             `json:"rules_deleted"`
	UsersAdded              uint64             `json:"users_added"`
	UsersUpdated            uint64             `json:"users_updated"`
	UsersDeleted            uint64             `json:"users_deleted"`
	CountersPreserved       uint64             `json:"counters_preserved"`
	CountersReset           uint64             `json:"counters_reset"`
	Rules                   int                `json:"rules"`
	Users                   int                `json:"users"`
	AuxActions              []auxActionSummary `json:"aux_actions,omitempty"`
	AttachTimings           []attachTiming     `json:"attach_timings,omitempty"`
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
	AuxActions        []auxActionSummary
}

type runtimeMapPins struct {
	Settings               string
	Rules                  string
	Connections            string
	Reverse                string
	RuleCounter            string
	RuleReplyCounter       string
	RuleDropCounter        string
	UserCounter            string
	Stats                  string
	WhitelistV4            string
	WhitelistV6            string
	WhitelistCacheV4       string
	WhitelistCacheV6       string
	IngressGeoV4           string
	IngressGeoV6           string
	IngressCityV4          string
	IngressPolicyModes     string
	IngressPolicyProvinces string
	IngressPolicyCities    string
	EgressWhitelistV4      string
	EgressWhitelistV6      string
	EgressWhitelistCacheV4 string
	EgressWhitelistCacheV6 string
	AllowedFlows           string
	AllowedFlowsV4         string
	HostEgressFlows        string
	SkipPorts              string
}

type xdpSettings struct {
	WhitelistEnabled      uint8
	BlockHTTP             uint8
	BlockTLS              uint8
	BlockSOCKS            uint8
	GuardEnabled          uint8
	HasSkipPorts          uint8
	EgressWhitelistCustom uint8
	EgressWhitelistGeo    uint8
	Pad                   [4]uint8
	ExternalIfindex       uint32
	LoopbackIfindex       uint32
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
	WhitelistPolicyID        uint16
	PadRule                  uint16
	PadRuleAlign             [4]uint8
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
	LastSeenNS         uint64
}

type whitelistLeaseActivityRow struct {
	Address    string `json:"address"`
	LastSeenAt int64  `json:"last_seen_at"`
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

type whitelistKeyV4 struct {
	PrefixLen uint32
	Addr      uint32
}

type whitelistKeyV6 struct {
	PrefixLen uint32
	Addr      [16]byte
}

type whitelistCacheKeyV6 struct {
	PolicyID uint16
	Pad      uint16
	Addr     [16]byte
}

type whitelistCacheKeyV4 struct {
	PolicyID uint16
	Pad      uint16
	Addr     uint32
}

type ingressPolicyModeVal struct {
	CNMode    uint8
	HasCities uint8
	Pad       [2]uint8
}

type ingressPolicyProvinceKey struct {
	PolicyID   uint16
	ProvinceID uint16
}

type ingressPolicyCityKey struct {
	PolicyID uint16
	Pad      uint16
	CityCode uint32
}

type flowKey struct {
	Family   uint8
	Protocol uint8
	Sport    uint16
	Dport    uint16
	Saddr    [16]byte
	Daddr    [16]byte
}

type flowKeyV4 struct {
	Family   uint8
	Protocol uint8
	Sport    uint16
	Dport    uint16
	Pad16    uint16
	Saddr    uint32
	Daddr    uint32
}

type guardFlowVal struct {
	Verdict uint8
	SeenLen uint8
	Pad     [6]uint8
	Prefix  [8]uint8
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
	case "__geo-build":
		return runGeoBuild(args[1:])
	case "geo-check":
		return runGeoCheck(args[1:])
	case "geo-export":
		return runGeoExport(args[1:])
	case "city-export":
		return runCityExport(args[1:])
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
	case "whitelist-lease-activity":
		return runWhitelistLeaseActivity(args[1:])
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

func runGeoBuild(args []string) error {
	fs := flag.NewFlagSet("__geo-build", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var assetDir string
	fs.StringVar(&assetDir, "asset-dir", "", "geo asset output dir")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("__geo-build 不接受额外参数")
	}
	if assetDir == "" {
		return fmt.Errorf("__geo-build 缺少 --asset-dir")
	}
	return buildGeoAssets(geoBuilderOptions{AssetDir: assetDir})
}

func runGeoCheck(args []string) error {
	fs := flag.NewFlagSet("geo-check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts geoCheckOptions
	fs.StringVar(&opts.AssetDir, "asset-dir", "", "geo asset dir")
	fs.StringVar(&opts.Address, "address", "", "ip address")
	fs.StringVar(&opts.Mode, "mode", "all", "off|all|provinces")
	fs.StringVar(&opts.ProvinceCSV, "provinces", "", "comma separated province names")
	fs.StringVar(&opts.CityFile, "city-file", "", "selected ingress city whitelist tsv")
	fs.StringVar(&opts.WhitelistFile, "whitelist-file", "", "colon separated ingress custom cidr files")
	fs.StringVar(&opts.EgressWhitelistFile, "egress-whitelist-file", "", "colon separated egress custom cidr files")
	fs.BoolVar(&opts.JSON, "json", false, "print machine-readable decision result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("geo-check 不接受额外参数")
	}
	if opts.AssetDir == "" {
		return fmt.Errorf("geo-check 缺少 --asset-dir")
	}
	if opts.Address == "" {
		return fmt.Errorf("geo-check 缺少 --address")
	}
	return geoCheck(opts)
}

func runGeoExport(args []string) error {
	fs := flag.NewFlagSet("geo-export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts geoExportOptions
	fs.StringVar(&opts.AssetDir, "asset-dir", "", "geo asset dir")
	fs.StringVar(&opts.Mode, "mode", "all", "off|all|provinces")
	fs.StringVar(&opts.ProvinceCSV, "provinces", "", "comma separated province names")
	fs.StringVar(&opts.IPVersion, "ip-version", "46", "4|6|46")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("geo-export 不接受额外参数")
	}
	return geoExport(opts)
}

func runCityExport(args []string) error {
	fs := flag.NewFlagSet("city-export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts cityExportOptions
	fs.StringVar(&opts.AssetDir, "asset-dir", "", "geo asset dir")
	fs.StringVar(&opts.CodesFile, "codes-file", "", "selected city codes file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("city-export 不接受额外参数")
	}
	return cityExport(opts)
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
	fs.StringVar(&opts.HostEgressPin, "host-egress-pin", "", "bpffs host egress tc program pin")
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
	fs.StringVar(&opts.HostEgressPin, "host-egress-pin", "", "bpffs host egress tc program pin")
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

func runWhitelistLeaseActivity(args []string) error {
	fs := flag.NewFlagSet("whitelist-lease-activity", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts statsOptions
	fs.StringVar(&opts.StatusFile, "status-file", "", "status json")
	fs.StringVar(&opts.StatsPin, "stats-pin", "/sys/fs/bpf/pfwd_stats", "bpffs stats map pin")
	var ruleCounterPin string
	var userCounterPin string
	fs.StringVar(&ruleCounterPin, "rule-counter-pin", "/sys/fs/bpf/pfwd_rule_counters", "bpffs rule counter map pin")
	fs.StringVar(&userCounterPin, "user-counter-pin", "/sys/fs/bpf/pfwd_user_counters", "bpffs user counter map pin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("whitelist-lease-activity 不接受额外参数")
	}
	rows, err := whitelistLeaseActivity(runtimeMapPinsFromPaths(ruleCounterPin, userCounterPin, opts.StatsPin))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}
