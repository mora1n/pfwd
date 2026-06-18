//go:build !geobuild

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

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
	if runtimeData.Settings.HostEgressEnabled && opts.HostEgressPin == "" {
		return fmt.Errorf("缺少 --host-egress-pin")
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
			HostEgressPin:  opts.HostEgressPin,
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
	hostEgressIfaces := []net.Interface{}
	hostEgressNames := []string{}
	if runtimeData.Settings.HostEgressEnabled {
		hostEgressIfaces, err = listHostEgressInterfaces()
		if err != nil {
			return err
		}
		if len(hostEgressIfaces) == 0 {
			return fmt.Errorf("未发现可附着宿主机出口白名单的非 loopback 网卡")
		}
		hostEgressNames = interfaceNames(hostEgressIfaces)
	}
	currentStatus, _ := readStatus(opts.StatusFile)
	protocolGuard := protocolGuardEnabled(runtimeData.Settings)
	needIngress := opts.GuardMode == "ingress" || (protocolGuard && guardIngressEnabled(runtimeData.Settings))
	runtimeSemanticConfigHash, err := runtimeSemanticHash(runtimeData)
	if err != nil {
		return err
	}
	if runtimeStatusReusable(currentStatus, runtimeData.Settings, opts, iface.Name, hostEgressNames, runtimeSemanticConfigHash) &&
		pinnedRuntimeMapsCompatible(opts) {
		return nil
	}
	if canIncrementalApply(currentStatus, runtimeData, opts, iface, needIngress, hostEgressNames) {
		if err := applyIncrementalRuntime(currentStatus, runtimeData, opts, iface, protocolGuard, hostEgressNames); err == nil {
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
		HostEgressPin:  opts.HostEgressPin,
		LoopbackPin:    opts.LoopbackPin,
		SkLookupPin:    opts.SkLookupPin,
		RuleCounterPin: opts.RuleCounterPin,
		UserCounterPin: opts.UserCounterPin,
		StatsPin:       opts.StatsPin,
	}); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("清理旧运行态失败: %w", err)
	}
	objs, err := loadObjects(opts.GuardMode, runtimeData.Settings.HostEgressEnabled)
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
	attachTimings := make([]attachTiming, 0, 5)
	if opts.GuardMode == "full" {
		xdpAttachStart := time.Now()
		xdpEffective, xdpKind, xdpReason, err = attachXDP(iface, objs.PFWDXDP, opts)
		if err != nil {
			return err
		}
		recordAttachTiming(&attachTimings, "xdp", xdpAttachStart)
	} else if err := removeXDPLink(opts.XDPPin); err != nil {
		return err
	}
	ingressKind := ""
	if needIngress {
		ingressStart := time.Now()
		ingressKind, err = attachIngress(iface, objs.PFWDIngress, opts.IngressPin)
		if err != nil {
			return err
		}
		recordAttachTiming(&attachTimings, "ingress", ingressStart)
	} else if err := removeIngressRuntime(opts.IngressPin, iface.Name); err != nil {
		return err
	}
	if runtimeData.Settings.HostEgressEnabled {
		hostEgressStart := time.Now()
		if hostEgressNames, err = attachHostEgress(hostEgressIfaces, objs.PFWDHostEgress, opts.HostEgressPin); err != nil {
			return err
		}
		recordAttachTiming(&attachTimings, "host_egress", hostEgressStart)
	} else if err := removeHostEgressRuntime(opts.HostEgressPin, nil); err != nil {
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
	if len(hostEgressNames) > 0 && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "pfwd-xdp: host egress attached on %s\n", strings.Join(hostEgressNames, ","))
	}
	if loopbackKind != "" && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "pfwd-xdp: loopback egress attached via %s\n", loopbackKind)
	}
	if skLookupKind != "" && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "pfwd-xdp: sk_lookup attached via %s\n", skLookupKind)
	}
	statusStart := time.Now()
	payload := statusPayload{
		Applied:              true,
		BinaryVersion:        binaryVersion,
		AppliedAt:            time.Now().UTC().Format(time.RFC3339),
		Interface:            iface.Name,
		InterfaceIndex:       iface.Index,
		GuardMode:            opts.GuardMode,
		XDPEffective:         xdpEffective,
		XDPAttachKind:        xdpKind,
		XDPReason:            xdpReason,
		IngressKind:          ingressKind,
		HostEgressEnabled:    runtimeData.Settings.HostEgressEnabled,
		HostEgressInterfaces: hostEgressNames,
		LoopbackKind:         loopbackKind,
		SkLookupKind:         skLookupKind,
		ProtocolGuard:        protocolGuard,
		RuntimeFile:          opts.RuntimeFile,
		StateFile:            opts.StateFile,
		ConfigHash:           runtimeSemanticConfigHash,
		RuntimeEpoch:         runtimeSemanticConfigHash,
		DataplaneVersion:     dataplaneVersion,
		MapABIVersion:        mapABIVersion,
		IncrementalApply:     false,
		ReattachReason:       "full-reattach",
		ProfileCounts:        profileCounts(runtimeData),
		Rules:                len(runtimeData.Rules),
		Users:                len(runtimeData.Users),
		XDPPin:               opts.XDPPin,
		IngressPin:           opts.IngressPin,
		HostEgressPin:        opts.HostEgressPin,
		LoopbackPin:          opts.LoopbackPin,
		SkLookupPin:          opts.SkLookupPin,
		RuleCounterPin:       opts.RuleCounterPin,
		UserCounterPin:       opts.UserCounterPin,
		StatsPin:             opts.StatsPin,
		AuxStateVersion:      auxStateVersion,
	}
	if payload.AuxState, err = runtimeAuxStateFromRuntime(runtimeData); err != nil {
		return err
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
		AuxActions: []auxActionSummary{
			{Component: "whitelist", Action: "reload", ChangedItems: len(payload.AuxState.WhitelistHashes)},
			{Component: "protocol_skip_ports", Action: "reload", ChangedItems: len(normalizeProtocolSkipPorts(payload.AuxState.ProtocolSkipPorts))},
			{Component: "egress_whitelist", Action: "reload", ChangedItems: len(payload.AuxState.EgressWhitelistHashes)},
			{Component: "host_egress_drop_cache", Action: "reload"},
			{Component: "guard_runtime_cache", Action: "reload"},
		},
		AttachTimings: attachTimings,
	}
	return writeStatus(opts.StatusFile, payload)
}

func loadObjects(guardMode string, hostEgressEnabled bool) (*bpfObjects, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpBPFEL))
	if err != nil {
		return nil, fmt.Errorf("加载 eBPF spec 失败: %w", err)
	}
	delete(spec.Programs, "pfwd_loopback_egress")
	delete(spec.Programs, "pfwd_sk_lookup")
	if !hostEgressEnabled {
		delete(spec.Programs, "pfwd_host_egress")
	}
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
		PFWDXDP:                    coll.Programs["pfwd_xdp"],
		PFWDIngress:                coll.Programs["pfwd_ingress"],
		PFWDHostEgress:             coll.Programs["pfwd_host_egress"],
		PFWDLoopbackEgress:         coll.Programs["pfwd_loopback_egress"],
		PFWDSkLookup:               coll.Programs["pfwd_sk_lookup"],
		PFWDSettings:               coll.Maps["pfwd_settings"],
		PFWDRules:                  coll.Maps["pfwd_rules"],
		PFWDConnections:            coll.Maps["pfwd_connections"],
		PFWDReverse:                coll.Maps["pfwd_reverse"],
		PFWDRuleCounter:            coll.Maps["pfwd_rule_counters"],
		PFWDRuleReplyCounter:       coll.Maps["pfwd_rule_reply_counters"],
		PFWDRuleDropCounter:        coll.Maps["pfwd_rule_drop_counters"],
		PFWDUserCounter:            coll.Maps["pfwd_user_counters"],
		PFWDStats:                  coll.Maps["pfwd_stats"],
		PFWDWhitelistV4:            coll.Maps["pfwd_whitelist_v4"],
		PFWDWhitelistV6:            coll.Maps["pfwd_whitelist_v6"],
		PFWDWhitelistCacheV4:       coll.Maps["pfwd_whitelist_cache_v4"],
		PFWDWhitelistCacheV6:       coll.Maps["pfwd_whitelist_cache_v6"],
		PFWDIngressGeoV4:           coll.Maps["pfwd_ingress_geo_v4"],
		PFWDIngressGeoV6:           coll.Maps["pfwd_ingress_geo_v6"],
		PFWDIngressCityV4:          coll.Maps["pfwd_ingress_city_v4"],
		PFWDIngressPolicyModes:     coll.Maps["pfwd_ingress_policy_modes"],
		PFWDIngressPolicyProvinces: coll.Maps["pfwd_ingress_policy_provinces"],
		PFWDIngressPolicyCities:    coll.Maps["pfwd_ingress_policy_cities"],
		PFWDEgressWhitelistV4:      coll.Maps["pfwd_egress_whitelist_v4"],
		PFWDEgressWhitelistV6:      coll.Maps["pfwd_egress_whitelist_v6"],
		PFWDEgressWhitelistCacheV4: coll.Maps["pfwd_egress_whitelist_cache_v4"],
		PFWDEgressWhitelistCacheV6: coll.Maps["pfwd_egress_whitelist_cache_v6"],
		PFWDFlows:                  coll.Maps["pfwd_allowed_flows"],
		PFWDFlowsV4:                coll.Maps["pfwd_allowed_flows_v4"],
		PFWDHostEgressFlows:        coll.Maps["pfwd_host_egress_flows"],
		PFWDSkipPorts:              coll.Maps["pfwd_protocol_skip_ports"],
		PFWDScratch:                coll.Maps["pfwd_scratch"],
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

func runtimeStatusReusable(
	currentStatus statusPayload,
	settings runtimeSettings,
	opts applyOptions,
	ifaceName string,
	hostEgressNames []string,
	runtimeSemanticConfigHash string,
) bool {
	if !currentStatus.Applied {
		return false
	}
	if currentStatus.BinaryVersion != binaryVersion {
		return false
	}
	if currentStatus.MapABIVersion != mapABIVersion {
		return false
	}
	if currentStatus.ConfigHash != runtimeSemanticConfigHash {
		return false
	}
	if currentStatus.GuardMode != opts.GuardMode {
		return false
	}
	if currentStatus.Interface != ifaceName {
		return false
	}
	if currentStatus.HostEgressEnabled != settings.HostEgressEnabled {
		return false
	}
	if settings.HostEgressEnabled && !stringSlicesEqual(currentStatus.HostEgressInterfaces, hostEgressNames) {
		return false
	}
	if settings.HostEgressEnabled && !pinnedPathExists(firstNonEmpty(opts.HostEgressPin, currentStatus.HostEgressPin)) {
		return false
	}
	return true
}

func runtimeSemanticHash(runtimeData *runtimeFile) (string, error) {
	if runtimeData == nil {
		return "", fmt.Errorf("runtime 为空")
	}
	hashes, err := whitelistFileHashes(runtimeData.Settings.WhitelistFiles)
	if err != nil {
		return "", err
	}
	egressHashes, err := whitelistFileHashes(runtimeData.Settings.EgressWhitelistFiles)
	if err != nil {
		return "", err
	}
	geoHashes, err := geoAssetHashes(runtimeData.Settings.GeoAssetDir)
	if err != nil {
		return "", err
	}
	settings := runtimeSemanticSettings{
		Interface:          runtimeData.Settings.Interface,
		GuardEnabled:       runtimeData.Settings.GuardEnabled,
		WhitelistEnabled:   runtimeData.Settings.WhitelistEnabled,
		HostEgressEnabled:  runtimeData.Settings.HostEgressEnabled,
		BlockHTTP:          runtimeData.Settings.BlockHTTP,
		BlockTLS:           runtimeData.Settings.BlockTLS,
		BlockSOCKS:         runtimeData.Settings.BlockSOCKS,
		ProtocolSkipPorts:  runtimeData.Settings.ProtocolSkipPorts,
		GuardIngressMode:   runtimeData.Settings.GuardIngressMode,
		IngressCNMode:      runtimeData.Settings.IngressCNMode,
		EgressCNMode:       runtimeData.Settings.EgressCNMode,
		IngressCNProvinces: append([]string{}, runtimeData.Settings.IngressCNProvinces...),
		IngressPolicies:    normalizeIngressPolicies(runtimeData.Settings),
		EgressCNProvinces:  append([]string{}, runtimeData.Settings.EgressCNProvinces...),
	}
	rules := make([]runtimeSemanticRule, 0, len(runtimeData.Rules))
	for _, rule := range runtimeData.Rules {
		semanticRule := runtimeSemanticRule{
			Index:             rule.Index,
			UserIndex:         rule.UserIndex,
			ListenIP:          rule.ListenIP,
			ListenPort:        rule.ListenPort,
			Protocol:          rule.Protocol,
			IPVersion:         rule.IPVersion,
			ResolvedTarget:    rule.ResolvedTarget,
			RemotePort:        rule.RemotePort,
			SNATMode:          rule.SNATMode,
			SNATSource:        rule.SNATSource,
			MSSMode:           rule.MSSMode,
			MSSValue:          rule.MSSValue,
			TrafficMode:       rule.TrafficMode,
			TrafficRatio:      rule.TrafficRatio,
			RuleLimit:         rule.RuleLimit,
			UserLimit:         rule.UserLimit,
			XDPDisabled:       rule.XDPDisabled,
			WhitelistPolicyID: rule.WhitelistPolicyID,
		}
		if rule.RuleLimit > 0 || rule.UserLimit > 0 {
			semanticRule.BillingUsedBase = rule.BillingUsedBase
			semanticRule.UserBillingUsedBase = rule.UserBillingUsedBase
		}
		rules = append(rules, semanticRule)
	}
	payload := struct {
		Settings              runtimeSemanticSettings `json:"settings"`
		Rules                 []runtimeSemanticRule   `json:"rules"`
		WhitelistHashes       []whitelistContentHash  `json:"whitelist_hashes"`
		EgressWhitelistHashes []whitelistContentHash  `json:"egress_whitelist_hashes"`
		GeoAssetHashes        []whitelistContentHash  `json:"geo_asset_hashes"`
	}{
		Settings:              settings,
		Rules:                 rules,
		WhitelistHashes:       hashes,
		EgressWhitelistHashes: egressHashes,
		GeoAssetHashes:        geoHashes,
	}
	content, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("序列化 runtime 语义 hash 失败: %w", err)
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}
