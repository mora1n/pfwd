//go:build !geobuild

package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

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
		Settings:               filepath.Join(dir, namespace+"_settings"),
		Rules:                  filepath.Join(dir, namespace+"_rules"),
		Connections:            filepath.Join(dir, namespace+"_connections"),
		Reverse:                filepath.Join(dir, namespace+"_reverse"),
		RuleCounter:            ruleCounterPin,
		RuleReplyCounter:       filepath.Join(dir, namespace+"_rule_reply_counters"),
		RuleDropCounter:        filepath.Join(dir, namespace+"_rule_drop_counters"),
		UserCounter:            userCounterPin,
		Stats:                  statsPin,
		WhitelistV4:            filepath.Join(dir, namespace+"_whitelist_v4"),
		WhitelistV6:            filepath.Join(dir, namespace+"_whitelist_v6"),
		WhitelistCacheV4:       filepath.Join(dir, namespace+"_whitelist_cache_v4"),
		WhitelistCacheV6:       filepath.Join(dir, namespace+"_whitelist_cache_v6"),
		IngressGeoV4:           filepath.Join(dir, namespace+"_ingress_geo_v4"),
		IngressGeoV6:           filepath.Join(dir, namespace+"_ingress_geo_v6"),
		IngressCityV4:          filepath.Join(dir, namespace+"_ingress_city_v4"),
		IngressPolicyModes:     filepath.Join(dir, namespace+"_ingress_policy_modes"),
		IngressPolicyProvinces: filepath.Join(dir, namespace+"_ingress_policy_provinces"),
		IngressPolicyCities:    filepath.Join(dir, namespace+"_ingress_policy_cities"),
		EgressWhitelistV4:      filepath.Join(dir, namespace+"_egress_whitelist_v4"),
		EgressWhitelistV6:      filepath.Join(dir, namespace+"_egress_whitelist_v6"),
		EgressWhitelistCacheV4: filepath.Join(dir, namespace+"_egress_whitelist_cache_v4"),
		EgressWhitelistCacheV6: filepath.Join(dir, namespace+"_egress_whitelist_cache_v6"),
		AllowedFlows:           filepath.Join(dir, namespace+"_allowed_flows"),
		AllowedFlowsV4:         filepath.Join(dir, namespace+"_allowed_flows_v4"),
		HostEgressFlows:        filepath.Join(dir, namespace+"_host_egress_flows"),
		SkipPorts:              filepath.Join(dir, namespace+"_protocol_skip_ports"),
	}
}

func legacyRuntimeMapPinsFromRuleCounterPin(ruleCounterPin string) []string {
	dir := filepath.Dir(ruleCounterPin)
	namespace := runtimePinNamespace(ruleCounterPin)
	return []string{
		filepath.Join(dir, namespace+"_guard_prefixes"),
		filepath.Join(dir, namespace+"_geo_bucket_v4"),
		filepath.Join(dir, namespace+"_geo_bucket_v6"),
		filepath.Join(dir, namespace+"_geo_segments_v4"),
		filepath.Join(dir, namespace+"_geo_segments_v6"),
		filepath.Join(dir, namespace+"_geo_province_policy"),
	}
}

func cleanupLegacyRuntimeMapPins(ruleCounterPin string) {
	for _, path := range legacyRuntimeMapPinsFromRuleCounterPin(ruleCounterPin) {
		if strings.TrimSpace(path) == "" {
			continue
		}
		_ = os.Remove(path)
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

func hasWhitelistFiles(files []string) bool {
	for _, filePath := range files {
		if strings.TrimSpace(filePath) != "" {
			return true
		}
	}
	return false
}

func effectiveDataplaneSettings(runtimeData *runtimeFile, opts applyOptions) runtimeSettings {
	settings := runtimeData.Settings
	settings.WhitelistFiles = effectiveWhitelistFiles(runtimeData, opts)
	return settings
}

func makeXDPSettings(settings runtimeSettings, externalIfindex uint32) xdpSettings {
	egressCustom := hasWhitelistFiles(settings.EgressWhitelistFiles)
	egressGeo := geoModeEnabled(settings.EgressCNMode)
	return xdpSettings{
		WhitelistEnabled:      boolToUint8(settings.WhitelistEnabled),
		BlockHTTP:             boolToUint8(settings.BlockHTTP),
		BlockTLS:              boolToUint8(settings.BlockTLS),
		BlockSOCKS:            boolToUint8(settings.BlockSOCKS),
		GuardEnabled:          boolToUint8(settings.GuardEnabled),
		HasSkipPorts:          boolToUint8(len(settings.ProtocolSkipPorts) > 0),
		EgressWhitelistCustom: boolToUint8(egressCustom),
		EgressWhitelistGeo:    boolToUint8(egressGeo),
		ExternalIfindex:       externalIfindex,
		LoopbackIfindex:       0,
	}
}

func loadMaps(objs *bpfObjects, runtimeData *runtimeFile, opts applyOptions) error {
	if objs.PFWDSettings == nil || objs.PFWDRules == nil || objs.PFWDRuleCounter == nil || objs.PFWDRuleReplyCounter == nil || objs.PFWDRuleDropCounter == nil || objs.PFWDUserCounter == nil {
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
	dataplaneSettings := effectiveDataplaneSettings(runtimeData, opts)
	settings := makeXDPSettings(dataplaneSettings, externalIfindex)
	key := uint32(0)
	if err := objs.PFWDSettings.Update(&key, &settings, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("写入 settings 失败: %w", err)
	}
	if err := loadProtocolSkipPorts(objs.PFWDSkipPorts, runtimeData.Settings.ProtocolSkipPorts); err != nil {
		return err
	}
	if runtimeData.Settings.WhitelistEnabled {
		if objs.PFWDWhitelistV4 == nil || objs.PFWDWhitelistV6 == nil || objs.PFWDWhitelistCacheV4 == nil || objs.PFWDWhitelistCacheV6 == nil ||
			objs.PFWDIngressGeoV4 == nil || objs.PFWDIngressGeoV6 == nil || objs.PFWDIngressCityV4 == nil ||
			objs.PFWDIngressPolicyModes == nil || objs.PFWDIngressPolicyProvinces == nil || objs.PFWDIngressPolicyCities == nil {
			return fmt.Errorf("入口白名单 BPF map 未加载")
		}
		if err := loadIngressWhitelist(objs, dataplaneSettings); err != nil {
			return err
		}
	}
	if runtimeData.Settings.HostEgressEnabled {
		if objs.PFWDEgressWhitelistV4 == nil || objs.PFWDEgressWhitelistV6 == nil || objs.PFWDEgressWhitelistCacheV4 == nil || objs.PFWDEgressWhitelistCacheV6 == nil || objs.PFWDHostEgressFlows == nil {
			return fmt.Errorf("宿主机出口白名单 BPF map 未加载")
		}
		if err := loadEffectiveWhitelist(
			objs.PFWDEgressWhitelistV4,
			objs.PFWDEgressWhitelistV6,
			runtimeData.Settings.EgressWhitelistFiles,
			runtimeData.Settings.GeoAssetDir,
			runtimeData.Settings.EgressCNMode,
			runtimeData.Settings.EgressCNProvinces,
		); err != nil {
			return err
		}
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
		if err := putRule(objs, rule, dataplaneSettings, zeroCounter, zeroReplyCounter, zeroDropCounter); err != nil {
			return err
		}
	}
	return nil
}

func pinRuntimeMaps(objs *bpfObjects, opts applyOptions) error {
	pinLayout := runtimeMapPinsFromApplyOptions(opts)
	pins := map[string]*ebpf.Map{
		pinLayout.Settings:               objs.PFWDSettings,
		pinLayout.Rules:                  objs.PFWDRules,
		pinLayout.Connections:            objs.PFWDConnections,
		pinLayout.Reverse:                objs.PFWDReverse,
		pinLayout.RuleCounter:            objs.PFWDRuleCounter,
		pinLayout.RuleReplyCounter:       objs.PFWDRuleReplyCounter,
		pinLayout.RuleDropCounter:        objs.PFWDRuleDropCounter,
		pinLayout.UserCounter:            objs.PFWDUserCounter,
		pinLayout.Stats:                  objs.PFWDStats,
		pinLayout.WhitelistV4:            objs.PFWDWhitelistV4,
		pinLayout.WhitelistV6:            objs.PFWDWhitelistV6,
		pinLayout.WhitelistCacheV4:       objs.PFWDWhitelistCacheV4,
		pinLayout.WhitelistCacheV6:       objs.PFWDWhitelistCacheV6,
		pinLayout.IngressGeoV4:           objs.PFWDIngressGeoV4,
		pinLayout.IngressGeoV6:           objs.PFWDIngressGeoV6,
		pinLayout.IngressCityV4:          objs.PFWDIngressCityV4,
		pinLayout.IngressPolicyModes:     objs.PFWDIngressPolicyModes,
		pinLayout.IngressPolicyProvinces: objs.PFWDIngressPolicyProvinces,
		pinLayout.IngressPolicyCities:    objs.PFWDIngressPolicyCities,
		pinLayout.EgressWhitelistV4:      objs.PFWDEgressWhitelistV4,
		pinLayout.EgressWhitelistV6:      objs.PFWDEgressWhitelistV6,
		pinLayout.EgressWhitelistCacheV4: objs.PFWDEgressWhitelistCacheV4,
		pinLayout.EgressWhitelistCacheV6: objs.PFWDEgressWhitelistCacheV6,
		pinLayout.AllowedFlows:           objs.PFWDFlows,
		pinLayout.AllowedFlowsV4:         objs.PFWDFlowsV4,
		pinLayout.HostEgressFlows:        objs.PFWDHostEgressFlows,
		pinLayout.SkipPorts:              objs.PFWDSkipPorts,
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
	cleanupLegacyRuntimeMapPins(opts.RuleCounterPin)
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
	opened := make([]*ebpf.Map, 0, 20)
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
	whitelistV4, err := load(pinLayout.WhitelistV4, "加载 pinned whitelist_v4 map 失败")
	if err != nil {
		return nil, err
	}
	whitelistV6, err := load(pinLayout.WhitelistV6, "加载 pinned whitelist_v6 map 失败")
	if err != nil {
		return nil, err
	}
	whitelistCacheV4, err := load(pinLayout.WhitelistCacheV4, "加载 pinned whitelist_cache_v4 map 失败")
	if err != nil {
		return nil, err
	}
	whitelistCacheV6, err := load(pinLayout.WhitelistCacheV6, "加载 pinned whitelist_cache_v6 map 失败")
	if err != nil {
		return nil, err
	}
	ingressGeoV4, err := load(pinLayout.IngressGeoV4, "加载 pinned ingress_geo_v4 map 失败")
	if err != nil {
		return nil, err
	}
	ingressGeoV6, err := load(pinLayout.IngressGeoV6, "加载 pinned ingress_geo_v6 map 失败")
	if err != nil {
		return nil, err
	}
	ingressCityV4, err := load(pinLayout.IngressCityV4, "加载 pinned ingress_city_v4 map 失败")
	if err != nil {
		return nil, err
	}
	ingressPolicyModes, err := load(pinLayout.IngressPolicyModes, "加载 pinned ingress_policy_modes map 失败")
	if err != nil {
		return nil, err
	}
	ingressPolicyProvinces, err := load(pinLayout.IngressPolicyProvinces, "加载 pinned ingress_policy_provinces map 失败")
	if err != nil {
		return nil, err
	}
	ingressPolicyCities, err := load(pinLayout.IngressPolicyCities, "加载 pinned ingress_policy_cities map 失败")
	if err != nil {
		return nil, err
	}
	egressWhitelistV4, err := load(pinLayout.EgressWhitelistV4, "加载 pinned egress_whitelist_v4 map 失败")
	if err != nil {
		return nil, err
	}
	egressWhitelistV6, err := load(pinLayout.EgressWhitelistV6, "加载 pinned egress_whitelist_v6 map 失败")
	if err != nil {
		return nil, err
	}
	egressWhitelistCacheV4, err := load(pinLayout.EgressWhitelistCacheV4, "加载 pinned egress_whitelist_cache_v4 map 失败")
	if err != nil {
		return nil, err
	}
	egressWhitelistCacheV6, err := load(pinLayout.EgressWhitelistCacheV6, "加载 pinned egress_whitelist_cache_v6 map 失败")
	if err != nil {
		return nil, err
	}
	allowedFlows, err := load(pinLayout.AllowedFlows, "加载 pinned allowed_flows map 失败")
	if err != nil {
		return nil, err
	}
	allowedFlowsV4, err := load(pinLayout.AllowedFlowsV4, "加载 pinned allowed_flows_v4 map 失败")
	if err != nil {
		return nil, err
	}
	hostEgressFlows, err := load(pinLayout.HostEgressFlows, "加载 pinned host_egress_flows map 失败")
	if err != nil {
		return nil, err
	}
	skipPorts, err := load(pinLayout.SkipPorts, "加载 pinned skip_ports map 失败")
	if err != nil {
		return nil, err
	}
	return &bpfObjects{
		PFWDSettings:               settings,
		PFWDRules:                  rules,
		PFWDConnections:            connections,
		PFWDReverse:                reverse,
		PFWDRuleCounter:            ruleCounter,
		PFWDRuleReplyCounter:       ruleReplyCounter,
		PFWDRuleDropCounter:        ruleDropCounter,
		PFWDUserCounter:            userCounter,
		PFWDStats:                  stats,
		PFWDWhitelistV4:            whitelistV4,
		PFWDWhitelistV6:            whitelistV6,
		PFWDWhitelistCacheV4:       whitelistCacheV4,
		PFWDWhitelistCacheV6:       whitelistCacheV6,
		PFWDIngressGeoV4:           ingressGeoV4,
		PFWDIngressGeoV6:           ingressGeoV6,
		PFWDIngressCityV4:          ingressCityV4,
		PFWDIngressPolicyModes:     ingressPolicyModes,
		PFWDIngressPolicyProvinces: ingressPolicyProvinces,
		PFWDIngressPolicyCities:    ingressPolicyCities,
		PFWDEgressWhitelistV4:      egressWhitelistV4,
		PFWDEgressWhitelistV6:      egressWhitelistV6,
		PFWDEgressWhitelistCacheV4: egressWhitelistCacheV4,
		PFWDEgressWhitelistCacheV6: egressWhitelistCacheV6,
		PFWDFlows:                  allowedFlows,
		PFWDFlowsV4:                allowedFlowsV4,
		PFWDHostEgressFlows:        hostEgressFlows,
		PFWDSkipPorts:              skipPorts,
	}, nil
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
	zero, err := zeroPerCPUCounterValues()
	if err != nil {
		return err
	}
	for i := uint32(0); i < maxEntries; i++ {
		key := i
		if err := m.Update(&key, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("重置 percpu counter 失败 (key=%d): %w", i, err)
		}
	}
	return nil
}

func clearPerCPUReplyCounterMap(m *ebpf.Map, maxEntries uint32) error {
	if m == nil {
		return nil
	}
	zero, err := zeroPerCPUReplyCounterValues()
	if err != nil {
		return err
	}
	for i := uint32(0); i < maxEntries; i++ {
		key := i
		if err := m.Update(&key, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("重置 percpu reply counter 失败 (key=%d): %w", i, err)
		}
	}
	return nil
}

func clearPerCPUDropCounterMap(m *ebpf.Map, maxEntries uint32) error {
	if m == nil {
		return nil
	}
	zero, err := zeroPerCPUDropCounterValues()
	if err != nil {
		return err
	}
	for i := uint32(0); i < maxEntries; i++ {
		key := i
		if err := m.Update(&key, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("重置 percpu drop counter 失败 (key=%d): %w", i, err)
		}
	}
	return nil
}

func clearPerCPUUserCounterMap(m *ebpf.Map, maxEntries uint32) error {
	if m == nil {
		return nil
	}
	zero, err := zeroPerCPUUserCounterValues()
	if err != nil {
		return err
	}
	for i := uint32(0); i < maxEntries; i++ {
		key := i
		if err := m.Update(&key, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("重置 percpu user counter 失败 (key=%d): %w", i, err)
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

func clearPortArrayMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	zero := uint8(0)
	for i := uint32(0); i < protocolSkipPortEntries; i++ {
		key := i
		if err := m.Update(&key, &zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("重置 skip-port array 失败 (key=%d): %w", i, err)
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
	if err := clearMap[whitelistCacheKeyV4, uint8](objs.PFWDWhitelistCacheV4); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV6, uint8](objs.PFWDWhitelistCacheV6); err != nil {
		return err
	}
	if err := clearIngressGeoPolicyMaps(objs); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV4, uint8](objs.PFWDEgressWhitelistV4); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV6, uint8](objs.PFWDEgressWhitelistV6); err != nil {
		return err
	}
	if err := clearMap[uint32, uint8](objs.PFWDEgressWhitelistCacheV4); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV6, uint8](objs.PFWDEgressWhitelistCacheV6); err != nil {
		return err
	}
	if err := clearAllowedFlows(objs.PFWDFlows, objs.PFWDFlowsV4); err != nil {
		return err
	}
	if err := clearMap[flowKey, uint8](objs.PFWDHostEgressFlows); err != nil {
		return err
	}
	if err := clearPortArrayMap(objs.PFWDSkipPorts); err != nil {
		return err
	}
	if err := clearPerCPUCounterMap(objs.PFWDRuleCounter, maxRules); err != nil {
		return err
	}
	if err := clearPerCPUReplyCounterMap(objs.PFWDRuleReplyCounter, maxRules); err != nil {
		return err
	}
	if err := clearPerCPUDropCounterMap(objs.PFWDRuleDropCounter, maxRules); err != nil {
		return err
	}
	if err := clearPerCPUUserCounterMap(objs.PFWDUserCounter, maxUsers); err != nil {
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
	if err := clearMap[whitelistCacheKeyV4, uint8](objs.PFWDWhitelistCacheV4); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV6, uint8](objs.PFWDWhitelistCacheV6); err != nil {
		return err
	}
	if err := clearIngressGeoPolicyMaps(objs); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV4, uint8](objs.PFWDEgressWhitelistV4); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV6, uint8](objs.PFWDEgressWhitelistV6); err != nil {
		return err
	}
	if err := clearMap[uint32, uint8](objs.PFWDEgressWhitelistCacheV4); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV6, uint8](objs.PFWDEgressWhitelistCacheV6); err != nil {
		return err
	}
	if err := clearAllowedFlows(objs.PFWDFlows, objs.PFWDFlowsV4); err != nil {
		return err
	}
	if err := clearMap[flowKey, uint8](objs.PFWDHostEgressFlows); err != nil {
		return err
	}
	if err := clearPortArrayMap(objs.PFWDSkipPorts); err != nil {
		return err
	}
	if err := clearPerCPUCounterMap(objs.PFWDRuleCounter, maxRules); err != nil {
		return err
	}
	if err := clearPerCPUReplyCounterMap(objs.PFWDRuleReplyCounter, maxRules); err != nil {
		return err
	}
	if err := clearPerCPUDropCounterMap(objs.PFWDRuleDropCounter, maxRules); err != nil {
		return err
	}
	if err := clearPerCPUUserCounterMap(objs.PFWDUserCounter, maxUsers); err != nil {
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
	if err := clearMap[whitelistCacheKeyV4, uint8](objs.PFWDWhitelistCacheV4); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV6, uint8](objs.PFWDWhitelistCacheV6); err != nil {
		return err
	}
	if err := clearIngressGeoPolicyMaps(objs); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV4, uint8](objs.PFWDEgressWhitelistV4); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV6, uint8](objs.PFWDEgressWhitelistV6); err != nil {
		return err
	}
	if err := clearMap[uint32, uint8](objs.PFWDEgressWhitelistCacheV4); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV6, uint8](objs.PFWDEgressWhitelistCacheV6); err != nil {
		return err
	}
	if err := clearAllowedFlows(objs.PFWDFlows, objs.PFWDFlowsV4); err != nil {
		return err
	}
	if err := clearPortArrayMap(objs.PFWDSkipPorts); err != nil {
		return err
	}
	return nil
}

func clearVerdictEntriesByValue(m *ebpf.Map, verdict uint8) error {
	if m == nil {
		return nil
	}
	it := m.Iterate()
	var key flowKey
	var value uint8
	for it.Next(&key, &value) {
		if value != verdict {
			continue
		}
		keyCopy := key
		if err := m.Delete(&keyCopy); err != nil {
			return fmt.Errorf("删除 verdict entry 失败: %w", err)
		}
	}
	return it.Err()
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
		"pfwd_settings":                  pinLayout.Settings,
		"pfwd_rules":                     pinLayout.Rules,
		"pfwd_connections":               pinLayout.Connections,
		"pfwd_reverse":                   pinLayout.Reverse,
		"pfwd_rule_counters":             pinLayout.RuleCounter,
		"pfwd_rule_reply_counters":       pinLayout.RuleReplyCounter,
		"pfwd_rule_drop_counters":        pinLayout.RuleDropCounter,
		"pfwd_user_counters":             pinLayout.UserCounter,
		"pfwd_stats":                     pinLayout.Stats,
		"pfwd_whitelist_v4":              pinLayout.WhitelistV4,
		"pfwd_whitelist_v6":              pinLayout.WhitelistV6,
		"pfwd_whitelist_cache_v4":        pinLayout.WhitelistCacheV4,
		"pfwd_whitelist_cache_v6":        pinLayout.WhitelistCacheV6,
		"pfwd_ingress_geo_v4":            pinLayout.IngressGeoV4,
		"pfwd_ingress_geo_v6":            pinLayout.IngressGeoV6,
		"pfwd_ingress_city_v4":           pinLayout.IngressCityV4,
		"pfwd_ingress_policy_modes":      pinLayout.IngressPolicyModes,
		"pfwd_ingress_policy_provinces":  pinLayout.IngressPolicyProvinces,
		"pfwd_ingress_policy_cities":     pinLayout.IngressPolicyCities,
		"pfwd_egress_whitelist_v4":       pinLayout.EgressWhitelistV4,
		"pfwd_egress_whitelist_v6":       pinLayout.EgressWhitelistV6,
		"pfwd_egress_whitelist_cache_v4": pinLayout.EgressWhitelistCacheV4,
		"pfwd_egress_whitelist_cache_v6": pinLayout.EgressWhitelistCacheV6,
		"pfwd_allowed_flows":             pinLayout.AllowedFlows,
		"pfwd_allowed_flows_v4":          pinLayout.AllowedFlowsV4,
		"pfwd_host_egress_flows":         pinLayout.HostEgressFlows,
		"pfwd_protocol_skip_ports":       pinLayout.SkipPorts,
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

func listHostEgressInterfaces() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("列出网卡失败: %w", err)
	}
	out := make([]net.Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		out = append(out, iface)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func interfaceNames(ifaces []net.Interface) []string {
	if len(ifaces) == 0 {
		return nil
	}
	names := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		names = append(names, iface.Name)
	}
	sort.Strings(names)
	return names
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func stringSlicesEqual(left []string, right []string) bool {
	left = uniqueSortedStrings(left)
	right = uniqueSortedStrings(right)
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func canIncrementalApply(payload statusPayload, runtimeData *runtimeFile, opts applyOptions, iface *net.Interface, needIngress bool, hostEgressInterfaces []string) bool {
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
	if payload.HostEgressEnabled != runtimeData.Settings.HostEgressEnabled {
		return false
	}
	if runtimeData.Settings.HostEgressEnabled {
		if !stringSlicesEqual(payload.HostEgressInterfaces, hostEgressInterfaces) {
			return false
		}
		if !pinnedPathExists(firstNonEmpty(opts.HostEgressPin, payload.HostEgressPin)) {
			return false
		}
	}
	pinLayout := runtimeMapPinsFromApplyOptions(opts)
	requiredMapPins := []string{
		pinLayout.Settings,
		pinLayout.Rules,
		pinLayout.Connections,
		pinLayout.Reverse,
		pinLayout.RuleCounter,
		pinLayout.RuleDropCounter,
		pinLayout.UserCounter,
		pinLayout.Stats,
		pinLayout.WhitelistV4,
		pinLayout.WhitelistV6,
		pinLayout.WhitelistCacheV4,
		pinLayout.WhitelistCacheV6,
		pinLayout.IngressGeoV4,
		pinLayout.IngressGeoV6,
		pinLayout.IngressCityV4,
		pinLayout.IngressPolicyModes,
		pinLayout.IngressPolicyProvinces,
		pinLayout.IngressPolicyCities,
		pinLayout.EgressWhitelistV4,
		pinLayout.EgressWhitelistV6,
		pinLayout.EgressWhitelistCacheV4,
		pinLayout.EgressWhitelistCacheV6,
		pinLayout.AllowedFlows,
		pinLayout.AllowedFlowsV4,
		pinLayout.HostEgressFlows,
		pinLayout.SkipPorts,
	}
	for _, path := range requiredMapPins {
		if !pinnedPathExists(path) {
			return false
		}
	}
	return runtimeData != nil && pinnedRuntimeMapsCompatible(opts)
}
