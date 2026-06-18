//go:build !geobuild

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

func runtimeAuxStateFromRuntime(runtimeData *runtimeFile) (runtimeAuxState, error) {
	if runtimeData == nil {
		return runtimeAuxState{}, fmt.Errorf("runtime 为空")
	}
	whitelistHashes, err := whitelistFileHashes(runtimeData.Settings.WhitelistFiles)
	if err != nil {
		return runtimeAuxState{}, err
	}
	egressHashes, err := whitelistFileHashes(runtimeData.Settings.EgressWhitelistFiles)
	if err != nil {
		return runtimeAuxState{}, err
	}
	geoHashes, err := geoAssetHashes(runtimeData.Settings.GeoAssetDir)
	if err != nil {
		return runtimeAuxState{}, err
	}
	return runtimeAuxState{
		GuardEnabled:          runtimeData.Settings.GuardEnabled,
		WhitelistEnabled:      runtimeData.Settings.WhitelistEnabled,
		HostEgressEnabled:     runtimeData.Settings.HostEgressEnabled,
		BlockHTTP:             runtimeData.Settings.BlockHTTP,
		BlockTLS:              runtimeData.Settings.BlockTLS,
		BlockSOCKS:            runtimeData.Settings.BlockSOCKS,
		ProtocolSkipPorts:     append([]uint16{}, runtimeData.Settings.ProtocolSkipPorts...),
		WhitelistHashes:       whitelistHashes,
		EgressWhitelistHashes: egressHashes,
		GeoAssetHashes:        geoHashes,
		IngressCNMode:         runtimeData.Settings.IngressCNMode,
		EgressCNMode:          runtimeData.Settings.EgressCNMode,
		IngressCNProvinces:    append([]string{}, runtimeData.Settings.IngressCNProvinces...),
		IngressPolicies:       normalizeIngressPolicies(runtimeData.Settings),
		EgressCNProvinces:     append([]string{}, runtimeData.Settings.EgressCNProvinces...),
	}, nil
}

func normalizeWhitelistHashes(hashes []whitelistContentHash) []whitelistContentHash {
	if len(hashes) == 0 {
		return nil
	}
	out := make([]whitelistContentHash, 0, len(hashes))
	for _, hash := range hashes {
		path := strings.TrimSpace(hash.Path)
		value := strings.TrimSpace(hash.Hash)
		if path == "" || value == "" {
			continue
		}
		out = append(out, whitelistContentHash{Path: path, Hash: value})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Hash < out[j].Hash
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func whitelistHashesEqual(left []whitelistContentHash, right []whitelistContentHash) bool {
	left = normalizeWhitelistHashes(left)
	right = normalizeWhitelistHashes(right)
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

func protocolSkipPortsEqual(left []uint16, right []uint16) bool {
	if len(left) == 0 && len(right) == 0 {
		return true
	}
	leftSorted := append([]uint16{}, left...)
	rightSorted := append([]uint16{}, right...)
	sort.Slice(leftSorted, func(i, j int) bool { return leftSorted[i] < leftSorted[j] })
	sort.Slice(rightSorted, func(i, j int) bool { return rightSorted[i] < rightSorted[j] })
	if len(leftSorted) != len(rightSorted) {
		return false
	}
	for i := range leftSorted {
		if leftSorted[i] != rightSorted[i] {
			return false
		}
	}
	return true
}

func countChangedWhitelistHashes(left []whitelistContentHash, right []whitelistContentHash) int {
	left = normalizeWhitelistHashes(left)
	right = normalizeWhitelistHashes(right)
	leftMap := make(map[string]string, len(left))
	rightMap := make(map[string]string, len(right))
	for _, hash := range left {
		leftMap[hash.Path] = hash.Hash
	}
	for _, hash := range right {
		rightMap[hash.Path] = hash.Hash
	}
	changed := 0
	seen := map[string]struct{}{}
	for path, value := range leftMap {
		seen[path] = struct{}{}
		if other, ok := rightMap[path]; !ok || other != value {
			changed++
		}
	}
	for path, value := range rightMap {
		if _, ok := seen[path]; ok {
			continue
		}
		if other, ok := leftMap[path]; !ok || other != value {
			changed++
		}
	}
	return changed
}

func normalizeProtocolSkipPorts(ports []uint16) []uint16 {
	if len(ports) == 0 {
		return nil
	}
	set := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if port == 0 {
			continue
		}
		set[port] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(set))
	for port := range set {
		out = append(out, port)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func countChangedProtocolSkipPorts(left []uint16, right []uint16) int {
	leftSet := make(map[uint16]struct{}, len(left))
	rightSet := make(map[uint16]struct{}, len(right))
	for _, port := range normalizeProtocolSkipPorts(left) {
		leftSet[port] = struct{}{}
	}
	for _, port := range normalizeProtocolSkipPorts(right) {
		rightSet[port] = struct{}{}
	}
	changed := 0
	for port := range leftSet {
		if _, ok := rightSet[port]; !ok {
			changed++
		}
	}
	for port := range rightSet {
		if _, ok := leftSet[port]; !ok {
			changed++
		}
	}
	return changed
}

func auxStateValid(payload statusPayload) bool {
	return payload.AuxStateVersion == auxStateVersion
}

func recordAuxAction(out *[]auxActionSummary, component string, action string, changedItems int) {
	if out == nil {
		return
	}
	entry := auxActionSummary{
		Component: component,
		Action:    action,
	}
	if changedItems > 0 {
		entry.ChangedItems = changedItems
	}
	*out = append(*out, entry)
}

func clearSkipPortEntries(skipMap *ebpf.Map, ports []uint16) error {
	if skipMap == nil {
		return fmt.Errorf("协议封锁 skip-port map 未加载")
	}
	for _, port := range normalizeProtocolSkipPorts(ports) {
		key := uint32(port)
		if err := skipMap.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("删除协议封锁跳过端口失败 (%d): %w", port, err)
		}
	}
	return nil
}

func updateProtocolSkipPorts(skipMap *ebpf.Map, current []uint16, next []uint16) (int, error) {
	currentSet := make(map[uint16]struct{}, len(current))
	nextSet := make(map[uint16]struct{}, len(next))
	for _, port := range normalizeProtocolSkipPorts(current) {
		currentSet[port] = struct{}{}
	}
	for _, port := range normalizeProtocolSkipPorts(next) {
		nextSet[port] = struct{}{}
	}
	removed := make([]uint16, 0)
	added := make([]uint16, 0)
	for port := range currentSet {
		if _, ok := nextSet[port]; !ok {
			removed = append(removed, port)
		}
	}
	for port := range nextSet {
		if _, ok := currentSet[port]; !ok {
			added = append(added, port)
		}
	}
	if err := clearSkipPortEntries(skipMap, removed); err != nil {
		return 0, err
	}
	if err := loadProtocolSkipPorts(skipMap, added); err != nil {
		return 0, err
	}
	return len(removed) + len(added), nil
}

func clearWhitelistMaps(mapV4 *ebpf.Map, mapV6 *ebpf.Map, cacheV4 *ebpf.Map, cacheV6 *ebpf.Map) error {
	if err := clearMap[whitelistKeyV4, uint8](mapV4); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV6, uint8](mapV6); err != nil {
		return err
	}
	if err := clearWhitelistCacheMaps(cacheV4, cacheV6); err != nil {
		return err
	}
	return nil
}

func clearWhitelistCacheMaps(cacheV4 *ebpf.Map, cacheV6 *ebpf.Map) error {
	if err := clearMap[uint32, uint8](cacheV4); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV6, uint8](cacheV6); err != nil {
		return err
	}
	return nil
}

func clearIngressWhitelistMaps(mapV4 *ebpf.Map, mapV6 *ebpf.Map, cacheV4 *ebpf.Map, cacheV6 *ebpf.Map) error {
	if err := clearMap[whitelistKeyV4, uint8](mapV4); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV6, uint8](mapV6); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV4, uint8](cacheV4); err != nil {
		return err
	}
	if err := clearMap[whitelistCacheKeyV6, uint8](cacheV6); err != nil {
		return err
	}
	return nil
}

func clearIngressGeoPolicyMaps(objs *bpfObjects) error {
	if err := clearMap[whitelistKeyV4, uint16](objs.PFWDIngressGeoV4); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV6, uint16](objs.PFWDIngressGeoV6); err != nil {
		return err
	}
	if err := clearMap[whitelistKeyV4, uint32](objs.PFWDIngressCityV4); err != nil {
		return err
	}
	if err := clearArrayMap[ingressPolicyModeVal](objs.PFWDIngressPolicyModes); err != nil {
		return err
	}
	if err := clearMap[ingressPolicyProvinceKey, uint8](objs.PFWDIngressPolicyProvinces); err != nil {
		return err
	}
	if err := clearMap[ingressPolicyCityKey, uint8](objs.PFWDIngressPolicyCities); err != nil {
		return err
	}
	return nil
}

func clearAllowedFlows(flowMap *ebpf.Map, flowMapV4 *ebpf.Map) error {
	if err := clearMap[flowKey, guardFlowVal](flowMap); err != nil {
		return fmt.Errorf("清理 guard flow cache 失败: %w", err)
	}
	if err := clearMap[flowKeyV4, guardFlowVal](flowMapV4); err != nil {
		return fmt.Errorf("清理 IPv4 guard flow cache 失败: %w", err)
	}
	return nil
}

func clearArrayMap[T any](m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	info, err := m.Info()
	if err != nil {
		return fmt.Errorf("读取 array map 信息失败: %w", err)
	}
	maxEntries := info.MaxEntries
	var zero T
	for i := uint32(0); i < maxEntries; i++ {
		key := i
		if err := m.Update(&key, &zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("清理 array map 失败 (key=%d): %w", i, err)
		}
	}
	return nil
}

func loadEffectiveWhitelist(
	mapV4 *ebpf.Map,
	mapV6 *ebpf.Map,
	files []string,
	geoAssetDir string,
	cnMode string,
	cnProvinces []string,
) error {
	if err := loadWhitelistFiles(mapV4, mapV6, files); err != nil {
		return err
	}
	if !geoModeEnabled(cnMode) {
		return nil
	}
	assets, err := loadGeoAssets(geoAssetDir)
	if err != nil {
		return err
	}
	allowed, err := geoAllowedProvinceIDs(assets, cnMode, cnProvinces)
	if err != nil {
		return err
	}
	return loadGeoPrefixesIntoWhitelist(mapV4, mapV6, assets, allowed)
}

func loadIngressWhitelist(objs *bpfObjects, settings runtimeSettings) error {
	if objs.PFWDWhitelistV4 == nil || objs.PFWDWhitelistV6 == nil ||
		objs.PFWDIngressGeoV4 == nil || objs.PFWDIngressGeoV6 == nil ||
		objs.PFWDIngressCityV4 == nil || objs.PFWDIngressPolicyModes == nil ||
		objs.PFWDIngressPolicyProvinces == nil || objs.PFWDIngressPolicyCities == nil {
		return fmt.Errorf("入口白名单 BPF map 未加载")
	}
	if err := loadWhitelistFiles(objs.PFWDWhitelistV4, objs.PFWDWhitelistV6, settings.WhitelistFiles); err != nil {
		return err
	}
	policies := normalizeIngressPolicies(settings)
	if ingressPoliciesNeedGeo(policies) {
		assets, err := loadGeoAssets(settings.GeoAssetDir)
		if err != nil {
			return err
		}
		if err := loadIngressGeoPrefixes(objs.PFWDIngressGeoV4, objs.PFWDIngressGeoV6, assets); err != nil {
			return err
		}
	}
	if ingressPoliciesNeedCity(policies) {
		if err := loadIngressCityPrefixes(objs.PFWDIngressCityV4, settings.GeoAssetDir); err != nil {
			return err
		}
	}
	return loadIngressPolicyMaps(objs.PFWDIngressPolicyModes, objs.PFWDIngressPolicyProvinces, objs.PFWDIngressPolicyCities, settings.GeoAssetDir, policies)
}

func loadIngressGeoPrefixes(mapV4 *ebpf.Map, mapV6 *ebpf.Map, assets *geoAssetRuntime) error {
	if assets == nil {
		return fmt.Errorf("缺少 geo 资产")
	}
	for i, prefix := range assets.PrefixesV4 {
		key := whitelistKeyV4{
			PrefixLen: prefix.PrefixLen,
			Addr:      ipv4LPMTrieAddr(ipv4BEToBytes(prefix.Addr)),
		}
		value := prefix.ProvinceID
		if err := mapV4.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("写入入口 geo v4 失败 (index=%d prefix=%d): %w", i, prefix.PrefixLen, err)
		}
	}
	for i, prefix := range assets.PrefixesV6 {
		key := whitelistKeyV6{
			PrefixLen: prefix.PrefixLen,
			Addr:      prefix.Addr,
		}
		value := prefix.ProvinceID
		if err := mapV6.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("写入入口 geo v6 失败 (index=%d prefix=%d): %w", i, prefix.PrefixLen, err)
		}
	}
	return nil
}

func loadIngressCityPrefixes(cityMap *ebpf.Map, assetDir string) error {
	indexes, prefixes, err := readCityIPv4Asset(filepath.Join(assetDir, cityIPv4AssetFile))
	if err != nil {
		return err
	}
	for _, index := range indexes {
		end := index.Offset + index.Count
		if end > uint32(len(prefixes)) {
			return fmt.Errorf("city v4 index 越界 (code=%d)", index.Code)
		}
		for i := index.Offset; i < end; i++ {
			prefix := prefixes[i]
			key := whitelistKeyV4{
				PrefixLen: prefix.PrefixLen,
				Addr:      ipv4LPMTrieAddr(ipv4BEToBytes(prefix.Addr)),
			}
			value := index.Code
			if err := cityMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("写入入口 city v4 失败 (code=%d prefix=%d): %w", index.Code, prefix.PrefixLen, err)
			}
		}
	}
	return nil
}

func loadIngressPolicyMaps(
	modeMap *ebpf.Map,
	provinceMap *ebpf.Map,
	cityMap *ebpf.Map,
	geoAssetDir string,
	policies []ingressPolicy,
) error {
	var assets *geoAssetRuntime
	value := uint8(1)
	for _, policy := range normalizeIngressPolicies(runtimeSettings{IngressPolicies: policies}) {
		key := uint32(policy.ID)
		modeValue := ingressPolicyModeVal{
			CNMode:    ingressPolicyModeValue(policy.CNMode),
			HasCities: boolToUint8(len(policy.CNCityCodes) > 0),
		}
		if err := modeMap.Update(&key, &modeValue, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("写入入口白名单 policy mode 失败 (policy=%d): %w", policy.ID, err)
		}
		if modeValue.CNMode == whitelistCNModeProvinces {
			if assets == nil {
				var err error
				assets, err = loadGeoAssets(geoAssetDir)
				if err != nil {
					return err
				}
			}
			for _, province := range policy.CNProvinces {
				id, ok := assets.ProvinceIDs[province]
				if !ok {
					return fmt.Errorf("未知入口白名单省份：%s", province)
				}
				provinceKey := ingressPolicyProvinceKey{PolicyID: policy.ID, ProvinceID: id}
				if err := provinceMap.Update(&provinceKey, &value, ebpf.UpdateAny); err != nil {
					return fmt.Errorf("写入入口白名单省份 policy 失败 (policy=%d province=%s): %w", policy.ID, province, err)
				}
			}
		}
		for _, rawCode := range policy.CNCityCodes {
			code, err := parseCityCode(rawCode)
			if err != nil {
				return err
			}
			cityKey := ingressPolicyCityKey{PolicyID: policy.ID, CityCode: code}
			if err := cityMap.Update(&cityKey, &value, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("写入入口白名单城市 policy 失败 (policy=%d city=%s): %w", policy.ID, rawCode, err)
			}
		}
	}
	return nil
}

func ingressPolicyModeValue(mode string) uint8 {
	switch strings.TrimSpace(mode) {
	case "all":
		return whitelistCNModeAll
	case "provinces":
		return whitelistCNModeProvinces
	default:
		return whitelistCNModeOff
	}
}

func loadGeoPrefixesIntoWhitelist(mapV4 *ebpf.Map, mapV6 *ebpf.Map, assets *geoAssetRuntime, allowed map[uint16]struct{}) error {
	if assets == nil {
		return fmt.Errorf("缺少 geo 资产")
	}
	if mapV4 == nil || mapV6 == nil {
		return fmt.Errorf("白名单 BPF map 未加载")
	}
	counts := countGeoWhitelistPrefixes(assets, allowed)
	if err := ensureGeoWhitelistCapacity("v4", counts.V4, mapV4); err != nil {
		return err
	}
	if err := ensureGeoWhitelistCapacity("v6", counts.V6, mapV6); err != nil {
		return err
	}
	value := uint8(1)
	for i, prefix := range assets.PrefixesV4 {
		if _, ok := allowed[prefix.ProvinceID]; !ok {
			continue
		}
		key := whitelistKeyV4{
			PrefixLen: prefix.PrefixLen,
			Addr:      ipv4LPMTrieAddr(ipv4BEToBytes(prefix.Addr)),
		}
		if err := mapV4.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("写入入口/出口 geo whitelist v4 失败 (index=%d prefix=%d): %w", i, prefix.PrefixLen, err)
		}
	}
	for i, prefix := range assets.PrefixesV6 {
		if _, ok := allowed[prefix.ProvinceID]; !ok {
			continue
		}
		key := whitelistKeyV6{
			PrefixLen: prefix.PrefixLen,
			Addr:      prefix.Addr,
		}
		if err := mapV6.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("写入入口/出口 geo whitelist v6 失败 (index=%d prefix=%d): %w", i, prefix.PrefixLen, err)
		}
	}
	return nil
}

type geoWhitelistPrefixCounts struct {
	V4 int
	V6 int
}

func countGeoWhitelistPrefixes(assets *geoAssetRuntime, allowed map[uint16]struct{}) geoWhitelistPrefixCounts {
	var counts geoWhitelistPrefixCounts
	if assets == nil || len(allowed) == 0 {
		return counts
	}
	for _, prefix := range assets.PrefixesV4 {
		if _, ok := allowed[prefix.ProvinceID]; ok {
			counts.V4++
		}
	}
	for _, prefix := range assets.PrefixesV6 {
		if _, ok := allowed[prefix.ProvinceID]; ok {
			counts.V6++
		}
	}
	return counts
}

func ensureGeoWhitelistCapacity(version string, needed int, m *ebpf.Map) error {
	info, err := m.Info()
	if err != nil {
		return fmt.Errorf("读取 geo whitelist %s BPF map 信息失败: %w", version, err)
	}
	return validateGeoWhitelistCapacity(version, needed, info.MaxEntries)
}

func validateGeoWhitelistCapacity(version string, needed int, maxEntries uint32) error {
	if needed <= int(maxEntries) {
		return nil
	}
	return fmt.Errorf(
		"geo whitelist %s prefixes=%d exceeds map max_entries=%d; rebuild with larger map or reduce CN asset",
		version,
		needed,
		maxEntries,
	)
}

func geoAllowedProvinceIDs(
	assets *geoAssetRuntime,
	mode string,
	provinces []string,
) (map[uint16]struct{}, error) {
	if assets == nil {
		return nil, fmt.Errorf("缺少 geo 资产")
	}
	allowed := make(map[uint16]struct{})
	switch strings.TrimSpace(mode) {
	case "all":
		for _, province := range assets.Meta.Provinces {
			allowed[province.ID] = struct{}{}
		}
	case "provinces":
		for _, province := range normalizeProvinceNames(provinces) {
			id, ok := assets.ProvinceIDs[province]
			if !ok {
				return nil, fmt.Errorf("未知白名单省份：%s", province)
			}
			allowed[id] = struct{}{}
		}
	default:
		return allowed, nil
	}
	return allowed, nil
}

func normalizeProvinceNames(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := set[value]; ok {
			continue
		}
		set[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func normalizeCityCodes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := set[value]; ok {
			continue
		}
		set[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func normalizeIngressPolicies(settings runtimeSettings) []ingressPolicy {
	policies := settings.IngressPolicies
	if len(policies) == 0 {
		policies = []ingressPolicy{{
			ID:          0,
			Source:      "global",
			CNMode:      settings.IngressCNMode,
			CNProvinces: settings.IngressCNProvinces,
		}}
	}
	out := make([]ingressPolicy, 0, len(policies))
	seen := map[uint16]struct{}{}
	for _, policy := range policies {
		if _, ok := seen[policy.ID]; ok {
			continue
		}
		seen[policy.ID] = struct{}{}
		mode := strings.TrimSpace(policy.CNMode)
		if mode == "" {
			mode = "off"
		}
		out = append(out, ingressPolicy{
			ID:          policy.ID,
			Source:      strings.TrimSpace(policy.Source),
			ListenPort:  policy.ListenPort,
			CNMode:      mode,
			CNProvinces: normalizeProvinceNames(policy.CNProvinces),
			CNCityCodes: normalizeCityCodes(policy.CNCityCodes),
		})
	}
	slices.SortFunc(out, func(left, right ingressPolicy) int {
		if left.ID < right.ID {
			return -1
		}
		if left.ID > right.ID {
			return 1
		}
		return 0
	})
	return out
}

func ingressPoliciesEqual(left, right []ingressPolicy) bool {
	left = normalizeIngressPolicies(runtimeSettings{IngressPolicies: left})
	right = normalizeIngressPolicies(runtimeSettings{IngressPolicies: right})
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].ID != right[i].ID ||
			left[i].ListenPort != right[i].ListenPort ||
			strings.TrimSpace(left[i].CNMode) != strings.TrimSpace(right[i].CNMode) ||
			!stringSlicesEqual(left[i].CNProvinces, right[i].CNProvinces) ||
			!stringSlicesEqual(left[i].CNCityCodes, right[i].CNCityCodes) {
			return false
		}
	}
	return true
}

func ingressPolicyByID(settings runtimeSettings, id uint16) ingressPolicy {
	for _, policy := range normalizeIngressPolicies(settings) {
		if policy.ID == id {
			return policy
		}
	}
	return ingressPolicy{ID: id, CNMode: "off"}
}

func ingressPolicyHasGeoStrategy(policy ingressPolicy) bool {
	return geoModeEnabled(policy.CNMode) || len(normalizeCityCodes(policy.CNCityCodes)) > 0
}

func ingressPoliciesNeedGeo(policies []ingressPolicy) bool {
	for _, policy := range normalizeIngressPolicies(runtimeSettings{IngressPolicies: policies}) {
		if geoModeEnabled(policy.CNMode) {
			return true
		}
	}
	return false
}

func ingressPoliciesNeedCity(policies []ingressPolicy) bool {
	for _, policy := range normalizeIngressPolicies(runtimeSettings{IngressPolicies: policies}) {
		if len(policy.CNCityCodes) > 0 {
			return true
		}
	}
	return false
}

func effectiveWhitelistFiles(runtimeData *runtimeFile, opts applyOptions) []string {
	files := runtimeData.Settings.WhitelistFiles
	if opts.WhitelistFile != "" {
		files = splitFiles(opts.WhitelistFile)
	}
	return files
}

func ingressGeoPolicyChanged(current, next runtimeAuxState) bool {
	return current.IngressCNMode != next.IngressCNMode ||
		!stringSlicesEqual(normalizeProvinceNames(current.IngressCNProvinces), normalizeProvinceNames(next.IngressCNProvinces)) ||
		!ingressPoliciesEqual(current.IngressPolicies, next.IngressPolicies)
}

func egressGeoPolicyChanged(current, next runtimeAuxState) bool {
	return current.EgressCNMode != next.EgressCNMode ||
		!stringSlicesEqual(normalizeProvinceNames(current.EgressCNProvinces), normalizeProvinceNames(next.EgressCNProvinces))
}

func ingressWhitelistStateChanged(currentValid bool, current, next runtimeAuxState) bool {
	geoAssetsChanged := !currentValid || !whitelistHashesEqual(current.GeoAssetHashes, next.GeoAssetHashes)
	return !currentValid ||
		current.WhitelistEnabled != next.WhitelistEnabled ||
		!whitelistHashesEqual(current.WhitelistHashes, next.WhitelistHashes) ||
		geoAssetsChanged ||
		ingressGeoPolicyChanged(current, next)
}

func guardRuntimeCacheChanged(currentValid bool, current, next runtimeAuxState) bool {
	return !currentValid ||
		current.GuardEnabled != next.GuardEnabled ||
		current.WhitelistEnabled != next.WhitelistEnabled ||
		current.BlockHTTP != next.BlockHTTP ||
		current.BlockTLS != next.BlockTLS ||
		current.BlockSOCKS != next.BlockSOCKS ||
		!protocolSkipPortsEqual(current.ProtocolSkipPorts, next.ProtocolSkipPorts)
}

func applyIncrementalAuxState(
	objs *bpfObjects,
	runtimeData *runtimeFile,
	opts applyOptions,
	current runtimeAuxState,
	currentValid bool,
) (runtimeAuxState, []auxActionSummary, error) {
	nextState, err := runtimeAuxStateFromRuntime(runtimeData)
	if err != nil {
		return runtimeAuxState{}, nil, err
	}
	actions := make([]auxActionSummary, 0, 4)
	allowedFlowsCleared := false

	whitelistFiles := effectiveWhitelistFiles(runtimeData, opts)
	geoAssetsChanged := !currentValid || !whitelistHashesEqual(current.GeoAssetHashes, nextState.GeoAssetHashes)
	ingressWhitelistChanged := ingressWhitelistStateChanged(currentValid, current, nextState)
	if ingressWhitelistChanged {
		if err := clearIngressWhitelistMaps(objs.PFWDWhitelistV4, objs.PFWDWhitelistV6, objs.PFWDWhitelistCacheV4, objs.PFWDWhitelistCacheV6); err != nil {
			return runtimeAuxState{}, nil, err
		}
		if err := clearIngressGeoPolicyMaps(objs); err != nil {
			return runtimeAuxState{}, nil, err
		}
		if err := clearAllowedFlows(objs.PFWDFlows, objs.PFWDFlowsV4); err != nil {
			return runtimeAuxState{}, nil, err
		}
		allowedFlowsCleared = true
		if nextState.WhitelistEnabled {
			settings := runtimeData.Settings
			settings.WhitelistFiles = whitelistFiles
			if err := loadIngressWhitelist(objs, settings); err != nil {
				return runtimeAuxState{}, nil, err
			}
		}
		changedItems := countChangedWhitelistHashes(current.WhitelistHashes, nextState.WhitelistHashes)
		if geoAssetsChanged || ingressGeoPolicyChanged(current, nextState) {
			changedItems++
		}
		recordAuxAction(&actions, "whitelist", "reload", changedItems)
		recordAuxAction(&actions, "allowed_flows", "reload", 0)
	} else {
		recordAuxAction(&actions, "whitelist", "reuse", 0)
	}

	if !currentValid {
		if _, err := updateProtocolSkipPorts(objs.PFWDSkipPorts, nil, nextState.ProtocolSkipPorts); err != nil {
			return runtimeAuxState{}, nil, err
		}
		recordAuxAction(&actions, "protocol_skip_ports", "delta-update", len(normalizeProtocolSkipPorts(nextState.ProtocolSkipPorts)))
	} else if protocolSkipPortsEqual(current.ProtocolSkipPorts, nextState.ProtocolSkipPorts) {
		recordAuxAction(&actions, "protocol_skip_ports", "reuse", 0)
	} else {
		changedItems, err := updateProtocolSkipPorts(objs.PFWDSkipPorts, current.ProtocolSkipPorts, nextState.ProtocolSkipPorts)
		if err != nil {
			return runtimeAuxState{}, nil, err
		}
		recordAuxAction(&actions, "protocol_skip_ports", "delta-update", changedItems)
	}

	egressWhitelistChanged := !currentValid ||
		current.HostEgressEnabled != nextState.HostEgressEnabled ||
		!whitelistHashesEqual(current.EgressWhitelistHashes, nextState.EgressWhitelistHashes) ||
		geoAssetsChanged ||
		egressGeoPolicyChanged(current, nextState)
	if egressWhitelistChanged {
		if err := clearWhitelistMaps(objs.PFWDEgressWhitelistV4, objs.PFWDEgressWhitelistV6, objs.PFWDEgressWhitelistCacheV4, objs.PFWDEgressWhitelistCacheV6); err != nil {
			return runtimeAuxState{}, nil, err
		}
		if nextState.HostEgressEnabled {
			if err := loadEffectiveWhitelist(
				objs.PFWDEgressWhitelistV4,
				objs.PFWDEgressWhitelistV6,
				runtimeData.Settings.EgressWhitelistFiles,
				runtimeData.Settings.GeoAssetDir,
				nextState.EgressCNMode,
				nextState.EgressCNProvinces,
			); err != nil {
				return runtimeAuxState{}, nil, err
			}
		}
		changedItems := countChangedWhitelistHashes(current.EgressWhitelistHashes, nextState.EgressWhitelistHashes)
		if geoAssetsChanged || egressGeoPolicyChanged(current, nextState) {
			changedItems++
		}
		recordAuxAction(&actions, "egress_whitelist", "reload", changedItems)
	} else {
		recordAuxAction(&actions, "egress_whitelist", "reuse", 0)
	}

	geoStateChanged := geoAssetsChanged ||
		ingressGeoPolicyChanged(current, nextState) ||
		egressGeoPolicyChanged(current, nextState)
	if geoStateChanged {
		recordAuxAction(&actions, "geo_assets", "reload", countChangedWhitelistHashes(current.GeoAssetHashes, nextState.GeoAssetHashes))
	} else {
		recordAuxAction(&actions, "geo_assets", "reuse", 0)
	}

	if nextState.HostEgressEnabled {
		if err := clearVerdictEntriesByValue(objs.PFWDHostEgressFlows, cacheVerdictDrop); err != nil {
			return runtimeAuxState{}, nil, fmt.Errorf("清理宿主机出口 drop cache 失败: %w", err)
		}
		recordAuxAction(&actions, "host_egress_drop_cache", "reload", 0)
	} else if current.HostEgressEnabled {
		if err := clearMap[flowKey, uint8](objs.PFWDHostEgressFlows); err != nil {
			return runtimeAuxState{}, nil, err
		}
		recordAuxAction(&actions, "host_egress_drop_cache", "reload", 0)
	} else {
		recordAuxAction(&actions, "host_egress_drop_cache", "reuse", 0)
	}

	if guardRuntimeCacheChanged(currentValid, current, nextState) {
		if !allowedFlowsCleared {
			if err := clearAllowedFlows(objs.PFWDFlows, objs.PFWDFlowsV4); err != nil {
				return runtimeAuxState{}, nil, err
			}
		}
		recordAuxAction(&actions, "guard_runtime_cache", "reload", 0)
	} else {
		recordAuxAction(&actions, "guard_runtime_cache", "reuse", 0)
	}

	return nextState, actions, nil
}

func recordAttachTiming(out *[]attachTiming, component string, started time.Time) {
	if out == nil {
		return
	}
	*out = append(*out, attachTiming{
		Component:      component,
		DurationMillis: elapsedMillis(started),
	})
}
