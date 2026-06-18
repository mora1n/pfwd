//go:build !geobuild

package main

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
)

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
	}
	expected, ok := allowed[ruleLookup]
	return ok && connectionMatchesRule(key, value, expected)
}

func runtimeRuleEntries(runtimeData *runtimeFile, settings runtimeSettings) (map[ruleKey]ruleVal, error) {
	entries := make(map[ruleKey]ruleVal, len(runtimeData.Rules))
	for _, rule := range runtimeData.Rules {
		key, err := makeRuleKey(rule)
		if err != nil {
			return nil, fmt.Errorf("生成规则 key 失败 (%s): %w", rule.ID, err)
		}
		value, err := makeRuleVal(rule, settings)
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

func reconcileRuntimeMaps(objs *bpfObjects, runtimeData *runtimeFile, opts applyOptions, currentStatus statusPayload) (mapReconcileReport, runtimeAuxState, error) {
	if objs.PFWDSettings == nil || objs.PFWDRules == nil || objs.PFWDRuleCounter == nil || objs.PFWDRuleReplyCounter == nil || objs.PFWDRuleDropCounter == nil || objs.PFWDUserCounter == nil {
		return mapReconcileReport{}, runtimeAuxState{}, fmt.Errorf("关键 BPF map 未加载")
	}
	oldUsers, err := currentRuleUserLimits(objs)
	if err != nil {
		return mapReconcileReport{}, runtimeAuxState{}, err
	}
	var externalIfindex uint32
	if opts.Iface != "" {
		iface, err := net.InterfaceByName(opts.Iface)
		if err != nil {
			return mapReconcileReport{}, runtimeAuxState{}, fmt.Errorf("查找外部网卡失败: %w", err)
		}
		externalIfindex = uint32(iface.Index)
	}
	dataplaneSettings := effectiveDataplaneSettings(runtimeData, opts)
	settings := makeXDPSettings(dataplaneSettings, externalIfindex)
	key := uint32(0)
	if err := objs.PFWDSettings.Update(&key, &settings, ebpf.UpdateAny); err != nil {
		return mapReconcileReport{}, runtimeAuxState{}, fmt.Errorf("写入 settings 失败: %w", err)
	}
	if objs.PFWDEgressWhitelistV4 == nil || objs.PFWDEgressWhitelistV6 == nil || objs.PFWDHostEgressFlows == nil {
		return mapReconcileReport{}, runtimeAuxState{}, fmt.Errorf("宿主机出口白名单 BPF map 未加载")
	}
	nextAuxState, auxActions, err := applyIncrementalAuxState(objs, runtimeData, opts, currentStatus.AuxState, auxStateValid(currentStatus))
	if err != nil {
		return mapReconcileReport{}, runtimeAuxState{}, err
	}
	rules, err := runtimeRuleEntries(runtimeData, dataplaneSettings)
	if err != nil {
		return mapReconcileReport{}, runtimeAuxState{}, err
	}
	report, err := reconcileRuleMap(objs, rules)
	if err != nil {
		return report, runtimeAuxState{}, err
	}
	userReport, err := reconcileUserCounters(objs, oldUsers, runtimeUserLimits(runtimeData))
	if err != nil {
		return report, runtimeAuxState{}, err
	}
	report.add(userReport)
	report.AuxActions = auxActions
	return report, nextAuxState, nil
}

func reverseKeyFromConn(key connKey, value connVal) reverseKey {
	return reverseKey{
		Family:     key.Family,
		Protocol:   key.Protocol,
		SourcePort: value.SourcePort,
		TargetPort: key.TargetPort,
		SourceAddr: value.SourceAddr,
		TargetAddr: key.TargetAddr,
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

func applyIncrementalRuntime(payload statusPayload, runtimeData *runtimeFile, opts applyOptions, iface *net.Interface, protocolGuard bool, hostEgressInterfaces []string) error {
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
	mapReport, nextAuxState, err := reconcileRuntimeMaps(objs, runtimeData, opts, payload)
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
	updated.HostEgressEnabled = runtimeData.Settings.HostEgressEnabled
	updated.HostEgressInterfaces = uniqueSortedStrings(hostEgressInterfaces)
	updated.HostEgressPin = opts.HostEgressPin
	updated.LoopbackPin = opts.LoopbackPin
	updated.SkLookupPin = opts.SkLookupPin
	updated.RuleCounterPin = opts.RuleCounterPin
	updated.UserCounterPin = opts.UserCounterPin
	updated.StatsPin = opts.StatsPin
	updated.AuxStateVersion = auxStateVersion
	updated.AuxState = nextAuxState
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
		AuxActions:              mapReport.AuxActions,
	}
	return writeStatus(opts.StatusFile, updated)
}
