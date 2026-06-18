//go:build !geobuild

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
)

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
		key := uint32(port)
		if err := skipMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("写入协议封锁跳过端口失败 (%d): %w", port, err)
		}
	}
	return nil
}

func putRule(objs *bpfObjects, rule runtimeRule, settings runtimeSettings, zeroCounter []counterVal, zeroReplyCounter []replyCounterVal, zeroDropCounter []dropCounterVal) error {
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
	value.WhitelistPolicyID = rule.WhitelistPolicyID
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
	if settings.GuardEnabled && len(settings.ProtocolSkipPorts) > 0 {
		value.Flags |= ruleFlagHasSkipPorts
	}
	if settings.GuardEnabled && rule.Protocol == "tcp" {
		if settings.BlockHTTP {
			value.Flags |= ruleFlagBlockHTTP
		}
		if settings.BlockTLS {
			value.Flags |= ruleFlagBlockTLS
		}
		if settings.BlockSOCKS {
			value.Flags |= ruleFlagBlockSOCKS
		}
		if settings.BlockHTTP || settings.BlockTLS || settings.BlockSOCKS {
			value.Flags |= ruleFlagNeedsGuard
		}
	}
	if settings.WhitelistEnabled {
		policy := ingressPolicyByID(settings, rule.WhitelistPolicyID)
		value.Flags |= ruleFlagNeedsAllow
		if hasWhitelistFiles(settings.WhitelistFiles) {
			value.Flags |= ruleFlagAllowCustom
		}
		if ingressPolicyHasGeoStrategy(policy) {
			value.Flags |= ruleFlagAllowGeo
		}
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
	if opts.GuardMode != "full" {
		return "disabled", "", "guard-only", nil
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

func pinTCProgram(prog *ebpf.Program, pin string) error {
	if prog == nil {
		return fmt.Errorf("tc program 未加载")
	}
	if err := os.MkdirAll(filepath.Dir(pin), 0o755); err != nil {
		return fmt.Errorf("创建 tc pin 目录失败: %w", err)
	}
	_ = removePinnedLink(pin)
	_ = removePinnedProgram(pin)
	if err := prog.Pin(pin); err != nil {
		return fmt.Errorf("pin tc program 失败: %w", err)
	}
	return nil
}

func attachPinnedTCFilter(ifaceName string, pin string, direction string) error {
	if err := runTC("qdisc", "replace", "dev", ifaceName, "clsact"); err != nil {
		return err
	}
	pref := tcPrefBPFIngress
	if direction == "egress" {
		pref = tcPrefBPFEgress
	}
	removeLegacyTCFilters(ifaceName, direction, pref)
	if err := runTC("filter", "replace", "dev", ifaceName, direction, "pref", pref, "bpf", "direct-action", "object-pinned", pin); err != nil {
		return err
	}
	return nil
}

func tcxCacheLookup(ifindex int, attach ebpf.AttachType) (tcxCapabilityResult, bool) {
	tcxCapabilityCacheMu.Lock()
	defer tcxCapabilityCacheMu.Unlock()
	result, ok := tcxCapabilityCache[tcxCapabilityKey{ifindex: ifindex, attach: attach}]
	return result, ok
}

func tcxCacheStore(ifindex int, attach ebpf.AttachType, result tcxCapabilityResult) {
	tcxCapabilityCacheMu.Lock()
	defer tcxCapabilityCacheMu.Unlock()
	tcxCapabilityCache[tcxCapabilityKey{ifindex: ifindex, attach: attach}] = result
}

func resetTCXCapabilityCache() {
	tcxCapabilityCacheMu.Lock()
	defer tcxCapabilityCacheMu.Unlock()
	tcxCapabilityCache = map[tcxCapabilityKey]tcxCapabilityResult{}
}

func isTCXUnsupportedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, link.ErrNotSupported) || errors.Is(err, ebpf.ErrNotSupported) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "operation not supported") ||
		strings.Contains(msg, "invalid attach type") ||
		strings.Contains(msg, "missing required feature")
}

func attachTCXOnce(iface *net.Interface, prog *ebpf.Program, attach ebpf.AttachType) (link.Link, error) {
	if iface == nil {
		return nil, fmt.Errorf("tc interface 为空")
	}
	if prog == nil {
		return nil, fmt.Errorf("tc program 未加载")
	}
	if cached, ok := tcxCacheLookup(iface.Index, attach); ok && !cached.supported {
		if cached.err != nil {
			return nil, cached.err
		}
		return nil, fmt.Errorf("TCX not supported")
	}
	attached, err := tcxAttachFunc(link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    attach,
	})
	if err == nil {
		tcxCacheStore(iface.Index, attach, tcxCapabilityResult{supported: true})
		return attached, nil
	}
	if isTCXUnsupportedError(err) {
		tcxCacheStore(iface.Index, attach, tcxCapabilityResult{supported: false, err: err})
	}
	return nil, err
}

func attachTCProgramWithTCXResult(
	iface *net.Interface,
	prog *ebpf.Program,
	pin string,
	attach ebpf.AttachType,
	direction string,
	tcxErr error,
) (string, error) {
	if tcxErr == nil {
		return "tcx", nil
	}
	if err := runTC("qdisc", "replace", "dev", iface.Name, "clsact"); err != nil {
		return "", fmt.Errorf("TCX attach 失败 (%v)，且设置 clsact 失败: %w", tcxErr, err)
	}
	if err := prog.Pin(pin); err != nil {
		return "", fmt.Errorf("pin tc program 失败: %w", err)
	}
	pref := tcPrefBPFIngress
	if direction == "egress" {
		pref = tcPrefBPFEgress
	}
	removeLegacyTCFilters(iface.Name, direction, pref)
	if err := runTC("filter", "replace", "dev", iface.Name, direction, "pref", pref, "bpf", "direct-action", "object-pinned", pin); err != nil {
		return "", fmt.Errorf("TCX attach 失败 (%v)，classic TC attach 失败: %w", tcxErr, err)
	}
	return "tc", nil
}

func attachTCProgram(iface *net.Interface, prog *ebpf.Program, pin string, attach ebpf.AttachType, direction string) (string, error) {
	if prog == nil {
		return "", fmt.Errorf("tc program 未加载")
	}
	if err := os.MkdirAll(filepath.Dir(pin), 0o755); err != nil {
		return "", fmt.Errorf("创建 tc pin 目录失败: %w", err)
	}
	_ = removePinnedLink(pin)
	_ = removePinnedProgram(pin)
	attached, tcxErr := attachTCXOnce(iface, prog, attach)
	if tcxErr == nil {
		defer attached.Close()
		if err := attached.Pin(pin); err != nil {
			return "", fmt.Errorf("pin tcx link 失败: %w", err)
		}
		if err := attached.Close(); err != nil {
			return "", fmt.Errorf("关闭 tcx link fd 失败: %w", err)
		}
		return "tcx", nil
	}
	return attachTCProgramWithTCXResult(iface, prog, pin, attach, direction, tcxErr)
}

func attachHostEgress(ifaces []net.Interface, prog *ebpf.Program, pin string) ([]string, error) {
	if prog == nil {
		return nil, fmt.Errorf("host egress tc program 未加载")
	}
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("没有可附着的宿主机出口网卡")
	}
	if err := pinTCProgram(prog, pin); err != nil {
		return nil, err
	}
	attached := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		if err := attachPinnedTCFilter(iface.Name, pin, "egress"); err != nil {
			_ = removeHostEgressRuntime(pin, attached)
			return nil, err
		}
		attached = append(attached, iface.Name)
	}
	return uniqueSortedStrings(attached), nil
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
		removeLegacyTCFilters(ifaceName, direction, pref)
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

func removeHostEgressRuntime(pin string, ifaceNames []string) error {
	for _, ifaceName := range uniqueSortedStrings(ifaceNames) {
		_ = runTC("filter", "delete", "dev", ifaceName, "egress", "pref", tcPrefBPFEgress)
	}
	if pin != "" {
		_ = removePinnedLink(pin)
		_ = removePinnedProgram(pin)
	}
	return nil
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
	hostEgressPin := firstNonEmpty(opts.HostEgressPin, payload.HostEgressPin)
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
	if hostEgressPin != "" || len(payload.HostEgressInterfaces) > 0 {
		hostEgressNames := append([]string{}, payload.HostEgressInterfaces...)
		if currentIfaces, err := listHostEgressInterfaces(); err == nil {
			hostEgressNames = append(hostEgressNames, interfaceNames(currentIfaces)...)
		}
		_ = removeHostEgressRuntime(hostEgressPin, hostEgressNames)
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
		pinLayout.RuleReplyCounter,
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
	} {
		if path != "" {
			_ = os.Remove(path)
		}
	}
	cleanupLegacyRuntimeMapPins(pinLayout.RuleCounter)
	return nil
}
