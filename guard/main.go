package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
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

//go:embed guard_bpfel.o
var guardBPFEL []byte

const binaryVersion = "0.1.0"

type bpfObjects struct {
	XDPGuard            *ebpf.Program `ebpf:"xdp_guard"`
	IngressGuard        *ebpf.Program `ebpf:"ingress_guard"`
	GuardSettings       *ebpf.Map     `ebpf:"guard_settings"`
	GuardWhitelistV4    *ebpf.Map     `ebpf:"guard_whitelist_v4"`
	GuardWhitelistV6    *ebpf.Map     `ebpf:"guard_whitelist_v6"`
	GuardAllPorts       *ebpf.Map     `ebpf:"guard_all_ports"`
	GuardAllowTCPPorts  *ebpf.Map     `ebpf:"guard_allow_tcp_ports"`
	GuardAllowedFlows   *ebpf.Map     `ebpf:"guard_allowed_flows"`
	GuardStats          *ebpf.Map     `ebpf:"guard_stats"`
}

func (o *bpfObjects) Close() {
	if o == nil {
		return
	}
	if o.XDPGuard != nil {
		_ = o.XDPGuard.Close()
	}
	if o.IngressGuard != nil {
		_ = o.IngressGuard.Close()
	}
	if o.GuardSettings != nil {
		_ = o.GuardSettings.Close()
	}
	if o.GuardWhitelistV4 != nil {
		_ = o.GuardWhitelistV4.Close()
	}
	if o.GuardWhitelistV6 != nil {
		_ = o.GuardWhitelistV6.Close()
	}
	if o.GuardAllPorts != nil {
		_ = o.GuardAllPorts.Close()
	}
	if o.GuardAllowTCPPorts != nil {
		_ = o.GuardAllowTCPPorts.Close()
	}
	if o.GuardAllowedFlows != nil {
		_ = o.GuardAllowedFlows.Close()
	}
	if o.GuardStats != nil {
		_ = o.GuardStats.Close()
	}
}

type guardSettings struct {
	WhitelistEnabled uint8
	BlockHTTP        uint8
	BlockTLS         uint8
	BlockSOCKS       uint8
}

type whitelistKeyV4 struct {
	PrefixLen uint32
	Addr      uint32
}

type whitelistKeyV6 struct {
	PrefixLen uint32
	Addr      [16]byte
}

type applyOptions struct {
	Iface            string
	XDPMode          string
	XDPPin           string
	IngressPin       string
	StatusFile       string
	ConfigHash       string
	XDPWhitelist     bool
	AllowAnyPorts    string
	WhitelistFile    string
	WhitelistEnabled bool
	AllowPorts       string
	BlockHTTP        bool
	BlockTLS         bool
	BlockSOCKS       bool
}

type removeOptions struct {
	XDPPin     string
	IngressPin string
	StatusFile string
}

type statusFilePayload struct {
	Applied           bool   `json:"applied"`
	BinaryVersion     string `json:"binary_version"`
	AppliedAt         string `json:"applied_at"`
	XDPMode           string `json:"xdp_mode,omitempty"`
	XDPEffective      string `json:"xdp_effective,omitempty"`
	XDPAttachKind     string `json:"xdp_attach_kind,omitempty"`
	XDPReason         string `json:"xdp_reason,omitempty"`
	AttachMode        string `json:"attach_mode"`
	Interface         string `json:"interface"`
	InterfaceIndex    int    `json:"interface_index"`
	XDPPin            string `json:"xdp_pin,omitempty"`
	IngressPin        string `json:"ingress_pin"`
	ConfigHash        string `json:"config_hash,omitempty"`
	WhitelistEnabled  bool   `json:"whitelist_enabled"`
	WhitelistFile     string `json:"whitelist_file"`
	XDPWhitelist      bool   `json:"xdp_whitelist"`
	AllowAnyPorts     int    `json:"allow_any_ports"`
	WhitelistEntries  int    `json:"whitelist_entries"`
	AllowTCPPorts     int    `json:"allow_tcp_ports"`
	BlockHTTP         bool   `json:"block_http"`
	BlockTLS          bool   `json:"block_tls"`
	BlockSOCKS        bool   `json:"block_socks"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pfwd-guard: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}

	switch args[0] {
	case "apply":
		return runApplyCommand(args[1:])
	case "remove":
		return runRemoveCommand(args[1:])
	case "status":
		return runStatusCommand(args[1:])
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

func runApplyCommand(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var opts applyOptions
	var whitelistEnabled string
	var xdpWhitelist string
	var blockHTTP string
	var blockTLS string
	var blockSOCKS string

	fs.StringVar(&opts.Iface, "iface", "", "network interface")
	fs.StringVar(&opts.XDPMode, "xdp-mode", "auto", "off|auto|force")
	fs.StringVar(&opts.XDPPin, "xdp-pin", "", "bpffs pin path for xdp")
	fs.StringVar(&opts.IngressPin, "ingress-pin", "", "bpffs pin path")
	fs.StringVar(&opts.StatusFile, "status-file", "", "status json path")
	fs.StringVar(&opts.ConfigHash, "config-hash", "", "runtime config hash")
	fs.StringVar(&xdpWhitelist, "xdp-whitelist", "false", "true|false")
	fs.StringVar(&opts.AllowAnyPorts, "allow-any-ports", "", "all forwarded ports list")
	fs.StringVar(&opts.WhitelistFile, "whitelist-file", "", "whitelist file path")
	fs.StringVar(&whitelistEnabled, "whitelist-enabled", "false", "true|false")
	fs.StringVar(&opts.AllowPorts, "allow-ports", "", "allowed forwarding ports list")
	fs.StringVar(&blockHTTP, "block-http", "false", "true|false")
	fs.StringVar(&blockTLS, "block-tls", "false", "true|false")
	fs.StringVar(&blockSOCKS, "block-socks", "false", "true|false")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("apply 不接受额外参数")
	}

	var err error
	opts.WhitelistEnabled, err = parseBoolValue(whitelistEnabled)
	if err != nil {
		return fmt.Errorf("解析 whitelist-enabled 失败: %w", err)
	}
	opts.XDPWhitelist, err = parseBoolValue(xdpWhitelist)
	if err != nil {
		return fmt.Errorf("解析 xdp-whitelist 失败: %w", err)
	}
	opts.BlockHTTP, err = parseBoolValue(blockHTTP)
	if err != nil {
		return fmt.Errorf("解析 block-http 失败: %w", err)
	}
	opts.BlockTLS, err = parseBoolValue(blockTLS)
	if err != nil {
		return fmt.Errorf("解析 block-tls 失败: %w", err)
	}
	opts.BlockSOCKS, err = parseBoolValue(blockSOCKS)
	if err != nil {
		return fmt.Errorf("解析 block-socks 失败: %w", err)
	}

	return applyGuard(opts)
}

func runRemoveCommand(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var opts removeOptions
	fs.StringVar(&opts.XDPPin, "xdp-pin", "", "bpffs pin path for xdp")
	fs.StringVar(&opts.IngressPin, "ingress-pin", "", "bpffs pin path")
	fs.StringVar(&opts.StatusFile, "status-file", "", "status json path")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("remove 不接受额外参数")
	}

	return removeGuard(opts)
}

func runStatusCommand(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var statusFile string
	fs.StringVar(&statusFile, "status-file", "", "status json path")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("status 不接受额外参数")
	}
	if statusFile == "" {
		return fmt.Errorf("status 缺少 --status-file")
	}

	payload, err := readStatusFile(statusFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			payload = statusFilePayload{
				Applied:       false,
				BinaryVersion: binaryVersion,
			}
		} else {
			return err
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func applyGuard(opts applyOptions) error {
	if opts.Iface == "" {
		return fmt.Errorf("缺少 --iface")
	}
	if opts.XDPMode == "" {
		opts.XDPMode = "auto"
	}
	switch opts.XDPMode {
	case "off", "auto", "force":
	default:
		return fmt.Errorf("无效 xdp-mode：%s", opts.XDPMode)
	}
	if opts.IngressPin == "" {
		return fmt.Errorf("缺少 --ingress-pin")
	}
	if opts.StatusFile == "" {
		return fmt.Errorf("缺少 --status-file")
	}
	if opts.XDPMode != "off" && opts.XDPPin == "" {
		return fmt.Errorf("启用 XDP 时缺少 --xdp-pin")
	}
	if opts.WhitelistEnabled && opts.WhitelistFile == "" {
		return fmt.Errorf("whitelist 已启用，但缺少 --whitelist-file")
	}

	iface, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return fmt.Errorf("查找网卡 %q 失败: %w", opts.Iface, err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("移除 memlock 限制失败: %w", err)
	}
	if err := removeGuard(removeOptions{
		XDPPin:     opts.XDPPin,
		IngressPin: opts.IngressPin,
		StatusFile: opts.StatusFile,
	}); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("清理旧 guard link 失败: %w", err)
	}

	objs, err := loadBPFObjects()
	if err != nil {
		return err
	}
	defer objs.Close()

	if err := updateSettings(objs.GuardSettings, opts); err != nil {
		return err
	}

	whitelistEntries := 0
	if opts.WhitelistEnabled {
		whitelistEntries, err = loadWhitelistFile(objs.GuardWhitelistV4, objs.GuardWhitelistV6, opts.WhitelistFile)
		if err != nil {
			return err
		}
	}
	allowAnyPortsEntries, err := loadAllowPorts(objs.GuardAllPorts, opts.AllowAnyPorts, "guard_all_ports")
	if err != nil {
		return err
	}
	allowPortsEntries, err := loadAllowPorts(objs.GuardAllowTCPPorts, opts.AllowPorts, "guard_allow_tcp_ports")
	if err != nil {
		return err
	}

	xdpEffective, xdpAttachKind, xdpReason, err := attachXDPGuard(iface, objs.XDPGuard, opts)
	if err != nil {
		return err
	}
	attachMode, err := attachGuard(iface, objs.IngressGuard, opts.IngressPin)
	if err != nil {
		return err
	}

	payload := statusFilePayload{
		Applied:          true,
		BinaryVersion:    binaryVersion,
		AppliedAt:        time.Now().UTC().Format(time.RFC3339),
		XDPMode:          opts.XDPMode,
		XDPEffective:     xdpEffective,
		XDPAttachKind:    xdpAttachKind,
		XDPReason:        xdpReason,
		AttachMode:       attachMode,
		Interface:        iface.Name,
		InterfaceIndex:   iface.Index,
		XDPPin:           opts.XDPPin,
		IngressPin:       opts.IngressPin,
		ConfigHash:       opts.ConfigHash,
		WhitelistEnabled: opts.WhitelistEnabled,
		WhitelistFile:    opts.WhitelistFile,
		XDPWhitelist:     opts.XDPWhitelist,
		AllowAnyPorts:    allowAnyPortsEntries,
		WhitelistEntries: whitelistEntries,
		AllowTCPPorts:    allowPortsEntries,
		BlockHTTP:        opts.BlockHTTP,
		BlockTLS:         opts.BlockTLS,
		BlockSOCKS:       opts.BlockSOCKS,
	}
	if err := writeStatusFile(opts.StatusFile, payload); err != nil {
		return err
	}

	return nil
}

func removeGuard(opts removeOptions) error {
	if opts.IngressPin == "" {
		return fmt.Errorf("缺少 --ingress-pin")
	}
	payload, _ := readStatusFile(opts.StatusFile)
	xdpPin := opts.XDPPin
	if xdpPin == "" {
		xdpPin = payload.XDPPin
	}
	if xdpPin != "" {
		_ = removePinnedLink(xdpPin)
		_ = removePinnedProgram(xdpPin)
	}
	switch payload.AttachMode {
	case "tc":
		if payload.Interface != "" {
			_ = runTC("filter", "delete", "dev", payload.Interface, "ingress")
			_ = runTC("qdisc", "delete", "dev", payload.Interface, "clsact")
		}
		if err := removePinnedProgram(opts.IngressPin); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("移除 pinned guard program 失败: %w", err)
		}
	default:
		if err := removePinnedLink(opts.IngressPin); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("移除 guard link 失败: %w", err)
		}
	}
	if opts.StatusFile != "" {
		if err := removeIfExists(opts.StatusFile); err != nil {
			return fmt.Errorf("删除状态文件失败: %w", err)
		}
	}
	return nil
}

func loadBPFObjects() (*bpfObjects, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(guardBPFEL))
	if err != nil {
		return nil, fmt.Errorf("加载 eBPF spec 失败: %w", err)
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("加载 eBPF 对象失败: %w", err)
	}
	return &objs, nil
}

func updateSettings(settingsMap *ebpf.Map, opts applyOptions) error {
	if settingsMap == nil {
		return fmt.Errorf("guard_settings map 未加载")
	}

	key := uint32(0)
	value := guardSettings{
		WhitelistEnabled: boolToUint8(opts.WhitelistEnabled),
		BlockHTTP:        boolToUint8(opts.BlockHTTP),
		BlockTLS:         boolToUint8(opts.BlockTLS),
		BlockSOCKS:       boolToUint8(opts.BlockSOCKS),
	}
	if err := settingsMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("写入 guard 设置失败: %w", err)
	}
	return nil
}

func loadWhitelistFile(whitelistMapV4 *ebpf.Map, whitelistMapV6 *ebpf.Map, filePath string) (int, error) {
	if whitelistMapV4 == nil {
		return 0, fmt.Errorf("guard_whitelist_v4 map 未加载")
	}
	if whitelistMapV6 == nil {
		return 0, fmt.Errorf("guard_whitelist_v6 map 未加载")
	}

	parts := strings.Split(filePath, ":")
	count := 0
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		file, err := os.Open(part)
		if err != nil {
			return 0, fmt.Errorf("打开白名单文件失败: %w", err)
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
				return 0, fmt.Errorf("解析白名单失败 (%s:%d): %w", part, lineNo, err)
			}
			prefix = prefix.Masked()

			value := uint8(1)
			if prefix.Addr().Is4() {
				addr := prefix.Addr().As4()
				key := whitelistKeyV4{
					PrefixLen: uint32(prefix.Bits()),
					Addr:      binary.BigEndian.Uint32(addr[:]),
				}
				if err := whitelistMapV4.Update(&key, &value, ebpf.UpdateAny); err != nil {
					_ = file.Close()
					return 0, fmt.Errorf("写入 IPv4 白名单失败 (%s:%d): %w", part, lineNo, err)
				}
			} else {
				addr := prefix.Addr().As16()
				key := whitelistKeyV6{
					PrefixLen: uint32(prefix.Bits()),
					Addr:      addr,
				}
				if err := whitelistMapV6.Update(&key, &value, ebpf.UpdateAny); err != nil {
					_ = file.Close()
					return 0, fmt.Errorf("写入 IPv6 白名单失败 (%s:%d): %w", part, lineNo, err)
				}
			}
			count++
		}

		if err := scanner.Err(); err != nil {
			_ = file.Close()
			return 0, fmt.Errorf("读取白名单文件失败: %w", err)
		}
		if err := file.Close(); err != nil {
			return 0, fmt.Errorf("关闭白名单文件失败: %w", err)
		}
	}
	return count, nil
}

func loadAllowPorts(portMap *ebpf.Map, raw string, mapName string) (int, error) {
	if portMap == nil {
		return 0, fmt.Errorf("%s map 未加载", mapName)
	}
	count := 0
	seen := make(map[uint32]struct{})
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) == 0 || fields[0] == "" {
			continue
		}
		portValue, err := netip.ParseAddrPort("0.0.0.0:" + fields[0])
		if err != nil {
			return 0, fmt.Errorf("解析监听端口失败: %s", line)
		}
		port := uint32(portValue.Port())
		if _, ok := seen[port]; ok {
			continue
		}
		val := uint8(1)
		if err := portMap.Update(&port, &val, ebpf.UpdateAny); err != nil {
			return 0, fmt.Errorf("写入监听端口失败 (%d): %w", port, err)
		}
		seen[port] = struct{}{}
		count++
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("读取监听端口失败: %w", err)
	}
	return count, nil
}

func attachXDPGuard(iface *net.Interface, prog *ebpf.Program, opts applyOptions) (string, string, string, error) {
	if opts.XDPMode == "off" {
		if opts.XDPPin != "" {
			_ = removePinnedLink(opts.XDPPin)
			_ = removePinnedProgram(opts.XDPPin)
		}
		return "off", "-", "", nil
	}
	if prog == nil {
		if opts.XDPMode == "force" {
			return "", "", "", fmt.Errorf("xdp_guard program 未加载")
		}
		return "disabled", "-", "program-missing", nil
	}
	if err := features.HaveProgramType(ebpf.XDP); err != nil {
		if opts.XDPMode == "force" {
			return "", "", "", fmt.Errorf("XDP 不可用: %w", err)
		}
		return "disabled", "-", "xdp-unsupported", nil
	}
	if err := os.MkdirAll(filepath.Dir(opts.XDPPin), 0o755); err != nil {
		return "", "", "", fmt.Errorf("创建 XDP bpffs 目录失败: %w", err)
	}
	_ = removePinnedLink(opts.XDPPin)
	_ = removePinnedProgram(opts.XDPPin)

	tryAttach := func(flags link.XDPAttachFlags, kind string) (string, string, string, error) {
		attached, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
			Flags:     flags,
		})
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

	if effective, kind, reason, err := tryAttach(link.XDPDriverMode, "driver"); err == nil {
		return effective, kind, reason, nil
	}
	if effective, kind, reason, err := tryAttach(link.XDPGenericMode, "generic"); err == nil {
		return effective, kind, reason, nil
	}
	if opts.XDPMode == "force" {
		return "", "", "", fmt.Errorf("XDP attach 失败")
	}
	return "disabled", "-", "attach-failed", nil
}

func attachGuard(iface *net.Interface, prog *ebpf.Program, pinPath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(pinPath), 0o755); err != nil {
		return "", fmt.Errorf("创建 bpffs 目录失败: %w", err)
	}

	attachedLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err == nil {
		defer attachedLink.Close()
		if err := attachedLink.Pin(pinPath); err != nil {
			return "", fmt.Errorf("pin guard link 失败: %w", err)
		}
		if err := attachedLink.Close(); err != nil {
			return "", fmt.Errorf("关闭 guard link fd 失败: %w", err)
		}
		return "tcx", nil
	}

	if !strings.Contains(err.Error(), "requires >= v6.6") && !strings.Contains(strings.ToLower(err.Error()), "not supported") {
		return "", fmt.Errorf("挂载 TCX ingress 失败: %w", err)
	}

	if err := prog.Pin(pinPath); err != nil {
		return "", fmt.Errorf("pin guard program 失败: %w", err)
	}
	if err := ensureClsact(iface.Name); err != nil {
		_ = removePinnedProgram(pinPath)
		return "", err
	}
	if err := runTC("filter", "replace", "dev", iface.Name, "ingress", "bpf", "direct-action", "object-pinned", pinPath); err != nil {
		_ = removePinnedProgram(pinPath)
		return "", fmt.Errorf("挂载 tc ingress filter 失败: %w", err)
	}
	return "tc", nil
}

func removePinnedLink(pinPath string) error {
	if pinPath == "" {
		return fmt.Errorf("pin path 不能为空")
	}

	if _, err := os.Stat(pinPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("检查 pin path 失败: %w", err)
	}

	loadedLink, err := link.LoadPinnedLink(pinPath, nil)
	if err != nil {
		return fmt.Errorf("加载 pinned guard link 失败: %w", err)
	}
	defer loadedLink.Close()

	if err := loadedLink.Detach(); err != nil {
		return fmt.Errorf("detach guard link 失败: %w", err)
	}
	if err := loadedLink.Unpin(); err != nil {
		return fmt.Errorf("unpin guard link 失败: %w", err)
	}
	return nil
}

func removePinnedProgram(pinPath string) error {
	if pinPath == "" {
		return fmt.Errorf("pin path 不能为空")
	}
	prog, err := ebpf.LoadPinnedProgram(pinPath, nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return fmt.Errorf("加载 pinned guard program 失败: %w", err)
	}
	defer prog.Close()
	if err := prog.Unpin(); err != nil {
		return fmt.Errorf("unpin guard program 失败: %w", err)
	}
	return nil
}

func ensureClsact(iface string) error {
	if err := runTC("qdisc", "replace", "dev", iface, "clsact"); err == nil {
		return nil
	}
	if err := runTC("qdisc", "add", "dev", iface, "clsact"); err != nil && !strings.Contains(err.Error(), "File exists") {
		return fmt.Errorf("创建 clsact qdisc 失败: %w", err)
	}
	return nil
}

func runTC(args ...string) error {
	cmd := exec.Command("tc", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(output))
		if text == "" {
			return err
		}
		return fmt.Errorf("%s: %w", text, err)
	}
	return nil
}

func writeStatusFile(filePath string, payload statusFilePayload) error {
	if filePath == "" {
		return fmt.Errorf("status file 不能为空")
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return fmt.Errorf("创建状态目录失败: %w", err)
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("编码状态 JSON 失败: %w", err)
	}
	data = append(data, '\n')

	tmpFile, err := os.CreateTemp(filepath.Dir(filePath), ".guard-status-*.tmp")
	if err != nil {
		return fmt.Errorf("创建状态临时文件失败: %w", err)
	}

	tmpName := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("写入状态临时文件失败: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("关闭状态临时文件失败: %w", err)
	}
	if err := os.Rename(tmpName, filePath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("更新状态文件失败: %w", err)
	}
	return nil
}

func readStatusFile(filePath string) (statusFilePayload, error) {
	var payload statusFilePayload

	data, err := os.ReadFile(filePath)
	if err != nil {
		return payload, err
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return payload, fmt.Errorf("解析状态文件失败: %w", err)
	}
	return payload, nil
}

func removeIfExists(filePath string) error {
	if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func parseBoolValue(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "on", "yes":
		return true, nil
	case "0", "false", "off", "no":
		return false, nil
	default:
		return false, fmt.Errorf("无效布尔值：%s", value)
	}
}

func boolToUint8(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func usageError() error {
	printUsage(os.Stderr)
	return fmt.Errorf("缺少子命令")
}

func printUsage(file *os.File) {
	_, _ = fmt.Fprintln(file, "用法:")
	_, _ = fmt.Fprintln(file, "  pfwd-guard apply --iface IFACE --xdp-mode off|auto|force --xdp-pin PATH --ingress-pin PATH --status-file PATH [--whitelist-file FILE] --whitelist-enabled true|false --xdp-whitelist true|false --allow-any-ports TSV --allow-ports TSV --block-http true|false --block-tls true|false --block-socks true|false")
	_, _ = fmt.Fprintln(file, "  pfwd-guard remove --xdp-pin PATH --ingress-pin PATH --status-file PATH")
	_, _ = fmt.Fprintln(file, "  pfwd-guard status --status-file PATH")
	_, _ = fmt.Fprintln(file, "  pfwd-guard version")
}
