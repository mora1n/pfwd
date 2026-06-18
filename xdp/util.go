//go:build !geobuild

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

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

func ipv4BEToBytes(value uint32) [4]byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], value)
	return out
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

func tcFilterPrefHasPFWDProgram(ifaceName string, direction string, pref string) bool {
	cmd := exec.Command("tc", "filter", "show", "dev", ifaceName, direction, "pref", pref)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	text := string(output)
	return strings.Contains(text, "name pfwd_") || strings.Contains(text, "pfwd_xdp_")
}

func removeLegacyTCFilters(ifaceName string, direction string, currentPref string) {
	if ifaceName == "" || currentPref == tcLegacyDefaultBPFPreference {
		return
	}
	if tcFilterPrefHasPFWDProgram(ifaceName, direction, tcLegacyDefaultBPFPreference) {
		_ = runTC("filter", "delete", "dev", ifaceName, direction, "pref", tcLegacyDefaultBPFPreference)
	}
}

func usageError() error {
	printUsage(os.Stderr)
	return fmt.Errorf("缺少子命令")
}

func printUsage(file *os.File) {
	_, _ = fmt.Fprintln(file, "用法：")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp apply --runtime-file FILE --state-file FILE --status-file FILE --iface IFACE --guard-mode off|ingress|full --xdp-pin PATH --ingress-pin PATH [--host-egress-pin PATH --loopback-pin PATH --rule-counter-pin PATH --user-counter-pin PATH --stats-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp remove --status-file FILE --xdp-pin PATH --ingress-pin PATH [--host-egress-pin PATH --loopback-pin PATH --rule-counter-pin PATH --user-counter-pin PATH --stats-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp status --status-file FILE")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp snapshot --runtime-file FILE --state-file FILE [--status-file FILE --rule-counter-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp stats [--status-file FILE --stats-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp whitelist-lease-activity [--rule-counter-pin PATH --user-counter-pin PATH --stats-pin PATH]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp geo-export --asset-dir DIR --mode all|provinces [--provinces CSV --ip-version 4|6|46]")
	_, _ = fmt.Fprintln(file, "  pfwd-xdp city-export --asset-dir DIR --codes-file FILE")
}
