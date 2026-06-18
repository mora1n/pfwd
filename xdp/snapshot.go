//go:build !geobuild

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

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
	var dropCounterMap *ebpf.Map
	dropCounterMap, err = ebpf.LoadPinnedMap(pinLayout.RuleDropCounter, nil)
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
		Passed            uint64       `json:"passed"`
		Dropped           uint64       `json:"dropped"`
		Forwarded         uint64       `json:"forwarded"`
		QuotaDropped      uint64       `json:"quota_dropped"`
		WhitelistDropped  uint64       `json:"whitelist_dropped"`
		ProtocolDropped   uint64       `json:"protocol_dropped"`
		ParseSkipped      uint64       `json:"parse_skipped"`
		TCPPrewarmed      uint64       `json:"tcp_prewarmed"`
		TCPEstablished    uint64       `json:"tcp_established"`
		HostEgressDropped uint64       `json:"host_egress_dropped"`
		ActiveSummary     *connSummary `json:"active_summary,omitempty"`
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
		&payload.HostEgressDropped,
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

func connAddrString(value connVal) (string, error) {
	addr16 := value.ClientAddr
	if bytes.Equal(addr16[4:], make([]byte, 12)) {
		v4 := [4]byte{addr16[0], addr16[1], addr16[2], addr16[3]}
		return netip.AddrFrom4(v4).String(), nil
	}
	addr, ok := netip.AddrFromSlice(addr16[:])
	if !ok {
		return "", fmt.Errorf("无效 client_addr")
	}
	return addr.String(), nil
}

func whitelistLeaseActivity(pinLayout runtimeMapPins) ([]whitelistLeaseActivityRow, error) {
	connMap, err := ebpf.LoadPinnedMap(pinLayout.Connections, nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []whitelistLeaseActivityRow{}, nil
		}
		return nil, fmt.Errorf("加载 pinned connections map 失败: %w", err)
	}
	defer connMap.Close()

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return nil, fmt.Errorf("读取 CLOCK_MONOTONIC 失败: %w", err)
	}
	nowMonoNS := uint64(ts.Nano())
	nowEpoch := time.Now().Unix()

	rows := map[string]int64{}
	it := connMap.Iterate()
	var key connKey
	var value connVal
	for it.Next(&key, &value) {
		if value.LastSeenNS == 0 {
			continue
		}
		address, err := connAddrString(value)
		if err != nil {
			continue
		}
		if value.LastSeenNS > nowMonoNS {
			continue
		}
		ageSec := int64((nowMonoNS - value.LastSeenNS) / uint64(time.Second))
		seen := nowEpoch - ageSec
		if seen <= 0 {
			continue
		}
		if current, ok := rows[address]; !ok || seen > current {
			rows[address] = seen
		}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("遍历 connection map 失败: %w", err)
	}
	out := make([]whitelistLeaseActivityRow, 0, len(rows))
	for address, lastSeen := range rows {
		out = append(out, whitelistLeaseActivityRow{
			Address:    address,
			LastSeenAt: lastSeen,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Address < out[j].Address
	})
	return out, nil
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
