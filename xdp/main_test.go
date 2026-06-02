package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type testXDBRegion struct {
	ptr uint32
	raw string
}

func writeTestXDBv4(t *testing.T, path string, segments []xdbScanSegmentV4) {
	t.Helper()
	writeTestXDB(t, path, 4, len(segments)*xdbIPv4SegmentSize, func(regionPtr uint32) [][]byte {
		out := make([][]byte, 0, len(segments))
		regions := map[string]testXDBRegion{}
		nextRegionPtr := regionPtr
		for _, segment := range segments {
			raw := "中国|" + segment.Province + "|0|0|0"
			info, ok := regions[raw]
			if !ok {
				info = testXDBRegion{ptr: nextRegionPtr, raw: raw}
				regions[raw] = info
				nextRegionPtr += uint32(len(raw))
			}
			entry := make([]byte, xdbIPv4SegmentSize)
			copy(entry[:4], segment.Start[:])
			copy(entry[4:8], segment.End[:])
			binary.LittleEndian.PutUint16(entry[8:], uint16(len(raw)))
			binary.LittleEndian.PutUint32(entry[10:], info.ptr)
			out = append(out, entry)
		}
		return out
	}, func() []byte {
		out := []byte{}
		seen := map[string]struct{}{}
		for _, segment := range segments {
			raw := "中国|" + segment.Province + "|0|0|0"
			if _, ok := seen[raw]; ok {
				continue
			}
			seen[raw] = struct{}{}
			out = append(out, []byte(raw)...)
		}
		return out
	})
}

func writeTestXDBv6(t *testing.T, path string, segments []xdbScanSegmentV6) {
	t.Helper()
	writeTestXDB(t, path, 6, len(segments)*xdbIPv6SegmentSize, func(regionPtr uint32) [][]byte {
		out := make([][]byte, 0, len(segments))
		regions := map[string]testXDBRegion{}
		nextRegionPtr := regionPtr
		for _, segment := range segments {
			raw := "中国|" + segment.Province + "|0|0|0"
			info, ok := regions[raw]
			if !ok {
				info = testXDBRegion{ptr: nextRegionPtr, raw: raw}
				regions[raw] = info
				nextRegionPtr += uint32(len(raw))
			}
			entry := make([]byte, xdbIPv6SegmentSize)
			copy(entry[:16], segment.Start[:])
			copy(entry[16:32], segment.End[:])
			binary.LittleEndian.PutUint16(entry[32:], uint16(len(raw)))
			binary.LittleEndian.PutUint32(entry[34:], info.ptr)
			out = append(out, entry)
		}
		return out
	}, func() []byte {
		out := []byte{}
		seen := map[string]struct{}{}
		for _, segment := range segments {
			raw := "中国|" + segment.Province + "|0|0|0"
			if _, ok := seen[raw]; ok {
				continue
			}
			seen[raw] = struct{}{}
			out = append(out, []byte(raw)...)
		}
		return out
	})
}

func writeTestXDB(t *testing.T, path string, ipVersion uint16, indexSize int, buildEntries func(regionPtr uint32) [][]byte, buildRegions func() []byte) {
	t.Helper()
	entries := buildEntries(uint32(xdbHeaderSize + indexSize))
	regions := buildRegions()
	header := make([]byte, xdbHeaderSize)
	binary.LittleEndian.PutUint16(header[xdbVersionOffset:], 2)
	binary.LittleEndian.PutUint32(header[xdbIndexStartOff:], xdbHeaderSize)
	if len(entries) == 0 {
		binary.LittleEndian.PutUint32(header[xdbIndexEndOff:], xdbHeaderSize)
	} else {
		binary.LittleEndian.PutUint32(header[xdbIndexEndOff:], uint32(xdbHeaderSize+indexSize-len(entries[0])))
	}
	binary.LittleEndian.PutUint16(header[xdbIPVersionOff:], ipVersion)
	binary.LittleEndian.PutUint16(header[xdbRuntimePtrOff:], 4)

	var payload bytes.Buffer
	payload.Write(header)
	for _, entry := range entries {
		payload.Write(entry)
	}
	payload.Write(regions)
	if err := os.WriteFile(path, payload.Bytes(), 0o644); err != nil {
		t.Fatalf("write test xdb: %v", err)
	}
}

func mustAddr16(t *testing.T, raw string) [16]byte {
	t.Helper()
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatalf("parse addr %q: %v", raw, err)
	}
	return addrTo16(addr)
}

func mustIPv4XDBBytes(t *testing.T, raw string) [4]byte {
	t.Helper()
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatalf("parse ipv4 addr %q: %v", raw, err)
	}
	v4 := addr.As4()
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], binary.BigEndian.Uint32(v4[:]))
	return out
}

func testRuleKey(family uint8, protocol uint8, listenPort uint16, listenAddr [16]byte) ruleKey {
	return ruleKey{
		Family:     family,
		Protocol:   protocol,
		ListenPort: htons(listenPort),
		ListenAddr: listenAddr,
	}
}

func baseConnKey(t *testing.T) connKey {
	t.Helper()
	return connKey{
		Family:     4,
		Protocol:   6,
		ClientPort: htons(44444),
		ListenPort: htons(38182),
		TargetPort: htons(80),
		ClientAddr: mustAddr16(t, "198.51.100.10"),
		ListenAddr: mustAddr16(t, "47.79.34.146"),
		TargetAddr: mustAddr16(t, "1.1.1.1"),
	}
}

func baseConnVal(t *testing.T) connVal {
	t.Helper()
	return connVal{
		RuleID:             2,
		UserID:             0,
		SourceAddr:         mustAddr16(t, "47.79.34.146"),
		SourcePort:         htons(40000),
		TrafficRatioScaled: ratioScale,
		BillingEnabled:     1,
	}
}

func baseRuleSemantics(t *testing.T) ruleSemantics {
	t.Helper()
	return ruleSemantics{
		RuleID:             2,
		UserID:             0,
		TargetAddr:         mustAddr16(t, "1.1.1.1"),
		TargetPort:         htons(80),
		TrafficRatioScaled: ratioScale,
		BillingEnabled:     1,
	}
}

func TestConnectionAllowedByRuntime(t *testing.T) {
	baseKey := baseConnKey(t)
	baseValue := baseConnVal(t)

	tests := []struct {
		name        string
		allowed     func(*testing.T) map[ruleKey]ruleSemantics
		value       func(connVal) connVal
		wantAllowed bool
	}{
		{
			name: "wildcard listen preserves matching connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): baseRuleSemantics(t),
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: true,
		},
		{
			name: "exact listen preserves matching connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, mustAddr16(t, "47.79.34.146")): baseRuleSemantics(t),
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: true,
		},
		{
			name: "target address change invalidates connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				semantics := baseRuleSemantics(t)
				semantics.TargetAddr = mustAddr16(t, "1.0.0.1")
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): semantics,
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: false,
		},
		{
			name: "fixed snat source change invalidates connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				semantics := baseRuleSemantics(t)
				semantics.SourceAddrFromRule = true
				semantics.SourceAddr = mustAddr16(t, "203.0.113.20")
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): semantics,
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: false,
		},
		{
			name: "unchanged fixed snat source preserves connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				semantics := baseRuleSemantics(t)
				semantics.SourceAddrFromRule = true
				semantics.SourceAddr = mustAddr16(t, "203.0.113.20")
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): semantics,
				}
			},
			value: func(value connVal) connVal {
				value.SourceAddr = mustAddr16(t, "203.0.113.20")
				return value
			},
			wantAllowed: true,
		},
		{
			name: "traffic mode change invalidates connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				semantics := baseRuleSemantics(t)
				semantics.TrafficMode = 1
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): semantics,
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: false,
		},
		{
			name: "billing mode change invalidates connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				semantics := baseRuleSemantics(t)
				semantics.BillingEnabled = 0
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): semantics,
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := connectionAllowedByRuntime(baseKey, tc.value(baseValue), tc.allowed(t))
			if got != tc.wantAllowed {
				t.Fatalf("connectionAllowedByRuntime()=%v, want %v", got, tc.wantAllowed)
			}
		})
	}
}

func TestRuleValEquivalentForRefresh(t *testing.T) {
	tests := []struct {
		name     string
		current  ruleVal
		expected ruleVal
		want     bool
	}{
		{
			name: "ignores billing base when billing disabled",
			current: ruleVal{
				RuleID:                   1,
				UserID:                   2,
				TargetPort:               htons(80),
				TrafficRatioScaled:       ratioScale,
				RuleBillingUsedBaseBytes: 100,
				UserBillingUsedBaseBytes: 200,
			},
			expected: ruleVal{
				RuleID:                   1,
				UserID:                   2,
				TargetPort:               htons(80),
				TrafficRatioScaled:       ratioScale,
				RuleBillingUsedBaseBytes: 300,
				UserBillingUsedBaseBytes: 400,
			},
			want: true,
		},
		{
			name: "detects billing base change when billing enabled",
			current: ruleVal{
				RuleID:                   1,
				UserID:                   2,
				TargetPort:               htons(80),
				TrafficRatioScaled:       ratioScale,
				BillingEnabled:           1,
				RuleBillingUsedBaseBytes: 100,
				UserBillingUsedBaseBytes: 200,
			},
			expected: ruleVal{
				RuleID:                   1,
				UserID:                   2,
				TargetPort:               htons(80),
				TrafficRatioScaled:       ratioScale,
				BillingEnabled:           1,
				RuleBillingUsedBaseBytes: 300,
				UserBillingUsedBaseBytes: 400,
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleValEquivalentForRefresh(tc.current, tc.expected)
			if got != tc.want {
				t.Fatalf("ruleValEquivalentForRefresh()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestGeoAssetRoundTripAndLookup(t *testing.T) {
	t.Run("v4 roundtrip and bucket lookup", func(t *testing.T) {
		tmpDir := t.TempDir()
		buckets := make([]geoBucket, geoBucketEntries)
		bucketIndex := int(1)<<8 | int(2)
		buckets[bucketIndex] = geoBucket{Start: 0, Count: 2}
		segments := []geoSegmentV4{
			{Start: binary.BigEndian.Uint32([]byte{1, 2, 0, 0}), End: binary.BigEndian.Uint32([]byte{1, 2, 0, 255}), ProvinceID: 1},
			{Start: binary.BigEndian.Uint32([]byte{1, 2, 1, 0}), End: binary.BigEndian.Uint32([]byte{1, 2, 1, 255}), ProvinceID: 2},
		}
		path := filepath.Join(tmpDir, geoIPv4AssetFile)
		if err := writeGeoAssetV4(path, buckets, segments, 2); err != nil {
			t.Fatalf("writeGeoAssetV4: %v", err)
		}
		gotBuckets, gotSegments, ipVer, err := readGeoAssetV4(path)
		if err != nil {
			t.Fatalf("readGeoAssetV4: %v", err)
		}
		if ipVer != 4 {
			t.Fatalf("readGeoAssetV4 ipVer=%d, want 4", ipVer)
		}
		if gotBuckets[bucketIndex].Count != 2 {
			t.Fatalf("bucket count=%d, want 2", gotBuckets[bucketIndex].Count)
		}
		found, ok := findGeoSegmentV4(gotSegments, gotBuckets[bucketIndex], binary.BigEndian.Uint32([]byte{1, 2, 1, 42}))
		if !ok {
			t.Fatalf("findGeoSegmentV4 not found")
		}
		if found.ProvinceID != 2 {
			t.Fatalf("findGeoSegmentV4 province=%d, want 2", found.ProvinceID)
		}
	})

	t.Run("v6 roundtrip and bucket lookup", func(t *testing.T) {
		tmpDir := t.TempDir()
		buckets := make([]geoBucket, geoBucketEntries)
		bucketIndex := int(0x24)<<8 | int(0x0e)
		buckets[bucketIndex] = geoBucket{Start: 0, Count: 1}
		start := netip.MustParseAddr("240e::").As16()
		end := netip.MustParseAddr("240e::ffff").As16()
		segments := []geoSegmentV6{
			{Start: start, End: end, ProvinceID: 3},
		}
		path := filepath.Join(tmpDir, geoIPv6AssetFile)
		if err := writeGeoAssetV6(path, buckets, segments, 3); err != nil {
			t.Fatalf("writeGeoAssetV6: %v", err)
		}
		gotBuckets, gotSegments, ipVer, err := readGeoAssetV6(path)
		if err != nil {
			t.Fatalf("readGeoAssetV6: %v", err)
		}
		if ipVer != 6 {
			t.Fatalf("readGeoAssetV6 ipVer=%d, want 6", ipVer)
		}
		target := netip.MustParseAddr("240e::1234").As16()
		found, ok := findGeoSegmentV6(gotSegments, gotBuckets[bucketIndex], target)
		if !ok {
			t.Fatalf("findGeoSegmentV6 not found")
		}
		if found.ProvinceID != 3 {
			t.Fatalf("findGeoSegmentV6 province=%d, want 3", found.ProvinceID)
		}
	})
}

func TestGeoCheckWithCustomCIDRAndProvinceMode(t *testing.T) {
	tmpDir := t.TempDir()
	meta := geoAssetMeta{
		FormatVersion: geoAssetVersion,
		BuiltAt:       time.Now().UTC().Format(time.RFC3339),
		Provinces: []geoProvinceEntry{
			{ID: 1, Name: "广东省"},
		},
		IPv4Buckets:  geoBucketEntries,
		IPv4Segments: 1,
		IPv6Buckets:  geoBucketEntries,
		IPv6Segments: 0,
	}
	metaContent, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, geoMetaAssetFile), metaContent, 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	buckets := make([]geoBucket, geoBucketEntries)
	bucketIndex := int(1)<<8 | int(2)
	buckets[bucketIndex] = geoBucket{Start: 0, Count: 1}
	segments := []geoSegmentV4{
		{Start: binary.BigEndian.Uint32([]byte{1, 2, 0, 0}), End: binary.BigEndian.Uint32([]byte{1, 2, 255, 255}), ProvinceID: 1},
	}
	if err := writeGeoAssetV4(filepath.Join(tmpDir, geoIPv4AssetFile), buckets, segments, 1); err != nil {
		t.Fatalf("write v4 asset: %v", err)
	}
	if err := writeGeoAssetV6(filepath.Join(tmpDir, geoIPv6AssetFile), make([]geoBucket, geoBucketEntries), nil, 1); err != nil {
		t.Fatalf("write v6 asset: %v", err)
	}

	customPath := filepath.Join(tmpDir, "custom.txt")
	if err := os.WriteFile(customPath, []byte("203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatalf("write custom cidr: %v", err)
	}

	var out bytes.Buffer
	stdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = stdout }()

	err = geoCheck(geoCheckOptions{
		AssetDir:      tmpDir,
		Address:       "203.0.113.7",
		Mode:          "provinces",
		ProvinceCSV:   "广东省",
		WhitelistFile: customPath,
	})
	_ = w.Close()
	_, _ = io.Copy(&out, r)
	_ = r.Close()
	if err != nil {
		t.Fatalf("geoCheck(custom allow): %v", err)
	}
	if !strings.Contains(out.String(), "allow custom") {
		t.Fatalf("geoCheck output=%q, want custom allow", out.String())
	}
}

func TestGeoAssetPlanningAndStreamingBuild(t *testing.T) {
	t.Run("v4 bucket planning uses prefix offsets", func(t *testing.T) {
		tmpDir := t.TempDir()
		xdbPath := filepath.Join(tmpDir, "test-v4.xdb")
		segs := []xdbScanSegmentV4{
			{Province: "广东省", Start: mustIPv4XDBBytes(t, "1.2.0.0"), End: mustIPv4XDBBytes(t, "1.2.0.255")},
			{Province: "广东省", Start: mustIPv4XDBBytes(t, "1.3.0.0"), End: mustIPv4XDBBytes(t, "1.3.0.255")},
			{Province: "北京市", Start: mustIPv4XDBBytes(t, "2.0.0.0"), End: mustIPv4XDBBytes(t, "2.0.255.255")},
		}
		writeTestXDBv4(t, xdbPath, segs)

		plan, stats, err := planGeoAssetV4(xdbPath)
		if err != nil {
			t.Fatalf("planGeoAssetV4: %v", err)
		}
		if stats.BucketCount != 3 {
			t.Fatalf("bucket count=%d, want 3", stats.BucketCount)
		}
		if stats.SegmentCount != 3 {
			t.Fatalf("segment count=%d, want 3", stats.SegmentCount)
		}
		if stats.MaxBucketCount != 1 {
			t.Fatalf("max bucket count=%d, want 1", stats.MaxBucketCount)
		}
		if stats.MaxLookupSteps != 1 {
			t.Fatalf("max lookup steps=%d, want 1", stats.MaxLookupSteps)
		}
		if got := plan.Buckets[int(1)<<8|int(2)]; got != (geoBucket{Start: 0, Count: 1}) {
			t.Fatalf("bucket 1.2=%+v, want {Start:0 Count:1}", got)
		}
		if got := plan.Buckets[int(1)<<8|int(3)]; got != (geoBucket{Start: 1, Count: 1}) {
			t.Fatalf("bucket 1.3=%+v, want {Start:1 Count:1}", got)
		}
		if got := plan.Buckets[int(2)<<8|int(0)]; got != (geoBucket{Start: 2, Count: 1}) {
			t.Fatalf("bucket 2.0=%+v, want {Start:2 Count:1}", got)
		}

		outPath := filepath.Join(tmpDir, geoIPv4AssetFile)
		provinceIDs := map[string]uint16{"北京市": 1, "广东省": 2}
		if err := writeGeoAssetV4FromSegments(outPath, plan, segs, provinceIDs, 2); err != nil {
			t.Fatalf("writeGeoAssetV4FromSegments: %v", err)
		}
		buckets, segments, ipVer, err := readGeoAssetV4(outPath)
		if err != nil {
			t.Fatalf("readGeoAssetV4: %v", err)
		}
		if ipVer != 4 {
			t.Fatalf("ipVer=%d, want 4", ipVer)
		}
		target := binary.BigEndian.Uint32([]byte{1, 3, 0, 42})
		found, ok := findGeoSegmentV4(segments, buckets[int(1)<<8|int(3)], target)
		if !ok {
			t.Fatalf("findGeoSegmentV4 not found")
		}
		if found.ProvinceID != 2 {
			t.Fatalf("province=%d, want 2", found.ProvinceID)
		}
	})

	t.Run("v6 streaming write preserves lookup", func(t *testing.T) {
		tmpDir := t.TempDir()
		xdbPath := filepath.Join(tmpDir, "test-v6.xdb")
		segs := []xdbScanSegmentV6{
			{Province: "广东省", Start: netip.MustParseAddr("240e::").As16(), End: netip.MustParseAddr("240e::ffff").As16()},
			{Province: "北京市", Start: netip.MustParseAddr("240f::").As16(), End: netip.MustParseAddr("240f::ffff").As16()},
		}
		writeTestXDBv6(t, xdbPath, segs)

		plan, stats, err := planGeoAssetV6(xdbPath)
		if err != nil {
			t.Fatalf("planGeoAssetV6: %v", err)
		}
		if stats.BucketCount != 2 {
			t.Fatalf("bucket count=%d, want 2", stats.BucketCount)
		}
		if stats.SegmentCount != 2 {
			t.Fatalf("segment count=%d, want 2", stats.SegmentCount)
		}

		outPath := filepath.Join(tmpDir, geoIPv6AssetFile)
		provinceIDs := map[string]uint16{"北京市": 1, "广东省": 2}
		if err := writeGeoAssetV6FromSegments(outPath, plan, segs, provinceIDs, 2); err != nil {
			t.Fatalf("writeGeoAssetV6FromSegments: %v", err)
		}
		buckets, segments, ipVer, err := readGeoAssetV6(outPath)
		if err != nil {
			t.Fatalf("readGeoAssetV6: %v", err)
		}
		if ipVer != 6 {
			t.Fatalf("ipVer=%d, want 6", ipVer)
		}
		target := netip.MustParseAddr("240f::1234").As16()
		found, ok := findGeoSegmentV6(segments, buckets[int(target[0])<<8|int(target[1])], target)
		if !ok {
			t.Fatalf("findGeoSegmentV6 not found")
		}
		if found.ProvinceID != 1 {
			t.Fatalf("province=%d, want 1", found.ProvinceID)
		}
	})
}

func TestProtocolSkipPortHelpers(t *testing.T) {
	tests := []struct {
		name             string
		left             []uint16
		right            []uint16
		wantEqual        bool
		wantChangedItems int
	}{
		{
			name:             "same set different order",
			left:             []uint16{443, 80, 8080},
			right:            []uint16{8080, 443, 80},
			wantEqual:        true,
			wantChangedItems: 0,
		},
		{
			name:             "one removed one added",
			left:             []uint16{80, 443},
			right:            []uint16{443, 8080},
			wantEqual:        false,
			wantChangedItems: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := protocolSkipPortsEqual(tc.left, tc.right); got != tc.wantEqual {
				t.Fatalf("protocolSkipPortsEqual()=%v, want %v", got, tc.wantEqual)
			}
			if got := countChangedProtocolSkipPorts(tc.left, tc.right); got != tc.wantChangedItems {
				t.Fatalf("countChangedProtocolSkipPorts()=%d, want %d", got, tc.wantChangedItems)
			}
		})
	}
}

func TestWhitelistHashHelpers(t *testing.T) {
	tests := []struct {
		name             string
		left             []whitelistContentHash
		right            []whitelistContentHash
		wantEqual        bool
		wantChangedItems int
	}{
		{
			name: "same hashes different order",
			left: []whitelistContentHash{
				{Path: "/tmp/b", Hash: "bbb"},
				{Path: "/tmp/a", Hash: "aaa"},
			},
			right: []whitelistContentHash{
				{Path: "/tmp/a", Hash: "aaa"},
				{Path: "/tmp/b", Hash: "bbb"},
			},
			wantEqual:        true,
			wantChangedItems: 0,
		},
		{
			name: "hash update plus file add/remove",
			left: []whitelistContentHash{
				{Path: "/tmp/a", Hash: "aaa"},
				{Path: "/tmp/b", Hash: "bbb"},
			},
			right: []whitelistContentHash{
				{Path: "/tmp/a", Hash: "aaa2"},
				{Path: "/tmp/c", Hash: "ccc"},
			},
			wantEqual:        false,
			wantChangedItems: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := whitelistHashesEqual(tc.left, tc.right); got != tc.wantEqual {
				t.Fatalf("whitelistHashesEqual()=%v, want %v", got, tc.wantEqual)
			}
			if got := countChangedWhitelistHashes(tc.left, tc.right); got != tc.wantChangedItems {
				t.Fatalf("countChangedWhitelistHashes()=%d, want %d", got, tc.wantChangedItems)
			}
		})
	}
}

func TestGeoPolicyChangeHelpers(t *testing.T) {
	base := runtimeAuxState{
		IngressCNMode:      "provinces",
		IngressCNProvinces: []string{"广东省", "浙江省"},
		EgressCNMode:       "all",
		EgressCNProvinces:  nil,
	}
	tests := []struct {
		name        string
		next        runtimeAuxState
		wantIngress bool
		wantEgress  bool
	}{
		{
			name:        "same policy ignores province order",
			next:        runtimeAuxState{IngressCNMode: "provinces", IngressCNProvinces: []string{"浙江省", "广东省"}, EgressCNMode: "all"},
			wantIngress: false,
			wantEgress:  false,
		},
		{
			name:        "ingress province change",
			next:        runtimeAuxState{IngressCNMode: "provinces", IngressCNProvinces: []string{"广东省"}, EgressCNMode: "all"},
			wantIngress: true,
			wantEgress:  false,
		},
		{
			name:        "egress mode change",
			next:        runtimeAuxState{IngressCNMode: "provinces", IngressCNProvinces: []string{"广东省", "浙江省"}, EgressCNMode: "provinces", EgressCNProvinces: []string{"广东省"}},
			wantIngress: false,
			wantEgress:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ingressGeoPolicyChanged(base, tc.next); got != tc.wantIngress {
				t.Fatalf("ingressGeoPolicyChanged()=%v, want %v", got, tc.wantIngress)
			}
			if got := egressGeoPolicyChanged(base, tc.next); got != tc.wantEgress {
				t.Fatalf("egressGeoPolicyChanged()=%v, want %v", got, tc.wantEgress)
			}
		})
	}
}

func TestAuxStateValid(t *testing.T) {
	tests := []struct {
		name    string
		payload statusPayload
		want    bool
	}{
		{
			name:    "empty payload invalid",
			payload: statusPayload{},
			want:    false,
		},
		{
			name:    "matching version valid",
			payload: statusPayload{AuxStateVersion: auxStateVersion},
			want:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := auxStateValid(tc.payload); got != tc.want {
				t.Fatalf("auxStateValid()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestStatusPayloadMarshalsAuxStateAndRefreshDetails(t *testing.T) {
	payload := statusPayload{
		Applied:         true,
		AuxStateVersion: auxStateVersion,
		AuxState: runtimeAuxState{
			GuardEnabled:      true,
			WhitelistEnabled:  true,
			HostEgressEnabled: true,
			BlockTLS:          true,
			ProtocolSkipPorts: []uint16{443, 8443},
			WhitelistHashes: []whitelistContentHash{
				{Path: "/tmp/allow_v4.txt", Hash: "abc"},
			},
		},
		RefreshReport: &refreshReport{
			Mode: "incremental",
			AuxActions: []auxActionSummary{
				{Component: "whitelist", Action: "reuse"},
				{Component: "protocol_skip_ports", Action: "delta-update", ChangedItems: 2},
			},
			AttachTimings: []attachTiming{
				{Component: "xdp", DurationMillis: 3},
			},
		},
	}
	content, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal status payload: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("unmarshal status payload: %v", err)
	}
	if decoded["aux_state_version"] == nil {
		t.Fatal("aux_state_version missing from JSON payload")
	}
	refreshRaw, ok := decoded["refresh_report"].(map[string]any)
	if !ok {
		t.Fatal("refresh_report missing from JSON payload")
	}
	if _, ok := refreshRaw["aux_actions"]; !ok {
		t.Fatal("refresh_report.aux_actions missing from JSON payload")
	}
	if _, ok := refreshRaw["attach_timings"]; !ok {
		t.Fatal("refresh_report.attach_timings missing from JSON payload")
	}
}

func TestElapsedMillis(t *testing.T) {
	start := time.Now().Add(-1500 * time.Millisecond)
	elapsed := elapsedMillis(start)
	if elapsed < 1000 {
		t.Fatalf("elapsedMillis returned %d, want at least 1000", elapsed)
	}
}

type fakeTCXLink struct {
	*link.RawLink
}

func (fakeTCXLink) Update(*ebpf.Program) error { return nil }
func (fakeTCXLink) Pin(string) error           { return nil }
func (fakeTCXLink) Unpin() error               { return nil }
func (fakeTCXLink) Close() error               { return nil }
func (fakeTCXLink) Detach() error              { return nil }
func (fakeTCXLink) Info() (*link.Info, error)  { return nil, nil }

func TestAttachTCXOnceCacheBehavior(t *testing.T) {
	orig := tcxAttachFunc
	defer func() {
		tcxAttachFunc = orig
		resetTCXCapabilityCache()
	}()

	iface := &net.Interface{Index: 7, Name: "eth-test"}
	prog := &ebpf.Program{}
	tests := []struct {
		name      string
		results   []error
		wantCalls int
	}{
		{
			name:      "cache unsupported failure",
			results:   []error{link.ErrNotSupported, link.ErrNotSupported},
			wantCalls: 1,
		},
		{
			name:      "do not cache transient failure",
			results:   []error{errors.New("permission denied"), nil},
			wantCalls: 2,
		},
		{
			name:      "success stays retryable",
			results:   []error{nil, nil},
			wantCalls: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetTCXCapabilityCache()
			callCount := 0
			tcxAttachFunc = func(opts link.TCXOptions) (link.Link, error) {
				if callCount >= len(tc.results) {
					t.Fatalf("unexpected attach call %d", callCount+1)
				}
				err := tc.results[callCount]
				callCount++
				if err != nil {
					return nil, err
				}
				return fakeTCXLink{}, nil
			}

			first, firstErr := attachTCXOnce(iface, prog, ebpf.AttachTCXIngress)
			if tc.results[0] == nil {
				if firstErr != nil || first == nil {
					t.Fatalf("first attach = (%v, %v), want success", first, firstErr)
				}
			} else if firstErr == nil {
				t.Fatalf("first attach unexpectedly succeeded")
			}

			second, secondErr := attachTCXOnce(iface, prog, ebpf.AttachTCXIngress)
			lastErr := tc.results[len(tc.results)-1]
			if lastErr == nil {
				if secondErr != nil || second == nil {
					t.Fatalf("second attach = (%v, %v), want success", second, secondErr)
				}
			} else if secondErr == nil {
				t.Fatalf("second attach unexpectedly succeeded")
			}

			if callCount != tc.wantCalls {
				t.Fatalf("attach call count = %d, want %d", callCount, tc.wantCalls)
			}
		})
	}
}
