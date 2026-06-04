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
	t.Run("v4 prefix roundtrip and lookup", func(t *testing.T) {
		tmpDir := t.TempDir()
		prefixes := []geoPrefixV4{
			{PrefixLen: 24, Addr: binary.BigEndian.Uint32([]byte{1, 2, 0, 0}), ProvinceID: 1},
			{PrefixLen: 24, Addr: binary.BigEndian.Uint32([]byte{1, 2, 1, 0}), ProvinceID: 2},
		}
		path := filepath.Join(tmpDir, geoIPv4AssetFile)
		if err := writeGeoAssetV4(path, prefixes, 2); err != nil {
			t.Fatalf("writeGeoAssetV4: %v", err)
		}
		gotPrefixes, ipVer, err := readGeoAssetV4(path)
		if err != nil {
			t.Fatalf("readGeoAssetV4: %v", err)
		}
		if ipVer != 4 {
			t.Fatalf("readGeoAssetV4 ipVer=%d, want 4", ipVer)
		}
		if len(gotPrefixes) != 2 {
			t.Fatalf("prefix count=%d, want 2", len(gotPrefixes))
		}
		found, ok := findGeoPrefixV4(gotPrefixes, binary.BigEndian.Uint32([]byte{1, 2, 1, 42}))
		if !ok {
			t.Fatalf("findGeoPrefixV4 not found")
		}
		if found.ProvinceID != 2 {
			t.Fatalf("findGeoPrefixV4 province=%d, want 2", found.ProvinceID)
		}
	})

	t.Run("v6 prefix roundtrip and lookup", func(t *testing.T) {
		tmpDir := t.TempDir()
		start := netip.MustParseAddr("240e::").As16()
		prefixes := []geoPrefixV6{
			{PrefixLen: 112, Addr: start, ProvinceID: 3},
		}
		path := filepath.Join(tmpDir, geoIPv6AssetFile)
		if err := writeGeoAssetV6(path, prefixes, 3); err != nil {
			t.Fatalf("writeGeoAssetV6: %v", err)
		}
		gotPrefixes, ipVer, err := readGeoAssetV6(path)
		if err != nil {
			t.Fatalf("readGeoAssetV6: %v", err)
		}
		if ipVer != 6 {
			t.Fatalf("readGeoAssetV6 ipVer=%d, want 6", ipVer)
		}
		target := netip.MustParseAddr("240e::1234").As16()
		found, ok := findGeoPrefixV6(gotPrefixes, target)
		if !ok {
			t.Fatalf("findGeoPrefixV6 not found")
		}
		if found.ProvinceID != 3 {
			t.Fatalf("findGeoPrefixV6 province=%d, want 3", found.ProvinceID)
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
		IPv4Buckets:  0,
		IPv4Segments: 1,
		IPv4Prefixes: 1,
		IPv6Buckets:  0,
		IPv6Segments: 0,
	}
	metaContent, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, geoMetaAssetFile), metaContent, 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	prefixes := []geoPrefixV4{
		{PrefixLen: 16, Addr: binary.BigEndian.Uint32([]byte{1, 2, 0, 0}), ProvinceID: 1},
	}
	if err := writeGeoAssetV4(filepath.Join(tmpDir, geoIPv4AssetFile), prefixes, 1); err != nil {
		t.Fatalf("write v4 asset: %v", err)
	}
	if err := writeGeoAssetV6(filepath.Join(tmpDir, geoIPv6AssetFile), nil, 1); err != nil {
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

	cityPath := filepath.Join(tmpDir, "city.tsv")
	if err := os.WriteFile(cityPath, []byte("430100\t湖南省\t长沙市\t203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatalf("write city cidr: %v", err)
	}
	out.Reset()
	r, w, err = os.Pipe()
	if err != nil {
		t.Fatalf("pipe city json: %v", err)
	}
	os.Stdout = w
	err = geoCheck(geoCheckOptions{
		AssetDir: tmpDir,
		Address:  "203.0.113.7",
		Mode:     "provinces",
		CityFile: cityPath,
		JSON:     true,
	})
	_ = w.Close()
	_, _ = io.Copy(&out, r)
	_ = r.Close()
	if err != nil {
		t.Fatalf("geoCheck(city allow): %v", err)
	}
	var cityResult geoCheckResult
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &cityResult); err != nil {
		t.Fatalf("unmarshal city geoCheck json: %v output=%q", err, out.String())
	}
	if !cityResult.Allowed || !cityResult.CityAllowed || cityResult.CityCode != "430100" || cityResult.MatchedSource != "city" {
		t.Fatalf("geoCheck city json=%+v, want allowed city 430100", cityResult)
	}

	out.Reset()
	r, w, err = os.Pipe()
	if err != nil {
		t.Fatalf("pipe json: %v", err)
	}
	os.Stdout = w
	err = geoCheck(geoCheckOptions{
		AssetDir:    tmpDir,
		Address:     "1.2.3.4",
		Mode:        "provinces",
		ProvinceCSV: "浙江省",
		JSON:        true,
	})
	_ = w.Close()
	_, _ = io.Copy(&out, r)
	_ = r.Close()
	if err == nil || !strings.Contains(err.Error(), "省份未授权") {
		t.Fatalf("geoCheck(json deny) error=%v, want province deny", err)
	}
	var result geoCheckResult
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &result); err != nil {
		t.Fatalf("unmarshal geoCheck json: %v output=%q", err, out.String())
	}
	if result.Allowed || result.GeoAllowed || result.Province != "广东省" || result.MatchedSource != "province-deny" {
		t.Fatalf("geoCheck json=%+v, want denied 广东省 province-deny", result)
	}
}

func TestGeoAssetPlanningAndStreamingBuild(t *testing.T) {
	t.Run("v4 planning merges adjacent ranges into prefixes", func(t *testing.T) {
		tmpDir := t.TempDir()
		xdbPath := filepath.Join(tmpDir, "test-v4.xdb")
		segs := []xdbScanSegmentV4{
			{Province: "广东省", Start: mustIPv4XDBBytes(t, "1.2.0.0"), End: mustIPv4XDBBytes(t, "1.2.0.255")},
			{Province: "广东省", Start: mustIPv4XDBBytes(t, "1.2.1.0"), End: mustIPv4XDBBytes(t, "1.2.1.255")},
			{Province: "北京市", Start: mustIPv4XDBBytes(t, "2.0.0.0"), End: mustIPv4XDBBytes(t, "2.0.255.255")},
		}
		writeTestXDBv4(t, xdbPath, segs)

		plan, stats, err := planGeoAssetV4(xdbPath)
		if err != nil {
			t.Fatalf("planGeoAssetV4: %v", err)
		}
		if stats.RawSegmentCount != 3 {
			t.Fatalf("raw segment count=%d, want 3", stats.RawSegmentCount)
		}
		if stats.MergedSegmentCount != 2 {
			t.Fatalf("merged segment count=%d, want 2", stats.MergedSegmentCount)
		}
		if stats.PrefixCount != 2 || plan.PrefixCount != 2 {
			t.Fatalf("prefix count stats=%d plan=%d, want 2", stats.PrefixCount, plan.PrefixCount)
		}

		outPath := filepath.Join(tmpDir, geoIPv4AssetFile)
		provinceIDs := map[string]uint16{"北京市": 1, "广东省": 2}
		if err := writeGeoAssetV4FromSegments(outPath, plan, segs, provinceIDs, 2); err != nil {
			t.Fatalf("writeGeoAssetV4FromSegments: %v", err)
		}
		prefixes, ipVer, err := readGeoAssetV4(outPath)
		if err != nil {
			t.Fatalf("readGeoAssetV4: %v", err)
		}
		if ipVer != 4 {
			t.Fatalf("ipVer=%d, want 4", ipVer)
		}
		target := binary.BigEndian.Uint32([]byte{1, 2, 1, 42})
		found, ok := findGeoPrefixV4(prefixes, target)
		if !ok {
			t.Fatalf("findGeoPrefixV4 not found")
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
		if stats.RawSegmentCount != 2 {
			t.Fatalf("raw segment count=%d, want 2", stats.RawSegmentCount)
		}
		if stats.PrefixCount != 2 || plan.PrefixCount != 2 {
			t.Fatalf("prefix count stats=%d plan=%d, want 2", stats.PrefixCount, plan.PrefixCount)
		}

		outPath := filepath.Join(tmpDir, geoIPv6AssetFile)
		provinceIDs := map[string]uint16{"北京市": 1, "广东省": 2}
		if err := writeGeoAssetV6FromSegments(outPath, plan, segs, provinceIDs, 2); err != nil {
			t.Fatalf("writeGeoAssetV6FromSegments: %v", err)
		}
		prefixes, ipVer, err := readGeoAssetV6(outPath)
		if err != nil {
			t.Fatalf("readGeoAssetV6: %v", err)
		}
		if ipVer != 6 {
			t.Fatalf("ipVer=%d, want 6", ipVer)
		}
		target := netip.MustParseAddr("240f::1234").As16()
		found, ok := findGeoPrefixV6(prefixes, target)
		if !ok {
			t.Fatalf("findGeoPrefixV6 not found")
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

func TestGeoPolicyFlagsByProvince(t *testing.T) {
	assets := &geoAssetRuntime{
		Meta: geoAssetMeta{
			Provinces: []geoProvinceEntry{
				{ID: 1, Name: "广东省"},
				{ID: 2, Name: "浙江省"},
				{ID: 3, Name: "北京市"},
			},
		},
		ProvinceIDs: map[string]uint16{
			"广东省": 1,
			"浙江省": 2,
			"北京市": 3,
		},
	}

	tests := []struct {
		name             string
		ingressMode      string
		ingressProvinces []string
		egressMode       string
		egressProvinces  []string
		want             map[uint16]uint8
		wantErr          string
	}{
		{
			name:             "ingress provinces and egress all merge flags",
			ingressMode:      "provinces",
			ingressProvinces: []string{"浙江省", "广东省"},
			egressMode:       "all",
			want: map[uint16]uint8{
				1: geoPolicyIngress | geoPolicyEgress,
				2: geoPolicyIngress | geoPolicyEgress,
				3: geoPolicyEgress,
			},
		},
		{
			name:        "disabled modes produce empty flags",
			want:        map[uint16]uint8{},
			ingressMode: "off",
			egressMode:  "off",
		},
		{
			name:             "unknown ingress province returns explicit error",
			ingressMode:      "provinces",
			ingressProvinces: []string{"不存在省"},
			wantErr:          "未知入口省份：不存在省",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := geoPolicyFlagsByProvince(assets, tc.ingressMode, tc.ingressProvinces, tc.egressMode, tc.egressProvinces)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("geoPolicyFlagsByProvince error=%v, want contains %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("geoPolicyFlagsByProvince: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("flags len=%d, want %d: got=%v", len(got), len(tc.want), got)
			}
			for provinceID, wantFlags := range tc.want {
				if got[provinceID] != wantFlags {
					t.Fatalf("province %d flags=%d, want %d", provinceID, got[provinceID], wantFlags)
				}
			}
		})
	}
}

func TestMakeRuleValGuardFlags(t *testing.T) {
	baseRule := runtimeRule{
		Index:          1,
		UserIndex:      2,
		Protocol:       "tcp",
		ResolvedTarget: "192.0.2.10",
		RemotePort:     443,
		TrafficRatio:   1,
	}
	tests := []struct {
		name      string
		rule      runtimeRule
		settings  runtimeSettings
		wantFlags uint16
		denyFlags uint16
	}{
		{
			name: "tcp guard encodes protocol filters and skip ports",
			rule: baseRule,
			settings: runtimeSettings{
				GuardEnabled:      true,
				BlockHTTP:         true,
				BlockTLS:          true,
				ProtocolSkipPorts: []uint16{443},
			},
			wantFlags: ruleFlagNeedsGuard | ruleFlagHasSkipPorts | ruleFlagBlockHTTP | ruleFlagBlockTLS,
			denyFlags: ruleFlagBlockSOCKS,
		},
		{
			name: "tcp skip ports without protocol filters only encode bypass",
			rule: baseRule,
			settings: runtimeSettings{
				GuardEnabled:      true,
				ProtocolSkipPorts: []uint16{443},
			},
			wantFlags: ruleFlagHasSkipPorts,
			denyFlags: ruleFlagNeedsGuard | ruleFlagBlockHTTP | ruleFlagBlockTLS | ruleFlagBlockSOCKS,
		},
		{
			name: "udp guard settings encode skip ports but not tcp-only filters",
			rule: func() runtimeRule {
				rule := baseRule
				rule.Protocol = "udp"
				return rule
			}(),
			settings: runtimeSettings{
				GuardEnabled:      true,
				BlockHTTP:         true,
				BlockTLS:          true,
				BlockSOCKS:        true,
				ProtocolSkipPorts: []uint16{443},
			},
			wantFlags: ruleFlagHasSkipPorts,
			denyFlags: ruleFlagNeedsGuard | ruleFlagBlockHTTP | ruleFlagBlockTLS | ruleFlagBlockSOCKS,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := makeRuleVal(tc.rule, tc.settings)
			if err != nil {
				t.Fatalf("makeRuleVal: %v", err)
			}
			if got.Flags&tc.wantFlags != tc.wantFlags {
				t.Fatalf("flags=%#x, want bits %#x", got.Flags, tc.wantFlags)
			}
			if got.Flags&tc.denyFlags != 0 {
				t.Fatalf("flags=%#x, denied bits %#x present", got.Flags, got.Flags&tc.denyFlags)
			}
		})
	}
}

func TestMakeRuleValWhitelistFlags(t *testing.T) {
	baseRule := runtimeRule{
		Index:          1,
		UserIndex:      2,
		Protocol:       "tcp",
		ResolvedTarget: "192.0.2.10",
		RemotePort:     443,
		TrafficRatio:   1,
	}
	tests := []struct {
		name      string
		settings  runtimeSettings
		wantFlags uint16
		denyFlags uint16
	}{
		{
			name: "whitelist off leaves allow strategy empty",
			settings: runtimeSettings{
				WhitelistFiles: []string{"/tmp/custom.txt"},
				IngressCNMode:  "all",
			},
			denyFlags: ruleFlagNeedsAllow | ruleFlagAllowCustom | ruleFlagAllowGeo,
		},
		{
			name: "custom only uses LPM strategy",
			settings: runtimeSettings{
				WhitelistEnabled: true,
				WhitelistFiles:   []string{"/tmp/custom.txt"},
			},
			wantFlags: ruleFlagNeedsAllow | ruleFlagAllowCustom,
			denyFlags: ruleFlagAllowGeo,
		},
		{
			name: "geo only skips custom LPM",
			settings: runtimeSettings{
				WhitelistEnabled: true,
				IngressCNMode:    "provinces",
			},
			wantFlags: ruleFlagNeedsAllow | ruleFlagAllowGeo,
			denyFlags: ruleFlagAllowCustom,
		},
		{
			name: "custom and geo enable both strategies",
			settings: runtimeSettings{
				WhitelistEnabled: true,
				WhitelistFiles:   []string{"/tmp/custom.txt"},
				IngressCNMode:    "all",
			},
			wantFlags: ruleFlagNeedsAllow | ruleFlagAllowCustom | ruleFlagAllowGeo,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := makeRuleVal(baseRule, tc.settings)
			if err != nil {
				t.Fatalf("makeRuleVal: %v", err)
			}
			if got.Flags&tc.wantFlags != tc.wantFlags {
				t.Fatalf("flags=%#x, want bits %#x", got.Flags, tc.wantFlags)
			}
			if got.Flags&tc.denyFlags != 0 {
				t.Fatalf("flags=%#x, denied bits %#x present", got.Flags, got.Flags&tc.denyFlags)
			}
		})
	}
}

func TestMakeXDPSettingsEgressWhitelistStrategy(t *testing.T) {
	tests := []struct {
		name       string
		settings   runtimeSettings
		wantCustom uint8
		wantGeo    uint8
	}{
		{
			name: "egress custom only",
			settings: runtimeSettings{
				EgressWhitelistFiles: []string{"/tmp/egress.txt"},
			},
			wantCustom: 1,
		},
		{
			name: "egress geo only",
			settings: runtimeSettings{
				EgressCNMode: "all",
			},
			wantGeo: 1,
		},
		{
			name: "egress custom and geo enable both strategies",
			settings: runtimeSettings{
				EgressWhitelistFiles: []string{"/tmp/egress.txt"},
				EgressCNMode:         "provinces",
			},
			wantCustom: 1,
			wantGeo:    1,
		},
		{
			name: "blank custom paths are ignored",
			settings: runtimeSettings{
				EgressWhitelistFiles: []string{"", " "},
				EgressCNMode:         "off",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := makeXDPSettings(tc.settings, 7)
			if got.EgressWhitelistCustom != tc.wantCustom ||
				got.EgressWhitelistGeo != tc.wantGeo {
				t.Fatalf("egress strategy custom=%d geo=%d, want %d/%d",
					got.EgressWhitelistCustom, got.EgressWhitelistGeo,
					tc.wantCustom, tc.wantGeo)
			}
			if got.ExternalIfindex != 7 {
				t.Fatalf("ExternalIfindex=%d, want 7", got.ExternalIfindex)
			}
		})
	}
}

func TestXDPSettingsABISize(t *testing.T) {
	if got, want := binary.Size(xdpSettings{}), 20; got != want {
		t.Fatalf("xdpSettings binary size=%d, want %d", got, want)
	}
}

func TestRuntimeStatusReusableRequiresCurrentMapABI(t *testing.T) {
	opts := applyOptions{GuardMode: "full"}
	settings := runtimeSettings{}
	status := statusPayload{
		Applied:       true,
		BinaryVersion: binaryVersion,
		MapABIVersion: mapABIVersion,
		ConfigHash:    "hash",
		GuardMode:     "full",
		Interface:     "eth0",
	}
	if !runtimeStatusReusable(status, settings, opts, "eth0", nil, "hash") {
		t.Fatalf("runtimeStatusReusable()=false, want true")
	}

	status.MapABIVersion = mapABIVersion - 1
	if runtimeStatusReusable(status, settings, opts, "eth0", nil, "hash") {
		t.Fatalf("runtimeStatusReusable()=true for stale ABI, want false")
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
