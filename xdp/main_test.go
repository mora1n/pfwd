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
	"slices"
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
			city := segment.City
			if city == "" {
				city = "0"
			}
			raw := "中国|" + segment.Province + "|" + city + "|0|0"
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
			city := segment.City
			if city == "" {
				city = "0"
			}
			raw := "中国|" + segment.Province + "|" + city + "|0|0"
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

func testRuleKey(family uint8, protocol uint8, listenPort uint16) ruleKey {
	return ruleKey{
		Family:     family,
		Protocol:   protocol,
		ListenPort: htons(listenPort),
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
					testRuleKey(4, 6, 38182): baseRuleSemantics(t),
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
					testRuleKey(4, 6, 38182): semantics,
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
					testRuleKey(4, 6, 38182): semantics,
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
					testRuleKey(4, 6, 38182): semantics,
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
					testRuleKey(4, 6, 38182): semantics,
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
					testRuleKey(4, 6, 38182): semantics,
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

func TestMakeRuleKeyRejectsConcreteListenIP(t *testing.T) {
	_, err := makeRuleKey(runtimeRule{
		IPVersion:  4,
		Protocol:   "tcp",
		ListenPort: 38182,
		ListenIP:   "47.79.34.146",
	})
	if err == nil || !strings.Contains(err.Error(), "不支持具体 listen_ip") {
		t.Fatalf("makeRuleKey error=%v, want concrete listen_ip rejection", err)
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

func TestGeoExport(t *testing.T) {
	tmpDir := t.TempDir()
	meta := geoAssetMeta{
		FormatVersion: geoAssetVersion,
		BuiltAt:       time.Now().UTC().Format(time.RFC3339),
		Provinces: []geoProvinceEntry{
			{ID: 1, Name: "浙江省"},
			{ID: 2, Name: "湖南省"},
		},
		IPv4Buckets:  0,
		IPv4Segments: 2,
		IPv4Prefixes: 2,
		IPv6Buckets:  0,
		IPv6Segments: 1,
		IPv6Prefixes: 1,
	}
	metaContent, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal geo meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, geoMetaAssetFile), metaContent, 0o644); err != nil {
		t.Fatalf("write geo meta: %v", err)
	}
	v4Prefixes := []geoPrefixV4{
		{PrefixLen: 24, Addr: binary.BigEndian.Uint32([]byte{203, 0, 113, 0}), ProvinceID: 1},
		{PrefixLen: 24, Addr: binary.BigEndian.Uint32([]byte{198, 51, 100, 0}), ProvinceID: 2},
	}
	if err := writeGeoAssetV4(filepath.Join(tmpDir, geoIPv4AssetFile), v4Prefixes, 2); err != nil {
		t.Fatalf("writeGeoAssetV4: %v", err)
	}
	v6Prefixes := []geoPrefixV6{
		{PrefixLen: 112, Addr: netip.MustParseAddr("240e::").As16(), ProvinceID: 1},
	}
	if err := writeGeoAssetV6(filepath.Join(tmpDir, geoIPv6AssetFile), v6Prefixes, 2); err != nil {
		t.Fatalf("writeGeoAssetV6: %v", err)
	}

	capture := func(opts geoExportOptions) (string, error) {
		t.Helper()
		var out bytes.Buffer
		oldStdout := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe geo export: %v", err)
		}
		os.Stdout = w
		err = geoExport(opts)
		_ = w.Close()
		os.Stdout = oldStdout
		_, _ = io.Copy(&out, r)
		_ = r.Close()
		return out.String(), err
	}

	all, err := capture(geoExportOptions{AssetDir: tmpDir, Mode: "all", IPVersion: "46"})
	if err != nil {
		t.Fatalf("geoExport all: %v", err)
	}
	wantAll := "203.0.113.0/24\n198.51.100.0/24\n240e::/112\n"
	if all != wantAll {
		t.Fatalf("geoExport all=%q, want %q", all, wantAll)
	}

	provinceV4, err := capture(geoExportOptions{AssetDir: tmpDir, Mode: "provinces", ProvinceCSV: "浙江省", IPVersion: "4"})
	if err != nil {
		t.Fatalf("geoExport province v4: %v", err)
	}
	if provinceV4 != "203.0.113.0/24\n" {
		t.Fatalf("geoExport province v4=%q, want Zhejiang v4 only", provinceV4)
	}

	empty, err := capture(geoExportOptions{AssetDir: tmpDir, Mode: "provinces", IPVersion: "4"})
	if err != nil {
		t.Fatalf("geoExport empty province: %v", err)
	}
	if empty != "" {
		t.Fatalf("geoExport empty province=%q, want empty", empty)
	}
}

func TestCityIPv4AssetRoundTripAndExport(t *testing.T) {
	tmpDir := t.TempDir()
	meta := `{
  "provinces": [
    {
      "name": "湖南省",
      "code": "430000",
      "cities": [
        {"name": "长沙市", "code": "430100"},
        {"name": "株洲市", "code": "430200"}
      ]
    }
  ]
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, cityMetaAssetFile), []byte(meta), 0o644); err != nil {
		t.Fatalf("write city meta: %v", err)
	}
	catalog, err := loadCityMetaIndex(filepath.Join(tmpDir, cityMetaAssetFile))
	if err != nil {
		t.Fatalf("loadCityMetaIndex: %v", err)
	}
	segments := []xdbScanSegmentV4{
		{Province: "湖南省", City: "长沙市", Start: mustIPv4XDBBytes(t, "203.0.113.0"), End: mustIPv4XDBBytes(t, "203.0.113.255")},
		{Province: "湖南省", City: "株洲市", Start: mustIPv4XDBBytes(t, "198.51.100.0"), End: mustIPv4XDBBytes(t, "198.51.100.255")},
	}
	if err := writeCityIPv4AssetFromSegments(filepath.Join(tmpDir, cityIPv4AssetFile), segments, catalog); err != nil {
		t.Fatalf("writeCityIPv4AssetFromSegments: %v", err)
	}
	indexes, prefixes, err := readCityIPv4Asset(filepath.Join(tmpDir, cityIPv4AssetFile))
	if err != nil {
		t.Fatalf("readCityIPv4Asset: %v", err)
	}
	if len(indexes) != 2 || len(prefixes) != 2 {
		t.Fatalf("city asset indexes=%d prefixes=%d, want 2/2", len(indexes), len(prefixes))
	}
	index, ok := findCityIndex(indexes, 430100)
	if !ok || index.Count != 1 {
		t.Fatalf("findCityIndex(430100)=%+v ok=%v, want one prefix", index, ok)
	}
	codesPath := filepath.Join(tmpDir, "codes.txt")
	if err := os.WriteFile(codesPath, []byte("430100\n"), 0o644); err != nil {
		t.Fatalf("write city codes: %v", err)
	}

	var out bytes.Buffer
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe city export: %v", err)
	}
	os.Stdout = w
	err = cityExport(cityExportOptions{AssetDir: tmpDir, CodesFile: codesPath})
	_ = w.Close()
	os.Stdout = oldStdout
	_, _ = io.Copy(&out, r)
	_ = r.Close()
	if err != nil {
		t.Fatalf("cityExport: %v", err)
	}
	want := "430100\t湖南省\t长沙市\t203.0.113.0/24\n"
	if out.String() != want {
		t.Fatalf("cityExport output=%q, want %q", out.String(), want)
	}
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

func TestGeoCheckHiddenCNUnknownOnlyAllowsAllMode(t *testing.T) {
	tmpDir := t.TempDir()
	meta := geoAssetMeta{
		FormatVersion: geoAssetVersion,
		BuiltAt:       time.Now().UTC().Format(time.RFC3339),
		Provinces: []geoProvinceEntry{
			{ID: 1, Name: "浙江省"},
			{ID: 2, Name: geoHiddenCNProvinceName, Hidden: true},
		},
		IPv4Segments: 1,
		IPv4Prefixes: 1,
	}
	metaContent, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, geoMetaAssetFile), metaContent, 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	prefixes := []geoPrefixV4{
		{PrefixLen: 24, Addr: binary.BigEndian.Uint32([]byte{39, 144, 124, 0}), ProvinceID: 2},
	}
	if err := writeGeoAssetV4(filepath.Join(tmpDir, geoIPv4AssetFile), prefixes, 2); err != nil {
		t.Fatalf("write v4 asset: %v", err)
	}
	if err := writeGeoAssetV6(filepath.Join(tmpDir, geoIPv6AssetFile), nil, 2); err != nil {
		t.Fatalf("write v6 asset: %v", err)
	}

	capture := func(opts geoCheckOptions) (geoCheckResult, error) {
		t.Helper()
		var out bytes.Buffer
		stdout := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		os.Stdout = w
		err = geoCheck(opts)
		_ = w.Close()
		os.Stdout = stdout
		_, _ = io.Copy(&out, r)
		_ = r.Close()
		var result geoCheckResult
		if decodeErr := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &result); decodeErr != nil {
			t.Fatalf("unmarshal geoCheck json: %v output=%q", decodeErr, out.String())
		}
		return result, err
	}

	all, err := capture(geoCheckOptions{AssetDir: tmpDir, Address: "39.144.124.183", Mode: "all", JSON: true})
	if err != nil {
		t.Fatalf("geoCheck all: %v", err)
	}
	if !all.Allowed || !all.GeoAllowed || all.Province != geoHiddenCNProvinceName || all.MatchedSource != "geo" {
		t.Fatalf("geoCheck all=%+v, want hidden CN geo allow", all)
	}

	provinces, err := capture(geoCheckOptions{AssetDir: tmpDir, Address: "39.144.124.183", Mode: "provinces", ProvinceCSV: "浙江省," + geoHiddenCNProvinceName, JSON: true})
	if err == nil || !strings.Contains(err.Error(), "省份未授权") {
		t.Fatalf("geoCheck provinces error=%v, want province deny", err)
	}
	if provinces.Allowed || provinces.GeoAllowed || provinces.MatchedSource != "province-deny" {
		t.Fatalf("geoCheck provinces=%+v, want deny hidden province", provinces)
	}
}

func TestAdysecIPMergeUnknownCNAndHiddenSubtract(t *testing.T) {
	tmpDir := t.TempDir()
	meta := `{
  "provinces": [
    {
      "name": "浙江省",
      "code": "330000",
      "cities": [
        {"name": "杭州市", "code": "330100"}
      ]
    }
  ]
}`
	metaPath := filepath.Join(tmpDir, cityMetaAssetFile)
	if err := os.WriteFile(metaPath, []byte(meta), 0o644); err != nil {
		t.Fatalf("write city meta: %v", err)
	}
	catalog, err := loadCityMetaIndex(metaPath)
	if err != nil {
		t.Fatalf("loadCityMetaIndex: %v", err)
	}
	mergePath := filepath.Join(tmpDir, "ip.merge.txt")
	content := strings.Join([]string{
		"39.144.101.0|39.144.136.255|中国|0|0|0|移动",
		"39.144.137.0|39.144.137.255|中国|0|浙江|杭州|移动",
		"",
	}, "\n")
	if err := os.WriteFile(mergePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write ip.merge: %v", err)
	}
	var out geoSupplementalSegments
	record := geoSourceRecord{Name: "test-ip-merge"}
	if err := ingestIPMergeSource(mergePath, catalog, &record, &out); err != nil {
		t.Fatalf("ingestIPMergeSource: %v", err)
	}
	if record.RowsAccepted != 2 {
		t.Fatalf("RowsAccepted=%d, want 2", record.RowsAccepted)
	}
	if len(out.V4) != 2 || out.V4[0].Province != geoHiddenCNProvinceName || out.V4[1].Province != "浙江省" || out.V4[1].City != "杭州市" {
		t.Fatalf("segments=%+v, want hidden unknown and 浙江/杭州", out.V4)
	}
	if len(out.CityV4) != 1 || out.CityV4[0].City != "杭州市" {
		t.Fatalf("city segments=%+v, want only 杭州", out.CityV4)
	}

	base := []xdbScanSegmentV4{
		{Province: "浙江省", Start: mustIPv4XDBBytes(t, "39.144.124.0"), End: mustIPv4XDBBytes(t, "39.144.124.255")},
	}
	final := finalizeGeoSegmentsV4(base, out.V4[:1])
	for _, segment := range final {
		if segment.Province != geoHiddenCNProvinceName {
			continue
		}
		start := xdbIPv4SegmentValue(segment.Start)
		end := xdbIPv4SegmentValue(segment.End)
		target := binary.BigEndian.Uint32([]byte{39, 144, 124, 183})
		if start <= target && target <= end {
			t.Fatalf("hidden segment still covers known 浙江 range: %+v", segment)
		}
	}
}

func TestNormalizeGeoSegmentsCanonicalizesCorruptProvinceNames(t *testing.T) {
	tmpDir := t.TempDir()
	meta := `{
  "provinces": [
    {
      "name": "浙江省",
      "code": "330000",
      "cities": [
        {"name": "杭州市", "code": "330100"}
      ]
    }
  ]
}`
	metaPath := filepath.Join(tmpDir, cityMetaAssetFile)
	if err := os.WriteFile(metaPath, []byte(meta), 0o644); err != nil {
		t.Fatalf("write city meta: %v", err)
	}
	catalog, err := loadCityMetaIndex(metaPath)
	if err != nil {
		t.Fatalf("loadCityMetaIndex: %v", err)
	}

	v4 := normalizeGeoSegmentsV4([]xdbScanSegmentV4{
		{Province: "\x01}\u8dcc\u000e中国–浙江–杭州", City: ""},
		{Province: "中国", City: ""},
		{Province: "台湾省", City: ""},
	}, catalog)
	if len(v4) != 3 {
		t.Fatalf("normalizeGeoSegmentsV4 len=%d, want 3", len(v4))
	}
	if v4[0].Province != "浙江省" {
		t.Fatalf("v4[0].Province=%q, want 浙江省", v4[0].Province)
	}
	if v4[1].Province != geoHiddenCNProvinceName {
		t.Fatalf("v4[1].Province=%q, want hidden", v4[1].Province)
	}
	if v4[2].Province != "台湾省" {
		t.Fatalf("v4[2].Province=%q, want 台湾省", v4[2].Province)
	}

	v6 := normalizeGeoSegmentsV6([]xdbScanSegmentV6{
		{Province: "\u0007\u0004\uFFFD'中国–浙江–杭州"},
		{Province: "中国"},
		{Province: "香港特别行政区"},
	}, catalog)
	if len(v6) != 3 {
		t.Fatalf("normalizeGeoSegmentsV6 len=%d, want 3", len(v6))
	}
	if v6[0].Province != "浙江省" {
		t.Fatalf("v6[0].Province=%q, want 浙江省", v6[0].Province)
	}
	if v6[1].Province != geoHiddenCNProvinceName {
		t.Fatalf("v6[1].Province=%q, want hidden", v6[1].Province)
	}
	if v6[2].Province != "香港特别行政区" {
		t.Fatalf("v6[2].Province=%q, want 香港特别行政区", v6[2].Province)
	}

	if got := normalizeGeoProvinceName("Dubai", catalog); got != geoHiddenCNProvinceName {
		t.Fatalf("normalizeGeoProvinceName(Dubai)=%q, want hidden", got)
	}
	if got := normalizeGeoProvinceName("114DNS", catalog); got != geoHiddenCNProvinceName {
		t.Fatalf("normalizeGeoProvinceName(114DNS)=%q, want hidden", got)
	}
	provinces := mergeProvinceNames(provinceSetFromSegmentsV4(v4), provinceSetFromSegmentsV6(v6))
	if slices.Contains(provinces, "Dubai") || slices.Contains(provinces, "114DNS") {
		t.Fatalf("merged provinces=%v, want noisy non-CN labels excluded", provinces)
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

func TestGeoAllowedProvinceIDs(t *testing.T) {
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
		name      string
		mode      string
		provinces []string
		want      map[uint16]struct{}
		wantErr   string
	}{
		{
			name:      "province mode selects requested province ids",
			mode:      "provinces",
			provinces: []string{"浙江省", "广东省", "广东省"},
			want: map[uint16]struct{}{
				1: {},
				2: {},
			},
		},
		{
			name: "all mode selects every known province",
			mode: "all",
			want: map[uint16]struct{}{
				1: {},
				2: {},
				3: {},
			},
		},
		{
			name: "off mode produces empty set",
			mode: "off",
			want: map[uint16]struct{}{},
		},
		{
			name:      "unknown province returns explicit error",
			mode:      "provinces",
			provinces: []string{"不存在省"},
			wantErr:   "未知白名单省份：不存在省",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := geoAllowedProvinceIDs(assets, tc.mode, tc.provinces)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("geoAllowedProvinceIDs error=%v, want contains %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("geoAllowedProvinceIDs: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("allowed len=%d, want %d: got=%v", len(got), len(tc.want), got)
			}
			for provinceID := range tc.want {
				if _, ok := got[provinceID]; !ok {
					t.Fatalf("province %d missing from allowed set: got=%v", provinceID, got)
				}
			}
		})
	}
}

func TestGeoWhitelistPrefixCounts(t *testing.T) {
	assets := &geoAssetRuntime{
		PrefixesV4: []geoPrefixV4{
			{ProvinceID: 1},
			{ProvinceID: 2},
			{ProvinceID: 2},
			{ProvinceID: 3},
		},
		PrefixesV6: []geoPrefixV6{
			{ProvinceID: 2},
			{ProvinceID: 4},
		},
	}
	allowed := map[uint16]struct{}{
		2: {},
		3: {},
	}

	got := countGeoWhitelistPrefixes(assets, allowed)
	if got.V4 != 3 || got.V6 != 1 {
		t.Fatalf("countGeoWhitelistPrefixes()=%+v, want V4=3 V6=1", got)
	}

	got = countGeoWhitelistPrefixes(assets, nil)
	if got.V4 != 0 || got.V6 != 0 {
		t.Fatalf("countGeoWhitelistPrefixes(nil allowed)=%+v, want zero", got)
	}
}

func TestValidateGeoWhitelistCapacity(t *testing.T) {
	if err := validateGeoWhitelistCapacity("v4", 3, 3); err != nil {
		t.Fatalf("validateGeoWhitelistCapacity exact fit: %v", err)
	}
	if err := validateGeoWhitelistCapacity("v6", 0, 0); err != nil {
		t.Fatalf("validateGeoWhitelistCapacity empty map: %v", err)
	}

	err := validateGeoWhitelistCapacity("v4", 4, 3)
	if err == nil {
		t.Fatalf("validateGeoWhitelistCapacity over capacity error=nil, want error")
	}
	want := "geo whitelist v4 prefixes=4 exceeds map max_entries=3"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("validateGeoWhitelistCapacity error=%q, want contains %q", err, want)
	}
}

func TestWhitelistV4MapCapacityCoversCurrentGeoAsset(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpBPFEL))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader: %v", err)
	}
	for _, name := range []string{"pfwd_whitelist_v4", "pfwd_egress_whitelist_v4"} {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			t.Fatalf("missing BPF map %s", name)
		}
		if mapSpec.MaxEntries < 131072 {
			t.Fatalf("%s max_entries=%d, want at least 131072", name, mapSpec.MaxEntries)
		}
	}

	data, err := os.ReadFile(filepath.Join("..", "assets", "pfwd-geo-meta.json"))
	if err != nil {
		t.Fatalf("read geo meta: %v", err)
	}
	var meta geoAssetMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("unmarshal geo meta: %v", err)
	}
	if meta.IPv4Prefixes > int(spec.Maps["pfwd_whitelist_v4"].MaxEntries) {
		t.Fatalf(
			"geo asset IPv4 prefixes=%d exceed pfwd_whitelist_v4 max_entries=%d",
			meta.IPv4Prefixes,
			spec.Maps["pfwd_whitelist_v4"].MaxEntries,
		)
	}
	if meta.IPv4Prefixes > int(spec.Maps["pfwd_egress_whitelist_v4"].MaxEntries) {
		t.Fatalf(
			"geo asset IPv4 prefixes=%d exceed pfwd_egress_whitelist_v4 max_entries=%d",
			meta.IPv4Prefixes,
			spec.Maps["pfwd_egress_whitelist_v4"].MaxEntries,
		)
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
		name         string
		policyID     uint16
		settings     runtimeSettings
		wantFlags    uint16
		denyFlags    uint16
		wantPolicyID uint16
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
			name: "whitelist enabled without sources blocks without LPM strategy",
			settings: runtimeSettings{
				WhitelistEnabled: true,
			},
			wantFlags: ruleFlagNeedsAllow,
			denyFlags: ruleFlagAllowCustom | ruleFlagAllowGeo,
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
		{
			name:     "port policy off overrides global geo",
			policyID: 7,
			settings: runtimeSettings{
				WhitelistEnabled: true,
				IngressPolicies: []ingressPolicy{
					{ID: 0, CNMode: "all"},
					{ID: 7, CNMode: "off"},
				},
			},
			wantFlags:    ruleFlagNeedsAllow,
			denyFlags:    ruleFlagAllowCustom | ruleFlagAllowGeo,
			wantPolicyID: 7,
		},
		{
			name:     "port city policy enables geo strategy",
			policyID: 7,
			settings: runtimeSettings{
				WhitelistEnabled: true,
				IngressPolicies: []ingressPolicy{
					{ID: 0, CNMode: "off"},
					{ID: 7, CNMode: "off", CNCityCodes: []string{"330100"}},
				},
			},
			wantFlags:    ruleFlagNeedsAllow | ruleFlagAllowGeo,
			denyFlags:    ruleFlagAllowCustom,
			wantPolicyID: 7,
		},
		{
			name:     "port province policy enables geo strategy",
			policyID: 7,
			settings: runtimeSettings{
				WhitelistEnabled: true,
				IngressPolicies: []ingressPolicy{
					{ID: 0, CNMode: "off"},
					{ID: 7, CNMode: "provinces", CNProvinces: []string{"浙江省"}},
				},
			},
			wantFlags:    ruleFlagNeedsAllow | ruleFlagAllowGeo,
			denyFlags:    ruleFlagAllowCustom,
			wantPolicyID: 7,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := baseRule
			rule.WhitelistPolicyID = tc.policyID
			got, err := makeRuleVal(rule, tc.settings)
			if err != nil {
				t.Fatalf("makeRuleVal: %v", err)
			}
			if got.Flags&tc.wantFlags != tc.wantFlags {
				t.Fatalf("flags=%#x, want bits %#x", got.Flags, tc.wantFlags)
			}
			if got.Flags&tc.denyFlags != 0 {
				t.Fatalf("flags=%#x, denied bits %#x present", got.Flags, got.Flags&tc.denyFlags)
			}
			if got.WhitelistPolicyID != tc.wantPolicyID {
				t.Fatalf("whitelist_policy_id=%d, want %d", got.WhitelistPolicyID, tc.wantPolicyID)
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

func TestRuleValABISize(t *testing.T) {
	if got, want := binary.Size(ruleVal{}), 104; got != want {
		t.Fatalf("ruleVal binary size=%d, want %d", got, want)
	}
}

func TestFlowKeyV4ABISize(t *testing.T) {
	if got, want := binary.Size(flowKeyV4{}), 16; got != want {
		t.Fatalf("flowKeyV4 binary size=%d, want %d", got, want)
	}
}

func TestRuntimeMapPinsIncludeIPv4GuardFlowCache(t *testing.T) {
	pins := runtimeMapPinsFromPaths(
		"/sys/fs/bpf/pfwd_rule_counters",
		"/sys/fs/bpf/pfwd_user_counters",
		"/sys/fs/bpf/pfwd_stats",
	)
	if pins.AllowedFlowsV4 == "" {
		t.Fatalf("AllowedFlowsV4 is empty")
	}
	if pins.AllowedFlowsV4 == pins.AllowedFlows {
		t.Fatalf("AllowedFlowsV4=%q must differ from AllowedFlows=%q", pins.AllowedFlowsV4, pins.AllowedFlows)
	}
	if !strings.HasSuffix(pins.AllowedFlowsV4, "/pfwd_allowed_flows_v4") {
		t.Fatalf("AllowedFlowsV4=%q, want suffix /pfwd_allowed_flows_v4", pins.AllowedFlowsV4)
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

func TestGuardRuntimeCacheChanged(t *testing.T) {
	base := runtimeAuxState{
		GuardEnabled:      true,
		WhitelistEnabled:  true,
		BlockHTTP:         true,
		BlockTLS:          true,
		BlockSOCKS:        true,
		ProtocolSkipPorts: []uint16{40422},
	}
	tests := []struct {
		name         string
		currentValid bool
		current      runtimeAuxState
		next         runtimeAuxState
		want         bool
	}{
		{
			name:         "unchanged valid state reuses cache",
			currentValid: true,
			current:      base,
			next:         base,
			want:         false,
		},
		{
			name:         "invalid current state reloads cache",
			currentValid: false,
			current:      base,
			next:         base,
			want:         true,
		},
		{
			name:         "protocol flag change reloads cache",
			currentValid: true,
			current:      base,
			next: func() runtimeAuxState {
				next := base
				next.BlockTLS = false
				return next
			}(),
			want: true,
		},
		{
			name:         "skip-port change reloads cache",
			currentValid: true,
			current:      base,
			next: func() runtimeAuxState {
				next := base
				next.ProtocolSkipPorts = []uint16{40422, 41423}
				return next
			}(),
			want: true,
		},
		{
			name:         "egress-only change does not reload guard cache",
			currentValid: true,
			current:      base,
			next: func() runtimeAuxState {
				next := base
				next.EgressWhitelistHashes = []whitelistContentHash{{Path: "/tmp/egress", Hash: "abc"}}
				return next
			}(),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := guardRuntimeCacheChanged(tc.currentValid, tc.current, tc.next)
			if got != tc.want {
				t.Fatalf("guardRuntimeCacheChanged()=%v, want %v", got, tc.want)
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
