package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	geoAssetMagic    = "PFGE"
	geoAssetVersion  = 2
	geoHeaderSize    = 20
	geoBucketEntries = 1 << 16

	geoIPv4AssetFile = "pfwd-geo-cn-v4.bin"
	geoIPv6AssetFile = "pfwd-geo-cn-v6.bin"
	geoMetaAssetFile = "pfwd-geo-meta.json"

	cityIPv4AssetFile = "pfwd-city-cn-v4.bin"
	cityMetaAssetFile = "pfwd-city-cn-meta.json"
	cityAssetMagic    = "PFCI"
	cityAssetVersion  = 1
	cityHeaderSize    = 20
	cityIndexSize     = 12
	cityPrefixSize    = 8

	xdbHeaderSize      = 256
	xdbVersionOffset   = 0
	xdbIndexStartOff   = 8
	xdbIndexEndOff     = 12
	xdbIPVersionOff    = 16
	xdbRuntimePtrOff   = 18
	xdbIPv4SegmentSize = 14
	xdbIPv6SegmentSize = 38

	// Keep these limits in sync with xdp.bpf.c.
	geoSegmentV4MapMaxEntries = 131072
	geoSegmentV6MapMaxEntries = 32768
	geoBuildTimeout           = 5 * time.Minute
	geoDownloadTimeout        = 2 * time.Minute
)

var (
	defaultGeoIPv4DownloadURLs = []string{
		"https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb",
		"https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
	}
	defaultGeoIPv6DownloadURLs = []string{
		"https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v6.xdb",
		"https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb",
	}
)

type geoBuilderOptions struct {
	AssetDir string
}

type geoHeader struct {
	Magic         [4]byte
	Version       uint16
	IPVersion     uint16
	BucketCount   uint32
	SegmentCount  uint32
	ProvinceCount uint32
}

type geoBucket struct {
	Start uint32
	Count uint32
}

type geoPrefixV4 struct {
	PrefixLen  uint32
	Addr       uint32
	ProvinceID uint16
	Pad        uint16
}

type geoPrefixV6 struct {
	PrefixLen  uint32
	Addr       [16]byte
	ProvinceID uint16
	Pad        uint16
}

type geoDownloadRecord struct {
	RequestedURLs []string `json:"requested_urls"`
	SelectedURL   string   `json:"selected_url"`
	SHA256        string   `json:"sha256"`
	Bytes         int64    `json:"bytes"`
	XDBVersion    uint16   `json:"xdb_version"`
	IPVersion     uint16   `json:"ip_version"`
	IndexStart    uint32   `json:"index_start"`
	IndexEnd      uint32   `json:"index_end"`
}

type geoProvinceEntry struct {
	ID   uint16 `json:"id"`
	Name string `json:"name"`
}

type cityAssetMeta struct {
	Provinces []cityProvinceMeta `json:"provinces"`
}

type cityProvinceMeta struct {
	Name   string          `json:"name"`
	Code   string          `json:"code"`
	Cities []cityEntryMeta `json:"cities"`
}

type cityEntryMeta struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

type geoAssetMeta struct {
	FormatVersion uint16             `json:"format_version"`
	BuiltAt       string             `json:"built_at"`
	IPv4          geoDownloadRecord  `json:"ipv4"`
	IPv6          geoDownloadRecord  `json:"ipv6"`
	Provinces     []geoProvinceEntry `json:"provinces"`
	IPv4Buckets   int                `json:"ipv4_buckets"`
	IPv4Segments  int                `json:"ipv4_segments"`
	IPv4Raw       int                `json:"ipv4_raw_segments"`
	IPv4Merged    int                `json:"ipv4_merged_segments"`
	IPv4Prefixes  int                `json:"ipv4_prefixes"`
	IPv6Buckets   int                `json:"ipv6_buckets"`
	IPv6Segments  int                `json:"ipv6_segments"`
	IPv6Raw       int                `json:"ipv6_raw_segments"`
	IPv6Merged    int                `json:"ipv6_merged_segments"`
	IPv6Prefixes  int                `json:"ipv6_prefixes"`
}

type geoAssetRuntime struct {
	Meta        geoAssetMeta
	PrefixesV4  []geoPrefixV4
	PrefixesV6  []geoPrefixV6
	ProvinceIDs map[string]uint16
}

type geoProvincePolicyVal struct {
	Flags uint8
	Pad   [3]byte
}

type downloadedXDB struct {
	Path        string
	Header      []byte
	SHA256      string
	SelectedURL string
	Bytes       int64
}

type xdbScanSegmentV4 struct {
	Province string
	City     string
	Start    [4]byte
	End      [4]byte
}

type xdbScanSegmentV6 struct {
	Province string
	Start    [16]byte
	End      [16]byte
}

type geoRangeV4 struct {
	Province string
	Start    uint32
	End      uint32
}

type cityRangeV4 struct {
	Code  uint32
	Start uint32
	End   uint32
}

type geoRangeV6 struct {
	Province string
	Start    [16]byte
	End      [16]byte
}

type geoAssetPlan struct {
	PrefixCount uint32
}

type geoAssetStats struct {
	BucketCount        int
	SegmentCount       int
	RawSegmentCount    int
	MergedSegmentCount int
	PrefixCount        int
	MaxBucketCount     uint32
	MaxLookupSteps     int
}

type cityHeader struct {
	Magic       [4]byte
	Version     uint16
	IPVersion   uint16
	IndexCount  uint32
	PrefixCount uint32
	Reserved    uint32
}

type cityIndexRecord struct {
	Code   uint32
	Offset uint32
	Count  uint32
}

type cityPrefixV4 struct {
	PrefixLen uint32
	Addr      uint32
}

type cityMetaEntry struct {
	Code     uint32
	CodeText string
	Province string
	City     string
}

type xdbScanHandlerV4 func(segment xdbScanSegmentV4) error
type xdbScanHandlerV6 func(segment xdbScanSegmentV6) error

func buildGeoAssets(opts geoBuilderOptions) error {
	if opts.AssetDir == "" {
		return fmt.Errorf("缺少 geo 资产目录")
	}
	if err := os.MkdirAll(opts.AssetDir, 0o755); err != nil {
		return fmt.Errorf("创建 geo 资产目录失败: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), geoBuildTimeout)
	defer cancel()

	v4XDB, err := downloadGeoXDB(ctx, 4, defaultGeoIPv4DownloadURLs)
	if err != nil {
		return err
	}
	defer os.Remove(v4XDB.Path)

	v6XDB, err := downloadGeoXDB(ctx, 6, defaultGeoIPv6DownloadURLs)
	if err != nil {
		return err
	}
	defer os.Remove(v6XDB.Path)

	v4Segments, err := collectGeoSegmentsV4(v4XDB.Path)
	if err != nil {
		return err
	}
	v6Segments, err := collectGeoSegmentsV6(v6XDB.Path)
	if err != nil {
		return err
	}
	provinces := mergeProvinceNames(provinceSetFromSegmentsV4(v4Segments), provinceSetFromSegmentsV6(v6Segments))
	provinceIDs := make(map[string]uint16, len(provinces))
	provinceMeta := make([]geoProvinceEntry, 0, len(provinces))
	for i, province := range provinces {
		id := uint16(i + 1)
		provinceIDs[province] = id
		provinceMeta = append(provinceMeta, geoProvinceEntry{ID: id, Name: province})
	}

	v4Plan, v4Stats := planGeoAssetV4Segments(v4Segments)
	if v4Plan == nil {
		return fmt.Errorf("构建 geo v4 计划失败")
	}
	if err := validateGeoAssetStats("v4", v4Stats, geoSegmentV4MapMaxEntries); err != nil {
		return err
	}
	if err := writeGeoAssetV4FromSegments(filepath.Join(opts.AssetDir, geoIPv4AssetFile), v4Plan, v4Segments, provinceIDs, len(provinceMeta)); err != nil {
		return err
	}
	cityIndex, err := loadCityMetaIndex(filepath.Join(opts.AssetDir, cityMetaAssetFile))
	if err != nil {
		return err
	}
	if err := writeCityIPv4AssetFromSegments(filepath.Join(opts.AssetDir, cityIPv4AssetFile), v4Segments, cityIndex); err != nil {
		return err
	}

	v6Plan, v6Stats := planGeoAssetV6Segments(v6Segments)
	if v6Plan == nil {
		return fmt.Errorf("构建 geo v6 计划失败")
	}
	if err := validateGeoAssetStats("v6", v6Stats, geoSegmentV6MapMaxEntries); err != nil {
		return err
	}
	if err := writeGeoAssetV6FromSegments(filepath.Join(opts.AssetDir, geoIPv6AssetFile), v6Plan, v6Segments, provinceIDs, len(provinceMeta)); err != nil {
		return err
	}

	meta := geoAssetMeta{
		FormatVersion: geoAssetVersion,
		BuiltAt:       time.Now().UTC().Format(time.RFC3339),
		IPv4: geoDownloadRecord{
			RequestedURLs: append([]string{}, defaultGeoIPv4DownloadURLs...),
			SelectedURL:   v4XDB.SelectedURL,
			SHA256:        v4XDB.SHA256,
			Bytes:         v4XDB.Bytes,
			XDBVersion:    binary.LittleEndian.Uint16(v4XDB.Header[xdbVersionOffset:]),
			IPVersion:     binary.LittleEndian.Uint16(v4XDB.Header[xdbIPVersionOff:]),
			IndexStart:    binary.LittleEndian.Uint32(v4XDB.Header[xdbIndexStartOff:]),
			IndexEnd:      binary.LittleEndian.Uint32(v4XDB.Header[xdbIndexEndOff:]),
		},
		IPv6: geoDownloadRecord{
			RequestedURLs: append([]string{}, defaultGeoIPv6DownloadURLs...),
			SelectedURL:   v6XDB.SelectedURL,
			SHA256:        v6XDB.SHA256,
			Bytes:         v6XDB.Bytes,
			XDBVersion:    binary.LittleEndian.Uint16(v6XDB.Header[xdbVersionOffset:]),
			IPVersion:     binary.LittleEndian.Uint16(v6XDB.Header[xdbIPVersionOff:]),
			IndexStart:    binary.LittleEndian.Uint32(v6XDB.Header[xdbIndexStartOff:]),
			IndexEnd:      binary.LittleEndian.Uint32(v6XDB.Header[xdbIndexEndOff:]),
		},
		Provinces:    provinceMeta,
		IPv4Buckets:  0,
		IPv4Segments: v4Stats.PrefixCount,
		IPv4Raw:      v4Stats.RawSegmentCount,
		IPv4Merged:   v4Stats.MergedSegmentCount,
		IPv4Prefixes: v4Stats.PrefixCount,
		IPv6Buckets:  0,
		IPv6Segments: v6Stats.PrefixCount,
		IPv6Raw:      v6Stats.RawSegmentCount,
		IPv6Merged:   v6Stats.MergedSegmentCount,
		IPv6Prefixes: v6Stats.PrefixCount,
	}
	preserveStableGeoMetaFields(opts.AssetDir, &meta)
	content, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 geo 元数据失败: %w", err)
	}
	if err := os.WriteFile(filepath.Join(opts.AssetDir, geoMetaAssetFile), append(content, '\n'), 0o644); err != nil {
		return fmt.Errorf("写入 geo 元数据失败: %w", err)
	}
	return nil
}

func preserveStableGeoMetaFields(assetDir string, meta *geoAssetMeta) {
	if meta == nil {
		return
	}
	content, err := os.ReadFile(filepath.Join(assetDir, geoMetaAssetFile))
	if err != nil {
		return
	}
	var existing geoAssetMeta
	if err := json.Unmarshal(content, &existing); err != nil {
		return
	}
	if !geoMetaStableFingerprintEqual(existing, *meta) {
		return
	}
	meta.BuiltAt = existing.BuiltAt
	meta.IPv4.SelectedURL = existing.IPv4.SelectedURL
	meta.IPv6.SelectedURL = existing.IPv6.SelectedURL
}

func geoMetaStableFingerprintEqual(left geoAssetMeta, right geoAssetMeta) bool {
	left.BuiltAt = ""
	right.BuiltAt = ""
	left.IPv4.SelectedURL = ""
	right.IPv4.SelectedURL = ""
	left.IPv6.SelectedURL = ""
	right.IPv6.SelectedURL = ""
	leftBytes, err := json.Marshal(left)
	if err != nil {
		return false
	}
	rightBytes, err := json.Marshal(right)
	if err != nil {
		return false
	}
	return bytes.Equal(leftBytes, rightBytes)
}

func loadGeoAssets(assetDir string) (*geoAssetRuntime, error) {
	metaContent, err := os.ReadFile(filepath.Join(assetDir, geoMetaAssetFile))
	if err != nil {
		return nil, fmt.Errorf("读取 geo 元数据失败: %w", err)
	}
	var meta geoAssetMeta
	if err := json.Unmarshal(metaContent, &meta); err != nil {
		return nil, fmt.Errorf("解析 geo 元数据失败: %w", err)
	}

	prefixes4, ipVer4, err := readGeoAssetV4(filepath.Join(assetDir, geoIPv4AssetFile))
	if err != nil {
		return nil, err
	}
	if ipVer4 != 4 {
		return nil, fmt.Errorf("geo v4 资产 ip_version 错误: %d", ipVer4)
	}
	prefixes6, ipVer6, err := readGeoAssetV6(filepath.Join(assetDir, geoIPv6AssetFile))
	if err != nil {
		return nil, err
	}
	if ipVer6 != 6 {
		return nil, fmt.Errorf("geo v6 资产 ip_version 错误: %d", ipVer6)
	}

	provinceIDs := make(map[string]uint16, len(meta.Provinces))
	for _, province := range meta.Provinces {
		provinceIDs[province.Name] = province.ID
	}
	return &geoAssetRuntime{
		Meta:        meta,
		PrefixesV4:  prefixes4,
		PrefixesV6:  prefixes6,
		ProvinceIDs: provinceIDs,
	}, nil
}

func downloadGeoXDB(ctx context.Context, ipVersion uint16, urls []string) (*downloadedXDB, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("缺少 xdb 下载地址")
	}
	client := &http.Client{Timeout: geoDownloadTimeout}
	errorsSeen := make([]string, 0, len(urls))
	for _, rawURL := range urls {
		url := strings.TrimSpace(rawURL)
		if url == "" {
			continue
		}
		result, err := fetchXDBURL(ctx, client, url)
		if err != nil {
			errorsSeen = append(errorsSeen, fmt.Sprintf("%s: %v", url, err))
			continue
		}
		if got := binary.LittleEndian.Uint16(result.Header[xdbIPVersionOff:]); got != ipVersion {
			_ = os.Remove(result.Path)
			errorsSeen = append(errorsSeen, fmt.Sprintf("%s: ip_version=%d", url, got))
			continue
		}
		return result, nil
	}
	return nil, fmt.Errorf("下载最新 IPv%d xdb 失败: %s", ipVersion, strings.Join(errorsSeen, "; "))
}

func fetchXDBURL(ctx context.Context, client *http.Client, url string) (*downloadedXDB, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "pfwd-geo-*.xdb")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, hasher), resp.Body)
	if err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	header := make([]byte, xdbHeaderSize)
	if _, err := io.ReadFull(tmp, header); err != nil {
		return nil, err
	}
	if got := binary.LittleEndian.Uint16(header[xdbRuntimePtrOff:]); got != 4 {
		return nil, fmt.Errorf("runtime ptr bytes=%d", got)
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	return &downloadedXDB{
		Path:        tmp.Name(),
		Header:      header,
		SHA256:      hex.EncodeToString(hasher.Sum(nil)),
		SelectedURL: url,
		Bytes:       size,
	}, nil
}

func mergeProvinceNames(sets ...map[string]struct{}) []string {
	merged := map[string]struct{}{}
	for _, set := range sets {
		for name := range set {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			merged[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(merged))
	for name := range merged {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func collectGeoSegmentsV4(path string) ([]xdbScanSegmentV4, error) {
	segments := make([]xdbScanSegmentV4, 0, 65536)
	if err := scanCNXDBv4(path, func(segment xdbScanSegmentV4) error {
		segments = append(segments, segment)
		return nil
	}); err != nil {
		return nil, err
	}
	return segments, nil
}

func collectGeoSegmentsV6(path string) ([]xdbScanSegmentV6, error) {
	segments := make([]xdbScanSegmentV6, 0, 8192)
	if err := scanCNXDBv6(path, func(segment xdbScanSegmentV6) error {
		segments = append(segments, segment)
		return nil
	}); err != nil {
		return nil, err
	}
	return segments, nil
}

func provinceSetFromSegmentsV4(segments []xdbScanSegmentV4) map[string]struct{} {
	set := make(map[string]struct{}, len(segments))
	for _, segment := range segments {
		set[segment.Province] = struct{}{}
	}
	return set
}

func provinceSetFromSegmentsV6(segments []xdbScanSegmentV6) map[string]struct{} {
	set := make(map[string]struct{}, len(segments))
	for _, segment := range segments {
		set[segment.Province] = struct{}{}
	}
	return set
}

func planGeoAssetV4(path string) (*geoAssetPlan, geoAssetStats, error) {
	segments, err := collectGeoSegmentsV4(path)
	if err != nil {
		return nil, geoAssetStats{}, err
	}
	plan, stats := planGeoAssetV4Segments(segments)
	if plan == nil {
		return nil, geoAssetStats{}, fmt.Errorf("构建 geo v4 计划失败")
	}
	return plan, stats, nil
}

func planGeoAssetV6(path string) (*geoAssetPlan, geoAssetStats, error) {
	segments, err := collectGeoSegmentsV6(path)
	if err != nil {
		return nil, geoAssetStats{}, err
	}
	plan, stats := planGeoAssetV6Segments(segments)
	if plan == nil {
		return nil, geoAssetStats{}, fmt.Errorf("构建 geo v6 计划失败")
	}
	return plan, stats, nil
}

func planGeoAssetV4Segments(segments []xdbScanSegmentV4) (*geoAssetPlan, geoAssetStats) {
	merged := mergeGeoSegmentsV4(segments)
	prefixCount := 0
	for _, segment := range merged {
		prefixCount += len(cidrPrefixesFromRangeV4(segment.Start, segment.End, nil))
	}
	return &geoAssetPlan{PrefixCount: uint32(prefixCount)}, geoAssetStats{
		SegmentCount:       prefixCount,
		RawSegmentCount:    len(segments),
		MergedSegmentCount: len(merged),
		PrefixCount:        prefixCount,
		MaxLookupSteps:     1,
	}
}

func planGeoAssetV6Segments(segments []xdbScanSegmentV6) (*geoAssetPlan, geoAssetStats) {
	merged := mergeGeoSegmentsV6(segments)
	prefixCount := 0
	for _, segment := range merged {
		prefixCount += len(cidrPrefixesFromRangeV6(segment.Start, segment.End, nil))
	}
	return &geoAssetPlan{PrefixCount: uint32(prefixCount)}, geoAssetStats{
		SegmentCount:       prefixCount,
		RawSegmentCount:    len(segments),
		MergedSegmentCount: len(merged),
		PrefixCount:        prefixCount,
		MaxLookupSteps:     1,
	}
}

func writeGeoAssetV4FromSegments(path string, plan *geoAssetPlan, segments []xdbScanSegmentV4, provinceIDs map[string]uint16, provinceCount int) error {
	if plan == nil {
		return fmt.Errorf("缺少 geo v4 计划")
	}
	encoded := make([]geoPrefixV4, 0, plan.PrefixCount)
	for _, segment := range mergeGeoSegmentsV4(segments) {
		provinceID, ok := provinceIDs[segment.Province]
		if !ok {
			return fmt.Errorf("未找到省份编号: %s", segment.Province)
		}
		for _, prefix := range cidrPrefixesFromRangeV4(segment.Start, segment.End, nil) {
			prefix.ProvinceID = provinceID
			encoded = append(encoded, prefix)
		}
	}
	return writeGeoAssetV4(path, encoded, provinceCount)
}

func writeCityIPv4AssetFromSegments(path string, segments []xdbScanSegmentV4, catalog cityMetaCatalog) error {
	ranges, err := cityRangesV4FromSegments(segments, catalog)
	if err != nil {
		return err
	}
	merged := mergeCityRangesV4(ranges)
	prefixesByCode := map[uint32][]cityPrefixV4{}
	for _, item := range merged {
		for _, prefix := range cidrPrefixesFromRangeV4(item.Start, item.End, nil) {
			prefixesByCode[item.Code] = append(prefixesByCode[item.Code], cityPrefixV4{
				PrefixLen: prefix.PrefixLen,
				Addr:      prefix.Addr,
			})
		}
	}
	codes := make([]uint32, 0, len(prefixesByCode))
	for code := range prefixesByCode {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	indexes := make([]cityIndexRecord, 0, len(codes))
	prefixes := make([]cityPrefixV4, 0, len(merged))
	for _, code := range codes {
		items := prefixesByCode[code]
		if len(items) == 0 {
			continue
		}
		indexes = append(indexes, cityIndexRecord{
			Code:   code,
			Offset: uint32(len(prefixes)),
			Count:  uint32(len(items)),
		})
		prefixes = append(prefixes, items...)
	}
	return writeCityIPv4Asset(path, indexes, prefixes)
}

func writeGeoAssetV6FromSegments(path string, plan *geoAssetPlan, segments []xdbScanSegmentV6, provinceIDs map[string]uint16, provinceCount int) error {
	if plan == nil {
		return fmt.Errorf("缺少 geo v6 计划")
	}
	encoded := make([]geoPrefixV6, 0, plan.PrefixCount)
	for _, segment := range mergeGeoSegmentsV6(segments) {
		provinceID, ok := provinceIDs[segment.Province]
		if !ok {
			return fmt.Errorf("未找到省份编号: %s", segment.Province)
		}
		for _, prefix := range cidrPrefixesFromRangeV6(segment.Start, segment.End, nil) {
			prefix.ProvinceID = provinceID
			encoded = append(encoded, prefix)
		}
	}
	return writeGeoAssetV6(path, encoded, provinceCount)
}

type cityMetaCatalog struct {
	ByName              map[string]cityMetaEntry
	ByCode              map[uint32]cityMetaEntry
	ProvincesWithCities map[string]struct{}
	DirectByProvince    map[string]cityMetaEntry
}

func loadCityMetaIndex(path string) (cityMetaCatalog, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return cityMetaCatalog{}, fmt.Errorf("读取 city 元数据失败: %w", err)
	}
	var meta cityAssetMeta
	if err := json.Unmarshal(content, &meta); err != nil {
		return cityMetaCatalog{}, fmt.Errorf("解析 city 元数据失败: %w", err)
	}
	catalog := cityMetaCatalog{
		ByName:              map[string]cityMetaEntry{},
		ByCode:              map[uint32]cityMetaEntry{},
		ProvincesWithCities: map[string]struct{}{},
		DirectByProvince:    map[string]cityMetaEntry{},
	}
	for _, province := range meta.Provinces {
		if len(province.Cities) == 0 {
			continue
		}
		provinceName := strings.TrimSpace(province.Name)
		catalog.ProvincesWithCities[cityMetaProvinceKey(provinceName)] = struct{}{}
		for _, city := range province.Cities {
			code, err := parseCityCode(city.Code)
			if err != nil {
				return cityMetaCatalog{}, err
			}
			entry := cityMetaEntry{
				Code:     code,
				CodeText: strings.TrimSpace(city.Code),
				Province: provinceName,
				City:     strings.TrimSpace(city.Name),
			}
			catalog.ByCode[code] = entry
			catalog.ByName[cityMetaKey(provinceName, city.Name)] = entry
			catalog.ByName[cityMetaNormalizedKey(provinceName, city.Name)] = entry
			if strings.Contains(entry.City, "省直辖") {
				catalog.DirectByProvince[cityMetaProvinceKey(provinceName)] = entry
			}
		}
	}
	return catalog, nil
}

func parseCityCode(raw string) (uint32, error) {
	raw = strings.TrimSpace(raw)
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("解析城市 code 失败 (%s): %w", raw, err)
	}
	return uint32(value), nil
}

func cityRangesV4FromSegments(segments []xdbScanSegmentV4, catalog cityMetaCatalog) ([]cityRangeV4, error) {
	ranges := make([]cityRangeV4, 0, len(segments))
	unmatched := map[string]struct{}{}
	for _, segment := range segments {
		if invalidRegionPart(segment.City) {
			continue
		}
		entry, ok, err := findCityMetaEntry(catalog, segment.Province, segment.City)
		if err != nil {
			return nil, err
		}
		if !ok {
			if _, hasCities := catalog.ProvincesWithCities[cityMetaProvinceKey(segment.Province)]; !hasCities {
				continue
			}
			unmatched[strings.TrimSpace(segment.Province)+"/"+strings.TrimSpace(segment.City)] = struct{}{}
			continue
		}
		start := xdbIPv4SegmentValue(segment.Start)
		end := xdbIPv4SegmentValue(segment.End)
		if start > end {
			continue
		}
		ranges = append(ranges, cityRangeV4{Code: entry.Code, Start: start, End: end})
	}
	if len(unmatched) > 0 {
		items := make([]string, 0, len(unmatched))
		for item := range unmatched {
			items = append(items, item)
		}
		slices.Sort(items)
		if len(items) > 12 {
			items = items[:12]
		}
		return nil, fmt.Errorf("xdb 城市未匹配 city meta：%s", strings.Join(items, ", "))
	}
	return ranges, nil
}

func findCityMetaEntry(catalog cityMetaCatalog, province, city string) (cityMetaEntry, bool, error) {
	if entry, ok := catalog.ByName[cityMetaKey(province, city)]; ok {
		return entry, true, nil
	}
	if entry, ok := catalog.ByName[cityMetaNormalizedKey(province, city)]; ok {
		return entry, true, nil
	}
	provinceKey := cityMetaProvinceKey(province)
	cityKey := normalizeCityMetaName(city)
	var matched cityMetaEntry
	matchedCount := 0
	for _, entry := range catalog.ByCode {
		if cityMetaProvinceKey(entry.Province) != provinceKey {
			continue
		}
		metaCityKey := normalizeCityMetaName(entry.City)
		if metaCityKey == cityKey || strings.HasPrefix(metaCityKey, cityKey) || strings.HasPrefix(cityKey, metaCityKey) {
			matched = entry
			matchedCount++
		}
	}
	if matchedCount > 1 {
		return cityMetaEntry{}, false, fmt.Errorf("xdb 城市匹配 city meta 存在多候选：%s/%s", strings.TrimSpace(province), strings.TrimSpace(city))
	}
	if matchedCount == 1 {
		return matched, true, nil
	}
	if entry, ok := catalog.DirectByProvince[provinceKey]; ok {
		return entry, true, nil
	}
	return cityMetaEntry{}, false, nil
}

func mergeCityRangesV4(ranges []cityRangeV4) []cityRangeV4 {
	slices.SortFunc(ranges, func(left, right cityRangeV4) int {
		if left.Code < right.Code {
			return -1
		}
		if left.Code > right.Code {
			return 1
		}
		if left.Start < right.Start {
			return -1
		}
		if left.Start > right.Start {
			return 1
		}
		if left.End < right.End {
			return -1
		}
		if left.End > right.End {
			return 1
		}
		return 0
	})
	merged := make([]cityRangeV4, 0, len(ranges))
	for _, current := range ranges {
		if current.Start > current.End {
			continue
		}
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		last := &merged[len(merged)-1]
		adjacent := last.End != ^uint32(0) && current.Start == last.End+1
		if last.Code == current.Code && (current.Start <= last.End || adjacent) {
			if current.End > last.End {
				last.End = current.End
			}
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func cityMetaKey(province, city string) string {
	return strings.TrimSpace(province) + "\t" + strings.TrimSpace(city)
}

func cityMetaNormalizedKey(province, city string) string {
	return cityMetaProvinceKey(province) + "\t" + normalizeCityMetaName(city)
}

func cityMetaProvinceKey(province string) string {
	return normalizeCityMetaName(province)
}

func normalizeCityMetaName(value string) string {
	value = strings.TrimSpace(value)
	for _, suffix := range []string{
		"特别行政区", "维吾尔自治区", "壮族自治区", "回族自治区", "土家族苗族自治州",
		"藏族羌族自治州", "哈尼族彝族自治州", "傣族自治州", "布依族苗族自治州",
		"苗族侗族自治州", "自治州", "自治区", "地区", "盟", "省", "市",
	} {
		value = strings.TrimSuffix(value, suffix)
	}
	return value
}

func mergeGeoSegmentsV4(segments []xdbScanSegmentV4) []geoRangeV4 {
	ranges := make([]geoRangeV4, 0, len(segments))
	for _, segment := range segments {
		ranges = append(ranges, geoRangeV4{
			Province: segment.Province,
			Start:    xdbIPv4SegmentValue(segment.Start),
			End:      xdbIPv4SegmentValue(segment.End),
		})
	}
	slices.SortFunc(ranges, func(left, right geoRangeV4) int {
		if left.Start < right.Start {
			return -1
		}
		if left.Start > right.Start {
			return 1
		}
		if left.End < right.End {
			return -1
		}
		if left.End > right.End {
			return 1
		}
		return strings.Compare(left.Province, right.Province)
	})
	merged := make([]geoRangeV4, 0, len(ranges))
	for _, current := range ranges {
		if current.Start > current.End {
			continue
		}
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		last := &merged[len(merged)-1]
		adjacent := last.End != ^uint32(0) && current.Start == last.End+1
		if last.Province == current.Province && (current.Start <= last.End || adjacent) {
			if current.End > last.End {
				last.End = current.End
			}
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func mergeGeoSegmentsV6(segments []xdbScanSegmentV6) []geoRangeV6 {
	ranges := make([]geoRangeV6, 0, len(segments))
	for _, segment := range segments {
		ranges = append(ranges, geoRangeV6{
			Province: segment.Province,
			Start:    segment.Start,
			End:      segment.End,
		})
	}
	slices.SortFunc(ranges, func(left, right geoRangeV6) int {
		if cmp := bytes.Compare(left.Start[:], right.Start[:]); cmp != 0 {
			return cmp
		}
		if cmp := bytes.Compare(left.End[:], right.End[:]); cmp != 0 {
			return cmp
		}
		return strings.Compare(left.Province, right.Province)
	})
	merged := make([]geoRangeV6, 0, len(ranges))
	for _, current := range ranges {
		if bytes.Compare(current.Start[:], current.End[:]) > 0 {
			continue
		}
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		last := &merged[len(merged)-1]
		nextAfterLast, ok := ipv6RangeNext(last.End)
		if last.Province == current.Province && (!ok || bytes.Compare(current.Start[:], nextAfterLast[:]) <= 0) {
			if bytes.Compare(current.End[:], last.End[:]) > 0 {
				last.End = current.End
			}
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func cidrPrefixesFromRangeV4(start, end uint32, out []geoPrefixV4) []geoPrefixV4 {
	for start <= end {
		alignmentBits := bits.TrailingZeros32(start)
		if start == 0 {
			alignmentBits = 32
		}
		remaining := uint64(end) - uint64(start) + 1
		remainingBits := bits.Len64(remaining) - 1
		blockBits := alignmentBits
		if remainingBits < blockBits {
			blockBits = remainingBits
		}
		out = append(out, geoPrefixV4{PrefixLen: uint32(32 - blockBits), Addr: start})
		if blockBits == 32 {
			break
		}
		start += uint32(uint64(1) << blockBits)
	}
	return out
}

func cidrPrefixesFromRangeV6(start, end [16]byte, out []geoPrefixV6) []geoPrefixV6 {
	current := ipv6BytesToBig(start)
	limit := ipv6BytesToBig(end)
	one := big.NewInt(1)
	for current.Cmp(limit) <= 0 {
		alignmentBits := ipv6TrailingZeros(current)
		remaining := new(big.Int).Sub(limit, current)
		remaining.Add(remaining, one)
		remainingBits := remaining.BitLen() - 1
		blockBits := alignmentBits
		if remainingBits < blockBits {
			blockBits = remainingBits
		}
		out = append(out, geoPrefixV6{PrefixLen: uint32(128 - blockBits), Addr: bigToIPv6Bytes(current)})
		if blockBits == 128 {
			break
		}
		current.Add(current, new(big.Int).Lsh(one, uint(blockBits)))
	}
	return out
}

func ipv6TrailingZeros(value *big.Int) int {
	if value.Sign() == 0 {
		return 128
	}
	for i := 0; i < 128; i++ {
		if value.Bit(i) != 0 {
			return i
		}
	}
	return 128
}

func ipv6BytesToBig(value [16]byte) *big.Int {
	return new(big.Int).SetBytes(value[:])
}

func bigToIPv6Bytes(value *big.Int) [16]byte {
	var out [16]byte
	raw := value.Bytes()
	copy(out[len(out)-len(raw):], raw)
	return out
}

func ipv6RangeNext(value [16]byte) ([16]byte, bool) {
	out := value
	for i := len(out) - 1; i >= 0; i-- {
		if out[i] != 0xff {
			out[i]++
			for j := i + 1; j < len(out); j++ {
				out[j] = 0
			}
			return out, true
		}
	}
	return out, false
}

func ipv6BucketStart(bucket int) [16]byte {
	var out [16]byte
	out[0] = byte(bucket >> 8)
	out[1] = byte(bucket)
	return out
}

func ipv6BucketEnd(bucket int) [16]byte {
	out := ipv6BucketStart(bucket)
	for i := 2; i < len(out); i++ {
		out[i] = 0xFF
	}
	return out
}

func scanCNXDBv4(path string, handler xdbScanHandlerV4) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("打开 IPv4 xdb 失败: %w", err)
	}
	defer file.Close()
	header, err := readXDBHeader(file)
	if err != nil {
		return err
	}
	if got := binary.LittleEndian.Uint16(header[xdbIPVersionOff:]); got != 4 {
		return fmt.Errorf("IPv4 xdb ip_version=%d", got)
	}
	indexStart := binary.LittleEndian.Uint32(header[xdbIndexStartOff:])
	indexEnd := binary.LittleEndian.Uint32(header[xdbIndexEndOff:])
	total := xdbIndexCount(indexStart, indexEnd, xdbIPv4SegmentSize)
	if _, err := file.Seek(int64(indexStart), io.SeekStart); err != nil {
		return fmt.Errorf("定位 IPv4 xdb index 失败: %w", err)
	}
	buf := make([]byte, xdbIPv4SegmentSize)
	for i := 0; i < total; i++ {
		if _, err := io.ReadFull(file, buf); err != nil {
			return fmt.Errorf("读取 IPv4 xdb index 失败: %w", err)
		}
		province, city, ok, err := xdbLocationByIndex(file, buf, 4)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		var start [4]byte
		var end [4]byte
		copy(start[:], buf[:4])
		copy(end[:], buf[4:8])
		if err := handler(xdbScanSegmentV4{Province: province, City: city, Start: start, End: end}); err != nil {
			return err
		}
	}
	return nil
}

func scanCNXDBv6(path string, handler xdbScanHandlerV6) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("打开 IPv6 xdb 失败: %w", err)
	}
	defer file.Close()
	header, err := readXDBHeader(file)
	if err != nil {
		return err
	}
	if got := binary.LittleEndian.Uint16(header[xdbIPVersionOff:]); got != 6 {
		return fmt.Errorf("IPv6 xdb ip_version=%d", got)
	}
	indexStart := binary.LittleEndian.Uint32(header[xdbIndexStartOff:])
	indexEnd := binary.LittleEndian.Uint32(header[xdbIndexEndOff:])
	total := xdbIndexCount(indexStart, indexEnd, xdbIPv6SegmentSize)
	if _, err := file.Seek(int64(indexStart), io.SeekStart); err != nil {
		return fmt.Errorf("定位 IPv6 xdb index 失败: %w", err)
	}
	buf := make([]byte, xdbIPv6SegmentSize)
	for i := 0; i < total; i++ {
		if _, err := io.ReadFull(file, buf); err != nil {
			return fmt.Errorf("读取 IPv6 xdb index 失败: %w", err)
		}
		province, _, ok, err := xdbLocationByIndex(file, buf, 6)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		var start [16]byte
		var end [16]byte
		copy(start[:], buf[:16])
		copy(end[:], buf[16:32])
		if err := handler(xdbScanSegmentV6{Province: province, Start: start, End: end}); err != nil {
			return err
		}
	}
	return nil
}

func readXDBHeader(file *os.File) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("定位 xdb header 失败: %w", err)
	}
	header := make([]byte, xdbHeaderSize)
	if _, err := io.ReadFull(file, header); err != nil {
		return nil, fmt.Errorf("读取 xdb header 失败: %w", err)
	}
	return header, nil
}

func xdbIndexCount(indexStart, indexEnd uint32, segmentSize int) int {
	if indexEnd < indexStart {
		return 0
	}
	return int((indexEnd-indexStart)/uint32(segmentSize)) + 1
}

func xdbLocationByIndex(file *os.File, segment []byte, ipVersion uint16) (string, string, bool, error) {
	var offset int
	if ipVersion == 4 {
		offset = 8
	} else {
		offset = 32
	}
	dataLen := binary.LittleEndian.Uint16(segment[offset:])
	dataPtr := binary.LittleEndian.Uint32(segment[offset+2:])
	region, err := readXDBRegion(file, dataPtr, dataLen)
	if err != nil {
		return "", "", false, err
	}
	if !strings.HasPrefix(region, "中国|") {
		return "", "", false, nil
	}
	parts := strings.Split(region, "|")
	if len(parts) < 2 {
		return "", "", false, nil
	}
	province := strings.TrimSpace(parts[1])
	if invalidRegionPart(province) {
		return "", "", false, nil
	}
	city := ""
	if len(parts) >= 3 {
		city = strings.TrimSpace(parts[2])
		if invalidRegionPart(city) {
			city = ""
		}
	}
	return province, city, true, nil
}

func invalidRegionPart(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || value == "0" || value == "Reserved"
}

func readXDBRegion(file *os.File, ptr uint32, length uint16) (string, error) {
	current, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", fmt.Errorf("读取 xdb 当前偏移失败: %w", err)
	}
	defer func() {
		_, _ = file.Seek(current, io.SeekStart)
	}()
	if _, err := file.Seek(int64(ptr), io.SeekStart); err != nil {
		return "", fmt.Errorf("定位 xdb region 失败: %w", err)
	}
	buf := make([]byte, int(length))
	if _, err := io.ReadFull(file, buf); err != nil {
		return "", fmt.Errorf("读取 xdb region 失败: %w", err)
	}
	return string(buf), nil
}

func forEachIPv4BucketPart(start, end [4]byte, yield func(partStart, partEnd [4]byte)) {
	for b1 := int(start[0]); b1 <= int(end[0]); b1++ {
		start2 := 0
		if b1 == int(start[0]) {
			start2 = int(start[1])
		}
		end2 := 255
		if b1 == int(end[0]) {
			end2 = int(end[1])
		}
		for b2 := start2; b2 <= end2; b2++ {
			partStart := [4]byte{byte(b1), byte(b2), 0x00, 0x00}
			partEnd := [4]byte{byte(b1), byte(b2), 0xFF, 0xFF}
			if b1 == int(start[0]) && b2 == int(start[1]) {
				partStart = start
			}
			if b1 == int(end[0]) && b2 == int(end[1]) {
				partEnd = end
			}
			yield(partStart, partEnd)
		}
	}
}

func forEachIPv6BucketPart(start, end [16]byte, yield func(partStart, partEnd [16]byte)) {
	for b1 := int(start[0]); b1 <= int(end[0]); b1++ {
		start2 := 0
		if b1 == int(start[0]) {
			start2 = int(start[1])
		}
		end2 := 255
		if b1 == int(end[0]) {
			end2 = int(end[1])
		}
		for b2 := start2; b2 <= end2; b2++ {
			partStart := [16]byte{byte(b1), byte(b2)}
			partEnd := [16]byte{byte(b1), byte(b2)}
			for i := 2; i < len(partEnd); i++ {
				partEnd[i] = 0xFF
			}
			if b1 == int(start[0]) && b2 == int(start[1]) {
				partStart = start
			}
			if b1 == int(end[0]) && b2 == int(end[1]) {
				partEnd = end
			}
			yield(partStart, partEnd)
		}
	}
}

func ipv4BytesToBE(value [4]byte) uint32 {
	return binary.BigEndian.Uint32(value[:])
}

func xdbIPv4SegmentValue(raw [4]byte) uint32 {
	return binary.LittleEndian.Uint32(raw[:])
}

func binarySearchSteps(count uint32) int {
	if count == 0 {
		return 0
	}
	return bits.Len32(count)
}

func validateGeoAssetStats(label string, stats geoAssetStats, segmentLimit int) error {
	if stats.PrefixCount > segmentLimit {
		return fmt.Errorf("geo %s prefix_count=%d 超过当前 BPF LPM map 上限 %d", label, stats.PrefixCount, segmentLimit)
	}
	return nil
}

func writeGeoAssetV4(path string, prefixes []geoPrefixV4, provinceCount int) error {
	header := geoHeader{}
	copy(header.Magic[:], []byte(geoAssetMagic))
	header.Version = geoAssetVersion
	header.IPVersion = 4
	header.BucketCount = 0
	header.SegmentCount = uint32(len(prefixes))
	header.ProvinceCount = uint32(provinceCount)
	return writeGeoAsset(path, header, prefixes, "v4")
}

func writeGeoAssetV6(path string, prefixes []geoPrefixV6, provinceCount int) error {
	header := geoHeader{}
	copy(header.Magic[:], []byte(geoAssetMagic))
	header.Version = geoAssetVersion
	header.IPVersion = 6
	header.BucketCount = 0
	header.SegmentCount = uint32(len(prefixes))
	header.ProvinceCount = uint32(provinceCount)
	return writeGeoAsset(path, header, prefixes, "v6")
}

func writeGeoAsset[T any](path string, header geoHeader, prefixes []T, label string) (err error) {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("创建 geo %s 资产失败: %w", label, err)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	if err := binary.Write(file, binary.LittleEndian, header); err != nil {
		return fmt.Errorf("编码 geo %s header 失败: %w", label, err)
	}
	for _, prefix := range prefixes {
		if err := binary.Write(file, binary.LittleEndian, prefix); err != nil {
			return fmt.Errorf("编码 geo %s prefix 失败: %w", label, err)
		}
	}
	if err := file.Chmod(0o644); err != nil {
		return fmt.Errorf("设置 geo %s 资产权限失败: %w", label, err)
	}
	return nil
}

func writeCityIPv4Asset(path string, indexes []cityIndexRecord, prefixes []cityPrefixV4) (err error) {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("创建 city v4 资产失败: %w", err)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	header := cityHeader{}
	copy(header.Magic[:], []byte(cityAssetMagic))
	header.Version = cityAssetVersion
	header.IPVersion = 4
	header.IndexCount = uint32(len(indexes))
	header.PrefixCount = uint32(len(prefixes))
	if err := binary.Write(file, binary.LittleEndian, header); err != nil {
		return fmt.Errorf("写入 city v4 header 失败: %w", err)
	}
	for _, item := range indexes {
		if err := binary.Write(file, binary.LittleEndian, item); err != nil {
			return fmt.Errorf("写入 city v4 index 失败: %w", err)
		}
	}
	for _, prefix := range prefixes {
		if err := binary.Write(file, binary.LittleEndian, prefix); err != nil {
			return fmt.Errorf("写入 city v4 prefix 失败: %w", err)
		}
	}
	return nil
}

func readGeoAssetV4(path string) ([]geoPrefixV4, uint16, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("读取 geo v4 资产失败: %w", err)
	}
	if len(content) < geoHeaderSize {
		return nil, 0, fmt.Errorf("geo v4 资产过短")
	}
	var header geoHeader
	if err := binary.Read(bytes.NewReader(content[:geoHeaderSize]), binary.LittleEndian, &header); err != nil {
		return nil, 0, fmt.Errorf("解析 geo v4 header 失败: %w", err)
	}
	if string(header.Magic[:]) != geoAssetMagic {
		return nil, 0, fmt.Errorf("geo v4 magic 不匹配")
	}
	if header.Version != geoAssetVersion {
		return nil, 0, fmt.Errorf("geo v4 资产版本=%d，不支持", header.Version)
	}
	if header.BucketCount != 0 {
		return nil, 0, fmt.Errorf("geo v4 资产 bucket_count=%d，不支持 v2 prefix 格式", header.BucketCount)
	}
	offset := geoHeaderSize
	prefixes := make([]geoPrefixV4, int(header.SegmentCount))
	if len(content) < offset+len(prefixes)*12 {
		return nil, 0, fmt.Errorf("geo v4 prefix 数据截断")
	}
	for i := range prefixes {
		prefixes[i].PrefixLen = binary.LittleEndian.Uint32(content[offset:])
		prefixes[i].Addr = binary.LittleEndian.Uint32(content[offset+4:])
		prefixes[i].ProvinceID = binary.LittleEndian.Uint16(content[offset+8:])
		prefixes[i].Pad = binary.LittleEndian.Uint16(content[offset+10:])
		offset += 12
	}
	return prefixes, header.IPVersion, nil
}

func readCityIPv4Asset(path string) ([]cityIndexRecord, []cityPrefixV4, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("读取 city v4 资产失败: %w", err)
	}
	if len(content) < cityHeaderSize {
		return nil, nil, fmt.Errorf("city v4 资产过短")
	}
	var header cityHeader
	if err := binary.Read(bytes.NewReader(content[:cityHeaderSize]), binary.LittleEndian, &header); err != nil {
		return nil, nil, fmt.Errorf("解析 city v4 header 失败: %w", err)
	}
	if string(header.Magic[:]) != cityAssetMagic {
		return nil, nil, fmt.Errorf("city v4 magic 不匹配")
	}
	if header.Version != cityAssetVersion {
		return nil, nil, fmt.Errorf("city v4 资产版本=%d，不支持", header.Version)
	}
	if header.IPVersion != 4 {
		return nil, nil, fmt.Errorf("city v4 资产 ip_version=%d，不支持", header.IPVersion)
	}
	indexBytes := int(header.IndexCount) * cityIndexSize
	prefixBytes := int(header.PrefixCount) * cityPrefixSize
	if len(content) < cityHeaderSize+indexBytes+prefixBytes {
		return nil, nil, fmt.Errorf("city v4 资产数据截断")
	}
	indexes := make([]cityIndexRecord, int(header.IndexCount))
	offset := cityHeaderSize
	for i := range indexes {
		indexes[i].Code = binary.LittleEndian.Uint32(content[offset:])
		indexes[i].Offset = binary.LittleEndian.Uint32(content[offset+4:])
		indexes[i].Count = binary.LittleEndian.Uint32(content[offset+8:])
		if indexes[i].Offset+indexes[i].Count > header.PrefixCount {
			return nil, nil, fmt.Errorf("city v4 index 越界 (code=%d)", indexes[i].Code)
		}
		offset += cityIndexSize
	}
	prefixes := make([]cityPrefixV4, int(header.PrefixCount))
	for i := range prefixes {
		prefixes[i].PrefixLen = binary.LittleEndian.Uint32(content[offset:])
		prefixes[i].Addr = binary.LittleEndian.Uint32(content[offset+4:])
		offset += cityPrefixSize
	}
	return indexes, prefixes, nil
}

func readGeoAssetV6(path string) ([]geoPrefixV6, uint16, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("读取 geo v6 资产失败: %w", err)
	}
	if len(content) < geoHeaderSize {
		return nil, 0, fmt.Errorf("geo v6 资产过短")
	}
	var header geoHeader
	if err := binary.Read(bytes.NewReader(content[:geoHeaderSize]), binary.LittleEndian, &header); err != nil {
		return nil, 0, fmt.Errorf("解析 geo v6 header 失败: %w", err)
	}
	if string(header.Magic[:]) != geoAssetMagic {
		return nil, 0, fmt.Errorf("geo v6 magic 不匹配")
	}
	if header.Version != geoAssetVersion {
		return nil, 0, fmt.Errorf("geo v6 资产版本=%d，不支持", header.Version)
	}
	if header.BucketCount != 0 {
		return nil, 0, fmt.Errorf("geo v6 资产 bucket_count=%d，不支持 v2 prefix 格式", header.BucketCount)
	}
	offset := geoHeaderSize
	prefixes := make([]geoPrefixV6, int(header.SegmentCount))
	if len(content) < offset+len(prefixes)*24 {
		return nil, 0, fmt.Errorf("geo v6 prefix 数据截断")
	}
	for i := range prefixes {
		prefixes[i].PrefixLen = binary.LittleEndian.Uint32(content[offset:])
		copy(prefixes[i].Addr[:], content[offset+4:offset+20])
		prefixes[i].ProvinceID = binary.LittleEndian.Uint16(content[offset+20:])
		prefixes[i].Pad = binary.LittleEndian.Uint16(content[offset+22:])
		offset += 24
	}
	return prefixes, header.IPVersion, nil
}

func geoAssetHashes(assetDir string) ([]whitelistContentHash, error) {
	assetDir = strings.TrimSpace(assetDir)
	if assetDir == "" {
		return nil, nil
	}
	files := []string{
		filepath.Join(assetDir, geoIPv4AssetFile),
		filepath.Join(assetDir, geoIPv6AssetFile),
		filepath.Join(assetDir, geoMetaAssetFile),
		filepath.Join(assetDir, cityIPv4AssetFile),
		filepath.Join(assetDir, cityMetaAssetFile),
	}
	return whitelistFileHashes(files)
}

func geoModeEnabled(mode string) bool {
	switch strings.TrimSpace(mode) {
	case "all", "provinces":
		return true
	default:
		return false
	}
}

type geoCheckResult struct {
	Address       string `json:"address"`
	Mode          string `json:"mode"`
	Province      string `json:"province,omitempty"`
	ProvinceID    uint16 `json:"province_id,omitempty"`
	CityProvince  string `json:"city_province,omitempty"`
	City          string `json:"city,omitempty"`
	CityCode      string `json:"city_code,omitempty"`
	CityAllowed   bool   `json:"city_allowed"`
	CustomAllowed bool   `json:"custom_allowed"`
	GeoAllowed    bool   `json:"geo_allowed"`
	Allowed       bool   `json:"allowed"`
	MatchedSource string `json:"matched_source"`
}

func geoCheck(opts geoCheckOptions) error {
	assets, err := loadGeoAssets(opts.AssetDir)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(opts.Address)
	if err != nil {
		return fmt.Errorf("解析地址失败: %w", err)
	}
	mode := strings.TrimSpace(opts.Mode)
	if mode == "" {
		mode = "all"
	}
	allowedProvinces := parseProvinceCSV(opts.ProvinceCSV)
	customFiles := splitFiles(opts.WhitelistFile)
	if len(customFiles) == 0 {
		customFiles = splitFiles(opts.EgressWhitelistFile)
	}
	customAllowed, err := cidrFilesContainAddress(customFiles, addr)
	if err != nil {
		return err
	}
	cityMatch, err := cityFileContainsAddress(opts.CityFile, addr)
	if err != nil {
		return err
	}
	result := geoCheckResult{
		Address: addr.String(),
		Mode:    mode,
	}
	provinceID, provinceName, geoHit, err := geoAssetContainsAddress(assets, addr)
	if err != nil {
		return err
	}
	if geoHit {
		result.ProvinceID = provinceID
		result.Province = provinceName
	}
	if cityMatch.Matched {
		result.CityAllowed = true
		result.CityProvince = cityMatch.Province
		result.City = cityMatch.City
		result.CityCode = cityMatch.Code
		result.Allowed = true
		result.MatchedSource = "city"
		if err := writeGeoCheckResult(opts, result); err != nil {
			return err
		}
		return nil
	}
	if customAllowed {
		result.CustomAllowed = true
		result.Allowed = true
		result.MatchedSource = "custom"
		if err := writeGeoCheckResult(opts, result); err != nil {
			return err
		}
		return nil
	}
	if !geoHit {
		result.MatchedSource = "not-cn"
		if err := writeGeoCheckResult(opts, result); err != nil {
			return err
		}
		return fmt.Errorf("未命中中国段")
	}
	switch mode {
	case "all":
		result.GeoAllowed = true
		result.Allowed = true
		result.MatchedSource = "geo"
		if err := writeGeoCheckResult(opts, result); err != nil {
			return err
		}
		return nil
	case "provinces":
		if _, ok := allowedProvinces[provinceName]; ok {
			result.GeoAllowed = true
			result.Allowed = true
			result.MatchedSource = "geo"
			if err := writeGeoCheckResult(opts, result); err != nil {
				return err
			}
			return nil
		}
		result.MatchedSource = "province-deny"
		if err := writeGeoCheckResult(opts, result); err != nil {
			return err
		}
		return fmt.Errorf("省份未授权: %s", provinceName)
	case "off":
		result.MatchedSource = "mode-off"
		if err := writeGeoCheckResult(opts, result); err != nil {
			return err
		}
		return fmt.Errorf("geo 模式已关闭")
	default:
		return fmt.Errorf("无效 geo mode: %s", mode)
	}
}

func cityExport(opts cityExportOptions) error {
	assetDir := strings.TrimSpace(opts.AssetDir)
	if assetDir == "" {
		return fmt.Errorf("city-export 缺少 --asset-dir")
	}
	codes, err := readCityCodesFile(opts.CodesFile)
	if err != nil {
		return err
	}
	if len(codes) == 0 {
		return nil
	}
	catalog, err := loadCityMetaIndex(filepath.Join(assetDir, cityMetaAssetFile))
	if err != nil {
		return err
	}
	indexes, prefixes, err := readCityIPv4Asset(filepath.Join(assetDir, cityIPv4AssetFile))
	if err != nil {
		return err
	}
	for _, code := range codes {
		meta, ok := catalog.ByCode[code]
		if !ok {
			return fmt.Errorf("未知城市 code：%d", code)
		}
		index, ok := findCityIndex(indexes, code)
		if !ok {
			return fmt.Errorf("城市 code 没有可用 IPv4 CIDR：%d", code)
		}
		start := int(index.Offset)
		end := int(index.Offset + index.Count)
		if start < 0 || end > len(prefixes) || start > end {
			return fmt.Errorf("city v4 index 越界 (code=%d)", code)
		}
		for _, prefix := range prefixes[start:end] {
			cidr, err := cityPrefixCIDR(prefix)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(os.Stdout, "%s\t%s\t%s\t%s\n", meta.CodeText, meta.Province, meta.City, cidr)
		}
	}
	return nil
}

func readCityCodesFile(filePath string) ([]uint32, error) {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return nil, fmt.Errorf("city-export 缺少 --codes-file")
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取城市 code 文件失败 (%s): %w", filePath, err)
	}
	seen := map[uint32]struct{}{}
	out := []uint32{}
	for lineNo, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		code, err := parseCityCode(line)
		if err != nil {
			return nil, fmt.Errorf("解析城市 code 文件失败 (%s:%d): %w", filePath, lineNo+1, err)
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	slices.Sort(out)
	return out, nil
}

func findCityIndex(indexes []cityIndexRecord, code uint32) (cityIndexRecord, bool) {
	pos, ok := slices.BinarySearchFunc(indexes, code, func(item cityIndexRecord, target uint32) int {
		if item.Code < target {
			return -1
		}
		if item.Code > target {
			return 1
		}
		return 0
	})
	if !ok {
		return cityIndexRecord{}, false
	}
	return indexes[pos], true
}

func cityPrefixCIDR(prefix cityPrefixV4) (string, error) {
	if prefix.PrefixLen > 32 {
		return "", fmt.Errorf("无效 city v4 prefix_len：%d", prefix.PrefixLen)
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], prefix.Addr)
	addr := netip.AddrFrom4(raw)
	return netip.PrefixFrom(addr, int(prefix.PrefixLen)).Masked().String(), nil
}

func writeGeoCheckResult(opts geoCheckOptions, result geoCheckResult) error {
	if opts.JSON {
		encoded, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("序列化 geo-check 结果失败: %w", err)
		}
		_, _ = fmt.Fprintln(os.Stdout, string(encoded))
		return nil
	}
	switch {
	case result.CityAllowed:
		_, _ = fmt.Fprintf(os.Stdout, "allow city province=%s city=%s code=%s\n", result.CityProvince, result.City, result.CityCode)
	case result.CustomAllowed:
		_, _ = fmt.Fprintln(os.Stdout, "allow custom")
	case result.Allowed && result.MatchedSource == "geo":
		_, _ = fmt.Fprintf(os.Stdout, "allow geo province=%s id=%d\n", result.Province, result.ProvinceID)
	case result.MatchedSource == "not-cn":
		_, _ = fmt.Fprintln(os.Stdout, "deny not-cn")
	case result.MatchedSource == "mode-off":
		_, _ = fmt.Fprintln(os.Stdout, "deny mode-off")
	default:
		_, _ = fmt.Fprintf(os.Stdout, "deny province=%s id=%d\n", result.Province, result.ProvinceID)
	}
	return nil
}

func parseProvinceCSV(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out[part] = struct{}{}
	}
	return out
}

func cidrFilesContainAddress(files []string, addr netip.Addr) (bool, error) {
	for _, filePath := range files {
		filePath = strings.TrimSpace(filePath)
		if filePath == "" {
			continue
		}
		content, err := os.ReadFile(filePath)
		if err != nil {
			return false, fmt.Errorf("读取 CIDR 文件失败 (%s): %w", filePath, err)
		}
		for _, raw := range strings.Split(string(content), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			prefix, err := netip.ParsePrefix(line)
			if err != nil {
				return false, fmt.Errorf("解析 CIDR 失败 (%s): %w", line, err)
			}
			if prefix.Contains(addr) {
				return true, nil
			}
		}
	}
	return false, nil
}

type cityCheckMatch struct {
	Matched  bool
	Code     string
	Province string
	City     string
}

func cityFileContainsAddress(filePath string, addr netip.Addr) (cityCheckMatch, error) {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" || !addr.Is4() {
		return cityCheckMatch{}, nil
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cityCheckMatch{}, nil
		}
		return cityCheckMatch{}, fmt.Errorf("读取市白名单文件失败 (%s): %w", filePath, err)
	}
	for lineNo, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 {
			return cityCheckMatch{}, fmt.Errorf("解析市白名单失败 (%s:%d): 需要 code/province/city/cidr 四列", filePath, lineNo+1)
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(parts[3]))
		if err != nil {
			return cityCheckMatch{}, fmt.Errorf("解析市白名单 CIDR 失败 (%s:%d): %w", filePath, lineNo+1, err)
		}
		if prefix.Masked().Contains(addr) {
			return cityCheckMatch{
				Matched:  true,
				Code:     strings.TrimSpace(parts[0]),
				Province: strings.TrimSpace(parts[1]),
				City:     strings.TrimSpace(parts[2]),
			}, nil
		}
	}
	return cityCheckMatch{}, nil
}

func geoAssetContainsAddress(assets *geoAssetRuntime, addr netip.Addr) (uint16, string, bool, error) {
	if assets == nil {
		return 0, "", false, fmt.Errorf("geo 资产为空")
	}
	if addr.Is4() {
		v4 := addr.As4()
		target := ipv4BytesToBE(v4)
		prefix, ok := findGeoPrefixV4(assets.PrefixesV4, target)
		if !ok {
			return 0, "", false, nil
		}
		return prefix.ProvinceID, assets.provinceName(prefix.ProvinceID), true, nil
	}
	v6 := addr.As16()
	prefix, ok := findGeoPrefixV6(assets.PrefixesV6, v6)
	if !ok {
		return 0, "", false, nil
	}
	return prefix.ProvinceID, assets.provinceName(prefix.ProvinceID), true, nil
}

func (assets *geoAssetRuntime) provinceName(id uint16) string {
	for _, province := range assets.Meta.Provinces {
		if province.ID == id {
			return province.Name
		}
	}
	return ""
}

func findGeoPrefixV4(prefixes []geoPrefixV4, target uint32) (geoPrefixV4, bool) {
	var best geoPrefixV4
	found := false
	for _, prefix := range prefixes {
		if prefix.PrefixLen > 32 {
			continue
		}
		if found && prefix.PrefixLen <= best.PrefixLen {
			continue
		}
		if geoPrefixV4Contains(prefix, target) {
			best = prefix
			found = true
		}
	}
	return best, found
}

func geoPrefixV4Contains(prefix geoPrefixV4, target uint32) bool {
	if prefix.PrefixLen == 0 {
		return true
	}
	mask := ^uint32(0) << (32 - prefix.PrefixLen)
	return target&mask == prefix.Addr&mask
}

func findGeoPrefixV6(prefixes []geoPrefixV6, target [16]byte) (geoPrefixV6, bool) {
	var best geoPrefixV6
	found := false
	for _, prefix := range prefixes {
		if prefix.PrefixLen > 128 {
			continue
		}
		if found && prefix.PrefixLen <= best.PrefixLen {
			continue
		}
		if geoPrefixV6Contains(prefix, target) {
			best = prefix
			found = true
		}
	}
	return best, found
}

func geoPrefixV6Contains(prefix geoPrefixV6, target [16]byte) bool {
	fullBytes := int(prefix.PrefixLen / 8)
	remainingBits := int(prefix.PrefixLen % 8)
	if fullBytes > 0 && !bytes.Equal(prefix.Addr[:fullBytes], target[:fullBytes]) {
		return false
	}
	if remainingBits == 0 {
		return true
	}
	mask := byte(0xff << (8 - remainingBits))
	return prefix.Addr[fullBytes]&mask == target[fullBytes]&mask
}
