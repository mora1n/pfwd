package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	geoAssetMagic    = "PFGE"
	geoAssetVersion  = 1
	geoHeaderSize    = 20
	geoBucketEntries = 1 << 16

	geoIPv4AssetFile = "pfwd-geo-cn-v4.bin"
	geoIPv6AssetFile = "pfwd-geo-cn-v6.bin"
	geoMetaAssetFile = "pfwd-geo-meta.json"

	xdbHeaderSize      = 256
	xdbVersionOffset   = 0
	xdbIndexStartOff   = 8
	xdbIndexEndOff     = 12
	xdbIPVersionOff    = 16
	xdbRuntimePtrOff   = 18
	xdbIPv4SegmentSize = 14
	xdbIPv6SegmentSize = 38

	// Keep these limits in sync with xdp.bpf.c.
	geoLookupLoopLimit        = 16
	geoSegmentV4MapMaxEntries = 131072
	geoSegmentV6MapMaxEntries = 32768
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

type geoSegmentV4 struct {
	Start      uint32
	End        uint32
	ProvinceID uint16
	Pad        uint16
}

type geoSegmentV6 struct {
	Start      [16]byte
	End        [16]byte
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

type geoAssetMeta struct {
	FormatVersion uint16             `json:"format_version"`
	BuiltAt       string             `json:"built_at"`
	IPv4          geoDownloadRecord  `json:"ipv4"`
	IPv6          geoDownloadRecord  `json:"ipv6"`
	Provinces     []geoProvinceEntry `json:"provinces"`
	IPv4Buckets   int                `json:"ipv4_buckets"`
	IPv4Segments  int                `json:"ipv4_segments"`
	IPv6Buckets   int                `json:"ipv6_buckets"`
	IPv6Segments  int                `json:"ipv6_segments"`
}

type geoAssetRuntime struct {
	Meta        geoAssetMeta
	BucketsV4   []geoBucket
	SegmentsV4  []geoSegmentV4
	BucketsV6   []geoBucket
	SegmentsV6  []geoSegmentV6
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
	Start    [4]byte
	End      [4]byte
}

type xdbScanSegmentV6 struct {
	Province string
	Start    [16]byte
	End      [16]byte
}

type geoAssetPlan struct {
	Buckets      []geoBucket
	SegmentCount uint32
}

type geoAssetStats struct {
	BucketCount    int
	SegmentCount   int
	MaxBucketCount uint32
	MaxLookupSteps int
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
		IPv4Buckets:  v4Stats.BucketCount,
		IPv4Segments: v4Stats.SegmentCount,
		IPv6Buckets:  v6Stats.BucketCount,
		IPv6Segments: v6Stats.SegmentCount,
	}
	content, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 geo 元数据失败: %w", err)
	}
	if err := os.WriteFile(filepath.Join(opts.AssetDir, geoMetaAssetFile), append(content, '\n'), 0o644); err != nil {
		return fmt.Errorf("写入 geo 元数据失败: %w", err)
	}
	return nil
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

	buckets4, segments4, ipVer4, err := readGeoAssetV4(filepath.Join(assetDir, geoIPv4AssetFile))
	if err != nil {
		return nil, err
	}
	if ipVer4 != 4 {
		return nil, fmt.Errorf("geo v4 资产 ip_version 错误: %d", ipVer4)
	}
	buckets6, segments6, ipVer6, err := readGeoAssetV6(filepath.Join(assetDir, geoIPv6AssetFile))
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
		BucketsV4:   buckets4,
		SegmentsV4:  segments4,
		BucketsV6:   buckets6,
		SegmentsV6:  segments6,
		ProvinceIDs: provinceIDs,
	}, nil
}

func downloadGeoXDB(ctx context.Context, ipVersion uint16, urls []string) (*downloadedXDB, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("缺少 xdb 下载地址")
	}
	client := &http.Client{Timeout: 30 * time.Second}
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
	slices.SortFunc(segments, func(left, right xdbScanSegmentV4) int {
		leftStart := xdbIPv4SegmentValue(left.Start)
		rightStart := xdbIPv4SegmentValue(right.Start)
		if leftStart < rightStart {
			return -1
		}
		if leftStart > rightStart {
			return 1
		}
		leftEnd := xdbIPv4SegmentValue(left.End)
		rightEnd := xdbIPv4SegmentValue(right.End)
		switch {
		case leftEnd < rightEnd:
			return -1
		case leftEnd > rightEnd:
			return 1
		default:
			return strings.Compare(left.Province, right.Province)
		}
	})

	buckets := make([]geoBucket, geoBucketEntries)
	first := 0
	last := 0
	active := 0
	var maxCount uint32
	for bucket := 0; bucket < geoBucketEntries; bucket++ {
		bucketStart := uint32(bucket) << 16
		bucketEnd := bucketStart | 0xFFFF
		for first < len(segments) && xdbIPv4SegmentValue(segments[first].End) < bucketStart {
			first++
		}
		if last < first {
			last = first
		}
		for last < len(segments) && xdbIPv4SegmentValue(segments[last].Start) <= bucketEnd {
			last++
		}
		if last > first {
			count := uint32(last - first)
			buckets[bucket] = geoBucket{Start: uint32(first), Count: count}
			active++
			if count > maxCount {
				maxCount = count
			}
		}
	}
	return &geoAssetPlan{Buckets: buckets, SegmentCount: uint32(len(segments))}, geoAssetStats{
		BucketCount:    active,
		SegmentCount:   len(segments),
		MaxBucketCount: maxCount,
		MaxLookupSteps: binarySearchSteps(maxCount),
	}
}

func planGeoAssetV6Segments(segments []xdbScanSegmentV6) (*geoAssetPlan, geoAssetStats) {
	slices.SortFunc(segments, func(left, right xdbScanSegmentV6) int {
		if cmp := bytes.Compare(left.Start[:], right.Start[:]); cmp != 0 {
			return cmp
		}
		if cmp := bytes.Compare(left.End[:], right.End[:]); cmp != 0 {
			return cmp
		}
		return strings.Compare(left.Province, right.Province)
	})

	buckets := make([]geoBucket, geoBucketEntries)
	first := 0
	last := 0
	active := 0
	var maxCount uint32
	for bucket := 0; bucket < geoBucketEntries; bucket++ {
		bucketStart := ipv6BucketStart(bucket)
		bucketEnd := ipv6BucketEnd(bucket)
		for first < len(segments) && bytes.Compare(segments[first].End[:], bucketStart[:]) < 0 {
			first++
		}
		if last < first {
			last = first
		}
		for last < len(segments) && bytes.Compare(segments[last].Start[:], bucketEnd[:]) <= 0 {
			last++
		}
		if last > first {
			count := uint32(last - first)
			buckets[bucket] = geoBucket{Start: uint32(first), Count: count}
			active++
			if count > maxCount {
				maxCount = count
			}
		}
	}
	return &geoAssetPlan{Buckets: buckets, SegmentCount: uint32(len(segments))}, geoAssetStats{
		BucketCount:    active,
		SegmentCount:   len(segments),
		MaxBucketCount: maxCount,
		MaxLookupSteps: binarySearchSteps(maxCount),
	}
}

func writeGeoAssetV4FromSegments(path string, plan *geoAssetPlan, segments []xdbScanSegmentV4, provinceIDs map[string]uint16, provinceCount int) error {
	encoded := make([]geoSegmentV4, 0, len(segments))
	for _, segment := range segments {
		provinceID, ok := provinceIDs[segment.Province]
		if !ok {
			return fmt.Errorf("未找到省份编号: %s", segment.Province)
		}
		encoded = append(encoded, geoSegmentV4{
			Start:      xdbIPv4SegmentValue(segment.Start),
			End:        xdbIPv4SegmentValue(segment.End),
			ProvinceID: provinceID,
		})
	}
	return writeGeoAssetV4(path, plan.Buckets, encoded, provinceCount)
}

func writeGeoAssetV6FromSegments(path string, plan *geoAssetPlan, segments []xdbScanSegmentV6, provinceIDs map[string]uint16, provinceCount int) error {
	encoded := make([]geoSegmentV6, 0, len(segments))
	for _, segment := range segments {
		provinceID, ok := provinceIDs[segment.Province]
		if !ok {
			return fmt.Errorf("未找到省份编号: %s", segment.Province)
		}
		encoded = append(encoded, geoSegmentV6{
			Start:      segment.Start,
			End:        segment.End,
			ProvinceID: provinceID,
		})
	}
	return writeGeoAssetV6(path, plan.Buckets, encoded, provinceCount)
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
		province, ok, err := xdbProvinceByIndex(file, buf, 4)
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
		if err := handler(xdbScanSegmentV4{Province: province, Start: start, End: end}); err != nil {
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
		province, ok, err := xdbProvinceByIndex(file, buf, 6)
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

func xdbProvinceByIndex(file *os.File, segment []byte, ipVersion uint16) (string, bool, error) {
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
		return "", false, err
	}
	if !strings.HasPrefix(region, "中国|") {
		return "", false, nil
	}
	parts := strings.Split(region, "|")
	if len(parts) < 2 {
		return "", false, nil
	}
	province := strings.TrimSpace(parts[1])
	if province == "" || province == "0" || province == "Reserved" {
		return "", false, nil
	}
	return province, true, nil
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
	if stats.SegmentCount > segmentLimit {
		return fmt.Errorf("geo %s segment_count=%d 超过当前 BPF map 上限 %d", label, stats.SegmentCount, segmentLimit)
	}
	if stats.MaxLookupSteps > geoLookupLoopLimit {
		return fmt.Errorf(
			"geo %s 最大 bucket 窗口=%d，需要 %d 次二分，超过当前 BPF loop 预算 %d",
			label,
			stats.MaxBucketCount,
			stats.MaxLookupSteps,
			geoLookupLoopLimit,
		)
	}
	return nil
}

func writeGeoAssetV4(path string, buckets []geoBucket, segments []geoSegmentV4, provinceCount int) error {
	header := geoHeader{}
	copy(header.Magic[:], []byte(geoAssetMagic))
	header.Version = geoAssetVersion
	header.IPVersion = 4
	header.BucketCount = uint32(len(buckets))
	header.SegmentCount = uint32(len(segments))
	header.ProvinceCount = uint32(provinceCount)
	return writeGeoAsset(path, header, buckets, segments, "v4")
}

func writeGeoAssetV6(path string, buckets []geoBucket, segments []geoSegmentV6, provinceCount int) error {
	header := geoHeader{}
	copy(header.Magic[:], []byte(geoAssetMagic))
	header.Version = geoAssetVersion
	header.IPVersion = 6
	header.BucketCount = uint32(len(buckets))
	header.SegmentCount = uint32(len(segments))
	header.ProvinceCount = uint32(provinceCount)
	return writeGeoAsset(path, header, buckets, segments, "v6")
}

func writeGeoAsset[T any](path string, header geoHeader, buckets []geoBucket, segments []T, label string) (err error) {
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
	for _, bucket := range buckets {
		if err := binary.Write(file, binary.LittleEndian, bucket); err != nil {
			return fmt.Errorf("编码 geo %s bucket 失败: %w", label, err)
		}
	}
	for _, segment := range segments {
		if err := binary.Write(file, binary.LittleEndian, segment); err != nil {
			return fmt.Errorf("编码 geo %s segment 失败: %w", label, err)
		}
	}
	if err := file.Chmod(0o644); err != nil {
		return fmt.Errorf("设置 geo %s 资产权限失败: %w", label, err)
	}
	return nil
}

func readGeoAssetV4(path string) ([]geoBucket, []geoSegmentV4, uint16, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("读取 geo v4 资产失败: %w", err)
	}
	if len(content) < geoHeaderSize {
		return nil, nil, 0, fmt.Errorf("geo v4 资产过短")
	}
	var header geoHeader
	if err := binary.Read(bytes.NewReader(content[:geoHeaderSize]), binary.LittleEndian, &header); err != nil {
		return nil, nil, 0, fmt.Errorf("解析 geo v4 header 失败: %w", err)
	}
	if string(header.Magic[:]) != geoAssetMagic {
		return nil, nil, 0, fmt.Errorf("geo v4 magic 不匹配")
	}
	offset := geoHeaderSize
	buckets := make([]geoBucket, int(header.BucketCount))
	for i := range buckets {
		buckets[i].Start = binary.LittleEndian.Uint32(content[offset:])
		buckets[i].Count = binary.LittleEndian.Uint32(content[offset+4:])
		offset += 8
	}
	segments := make([]geoSegmentV4, int(header.SegmentCount))
	for i := range segments {
		segments[i].Start = binary.LittleEndian.Uint32(content[offset:])
		segments[i].End = binary.LittleEndian.Uint32(content[offset+4:])
		segments[i].ProvinceID = binary.LittleEndian.Uint16(content[offset+8:])
		segments[i].Pad = binary.LittleEndian.Uint16(content[offset+10:])
		offset += 12
	}
	return buckets, segments, header.IPVersion, nil
}

func readGeoAssetV6(path string) ([]geoBucket, []geoSegmentV6, uint16, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("读取 geo v6 资产失败: %w", err)
	}
	if len(content) < geoHeaderSize {
		return nil, nil, 0, fmt.Errorf("geo v6 资产过短")
	}
	var header geoHeader
	if err := binary.Read(bytes.NewReader(content[:geoHeaderSize]), binary.LittleEndian, &header); err != nil {
		return nil, nil, 0, fmt.Errorf("解析 geo v6 header 失败: %w", err)
	}
	if string(header.Magic[:]) != geoAssetMagic {
		return nil, nil, 0, fmt.Errorf("geo v6 magic 不匹配")
	}
	offset := geoHeaderSize
	buckets := make([]geoBucket, int(header.BucketCount))
	for i := range buckets {
		buckets[i].Start = binary.LittleEndian.Uint32(content[offset:])
		buckets[i].Count = binary.LittleEndian.Uint32(content[offset+4:])
		offset += 8
	}
	segments := make([]geoSegmentV6, int(header.SegmentCount))
	for i := range segments {
		copy(segments[i].Start[:], content[offset:offset+16])
		copy(segments[i].End[:], content[offset+16:offset+32])
		segments[i].ProvinceID = binary.LittleEndian.Uint16(content[offset+32:])
		segments[i].Pad = binary.LittleEndian.Uint16(content[offset+34:])
		offset += 36
	}
	return buckets, segments, header.IPVersion, nil
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
	if customAllowed {
		_, _ = fmt.Fprintln(os.Stdout, "allow custom")
		return nil
	}
	provinceID, provinceName, geoAllowed, err := geoAssetContainsAddress(assets, addr)
	if err != nil {
		return err
	}
	if !geoAllowed {
		_, _ = fmt.Fprintln(os.Stdout, "deny not-cn")
		return fmt.Errorf("未命中中国段")
	}
	switch mode {
	case "all":
		_, _ = fmt.Fprintf(os.Stdout, "allow geo province=%s id=%d\n", provinceName, provinceID)
		return nil
	case "provinces":
		if _, ok := allowedProvinces[provinceName]; ok {
			_, _ = fmt.Fprintf(os.Stdout, "allow geo province=%s id=%d\n", provinceName, provinceID)
			return nil
		}
		_, _ = fmt.Fprintf(os.Stdout, "deny province=%s id=%d\n", provinceName, provinceID)
		return fmt.Errorf("省份未授权: %s", provinceName)
	case "off":
		_, _ = fmt.Fprintln(os.Stdout, "deny mode-off")
		return fmt.Errorf("geo 模式已关闭")
	default:
		return fmt.Errorf("无效 geo mode: %s", mode)
	}
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

func geoAssetContainsAddress(assets *geoAssetRuntime, addr netip.Addr) (uint16, string, bool, error) {
	if assets == nil {
		return 0, "", false, fmt.Errorf("geo 资产为空")
	}
	if addr.Is4() {
		v4 := addr.As4()
		bucket := assets.BucketsV4[int(v4[0])<<8|int(v4[1])]
		if bucket.Count == 0 {
			return 0, "", false, nil
		}
		target := ipv4BytesToBE(v4)
		segment, ok := findGeoSegmentV4(assets.SegmentsV4, bucket, target)
		if !ok {
			return 0, "", false, nil
		}
		return segment.ProvinceID, assets.provinceName(segment.ProvinceID), true, nil
	}
	v6 := addr.As16()
	bucket := assets.BucketsV6[int(v6[0])<<8|int(v6[1])]
	if bucket.Count == 0 {
		return 0, "", false, nil
	}
	segment, ok := findGeoSegmentV6(assets.SegmentsV6, bucket, v6)
	if !ok {
		return 0, "", false, nil
	}
	return segment.ProvinceID, assets.provinceName(segment.ProvinceID), true, nil
}

func (assets *geoAssetRuntime) provinceName(id uint16) string {
	for _, province := range assets.Meta.Provinces {
		if province.ID == id {
			return province.Name
		}
	}
	return ""
}

func findGeoSegmentV4(segments []geoSegmentV4, bucket geoBucket, target uint32) (geoSegmentV4, bool) {
	low := int(bucket.Start)
	high := low + int(bucket.Count) - 1
	for low <= high {
		mid := low + (high-low)/2
		segment := segments[mid]
		if target < segment.Start {
			high = mid - 1
			continue
		}
		if target > segment.End {
			low = mid + 1
			continue
		}
		return segment, true
	}
	return geoSegmentV4{}, false
}

func findGeoSegmentV6(segments []geoSegmentV6, bucket geoBucket, target [16]byte) (geoSegmentV6, bool) {
	low := int(bucket.Start)
	high := low + int(bucket.Count) - 1
	for low <= high {
		mid := low + (high-low)/2
		segment := segments[mid]
		if bytes.Compare(target[:], segment.Start[:]) < 0 {
			high = mid - 1
			continue
		}
		if bytes.Compare(target[:], segment.End[:]) > 0 {
			low = mid + 1
			continue
		}
		return segment, true
	}
	return geoSegmentV6{}, false
}
