package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

const (
	geoHiddenCNProvinceName = "中国(未知省市)"

	adysecIPDatabaseRawBase    = "https://raw.githubusercontent.com/adysec/IP_database/main"
	adysecIPDatabaseMirrorBase = "https://raw.gitmirror.com/adysec/IP_database/main"
)

type geoSourceRecord struct {
	Name          string   `json:"name"`
	Path          string   `json:"path"`
	Kind          string   `json:"kind"`
	RequestedURLs []string `json:"requested_urls"`
	SelectedURL   string   `json:"selected_url"`
	SHA256        string   `json:"sha256"`
	Bytes         int64    `json:"bytes"`
	UsedFor       []string `json:"used_for"`
	RowsAccepted  int      `json:"rows_accepted"`
	RowsSkipped   int      `json:"rows_skipped"`
	Conflicts     int      `json:"conflicts"`
	CityUnmatched int      `json:"city_unmatched"`
}

type downloadedGeoSource struct {
	Path        string
	SHA256      string
	SelectedURL string
	Bytes       int64
}

type geoSourceDefinition struct {
	Name     string
	Path     string
	Kind     string
	UsedFor  []string
	Required bool
}

type geoSupplementalSegments struct {
	V4      []xdbScanSegmentV4
	V6      []xdbScanSegmentV6
	CityV4  []xdbScanSegmentV4
	Records []geoSourceRecord
}

type ipdbMetadata struct {
	Build     int64          `json:"build"`
	IPVersion uint16         `json:"ip_version"`
	Languages map[string]int `json:"languages"`
	NodeCount int            `json:"node_count"`
	TotalSize int            `json:"total_size"`
	Fields    []string       `json:"fields"`
}

type ipdbReader struct {
	meta     ipdbMetadata
	data     []byte
	v4Offset int
}

type qqwryEntry struct {
	Start    uint32
	End      uint32
	Location string
}

var adysecSourceDefinitions = []geoSourceDefinition{
	{Name: "adysec-ip-merge", Path: "ip2region/ip.merge.txt", Kind: "ip-merge", UsedFor: []string{"geo-v4", "city-v4"}, Required: true},
	{Name: "adysec-ip2region-xdb", Path: "ip2region/ip2region.xdb", Kind: "xdb-v4", UsedFor: []string{"geo-v4", "city-v4"}, Required: true},
	{Name: "adysec-geolite-city", Path: "geolite/GeoLite2-City.mmdb", Kind: "mmdb-city", UsedFor: []string{"geo-v4", "geo-v6", "city-v4"}, Required: true},
	{Name: "adysec-geolite-country", Path: "geolite/GeoLite2-Country.mmdb", Kind: "mmdb-country", UsedFor: []string{"geo-v4", "geo-v6"}, Required: true},
	{Name: "adysec-dbip-city", Path: "db-ip/dbip-city-lite.mmdb", Kind: "mmdb-city", UsedFor: []string{"geo-v4", "geo-v6", "city-v4"}, Required: true},
	{Name: "adysec-dbip-country", Path: "db-ip/dbip-country-lite.mmdb", Kind: "mmdb-country", UsedFor: []string{"geo-v4", "geo-v6"}, Required: true},
	{Name: "adysec-ipdb-city", Path: "ipdb/city.free.ipdb", Kind: "ipdb-city", UsedFor: []string{"geo-v4", "geo-v6", "city-v4"}, Required: true},
	{Name: "adysec-qqwry", Path: "qqwry/qqwry.dat", Kind: "qqwry", UsedFor: []string{"geo-v4", "city-v4"}, Required: true},
	{Name: "adysec-17mon", Path: "17monipdb/17monipdb.dat", Kind: "17mon", UsedFor: []string{"geo-v4", "city-v4"}, Required: true},
	{Name: "adysec-geolite-asn", Path: "geolite/GeoLite2-ASN.mmdb", Kind: "mmdb-asn", UsedFor: []string{"metadata"}, Required: true},
	{Name: "adysec-dbip-asn", Path: "db-ip/dbip-asn-lite.mmdb", Kind: "mmdb-asn", UsedFor: []string{"metadata"}, Required: true},
}

func collectAdysecSupplementalSegments(ctx context.Context, client *http.Client, catalog cityMetaCatalog) (geoSupplementalSegments, error) {
	out := geoSupplementalSegments{}
	for _, def := range adysecSourceDefinitions {
		record := geoSourceRecord{
			Name:          def.Name,
			Path:          def.Path,
			Kind:          def.Kind,
			RequestedURLs: adysecDownloadURLs(def.Path),
			UsedFor:       append([]string{}, def.UsedFor...),
		}
		downloaded, err := downloadGeoSource(ctx, client, record.RequestedURLs)
		if err != nil {
			if def.Required {
				return out, fmt.Errorf("下载 %s 失败: %w", def.Name, err)
			}
			record.RowsSkipped++
			out.Records = append(out.Records, record)
			continue
		}
		record.SelectedURL = downloaded.SelectedURL
		record.SHA256 = downloaded.SHA256
		record.Bytes = downloaded.Bytes
		defer os.Remove(downloaded.Path)

		switch def.Kind {
		case "ip-merge":
			err = ingestIPMergeSource(downloaded.Path, catalog, &record, &out)
		case "xdb-v4":
			err = ingestXDBv4Source(downloaded.Path, catalog, &record, &out)
		case "mmdb-city", "mmdb-country":
			err = ingestMMDBSource(downloaded.Path, def.Kind, catalog, &record, &out)
		case "ipdb-city":
			err = ingestIPDBSource(downloaded.Path, catalog, &record, &out)
		case "qqwry":
			err = ingestQQWrySource(downloaded.Path, catalog, &record, &out)
		case "17mon":
			err = ingest17MonSource(downloaded.Path, catalog, &record, &out)
		case "mmdb-asn":
			record.RowsSkipped++
		default:
			err = fmt.Errorf("未知 adysec source kind: %s", def.Kind)
		}
		if err != nil {
			return out, fmt.Errorf("解析 %s 失败: %w", def.Name, err)
		}
		out.Records = append(out.Records, record)
	}
	return out, nil
}

func adysecDownloadURLs(path string) []string {
	path = strings.TrimLeft(strings.TrimSpace(path), "/")
	return []string{
		adysecIPDatabaseRawBase + "/" + path,
		adysecIPDatabaseMirrorBase + "/" + path,
	}
}

func downloadGeoSource(ctx context.Context, client *http.Client, urls []string) (*downloadedGeoSource, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("缺少下载地址")
	}
	var errorsSeen []string
	for _, rawURL := range urls {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			continue
		}
		result, err := fetchGeoSourceURL(ctx, client, rawURL)
		if err != nil {
			errorsSeen = append(errorsSeen, fmt.Sprintf("%s: %v", rawURL, err))
			continue
		}
		return result, nil
	}
	return nil, fmt.Errorf("%s", strings.Join(errorsSeen, "; "))
}

func fetchGeoSourceURL(ctx context.Context, client *http.Client, url string) (*downloadedGeoSource, error) {
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
	tmp, err := os.CreateTemp("", "pfwd-geo-source-*")
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
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	return &downloadedGeoSource{
		Path:        tmp.Name(),
		SHA256:      hex.EncodeToString(hasher.Sum(nil)),
		SelectedURL: url,
		Bytes:       size,
	}, nil
}

func ingestIPMergeSource(path string, catalog cityMetaCatalog, record *geoSourceRecord, out *geoSupplementalSegments) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			record.RowsSkipped++
			continue
		}
		if strings.TrimSpace(parts[2]) != "中国" {
			record.RowsSkipped++
			continue
		}
		start, err := parseIPv4Value(parts[0])
		if err != nil {
			return err
		}
		end, err := parseIPv4Value(parts[1])
		if err != nil {
			return err
		}
		if start > end {
			return fmt.Errorf("ip.merge.txt 起止倒置: %s", line)
		}
		province := ""
		city := ""
		if len(parts) >= 5 {
			province = parts[4]
		}
		if len(parts) >= 6 {
			city = parts[5]
		}
		appendCNSegmentV4(out, start, end, province, city, catalog, record)
	}
	return scanner.Err()
}

func ingestXDBv4Source(path string, catalog cityMetaCatalog, record *geoSourceRecord, out *geoSupplementalSegments) error {
	return scanCNXDBv4(path, func(segment xdbScanSegmentV4) error {
		start := xdbIPv4SegmentValue(segment.Start)
		end := xdbIPv4SegmentValue(segment.End)
		appendCNSegmentV4(out, start, end, segment.Province, segment.City, catalog, record)
		return nil
	})
}

func ingestMMDBSource(path, kind string, catalog cityMetaCatalog, record *geoSourceRecord, out *geoSupplementalSegments) error {
	db, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	defer db.Close()
	for result := range db.Networks(maxminddb.SkipEmptyValues()) {
		if err := result.Err(); err != nil {
			return err
		}
		var item map[string]any
		if err := result.Decode(&item); err != nil {
			return err
		}
		if !mmdbRecordIsCN(item) {
			record.RowsSkipped++
			continue
		}
		prefix := result.Prefix()
		province := ""
		city := ""
		if kind == "mmdb-city" {
			province = mmdbProvinceName(item)
			city = mmdbLocalizedField(item["city"])
		}
		appendCNPrefix(out, prefix, province, city, catalog, record)
	}
	return nil
}

func mmdbRecordIsCN(item map[string]any) bool {
	for _, key := range []string{"country", "country_code", "country_iso_code", "country_iso", "registered_country_code"} {
		value := mmdbAnyString(item[key])
		if strings.EqualFold(value, "CN") || strings.EqualFold(value, "CHN") || value == "中国" || strings.EqualFold(value, "China") {
			return true
		}
	}
	for _, key := range []string{"country", "registered_country", "represented_country"} {
		values := mmdbMap(item[key])
		code := mmdbStringField(values, "iso_code")
		if strings.EqualFold(strings.TrimSpace(code), "CN") {
			return true
		}
		name := mmdbLocalizedField(values)
		if name == "中国" || strings.EqualFold(name, "China") {
			return true
		}
	}
	return false
}

func mmdbProvinceName(item map[string]any) string {
	subdivisions, ok := item["subdivisions"].([]any)
	if ok && len(subdivisions) > 0 {
		first := mmdbMap(subdivisions[0])
		if value := mmdbLocalizedField(first); value != "" {
			return value
		}
		return cnSubdivisionISOName(mmdbStringField(first, "iso_code"))
	}
	for _, key := range []string{"subdivision", "region", "state", "province"} {
		if value := mmdbLocalizedField(item[key]); value != "" {
			return value
		}
	}
	return ""
}

func mmdbLocalizedField(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case map[string]any:
		return mmdbLocalizedNames(mmdbMap(typed["names"]))
	default:
		return ""
	}
}

func mmdbLocalizedNames(names map[string]any) string {
	for _, key := range []string{"zh-CN", "zh", "cn", "en"} {
		if value := mmdbAnyString(names[key]); value != "" {
			return value
		}
	}
	return ""
}

func mmdbMap(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

func mmdbStringField(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	return mmdbAnyString(values[key])
}

func mmdbAnyString(value any) string {
	if typed, ok := value.(string); ok {
		return strings.TrimSpace(typed)
	}
	return ""
}

func ingestIPDBSource(path string, catalog cityMetaCatalog, record *geoSourceRecord, out *geoSupplementalSegments) error {
	reader, err := openIPDBReader(path)
	if err != nil {
		return err
	}
	if reader.meta.Languages["CN"] == 0 && !ipdbHasLanguage(reader.meta, "CN") {
		return fmt.Errorf("ipdb 不包含 CN 语言")
	}
	if reader.supportsIPv4() {
		err = reader.walkIPv4(func(start, end uint32, fields map[string]string) error {
			if !ipdbFieldsAreCN(fields) {
				record.RowsSkipped++
				return nil
			}
			appendCNSegmentV4(out, start, end, fields["region_name"], fields["city_name"], catalog, record)
			return nil
		})
		if err != nil {
			return err
		}
	}
	if reader.supportsIPv6() {
		err = reader.walkIPv6(func(start, end [16]byte, fields map[string]string) error {
			if !ipdbFieldsAreCN(fields) {
				record.RowsSkipped++
				return nil
			}
			segment := normalizeCNSegment(fields["region_name"], "", catalog, record)
			out.V6 = append(out.V6, xdbScanSegmentV6{Province: segment.Province, Start: start, End: end})
			record.RowsAccepted++
			return nil
		})
	}
	return err
}

func ipdbHasLanguage(meta ipdbMetadata, language string) bool {
	_, ok := meta.Languages[language]
	return ok
}

func ipdbFieldsAreCN(fields map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(fields["country_code"]), "CN") ||
		strings.EqualFold(strings.TrimSpace(fields["country_code3"]), "CHN") ||
		strings.TrimSpace(fields["country_name"]) == "中国"
}

func openIPDBReader(path string) (*ipdbReader, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(body) < 4 {
		return nil, fmt.Errorf("ipdb 文件过短")
	}
	metaLen := int(binary.BigEndian.Uint32(body[:4]))
	if len(body) < 4+metaLen {
		return nil, fmt.Errorf("ipdb metadata 截断")
	}
	var meta ipdbMetadata
	if err := json.Unmarshal(body[4:4+metaLen], &meta); err != nil {
		return nil, err
	}
	if len(body) != 4+metaLen+meta.TotalSize {
		return nil, fmt.Errorf("ipdb total_size 不匹配")
	}
	reader := &ipdbReader{
		meta: meta,
		data: body[4+metaLen:],
	}
	node := 0
	for i := 0; i < 96 && node < reader.meta.NodeCount; i++ {
		if i >= 80 {
			node = reader.readNode(node, 1)
		} else {
			node = reader.readNode(node, 0)
		}
	}
	reader.v4Offset = node
	return reader, nil
}

func (r *ipdbReader) supportsIPv4() bool {
	return int(r.meta.IPVersion)&1 == 1
}

func (r *ipdbReader) supportsIPv6() bool {
	return int(r.meta.IPVersion)&2 == 2
}

func (r *ipdbReader) readNode(node, index int) int {
	offset := node*8 + index*4
	return int(binary.BigEndian.Uint32(r.data[offset : offset+4]))
}

func (r *ipdbReader) resolve(node int) ([]byte, error) {
	resolved := node - r.meta.NodeCount + r.meta.NodeCount*8
	if resolved < 0 || resolved+2 > len(r.data) {
		return nil, fmt.Errorf("ipdb data offset 越界")
	}
	size := int(binary.BigEndian.Uint16(r.data[resolved : resolved+2]))
	if resolved+2+size > len(r.data) {
		return nil, fmt.Errorf("ipdb data body 截断")
	}
	return r.data[resolved+2 : resolved+2+size], nil
}

func (r *ipdbReader) decodeFields(node int) (map[string]string, error) {
	body, err := r.resolve(node)
	if err != nil {
		return nil, err
	}
	values := strings.Split(string(body), "\t")
	offset, ok := r.meta.Languages["CN"]
	if !ok {
		return nil, fmt.Errorf("ipdb 不包含 CN 语言")
	}
	if offset+len(r.meta.Fields) > len(values) {
		return nil, fmt.Errorf("ipdb 字段数量不足")
	}
	out := make(map[string]string, len(r.meta.Fields))
	for i, name := range r.meta.Fields {
		out[name] = values[offset+i]
	}
	return out, nil
}

func (r *ipdbReader) walkIPv4(handler func(start, end uint32, fields map[string]string) error) error {
	var walk func(node int, depth int, prefix uint32) error
	walk = func(node int, depth int, prefix uint32) error {
		if node > r.meta.NodeCount {
			fields, err := r.decodeFields(node)
			if err != nil {
				return err
			}
			start, end := ipv4RangeFromPrefixBits(prefix, depth)
			return handler(start, end, fields)
		}
		if depth >= 32 {
			return nil
		}
		for bit := 0; bit <= 1; bit++ {
			next := r.readNode(node, bit)
			if err := walk(next, depth+1, prefix|uint32(bit)<<(31-depth)); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(r.v4Offset, 0, 0)
}

func (r *ipdbReader) walkIPv6(handler func(start, end [16]byte, fields map[string]string) error) error {
	var walk func(node int, depth int, prefix [16]byte) error
	walk = func(node int, depth int, prefix [16]byte) error {
		if node > r.meta.NodeCount {
			fields, err := r.decodeFields(node)
			if err != nil {
				return err
			}
			start, end := ipv6RangeFromPrefixBits(prefix, depth)
			return handler(start, end, fields)
		}
		if depth >= 128 {
			return nil
		}
		for bit := 0; bit <= 1; bit++ {
			nextPrefix := prefix
			if bit == 1 {
				nextPrefix[depth/8] |= byte(1 << uint(7-depth%8))
			}
			if err := walk(r.readNode(node, bit), depth+1, nextPrefix); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(0, 0, [16]byte{})
}

func ingest17MonSource(path string, catalog cityMetaCatalog, record *geoSourceRecord, out *geoSupplementalSegments) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(content) < 1028 {
		return fmt.Errorf("17mon 文件过短")
	}
	offset := binary.BigEndian.Uint32(content[:4])
	if int(offset) > len(content) || offset < 1028 {
		return fmt.Errorf("17mon offset 越界")
	}
	index := content[4:offset]
	var prev uint32
	for pos := 1024; pos+8 <= len(index)-4; pos += 8 {
		end := binary.BigEndian.Uint32(index[pos : pos+4])
		length := uint32(index[pos+7])
		dataOffset := uint32(index[pos+4]) | uint32(index[pos+5])<<8 | uint32(index[pos+6])<<16
		locationPos := int(dataOffset + offset - 1028)
		if locationPos < 0 || locationPos+int(length) > len(index) {
			record.RowsSkipped++
			continue
		}
		if prev > end {
			record.RowsSkipped++
			continue
		}
		location := string(index[locationPos : locationPos+int(length)])
		appendLocationTextSegmentV4(out, prev, end, location, catalog, record)
		if end == ^uint32(0) {
			break
		}
		prev = end + 1
	}
	return nil
}

func ingestQQWrySource(path string, catalog cityMetaCatalog, record *geoSourceRecord, out *geoSupplementalSegments) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	entries, err := readQQWryEntries(content)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		appendLocationTextSegmentV4(out, entry.Start, entry.End, entry.Location, catalog, record)
	}
	return nil
}

func readQQWryEntries(content []byte) ([]qqwryEntry, error) {
	if len(content) < 8 {
		return nil, fmt.Errorf("qqwry 文件过短")
	}
	first := binary.LittleEndian.Uint32(content[:4])
	last := binary.LittleEndian.Uint32(content[4:8])
	if first > last || int(last)+7 > len(content) {
		return nil, fmt.Errorf("qqwry index 越界")
	}
	total := int((last-first)/7) + 1
	out := make([]qqwryEntry, 0, total)
	for i := 0; i < total; i++ {
		pos := int(first) + i*7
		start := binary.LittleEndian.Uint32(content[pos : pos+4])
		recordOffset := readQQWryOffset(content[pos+4 : pos+7])
		if int(recordOffset)+4 > len(content) {
			continue
		}
		end := binary.LittleEndian.Uint32(content[recordOffset : recordOffset+4])
		location, err := readQQWryLocation(content, int(recordOffset)+4)
		if err != nil {
			continue
		}
		out = append(out, qqwryEntry{Start: start, End: end, Location: location})
	}
	return out, nil
}

func readQQWryLocation(content []byte, pos int) (string, error) {
	if pos >= len(content) {
		return "", fmt.Errorf("qqwry location offset 越界")
	}
	var country string
	var area string
	switch content[pos] {
	case 0x01:
		redirect := int(readQQWryOffset(content[pos+1 : pos+4]))
		if redirect >= len(content) {
			return "", fmt.Errorf("qqwry redirect 越界")
		}
		if content[redirect] == 0x02 {
			text, err := readQQWryStringAt(content, int(readQQWryOffset(content[redirect+1:redirect+4])))
			if err != nil {
				return "", err
			}
			country = text
			area, _ = readQQWryArea(content, pos+4)
		} else {
			text, next, err := readQQWryString(content, redirect)
			if err != nil {
				return "", err
			}
			country = text
			area, _ = readQQWryArea(content, next)
		}
	case 0x02:
		text, err := readQQWryStringAt(content, int(readQQWryOffset(content[pos+1:pos+4])))
		if err != nil {
			return "", err
		}
		country = text
		area, _ = readQQWryArea(content, pos+4)
	default:
		text, next, err := readQQWryString(content, pos)
		if err != nil {
			return "", err
		}
		country = text
		area, _ = readQQWryArea(content, next)
	}
	return strings.TrimSpace(country + "\t" + area), nil
}

func readQQWryArea(content []byte, pos int) (string, error) {
	if pos >= len(content) {
		return "", nil
	}
	switch content[pos] {
	case 0x01, 0x02:
		return readQQWryStringAt(content, int(readQQWryOffset(content[pos+1:pos+4])))
	default:
		text, _, err := readQQWryString(content, pos)
		return text, err
	}
}

func readQQWryOffset(raw []byte) uint32 {
	if len(raw) < 3 {
		return 0
	}
	return uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16
}

func readQQWryStringAt(content []byte, pos int) (string, error) {
	text, _, err := readQQWryString(content, pos)
	return text, err
}

func readQQWryString(content []byte, pos int) (string, int, error) {
	if pos < 0 || pos >= len(content) {
		return "", pos, fmt.Errorf("qqwry string offset 越界")
	}
	end := pos
	for end < len(content) && content[end] != 0 {
		end++
	}
	if end >= len(content) {
		return "", end, fmt.Errorf("qqwry string 未终止")
	}
	reader := transform.NewReader(bytes.NewReader(content[pos:end]), simplifiedchinese.GBK.NewDecoder())
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", end + 1, err
	}
	return string(decoded), end + 1, nil
}

func appendLocationTextSegmentV4(out *geoSupplementalSegments, start, end uint32, location string, catalog cityMetaCatalog, record *geoSourceRecord) {
	province, city, cn := parseLocationText(location, catalog)
	if !cn {
		record.RowsSkipped++
		return
	}
	appendCNSegmentV4(out, start, end, province, city, catalog, record)
}

func parseLocationText(location string, catalog cityMetaCatalog) (string, string, bool) {
	location = strings.TrimSpace(strings.ReplaceAll(location, "\u0000", ""))
	if location == "" || strings.Contains(location, "CZ88") {
		return "", "", false
	}
	parts := strings.FieldsFunc(location, func(r rune) bool {
		return r == '\t' || r == '|' || r == ',' || r == '，' || r == ' '
	})
	if len(parts) > 0 {
		if strings.EqualFold(parts[0], "CN") || parts[0] == "中国" {
			province := ""
			city := ""
			if len(parts) > 1 {
				province = parts[1]
			}
			if len(parts) > 2 {
				city = parts[2]
			}
			return province, city, true
		}
		if province, city, ok := splitChineseProvinceCity(parts[0], catalog); ok {
			return province, city, true
		}
	}
	if province, city, ok := splitChineseProvinceCity(location, catalog); ok {
		return province, city, true
	}
	return "", "", false
}

func splitChineseProvinceCity(value string, catalog cityMetaCatalog) (string, string, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "中国")
	if value == "" {
		return "", "", true
	}
	for _, province := range catalog.ProvinceNamesByLength {
		if strings.HasPrefix(value, province) {
			return province, strings.TrimSpace(strings.TrimPrefix(value, province)), true
		}
		short := normalizeCityMetaName(province)
		if short != "" && strings.HasPrefix(value, short) {
			return province, strings.TrimSpace(strings.TrimPrefix(value, short)), true
		}
	}
	return "", "", strings.Contains(value, "中国")
}

func appendCNPrefix(out *geoSupplementalSegments, prefix netip.Prefix, province, city string, catalog cityMetaCatalog, record *geoSourceRecord) {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		start, end := ipv4RangeFromNetipPrefix(prefix)
		appendCNSegmentV4(out, start, end, province, city, catalog, record)
		return
	}
	if prefix.Addr().Is6() {
		start, end := ipv6RangeFromNetipPrefix(prefix)
		segment := normalizeCNSegment(province, "", catalog, record)
		out.V6 = append(out.V6, xdbScanSegmentV6{Province: segment.Province, Start: start, End: end})
		record.RowsAccepted++
	}
}

func appendCNSegmentV4(out *geoSupplementalSegments, start, end uint32, province, city string, catalog cityMetaCatalog, record *geoSourceRecord) {
	segment := normalizeCNSegment(province, city, catalog, record)
	item := xdbScanSegmentV4{
		Province: segment.Province,
		City:     segment.City,
		Start:    uint32ToXDBIPv4(start),
		End:      uint32ToXDBIPv4(end),
	}
	out.V4 = append(out.V4, item)
	if segment.City != "" {
		out.CityV4 = append(out.CityV4, item)
	}
	record.RowsAccepted++
}

func normalizeCNSegment(province, city string, catalog cityMetaCatalog, record *geoSourceRecord) xdbScanSegmentV4 {
	province = normalizeGeoProvinceName(province, catalog)
	city = strings.TrimSpace(city)
	if province == geoHiddenCNProvinceName {
		return xdbScanSegmentV4{Province: geoHiddenCNProvinceName}
	}
	if invalidRegionPart(city) {
		return xdbScanSegmentV4{Province: province}
	}
	entry, ok, err := findCityMetaEntry(catalog, province, city)
	if err == nil && ok {
		return xdbScanSegmentV4{Province: entry.Province, City: entry.City}
	}
	if record != nil {
		record.CityUnmatched++
	}
	return xdbScanSegmentV4{Province: province}
}

func finalizeGeoSegmentsV4(base []xdbScanSegmentV4, supplemental []xdbScanSegmentV4) []xdbScanSegmentV4 {
	known := make([]xdbScanSegmentV4, 0, len(base)+len(supplemental))
	hidden := make([]xdbScanSegmentV4, 0)
	for _, segment := range base {
		if segment.Province == geoHiddenCNProvinceName {
			hidden = append(hidden, segment)
		} else {
			known = append(known, segment)
		}
	}
	for _, segment := range supplemental {
		if segment.Province == geoHiddenCNProvinceName {
			hidden = append(hidden, segment)
		} else {
			known = append(known, segment)
		}
	}
	known = mergeSameProvinceSegmentsV4(known)
	hidden = subtractKnownFromHiddenV4(hidden, known)
	return append(known, hidden...)
}

func finalizeCitySegmentsV4(base []xdbScanSegmentV4, supplemental []xdbScanSegmentV4) []xdbScanSegmentV4 {
	out := make([]xdbScanSegmentV4, 0, len(base)+len(supplemental))
	for _, segment := range base {
		if segment.City != "" {
			out = append(out, segment)
		}
	}
	for _, segment := range supplemental {
		if segment.City != "" {
			out = append(out, segment)
		}
	}
	return out
}

func mergeSameProvinceSegmentsV4(segments []xdbScanSegmentV4) []xdbScanSegmentV4 {
	ranges := mergeGeoSegmentsV4(segments)
	out := make([]xdbScanSegmentV4, 0, len(ranges))
	for _, item := range ranges {
		out = append(out, xdbScanSegmentV4{
			Province: item.Province,
			Start:    uint32ToXDBIPv4(item.Start),
			End:      uint32ToXDBIPv4(item.End),
		})
	}
	return out
}

func subtractKnownFromHiddenV4(hidden []xdbScanSegmentV4, known []xdbScanSegmentV4) []xdbScanSegmentV4 {
	knownRanges := make([]geoRangeV4, 0, len(known))
	for _, segment := range known {
		knownRanges = append(knownRanges, geoRangeV4{
			Province: segment.Province,
			Start:    xdbIPv4SegmentValue(segment.Start),
			End:      xdbIPv4SegmentValue(segment.End),
		})
	}
	slices.SortFunc(knownRanges, func(left, right geoRangeV4) int {
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
	out := make([]xdbScanSegmentV4, 0, len(hidden))
	for _, segment := range mergeSameProvinceSegmentsV4(hidden) {
		start := xdbIPv4SegmentValue(segment.Start)
		end := xdbIPv4SegmentValue(segment.End)
		pos, _ := slices.BinarySearchFunc(knownRanges, start, func(item geoRangeV4, target uint32) int {
			if item.Start < target {
				return -1
			}
			if item.Start > target {
				return 1
			}
			return 0
		})
		if pos > 0 {
			pos--
			for pos > 0 && knownRanges[pos-1].End >= start {
				pos--
			}
		}
		current := start
		covered := false
		for ; pos < len(knownRanges) && knownRanges[pos].Start <= end; pos++ {
			item := knownRanges[pos]
			if item.End < current {
				continue
			}
			if item.Start > current {
				out = append(out, xdbScanSegmentV4{
					Province: geoHiddenCNProvinceName,
					Start:    uint32ToXDBIPv4(current),
					End:      uint32ToXDBIPv4(item.Start - 1),
				})
			}
			if item.End >= end {
				covered = true
				break
			}
			if item.End+1 > current {
				current = item.End + 1
			}
		}
		if !covered && current <= end {
			out = append(out, xdbScanSegmentV4{
				Province: geoHiddenCNProvinceName,
				Start:    uint32ToXDBIPv4(current),
				End:      uint32ToXDBIPv4(end),
			})
		}
	}
	return out
}

func parseIPv4Value(raw string) (uint32, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return 0, err
	}
	if !addr.Is4() {
		return 0, fmt.Errorf("不是 IPv4 地址: %s", raw)
	}
	return binary.BigEndian.Uint32(addr.AsSlice()), nil
}

func uint32ToXDBIPv4(value uint32) [4]byte {
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], value)
	return out
}

func ipv4RangeFromPrefixBits(prefix uint32, bits int) (uint32, uint32) {
	if bits <= 0 {
		return 0, ^uint32(0)
	}
	if bits >= 32 {
		return prefix, prefix
	}
	mask := ^uint32(0) << uint(32-bits)
	start := prefix & mask
	end := start | ^mask
	return start, end
}

func ipv4RangeFromNetipPrefix(prefix netip.Prefix) (uint32, uint32) {
	bits := prefix.Bits()
	start := binary.BigEndian.Uint32(prefix.Addr().AsSlice())
	return ipv4RangeFromPrefixBits(start, bits)
}

func ipv6RangeFromNetipPrefix(prefix netip.Prefix) ([16]byte, [16]byte) {
	return ipv6RangeFromPrefixBits(prefix.Addr().As16(), prefix.Bits())
}

func ipv6RangeFromPrefixBits(prefix [16]byte, bits int) ([16]byte, [16]byte) {
	start := prefix
	end := prefix
	for bit := bits; bit < 128; bit++ {
		end[bit/8] |= byte(1 << uint(7-bit%8))
	}
	for bit := bits; bit < 128; bit++ {
		start[bit/8] &^= byte(1 << uint(7-bit%8))
	}
	return start, end
}

func cnSubdivisionISOName(code string) string {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "AH":
		return "安徽省"
	case "BJ":
		return "北京市"
	case "CQ":
		return "重庆市"
	case "FJ":
		return "福建省"
	case "GD":
		return "广东省"
	case "GS":
		return "甘肃省"
	case "GX":
		return "广西壮族自治区"
	case "GZ":
		return "贵州省"
	case "HA":
		return "河南省"
	case "HB":
		return "湖北省"
	case "HE":
		return "河北省"
	case "HI":
		return "海南省"
	case "HK":
		return "香港特别行政区"
	case "HL":
		return "黑龙江省"
	case "HN":
		return "湖南省"
	case "JL":
		return "吉林省"
	case "JS":
		return "江苏省"
	case "JX":
		return "江西省"
	case "LN":
		return "辽宁省"
	case "MO":
		return "澳门特别行政区"
	case "NM":
		return "内蒙古自治区"
	case "NX":
		return "宁夏回族自治区"
	case "QH":
		return "青海省"
	case "SC":
		return "四川省"
	case "SD":
		return "山东省"
	case "SH":
		return "上海市"
	case "SN":
		return "陕西省"
	case "SX":
		return "山西省"
	case "TJ":
		return "天津市"
	case "TW":
		return "台湾省"
	case "XJ":
		return "新疆维吾尔自治区"
	case "XZ":
		return "西藏自治区"
	case "YN":
		return "云南省"
	case "ZJ":
		return "浙江省"
	default:
		return ""
	}
}

func geoSourceRecordFromXDB(name string, ipVersion uint16, urls []string, xdb *downloadedXDB, rows int) geoSourceRecord {
	return geoSourceRecord{
		Name:          name,
		Path:          fmt.Sprintf("ip2region_v%d.xdb", ipVersion),
		Kind:          fmt.Sprintf("xdb-v%d", ipVersion),
		RequestedURLs: append([]string{}, urls...),
		SelectedURL:   xdb.SelectedURL,
		SHA256:        xdb.SHA256,
		Bytes:         xdb.Bytes,
		UsedFor:       []string{fmt.Sprintf("geo-v%d", ipVersion)},
		RowsAccepted:  rows,
	}
}

func hiddenProvinceIDs(meta geoAssetMeta) map[uint16]struct{} {
	out := map[uint16]struct{}{}
	for _, province := range meta.Provinces {
		if province.Hidden {
			out[province.ID] = struct{}{}
		}
	}
	return out
}

func (assets *geoAssetRuntime) provinceHidden(id uint16) bool {
	if assets == nil {
		return false
	}
	_, ok := assets.HiddenProvinceIDs[id]
	return ok
}
