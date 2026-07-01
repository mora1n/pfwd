package app

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

func normalizeUserID(value string) string {
	return strings.TrimRight(value, " \t\r\n")
}

func validateUserID(value string) error {
	if normalizeUserID(value) == "" {
		return fmt.Errorf("用户名不能为空")
	}
	if strings.ContainsAny(value, "\r\n\t") {
		return fmt.Errorf("无效用户名：不能包含控制字符")
	}
	return nil
}

func validatePort(value int) error {
	if value < 1 || value > 65535 {
		return fmt.Errorf("端口超出范围：%d", value)
	}
	return nil
}

func parsePort(value string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("无效端口：%s", value)
	}
	if err := validatePort(n); err != nil {
		return 0, err
	}
	return uint16(n), nil
}

func expandPortSpec(value string) ([]uint16, error) {
	value = strings.ReplaceAll(strings.TrimSpace(value), " ", "")
	if value == "" {
		return nil, fmt.Errorf("端口不能为空")
	}
	if strings.HasPrefix(value, ",") || strings.HasSuffix(value, ",") || strings.Contains(value, ",,") {
		return nil, fmt.Errorf("无效端口列表：%s", value)
	}
	var out []uint16
	for _, token := range strings.Split(value, ",") {
		if strings.Contains(token, "-") {
			parts := strings.Split(token, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("无效端口范围：%s", token)
			}
			start, err := parsePort(parts[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(parts[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("端口范围顺序错误：%s", token)
			}
			for p := start; p <= end; p++ {
				out = append(out, p)
				if p == math.MaxUint16 {
					break
				}
			}
			continue
		}
		port, err := parsePort(token)
		if err != nil {
			return nil, err
		}
		out = append(out, port)
	}
	return out, nil
}

func parseHostPort(value string) (string, uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, fmt.Errorf("远端地址不能为空")
	}
	var host, portText string
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]")
		if end <= 1 || end+1 >= len(value) || value[end+1] != ':' {
			return "", 0, fmt.Errorf("无效远端地址：%s", value)
		}
		host = value[1:end]
		portText = value[end+2:]
	} else {
		idx := strings.LastIndex(value, ":")
		if idx <= 0 {
			return "", 0, fmt.Errorf("远端地址必须包含端口：%s", value)
		}
		host = value[:idx]
		portText = value[idx+1:]
	}
	if strings.TrimSpace(host) == "" {
		return "", 0, fmt.Errorf("远端主机不能为空")
	}
	port, err := parsePort(portText)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func parseHostPortSpec(value string) (string, []uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil, fmt.Errorf("远端地址不能为空")
	}
	var host, portText string
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]")
		if end <= 1 || end+1 >= len(value) || value[end+1] != ':' {
			return "", nil, fmt.Errorf("无效远端地址：%s", value)
		}
		host = value[1:end]
		portText = value[end+2:]
	} else {
		idx := strings.LastIndex(value, ":")
		if idx <= 0 {
			return "", nil, fmt.Errorf("远端地址必须包含端口：%s", value)
		}
		host = value[:idx]
		portText = value[idx+1:]
	}
	ports, err := expandPortSpec(portText)
	if err != nil {
		return "", nil, err
	}
	return host, ports, nil
}

func validateListenIP(value string) error {
	switch strings.TrimSpace(value) {
	case "", "::", "0.0.0.0":
		return nil
	default:
		return fmt.Errorf("当前转发快路径仅支持通配监听地址（:: 或 0.0.0.0），不支持具体 listen_ip：%s", value)
	}
}

func validateProtocol(value string) error {
	switch value {
	case "tcp", "udp", "tcp_udp":
		return nil
	default:
		return fmt.Errorf("无效转发协议：%s", value)
	}
}

func protocolsConflict(left, right string) bool {
	return left == "tcp_udp" || right == "tcp_udp" || left == right
}

func validateTrafficMode(value string) error {
	switch value {
	case "one-way", "two-way":
		return nil
	default:
		return fmt.Errorf("无效流量统计模式：%s", value)
	}
}

func validateSNAT(mode, source string) error {
	switch mode {
	case "", "masquerade":
		if strings.TrimSpace(source) != "" {
			return fmt.Errorf("masquerade 模式不允许设置 snat_source")
		}
		return nil
	case "snat":
		if strings.TrimSpace(source) == "" {
			return fmt.Errorf("snat 模式必须提供源地址")
		}
		if _, err := netip.ParseAddr(source); err != nil {
			return fmt.Errorf("需要显式 IP 地址：%s", source)
		}
		return nil
	default:
		return fmt.Errorf("无效 SNAT 模式：%s", mode)
	}
}

func normalizeStopAt(raw string) (*string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "-" {
		return nil, nil
	}
	if strings.HasPrefix(raw, "+") || strings.HasSuffix(strings.ToLower(raw), "d") {
		daysText := strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(raw), "d"), "+")
		days, err := strconv.Atoi(daysText)
		if err != nil || days < 0 {
			return nil, fmt.Errorf("无效日期：%s", raw)
		}
		value := time.Now().AddDate(0, 0, days).Format("2006-01-02 00:00")
		return &value, nil
	}
	layouts := []string{"20060102 15:04", "20060102", "2006-01-02 15:04", "2006-01-02", "2006/01/02 15:04", "2006/01/02"}
	for _, layout := range layouts {
		t, err := time.ParseInLocation(layout, raw, time.Local)
		if err == nil {
			value := t.Format("2006-01-02 15:04")
			if len(layout) == len("20060102") || len(layout) == len("2006-01-02") || len(layout) == len("2006/01/02") {
				value = t.Format("2006-01-02 00:00")
			}
			return &value, nil
		}
	}
	return nil, fmt.Errorf("无效日期：%s，支持 YYYYMMDD、YYYY-MM-DD、YYYY/MM/DD、可选 HH:MM、+7、7d", raw)
}

func parseSizeBytes(value string) (uint64, error) {
	raw := strings.TrimSpace(strings.ToUpper(value))
	if raw == "" {
		return 0, fmt.Errorf("流量大小不能为空")
	}
	multiplier := float64(1)
	for _, suffix := range []struct {
		s string
		m float64
	}{
		{"TIB", 1 << 40}, {"TB", 1e12}, {"GIB", 1 << 30}, {"GB", 1e9}, {"MIB", 1 << 20}, {"MB", 1e6}, {"KIB", 1 << 10}, {"KB", 1e3}, {"B", 1},
	} {
		if strings.HasSuffix(raw, suffix.s) {
			raw = strings.TrimSpace(strings.TrimSuffix(raw, suffix.s))
			multiplier = suffix.m
			break
		}
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("无效流量大小：%s", value)
	}
	return uint64(n * multiplier), nil
}

func randomID(prefix string) (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b[:]), nil
}

func ptrString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
