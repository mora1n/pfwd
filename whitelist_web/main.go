package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type routeConfig struct {
	Secret        string   `json:"secret"`
	Label         string   `json:"label"`
	SSHTarget     string   `json:"ssh_target"`
	IdleTTL       string   `json:"idle_ttl"`
	SSHOptions    []string `json:"ssh_options"`
	IPv4PrefixLen *int     `json:"ipv4_prefix_len,omitempty"`
	IPv6PrefixLen *int     `json:"ipv6_prefix_len,omitempty"`
}

type config struct {
	ListenHost        string        `json:"listen_host"`
	ListenPort        int           `json:"listen_port"`
	TrustedProxyCIDRs []string      `json:"trusted_proxy_cidrs"`
	RequestTimeoutSec int           `json:"request_timeout_sec"`
	Routes            []routeConfig `json:"routes"`
}

type compiledRoute struct {
	RouteConfig   routeConfig
	IdleTTL       string
	IPv4PrefixLen int
	IPv6PrefixLen int
}

type server struct {
	cfg            config
	routes         map[string]compiledRoute
	trustedProxies []netip.Prefix
	leasePusher    func(context.Context, compiledRoute, string, string) error
}

type responseFormat string

const (
	formatJSON responseFormat = "json"
	formatHTML responseFormat = "html"
)

type responsePayload struct {
	OK         bool   `json:"ok"`
	Format     string `json:"format"`
	Code       string `json:"code,omitempty"`
	Label      string `json:"label,omitempty"`
	ObservedIP string `json:"observed_ip,omitempty"`
	LeaseCIDR  string `json:"lease_cidr,omitempty"`
	IdleTTL    string `json:"idle_ttl,omitempty"`
	Error      string `json:"error,omitempty"`
}

type responseModel struct {
	Status      int
	Format      responseFormat
	Payload     responsePayload
	HTMLTitle   string
	HTMLSummary string
}

var htmlPageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.HTMLTitle}}</title>
  <style>
    :root {
      color-scheme: light dark;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    body {
      margin: 0;
      background: #f3f4f6;
      color: #111827;
    }
    .wrap {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .panel {
      width: min(100%, 420px);
      background: #ffffff;
      border: 1px solid #d1d5db;
      border-radius: 8px;
      padding: 24px;
      box-sizing: border-box;
    }
    .status {
      font-size: 14px;
      font-weight: 600;
      letter-spacing: 0;
      margin: 0 0 8px;
      color: {{if .Payload.OK}}#047857{{else}}#b91c1c{{end}};
    }
    h1 {
      margin: 0 0 10px;
      font-size: 24px;
      line-height: 1.25;
    }
    p {
      margin: 0 0 18px;
      color: #4b5563;
      line-height: 1.5;
    }
    dl {
      margin: 0;
      display: grid;
      grid-template-columns: 96px 1fr;
      gap: 10px 12px;
      font-size: 14px;
    }
    dt {
      color: #6b7280;
    }
    dd {
      margin: 0;
      color: #111827;
      word-break: break-all;
    }
    @media (prefers-color-scheme: dark) {
      body {
        background: #111827;
        color: #f9fafb;
      }
      .panel {
        background: #1f2937;
        border-color: #374151;
      }
      p, dt {
        color: #9ca3af;
      }
      dd {
        color: #f9fafb;
      }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="panel">
      <div class="status">{{if .Payload.OK}}临时白名单已放行{{else}}临时白名单处理失败{{end}}</div>
      <h1>{{.HTMLTitle}}</h1>
      <p>{{.HTMLSummary}}</p>
      <dl>
        {{if .Payload.Label}}<dt>标签</dt><dd>{{.Payload.Label}}</dd>{{end}}
        {{if .Payload.ObservedIP}}<dt>来源 IP</dt><dd>{{.Payload.ObservedIP}}</dd>{{end}}
        {{if .Payload.LeaseCIDR}}<dt>放行范围</dt><dd>{{.Payload.LeaseCIDR}}</dd>{{end}}
        {{if .Payload.IdleTTL}}<dt>时效</dt><dd>{{.Payload.IdleTTL}}</dd>{{end}}
        {{if .Payload.Code}}<dt>状态码</dt><dd>{{.Payload.Code}}</dd>{{end}}
      </dl>
    </section>
  </div>
</body>
</html>`))

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法：pfwd-whitelist-web run --config /etc/pfwd/whitelist-web.json")
	}
	switch args[0] {
	case "run":
		return runServer(args[1:])
	default:
		return fmt.Errorf("未知子命令：%s", args[0])
	}
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var configPath string
	fs.StringVar(&configPath, "config", "", "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return fmt.Errorf("run 缺少 --config")
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	srv, err := newServer(cfg)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              net.JoinHostPort(cfg.ListenHost, fmt.Sprintf("%d", cfg.ListenPort)),
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return httpServer.ListenAndServe()
}

func loadConfig(path string) (config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("读取配置失败: %w", err)
	}
	var cfg config
	if err := json.Unmarshal(content, &cfg); err != nil {
		return config{}, fmt.Errorf("解析配置失败: %w", err)
	}
	if strings.TrimSpace(cfg.ListenHost) == "" {
		cfg.ListenHost = "127.0.0.1"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 18080
	}
	if cfg.RequestTimeoutSec <= 0 {
		cfg.RequestTimeoutSec = 10
	}
	if len(cfg.Routes) == 0 {
		return config{}, errors.New("routes 不能为空")
	}
	return cfg, nil
}

func newServer(cfg config) (*server, error) {
	routes := make(map[string]compiledRoute, len(cfg.Routes))
	for _, route := range cfg.Routes {
		if strings.TrimSpace(route.Secret) == "" {
			return nil, errors.New("route.secret 不能为空")
		}
		if strings.TrimSpace(route.Label) == "" {
			return nil, fmt.Errorf("route %s 缺少 label", route.Secret)
		}
		if strings.TrimSpace(route.SSHTarget) == "" {
			return nil, fmt.Errorf("route %s 缺少 ssh_target", route.Secret)
		}
		if strings.TrimSpace(route.IdleTTL) == "" {
			return nil, fmt.Errorf("route %s 缺少 idle_ttl", route.Secret)
		}
		ipv4PrefixLen := 32
		if route.IPv4PrefixLen != nil {
			ipv4PrefixLen = *route.IPv4PrefixLen
		}
		if err := validateRoutePrefixLen(ipv4PrefixLen, 32, "route.ipv4_prefix_len"); err != nil {
			return nil, err
		}
		ipv6PrefixLen := 128
		if route.IPv6PrefixLen != nil {
			ipv6PrefixLen = *route.IPv6PrefixLen
		}
		if err := validateRoutePrefixLen(ipv6PrefixLen, 128, "route.ipv6_prefix_len"); err != nil {
			return nil, err
		}
		routes[route.Secret] = compiledRoute{
			RouteConfig:   route,
			IdleTTL:       strings.TrimSpace(route.IdleTTL),
			IPv4PrefixLen: ipv4PrefixLen,
			IPv6PrefixLen: ipv6PrefixLen,
		}
	}
	trusted := make([]netip.Prefix, 0, len(cfg.TrustedProxyCIDRs))
	for _, raw := range cfg.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("trusted_proxy_cidrs 无效: %s", raw)
		}
		trusted = append(trusted, prefix)
	}
	return &server{
		cfg:            cfg,
		routes:         routes,
		trustedProxies: trusted,
	}, nil
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := http.StatusInternalServerError
	code := ""
	routeLabel := ""
	observedIP := ""
	leaseCIDR := ""
	sshDuration := time.Duration(-1)
	errorDetail := ""
	write := func(resp responseModel) {
		status = resp.Status
		code = resp.Payload.Code
		writeResponse(w, resp)
	}
	defer func() {
		logWhitelistWebRequest(start, status, code, routeLabel, observedIP, leaseCIDR, sshDuration, errorDetail)
	}()

	format, err := negotiateResponseFormat(r)
	if err != nil {
		errorDetail = err.Error()
		write(invalidFormatResponse(err.Error(), format))
		return
	}
	if r.Method != http.MethodGet {
		write(methodNotAllowedResponse(format))
		return
	}
	secret := strings.Trim(strings.TrimSpace(r.URL.Path), "/")
	route, ok := s.routes[secret]
	if !ok {
		write(secretNotFoundResponse(format))
		return
	}
	routeLabel = strings.TrimSpace(route.RouteConfig.Label)
	observedIP, err = s.observedIP(r)
	if err != nil {
		errorDetail = err.Error()
		write(clientIPUnavailableResponse(format, err.Error()))
		return
	}
	leaseCIDR, err = leaseCIDRForAddress(observedIP, route)
	if err != nil {
		errorDetail = err.Error()
		write(internalConfigErrorResponse(format, err.Error()))
		return
	}
	sshStart := time.Now()
	err = s.pushLease(r.Context(), route, observedIP, leaseCIDR)
	sshDuration = time.Since(sshStart)
	if err != nil {
		errorDetail = err.Error()
		write(leasePushFailedResponse(format, err.Error()))
		return
	}
	write(successResponse(format, route, observedIP, leaseCIDR))
}

func logWhitelistWebRequest(start time.Time, status int, code string, routeLabel string, observedIP string, leaseCIDR string, sshDuration time.Duration, errorDetail string) {
	sshMS := "not_run"
	if sshDuration >= 0 {
		sshMS = fmt.Sprintf("%d", sshDuration.Milliseconds())
	}
	totalMS := time.Since(start).Milliseconds()
	if errorDetail == "" {
		log.Printf("whitelist-web request label=%q status=%d code=%q observed_ip=%q lease_cidr=%q total_ms=%d ssh_ms=%s", routeLabel, status, code, observedIP, leaseCIDR, totalMS, sshMS)
		return
	}
	log.Printf("whitelist-web request label=%q status=%d code=%q observed_ip=%q lease_cidr=%q total_ms=%d ssh_ms=%s error=%q", routeLabel, status, code, observedIP, leaseCIDR, totalMS, sshMS, compactLogDetail(errorDetail, 512))
}

func compactLogDetail(raw string, maxLen int) string {
	detail := strings.Join(strings.Fields(raw), " ")
	if maxLen <= 0 || len(detail) <= maxLen {
		return detail
	}
	return detail[:maxLen] + "..."
}

func (s *server) observedIP(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("remote addr 无效: %w", err)
	}
	peerAddr, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("remote addr 不是 IP: %w", err)
	}
	if isTrustedProxy(peerAddr, s.trustedProxies) {
		if ip := firstForwardedIP(r.Header.Get("X-Real-IP")); ip != "" {
			return ip, nil
		}
		if ip := firstForwardedIP(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip, nil
		}
	}
	return peerAddr.String(), nil
}

func isTrustedProxy(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func firstForwardedIP(raw string) string {
	for _, piece := range strings.Split(raw, ",") {
		candidate := strings.TrimSpace(piece)
		if candidate == "" {
			continue
		}
		addr, err := netip.ParseAddr(candidate)
		if err == nil {
			return addr.String()
		}
	}
	return ""
}

func validateRoutePrefixLen(prefixLen int, maxBits int, field string) error {
	if prefixLen < 0 || prefixLen > maxBits {
		return fmt.Errorf("%s 必须是 0-%d", field, maxBits)
	}
	return nil
}

func leaseCIDRForAddress(observedIP string, route compiledRoute) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(observedIP))
	if err != nil {
		return "", fmt.Errorf("来源 IP 无效: %w", err)
	}
	prefixLen := route.IPv6PrefixLen
	if addr.Is4() {
		prefixLen = route.IPv4PrefixLen
	}
	prefix := netip.PrefixFrom(addr, prefixLen).Masked()
	return prefix.String(), nil
}

func (s *server) pushWhitelistLease(parent context.Context, route compiledRoute, observedIP string, _ string) error {
	timeout := time.Duration(s.cfg.RequestTimeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	args := sshOptionsWithControlMaster(route.RouteConfig.SSHOptions)
	args = append(args, route.RouteConfig.SSHTarget,
		"pfwd", "guard", "whitelist-lease", "add",
		"--address", observedIP,
		"--ipv4-prefix-len", fmt.Sprintf("%d", route.IPv4PrefixLen),
		"--ipv6-prefix-len", fmt.Sprintf("%d", route.IPv6PrefixLen),
		"--idle-ttl", route.IdleTTL,
		"--channel", "web",
		"--note", strings.TrimSpace(route.RouteConfig.Label),
	)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh 下发失败: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func sshOptionsWithControlMaster(options []string) []string {
	args := append([]string{}, options...)
	if sshOptionConfigured(args, "ControlMaster") || sshOptionConfigured(args, "ControlPath") {
		return args
	}
	controlDir := strings.TrimSpace(os.Getenv("PFWD_WHITELIST_WEB_CONTROL_DIR"))
	if controlDir == "" {
		controlDir = filepath.Join(os.TempDir(), "pfwd-whitelist-web-control")
	}
	if err := os.MkdirAll(controlDir, 0700); err != nil {
		// Let ssh fail with a precise ControlPath error if the directory cannot be prepared.
		log.Printf("whitelist-web ssh control dir prepare failed path=%q error=%q", controlDir, err.Error())
	}
	controlPath := filepath.Join(controlDir, "ssh-%C")
	args = append(args,
		"-o", "ControlMaster=auto",
		"-o", "ControlPersist=60s",
		"-o", "ControlPath="+controlPath,
	)
	return args
}

func sshOptionConfigured(options []string, name string) bool {
	prefix := strings.ToLower(name) + "="
	for i := 0; i < len(options); i++ {
		opt := strings.TrimSpace(options[i])
		lower := strings.ToLower(opt)
		switch {
		case lower == "-o":
			if i+1 < len(options) && strings.HasPrefix(strings.ToLower(strings.TrimSpace(options[i+1])), prefix) {
				return true
			}
			i++
		case strings.HasPrefix(lower, "-o"+prefix):
			return true
		case strings.HasPrefix(lower, prefix):
			return true
		}
	}
	return false
}

func (s *server) pushLease(parent context.Context, route compiledRoute, observedIP string, leaseCIDR string) error {
	if s.leasePusher != nil {
		return s.leasePusher(parent, route, observedIP, leaseCIDR)
	}
	return s.pushWhitelistLease(parent, route, observedIP, leaseCIDR)
}

func negotiateResponseFormat(r *http.Request) (responseFormat, error) {
	switch strings.TrimSpace(strings.ToLower(r.URL.Query().Get("format"))) {
	case "":
	case string(formatJSON):
		return formatJSON, nil
	case string(formatHTML):
		return formatHTML, nil
	default:
		return formatJSON, fmt.Errorf("format 仅支持 html 或 json")
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
		return formatHTML, nil
	}
	return formatJSON, nil
}

func successResponse(format responseFormat, route compiledRoute, observedIP string, leaseCIDR string) responseModel {
	payload := responsePayload{
		OK:         true,
		Format:     string(format),
		Label:      route.RouteConfig.Label,
		ObservedIP: observedIP,
		LeaseCIDR:  leaseCIDR,
		IdleTTL:    route.IdleTTL,
	}
	return responseModel{
		Status:      http.StatusOK,
		Format:      format,
		Payload:     payload,
		HTMLTitle:   "临时白名单已生效",
		HTMLSummary: "本次来源 IP 已写入目标机临时白名单，可在时效内直接访问。",
	}
}

func invalidFormatResponse(details string, fallback responseFormat) responseModel {
	return errorResponse(http.StatusBadRequest, fallback, "invalid_format", details, "响应格式无效", "请使用 ?format=json 或 ?format=html。")
}

func methodNotAllowedResponse(format responseFormat) responseModel {
	return errorResponse(http.StatusMethodNotAllowed, format, "method_not_allowed", "method not allowed", "请求方法不受支持", "当前入口仅支持 GET 请求。")
}

func secretNotFoundResponse(format responseFormat) responseModel {
	return errorResponse(http.StatusNotFound, format, "secret_not_found", "secret not found", "链接无效或已失效", "请确认访问的是正确的私密链接。")
}

func clientIPUnavailableResponse(format responseFormat, details string) responseModel {
	return errorResponse(http.StatusBadRequest, format, "client_ip_unavailable", details, "无法识别来源 IP", "请检查直连来源 IP 或反代透传头是否正确。")
}

func internalConfigErrorResponse(format responseFormat, details string) responseModel {
	return errorResponse(http.StatusInternalServerError, format, "internal_config_error", details, "服务端配置无效", "请联系管理员检查临时白名单 Web 配置。")
}

func leasePushFailedResponse(format responseFormat, details string) responseModel {
	summary := "请稍后重试；如果持续失败，请联系管理员排查目标机 SSH 链路。"
	if strings.Contains(strings.ToLower(details), "host key verification failed") {
		summary = "控制机尚未信任目标机 host key；请先补齐 known_hosts 后再重试。"
	}
	return errorResponse(http.StatusBadGateway, format, "lease_push_failed", details, "临时白名单下发失败", summary)
}

func errorResponse(status int, format responseFormat, code string, details string, title string, summary string) responseModel {
	return responseModel{
		Status: status,
		Format: format,
		Payload: responsePayload{
			OK:     false,
			Format: string(format),
			Code:   code,
			Error:  details,
		},
		HTMLTitle:   title,
		HTMLSummary: summary,
	}
}

func writeResponse(w http.ResponseWriter, resp responseModel) {
	if resp.Format == formatHTML {
		writeHTML(w, resp)
		return
	}
	writeJSON(w, resp.Status, resp.Payload)
}

func writeHTML(w http.ResponseWriter, resp responseModel) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(resp.Status)
	_ = htmlPageTemplate.Execute(w, resp)
}

func writeJSON(w http.ResponseWriter, status int, payload responsePayload) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
