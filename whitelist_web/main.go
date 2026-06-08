package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

type routeConfig struct {
	Secret     string   `json:"secret"`
	Label      string   `json:"label"`
	SSHTarget  string   `json:"ssh_target"`
	IdleTTL    string   `json:"idle_ttl"`
	SSHOptions []string `json:"ssh_options"`
}

type config struct {
	ListenHost        string        `json:"listen_host"`
	ListenPort        int           `json:"listen_port"`
	TrustedProxyCIDRs []string      `json:"trusted_proxy_cidrs"`
	RequestTimeoutSec int           `json:"request_timeout_sec"`
	Routes            []routeConfig `json:"routes"`
}

type compiledRoute struct {
	RouteConfig routeConfig
	IdleTTL     string
}

type server struct {
	cfg            config
	routes         map[string]compiledRoute
	trustedProxies []netip.Prefix
}

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
		cfg.RequestTimeoutSec = 8
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
		routes[route.Secret] = compiledRoute{
			RouteConfig: route,
			IdleTTL:     strings.TrimSpace(route.IdleTTL),
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
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	secret := strings.Trim(strings.TrimSpace(r.URL.Path), "/")
	route, ok := s.routes[secret]
	if !ok {
		http.NotFound(w, r)
		return
	}
	observedIP, err := s.observedIP(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.pushWhitelistLease(r.Context(), route, observedIP); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"label":       route.RouteConfig.Label,
		"observed_ip": observedIP,
	})
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

func (s *server) pushWhitelistLease(parent context.Context, route compiledRoute, observedIP string) error {
	timeout := time.Duration(s.cfg.RequestTimeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	args := append([]string{}, route.RouteConfig.SSHOptions...)
	args = append(args, route.RouteConfig.SSHTarget,
		"pfwd", "guard", "whitelist-lease", "add",
		"--address", observedIP,
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

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
