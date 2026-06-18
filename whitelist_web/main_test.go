package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func intPtr(value int) *int {
	return &value
}

func newTestServer(t *testing.T, route routeConfig) *server {
	t.Helper()
	srv, err := newServer(config{
		ListenHost:        "127.0.0.1",
		ListenPort:        18080,
		RequestTimeoutSec: 8,
		Routes:            []routeConfig{route},
	})
	if err != nil {
		t.Fatalf("newServer() error = %v", err)
	}
	return srv
}

func decodeJSONResponse(t *testing.T, rec *httptest.ResponseRecorder) responsePayload {
	t.Helper()
	var payload responsePayload
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v, body=%q", err, rec.Body.String())
	}
	return payload
}

func captureLogOutput(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
	}()
	fn()
	return buf.String()
}

func TestLoadConfigDefaultsRequestTimeoutToTenSeconds(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "whitelist-web.json")
	content := `{
		"listen_host": "127.0.0.1",
		"listen_port": 18080,
		"routes": [{
			"secret": "secret",
			"label": "po0-sh",
			"ssh_target": "root@example",
			"idle_ttl": "4h"
		}]
	}`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.RequestTimeoutSec != 10 {
		t.Fatalf("RequestTimeoutSec = %d, want 10", cfg.RequestTimeoutSec)
	}
}

func TestSSHOptionsWithControlMasterAddsDefaults(t *testing.T) {
	controlDir := t.TempDir()
	t.Setenv("PFWD_WHITELIST_WEB_CONTROL_DIR", controlDir)

	got := sshOptionsWithControlMaster([]string{"-i", "/root/.ssh/key", "-o", "BatchMode=yes"})
	joined := strings.Join(got, " ")

	for _, want := range []string{"ControlMaster=auto", "ControlPersist=60s", "ControlPath=" + controlDir} {
		if !strings.Contains(joined, want) {
			t.Fatalf("ssh options missing %q: %v", want, got)
		}
	}
}

func TestSSHOptionsWithControlMasterRespectsExplicitControlPath(t *testing.T) {
	got := sshOptionsWithControlMaster([]string{"-o", "ControlPath=/tmp/custom-%C"})
	joined := strings.Join(got, " ")

	if strings.Contains(joined, "ControlMaster=auto") {
		t.Fatalf("ssh options should not inject control master when ControlPath is explicit: %v", got)
	}
	if !strings.Contains(joined, "ControlPath=/tmp/custom-%C") {
		t.Fatalf("ssh options lost explicit ControlPath: %v", got)
	}
}

func TestServeHTTPSuccessJSONByDefault(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "po0-sh",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string, _ string) error {
		return nil
	}

	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	req.RemoteAddr = "203.0.113.10:42311"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	payload := decodeJSONResponse(t, rec)
	if !payload.OK || payload.Format != "json" || payload.Label != "po0-sh" || payload.ObservedIP != "203.0.113.10" || payload.LeaseCIDR != "203.0.113.10/32" || payload.IdleTTL != "4h" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestServeHTTPSuccessJSONWithConfiguredIPv4Prefix(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:        "secret",
		Label:         "po0-sh",
		SSHTarget:     "root@example",
		IdleTTL:       "4h",
		IPv4PrefixLen: intPtr(24),
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, observedIP string, leaseCIDR string) error {
		if observedIP != "203.0.113.27" || leaseCIDR != "203.0.113.0/24" {
			t.Fatalf("unexpected push args observedIP=%q leaseCIDR=%q", observedIP, leaseCIDR)
		}
		return nil
	}

	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	req.RemoteAddr = "203.0.113.27:42311"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	payload := decodeJSONResponse(t, rec)
	if payload.LeaseCIDR != "203.0.113.0/24" {
		t.Fatalf("LeaseCIDR = %q, want 203.0.113.0/24", payload.LeaseCIDR)
	}
}

func TestServeHTTPHTMLByAccept(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "po0-sh",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string, _ string) error {
		return nil
	}

	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	req.RemoteAddr = "203.0.113.11:42311"
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", got)
	}
	body := rec.Body.String()
	for _, want := range []string{"临时白名单已生效", "po0-sh", "203.0.113.11", "203.0.113.11/32", "4h"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}

func TestServeHTTPQueryFormatOverridesAccept(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "po0-sh",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string, _ string) error {
		return nil
	}

	req := httptest.NewRequest(http.MethodGet, "/secret?format=json", nil)
	req.RemoteAddr = "203.0.113.12:42311"
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	payload := decodeJSONResponse(t, rec)
	if payload.Format != "json" || payload.ObservedIP != "203.0.113.12" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestServeHTTPInvalidFormat(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "po0-sh",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})

	req := httptest.NewRequest(http.MethodGet, "/secret?format=xml", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	payload := decodeJSONResponse(t, rec)
	if payload.Code != "invalid_format" || payload.Format != "json" || payload.OK {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestServeHTTPSecretNotFoundHTML(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "po0-sh",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})

	req := httptest.NewRequest(http.MethodGet, "/missing?format=html", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	body := rec.Body.String()
	for _, want := range []string{"链接无效或已失效", "secret_not_found"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}

func TestServeHTTPLeasePushFailureHTMLHidesRawError(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "po0-sh",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string, _ string) error {
		return errors.New("ssh 下发失败: sensitive backend detail")
	}

	req := httptest.NewRequest(http.MethodGet, "/secret?format=html", nil)
	req.RemoteAddr = "203.0.113.13:42311"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "临时白名单下发失败") {
		t.Fatalf("body missing title: %s", body)
	}
	if strings.Contains(body, "sensitive backend detail") {
		t.Fatalf("body leaked backend detail: %s", body)
	}
}

func TestServeHTTPLeasePushFailureJSONKeepsErrorDetails(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "po0-sh",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string, _ string) error {
		return errors.New("ssh 下发失败: sensitive backend detail")
	}

	req := httptest.NewRequest(http.MethodGet, "/secret?format=json", nil)
	req.RemoteAddr = "203.0.113.14:42311"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	payload := decodeJSONResponse(t, rec)
	if payload.Code != "lease_push_failed" || !strings.Contains(payload.Error, "sensitive backend detail") {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestServeHTTPLeasePushFailureHTMLShowsHostKeyHint(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "po0-sh",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string, _ string) error {
		return errors.New("ssh 下发失败: exit status 255: Host key verification failed.")
	}

	req := httptest.NewRequest(http.MethodGet, "/secret?format=html", nil)
	req.RemoteAddr = "203.0.113.16:42311"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "控制机尚未信任目标机 host key") {
		t.Fatalf("body missing host key hint: %s", body)
	}
}

func TestServeHTTPLogsTimingWithoutSecret(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "very-secret-token",
		Label:     "po0-sh",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string, _ string) error {
		return nil
	}

	req := httptest.NewRequest(http.MethodGet, "/very-secret-token", nil)
	req.RemoteAddr = "203.0.113.17:42311"
	rec := httptest.NewRecorder()

	output := captureLogOutput(t, func() {
		srv.ServeHTTP(rec, req)
	})

	for _, want := range []string{`label="po0-sh"`, "status=200", `code=""`, `observed_ip="203.0.113.17"`, `lease_cidr="203.0.113.17/32"`, "total_ms=", "ssh_ms="} {
		if !strings.Contains(output, want) {
			t.Fatalf("log missing %q: %s", want, output)
		}
	}
	if strings.Contains(output, "very-secret-token") {
		t.Fatalf("log leaked route secret: %s", output)
	}
}

func TestServeHTTPHTMLEscapesLabel(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "<b>unsafe</b>",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string, _ string) error {
		return nil
	}

	req := httptest.NewRequest(http.MethodGet, "/secret?format=html", nil)
	req.RemoteAddr = "203.0.113.15:42311"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "<b>unsafe</b>") {
		t.Fatalf("body did not escape label: %s", body)
	}
	if !strings.Contains(body, "&lt;b&gt;unsafe&lt;/b&gt;") {
		t.Fatalf("body missing escaped label: %s", body)
	}
}
