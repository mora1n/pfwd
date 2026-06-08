package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

func TestServeHTTPSuccessJSONByDefault(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "po0-sh",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string) error {
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
	if !payload.OK || payload.Format != "json" || payload.Label != "po0-sh" || payload.ObservedIP != "203.0.113.10" || payload.IdleTTL != "4h" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestServeHTTPHTMLByAccept(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "po0-sh",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string) error {
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
	for _, want := range []string{"临时白名单已生效", "po0-sh", "203.0.113.11", "4h"} {
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
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string) error {
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
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string) error {
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
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string) error {
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

func TestServeHTTPHTMLEscapesLabel(t *testing.T) {
	srv := newTestServer(t, routeConfig{
		Secret:    "secret",
		Label:     "<b>unsafe</b>",
		SSHTarget: "root@example",
		IdleTTL:   "4h",
	})
	srv.leasePusher = func(_ context.Context, _ compiledRoute, _ string) error {
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
