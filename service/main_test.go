package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOpenDBInitializesSchema(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "pfwd.db"))
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.close()
	version, err := db.schemaVersion(context.Background())
	if err != nil {
		t.Fatalf("schemaVersion: %v", err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version=%q, want %q", version, schemaVersion)
	}
}

func TestDaemonStatusAndReload(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "pfwd.sock")
	dbPath := filepath.Join(dir, "pfwd.db")
	logPath := filepath.Join(dir, "pfwd.log")
	cancel, errCh := startTestDaemon(t, socketPath, dbPath, logPath, 0)
	data, err := socketRequest(http.MethodGet, socketPath, "/v1/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("empty status response")
	}
	if _, err := socketRequest(http.MethodPost, socketPath, "/v1/reload"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	waitForLogCount(t, logPath, "refresh", 2)
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("daemon did not exit")
	}
}

func TestStorePutAndGet(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pfwd.db")
	if err := runStorePut([]string{"--db", dbPath, "--key", "config_json"}, bytes.NewBufferString(`{"ok":true}`)); err != nil {
		t.Fatalf("store put: %v", err)
	}
	db, err := openDB(dbPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.close()
	value, ok, err := db.getRuntimeState(context.Background(), "config_json")
	if err != nil {
		t.Fatalf("getRuntimeState: %v", err)
	}
	if !ok || value != `{"ok":true}` {
		t.Fatalf("stored value ok=%v value=%q", ok, value)
	}
}

func TestSocketStorePutAndGet(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "pfwd.sock")
	dbPath := filepath.Join(dir, "pfwd.db")
	logPath := filepath.Join(dir, "pfwd.log")
	cancel, errCh := startTestDaemon(t, socketPath, dbPath, logPath, 0)
	if err := runStorePut([]string{"--socket", socketPath, "--key", "config_json"}, bytes.NewBufferString(`{"from":"socket"}`)); err != nil {
		t.Fatalf("socket store put: %v", err)
	}
	value, err := socketStoreGet(socketPath, "config_json")
	if err != nil {
		t.Fatalf("socket store get: %v", err)
	}
	if !jsonEqual(value, `{"from":"socket"}`) {
		t.Fatalf("socket value=%q", value)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("daemon did not exit")
	}
}

func TestDaemonRunsBootRefreshAndPeriodicReconcile(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "pfwd.sock")
	dbPath := filepath.Join(dir, "pfwd.db")
	logPath := filepath.Join(dir, "pfwd.log")
	cancel, errCh := startTestDaemon(t, socketPath, dbPath, logPath, 25*time.Millisecond)
	waitForLogCount(t, logPath, "refresh", 1)
	waitForLogCount(t, logPath, "reconcile", 1)
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("daemon did not exit")
	}
}

func startTestDaemon(t *testing.T, socketPath, dbPath, logPath string, reconcileInterval time.Duration) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Serve(ctx, DaemonConfig{
			SocketPath:        socketPath,
			DBPath:            dbPath,
			ReconcileInterval: reconcileInterval,
			CommandRunner: func(_ context.Context, args ...string) (string, error) {
				if len(args) > 0 {
					f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
					if err != nil {
						return "", err
					}
					defer f.Close()
					_, err = fmt.Fprintln(f, args[0])
					return strings.Join(args, " ") + " ok", err
				}
				return "", nil
			},
		})
	}()
	waitForSocket(t, socketPath)
	t.Cleanup(cancel)
	return cancel, errCh
}

func waitForLogCount(t *testing.T, logPath, entry string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(logPath)
		if err == nil && strings.Count(string(data), entry) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	data, _ := os.ReadFile(logPath)
	t.Fatalf("log %s did not contain %d %q entries; got %q", logPath, want, entry, string(data))
}

func jsonEqual(left, right string) bool {
	var leftValue any
	var rightValue any
	if err := json.Unmarshal([]byte(left), &leftValue); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(right), &rightValue); err != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func waitForSocket(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			conn, err := net.Dial("unix", socketPath)
			if err == nil {
				_ = conn.Close()
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket not ready: %s", socketPath)
}
