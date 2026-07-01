package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultDBPath            = "/var/lib/pfwd/sqlite.db"
	defaultSocketPath        = "/run/pfwd/pfwd.sock"
	defaultPFWDBinPath       = "/usr/local/bin/pfwd"
	defaultReconcileInterval = 60 * time.Second
	schemaVersion            = "1"
)

type dbHandle struct {
	sql *sql.DB
}

type componentStatus struct {
	State     string `json:"state"`
	Message   string `json:"message,omitempty"`
	Error     string `json:"error,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

type daemonStatus struct {
	OK            bool                       `json:"ok"`
	StartedAt     string                     `json:"started_at"`
	ReloadedAt    string                     `json:"reloaded_at,omitempty"`
	DBPath        string                     `json:"db_path"`
	SocketPath    string                     `json:"socket_path"`
	PFWDBin       string                     `json:"pfwd_bin"`
	SchemaVersion string                     `json:"schema_version"`
	Components    map[string]componentStatus `json:"components"`
}

type daemonConfig struct {
	SocketPath        string
	DBPath            string
	PFWDBin           string
	ReconcileInterval time.Duration
}

type server struct {
	socketPath        string
	dbPath            string
	pfwdBin           string
	reconcileInterval time.Duration
	startedAt         string

	mu        sync.Mutex
	status    daemonStatus
	reloadMu  sync.Mutex
	commandMu sync.Mutex
}

type storeRequest struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value,omitempty"`
}

type storeResponse struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "help"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "daemon":
		return runDaemon(args)
	case "status":
		return runStatus(args)
	case "reload":
		return runReload(args)
	case "store":
		return runStore(args)
	case "version":
		fmt.Println("pfwd-service 0.1.0")
		return nil
	case "help", "-h", "--help":
		printHelp()
		return nil
	default:
		return fmt.Errorf("未知命令：%s", cmd)
	}
}

func runStore(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("store 缺少子命令")
	}
	cmd := args[0]
	args = args[1:]
	switch cmd {
	case "get":
		return runStoreGet(args)
	case "put":
		return runStorePut(args, os.Stdin)
	default:
		return fmt.Errorf("未知 store 子命令：%s", cmd)
	}
}

func runStoreGet(args []string) error {
	fs := flag.NewFlagSet("store get", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDBPath, "SQLite DB path")
	socketPath := fs.String("socket", "", "Unix socket path")
	key := fs.String("key", "", "runtime state key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("store get 不接受额外参数")
	}
	if strings.TrimSpace(*key) == "" {
		return fmt.Errorf("store get 缺少 --key")
	}
	if strings.TrimSpace(*socketPath) != "" {
		value, err := socketStoreGet(*socketPath, *key)
		if err != nil {
			return err
		}
		fmt.Println(value)
		return nil
	}
	db, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.close()
	value, ok, err := db.getRuntimeState(context.Background(), *key)
	if err != nil {
		return err
	}
	if !ok {
		return os.ErrNotExist
	}
	fmt.Println(value)
	return nil
}

func runStorePut(args []string, reader io.Reader) error {
	fs := flag.NewFlagSet("store put", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDBPath, "SQLite DB path")
	socketPath := fs.String("socket", "", "Unix socket path")
	key := fs.String("key", "", "runtime state key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("store put 不接受额外参数")
	}
	if strings.TrimSpace(*key) == "" {
		return fmt.Errorf("store put 缺少 --key")
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	value := strings.TrimRight(string(data), "\n")
	if !json.Valid([]byte(value)) {
		return fmt.Errorf("store put 需要 JSON 输入")
	}
	if strings.TrimSpace(*socketPath) != "" {
		return socketStorePut(*socketPath, *key, value)
	}
	db, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.close()
	return db.putRuntimeState(context.Background(), *key, value)
}

func printHelp() {
	fmt.Println(`pfwd-service

用法：
  pfwd-service daemon [--socket PATH] [--db PATH] [--pfwd-bin PATH]
  pfwd-service status [--socket PATH]
  pfwd-service reload [--socket PATH]
  pfwd-service store get [--socket PATH|--db PATH] --key KEY
  pfwd-service store put [--socket PATH|--db PATH] --key KEY
  pfwd-service version`)
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	socketPath := fs.String("socket", defaultSocketPath, "Unix socket path")
	dbPath := fs.String("db", defaultDBPath, "SQLite DB path")
	pfwdBin := fs.String("pfwd-bin", defaultPFWDBinPath, "pfwd shell entrypoint path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, daemonConfig{
		SocketPath:        *socketPath,
		DBPath:            *dbPath,
		PFWDBin:           *pfwdBin,
		ReconcileInterval: defaultReconcileInterval,
	})
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	socketPath := fs.String("socket", defaultSocketPath, "Unix socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	data, err := socketRequest(http.MethodGet, *socketPath, "/v1/status")
	if err != nil {
		return err
	}
	var status daemonStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return err
	}
	fmt.Printf("daemon_ok: %v\n", status.OK)
	fmt.Printf("started_at: %s\n", status.StartedAt)
	fmt.Printf("reloaded_at: %s\n", status.ReloadedAt)
	fmt.Printf("db: %s\n", status.DBPath)
	fmt.Printf("socket: %s\n", status.SocketPath)
	fmt.Printf("pfwd_bin: %s\n", status.PFWDBin)
	fmt.Printf("schema_version: %s\n", status.SchemaVersion)
	for _, name := range []string{"sqlite", "runtime", "reconcile"} {
		c, ok := status.Components[name]
		if !ok {
			continue
		}
		line := fmt.Sprintf("%s: %s", name, c.State)
		if c.Message != "" {
			line += " (" + c.Message + ")"
		}
		if c.Error != "" {
			line += " error=" + c.Error
		}
		fmt.Println(line)
	}
	return nil
}

func runReload(args []string) error {
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	socketPath := fs.String("socket", defaultSocketPath, "Unix socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := socketRequest(http.MethodPost, *socketPath, "/v1/reload"); err != nil {
		return err
	}
	fmt.Println("daemon reloaded")
	return nil
}

func serve(ctx context.Context, cfg daemonConfig) error {
	cfg = normalizeDaemonConfig(cfg)
	s := newServer(cfg)
	if err := s.reload(); err != nil {
		return err
	}
	ln, err := listenUnix(cfg.SocketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(cfg.SocketPath)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/reload", s.handleReload)
	mux.HandleFunc("/v1/store/get", s.handleStoreGet)
	mux.HandleFunc("/v1/store/put", s.handleStorePut)
	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := httpSrv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	go func() {
		_ = s.runPFWDCommand(ctx, "runtime", "refresh")
	}()
	if cfg.ReconcileInterval > 0 {
		go s.runReconcileLoop(ctx)
	}
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		return <-errCh
	case err := <-errCh:
		return err
	}
}

func normalizeDaemonConfig(cfg daemonConfig) daemonConfig {
	if strings.TrimSpace(cfg.SocketPath) == "" {
		cfg.SocketPath = defaultSocketPath
	}
	if strings.TrimSpace(cfg.DBPath) == "" {
		cfg.DBPath = defaultDBPath
	}
	if strings.TrimSpace(cfg.PFWDBin) == "" {
		cfg.PFWDBin = defaultPFWDBinPath
	}
	return cfg
}

func newServer(cfg daemonConfig) *server {
	startedAt := nowISO()
	return &server{
		socketPath:        cfg.SocketPath,
		dbPath:            cfg.DBPath,
		pfwdBin:           cfg.PFWDBin,
		reconcileInterval: cfg.ReconcileInterval,
		startedAt:         startedAt,
		status: daemonStatus{
			OK:         true,
			StartedAt:  startedAt,
			DBPath:     cfg.DBPath,
			SocketPath: cfg.SocketPath,
			PFWDBin:    cfg.PFWDBin,
			Components: map[string]componentStatus{
				"sqlite":    component("starting", "initializing sqlite", nil),
				"runtime":   component("pending", "startup refresh pending", nil),
				"reconcile": component("idle", "periodic reconcile pending", nil),
			},
		},
	}
}

func (s *server) reload() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	db, err := openDB(s.dbPath)
	if err != nil {
		s.updateComponent("sqlite", component("error", "", err))
		return err
	}
	defer db.close()
	version, err := db.schemaVersion(context.Background())
	if err != nil {
		s.updateComponent("sqlite", component("error", "", err))
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.ReloadedAt = nowISO()
	s.status.DBPath = s.dbPath
	s.status.SocketPath = s.socketPath
	s.status.PFWDBin = s.pfwdBin
	s.status.SchemaVersion = version
	if s.status.Components == nil {
		s.status.Components = make(map[string]componentStatus)
	}
	s.status.Components["sqlite"] = component("running", "schema_version="+version, nil)
	s.recomputeOKLocked()
	return nil
}

func (s *server) updateComponent(name string, status componentStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.Components == nil {
		s.status.Components = make(map[string]componentStatus)
	}
	s.status.Components[name] = status
	s.recomputeOKLocked()
}

func (s *server) recomputeOKLocked() {
	ok := true
	for _, c := range s.status.Components {
		if c.State == "error" {
			ok = false
			break
		}
	}
	s.status.OK = ok
}

func (s *server) snapshot() daemonStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	components := make(map[string]componentStatus, len(s.status.Components))
	for k, v := range s.status.Components {
		components[k] = v
	}
	out := s.status
	out.Components = components
	return out
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]bool{"ok": s.snapshot().OK})
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.snapshot())
}

func (s *server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.reload(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.runPFWDCommand(r.Context(), "runtime", "refresh"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, s.snapshot())
}

func (s *server) runReconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(s.reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.runPFWDCommand(ctx, "reconcile", "reconcile")
		}
	}
}

func (s *server) runPFWDCommand(ctx context.Context, componentName string, args ...string) error {
	if strings.TrimSpace(s.pfwdBin) == "" {
		err := errors.New("pfwd-bin 为空")
		s.updateComponent(componentName, component("error", "", err))
		return err
	}
	commandLabel := "pfwd " + strings.Join(args, " ")
	s.commandMu.Lock()
	defer s.commandMu.Unlock()
	s.updateComponent(componentName, component("running", commandLabel, nil))
	cmd := exec.CommandContext(ctx, s.pfwdBin, args...)
	cmd.Env = append(os.Environ(),
		"PFWD_SERVICE_SOCKET="+s.socketPath,
		"PFWD_DB_FILE="+s.dbPath,
	)
	output, err := cmd.CombinedOutput()
	message := strings.TrimSpace(string(output))
	if err != nil {
		if message != "" {
			err = fmt.Errorf("%w: %s", err, message)
		}
		s.updateComponent(componentName, component("error", commandLabel, err))
		return err
	}
	if message == "" {
		message = commandLabel + " ok"
	}
	s.updateComponent(componentName, component("ok", message, nil))
	return nil
}

func (s *server) handleStoreGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req storeRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.Key)
	if key == "" {
		http.Error(w, "store get 缺少 key", http.StatusBadRequest)
		return
	}
	db, err := openDB(s.dbPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.close()
	value, ok, err := db.getRuntimeState(r.Context(), key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, storeResponse{Key: key, Value: json.RawMessage(value)})
}

func (s *server) handleStorePut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req storeRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.Key)
	if key == "" {
		http.Error(w, "store put 缺少 key", http.StatusBadRequest)
		return
	}
	if len(req.Value) == 0 || !json.Valid(req.Value) {
		http.Error(w, "store put 需要 JSON value", http.StatusBadRequest)
		return
	}
	db, err := openDB(s.dbPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.close()
	if err := db.putRuntimeState(r.Context(), key, string(req.Value)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func openDB(path string) (*dbHandle, error) {
	if strings.TrimSpace(path) == "" {
		path = defaultDBPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("创建 DB 目录失败: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	out := &dbHandle{sql: db}
	if err := out.init(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return out, nil
}

func (db *dbHandle) close() error {
	return db.sql.Close()
}

func (db *dbHandle) init(ctx context.Context) error {
	stmts := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS forwards(id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS traffic_state(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS runtime_state(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', '` + schemaVersion + `')`,
	}
	for _, stmt := range stmts {
		if _, err := db.sql.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (db *dbHandle) schemaVersion(ctx context.Context) (string, error) {
	var version string
	if err := db.sql.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&version); err != nil {
		return "", err
	}
	return version, nil
}

func (db *dbHandle) getRuntimeState(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := db.sql.QueryRowContext(ctx, `SELECT value FROM runtime_state WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (db *dbHandle) putRuntimeState(ctx context.Context, key, value string) error {
	_, err := db.sql.ExecContext(
		ctx,
		`INSERT INTO runtime_state(key, value, updated_at) VALUES(?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key,
		value,
		nowISO(),
	)
	return err
}

func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("创建 socket 目录失败: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("移除旧 socket 失败: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("设置 socket 权限失败: %w", err)
	}
	return ln, nil
}

func socketRequest(method, socketPath, apiPath string) ([]byte, error) {
	return socketRequestWithBody(method, socketPath, apiPath, nil)
}

func socketRequestWithBody(method, socketPath, apiPath string, body []byte) ([]byte, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://pfwd"+apiPath, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接 pfwd daemon 失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if len(data) == 0 {
			return nil, fmt.Errorf("daemon HTTP %d", resp.StatusCode)
		}
		return nil, errors.New(strings.TrimSpace(string(data)))
	}
	return data, nil
}

func socketStoreGet(socketPath, key string) (string, error) {
	request, err := json.Marshal(storeRequest{Key: key})
	if err != nil {
		return "", err
	}
	data, err := socketRequestWithBody(http.MethodPost, socketPath, "/v1/store/get", request)
	if err != nil {
		return "", err
	}
	var resp storeResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", err
	}
	if !json.Valid(resp.Value) {
		return "", fmt.Errorf("daemon store 返回非 JSON value")
	}
	return string(resp.Value), nil
}

func socketStorePut(socketPath, key, value string) error {
	if !json.Valid([]byte(value)) {
		return fmt.Errorf("store put 需要 JSON 输入")
	}
	request, err := json.Marshal(storeRequest{Key: key, Value: json.RawMessage(value)})
	if err != nil {
		return err
	}
	_, err = socketRequestWithBody(http.MethodPost, socketPath, "/v1/store/put", request)
	return err
}

func decodeJSONBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 32<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("无效 JSON 请求: %w", err)
	}
	return nil
}

func component(state, message string, err error) componentStatus {
	status := componentStatus{
		State:     state,
		Message:   message,
		UpdatedAt: nowISO(),
	}
	if err != nil {
		status.Error = err.Error()
	}
	return status
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}
