package app

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

type telegramCall struct {
	token  string
	chatID string
	text   string
}

func TestDefaultCommandRequiresInteractiveTerminal(t *testing.T) {
	t.Setenv("PFWD_ROOT_PREFIX", t.TempDir())
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = r.Close()
		_ = w.Close()
	})
	os.Stdin = r
	err = Run(nil, BuildInfo{Version: "test"})
	if err == nil {
		t.Fatal("expected non-interactive default command to fail")
	}
	if !strings.Contains(err.Error(), "交互式终端") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTUIHomeShowsKeySections(t *testing.T) {
	m := tuiModel{app: &App{Paths: LoadPaths()}, cfg: defaultConfig(), stats: defaultStats()}
	view := m.View()
	for _, want := range []string{"pfwd 管理", "状态", "用户", "转发规则", "统计", "通知", "运行态", "诊断"} {
		if !strings.Contains(view, want) {
			t.Fatalf("home view missing %q in:\n%s", want, view)
		}
	}
}

func TestTUINavigationKeys(t *testing.T) {
	m := tuiModel{app: &App{Paths: LoadPaths()}, cfg: defaultConfig(), stats: defaultStats()}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	got := next.(tuiModel)
	if got.mode != tuiUsers {
		t.Fatalf("expected users view, got %v", got.mode)
	}
	next, _ = got.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'0'}})
	got = next.(tuiModel)
	if got.mode != tuiHome {
		t.Fatalf("expected home view, got %v", got.mode)
	}
	_, cmd := got.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatal("expected q to return quit command")
	}
}

func TestTUIUserMutationWritesDB(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PFWD_ROOT_PREFIX", root)
	app := &App{Paths: LoadPaths()}
	m := tuiModel{app: app, cfg: defaultConfig(), stats: defaultStats()}
	if err := m.addUser("alice"); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(app.Paths.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg, err := loadConfig(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findUser(cfg, "alice"); !ok {
		t.Fatalf("user not saved: %+v", cfg.Users)
	}
}

func TestTUIForwardWizardAddsAdvancedForward(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PFWD_ROOT_PREFIX", root)
	app := &App{Paths: LoadPaths()}
	m := tuiModel{app: app, cfg: defaultConfig(), stats: defaultStats()}
	if err := m.addUser("alice"); err != nil {
		t.Fatal(err)
	}
	m = m.startAddForwardWizard()
	if m.mode != tuiForwardWizard || m.forwardWizard.step != tuiForwardStepUser {
		t.Fatalf("expected user selection step, got mode=%v step=%v", m.mode, m.forwardWizard.step)
	}
	m = tuiPress(m, tea.KeyEnter)
	if m.forwardWizard.userID != "alice" || m.forwardWizard.step != tuiForwardStepRemote {
		t.Fatalf("expected alice remote step, got user=%q step=%v", m.forwardWizard.userID, m.forwardWizard.step)
	}
	m = tuiType(m, "203.0.113.10:443")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiType(m, "25001")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiRune(m, '2')
	m = tuiType(m, "web")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiRune(m, '2')
	m = tuiType(m, "198.51.100.10")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiRune(m, '3')
	m = tuiType(m, "1360")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiType(m, "100GB")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiType(m, "50Mbps")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	if m.mode != tuiForwards {
		t.Fatalf("expected forwards view after save, got %v err=%q", m.mode, m.err)
	}
	cfg := loadTestConfig(t, app)
	if len(cfg.Forwards) != 1 {
		t.Fatalf("expected one forward, got %+v", cfg.Forwards)
	}
	fwd := cfg.Forwards[0]
	if fwd.UserID != "alice" || fwd.RemoteHost != "203.0.113.10" || fwd.RemotePort != 443 || fwd.ListenPort != 25001 || fwd.Protocol != "tcp" {
		t.Fatalf("unexpected forward core fields: %+v", fwd)
	}
	if fwd.Net.SNATMode != "snat" || fwd.Net.SNATSource == nil || *fwd.Net.SNATSource != "198.51.100.10" {
		t.Fatalf("unexpected snat config: %+v", fwd.Net)
	}
	if fwd.Net.MSSMode == nil || *fwd.Net.MSSMode != "set" || fwd.Net.MSSValue == nil || *fwd.Net.MSSValue != 1360 {
		t.Fatalf("unexpected mss config: %+v", fwd.Net)
	}
	if fwd.Limits.TrafficBytes == nil || *fwd.Limits.TrafficBytes != 100_000_000_000 {
		t.Fatalf("unexpected traffic limit: %+v", fwd.Limits.TrafficBytes)
	}
	if fwd.Limits.Rate == nil || *fwd.Limits.Rate != "50Mbps" {
		t.Fatalf("unexpected rate limit: %+v", fwd.Limits.Rate)
	}
}

func TestTUIForwardWizardEditsAdvancedForward(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PFWD_ROOT_PREFIX", root)
	app := &App{Paths: LoadPaths()}
	m := tuiModel{app: app, cfg: defaultConfig(), stats: defaultStats()}
	if err := m.addUser("alice"); err != nil {
		t.Fatal(err)
	}
	fwd := Forward{
		ID:           "fwd_test",
		UserID:       "alice",
		ListenIP:     "::",
		ListenPort:   25001,
		RemoteHost:   "203.0.113.10",
		RemotePort:   443,
		Protocol:     "tcp",
		Enabled:      true,
		TrafficMode:  "two-way",
		TrafficRatio: 1,
		Comment:      ptrString("old"),
		Net: NetConfig{
			MSSMode:    ptrString("set"),
			MSSValue:   uint16Ptr(1360),
			SNATMode:   "snat",
			SNATSource: ptrString("198.51.100.10"),
		},
		Limits: ForwardLimits{
			TrafficBytes: uint64Ptr(100_000_000_000),
			Rate:         ptrString("50Mbps"),
		},
		CreatedAt: nowISO(),
	}
	if err := saveTestConfig(t, app, func(cfg Config) Config {
		cfg.Forwards = append(cfg.Forwards, fwd)
		return cfg
	}); err != nil {
		t.Fatal(err)
	}
	m.cfg = loadTestConfig(t, app)
	m = m.startEditForwardWizard(fwd)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiClear(m)
	m = tuiType(m, "25002")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiClear(m)
	m = tuiType(m, "updated")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiRune(m, '1')
	m = tuiRune(m, '1')
	m = tuiClear(m)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiClear(m)
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	if m.mode != tuiForwards {
		t.Fatalf("expected forwards view after edit, got %v err=%q", m.mode, m.err)
	}
	cfg := loadTestConfig(t, app)
	if len(cfg.Forwards) != 1 {
		t.Fatalf("expected one forward, got %+v", cfg.Forwards)
	}
	got := cfg.Forwards[0]
	if got.ListenPort != 25002 || got.Comment == nil || *got.Comment != "updated" {
		t.Fatalf("unexpected edited fields: %+v", got)
	}
	if got.Net.SNATMode != "masquerade" || got.Net.SNATSource != nil || got.Net.MSSMode != nil || got.Net.MSSValue != nil {
		t.Fatalf("advanced fields were not cleared: %+v", got.Net)
	}
	if got.Limits.TrafficBytes != nil || got.Limits.Rate != nil {
		t.Fatalf("limits were not cleared: %+v", got.Limits)
	}
}

func TestHelpShowsGroupedRowsAndTelegramCommands(t *testing.T) {
	var out bytes.Buffer
	app := &App{Paths: LoadPaths()}
	app.printHelp(&out)
	text := out.String()
	for _, want := range []string{
		"Telegram 通知：",
		"pfwd notify-send --user-id ID --text TEXT",
		"pfwd user telegram <username>|--all",
		"pfwd tui",
		"配置、统计、运行态和状态都保存在 pfwd.db",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("help output missing %q in:\n%s", want, text)
		}
	}
}

func TestNotifySendUsesConfiguredTelegram(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PFWD_ROOT_PREFIX", root)
	calls := []telegramCall{}
	app := &App{
		Paths: LoadPaths(),
		telegramSender: func(ctx context.Context, token, chatID, text string) error {
			calls = append(calls, telegramCall{token: token, chatID: chatID, text: text})
			return nil
		},
	}
	if err := saveTestConfig(t, app, func(cfg Config) Config {
		cfg.Users = append(cfg.Users, User{
			ID:        "alice",
			CreatedAt: nowISO(),
			Telegram:  TelegramConfig{BotToken: "token-1", ChatID: "chat-1"},
			Limits:    Limits{TrafficMode: "two-way"},
		})
		return cfg
	}); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(func() error {
		return app.run([]string{"notify-send", "--user-id", "alice", "--text", "hello"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Telegram 消息已发送：alice") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if len(calls) != 1 {
		t.Fatalf("expected one telegram call, got %+v", calls)
	}
	if calls[0] != (telegramCall{token: "token-1", chatID: "chat-1", text: "hello"}) {
		t.Fatalf("unexpected telegram call: %+v", calls[0])
	}
}

func TestNotifySendRequiresTextAndConfig(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PFWD_ROOT_PREFIX", root)
	app := &App{Paths: LoadPaths()}
	if err := saveTestConfig(t, app, func(cfg Config) Config {
		cfg.Users = append(cfg.Users, User{ID: "alice", CreatedAt: nowISO(), Limits: Limits{TrafficMode: "two-way"}})
		return cfg
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.run([]string{"notify-send", "--user-id", "alice"}); err == nil || !strings.Contains(err.Error(), "--text") {
		t.Fatalf("expected missing text error, got %v", err)
	}
	if err := app.run([]string{"notify-send", "--user-id", "alice", "--text", "hello"}); err == nil || !strings.Contains(err.Error(), "未配置 Telegram") {
		t.Fatalf("expected missing telegram config error, got %v", err)
	}
}

func TestTUINotifyConfigureScheduleAndSend(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PFWD_ROOT_PREFIX", root)
	calls := []telegramCall{}
	app := &App{
		Paths: LoadPaths(),
		telegramSender: func(ctx context.Context, token, chatID, text string) error {
			calls = append(calls, telegramCall{token: token, chatID: chatID, text: text})
			return nil
		},
	}
	m := tuiModel{app: app, cfg: defaultConfig(), stats: defaultStats()}
	if err := m.addUser("alice"); err != nil {
		t.Fatal(err)
	}
	m.mode = tuiNotify
	m = m.startNotifyConfigure(m.cfg.Users[0])
	m = tuiType(m, "token-1")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiType(m, "chat-1")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiClear(m)
	m = tuiType(m, "server-1")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiPress(m, tea.KeyEnter)
	if m.mode != tuiNotify {
		t.Fatalf("expected notify view after config, got %v err=%q", m.mode, m.err)
	}
	cfg := loadTestConfig(t, app)
	tg := cfg.Users[0].Telegram
	if tg.BotToken != "token-1" || tg.ChatID != "chat-1" || tg.ServerName != "server-1" || !tg.Enabled {
		t.Fatalf("unexpected telegram config: %+v", tg)
	}

	m.cfg = cfg
	m = m.startNotifySchedule(cfg.Users[0])
	m = tuiType(m, "30")
	m = tuiPress(m, tea.KeyEnter)
	m = tuiType(m, "09:15")
	m = tuiPress(m, tea.KeyEnter)
	cfg = loadTestConfig(t, app)
	tg = cfg.Users[0].Telegram
	if tg.ScheduleIntervalMinutes == nil || *tg.ScheduleIntervalMinutes != 30 || tg.ScheduleDailyTime == nil || *tg.ScheduleDailyTime != "09:15" {
		t.Fatalf("unexpected telegram schedule: %+v", tg)
	}

	m.cfg = cfg
	m = m.startNotifySend(cfg.Users[0])
	m = tuiType(m, "hello from tui")
	m = tuiPress(m, tea.KeyEnter)
	if m.mode != tuiNotify {
		t.Fatalf("expected notify view after send, got %v err=%q", m.mode, m.err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected one telegram call, got %+v", calls)
	}
	if calls[0] != (telegramCall{token: "token-1", chatID: "chat-1", text: "hello from tui"}) {
		t.Fatalf("unexpected telegram call: %+v", calls[0])
	}
}

func TestRefreshUsesNonJSONRuntimeKeys(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PFWD_ROOT_PREFIX", root)
	app := &App{Paths: LoadPaths()}
	if err := saveTestConfig(t, app, func(cfg Config) Config {
		cfg.Users = append(cfg.Users, User{ID: "alice", CreatedAt: nowISO(), Limits: Limits{TrafficMode: "two-way"}})
		cfg.Forwards = append(cfg.Forwards, Forward{
			ID:           "fwd_test",
			UserID:       "alice",
			ListenIP:     "::",
			ListenPort:   25001,
			RemoteHost:   "203.0.113.10",
			RemotePort:   443,
			Protocol:     "tcp",
			Enabled:      true,
			TrafficMode:  "two-way",
			TrafficRatio: 1,
			Net:          NetConfig{SNATMode: "masquerade"},
			CreatedAt:    nowISO(),
		})
		return cfg
	}); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(app.Paths.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := app.refresh(context.Background(), store, false); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{keyRuntime, keyRuntimeXDP, keyRuntimeNFT, keyForwarderStatus} {
		if _, ok, err := store.GetRaw(context.Background(), key); err != nil || !ok {
			t.Fatalf("expected new key %q present, ok=%v err=%v", key, ok, err)
		}
	}
	for _, oldKey := range []string{"runtime_json", "runtime_xdp_json", "runtime_nft_json", "forwarder_status_json", "xdp_status_json"} {
		if _, ok, err := store.GetRaw(context.Background(), oldKey); err != nil || ok {
			t.Fatalf("old key %q should be absent, ok=%v err=%v", oldKey, ok, err)
		}
	}
}

func TestDoctorUsesDBRuntimeStateOnly(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PFWD_ROOT_PREFIX", root)
	app := &App{Build: BuildInfo{Version: "test"}, Paths: LoadPaths()}
	runDir := filepath.Join(root, "run", "pfwd")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "legacy.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(func() error {
		return app.runDoctor(nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "run_json") {
		t.Fatalf("doctor should not mention run_json:\n%s", out)
	}
	for _, oldName := range []string{"runtime_json", "runtime_xdp_json", "runtime_nft_json", "forwarder_status_json", "xdp_status_json"} {
		if strings.Contains(out, oldName) {
			t.Fatalf("doctor should not mention old runtime key %q:\n%s", oldName, out)
		}
	}
	for _, want := range []string{"runtime_state: db", "config: present", "stats: present"} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q in:\n%s", want, out)
		}
	}
}

func tuiType(m tuiModel, value string) tuiModel {
	for _, r := range value {
		m = tuiRune(m, r)
	}
	return m
}

func tuiRune(m tuiModel, r rune) tuiModel {
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	return next.(tuiModel)
}

func tuiPress(m tuiModel, key tea.KeyType) tuiModel {
	next, _ := m.Update(tea.KeyMsg{Type: key})
	return next.(tuiModel)
}

func tuiClear(m tuiModel) tuiModel {
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	return next.(tuiModel)
}

func loadTestConfig(t *testing.T, app *App) Config {
	t.Helper()
	store, err := OpenStore(app.Paths.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg, err := loadConfig(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func saveTestConfig(t *testing.T, app *App, mutate func(Config) Config) error {
	t.Helper()
	store, err := OpenStore(app.Paths.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	cfg, err := loadConfig(context.Background(), store)
	if err != nil {
		return err
	}
	cfg = mutate(cfg)
	return saveConfig(context.Background(), store, cfg)
}

func uint16Ptr(value uint16) *uint16 {
	return &value
}

func uint64Ptr(value uint64) *uint64 {
	return &value
}

func captureStdout(fn func() error) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	err = fn()
	_ = w.Close()
	os.Stdout = old
	var b bytes.Buffer
	_, _ = io.Copy(&b, r)
	_ = r.Close()
	return b.String(), err
}
