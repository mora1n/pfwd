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
	for _, want := range []string{"pfwd 管理", "状态", "用户", "转发规则", "统计", "运行态", "诊断"} {
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
	for _, want := range []string{"runtime_state: db", "config_json: present", "stats_json: present"} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q in:\n%s", want, out)
		}
	}
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
