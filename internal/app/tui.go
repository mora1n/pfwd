package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tuiView int

const (
	tuiHome tuiView = iota
	tuiStatus
	tuiUsers
	tuiForwards
	tuiStats
	tuiRuntime
	tuiDoctor
	tuiInput
	tuiConfirm
)

var (
	tuiTitleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	tuiSelectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("16")).Background(lipgloss.Color("78"))
	tuiHelpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	tuiOKStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	tuiErrStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	tuiWarnStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	tuiLabelStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("36"))
)

type tuiRow struct {
	text   string
	hint   string
	detail string
}

type tuiInputState struct {
	title    string
	help     string
	value    string
	previous tuiView
	submit   func(*tuiModel, string) error
}

type tuiConfirmState struct {
	title    string
	message  string
	help     string
	previous tuiView
	confirm  func(*tuiModel) error
}

type tuiModel struct {
	app     *App
	cfg     Config
	stats   StatsState
	mode    tuiView
	cursor  int
	input   tuiInputState
	confirm tuiConfirmState
	status  string
	err     string
}

func (a *App) runTUI() error {
	store, err := OpenStore(a.Paths.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx := context.Background()
	cfg, err := loadConfig(ctx, store)
	if err != nil {
		return err
	}
	stats, err := loadStats(ctx, store)
	if err != nil {
		return err
	}
	m := tuiModel{app: a, cfg: cfg, stats: stats}
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func (m tuiModel) Init() tea.Cmd { return nil }

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch m.mode {
	case tuiHome:
		return m.updateHome(key)
	case tuiStatus:
		return m.updateStatus(key)
	case tuiUsers:
		return m.updateUsers(key)
	case tuiForwards:
		return m.updateForwards(key)
	case tuiStats:
		return m.updateStats(key)
	case tuiRuntime:
		return m.updateRuntime(key)
	case tuiDoctor:
		return m.updateDoctor(key)
	case tuiInput:
		return m.updateInput(key)
	case tuiConfirm:
		return m.updateConfirm(key)
	default:
		return m, nil
	}
}

func (m tuiModel) View() string {
	switch m.mode {
	case tuiStatus:
		return m.viewStatus()
	case tuiUsers:
		return m.viewUsers()
	case tuiForwards:
		return m.viewForwards()
	case tuiStats:
		return m.viewStats()
	case tuiRuntime:
		return m.viewRuntime()
	case tuiDoctor:
		return m.viewDoctor()
	case tuiInput:
		return m.viewInput()
	case tuiConfirm:
		return m.viewConfirm()
	default:
		return m.viewHome()
	}
}

func (m tuiModel) updateHome(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := tuiShouldQuit(key); quit {
		return m, cmd
	}
	if moved, ok := m.moveCursor(key, 6); ok {
		return moved, nil
	}
	idx, ok := m.choice(key, 6)
	if !ok {
		return m, nil
	}
	m.cursor = 0
	m.status = ""
	m.err = ""
	switch idx {
	case 0:
		m.mode = tuiStatus
	case 1:
		m.mode = tuiUsers
	case 2:
		m.mode = tuiForwards
	case 3:
		m.mode = tuiStats
	case 4:
		m.mode = tuiRuntime
	case 5:
		m.mode = tuiDoctor
	}
	return m, nil
}

func (m tuiModel) viewHome() string {
	rows := []tuiRow{
		{text: "状态", hint: "DB / socket / 规则摘要", detail: "查看 SQLite 运行态和基础对象数量。"},
		{text: "用户", hint: "查看、添加、删除", detail: "管理用户；删除前需要确认。"},
		{text: "转发规则", hint: "查看、添加、启停、删除", detail: "管理常用转发规则，高级字段继续使用 CLI。"},
		{text: "统计", hint: "总量和规则用量", detail: "查看 billing/input/output 统计摘要。"},
		{text: "运行态", hint: "refresh / restart / status", detail: "编译并应用运行态，或查看 render status 摘要。"},
		{text: "诊断", hint: "doctor", detail: "运行 DB 化诊断。"},
	}
	return m.renderRows("pfwd 管理", rows, "↑/↓/k/j 选择 • Enter/l 进入 • 数字选择 • q 退出")
}

func (m tuiModel) updateStatus(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := tuiShouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	if m.enterKey(key) || key.String() == "r" {
		if err := m.reload(); err != nil {
			m.setError(err)
			return m, nil
		}
		m.status = "状态已刷新"
		m.err = ""
	}
	return m, nil
}

func (m tuiModel) viewStatus() string {
	var b strings.Builder
	b.WriteString(tuiTitleStyle.Render("状态") + "\n\n")
	b.WriteString(tuiLabelStyle.Render("DB: ") + m.app.Paths.DBPath + "\n")
	b.WriteString(tuiLabelStyle.Render("Socket: ") + m.app.Paths.SocketPath + "\n")
	b.WriteString(tuiLabelStyle.Render("Users: ") + fmt.Sprint(len(m.cfg.Users)) + "\n")
	b.WriteString(tuiLabelStyle.Render("Forwards: ") + fmt.Sprintf("%d enabled=%d", len(m.cfg.Forwards), countEnabledForwards(m.cfg)) + "\n")
	b.WriteString(tuiLabelStyle.Render("Runtime state: ") + "SQLite DB\n")
	b.WriteString("\n")
	b.WriteString(m.statusLine())
	b.WriteString(tuiHelpStyle.Render("Enter/r 刷新 • h/0/Esc 返回 • q 退出"))
	return b.String()
}

func (m tuiModel) updateUsers(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := tuiShouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	rows := len(sortedUsers(m.cfg)) + 1
	if moved, ok := m.moveCursor(key, rows); ok {
		return moved, nil
	}
	if key.String() == "a" {
		return m.inputPrompt("添加用户", "输入用户名，Enter 保存 • Esc 取消", tuiUsers, func(m *tuiModel, value string) error {
			return m.addUser(value)
		}), nil
	}
	if key.String() == "d" || m.enterKey(key) {
		users := sortedUsers(m.cfg)
		if m.cursor >= len(users) {
			return m.inputPrompt("添加用户", "输入用户名，Enter 保存 • Esc 取消", tuiUsers, func(m *tuiModel, value string) error {
				return m.addUser(value)
			}), nil
		}
		user := users[m.cursor]
		return m.confirmPrompt("删除用户", fmt.Sprintf("确认删除用户 %s？仅无转发规则的用户可删除。", user.ID), "Y 确认 • 其它键取消", tuiUsers, func(m *tuiModel) error {
			return m.deleteUser(user.ID)
		}), nil
	}
	return m, nil
}

func (m tuiModel) viewUsers() string {
	rows := []tuiRow{}
	for _, user := range sortedUsers(m.cfg) {
		rows = append(rows, tuiRow{text: user.ID, hint: userSummary(m.cfg, user.ID), detail: "Enter/d 删除；a 添加用户。"})
	}
	rows = append(rows, tuiRow{text: "添加用户", hint: "输入用户名", detail: "创建用户后可新增转发规则。"})
	return m.renderRows("用户", rows, "a 添加 • Enter/d 删除当前用户 • h/0/Esc 返回 • q 退出")
}

func (m tuiModel) updateForwards(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := tuiShouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	forwards := sortedForwards(m.cfg)
	rows := len(forwards) + 1
	if moved, ok := m.moveCursor(key, rows); ok {
		return moved, nil
	}
	if key.String() == "a" {
		return m.inputPrompt("添加转发", "格式：user remote listen_port [protocol] [comment]，例：alice example.com:443 25001 tcp web", tuiForwards, func(m *tuiModel, value string) error {
			return m.addForward(value)
		}), nil
	}
	if m.cursor >= len(forwards) {
		if m.enterKey(key) {
			return m.inputPrompt("添加转发", "格式：user remote listen_port [protocol] [comment]", tuiForwards, func(m *tuiModel, value string) error {
				return m.addForward(value)
			}), nil
		}
		return m, nil
	}
	fwd := forwards[m.cursor]
	switch key.String() {
	case " ", "enter":
		if err := m.setForwardEnabled(fwd.ID, !fwd.Enabled); err != nil {
			m.setError(err)
			return m, nil
		}
		m.status = fmt.Sprintf("转发状态已更新：%s enabled=%v", fwd.ID, !fwd.Enabled)
		m.err = ""
	case "d":
		return m.confirmPrompt("删除转发", fmt.Sprintf("确认删除转发 %s？", fwd.ID), "Y 确认 • 其它键取消", tuiForwards, func(m *tuiModel) error {
			return m.deleteForward(fwd.ID)
		}), nil
	}
	return m, nil
}

func (m tuiModel) viewForwards() string {
	rows := []tuiRow{}
	for _, fwd := range sortedForwards(m.cfg) {
		state := "off"
		if fwd.Enabled {
			state = "on"
		}
		rows = append(rows, tuiRow{
			text:   fmt.Sprintf("%s  %s:%d -> %s  %s", fwd.ID, fwd.ListenIP, fwd.ListenPort, formatRemote(fwd.RemoteHost, fwd.RemotePort), state),
			hint:   fmt.Sprintf("user=%s proto=%s", fwd.UserID, fwd.Protocol),
			detail: "Space/Enter 启停；d 删除；a 添加。",
		})
	}
	rows = append(rows, tuiRow{text: "添加转发", hint: "user remote listen_port [protocol] [comment]", detail: "高级字段如 SNAT/MSS/限速继续使用 CLI。"})
	return m.renderRows("转发规则", rows, "a 添加 • Space/Enter 启停 • d 删除 • h/0/Esc 返回 • q 退出")
}

func (m tuiModel) updateStats(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := tuiShouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	if key.String() == "r" || m.enterKey(key) {
		if err := m.reload(); err != nil {
			m.setError(err)
			return m, nil
		}
		m.status = "统计已刷新"
		m.err = ""
	}
	return m, nil
}

func (m tuiModel) viewStats() string {
	var total uint64
	rows := []tuiRow{}
	for _, fwd := range sortedForwards(m.cfg) {
		usage := m.stats.Forwards[fwd.ID]
		bytes := usage.InputTotalBytes + usage.OutputTotalBytes
		total += bytes
		rows = append(rows, tuiRow{
			text: fmt.Sprintf("%s  %s", fwd.ID, formatBytes(bytes)),
			hint: fmt.Sprintf("billing=%s in=%s out=%s",
				formatBytes(usage.BillingUsedBytes), formatBytes(usage.InputTotalBytes), formatBytes(usage.OutputTotalBytes)),
			detail: fmt.Sprintf("%s -> %s", fwd.UserID, formatRemote(fwd.RemoteHost, fwd.RemotePort)),
		})
	}
	var b strings.Builder
	b.WriteString(tuiTitleStyle.Render("统计") + "\n\n")
	b.WriteString(tuiLabelStyle.Render("Total: ") + formatBytes(total) + "\n\n")
	b.WriteString(m.renderRowsBody(rows))
	b.WriteString("\n")
	b.WriteString(m.statusLine())
	b.WriteString(tuiHelpStyle.Render("Enter/r 刷新 • h/0/Esc 返回 • q 退出"))
	return b.String()
}

func (m tuiModel) updateRuntime(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := tuiShouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	if moved, ok := m.moveCursor(key, 3); ok {
		return moved, nil
	}
	idx, ok := m.choice(key, 3)
	if !ok {
		return m, nil
	}
	switch idx {
	case 0:
		out, err := m.capture(func() error { return m.app.runRefresh(nil) })
		if err != nil {
			m.setError(err)
			return m, nil
		}
		_ = m.reload()
		m.status = strings.TrimSpace(out)
		m.err = ""
	case 1:
		out, err := m.capture(func() error { return m.app.runRestart(nil) })
		if err != nil {
			m.setError(err)
			return m, nil
		}
		_ = m.reload()
		m.status = strings.TrimSpace(out)
		m.err = ""
	case 2:
		m.status = m.runtimeStatusSummary()
		m.err = ""
	}
	return m, nil
}

func (m tuiModel) viewRuntime() string {
	rows := []tuiRow{
		{text: "refresh", hint: "编译并应用运行态", detail: "等同 pfwd refresh。"},
		{text: "restart", hint: "重新应用运行态", detail: "等同 pfwd restart 当前核心动作。"},
		{text: "status", hint: "查看 runtime_state 摘要", detail: "读取 DB 中的 forwarder/xdp 状态。"},
	}
	return m.renderRows("运行态", rows, "Enter 执行 • h/0/Esc 返回 • q 退出")
}

func (m tuiModel) updateDoctor(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := tuiShouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	if key.String() == "r" || m.enterKey(key) {
		out, err := m.capture(func() error { return m.app.runDoctor(nil) })
		if err != nil {
			m.err = err.Error()
			m.status = out
			return m, nil
		}
		m.status = strings.TrimSpace(out)
		m.err = ""
	}
	return m, nil
}

func (m tuiModel) viewDoctor() string {
	var b strings.Builder
	b.WriteString(tuiTitleStyle.Render("诊断") + "\n\n")
	if m.status == "" {
		b.WriteString(tuiHelpStyle.Render("Enter/r 运行 doctor") + "\n")
	} else {
		b.WriteString(m.status + "\n")
	}
	b.WriteString("\n")
	b.WriteString(m.statusLine())
	b.WriteString(tuiHelpStyle.Render("Enter/r 运行 • h/0/Esc 返回 • q 退出"))
	return b.String()
}

func (m tuiModel) updateInput(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if tuiCancelKey(key) {
		m.mode = m.input.previous
		m.input = tuiInputState{}
		return m, nil
	}
	switch key.Type {
	case tea.KeyEnter:
		value := strings.TrimSpace(m.input.value)
		if err := m.input.submit(&m, value); err != nil {
			m.setError(err)
			return m, nil
		}
		m.mode = m.input.previous
		m.cursor = 0
		m.input = tuiInputState{}
		return m, nil
	case tea.KeyBackspace:
		if len(m.input.value) > 0 {
			m.input.value = m.input.value[:len(m.input.value)-1]
		}
	case tea.KeyRunes:
		m.input.value += string(key.Runes)
	}
	return m, nil
}

func (m tuiModel) viewInput() string {
	var b strings.Builder
	b.WriteString(tuiTitleStyle.Render(m.input.title) + "\n\n")
	b.WriteString(m.input.value + "\n\n")
	b.WriteString(m.statusLine())
	b.WriteString(tuiHelpStyle.Render(m.input.help))
	return b.String()
}

func (m tuiModel) updateConfirm(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.Type == tea.KeyRunes && strings.EqualFold(string(key.Runes), "y") {
		if err := m.confirm.confirm(&m); err != nil {
			m.setError(err)
			return m, nil
		}
		m.mode = m.confirm.previous
		m.cursor = 0
		m.confirm = tuiConfirmState{}
		return m, nil
	}
	m.mode = m.confirm.previous
	m.confirm = tuiConfirmState{}
	return m, nil
}

func (m tuiModel) viewConfirm() string {
	var b strings.Builder
	b.WriteString(tuiTitleStyle.Render(m.confirm.title) + "\n\n")
	b.WriteString(tuiWarnStyle.Render(m.confirm.message) + "\n\n")
	b.WriteString(m.statusLine())
	b.WriteString(tuiHelpStyle.Render(m.confirm.help))
	return b.String()
}

func (m tuiModel) renderRows(title string, rows []tuiRow, help string) string {
	var b strings.Builder
	b.WriteString(tuiTitleStyle.Render(title) + "\n\n")
	b.WriteString(m.renderRowsBody(rows))
	b.WriteString("\n")
	b.WriteString(m.statusLine())
	b.WriteString(tuiHelpStyle.Render(help))
	return b.String()
}

func (m tuiModel) renderRowsBody(rows []tuiRow) string {
	if len(rows) == 0 {
		return tuiHelpStyle.Render("暂无数据") + "\n"
	}
	var b strings.Builder
	for i, row := range rows {
		prefix := "  "
		line := fmt.Sprintf("%s%d. %s", prefix, i+1, row.text)
		if row.hint != "" {
			line += "  " + tuiHelpStyle.Render(row.hint)
		}
		if i == m.cursor {
			line = tuiSelectedStyle.Render(" " + strings.TrimSpace(line) + " ")
		}
		b.WriteString(line + "\n")
		if i == m.cursor && row.detail != "" {
			b.WriteString("    " + tuiHelpStyle.Render(row.detail) + "\n")
		}
	}
	return b.String()
}

func (m tuiModel) statusLine() string {
	if m.err != "" {
		return tuiErrStyle.Render("错误："+m.err) + "\n\n"
	}
	if m.status != "" {
		return tuiOKStyle.Render(m.status) + "\n\n"
	}
	return ""
}

func (m tuiModel) inputPrompt(title, help string, previous tuiView, submit func(*tuiModel, string) error) tuiModel {
	m.mode = tuiInput
	m.input = tuiInputState{title: title, help: help, previous: previous, submit: submit}
	m.status = ""
	m.err = ""
	return m
}

func (m tuiModel) confirmPrompt(title, message, help string, previous tuiView, confirm func(*tuiModel) error) tuiModel {
	m.mode = tuiConfirm
	m.confirm = tuiConfirmState{title: title, message: message, help: help, previous: previous, confirm: confirm}
	m.status = ""
	m.err = ""
	return m
}

func (m tuiModel) goHome() tuiModel {
	m.mode = tuiHome
	m.cursor = 0
	m.status = ""
	m.err = ""
	return m
}

func (m tuiModel) moveCursor(key tea.KeyMsg, total int) (tuiModel, bool) {
	if total <= 0 {
		m.cursor = 0
		return m, false
	}
	switch key.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
		return m, true
	case "down", "j":
		if m.cursor < total-1 {
			m.cursor++
		}
		return m, true
	default:
		return m, false
	}
}

func (m tuiModel) choice(key tea.KeyMsg, total int) (int, bool) {
	if m.enterKey(key) {
		return m.cursor, true
	}
	if key.Type != tea.KeyRunes {
		return 0, false
	}
	n, err := strconv.Atoi(string(key.Runes))
	if err != nil || n < 1 || n > total {
		return 0, false
	}
	return n - 1, true
}

func (m tuiModel) enterKey(key tea.KeyMsg) bool {
	return key.Type == tea.KeyEnter || key.String() == "l"
}

func (m tuiModel) backKey(key tea.KeyMsg) bool {
	return key.String() == "esc" || key.String() == "h" || (key.Type == tea.KeyRunes && string(key.Runes) == "0")
}

func tuiShouldQuit(key tea.KeyMsg) (bool, tea.Cmd) {
	switch key.String() {
	case "q", "ctrl+c":
		return true, tea.Quit
	default:
		return false, nil
	}
}

func tuiCancelKey(key tea.KeyMsg) bool {
	return key.String() == "esc" || key.String() == "ctrl+c"
}

func (m *tuiModel) setError(err error) {
	m.err = err.Error()
	m.status = ""
}

func (m *tuiModel) reload() error {
	return m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		stats, err := loadStats(ctx, store)
		if err != nil {
			return err
		}
		m.cfg = cfg
		m.stats = stats
		return nil
	})
}

func (m *tuiModel) withStore(fn func(context.Context, *Store) error) error {
	store, err := OpenStore(m.app.Paths.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	return fn(context.Background(), store)
}

func (m *tuiModel) addUser(value string) error {
	userID := normalizeUserID(value)
	if err := validateUserID(userID); err != nil {
		return err
	}
	if err := m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		if _, ok := findUser(cfg, userID); ok {
			return fmt.Errorf("用户已存在：%s", userID)
		}
		cfg.Users = append(cfg.Users, User{
			ID:        userID,
			CreatedAt: nowISO(),
			Limits:    Limits{TrafficMode: "two-way"},
		})
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		m.cfg = cfg
		return nil
	}); err != nil {
		return err
	}
	m.status = "用户已添加：" + userID
	m.err = ""
	return nil
}

func (m *tuiModel) deleteUser(id string) error {
	if err := m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findUser(cfg, id)
		if !ok {
			return fmt.Errorf("用户不存在：%s", id)
		}
		for _, fwd := range cfg.Forwards {
			if fwd.UserID == id {
				return fmt.Errorf("用户仍有关联转发：%s", id)
			}
		}
		cfg.Users = append(cfg.Users[:idx], cfg.Users[idx+1:]...)
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		m.cfg = cfg
		return nil
	}); err != nil {
		return err
	}
	m.status = "用户已删除：" + id
	m.err = ""
	return nil
}

func (m *tuiModel) addForward(value string) error {
	fields := strings.Fields(value)
	if len(fields) < 3 {
		return fmt.Errorf("格式：user remote listen_port [protocol] [comment]")
	}
	userID := normalizeUserID(fields[0])
	remoteHost, remotePorts, err := parseHostPortSpec(fields[1])
	if err != nil {
		return err
	}
	if len(remotePorts) != 1 {
		return fmt.Errorf("TUI 添加转发一次只支持一个远端端口")
	}
	listenPort, err := parsePort(fields[2])
	if err != nil {
		return err
	}
	protocol := "tcp_udp"
	if len(fields) >= 4 {
		protocol = fields[3]
	}
	if err := validateProtocol(protocol); err != nil {
		return err
	}
	comment := ""
	if len(fields) >= 5 {
		comment = strings.Join(fields[4:], " ")
	}
	if err := m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		if _, ok := findUser(cfg, userID); !ok {
			return fmt.Errorf("用户不存在：%s", userID)
		}
		for _, existing := range cfg.Forwards {
			if existing.ListenPort == listenPort && protocolsConflict(protocol, existing.Protocol) {
				return fmt.Errorf("监听端口已配置冲突协议：%d", listenPort)
			}
		}
		id, err := randomID("fwd")
		if err != nil {
			return err
		}
		cfg.Forwards = append(cfg.Forwards, Forward{
			ID:           id,
			UserID:       userID,
			ListenIP:     cfg.Settings.DefaultListenIP,
			ListenPort:   listenPort,
			RemoteHost:   remoteHost,
			RemotePort:   remotePorts[0],
			Protocol:     protocol,
			Enabled:      true,
			TrafficMode:  "two-way",
			TrafficRatio: 1,
			Comment:      ptrString(comment),
			Net:          NetConfig{SNATMode: "masquerade"},
			CreatedAt:    nowISO(),
		})
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		if err := m.app.refresh(ctx, store, false); err != nil {
			return err
		}
		m.cfg = cfg
		return nil
	}); err != nil {
		return err
	}
	m.status = "转发已添加"
	m.err = ""
	return nil
}

func (m *tuiModel) setForwardEnabled(id string, enabled bool) error {
	return m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findForward(cfg, id)
		if !ok {
			return fmt.Errorf("转发规则不存在：%s", id)
		}
		cfg.Forwards[idx].Enabled = enabled
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		if err := m.app.refresh(ctx, store, false); err != nil {
			return err
		}
		m.cfg = cfg
		return nil
	})
}

func (m *tuiModel) deleteForward(id string) error {
	if err := m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findForward(cfg, id)
		if !ok {
			return fmt.Errorf("转发规则不存在：%s", id)
		}
		cfg.Forwards = append(cfg.Forwards[:idx], cfg.Forwards[idx+1:]...)
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		if err := m.app.refresh(ctx, store, false); err != nil {
			return err
		}
		m.cfg = cfg
		return nil
	}); err != nil {
		return err
	}
	m.status = "转发已删除：" + id
	m.err = ""
	return nil
}

func (m tuiModel) runtimeStatusSummary() string {
	parts := []string{}
	_ = m.withStore(func(ctx context.Context, store *Store) error {
		for _, key := range []string{keyRuntime, keyForwarderStatus, keyXDPStatus} {
			_, ok, err := store.GetRaw(ctx, key)
			if err != nil {
				return err
			}
			status := "missing"
			if ok {
				status = "present"
			}
			parts = append(parts, key+"="+status)
		}
		return nil
	})
	return strings.Join(parts, " ")
}

func (m tuiModel) capture(fn func() error) (string, error) {
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

func userSummary(cfg Config, userID string) string {
	count := 0
	for _, fwd := range cfg.Forwards {
		if fwd.UserID == userID {
			count++
		}
	}
	return fmt.Sprintf("forwards=%d", count)
}

func countEnabledForwards(cfg Config) int {
	count := 0
	for _, fwd := range cfg.Forwards {
		if fwd.Enabled {
			count++
		}
	}
	return count
}

func formatBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exp := uint64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(div), "KMGTPE"[exp])
}
