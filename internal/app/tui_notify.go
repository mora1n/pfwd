package app

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func (m tuiModel) updateNotify(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := tuiShouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	users := sortedUsers(m.cfg)
	if len(users) == 0 {
		if key.String() == "a" || m.enterKey(key) {
			return m.inputPrompt("添加用户", "输入用户名，Enter 保存 • Esc 取消", tuiNotify, func(m *tuiModel, value string) error {
				return m.addUser(value)
			}), nil
		}
		return m, nil
	}
	if moved, ok := m.moveCursor(key, len(users)); ok {
		return moved, nil
	}
	user := users[m.cursor]
	switch key.String() {
	case "c", "enter":
		return m.startNotifyConfigure(user), nil
	case "e", " ":
		if err := m.setNotifyEnabled(user.ID, !user.Telegram.Enabled); err != nil {
			m.setError(err)
			return m, nil
		}
	case "s":
		return m.startNotifySend(user), nil
	case "t":
		if err := m.sendNotifyTest(user.ID); err != nil {
			m.setError(err)
			return m, nil
		}
	case "p":
		return m.startNotifySchedule(user), nil
	case "d":
		return m.confirmPrompt("删除 Telegram 配置", fmt.Sprintf("确认删除用户 %s 的 Telegram 配置？", user.ID), "Y 确认 • 其它键取消", tuiNotify, func(m *tuiModel) error {
			return m.deleteNotifyConfig(user.ID)
		}), nil
	}
	return m, nil
}

func (m tuiModel) viewNotify() string {
	rows := []tuiRow{}
	for _, user := range sortedUsers(m.cfg) {
		rows = append(rows, tuiRow{
			text:   user.ID,
			hint:   notifySummary(user.Telegram),
			detail: "Enter/c 配置；e 启停；s 发送；t 测试；p 计划；d 删除配置。",
		})
	}
	if len(rows) == 0 {
		rows = append(rows, tuiRow{text: "添加用户", hint: "通知配置需要先有用户", detail: "按 a 或 Enter 创建用户。"})
	}
	return m.renderRows("通知", rows, "c 配置 • e 启停 • s 发送 • t 测试 • p 计划 • d 删除 • h/0/Esc 返回 • q 退出")
}

func (m tuiModel) startNotifyConfigure(user User) tuiModel {
	host := user.Telegram.ServerName
	if host == "" {
		if value, err := os.Hostname(); err == nil {
			host = value
		} else {
			host = "pfwd"
		}
	}
	enabled := user.Telegram.Enabled
	if user.Telegram.BotToken == "" && user.Telegram.ChatID == "" {
		enabled = true
	}
	m.mode = tuiNotifyWizard
	m.cursor = 0
	m.status = ""
	m.err = ""
	m.notifyWizard = tuiNotifyWizardState{
		kind:       tuiNotifyConfigure,
		step:       tuiNotifyStepToken,
		userID:     user.ID,
		botToken:   user.Telegram.BotToken,
		chatID:     user.Telegram.ChatID,
		serverName: host,
		enabled:    enabled,
	}
	return m.setNotifyWizardStep(tuiNotifyStepToken)
}

func (m tuiModel) startNotifySchedule(user User) tuiModel {
	interval := ""
	if user.Telegram.ScheduleIntervalMinutes != nil {
		interval = strconv.Itoa(*user.Telegram.ScheduleIntervalMinutes)
	}
	daily := ""
	if user.Telegram.ScheduleDailyTime != nil {
		daily = *user.Telegram.ScheduleDailyTime
	}
	m.mode = tuiNotifyWizard
	m.cursor = 0
	m.status = ""
	m.err = ""
	m.notifyWizard = tuiNotifyWizardState{
		kind:     tuiNotifySchedule,
		step:     tuiNotifyStepInterval,
		userID:   user.ID,
		interval: interval,
		daily:    daily,
	}
	return m.setNotifyWizardStep(tuiNotifyStepInterval)
}

func (m tuiModel) startNotifySend(user User) tuiModel {
	m.mode = tuiNotifyWizard
	m.cursor = 0
	m.status = ""
	m.err = ""
	m.notifyWizard = tuiNotifyWizardState{
		kind:   tuiNotifySend,
		step:   tuiNotifyStepMessage,
		userID: user.ID,
	}
	return m.setNotifyWizardStep(tuiNotifyStepMessage)
}

func (m tuiModel) updateNotifyWizard(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if tuiCancelKey(key) {
		return m.cancelNotifyWizard(), nil
	}
	if m.notifyWizard.step == tuiNotifyStepEnabled {
		if quit, cmd := tuiShouldQuit(key); quit {
			return m, cmd
		}
		return m.updateNotifyWizardChoice(key), nil
	}
	switch key.String() {
	case "enter":
		if err := m.submitNotifyWizardInput(); err != nil {
			m.setError(err)
			return m, nil
		}
		return m.nextNotifyWizardStep(), nil
	case "backspace", "ctrl+h":
		if len(m.notifyWizard.value) > 0 {
			runes := []rune(m.notifyWizard.value)
			m.notifyWizard.value = string(runes[:len(runes)-1])
		}
		return m, nil
	case "ctrl+u":
		m.notifyWizard.value = ""
		return m, nil
	case " ":
		m.notifyWizard.value += " "
		return m, nil
	}
	if key.Type == tea.KeyRunes {
		m.notifyWizard.value += string(key.Runes)
	}
	return m, nil
}

func (m tuiModel) updateNotifyWizardChoice(key tea.KeyMsg) tea.Model {
	if key.String() == "h" || key.String() == "0" {
		return m.previousNotifyWizardStep()
	}
	if moved, ok := m.moveCursor(key, 2); ok {
		return moved
	}
	idx, ok := m.choice(key, 2)
	if !ok {
		return m
	}
	m.notifyWizard.enabled = idx == 0
	return m.nextNotifyWizardStep()
}

func (m tuiModel) viewNotifyWizard() string {
	var b strings.Builder
	b.WriteString(tuiTitleStyle.Render(m.notifyWizardTitle()) + "\n")
	b.WriteString(tuiHelpStyle.Render(m.notifyWizardProgress()) + "\n\n")
	if m.notifyWizard.step == tuiNotifyStepEnabled {
		rows := []tuiRow{
			{text: "enabled=true", hint: "启用通知", detail: "保存后允许计划通知发送。"},
			{text: "enabled=false", hint: "停用通知", detail: "保留 token/chat id，但停用计划通知。"},
		}
		b.WriteString(m.renderRowsBody(rows))
		b.WriteString("\n")
		b.WriteString(m.statusLine())
		b.WriteString(tuiHelpStyle.Render("↑/↓/k/j 选择 • Enter/l 确认 • h/0 返回 • Esc 取消 • q 退出"))
		return b.String()
	}
	title, help := notifyWizardInputPrompt(m.notifyWizard.step)
	b.WriteString(tuiLabelStyle.Render(title) + "\n\n")
	if m.notifyWizard.value == "" {
		b.WriteString(tuiHelpStyle.Render("（空）") + "\n\n")
	} else if m.notifyWizard.step == tuiNotifyStepToken {
		b.WriteString(maskTelegramToken(m.notifyWizard.value) + "\n\n")
	} else {
		b.WriteString(m.notifyWizard.value + "\n\n")
	}
	b.WriteString(m.notifyWizardMiniSummary())
	b.WriteString("\n")
	b.WriteString(m.statusLine())
	b.WriteString(tuiHelpStyle.Render(help + " • Enter 下一步 • Ctrl+U 清空 • Esc 取消"))
	return b.String()
}

func (m tuiModel) notifyWizardTitle() string {
	switch m.notifyWizard.kind {
	case tuiNotifyConfigure:
		return "配置 Telegram " + m.notifyWizard.userID
	case tuiNotifySchedule:
		return "计划通知 " + m.notifyWizard.userID
	case tuiNotifySend:
		return "发送 Telegram " + m.notifyWizard.userID
	default:
		return "Telegram"
	}
}

func (m tuiModel) notifyWizardProgress() string {
	steps := notifyWizardSteps(m.notifyWizard.kind)
	current := 0
	for i, step := range steps {
		if step == m.notifyWizard.step {
			current = i + 1
			break
		}
	}
	return fmt.Sprintf("步骤 %d/%d", current, len(steps))
}

func (m tuiModel) notifyWizardMiniSummary() string {
	w := m.notifyWizard
	switch w.kind {
	case tuiNotifyConfigure:
		return tuiHelpStyle.Render(fmt.Sprintf("user=%s token=%s chat=%s server=%s enabled=%v",
			w.userID, tokenStatus(w.botToken), emptyDash(w.chatID), emptyDash(w.serverName), w.enabled))
	case tuiNotifySchedule:
		return tuiHelpStyle.Render(fmt.Sprintf("user=%s interval=%s daily=%s",
			w.userID, emptyDash(w.interval), emptyDash(w.daily)))
	case tuiNotifySend:
		return tuiHelpStyle.Render("user=" + w.userID)
	default:
		return ""
	}
}

func notifyWizardSteps(kind tuiNotifyWizardKind) []tuiNotifyStep {
	switch kind {
	case tuiNotifyConfigure:
		return []tuiNotifyStep{tuiNotifyStepToken, tuiNotifyStepChatID, tuiNotifyStepServerName, tuiNotifyStepEnabled}
	case tuiNotifySchedule:
		return []tuiNotifyStep{tuiNotifyStepInterval, tuiNotifyStepDaily}
	case tuiNotifySend:
		return []tuiNotifyStep{tuiNotifyStepMessage}
	default:
		return nil
	}
}

func notifyWizardInputPrompt(step tuiNotifyStep) (string, string) {
	switch step {
	case tuiNotifyStepToken:
		return "Bot token", "必填；不会在列表中明文展示"
	case tuiNotifyStepChatID:
		return "Chat ID", "必填；例如 123456789 或 -100..."
	case tuiNotifyStepServerName:
		return "Server name", "可留空；留空使用 pfwd"
	case tuiNotifyStepInterval:
		return "Interval minutes", "可留空或输入 - 清空；必须大于 0"
	case tuiNotifyStepDaily:
		return "Daily time", "可留空或输入 - 清空；格式 HH:MM"
	case tuiNotifyStepMessage:
		return "Message", "必填；发送到该用户 Telegram chat"
	default:
		return "输入", ""
	}
}

func (m tuiModel) setNotifyWizardStep(step tuiNotifyStep) tuiModel {
	m.notifyWizard.step = step
	m.notifyWizard.value = notifyWizardInputValue(m.notifyWizard, step)
	if step == tuiNotifyStepEnabled && !m.notifyWizard.enabled {
		m.cursor = 1
	} else {
		m.cursor = 0
	}
	m.err = ""
	return m
}

func notifyWizardInputValue(w tuiNotifyWizardState, step tuiNotifyStep) string {
	switch step {
	case tuiNotifyStepToken:
		return w.botToken
	case tuiNotifyStepChatID:
		return w.chatID
	case tuiNotifyStepServerName:
		return w.serverName
	case tuiNotifyStepInterval:
		return w.interval
	case tuiNotifyStepDaily:
		return w.daily
	case tuiNotifyStepMessage:
		return w.message
	default:
		return ""
	}
}

func (m *tuiModel) submitNotifyWizardInput() error {
	value := strings.TrimSpace(m.notifyWizard.value)
	switch m.notifyWizard.step {
	case tuiNotifyStepToken:
		if value == "" {
			return fmt.Errorf("bot token 不能为空")
		}
		m.notifyWizard.botToken = value
	case tuiNotifyStepChatID:
		if value == "" {
			return fmt.Errorf("chat id 不能为空")
		}
		m.notifyWizard.chatID = value
	case tuiNotifyStepServerName:
		if value == "" {
			value = "pfwd"
		}
		m.notifyWizard.serverName = value
	case tuiNotifyStepInterval:
		if value == "-" {
			value = ""
		}
		if value != "" {
			interval, err := strconv.Atoi(value)
			if err != nil || interval <= 0 {
				return fmt.Errorf("interval minutes 必须大于 0")
			}
			value = strconv.Itoa(interval)
		}
		m.notifyWizard.interval = value
	case tuiNotifyStepDaily:
		if value == "-" {
			value = ""
		}
		if value != "" {
			if _, err := time.Parse("15:04", value); err != nil {
				return fmt.Errorf("无效 daily time：%s", value)
			}
		}
		m.notifyWizard.daily = value
	case tuiNotifyStepMessage:
		if value == "" {
			return fmt.Errorf("消息不能为空")
		}
		m.notifyWizard.message = value
	}
	return nil
}

func (m tuiModel) nextNotifyWizardStep() tuiModel {
	steps := notifyWizardSteps(m.notifyWizard.kind)
	for i, step := range steps {
		if step == m.notifyWizard.step && i+1 < len(steps) {
			return m.setNotifyWizardStep(steps[i+1])
		}
	}
	if err := m.saveNotifyWizard(); err != nil {
		m.setError(err)
	}
	return m
}

func (m tuiModel) previousNotifyWizardStep() tuiModel {
	steps := notifyWizardSteps(m.notifyWizard.kind)
	for i, step := range steps {
		if step == m.notifyWizard.step {
			if i == 0 {
				return m.cancelNotifyWizard()
			}
			return m.setNotifyWizardStep(steps[i-1])
		}
	}
	return m.cancelNotifyWizard()
}

func (m tuiModel) cancelNotifyWizard() tuiModel {
	m.mode = tuiNotify
	m.notifyWizard = tuiNotifyWizardState{}
	m.cursor = 0
	m.err = ""
	m.status = ""
	return m
}

func (m *tuiModel) saveNotifyWizard() error {
	switch m.notifyWizard.kind {
	case tuiNotifyConfigure:
		return m.saveNotifyConfig()
	case tuiNotifySchedule:
		return m.saveNotifySchedule()
	case tuiNotifySend:
		return m.sendNotifyMessage()
	default:
		return fmt.Errorf("未知通知向导")
	}
}

func (m *tuiModel) saveNotifyConfig() error {
	w := m.notifyWizard
	if err := m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findUser(cfg, w.userID)
		if !ok {
			return fmt.Errorf("用户不存在：%s", w.userID)
		}
		cfg.Users[idx].Telegram.BotToken = w.botToken
		cfg.Users[idx].Telegram.ChatID = w.chatID
		cfg.Users[idx].Telegram.ServerName = w.serverName
		cfg.Users[idx].Telegram.Enabled = w.enabled
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		m.cfg = cfg
		return nil
	}); err != nil {
		return err
	}
	m.mode = tuiNotify
	m.notifyWizard = tuiNotifyWizardState{}
	m.cursor = 0
	m.err = ""
	m.status = "Telegram 配置已更新：" + w.userID
	return nil
}

func (m *tuiModel) saveNotifySchedule() error {
	w := m.notifyWizard
	if err := m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findUser(cfg, w.userID)
		if !ok {
			return fmt.Errorf("用户不存在：%s", w.userID)
		}
		cfg.Users[idx].Telegram.ScheduleIntervalMinutes = nil
		if w.interval != "" {
			interval, err := strconv.Atoi(w.interval)
			if err != nil || interval <= 0 {
				return fmt.Errorf("interval minutes 必须大于 0")
			}
			cfg.Users[idx].Telegram.ScheduleIntervalMinutes = &interval
		}
		cfg.Users[idx].Telegram.ScheduleDailyTime = nil
		if w.daily != "" {
			if _, err := time.Parse("15:04", w.daily); err != nil {
				return fmt.Errorf("无效 daily time：%s", w.daily)
			}
			cfg.Users[idx].Telegram.ScheduleDailyTime = ptrString(w.daily)
		}
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		m.cfg = cfg
		return nil
	}); err != nil {
		return err
	}
	m.mode = tuiNotify
	m.notifyWizard = tuiNotifyWizardState{}
	m.cursor = 0
	m.err = ""
	m.status = "Telegram 计划已更新：" + w.userID
	return nil
}

func (m *tuiModel) sendNotifyMessage() error {
	w := m.notifyWizard
	if err := m.app.sendTelegramToUser(context.Background(), w.userID, w.message); err != nil {
		return err
	}
	if err := m.reload(); err != nil {
		return err
	}
	m.mode = tuiNotify
	m.notifyWizard = tuiNotifyWizardState{}
	m.cursor = 0
	m.err = ""
	m.status = "Telegram 消息已发送：" + w.userID
	return nil
}

func (m *tuiModel) setNotifyEnabled(userID string, enabled bool) error {
	if err := m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findUser(cfg, userID)
		if !ok {
			return fmt.Errorf("用户不存在：%s", userID)
		}
		cfg.Users[idx].Telegram.Enabled = enabled
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		m.cfg = cfg
		return nil
	}); err != nil {
		return err
	}
	m.err = ""
	m.status = fmt.Sprintf("Telegram 通知已更新：%s enabled=%v", userID, enabled)
	return nil
}

func (m *tuiModel) deleteNotifyConfig(userID string) error {
	if err := m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findUser(cfg, userID)
		if !ok {
			return fmt.Errorf("用户不存在：%s", userID)
		}
		cfg.Users[idx].Telegram = TelegramConfig{}
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		m.cfg = cfg
		return nil
	}); err != nil {
		return err
	}
	m.err = ""
	m.status = "Telegram 配置已删除：" + userID
	return nil
}

func (m *tuiModel) sendNotifyTest(userID string) error {
	if err := m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findUser(cfg, userID)
		if !ok {
			return fmt.Errorf("用户不存在：%s", userID)
		}
		tg := cfg.Users[idx].Telegram
		if tg.BotToken == "" || tg.ChatID == "" {
			return fmt.Errorf("用户未配置 Telegram：%s", userID)
		}
		text := fmt.Sprintf("pfwd notify test\nuser: %s\nserver: %s", userID, tg.ServerName)
		return m.app.sendTelegram(ctx, tg.BotToken, tg.ChatID, text)
	}); err != nil {
		return err
	}
	m.err = ""
	m.status = "Telegram 测试通知已发送：" + userID
	return nil
}

func notifySummary(tg TelegramConfig) string {
	if tg.BotToken == "" || tg.ChatID == "" {
		return "missing"
	}
	enabled := "disabled"
	if tg.Enabled {
		enabled = "enabled"
	}
	parts := []string{enabled, "chat=" + tg.ChatID}
	if tg.ScheduleIntervalMinutes != nil {
		parts = append(parts, fmt.Sprintf("interval=%dm", *tg.ScheduleIntervalMinutes))
	}
	if tg.ScheduleDailyTime != nil {
		parts = append(parts, "daily="+*tg.ScheduleDailyTime)
	}
	return strings.Join(parts, " ")
}

func tokenStatus(value string) string {
	if value == "" {
		return "missing"
	}
	return "configured"
}

func maskTelegramToken(value string) string {
	if value == "" {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= 8 {
		return "********"
	}
	return string(runes[:4]) + "..." + string(runes[len(runes)-4:])
}
