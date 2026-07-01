package app

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m tuiModel) startAddForwardWizard() tuiModel {
	if len(sortedUsers(m.cfg)) == 0 {
		m.setError(fmt.Errorf("请先添加用户"))
		return m
	}
	listenIP := m.cfg.Settings.DefaultListenIP
	if listenIP == "" {
		listenIP = "::"
	}
	m.mode = tuiForwardWizard
	m.cursor = 0
	m.status = ""
	m.err = ""
	m.forwardWizard = tuiForwardWizardState{
		step:         tuiForwardStepUser,
		listenIP:     listenIP,
		protocol:     "tcp_udp",
		trafficMode:  "two-way",
		trafficRatio: "1",
		snatMode:     "masquerade",
		mssMode:      "none",
	}
	return m.setForwardWizardStep(tuiForwardStepUser)
}

func (m tuiModel) startEditForwardWizard(fwd Forward) tuiModel {
	m.mode = tuiForwardWizard
	m.cursor = 0
	m.status = ""
	m.err = ""
	wizard := tuiForwardWizardState{
		edit:         true,
		forwardID:    fwd.ID,
		step:         tuiForwardStepUser,
		userID:       fwd.UserID,
		remoteHost:   fwd.RemoteHost,
		remotePort:   fwd.RemotePort,
		listenIP:     fwd.ListenIP,
		listenPort:   fwd.ListenPort,
		protocol:     fwd.Protocol,
		trafficMode:  fwd.TrafficMode,
		trafficRatio: strconv.FormatFloat(fwd.TrafficRatio, 'f', -1, 64),
		snatMode:     fwd.Net.SNATMode,
	}
	if wizard.listenIP == "" {
		wizard.listenIP = "::"
	}
	if wizard.protocol == "" {
		wizard.protocol = "tcp_udp"
	}
	if wizard.trafficMode == "" {
		wizard.trafficMode = "two-way"
	}
	if wizard.trafficRatio == "" || wizard.trafficRatio == "0" {
		wizard.trafficRatio = "1"
	}
	if wizard.snatMode == "" {
		wizard.snatMode = "masquerade"
	}
	if fwd.Comment != nil {
		wizard.comment = *fwd.Comment
	}
	if fwd.StopAt != nil {
		wizard.stopAt = *fwd.StopAt
	}
	if fwd.Net.SNATSource != nil {
		wizard.snatSource = *fwd.Net.SNATSource
	}
	wizard.mssMode = "none"
	if fwd.Net.MSSMode != nil && *fwd.Net.MSSMode != "" {
		wizard.mssMode = *fwd.Net.MSSMode
	}
	if fwd.Net.MSSValue != nil {
		wizard.mssMode = "set"
		wizard.mssValue = strconv.Itoa(int(*fwd.Net.MSSValue))
	}
	if fwd.Limits.TrafficBytes != nil {
		wizard.trafficLimit = strconv.FormatUint(*fwd.Limits.TrafficBytes, 10)
	}
	if fwd.Limits.Rate != nil {
		wizard.rate = *fwd.Limits.Rate
	}
	m.forwardWizard = wizard
	return m.setForwardWizardStep(tuiForwardStepUser)
}

func (m tuiModel) updateForwardWizard(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.forwardWizardInputStep() {
		return m.updateForwardWizardInput(key), nil
	}
	if quit, cmd := tuiShouldQuit(key); quit {
		return m, cmd
	}
	switch key.String() {
	case "esc":
		return m.cancelForwardWizard(), nil
	case "h", "0":
		return m.previousForwardWizardStep(), nil
	}
	if m.forwardWizard.step == tuiForwardStepReview {
		if m.enterKey(key) || key.String() == "y" {
			if err := m.saveForwardWizard(); err != nil {
				m.setError(err)
			}
		}
		return m, nil
	}
	rows := len(m.forwardWizardRows())
	if moved, ok := m.moveCursor(key, rows); ok {
		return moved, nil
	}
	idx, ok := m.choice(key, rows)
	if !ok {
		return m, nil
	}
	next, err := m.chooseForwardWizard(idx)
	if err != nil {
		m.setError(err)
		return m, nil
	}
	return next, nil
}

func (m tuiModel) updateForwardWizardInput(key tea.KeyMsg) tea.Model {
	switch key.String() {
	case "esc":
		return m.cancelForwardWizard()
	case "enter":
		if err := m.submitForwardWizardInput(); err != nil {
			m.setError(err)
			return m
		}
		return m.nextForwardWizardStep()
	case "backspace", "ctrl+h":
		if len(m.forwardWizard.value) > 0 {
			runes := []rune(m.forwardWizard.value)
			m.forwardWizard.value = string(runes[:len(runes)-1])
		}
		return m
	case "ctrl+u":
		m.forwardWizard.value = ""
		return m
	case " ":
		m.forwardWizard.value += " "
		return m
	}
	if key.Type == tea.KeyRunes {
		m.forwardWizard.value += string(key.Runes)
	}
	return m
}

func (m tuiModel) viewForwardWizard() string {
	var b strings.Builder
	b.WriteString(tuiTitleStyle.Render(m.forwardWizardTitle()) + "\n")
	b.WriteString(tuiHelpStyle.Render(m.forwardWizardProgress()) + "\n\n")
	if m.forwardWizard.step == tuiForwardStepReview {
		b.WriteString(m.forwardWizardSummary())
		b.WriteString("\n")
		b.WriteString(m.statusLine())
		b.WriteString(tuiHelpStyle.Render("Enter/y 保存 • h 返回上一步 • Esc 取消 • q 退出"))
		return b.String()
	}
	if m.forwardWizardInputStep() {
		title, help := forwardWizardInputPrompt(m.forwardWizard.step)
		b.WriteString(tuiLabelStyle.Render(title) + "\n\n")
		if m.forwardWizard.value == "" {
			b.WriteString(tuiHelpStyle.Render("（空）") + "\n\n")
		} else {
			b.WriteString(m.forwardWizard.value + "\n\n")
		}
		b.WriteString(m.forwardWizardMiniSummary())
		b.WriteString("\n")
		b.WriteString(m.statusLine())
		b.WriteString(tuiHelpStyle.Render(help + " • Enter 下一步 • Esc 取消"))
		return b.String()
	}
	b.WriteString(m.renderRowsBody(m.forwardWizardRows()))
	b.WriteString("\n")
	b.WriteString(m.statusLine())
	b.WriteString(tuiHelpStyle.Render("↑/↓/k/j 选择 • Enter/l 确认 • h/0 返回 • Esc 取消 • q 退出"))
	return b.String()
}

func (m tuiModel) forwardWizardTitle() string {
	if m.forwardWizard.edit {
		return "编辑转发 " + m.forwardWizard.forwardID
	}
	return "添加转发"
}

func (m tuiModel) forwardWizardProgress() string {
	steps := forwardWizardSteps(m.forwardWizard)
	current := 0
	for i, step := range steps {
		if step == m.forwardWizard.step {
			current = i + 1
			break
		}
	}
	return fmt.Sprintf("步骤 %d/%d", current, len(steps))
}

func (m tuiModel) forwardWizardRows() []tuiRow {
	switch m.forwardWizard.step {
	case tuiForwardStepUser:
		rows := []tuiRow{}
		for _, user := range sortedUsers(m.cfg) {
			rows = append(rows, tuiRow{text: user.ID, hint: userSummary(m.cfg, user.ID), detail: "选择该用户作为转发规则归属。"})
		}
		return rows
	case tuiForwardStepProtocol:
		return []tuiRow{
			{text: "tcp_udp", hint: "TCP + UDP", detail: "同一监听端口同时接收 TCP 和 UDP。"},
			{text: "tcp", hint: "仅 TCP", detail: "只接收 TCP。"},
			{text: "udp", hint: "仅 UDP", detail: "只接收 UDP。"},
		}
	case tuiForwardStepTrafficMode:
		return []tuiRow{
			{text: "two-way", hint: "双向计费", detail: "统计输入和输出流量。"},
			{text: "one-way", hint: "单向计费", detail: "仅按主要方向计费。"},
		}
	case tuiForwardStepSNATMode:
		return []tuiRow{
			{text: "masquerade", hint: "自动源地址", detail: "使用系统出口地址做 masquerade。"},
			{text: "snat", hint: "固定源地址", detail: "下一步输入 SNAT source IP。"},
		}
	case tuiForwardStepMSSMode:
		return []tuiRow{
			{text: "none", hint: "不改 MSS", detail: "不写 MSS 规则。"},
			{text: "clamp", hint: "自动 clamp", detail: "按路径 MTU clamp MSS。"},
			{text: "set", hint: "固定 MSS", detail: "下一步输入 MSS 数值。"},
		}
	default:
		return nil
	}
}

func (m tuiModel) chooseForwardWizard(idx int) (tuiModel, error) {
	switch m.forwardWizard.step {
	case tuiForwardStepUser:
		users := sortedUsers(m.cfg)
		if idx < 0 || idx >= len(users) {
			return m, fmt.Errorf("无效用户选择")
		}
		m.forwardWizard.userID = users[idx].ID
	case tuiForwardStepProtocol:
		values := []string{"tcp_udp", "tcp", "udp"}
		m.forwardWizard.protocol = values[idx]
	case tuiForwardStepTrafficMode:
		values := []string{"two-way", "one-way"}
		m.forwardWizard.trafficMode = values[idx]
	case tuiForwardStepSNATMode:
		values := []string{"masquerade", "snat"}
		m.forwardWizard.snatMode = values[idx]
		if m.forwardWizard.snatMode == "masquerade" {
			m.forwardWizard.snatSource = ""
		}
	case tuiForwardStepMSSMode:
		values := []string{"none", "clamp", "set"}
		m.forwardWizard.mssMode = values[idx]
		if m.forwardWizard.mssMode != "set" {
			m.forwardWizard.mssValue = ""
		}
	}
	return m.nextForwardWizardStep(), nil
}

func (m tuiModel) forwardWizardInputStep() bool {
	switch m.forwardWizard.step {
	case tuiForwardStepRemote, tuiForwardStepListenPort, tuiForwardStepListenIP,
		tuiForwardStepComment, tuiForwardStepStopAt, tuiForwardStepTrafficRatio,
		tuiForwardStepSNATSource, tuiForwardStepMSSValue, tuiForwardStepTrafficLimit,
		tuiForwardStepRate:
		return true
	default:
		return false
	}
}

func (m tuiModel) nextForwardWizardStep() tuiModel {
	steps := forwardWizardSteps(m.forwardWizard)
	for i, step := range steps {
		if step == m.forwardWizard.step && i+1 < len(steps) {
			return m.setForwardWizardStep(steps[i+1])
		}
	}
	return m.setForwardWizardStep(tuiForwardStepReview)
}

func (m tuiModel) previousForwardWizardStep() tuiModel {
	steps := forwardWizardSteps(m.forwardWizard)
	for i, step := range steps {
		if step == m.forwardWizard.step {
			if i == 0 {
				return m.cancelForwardWizard()
			}
			return m.setForwardWizardStep(steps[i-1])
		}
	}
	return m.cancelForwardWizard()
}

func (m tuiModel) cancelForwardWizard() tuiModel {
	m.mode = tuiForwards
	m.forwardWizard = tuiForwardWizardState{}
	m.cursor = 0
	m.err = ""
	m.status = ""
	return m
}

func (m tuiModel) setForwardWizardStep(step tuiForwardStep) tuiModel {
	m.forwardWizard.step = step
	m.forwardWizard.value = forwardWizardInputValue(m.forwardWizard, step)
	m.cursor = m.forwardWizardCursor(step)
	m.err = ""
	return m
}

func (m tuiModel) forwardWizardCursor(step tuiForwardStep) int {
	switch step {
	case tuiForwardStepUser:
		return userWizardIndex(sortedUsers(m.cfg), m.forwardWizard.userID)
	case tuiForwardStepProtocol:
		return valueIndex([]string{"tcp_udp", "tcp", "udp"}, m.forwardWizard.protocol)
	case tuiForwardStepTrafficMode:
		return valueIndex([]string{"two-way", "one-way"}, m.forwardWizard.trafficMode)
	case tuiForwardStepSNATMode:
		return valueIndex([]string{"masquerade", "snat"}, m.forwardWizard.snatMode)
	case tuiForwardStepMSSMode:
		return valueIndex([]string{"none", "clamp", "set"}, m.forwardWizard.mssMode)
	default:
		return 0
	}
}

func forwardWizardSteps(w tuiForwardWizardState) []tuiForwardStep {
	steps := []tuiForwardStep{
		tuiForwardStepUser,
		tuiForwardStepRemote,
		tuiForwardStepListenPort,
		tuiForwardStepListenIP,
		tuiForwardStepProtocol,
		tuiForwardStepComment,
		tuiForwardStepStopAt,
		tuiForwardStepTrafficMode,
		tuiForwardStepTrafficRatio,
		tuiForwardStepSNATMode,
	}
	if w.snatMode == "snat" {
		steps = append(steps, tuiForwardStepSNATSource)
	}
	steps = append(steps, tuiForwardStepMSSMode)
	if w.mssMode == "set" {
		steps = append(steps, tuiForwardStepMSSValue)
	}
	steps = append(steps, tuiForwardStepTrafficLimit, tuiForwardStepRate, tuiForwardStepReview)
	return steps
}

func forwardWizardInputValue(w tuiForwardWizardState, step tuiForwardStep) string {
	switch step {
	case tuiForwardStepRemote:
		if w.remoteHost == "" || w.remotePort == 0 {
			return ""
		}
		return formatRemote(w.remoteHost, w.remotePort)
	case tuiForwardStepListenPort:
		if w.listenPort == 0 {
			return ""
		}
		return strconv.Itoa(int(w.listenPort))
	case tuiForwardStepListenIP:
		return w.listenIP
	case tuiForwardStepComment:
		return w.comment
	case tuiForwardStepStopAt:
		return w.stopAt
	case tuiForwardStepTrafficRatio:
		return w.trafficRatio
	case tuiForwardStepSNATSource:
		return w.snatSource
	case tuiForwardStepMSSValue:
		return w.mssValue
	case tuiForwardStepTrafficLimit:
		return w.trafficLimit
	case tuiForwardStepRate:
		return w.rate
	default:
		return ""
	}
}

func forwardWizardInputPrompt(step tuiForwardStep) (string, string) {
	switch step {
	case tuiForwardStepRemote:
		return "远端地址", "例：example.com:443 或 [2001:db8::1]:443"
	case tuiForwardStepListenPort:
		return "监听端口", "1-65535"
	case tuiForwardStepListenIP:
		return "监听地址", "默认 ::；当前快路径仅支持 :: 或 0.0.0.0"
	case tuiForwardStepComment:
		return "备注", "可留空；Ctrl+U 清空当前输入"
	case tuiForwardStepStopAt:
		return "到期时间", "可留空；支持 YYYY-MM-DD、YYYY-MM-DD HH:MM、+7、7d"
	case tuiForwardStepTrafficRatio:
		return "流量倍率", "必须大于 0；默认 1"
	case tuiForwardStepSNATSource:
		return "SNAT 源地址", "必须是明确 IP 地址"
	case tuiForwardStepMSSValue:
		return "MSS 数值", "必须大于等于 536"
	case tuiForwardStepTrafficLimit:
		return "规则流量上限", "可留空；例：100GB、1TiB"
	case tuiForwardStepRate:
		return "规则限速", "可留空；例：50Mbps"
	default:
		return "输入", ""
	}
}

func (m *tuiModel) submitForwardWizardInput() error {
	value := strings.TrimSpace(m.forwardWizard.value)
	switch m.forwardWizard.step {
	case tuiForwardStepRemote:
		host, ports, err := parseHostPortSpec(value)
		if err != nil {
			return err
		}
		if len(ports) != 1 {
			return fmt.Errorf("TUI 向导一次只支持一个远端端口")
		}
		m.forwardWizard.remoteHost = host
		m.forwardWizard.remotePort = ports[0]
	case tuiForwardStepListenPort:
		port, err := parsePort(value)
		if err != nil {
			return err
		}
		m.forwardWizard.listenPort = port
	case tuiForwardStepListenIP:
		if err := validateListenIP(value); err != nil {
			return err
		}
		m.forwardWizard.listenIP = value
	case tuiForwardStepComment:
		m.forwardWizard.comment = value
	case tuiForwardStepStopAt:
		stopAt, err := normalizeStopAt(value)
		if err != nil {
			return err
		}
		if stopAt == nil {
			m.forwardWizard.stopAt = ""
		} else {
			m.forwardWizard.stopAt = *stopAt
		}
	case tuiForwardStepTrafficRatio:
		ratio, err := strconv.ParseFloat(value, 64)
		if err != nil || ratio <= 0 {
			return fmt.Errorf("无效流量倍率：%s", value)
		}
		m.forwardWizard.trafficRatio = strconv.FormatFloat(ratio, 'f', -1, 64)
	case tuiForwardStepSNATSource:
		if err := validateSNAT("snat", value); err != nil {
			return err
		}
		m.forwardWizard.snatSource = value
	case tuiForwardStepMSSValue:
		port, err := parsePort(value)
		if err != nil || port < 536 {
			return fmt.Errorf("无效 MSS 值：%s", value)
		}
		m.forwardWizard.mssValue = strconv.Itoa(int(port))
	case tuiForwardStepTrafficLimit:
		if value == "" || value == "-" {
			m.forwardWizard.trafficLimit = ""
			return nil
		}
		bytes, err := parseSizeBytes(value)
		if err != nil {
			return err
		}
		m.forwardWizard.trafficLimit = strconv.FormatUint(bytes, 10)
	case tuiForwardStepRate:
		if value == "-" {
			value = ""
		}
		m.forwardWizard.rate = value
	}
	return nil
}

func (m *tuiModel) saveForwardWizard() error {
	wizard := m.forwardWizard
	var savedID string
	if err := m.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		if _, ok := findUser(cfg, wizard.userID); !ok {
			return fmt.Errorf("用户不存在：%s", wizard.userID)
		}
		existing := Forward{Enabled: true, CreatedAt: nowISO()}
		idx := -1
		if wizard.edit {
			var ok bool
			idx, ok = findForward(cfg, wizard.forwardID)
			if !ok {
				return fmt.Errorf("转发规则不存在：%s", wizard.forwardID)
			}
			existing = cfg.Forwards[idx]
		} else {
			id, err := randomID("fwd")
			if err != nil {
				return err
			}
			existing.ID = id
		}
		fwd, err := forwardFromWizard(wizard, existing)
		if err != nil {
			return err
		}
		for _, other := range cfg.Forwards {
			if other.ID != fwd.ID && other.ListenPort == fwd.ListenPort && protocolsConflict(fwd.Protocol, other.Protocol) {
				return fmt.Errorf("监听端口已配置冲突协议：%d", fwd.ListenPort)
			}
		}
		if wizard.edit {
			cfg.Forwards[idx] = fwd
		} else {
			cfg.Forwards = append(cfg.Forwards, fwd)
		}
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		if err := m.app.refresh(ctx, store, false); err != nil {
			return err
		}
		m.cfg = normalizeConfig(cfg)
		savedID = fwd.ID
		return nil
	}); err != nil {
		return err
	}
	m.mode = tuiForwards
	m.cursor = 0
	m.forwardWizard = tuiForwardWizardState{}
	m.err = ""
	if wizard.edit {
		m.status = "转发已更新：" + savedID
	} else {
		m.status = "转发已添加：" + savedID
	}
	return nil
}

func forwardFromWizard(w tuiForwardWizardState, existing Forward) (Forward, error) {
	if w.remoteHost == "" {
		return Forward{}, fmt.Errorf("远端主机不能为空")
	}
	if err := validatePort(int(w.remotePort)); err != nil {
		return Forward{}, err
	}
	if err := validatePort(int(w.listenPort)); err != nil {
		return Forward{}, err
	}
	if err := validateListenIP(w.listenIP); err != nil {
		return Forward{}, err
	}
	if err := validateProtocol(w.protocol); err != nil {
		return Forward{}, err
	}
	if err := validateTrafficMode(w.trafficMode); err != nil {
		return Forward{}, err
	}
	ratio, err := strconv.ParseFloat(w.trafficRatio, 64)
	if err != nil || ratio <= 0 {
		return Forward{}, fmt.Errorf("无效流量倍率：%s", w.trafficRatio)
	}
	stopAt, err := normalizeStopAt(w.stopAt)
	if err != nil {
		return Forward{}, err
	}
	netCfg, err := netConfigFromWizard(w)
	if err != nil {
		return Forward{}, err
	}
	limits, err := limitsFromWizard(w)
	if err != nil {
		return Forward{}, err
	}
	fwd := existing
	fwd.UserID = w.userID
	fwd.ListenIP = w.listenIP
	fwd.ListenPort = w.listenPort
	fwd.RemoteHost = w.remoteHost
	fwd.RemotePort = w.remotePort
	fwd.Protocol = w.protocol
	fwd.StopAt = stopAt
	fwd.TrafficMode = w.trafficMode
	fwd.TrafficRatio = ratio
	fwd.Comment = ptrString(w.comment)
	fwd.Net = netCfg
	fwd.Limits = limits
	if fwd.CreatedAt == "" {
		fwd.CreatedAt = nowISO()
	}
	if stopAt != nil && *stopAt > nowMinute() {
		fwd.Enabled = true
	}
	return fwd, nil
}

func netConfigFromWizard(w tuiForwardWizardState) (NetConfig, error) {
	snatMode := w.snatMode
	if snatMode == "" {
		snatMode = "masquerade"
	}
	snatSource := strings.TrimSpace(w.snatSource)
	if snatMode == "masquerade" {
		snatSource = ""
	}
	if err := validateSNAT(snatMode, snatSource); err != nil {
		return NetConfig{}, err
	}
	cfg := NetConfig{SNATMode: snatMode}
	if snatSource != "" {
		cfg.SNATSource = ptrString(snatSource)
	}
	switch w.mssMode {
	case "", "none":
		return cfg, nil
	case "clamp":
		cfg.MSSMode = ptrString("clamp")
		return cfg, nil
	case "set":
		port, err := parsePort(w.mssValue)
		if err != nil || port < 536 {
			return NetConfig{}, fmt.Errorf("无效 MSS 值：%s", w.mssValue)
		}
		cfg.MSSMode = ptrString("set")
		cfg.MSSValue = &port
		return cfg, nil
	default:
		return NetConfig{}, fmt.Errorf("无效 MSS 模式：%s", w.mssMode)
	}
}

func limitsFromWizard(w tuiForwardWizardState) (ForwardLimits, error) {
	var limits ForwardLimits
	traffic := strings.TrimSpace(w.trafficLimit)
	if traffic != "" && traffic != "-" {
		bytes, err := parseSizeBytes(traffic)
		if err != nil {
			return limits, err
		}
		limits.TrafficBytes = &bytes
	}
	rate := strings.TrimSpace(w.rate)
	if rate != "" && rate != "-" {
		limits.Rate = ptrString(rate)
	}
	return limits, nil
}

func (m tuiModel) forwardWizardMiniSummary() string {
	lines := []string{
		"用户: " + emptyDash(m.forwardWizard.userID),
		"远端: " + forwardWizardRemote(m.forwardWizard),
		"监听: " + forwardWizardListen(m.forwardWizard),
	}
	return tuiHelpStyle.Render(strings.Join(lines, "  ")) + "\n"
}

func (m tuiModel) forwardWizardSummary() string {
	rows := []string{
		"用户: " + emptyDash(m.forwardWizard.userID),
		"监听: " + forwardWizardListen(m.forwardWizard),
		"远端: " + forwardWizardRemote(m.forwardWizard),
		"协议: " + emptyDash(m.forwardWizard.protocol),
		"备注: " + emptyDash(m.forwardWizard.comment),
		"到期: " + emptyDash(m.forwardWizard.stopAt),
		"计费: " + emptyDash(m.forwardWizard.trafficMode) + " x" + emptyDash(m.forwardWizard.trafficRatio),
		"SNAT: " + forwardWizardSNAT(m.forwardWizard),
		"MSS: " + forwardWizardMSS(m.forwardWizard),
		"限制: traffic=" + emptyDash(m.forwardWizard.trafficLimit) + " rate=" + emptyDash(m.forwardWizard.rate),
	}
	var b strings.Builder
	for _, row := range rows {
		b.WriteString(row + "\n")
	}
	return b.String()
}

func forwardTUIHint(fwd Forward) string {
	parts := []string{"user=" + fwd.UserID, "proto=" + fwd.Protocol, "snat=" + fwd.Net.SNATMode}
	if fwd.Net.SNATSource != nil {
		parts = append(parts, "src="+*fwd.Net.SNATSource)
	}
	if fwd.Net.MSSMode != nil && *fwd.Net.MSSMode != "" {
		if fwd.Net.MSSValue != nil {
			parts = append(parts, fmt.Sprintf("mss=%d", *fwd.Net.MSSValue))
		} else {
			parts = append(parts, "mss="+*fwd.Net.MSSMode)
		}
	}
	if fwd.Limits.TrafficBytes != nil {
		parts = append(parts, "limit="+formatBytes(*fwd.Limits.TrafficBytes))
	}
	if fwd.Limits.Rate != nil {
		parts = append(parts, "rate="+*fwd.Limits.Rate)
	}
	return strings.Join(parts, " ")
}

func forwardWizardRemote(w tuiForwardWizardState) string {
	if w.remoteHost == "" || w.remotePort == 0 {
		return "-"
	}
	return formatRemote(w.remoteHost, w.remotePort)
}

func forwardWizardListen(w tuiForwardWizardState) string {
	if w.listenPort == 0 {
		return emptyDash(w.listenIP) + ":-"
	}
	return fmt.Sprintf("%s:%d", emptyDash(w.listenIP), w.listenPort)
}

func forwardWizardSNAT(w tuiForwardWizardState) string {
	if w.snatMode == "snat" {
		return "snat " + emptyDash(w.snatSource)
	}
	return "masquerade"
}

func forwardWizardMSS(w tuiForwardWizardState) string {
	switch w.mssMode {
	case "set":
		return "set " + emptyDash(w.mssValue)
	case "clamp":
		return "clamp"
	default:
		return "none"
	}
}

func userWizardIndex(users []User, id string) int {
	for i, user := range users {
		if user.ID == id {
			return i
		}
	}
	return 0
}

func valueIndex(values []string, value string) int {
	for i, item := range values {
		if item == value {
			return i
		}
	}
	return 0
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
