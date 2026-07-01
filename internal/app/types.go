package app

type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
}

type Config struct {
	Settings Settings  `json:"settings"`
	Users    []User    `json:"users"`
	Forwards []Forward `json:"forwards"`
}

type Settings struct {
	NFTFamily              string          `json:"nft_family"`
	NFTTable               string          `json:"nft_table"`
	ForwardTable           string          `json:"forward_table"`
	DomainRefreshInterval  string          `json:"domain_refresh_interval"`
	TCInterface            string          `json:"tc_interface"`
	Forward                ForwardSettings `json:"forward"`
	DefaultListenIP        string          `json:"default_listen_ip"`
	DefaultRandomPortRange string          `json:"default_random_port_range"`
}

type ForwardSettings struct {
	Interface string `json:"interface"`
}

type User struct {
	ID              string          `json:"id"`
	CreatedAt       string          `json:"created_at"`
	ForwardDefaults ForwardDefaults `json:"forward_defaults"`
	Telegram        TelegramConfig  `json:"telegram"`
	Limits          Limits          `json:"limits"`
}

type ForwardDefaults struct {
	StopAt *string `json:"stop_at"`
}

type TelegramConfig struct {
	Enabled                 bool    `json:"enabled"`
	BotToken                string  `json:"bot_token"`
	ChatID                  string  `json:"chat_id"`
	ServerName              string  `json:"server_name"`
	ScheduleIntervalMinutes *int    `json:"schedule_interval_minutes"`
	ScheduleDailyTime       *string `json:"schedule_daily_time"`
	LastIntervalSentAt      *string `json:"last_interval_sent_at"`
	LastDailySentDate       *string `json:"last_daily_sent_date"`
}

type Limits struct {
	TrafficBytes *uint64 `json:"traffic_bytes"`
	Rate         *string `json:"rate"`
	TrafficMode  string  `json:"traffic_mode"`
}

type Forward struct {
	ID           string        `json:"id"`
	UserID       string        `json:"user_id"`
	ListenIP     string        `json:"listen_ip"`
	ListenPort   uint16        `json:"listen_port"`
	RemoteHost   string        `json:"remote_host"`
	RemotePort   uint16        `json:"remote_port"`
	Protocol     string        `json:"protocol"`
	Enabled      bool          `json:"enabled"`
	StopAt       *string       `json:"stop_at"`
	TrafficMode  string        `json:"traffic_mode"`
	TrafficRatio float64       `json:"traffic_ratio"`
	Comment      *string       `json:"comment"`
	Net          NetConfig     `json:"net"`
	Limits       ForwardLimits `json:"limits"`
	CreatedAt    string        `json:"created_at"`
}

type NetConfig struct {
	MSSMode    *string `json:"mss_mode"`
	MSSValue   *uint16 `json:"mss_value"`
	SNATMode   string  `json:"snat_mode"`
	SNATSource *string `json:"snat_source"`
}

type ForwardLimits struct {
	TrafficBytes *uint64 `json:"traffic_bytes"`
	Rate         *string `json:"rate"`
}

type StatsState struct {
	Users    map[string]UsageState `json:"users"`
	Forwards map[string]UsageState `json:"forwards"`
}

type UsageState struct {
	BillingUsedBytes uint64  `json:"billing_used_bytes"`
	InputTotalBytes  uint64  `json:"input_total_bytes"`
	OutputTotalBytes uint64  `json:"output_total_bytes"`
	ResetDay         *string `json:"reset_day,omitempty"`
}

func defaultConfig() Config {
	return Config{
		Settings: Settings{
			NFTFamily:              "inet",
			NFTTable:               "pfwd",
			ForwardTable:           "port_forward",
			DomainRefreshInterval:  "60s",
			Forward:                ForwardSettings{},
			DefaultListenIP:        "::",
			DefaultRandomPortRange: "20000-30000",
		},
		Users:    []User{},
		Forwards: []Forward{},
	}
}

func defaultStats() StatsState {
	return StatsState{
		Users:    map[string]UsageState{},
		Forwards: map[string]UsageState{},
	}
}
