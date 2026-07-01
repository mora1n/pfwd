package app

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type telegramSender func(context.Context, string, string, string) error

func (a *App) runUserTelegram(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法：pfwd user telegram <username>|--all --bot-token TOKEN --chat-id CHAT_ID [--server-name NAME] [--enabled true|false]")
	}
	applyAll := args[0] == "--all"
	userID := ""
	if applyAll {
		args = args[1:]
	} else {
		userID = normalizeUserID(args[0])
		args = args[1:]
	}
	fs := flag.NewFlagSet("user telegram", flag.ContinueOnError)
	token := fs.String("bot-token", "", "bot token")
	chatID := fs.String("chat-id", "", "chat id")
	serverName := fs.String("server-name", "", "server name")
	enabled := fs.Bool("enabled", true, "enabled")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" || *chatID == "" {
		return fmt.Errorf("必须提供 --bot-token 和 --chat-id")
	}
	if *serverName == "" {
		host, err := os.Hostname()
		if err == nil {
			*serverName = host
		} else {
			*serverName = "pfwd"
		}
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		updated := 0
		for i := range cfg.Users {
			if applyAll || cfg.Users[i].ID == userID {
				cfg.Users[i].Telegram.Enabled = *enabled
				cfg.Users[i].Telegram.BotToken = *token
				cfg.Users[i].Telegram.ChatID = *chatID
				cfg.Users[i].Telegram.ServerName = *serverName
				updated++
			}
		}
		if updated == 0 {
			return fmt.Errorf("用户不存在：%s", userID)
		}
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		if applyAll {
			fmt.Println("Telegram 配置已批量更新：全部用户")
		} else {
			fmt.Printf("Telegram 配置已更新：%s\n", userID)
		}
		return nil
	})
}

func (a *App) runNotify(cmd string, args []string) error {
	switch cmd {
	case "notify-send":
		return a.sendNotify(args)
	case "notify-enable":
		return a.toggleNotify(args, true)
	case "notify-disable":
		return a.toggleNotify(args, false)
	case "notify-delete":
		return a.deleteNotify(args)
	case "notify-schedule":
		return a.scheduleNotify(args)
	case "notify-test":
		return a.testNotify(args)
	default:
		return fmt.Errorf("未知通知命令：%s", cmd)
	}
}

func (a *App) sendNotify(args []string) error {
	fs := flag.NewFlagSet("notify-send", flag.ContinueOnError)
	userID := fs.String("user-id", "", "user id")
	text := fs.String("text", "", "message text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*userID) == "" {
		return fmt.Errorf("必须提供 --user-id")
	}
	if strings.TrimSpace(*text) == "" {
		return fmt.Errorf("必须提供 --text")
	}
	user := normalizeUserID(*userID)
	if err := a.sendTelegramToUser(context.Background(), user, *text); err != nil {
		return err
	}
	fmt.Printf("Telegram 消息已发送：%s\n", user)
	return nil
}

func parseNotifyUser(args []string) (string, error) {
	fs := flag.NewFlagSet("notify", flag.ContinueOnError)
	userID := fs.String("user-id", "", "user id")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if *userID == "" {
		return "", fmt.Errorf("必须提供 --user-id")
	}
	return normalizeUserID(*userID), nil
}

func (a *App) toggleNotify(args []string, enabled bool) error {
	userID, err := parseNotifyUser(args)
	if err != nil {
		return err
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
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
		fmt.Printf("Telegram 通知已更新：%s enabled=%v\n", userID, enabled)
		return nil
	})
}

func (a *App) deleteNotify(args []string) error {
	userID, err := parseNotifyUser(args)
	if err != nil {
		return err
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
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
		fmt.Printf("Telegram 配置已删除：%s\n", userID)
		return nil
	})
}

func (a *App) scheduleNotify(args []string) error {
	fs := flag.NewFlagSet("notify-schedule", flag.ContinueOnError)
	userID := fs.String("user-id", "", "user id")
	interval := fs.Int("interval-minutes", -1, "interval minutes")
	clearInterval := fs.Bool("clear-interval", false, "clear interval")
	daily := fs.String("daily-time", "__KEEP__", "daily time")
	clearDaily := fs.Bool("clear-daily", false, "clear daily")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *userID == "" {
		return fmt.Errorf("必须提供 --user-id")
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
		cfg, err := loadConfig(ctx, store)
		if err != nil {
			return err
		}
		idx, ok := findUser(cfg, normalizeUserID(*userID))
		if !ok {
			return fmt.Errorf("用户不存在：%s", *userID)
		}
		if *clearInterval {
			cfg.Users[idx].Telegram.ScheduleIntervalMinutes = nil
		} else if *interval >= 0 {
			if *interval == 0 {
				return fmt.Errorf("--interval-minutes 必须大于 0")
			}
			cfg.Users[idx].Telegram.ScheduleIntervalMinutes = interval
		}
		if *clearDaily {
			cfg.Users[idx].Telegram.ScheduleDailyTime = nil
		} else if *daily != "__KEEP__" {
			if _, err := time.Parse("15:04", *daily); err != nil {
				return fmt.Errorf("无效 daily-time：%s", *daily)
			}
			cfg.Users[idx].Telegram.ScheduleDailyTime = daily
		}
		if err := saveConfig(ctx, store, cfg); err != nil {
			return err
		}
		fmt.Printf("Telegram 计划已更新：%s\n", normalizeUserID(*userID))
		return nil
	})
}

func (a *App) testNotify(args []string) error {
	userID, err := parseNotifyUser(args)
	if err != nil {
		return err
	}
	return a.withStore(func(ctx context.Context, store *Store) error {
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
		if err := a.sendTelegram(ctx, tg.BotToken, tg.ChatID, text); err != nil {
			return err
		}
		fmt.Printf("Telegram 测试通知已发送：%s\n", userID)
		return nil
	})
}

func (a *App) sendTelegramToUser(ctx context.Context, userID, text string) error {
	store, err := OpenStore(a.Paths.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
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
	return a.sendTelegram(ctx, tg.BotToken, tg.ChatID, text)
}

func (a *App) sendTelegram(ctx context.Context, token, chatID, text string) error {
	sender := a.telegramSender
	if sender == nil {
		sender = sendTelegram
	}
	return sender(ctx, token, chatID, text)
}

func sendTelegram(ctx context.Context, token, chatID, text string) error {
	payload, err := json.Marshal(map[string]string{"chat_id": chatID, "text": text})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+token+"/sendMessage", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if !result.OK {
		return fmt.Errorf("Telegram API 返回失败：%s", result.Description)
	}
	return nil
}
