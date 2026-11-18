package main

// agentdiag answers one question against a live account: does the agent id the
// gateway stores still belong to the account's upstream user?
//
// It runs the same opening sequence the web client does (config → agent list →
// connections), prints every agent the account owns, and then tries to open a
// session with the *stored* id and with the *discovered* id. "session ownership
// denied" on one and a session on the other is the whole answer.
//
//	go run ./cmd/agentdiag   (APP_JSON, ACC, MM_PROXY honoured)

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"minimax2api/internal/config"
	"minimax2api/internal/minimax"
)

type doc struct {
	Settings struct {
		Upstream struct {
			BaseURL string `json:"baseURL"`
			Proxy   string `json:"proxy"`
		} `json:"upstream"`
	} `json:"settings"`
	Accounts []map[string]any `json:"accounts"`
}

func str(node map[string]any, key string) string {
	if v, ok := node[key].(string); ok {
		return v
	}
	return ""
}

func main() {
	path := os.Getenv("APP_JSON")
	if path == "" {
		path = "/opt/minimax2api/data/app.json"
	}
	want := os.Getenv("ACC")

	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("read app.json:", err)
		os.Exit(1)
	}
	var d doc
	if err := json.Unmarshal(raw, &d); err != nil {
		fmt.Println("parse app.json:", err)
		os.Exit(1)
	}

	var acc map[string]any
	for _, a := range d.Accounts {
		if str(a, "id") == want {
			acc = a
			break
		}
	}
	if acc == nil {
		fmt.Println("account not found:", want)
		os.Exit(1)
	}

	sw, sh := 1920, 1080
	if v, ok := acc["screenWidth"].(float64); ok && v > 0 {
		sw = int(v)
	}
	if v, ok := acc["screenHeight"].(float64); ok && v > 0 {
		sh = int(v)
	}

	cred := minimax.Credential{
		Region:       str(acc, "region"),
		Token:        str(acc, "token"),
		UserID:       str(acc, "userId"),
		AgentID:      str(acc, "agentID"),
		DeviceID:     str(acc, "deviceID"),
		UUID:         str(acc, "uuid"),
		ScreenWidth:  sw,
		ScreenHeight: sh,
		BaseURL:      str(acc, "baseURL"),
	}
	stored := cred.AgentID

	if p := os.Getenv("MM_PROXY"); p != "" {
		d.Settings.Upstream.Proxy = p
	}

	settings := config.DefaultSettings(os.TempDir())
	if d.Settings.Upstream.BaseURL != "" {
		settings.Upstream.BaseURL = d.Settings.Upstream.BaseURL
	}
	settings.Upstream.Proxy = d.Settings.Upstream.Proxy
	settings.Upstream.ScreenWidth = sw
	settings.Upstream.ScreenHeight = sh

	client := minimax.New(func() config.Settings { return settings })
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	fmt.Printf("account   : %s (%s)\n", str(acc, "name"), want)
	fmt.Printf("userId    : %s   (relogin %s)\n", cred.UserID, str(acc, "lastLoginAt"))
	fmt.Printf("stored ag.: %s\n", stored)
	fmt.Printf("token     : %s…\n", head(cred.Token, 12))

	prepared, perr := client.Prepare(ctx, cred)
	fmt.Printf("\nprepare   : err=%v\n", perr)
	if prepared != nil {
		fmt.Printf("agents    : %d\n", len(prepared.Agents))
		for _, a := range prepared.Agents {
			mark := ""
			if a.ID == stored {
				mark = "   <-- stored"
			}
			fmt.Printf("  - id=%s role=%s root_session=%s%s\n", a.ID, a.Role, head(a.RootSessionID, 8), mark)
		}
		fmt.Printf("discovered: %q\n", prepared.AgentID())
	}

	fmt.Println("\n== session create, stored agent ==")
	trySession(ctx, client, cred, stored)

	if prepared != nil {
		if id := prepared.AgentID(); id != "" && id != stored {
			fmt.Println("\n== session create, discovered agent ==")
			trySession(ctx, client, cred, id)
		}
	}
}

func trySession(ctx context.Context, client *minimax.Client, cred minimax.Credential, agentID string) {
	if strings.TrimSpace(agentID) == "" {
		fmt.Println("  (no agent id)")
		return
	}
	c := cred
	c.AgentID = agentID
	start := time.Now()
	id, err := client.CreateSession(ctx, c)
	fmt.Printf("  agent %s -> %v (%s)\n", agentID, compact(id), time.Since(start).Round(time.Millisecond))
	if err != nil {
		fmt.Printf("  error: %v\n", err)
	}
}

func compact(id string) string {
	if id == "" {
		return "no session"
	}
	return "session " + head(id, 10) + "…"
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
