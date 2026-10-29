package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"minimax2api/internal/config"
	"minimax2api/internal/minimax"
	"minimax2api/internal/pool"
	"minimax2api/internal/store"
)

// newReloginHarness builds an API whose upstream and browser bridge are both
// stubs. The upstream answers the identity call the re-login verifies against
// and the agent calls the follow-up quota probe makes, so the account ends the
// way it would in production.
func newReloginHarness(t *testing.T, bridge http.HandlerFunc, infoEmail string) (*API, *store.Store) {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/api/user/info"):
			_, _ = io.WriteString(w, `{"data":{"userInfo":{"realUserID":"557000000000000001","name":"tester","email":"`+infoEmail+`","phone":"+14155550123"}}}`)
		case strings.HasSuffix(r.URL.Path, "/session"):
			w.Header().Set("content-type", "application/json")
			_, _ = io.WriteString(w, `{"session_id":"sess-1"}`)
		case strings.HasSuffix(r.URL.Path, "/message"):
			w.Header().Set("content-type", "text/event-stream")
			_, _ = io.WriteString(w, `data:{"type":6,"agent_message_chunk":{"msg_content":"pong"}}`+"\n\n"+
				`data:{"type":9,"finish_reason":"stop"}`+"\n\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	storeDir := t.TempDir()
	st, err := store.Open(storeDir, "admin", "admin12345")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	dir := t.TempDir()
	settings := func() config.Settings {
		s := config.DefaultSettings(dir)
		s.Upstream.BaseURL = upstream.URL
		s.Upstream.RequestTimeoutSec = 3
		s.Upstream.StreamIdleTimeoutSec = 2
		return s
	}

	bridgeServer := httptest.NewServer(bridge)
	t.Cleanup(bridgeServer.Close)

	client := minimax.New(settings)
	return New(st, pool.New(st, settings), client, nil, settings, bridgeServer.URL), st
}

func TestReloginSignsInAndStoresTheVerifiedToken(t *testing.T) {
	var sawLogin map[string]any
	token := unsignedToken(t, map[string]any{"user_id": "1", "exp": time.Now().Add(30 * 24 * time.Hour).Unix()})

	api, st := newReloginHarness(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/login":
			_ = json.NewDecoder(r.Body).Decode(&sawLogin)
			_, _ = io.WriteString(w, `{"sessionId":"bridge-1"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/login/bridge-1":
			_, _ = io.WriteString(w, `{"status":"ok","token":"`+token+`","host":"https://agent.minimax.io"}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/login/bridge-1":
			_, _ = io.WriteString(w, `{"cancelled":true}`)
		default:
			http.NotFound(w, r)
		}
	}, "login@example.com")

	account := addAccount(t, st, map[string]any{
		"user_id": "9", "email": "a@b.c", "phone": "+14155550123",
	}, store.RegionGlobal)
	_, _ = st.UpdateAccount(account.ID, func(target *store.Account) {
		target.Email = "login@example.com"
		target.Password = "test-password"
		target.AutoLogin = true
		target.AgentID = "123"
		target.Status = store.StatusInvalid
	})
	account, _ = st.AccountByID(account.ID)

	if err := api.relogin(context.Background(), account); err != nil {
		t.Fatalf("relogin: %v", err)
	}

	if sawLogin["email"] != "login@example.com" || sawLogin["password"] != "test-password" {
		t.Errorf("bridge login payload = %v, want the stored credential", sawLogin)
	}
	stored, _ := st.AccountByID(account.ID)
	if stored.Token != token {
		t.Errorf("token was not replaced")
	}
	if stored.UserID != "557000000000000001" {
		t.Errorf("userId = %q, want the identity the upstream reported", stored.UserID)
	}
	if stored.Status != store.StatusActive {
		t.Errorf("status = %q, want active after a successful login", stored.Status)
	}
	if stored.LastLoginError != "" {
		t.Errorf("lastLoginError = %q, want empty", stored.LastLoginError)
	}
	if stored.LastLoginAt.IsZero() {
		t.Errorf("lastLoginAt was not recorded")
	}
}

func TestReloginRecordsAFailureWithoutTouchingTheToken(t *testing.T) {
	api, st := newReloginHarness(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/login":
			_, _ = io.WriteString(w, `{"sessionId":"bridge-2"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/login/bridge-2":
			_, _ = io.WriteString(w, `{"status":"error","error":"no password step: 账号未设置密码"}`)
		case r.Method == http.MethodDelete:
			_, _ = io.WriteString(w, `{"cancelled":true}`)
		default:
			http.NotFound(w, r)
		}
	}, "login@example.com")

	account := addAccount(t, st, map[string]any{"user_id": "9", "phone": "+14155550123"}, store.RegionGlobal)
	before := account.Token
	_, _ = st.UpdateAccount(account.ID, func(target *store.Account) {
		target.Email = "login@example.com"
		target.Password = "test-password"
		target.AutoLogin = true
	})
	account, _ = st.AccountByID(account.ID)

	if err := api.relogin(context.Background(), account); err == nil {
		t.Fatal("relogin succeeded, want the bridge's error")
	}
	stored, _ := st.AccountByID(account.ID)
	if stored.Token != before {
		t.Errorf("a failed login replaced the token")
	}
	if !strings.Contains(stored.LastLoginError, "未设置密码") {
		t.Errorf("lastLoginError = %q, want the bridge's reason", stored.LastLoginError)
	}
	if stored.LastLoginAt.IsZero() {
		t.Errorf("a failed attempt must still be recorded, or the loop retries in a spin")
	}
}

func TestAutoLoginDue(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	token := func(expiry time.Time) string {
		return unsignedToken(t, map[string]any{"user_id": "1", "exp": expiry.Unix()})
	}
	base := func() *store.Account {
		return &store.Account{
			Enabled: true, AutoLogin: true,
			Email: "a@b.c", Password: "pw",
			Token: token(now.Add(30 * 24 * time.Hour)),
		}
	}

	cases := []struct {
		name   string
		mutate func(*store.Account)
		want   bool
	}{
		{"fine for weeks", func(*store.Account) {}, false},
		{"close to expiry", func(a *store.Account) { a.Token = token(now.Add(24 * time.Hour)) }, true},
		{"invalid", func(a *store.Account) { a.Status = store.StatusInvalid }, true},
		{"disabled", func(a *store.Account) { a.Enabled = false }, false},
		{"switch off", func(a *store.Account) { a.AutoLogin = false }, false},
		{"no password", func(a *store.Account) { a.Password = "" }, false},
		{"no email", func(a *store.Account) { a.Email = "" }, false},
		{"tried a moment ago", func(a *store.Account) {
			a.Status = store.StatusInvalid
			a.LastLoginAt = now.Add(-time.Minute)
		}, false},
		{"token without an expiry", func(a *store.Account) { a.Token = "not-a-jwt" }, false},
	}
	for _, tc := range cases {
		account := base()
		tc.mutate(account)
		if got := autoLoginDue(account, now); got != tc.want {
			t.Errorf("%s: autoLoginDue = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCheckLoginCredential(t *testing.T) {
	if err := checkLoginCredential("a@b.c", "pw", true); err != nil {
		t.Errorf("complete credential rejected: %v", err)
	}
	if err := checkLoginCredential("", "pw", true); err == nil {
		t.Error("auto-login without an email was accepted")
	}
	if err := checkLoginCredential("a@b.c", "", true); err == nil {
		t.Error("auto-login without a password was accepted")
	}
	if err := checkLoginCredential("", "", false); err != nil {
		t.Errorf("switching auto-login off must not require a credential: %v", err)
	}
}

// The browser profile is shared, so a remembered session could belong to
// another account. The identity check is what keeps that session from replacing
// this account's token.
func TestReloginRejectsASessionForAnotherAccount(t *testing.T) {
	token := unsignedToken(t, map[string]any{"user_id": "1", "exp": time.Now().Add(30 * 24 * time.Hour).Unix()})
	api, st := newReloginHarness(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/login":
			_, _ = io.WriteString(w, `{"sessionId":"bridge-3"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/login/bridge-3":
			_, _ = io.WriteString(w, `{"status":"ok","token":"`+token+`"}`)
		case r.Method == http.MethodDelete:
			_, _ = io.WriteString(w, `{"cancelled":true}`)
		default:
			http.NotFound(w, r)
		}
	}, "someone-else@example.com")

	account := addAccount(t, st, map[string]any{"user_id": "9", "phone": "+14155550123"}, store.RegionGlobal)
	before := account.Token
	_, _ = st.UpdateAccount(account.ID, func(target *store.Account) {
		target.Email = "login@example.com"
		target.Password = "test-password"
		target.AutoLogin = true
	})
	account, _ = st.AccountByID(account.ID)

	if err := api.relogin(context.Background(), account); err == nil {
		t.Fatal("relogin accepted a session for a different account")
	}
	stored, _ := st.AccountByID(account.ID)
	if stored.Token != before {
		t.Error("a foreign session replaced the token")
	}
	if !strings.Contains(stored.LastLoginError, "另一个账号") {
		t.Errorf("lastLoginError = %q, want the identity mismatch", stored.LastLoginError)
	}
}
