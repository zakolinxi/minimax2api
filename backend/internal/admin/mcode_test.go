package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"minimax2api/internal/minimax"
	"minimax2api/internal/store"
)

func newMCodeTestAPI(t *testing.T) (*API, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir(), "admin", "admin12345")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, nil, nil, nil, st.Settings, ""), st
}

// A device authorization produces an account that the pool can actually route:
// the pair is persisted, the expiry is kept (the access token is opaque), and
// the view reports the renewable half without leaking either token.
func TestAddMCodeAccountPersistsThePair(t *testing.T) {
	api, st := newMCodeTestAPI(t)
	expiry := time.Now().Add(12 * time.Hour).Truncate(time.Second)

	account, err := api.addMCodeAccount(&minimax.MCodeTokens{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		ExpiresAt:    expiry,
	}, store.RegionGlobal, "", "设备码登录")
	if err != nil {
		t.Fatalf("add account: %v", err)
	}
	if account.Kind != store.KindMCode || account.Token != "test-access-token" || account.RefreshToken != "test-refresh-token" {
		t.Fatalf("account = %+v", account)
	}
	if !account.TokenExpiresAt.Equal(expiry) {
		t.Fatalf("expiry = %s, want %s", account.TokenExpiresAt, expiry)
	}
	if account.Group != "mcode" || !account.Enabled {
		t.Fatalf("account = %+v", account)
	}

	stored, ok := st.AccountByID(account.ID)
	if !ok {
		t.Fatal("account was not persisted")
	}
	view := store.NewAccountView(stored, 0)
	if !view.HasRefreshToken {
		t.Fatal("view must report the refresh token without exposing it")
	}
	if view.TokenMasked == "test-access-token" || view.TokenMasked == "" {
		t.Fatalf("masked token = %q", view.TokenMasked)
	}
	if view.Kind != store.KindMCode {
		t.Fatalf("view kind = %q", view.Kind)
	}
}

// An unknown flow id is a 404, not an empty success: the console polls this
// endpoint and would otherwise spin forever.
func TestGetMCodeDeviceUnknownFlowIs404(t *testing.T) {
	api, _ := newMCodeTestAPI(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/accounts/mcode/device/missing", nil)
	req.SetPathValue("id", "missing")

	api.getMCodeDevice(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// A refresh token is optional: an access token alone is still a usable account,
// it just has no expiry to renew against.
func TestAddMCodeAccountAllowsAnAccessTokenOnly(t *testing.T) {
	api, st := newMCodeTestAPI(t)
	account, err := api.addMCodeAccount(&minimax.MCodeTokens{AccessToken: "test-access-only"}, store.RegionCN, "named", "")
	if err != nil {
		t.Fatalf("add account: %v", err)
	}
	if account.RefreshToken != "" || !account.TokenExpiresAt.IsZero() {
		t.Fatalf("account = %+v", account)
	}
	if account.Name != "named" || account.Region != store.RegionCN {
		t.Fatalf("account = %+v", account)
	}
	if _, ok := st.AccountByID(account.ID); !ok {
		t.Fatal("account was not persisted")
	}
}
