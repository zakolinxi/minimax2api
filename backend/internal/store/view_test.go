package store

import (
	"encoding/json"
	"strings"
	"testing"
)

// The password is the one stored secret the console must never receive. The
// view is a state file's public face, so this pins the projection rather than
// trusting every handler to remember.
func TestAccountViewNeverCarriesThePassword(t *testing.T) {
	account := &Account{
		ID: "acc_1", Name: "primary", Email: "login@example.com",
		Password: "test-password", AutoLogin: true, Token: "tok",
	}
	view := NewAccountView(account, 0)
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal view: %v", err)
	}
	if strings.Contains(string(raw), "test-password") {
		t.Fatalf("the password leaked into the API view: %s", raw)
	}
	if !view.HasPassword {
		t.Error("hasPassword = false, want true so the console can say one is stored")
	}
	if view.Email != "login@example.com" || !view.AutoLogin {
		t.Errorf("view = %+v, want the login email and the switch", view)
	}
}
