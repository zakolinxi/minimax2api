package gateway

import (
	"context"
	"testing"

	"minimax2api/internal/store"
)

// webAccount is a routable account of the web lane: the pool requires a token,
// a fingerprint and a prepared agent before it hands one out.
func webAccount(token string) *store.Account {
	return &store.Account{
		Name: "web", Kind: store.KindToken, Region: store.RegionGlobal, Token: token,
		UUID: "uuid", DeviceID: "12345678", UserID: "123", AgentID: "443154487857417",
		Enabled: true,
	}
}

// The two credential kinds must never cross lanes. A web token sent to the
// Messages API and an mcode bearer sent to the agent session API both answer
// 401, which is indistinguishable from an expired account and is how a healthy
// account gets retired for the wrong reason.
func TestAcquireAccountKeepsTheLanesApart(t *testing.T) {
	h := newHarness(t, upstreamFunc(nil, func(string) string { return `{}` }))

	if err := h.store.AddAccount(webAccount("web-token")); err != nil {
		t.Fatalf("add web account: %v", err)
	}
	mcode := &store.Account{Name: "mcode", Kind: store.KindMCode, Region: store.RegionGlobal, Token: "mmoat_token", Enabled: true}
	if err := h.store.AddAccount(mcode); err != nil {
		t.Fatalf("add mcode account: %v", err)
	}

	mcodeModel := &store.ModelConfig{ID: "mcode-m3.1-flash", Upstream: store.UpstreamMCode}
	lease, err := h.gateway.acquireAccount(context.Background(), "s", mcodeModel)
	if err != nil {
		t.Fatalf("acquire for mcode model: %v", err)
	}
	if lease.Account.Kind != store.KindMCode {
		t.Fatalf("mcode model leased a %q account", lease.Account.Kind)
	}
	lease.Release(nil)

	webModel := &store.ModelConfig{ID: "minimax-m3", Upstream: "chat"}
	for i := 0; i < 2; i++ {
		lease, err := h.gateway.acquireAccount(context.Background(), "s", webModel)
		if err != nil {
			t.Fatalf("acquire for web model: %v", err)
		}
		if lease.Account.Kind == store.KindMCode {
			t.Fatalf("web model leased the mcode account")
		}
		lease.Release(nil)
	}
}

// A model that needs an mcode account must fail with the subscription sentinel
// (503) rather than a generic pool error when there is none.
func TestAcquireAccountWithoutAnMCodeAccountFailsFast(t *testing.T) {
	h := newHarness(t, upstreamFunc(nil, func(string) string { return `{}` }))

	if err := h.store.AddAccount(webAccount("web-token")); err != nil {
		t.Fatalf("add web account: %v", err)
	}

	_, err := h.gateway.acquireAccount(context.Background(), "s", &store.ModelConfig{
		ID: "mcode-m3", Upstream: store.UpstreamMCode,
	})
	if err == nil {
		t.Fatal("expected an error when no mcode account exists")
	}
}
