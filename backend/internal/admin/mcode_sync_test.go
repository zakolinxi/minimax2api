package admin

import (
	"testing"

	"minimax2api/internal/minimax"
	"minimax2api/internal/store"
)

func mcodeEntry(id, upstreamID string, enabled bool) *store.ModelConfig {
	return &store.ModelConfig{
		ID: id, Upstream: store.UpstreamMCode, UpstreamModel: upstreamID,
		Type: store.ModelTypeChat, Enabled: enabled,
	}
}

// The sync owns capabilities, never ownership: an entry the operator disabled
// must stay disabled, and an entry the upstream dropped must be disabled rather
// than deleted (its counters and notes live on it).
func TestPlanMCodeSyncDiffsByUpstreamModel(t *testing.T) {
	existing := []*store.ModelConfig{
		mcodeEntry("mcode-m3", "MiniMax-M3", true),
		mcodeEntry("mcode-m3.1-flash", "MiniMax-M3.1-Flash", false),
		mcodeEntry("mcode-m2", "MiniMax-M2", true),
		{ID: "minimax-agent", Upstream: "agent", Type: store.ModelTypeChat, Enabled: true},
	}
	catalog := []minimax.MCodeModel{
		{ID: "MiniMax-M3", Name: "M3", ContextLimit: 512000, ContextWindows: []int{512000, 1000000},
			Thinking: "switchable"},
		{ID: "MiniMax-M3.1-Flash", Name: "M3.1-Flash", ContextLimit: 512000,
			Thinking: "forced_on", EffortOptions: []string{"default", "high", " "}, DefaultEffort: "default"},
		{ID: "MiniMax-M4", Name: "M4", ContextLimit: 0, ContextWindows: []int{1000000},
			Thinking: "bogus"},
	}

	adds, updates, disabled := planMCodeSync(existing, catalog)

	if len(adds) != 1 || adds[0].ID != "mcode-m4" || adds[0].UpstreamModel != "MiniMax-M4" {
		t.Fatalf("adds = %+v", adds)
	}
	if adds[0].ContextLimit != 1000000 {
		t.Fatalf("context limit should fall back to the first window: %+v", adds[0])
	}
	if adds[0].ThinkingMode != "" {
		t.Fatalf("an unknown thinking mode must not be copied: %q", adds[0].ThinkingMode)
	}
	if adds[0].Enabled != true || adds[0].Builtin {
		t.Fatalf("a new entry starts enabled and non-builtin: %+v", adds[0])
	}

	if len(updates) != 2 {
		t.Fatalf("updates = %+v", updates)
	}
	byID := map[string]mcodeModelUpdate{}
	for _, update := range updates {
		byID[update.ID] = update
	}
	if cap := byID["mcode-m3.1-flash"].Cap; len(cap.EffortOptions) != 2 || cap.EffortOptions[1] != "high" {
		t.Fatalf("effort options = %+v", cap.EffortOptions)
	}
	if cap := byID["mcode-m3.1-flash"].Cap; cap.ThinkingMode != "forced_on" || cap.DefaultEffort != "default" {
		t.Fatalf("capabilities = %+v", cap)
	}

	if len(disabled) != 1 || disabled[0] != "mcode-m2" {
		t.Fatalf("disabled = %v", disabled)
	}
}

// The id is derived once; a later sync matches on the upstream model, so an
// operator-created entry with the derived id must not be shadowed.
func TestPlanMCodeSyncAvoidsIDCollisions(t *testing.T) {
	existing := []*store.ModelConfig{
		{ID: "mcode-m4", Upstream: "chat", Type: store.ModelTypeChat, Enabled: true},
	}
	catalog := []minimax.MCodeModel{{ID: "MiniMax-M4", Name: "M4", ContextLimit: 1000}}

	adds, updates, disabled := planMCodeSync(existing, catalog)
	if len(adds) != 1 || adds[0].ID != "mcode-m4-2" {
		t.Fatalf("adds = %+v", adds)
	}
	if len(updates) != 0 || len(disabled) != 0 {
		t.Fatalf("updates=%v disabled=%v", updates, disabled)
	}
}

// Re-syncing the same catalog is a no-op apart from capability refreshes: no
// duplicate entries, nothing disabled.
func TestPlanMCodeSyncIsIdempotent(t *testing.T) {
	catalog := []minimax.MCodeModel{
		{ID: "MiniMax-M3", Name: "M3", ContextLimit: 512000},
		{ID: "MiniMax-M3.1-Flash", Name: "M3.1-Flash", ContextLimit: 512000},
	}
	existing := []*store.ModelConfig{
		mcodeEntry("mcode-m3", "MiniMax-M3", true),
		mcodeEntry("mcode-m3.1-flash", "MiniMax-M3.1-Flash", true),
	}
	adds, updates, disabled := planMCodeSync(existing, catalog)
	if len(adds) != 0 || len(updates) != 2 || len(disabled) != 0 {
		t.Fatalf("adds=%d updates=%d disabled=%v", len(adds), len(updates), disabled)
	}
}
