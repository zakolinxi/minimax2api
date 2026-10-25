package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"minimax2api/internal/config"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir(), "admin", "admin12345")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestSaveAccountStateCallbackReadsSettings is a regression guard for a total
// service deadlock. Mutation callbacks run while the write lock is held, and
// production callbacks (admin.syncQuota, pool.release) read settings from
// inside them. Go's sync.RWMutex is not reentrant, so if Settings() took the
// read lock the goroutine would wait on itself forever and every subsequent
// request would block behind the leaked write lock.
func TestSaveAccountStateCallbackReadsSettings(t *testing.T) {
	st := newTestStore(t)

	account := &Account{Name: "probe", Token: "jwt-token-x", Enabled: true}
	if err := st.AddAccount(account); err != nil {
		t.Fatalf("add account: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		st.SaveAccountState(account.ID, func(target *Account) {
			// Mirrors admin.syncQuota: read settings from within the callback.
			target.CooldownUntil = time.Now().Add(st.Settings().CooldownBase())
			target.Status = StatusCooldown
		})
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("SaveAccountState deadlocked: callback could not read Settings")
	}

	updated, ok := st.AccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared")
	}
	if updated.Status != StatusCooldown {
		t.Fatalf("callback mutation was not applied: status=%q", updated.Status)
	}
	if updated.CooldownUntil.IsZero() {
		t.Fatal("callback did not set CooldownUntil")
	}
}

// TestSettingsReadableUnderWriteLock covers every mutation helper that runs a
// caller supplied callback under the write lock.
func TestSettingsReadableUnderWriteLock(t *testing.T) {
	st := newTestStore(t)

	account := &Account{Name: "probe", Token: "jwt-token-x", Enabled: true}
	if err := st.AddAccount(account); err != nil {
		t.Fatalf("add account: %v", err)
	}
	key, err := st.CreateClientKey("probe-key", 10, 2)
	if err != nil {
		t.Fatalf("create client key: %v", err)
	}

	cases := []struct {
		name string
		run  func()
	}{
		{"UpdateAccount", func() {
			if _, err := st.UpdateAccount(account.ID, func(a *Account) {
				a.Priority = 1 + int(st.Settings().Routing.CooldownBaseSec%9)
			}); err != nil {
				t.Errorf("UpdateAccount: %v", err)
			}
		}},
		{"UpdateAccounts", func() {
			if _, err := st.UpdateAccounts([]string{account.ID}, func(a *Account) {
				a.MaxConcurrent = 1 + int(st.Settings().Routing.MaxAttempts)
			}); err != nil {
				t.Errorf("UpdateAccounts: %v", err)
			}
		}},
		{"UpdateClientKey", func() {
			if _, err := st.UpdateClientKey(key.ID, func(k *ClientKey) {
				k.RPMLimit = 30 + st.Settings().Audit.RetentionDays
			}); err != nil {
				t.Errorf("UpdateClientKey: %v", err)
			}
		}},
		{"UpdateModel", func() {
			models := st.ListModels()
			if len(models) == 0 {
				return
			}
			if _, err := st.UpdateModel(models[0].ID, func(m *ModelConfig) {
				m.Description = "probe-" + st.Settings().Routing.Strategy
			}); err != nil {
				t.Errorf("UpdateModel: %v", err)
			}
		}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.run()
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s deadlocked: callback could not read Settings", tc.name)
			}
		})
	}
}

// TestSettingsSnapshotFollowsUpdate makes sure the lock-free snapshot stays in
// sync with the persisted state after a settings change.
func TestSettingsSnapshotFollowsUpdate(t *testing.T) {
	st := newTestStore(t)

	if err := st.UpdateSettings(func(s *config.Settings) {
		s.Routing.CooldownBaseSec = 123
		s.Audit.RetentionDays = 11
	}); err != nil {
		t.Fatalf("update settings: %v", err)
	}

	if got := st.Settings().Routing.CooldownBaseSec; got != 123 {
		t.Fatalf("snapshot not refreshed: cooldownBaseSec=%d", got)
	}
	if got := st.Settings().CooldownBase(); got != 123*time.Second {
		t.Fatalf("derived duration wrong: %v", got)
	}

	// A fresh store reading the same directory must observe the persisted value.
	// Persistence is debounced, so force a flush before reopening.
	if err := st.Save(); err != nil {
		t.Fatalf("flush store: %v", err)
	}
	reopened, err := Open(st.DataDir(), "admin", "admin12345")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if got := reopened.Settings().Routing.CooldownBaseSec; got != 123 {
		t.Fatalf("persisted settings not reloaded: %d", got)
	}
}

// TestConcurrentSettingsReadsAndWrites exercises the atomic snapshot under the
// race detector.
func TestConcurrentSettingsReadsAndWrites(t *testing.T) {
	st := newTestStore(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = st.Settings().CooldownBase()
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stop)
		for i := 0; i < 50; i++ {
			if err := st.UpdateSettings(func(s *config.Settings) {
				s.Routing.CooldownBaseSec = 10 + i
			}); err != nil {
				t.Errorf("update settings: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}

// ListAccounts and AccountByID must hand out detached copies. The pool reads
// account fields outside of any lock, so returning pointers into the live state
// would race with SaveAccountState mutating those same objects.
func TestListAccountsReturnsDetachedSnapshot(t *testing.T) {
	st := newTestStore(t)

	account := &Account{ID: "acc_1", Name: "primary", Token: "jwt-token-x", Enabled: true}
	if err := st.AddAccount(account); err != nil {
		t.Fatalf("add account: %v", err)
	}

	snapshot := st.ListAccounts()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot length = %d, want 1", len(snapshot))
	}

	// Mutating the snapshot must not reach the store.
	snapshot[0].Status = "tampered"
	snapshot[0].Token = "tampered"
	snapshot[0].Priority = 999
	snapshot[0].Quota = &Quota{Plan: "tampered"}

	live, ok := st.AccountByID("acc_1")
	if !ok {
		t.Fatal("account missing")
	}
	if live.Status == "tampered" || live.Token == "tampered" || live.Priority == 999 {
		t.Fatalf("snapshot mutation leaked into the store: %+v", live)
	}
	if live.Quota != nil && live.Quota.Plan == "tampered" {
		t.Fatal("nested quota pointer was shared with the snapshot")
	}

	// And the reverse: a store mutation must not rewrite an earlier snapshot.
	before := st.ListAccounts()[0]
	st.SaveAccountState("acc_1", func(a *Account) {
		a.Status = StatusInvalid
		a.FailCount = 7
	})
	if before.Status == StatusInvalid || before.FailCount == 7 {
		t.Fatal("store mutation rewrote an already returned snapshot")
	}
}

func TestAccountByIDReturnsDetachedCopy(t *testing.T) {
	st := newTestStore(t)

	account := &Account{ID: "acc_1", Name: "primary", Token: "jwt-token-x", Enabled: true}
	if err := st.AddAccount(account); err != nil {
		t.Fatalf("add account: %v", err)
	}

	first, ok := st.AccountByID("acc_1")
	if !ok {
		t.Fatal("account missing")
	}
	second, ok := st.AccountByID("acc_1")
	if !ok {
		t.Fatal("account missing on second read")
	}
	if first == second {
		t.Fatal("AccountByID returned the same pointer twice; callers could race on it")
	}

	if _, ok := st.AccountByID("nope"); ok {
		t.Fatal("unknown id reported as found")
	}
}

// --- repairing a settings file an older build wrote -------------------------

// TestOpeningARepairedSettingsFileWritesTheRepairBack covers the half of a
// settings migration that is easy to leave out.
//
// Normalize fixes the value in memory, which is enough to make the process work
// — but the file keeps the old value, so the file describes a configuration the
// process is not using. That disagreement is not cosmetic: it is precisely how a
// broken default outlives a fix to the default, because the next reader sees a
// perfectly ordinary-looking path and concludes the fix did not apply.
func TestOpeningARepairedSettingsFileWritesTheRepairBack(t *testing.T) {
	dir := t.TempDir()

	// Seed a settings file the way an earlier build would have left it: the
	// whole default set written out, including the two values that cannot work.
	//
	// The rest of the state is seeded too, and that part is not decoration. An
	// empty admin makes Open write a snapshot of its own while creating the
	// account, which would carry the repaired settings to disk by accident and
	// let this test pass with the write-back removed.
	seeded := config.DefaultSettings(dir)
	seeded.Upstream.SessionPath = "/agent/{agent_id}/session"
	seeded.Upstream.AgentID = "general"
	raw, err := json.Marshal(State{
		Version:  schemaVersion,
		Admin:    Admin{Username: "admin", Salt: "seeded", PasswordHash: "seeded"},
		Settings: seeded,
		Models:   BuiltinModels(),
	})
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFile), raw, 0o644); err != nil {
		t.Fatalf("seed %s: %v", stateFile, err)
	}

	st, err := Open(dir, "admin", "admin12345")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	// The live settings are repaired...
	live := st.Settings()
	if live.Upstream.SessionPath != config.DefaultSettings(dir).Upstream.SessionPath {
		t.Errorf("live session path = %q, want it repaired", live.Upstream.SessionPath)
	}
	if live.Upstream.AgentID == "general" {
		t.Errorf("live agent id is still the role name %q", live.Upstream.AgentID)
	}

	// ...and so is the file, which is what this test is about. The write is
	// queued rather than immediate, so give the loop a moment.
	var onDisk config.Settings
	deadline := time.Now().Add(3 * time.Second)
	for {
		content, readErr := os.ReadFile(filepath.Join(dir, stateFile))
		if readErr == nil {
			var got State
			if json.Unmarshal(content, &got) == nil {
				onDisk = got.Settings
				if onDisk.Upstream.SessionPath == live.Upstream.SessionPath &&
					onDisk.Upstream.AgentID == live.Upstream.AgentID {
					break
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the repair never reached %s: sessionPath=%q agentID=%q",
				stateFile, onDisk.Upstream.SessionPath, onDisk.Upstream.AgentID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A built-in added by a later release has to reach installs that already exist.
//
// `Open` seeds the catalogue only when it is empty, and a fresh install freezes
// a copy of every built-in into the state file — so a release that adds a model
// would ship it to new users only. There is no symptom on anyone else's machine:
// the stored list looks like a perfectly ordinary catalogue, just a shorter one.
// That is the same trap the settings defaults fall into, and it is worth a test
// because the failure is invisible rather than loud.
func TestOpeningAnOlderCatalogueAddsNewBuiltins(t *testing.T) {
	dir := t.TempDir()

	// Seed the catalogue as an earlier release left it: every built-in except
	// the video ones, with one entry deliberately disabled and one carrying
	// usage counters. Those two details are the point — a merge that replaced
	// the stored list instead of extending it would silently re-enable a model
	// the operator turned off and zero their statistics.
	older := make([]*ModelConfig, 0, 4)
	for _, model := range BuiltinModels() {
		if model.Type == ModelTypeVideo {
			continue
		}
		older = append(older, model)
	}
	if len(older) == 0 {
		t.Fatal("the catalogue has no chat entries to seed with")
	}
	older[0].Enabled = false
	older[0].Requests = 42
	older[0].Tokens = 1234

	raw, err := json.Marshal(State{
		Version:  schemaVersion,
		Admin:    Admin{Username: "admin", Salt: "seeded", PasswordHash: "seeded"},
		Settings: config.DefaultSettings(dir),
		Models:   older,
	})
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFile), raw, 0o644); err != nil {
		t.Fatalf("seed %s: %v", stateFile, err)
	}

	st, err := Open(dir, "admin", "admin12345")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	// Every built-in is present...
	for _, builtin := range BuiltinModels() {
		got, ok := st.ModelByID(builtin.ID)
		if !ok {
			t.Errorf("built-in %q never reached an existing install", builtin.ID)
			continue
		}
		if builtin.Type == ModelTypeVideo && got.UpstreamModel == "" {
			t.Errorf("video model %q has no upstream model id, so a generation request would carry nothing", builtin.ID)
		}
	}

	// ...and the stored state of the entries that were already there is intact.
	kept, ok := st.ModelByID(older[0].ID)
	if !ok {
		t.Fatalf("pre-existing model %q disappeared", older[0].ID)
	}
	if kept.Enabled {
		t.Errorf("model %q was re-enabled by the merge; the operator's choice was overwritten", older[0].ID)
	}
	if kept.Requests != 42 || kept.Tokens != 1234 {
		t.Errorf("model %q lost its counters: requests=%d tokens=%d", older[0].ID, kept.Requests, kept.Tokens)
	}

	// The merge is written back, for the same reason a repaired setting is: a
	// file that describes a shorter catalogue than the process is serving makes
	// the next release do this work again.
	var onDisk State
	deadline := time.Now().Add(3 * time.Second)
	for {
		if content, readErr := os.ReadFile(filepath.Join(dir, stateFile)); readErr == nil {
			if json.Unmarshal(content, &onDisk) == nil && len(onDisk.Models) == len(BuiltinModels()) {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the merged catalogue never reached %s: %d models", stateFile, len(onDisk.Models))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Merging twice must be a no-op, or every open would append duplicates.
func TestMergeBuiltinModelsIsIdempotent(t *testing.T) {
	merged, changed := MergeBuiltinModels(nil)
	if !changed {
		t.Fatal("an empty catalogue should gain every built-in")
	}
	again, changedAgain := MergeBuiltinModels(merged)
	if changedAgain {
		t.Error("merging an already-complete catalogue reported a change")
	}
	if len(again) != len(merged) {
		t.Errorf("merge duplicated entries: %d -> %d", len(merged), len(again))
	}
}

// The plan requirement is adopted by existing installs the same way the
// upstream id is: it is a fact the console cannot edit, so a false value on a
// stored built-in is a freeze of an older catalogue rather than a choice. The
// old billing note is rewritten only while it is still the built-in's own
// wording, so an operator's description edit survives.
func TestMergeBuiltinModelsAdoptsSubscriptionRequirement(t *testing.T) {
	modelByID := func(models []*ModelConfig, id string) *ModelConfig {
		for _, model := range models {
			if model.ID == id {
				return model
			}
		}
		return nil
	}

	stored := BuiltinModels()
	for _, model := range stored {
		model.SubscriptionOnly = false
	}
	modelByID(stored, "minimax-h3").Description = legacyModelDescriptions["minimax-h3"]
	modelByID(stored, "minimax-h3-max").Description = "我自己写的说明"

	merged, changed := MergeBuiltinModels(stored)
	if !changed {
		t.Fatal("a catalogue without the plan requirement should report a change")
	}
	for _, id := range []string{"minimax-h3", "minimax-h3-max"} {
		if got := modelByID(merged, id); got == nil || !got.SubscriptionOnly {
			t.Errorf("model %q did not adopt the plan requirement", id)
		}
	}
	if got, want := modelByID(merged, "minimax-h3").Description, modelByID(BuiltinModels(), "minimax-h3").Description; got != want {
		t.Errorf("the stale billing note survived: %q", got)
	}
	if got := modelByID(merged, "minimax-h3-max").Description; got != "我自己写的说明" {
		t.Errorf("the merge overwrote an operator's description: %q", got)
	}
	if _, changedAgain := MergeBuiltinModels(merged); changedAgain {
		t.Error("merging an already-updated catalogue reported a change")
	}
}

// Subscribed is the routing rule for plan-only models, so every boundary of it
// is pinned: no reading is not a subscription, and the free label is matched
// without case or surrounding space.
func TestAccountSubscribed(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		credit *Credit
		want   bool
	}{
		{"no reading", nil, false},
		{"empty plan", &Credit{}, false},
		{"free", &Credit{PlanName: "Free"}, false},
		{"free lowercase and spaced", &Credit{PlanName: " free "}, false},
		{"basic", &Credit{PlanName: "Basic"}, true},
		{"pro", &Credit{PlanName: "Pro"}, true},
		{"token plan expiry in the future", &Credit{TokenPlanTier: "Pro", TokenPlanExpiresAt: now.Add(24 * time.Hour)}, true},
		{"token plan without a date", &Credit{TokenPlanTier: "Basic"}, true},
		{"token plan expired", &Credit{TokenPlanTier: "Pro", TokenPlanExpiresAt: now.Add(-time.Hour)}, false},
		// The Token Plan reading wins: an expired subscription must not stay in
		// rotation just because the older membership label still says Pro.
		{"expired token plan with a paid membership name", &Credit{PlanName: "Pro", TokenPlanTier: "Pro", TokenPlanExpiresAt: now.Add(-time.Hour)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			account := &Account{Credit: tc.credit}
			if got := account.Subscribed(); got != tc.want {
				t.Fatalf("Subscribed() = %v, want %v", got, tc.want)
			}
		})
	}
	var missing *Account
	if missing.Subscribed() {
		t.Error("a nil account reported a subscription")
	}
}

// An upstream model id added to an existing built-in has to reach installs that
// already hold that entry. There is no console and no API that sets
// UpstreamModel, so an empty value on a stored built-in is a freeze of an older
// default — never the operator's choice — and the merge adopts the new id
// without touching enablement, counters or anything else the operator owns.
func TestMergeBuiltinModelsBackfillsUpstreamModel(t *testing.T) {
	stored := BuiltinModels()
	for _, model := range stored {
		model.UpstreamModel = "" // as an older release froze it
	}
	modelByID := func(models []*ModelConfig, id string) *ModelConfig {
		for _, model := range models {
			if model.ID == id {
				return model
			}
		}
		return nil
	}
	disabled := modelByID(stored, "minimax-m3")
	disabled.Enabled = false
	disabled.Requests = 7

	merged, changed := MergeBuiltinModels(stored)
	if !changed {
		t.Fatal("a catalogue stripped of upstream ids should report a change")
	}
	for _, builtin := range BuiltinModels() {
		if builtin.UpstreamModel == "" {
			continue
		}
		got := modelByID(merged, builtin.ID)
		if got == nil {
			t.Fatalf("built-in %q vanished", builtin.ID)
		}
		if got.UpstreamModel != builtin.UpstreamModel {
			t.Errorf("model %q upstream = %q, want %q", builtin.ID, got.UpstreamModel, builtin.UpstreamModel)
		}
	}
	if modelByID(merged, "minimax-m3").Enabled {
		t.Error("the merge re-enabled a model the operator had turned off")
	}
	if got := modelByID(merged, "minimax-m3"); got.Requests != 7 {
		t.Errorf("the merge reset usage counters: requests=%d", got.Requests)
	}
	// Entries that carry no upstream id stay that way — the agent entry has
	// always served whatever the account defaults to.
	if got := modelByID(merged, "minimax-agent").UpstreamModel; got != "" {
		t.Errorf("minimax-agent grew an upstream id %q", got)
	}
}

// The generation ranges have to reach installs that already hold the entry, for
// the same reason the upstream id does — and the failure is worse here. A
// missing id shows up as a request that goes nowhere; a missing range shows up
// as nothing at all, because the gateway simply stops repairing unsupported
// values and every request still succeeds.
func TestMergeBuiltinModelsBackfillsVideoRanges(t *testing.T) {
	stored := BuiltinModels()
	for _, model := range stored {
		model.Ratios, model.Resolutions, model.Durations = nil, nil, nil
	}
	modelByID := func(models []*ModelConfig, id string) *ModelConfig {
		for _, model := range models {
			if model.ID == id {
				return model
			}
		}
		return nil
	}

	merged, changed := MergeBuiltinModels(stored)
	if !changed {
		t.Fatal("a catalogue stripped of its ranges should report a change")
	}

	for _, builtin := range BuiltinModels() {
		if len(builtin.Resolutions) == 0 {
			continue
		}
		got := modelByID(merged, builtin.ID)
		if got == nil {
			t.Fatalf("built-in %q vanished", builtin.ID)
		}
		if len(got.Ratios) != len(builtin.Ratios) || len(got.Durations) != len(builtin.Durations) {
			t.Errorf("model %q ratios=%v durations=%v, want %v and %v",
				builtin.ID, got.Ratios, got.Durations, builtin.Ratios, builtin.Durations)
		}
		if len(got.Resolutions) != len(builtin.Resolutions) {
			t.Errorf("model %q resolutions = %v, want %v", builtin.ID, got.Resolutions, builtin.Resolutions)
		}
	}

	// Hailuo has no recorded ranges, and the merge must not invent any: an
	// empty set means "unconstrained", and a range filled in from the H3
	// variants would start rejecting requests the upstream may accept.
	hailuo := modelByID(merged, "minimax-hailuo-2-3")
	if hailuo == nil {
		t.Fatal("the Hailuo entry vanished")
	}
	if len(hailuo.Ratios) != 0 || len(hailuo.Resolutions) != 0 || len(hailuo.Durations) != 0 {
		t.Errorf("the merge invented ranges for an unread model: %v %v %v",
			hailuo.Ratios, hailuo.Resolutions, hailuo.Durations)
	}
	if _, changedAgain := MergeBuiltinModels(merged); changedAgain {
		t.Error("merging an already-backfilled catalogue reported a change")
	}
}

// The reference cap reaches existing installs the same way the ranges do, and
// it has the same trap: zero means "unconstrained", so a missing cap has no
// symptom on this side at all. The gateway simply stops trimming, every request
// still succeeds, and the party that notices is the upstream — which answers a
// picture it has nowhere to put by asking the caller to choose.
func TestMergeBuiltinModelsBackfillsTheReferenceCap(t *testing.T) {
	stored := BuiltinModels()
	for _, model := range stored {
		model.MaxReferences = 0
	}
	merged, changed := MergeBuiltinModels(stored)
	if !changed {
		t.Fatal("a catalogue stripped of its caps should report a change")
	}

	modelByID := func(id string) *ModelConfig {
		for _, model := range merged {
			if model.ID == id {
				return model
			}
		}
		return nil
	}
	if got := modelByID("minimax-h3-max"); got == nil || got.MaxReferences != 2 {
		t.Errorf("H3-Max cap = %v, want 2 (a first and a last frame)", got)
	}
	// Zero is a real value, not a gap: H3.0 takes a reference set rather than a
	// frame pair, and Hailuo's panel has not been read. Neither may be given a
	// cap borrowed from the model next to it.
	for _, id := range []string{"minimax-h3", "minimax-hailuo-2-3"} {
		if got := modelByID(id); got == nil || got.MaxReferences != 0 {
			t.Errorf("%s cap = %v, want 0 (uncapped)", id, got)
		}
	}
}

// The context sizes and the thinking mode are upstream facts like the video
// ranges, and they fail the same way when they do not reach an existing
// install: silently. A frozen entry would answer every request at the default
// window and refuse to offer 1M, with nothing on screen to say why.
func TestMergeBuiltinModelsBackfillsContextAndThinking(t *testing.T) {
	stored := BuiltinModels()
	for _, model := range stored {
		model.ContextLimit, model.ContextWindows, model.ThinkingMode = 0, nil, ""
	}
	merged, changed := MergeBuiltinModels(stored)
	if !changed {
		t.Fatal("a catalogue stripped of its context facts should report a change")
	}
	modelByID := func(id string) *ModelConfig {
		for _, model := range merged {
			if model.ID == id {
				return model
			}
		}
		return nil
	}
	flash := modelByID("minimax-m3.1-flash")
	if flash == nil || flash.ContextLimit != 512000 {
		t.Fatalf("M3.1-Flash default window = %v, want 512000", flash)
	}
	if got := strings.Join(intStrings(flash.ContextWindows), "/"); got != "512000/1000000" {
		t.Errorf("M3.1-Flash windows = %s, want 512000/1000000", got)
	}
	if flash.ThinkingMode != "forced_on" {
		t.Errorf("M3.1-Flash thinking = %q, want forced_on", flash.ThinkingMode)
	}
	m3 := modelByID("minimax-m3")
	if m3 == nil || m3.ThinkingMode != "switchable" {
		t.Fatalf("M3 thinking = %v, want switchable", m3)
	}
	// No options means no choice, which is a different state from "not read":
	// the default still goes out, it just cannot be changed.
	if len(m3.ContextWindows) != 0 {
		t.Errorf("M3 grew windows %v", m3.ContextWindows)
	}
	// The agent entry has no model at all, so none of this applies to it.
	if agent := modelByID("minimax-agent"); agent == nil || agent.ContextLimit != 0 || agent.ThinkingMode != "" {
		t.Errorf("minimax-agent grew upstream facts: %+v", agent)
	}
}

func intStrings(values []int) []string {
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = strconv.Itoa(value)
	}
	return out
}

// The two H3 variants differ in resolution and agree on everything else. That
// difference is the whole reason the ranges are per model rather than global,
// so it is pinned here: a request that is valid on one and not the other is the
// case the gateway exists to repair.
func TestBuiltinVideoRangesDifferByResolutionOnly(t *testing.T) {
	models := make(map[string]*ModelConfig)
	for _, model := range BuiltinModels() {
		models[model.ID] = model
	}
	h3, h3Max := models["minimax-h3"], models["minimax-h3-max"]
	if h3 == nil || h3Max == nil {
		t.Fatal("both H3 variants must be in the catalogue")
	}
	if strings.Join(h3.Ratios, ",") != strings.Join(h3Max.Ratios, ",") {
		t.Errorf("ratios differ: %v vs %v", h3.Ratios, h3Max.Ratios)
	}
	if len(h3.Durations) != len(h3Max.Durations) {
		t.Errorf("durations differ: %v vs %v", h3.Durations, h3Max.Durations)
	}
	if got := strings.Join(h3Max.Resolutions, "/"); got != "480P/768P" {
		t.Errorf("H3-Max resolutions = %s, want 480P/768P", got)
	}
	if got := strings.Join(h3.Resolutions, "/"); got != "768P/2K" {
		t.Errorf("H3.0 resolutions = %s, want 768P/2K", got)
	}
	// The durations are the panel's whole-second buttons, 5 through 15.
	for index, duration := range h3Max.Durations {
		if duration != 5+index {
			t.Fatalf("durations are not 5..15: %v", h3Max.Durations)
		}
	}
	if len(h3Max.Durations) != 11 {
		t.Errorf("durations = %v, want eleven of them", h3Max.Durations)
	}
}

// The catalogue must name every model the upstream's config endpoint lists, so
// a client filling its picker from /v1/models can select each of them.
func TestBuiltinModelsCoverTheUpstreamSelector(t *testing.T) {
	want := map[string]string{
		"minimax-agent":      "",
		"minimax-m3.1-flash": "MiniMax-M3.1-Flash",
		"minimax-m3":         "MiniMax-M3",
	}
	for _, model := range BuiltinModels() {
		expected, ok := want[model.ID]
		if !ok {
			continue
		}
		if model.UpstreamModel != expected {
			t.Errorf("model %q upstream = %q, want %q", model.ID, model.UpstreamModel, expected)
		}
		delete(want, model.ID)
	}
	for id := range want {
		t.Errorf("the catalogue has no entry for %q", id)
	}
}

// A retired built-in leaves the catalogue, counters or not.
//
// The entry is what every client shows in its picker, and the model behind it
// no longer exists upstream. Usage history survives in the audit log, which
// records the model id and token counts per call, so dropping the label is not
// the same as dropping the record.
func TestMergeBuiltinModelsRetiresEntriesWithUsageToo(t *testing.T) {
	stored := []*ModelConfig{
		{ID: "minimax-m2.7", Name: "MiniMax M2.7", Builtin: true, Enabled: true},
		{ID: "minimax-m2.7-highspeed", Name: "MiniMax M2.7 HighSpeed", Builtin: true, Enabled: true, Requests: 3, Tokens: 1200},
		{ID: "minimax-m3.1-flash-preview", Name: "MiniMax M3.1 Flash Preview", Builtin: true, Enabled: true},
		{ID: "minimax-m3-thinking", Name: "MiniMax M3 Thinking", Builtin: true, Enabled: true, Requests: 9},
	}
	merged, changed := MergeBuiltinModels(stored)
	if !changed {
		t.Fatal("retiring entries and adding the released model must report a change")
	}
	byID := make(map[string]*ModelConfig, len(merged))
	for _, model := range merged {
		byID[model.ID] = model
	}
	for _, id := range []string{"minimax-m2.7", "minimax-m2.7-highspeed", "minimax-m3.1-flash-preview", "minimax-m3-thinking"} {
		if _, ok := byID[id]; ok {
			t.Errorf("%s is retired upstream; it must not stay in the catalogue", id)
		}
	}
	if _, ok := byID["minimax-m3.1-flash"]; !ok {
		t.Error("the released model must be added")
	}
	if _, again := MergeBuiltinModels(merged); again {
		t.Error("the retirement must be idempotent")
	}
}

// A cooldown that has run out must read as active.
//
// The status is persisted and only rewritten when the account is touched again,
// so an account that cooled down once and then went idle keeps reporting
// "cooldown" forever. Every read goes through the snapshot, so a stale value
// there made a fully recovered pool look drained in the admin list while /health
// — which evaluates the deadline — disagreed.
func TestExpiredCooldownReadsAsActive(t *testing.T) {
	expired := &Account{Status: StatusCooldown, CooldownUntil: time.Now().Add(-time.Minute)}
	snapshot := expired.clone()
	if snapshot.Status != StatusActive {
		t.Fatalf("expired cooldown status = %q, want active", snapshot.Status)
	}
	if !snapshot.CooldownUntil.IsZero() {
		t.Fatalf("expired cooldown deadline = %s, want zero", snapshot.CooldownUntil)
	}
	if expired.Status != StatusCooldown {
		t.Fatal("clone mutated the account it was reading")
	}

	live := &Account{Status: StatusCooldown, CooldownUntil: time.Now().Add(time.Minute)}
	if got := live.clone(); got.Status != StatusCooldown || got.CooldownUntil.IsZero() {
		t.Fatalf("live cooldown = %s/%s, want cooldown with its deadline kept", got.Status, got.CooldownUntil)
	}
}

// --- every pointer that leaves the store is detached -------------------------

// ListClientKeys, ClientKeyByValue, CreateClientKey and UpdateClientKey used to
// hand out the live objects, which raced with BumpClientKeyUsage writing the
// same structs under the write lock.
func TestClientKeySnapshotsAreDetached(t *testing.T) {
	st := newTestStore(t)

	created, err := st.CreateClientKey("probe", 10, 2)
	if err != nil {
		t.Fatalf("create client key: %v", err)
	}

	listed := st.ListClientKeys()
	if len(listed) != 1 {
		t.Fatalf("ListClientKeys returned %d keys, want 1", len(listed))
	}
	if listed[0] == created {
		t.Fatal("ListClientKeys returned the very pointer CreateClientKey handed out")
	}

	// Mutating every shape of snapshot must not reach the store.
	snapshot := listed[0]
	snapshot.Name = "tampered"
	snapshot.RPMLimit = 999
	snapshot.TotalRequests = 999
	if byValue, ok := st.ClientKeyByValue(created.Key); !ok {
		t.Fatal("ClientKeyByValue missed the key it just created")
	} else {
		byValue.Enabled = false
	}
	updated, err := st.UpdateClientKey(created.ID, func(k *ClientKey) { k.RPMLimit = 30 })
	if err != nil {
		t.Fatalf("update client key: %v", err)
	}
	updated.Enabled = false
	updated.TotalRequests = 12345

	fresh := st.ListClientKeys()
	if len(fresh) != 1 {
		t.Fatalf("ListClientKeys returned %d keys, want 1", len(fresh))
	}
	got := fresh[0]
	if got.Name == "tampered" || got.RPMLimit != 30 || got.TotalRequests != 0 || !got.Enabled {
		t.Fatalf("a returned client key aliased the store's own object: %+v", got)
	}
}

// The model snapshots must be deep copies: the generation ranges are slices,
// and a shared backing array would let a caller write into the live catalogue
// without holding the lock.
func TestModelSnapshotsAreDetached(t *testing.T) {
	st := newTestStore(t)

	models := st.ListModels()
	var video, flash *ModelConfig
	for _, model := range models {
		switch model.ID {
		case "minimax-h3":
			video = model
		case "minimax-m3.1-flash":
			flash = model
		}
	}
	if video == nil || flash == nil {
		t.Fatalf("catalogue incomplete: video=%v flash=%v", video, flash)
	}

	video.Ratios[0] = "tampered"
	video.Resolutions[0] = "tampered"
	video.Durations[0] = 999
	video.Enabled = false
	flash.ContextWindows[0] = -1

	updated, err := st.UpdateModel(video.ID, func(m *ModelConfig) { m.Description = "edited" })
	if err != nil {
		t.Fatalf("update model: %v", err)
	}
	updated.Name = "tampered"

	for _, model := range st.ListModels() {
		switch model.ID {
		case "minimax-h3":
			if !model.Enabled {
				t.Fatal("mutating a returned model reached the store")
			}
			if model.Ratios[0] != "21:9" || model.Resolutions[0] != "768P" || model.Durations[0] != 5 {
				t.Fatalf("a snapshot's slice shared a backing array with the store: %v %v %v",
					model.Ratios, model.Resolutions, model.Durations)
			}
			if model.Name == "tampered" || model.Description != "edited" {
				t.Fatalf("UpdateModel's return value aliased the live entry: %+v", model)
			}
		case "minimax-m3.1-flash":
			if model.ContextWindows[0] != 512000 {
				t.Fatalf("a snapshot's slice shared a backing array with the store: %v", model.ContextWindows)
			}
		}
	}
}

// UpdateAccount must return a snapshot like every other read path, and
// AddAccount must not leave the store aliasing the caller's object.
func TestAccountMutationsReturnDetachedCopies(t *testing.T) {
	st := newTestStore(t)

	account := &Account{ID: "acc_1", Name: "primary", Token: "jwt-token-x", Enabled: true}
	if err := st.AddAccount(account); err != nil {
		t.Fatalf("add account: %v", err)
	}
	if account.ID == "" {
		t.Fatal("AddAccount did not apply the generated id to the caller's object")
	}

	updated, err := st.UpdateAccount("acc_1", func(a *Account) { a.Priority = 7 })
	if err != nil {
		t.Fatalf("update account: %v", err)
	}
	updated.Priority = 999
	updated.Token = "tampered"
	// The caller keeps owning the object it passed in; the store must not.
	account.Name = "tampered-after-add"

	fresh, ok := st.AccountByID("acc_1")
	if !ok {
		t.Fatal("account missing")
	}
	if fresh.Priority != 7 || fresh.Token != "jwt-token-x" || fresh.Name != "primary" {
		t.Fatalf("a returned account aliased the store's own object: %+v", fresh)
	}
}

// The usage bumpers write the live objects under the write lock while request
// handlers read the List* results without any lock. With live pointers handed
// out this is exactly the race the detector catches; with detached copies it
// must run clean under -race.
func TestUsageCountersRaceFreeAgainstSnapshots(t *testing.T) {
	st := newTestStore(t)
	key, err := st.CreateClientKey("probe", 10, 2)
	if err != nil {
		t.Fatalf("create client key: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				st.BumpClientKeyUsage(key.ID)
				st.RecordModelUsage("minimax-h3", 1, 100)
			}
		}
	}()

	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		for _, k := range st.ListClientKeys() {
			k.TotalRequests = -1 // write through the snapshot
		}
		for _, m := range st.ListModels() {
			m.Requests = -1
		}
		if k, ok := st.ClientKeyByValue(key.Key); ok {
			k.Enabled = false
		}
	}
	close(stop)
	wg.Wait()

	fresh := st.ListClientKeys()
	if len(fresh) != 1 || fresh[0].TotalRequests < 0 || !fresh[0].Enabled {
		t.Fatalf("snapshot writes leaked into the store: %+v", fresh)
	}
}

// --- persistence of the paths that used to skip markDirty --------------------

// AppendAudit, BumpClientKeyUsage, RecordModelUsage and AddMedia only changed
// memory, so a crash lost everything since the last unrelated flush; and
// PurgeAudits resurrected the records it had dropped. Every one of them must
// survive a restart, and a purge must stay dead.
func TestUsageAndAuditMutationsPersistAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, "admin", "admin12345")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	key, err := st.CreateClientKey("probe", 10, 2)
	if err != nil {
		t.Fatalf("create client key: %v", err)
	}
	st.AppendAudit(&Audit{ID: "audit-new", CreatedAt: time.Now(), KeyName: "probe"})
	// Thirty days back is well beyond the default seven-day retention, so the
	// purge below has something to drop.
	st.AppendAudit(&Audit{ID: "audit-old", CreatedAt: time.Now().AddDate(0, 0, -30), KeyName: "probe"})
	st.BumpClientKeyUsage(key.ID)
	st.RecordModelUsage("minimax-h3", 2, 4096)
	st.AddMedia(&MediaItem{ID: "media-1", Kind: "image", URL: "https://cdn/x.png", CreatedAt: time.Now()})

	if err := st.Save(); err != nil {
		t.Fatalf("flush store: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	reopened, err := Open(dir, "admin", "admin12345")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	if got := reopened.ListAudits(); len(got) != 2 {
		t.Fatalf("audits did not survive the restart: %d", len(got))
	}
	if keys := reopened.ListClientKeys(); len(keys) != 1 || keys[0].TotalRequests != 1 {
		t.Fatalf("bumped usage did not survive the restart: %+v", keys)
	}
	if model, ok := reopened.ModelByID("minimax-h3"); !ok || model.Requests != 2 || model.Tokens != 4096 {
		t.Fatalf("recorded model usage did not survive the restart: %+v", model)
	}
	if got := reopened.ListMedia(); len(got) != 1 {
		t.Fatalf("media did not survive the restart: %d", len(got))
	}

	// The purge must reach the disk too, or the old record comes back on the
	// next restart.
	reopened.PurgeAudits()
	if got := reopened.ListAudits(); len(got) != 1 || got[0].ID != "audit-new" {
		t.Fatalf("purge dropped the wrong records: %+v", got)
	}
	if err := reopened.Save(); err != nil {
		t.Fatalf("flush store: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	again, err := Open(dir, "admin", "admin12345")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer func() { _ = again.Close() }()
	if got := again.ListAudits(); len(got) != 1 || got[0].ID != "audit-new" {
		t.Fatalf("a purged audit came back from the dead: %+v", got)
	}
}

// A failed UpdateSettings must leave the live state, the published snapshot and
// the file all untouched — previously the in-memory change survived while the
// snapshot and the file never learned about it.
func TestUpdateSettingsFailureLeavesStateUntouched(t *testing.T) {
	st := newTestStore(t)

	// A regular file where a directory is required makes MkdirAll fail.
	blocked := filepath.Join(st.DataDir(), "blocked")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	before := st.Settings()

	err := st.UpdateSettings(func(s *config.Settings) {
		s.Media.GeneratedDir = filepath.Join(blocked, "generated")
		s.Routing.CooldownBaseSec = 999
	})
	if err == nil {
		t.Fatal("UpdateSettings succeeded although the media dir cannot be created")
	}
	if got := st.Settings(); got != before {
		t.Fatalf("a failed UpdateSettings changed the live settings: %+v", got)
	}

	// And the file must not have learned about the abandoned change either.
	if err := st.Save(); err != nil {
		t.Fatalf("flush store: %v", err)
	}
	reopened, err := Open(st.DataDir(), "admin", "admin12345")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if got := reopened.Settings().Routing.CooldownBaseSec; got == 999 {
		t.Fatal("the abandoned settings change reached the disk")
	}
	if got := reopened.Settings().Media.GeneratedDir; got == filepath.Join(blocked, "generated") {
		t.Fatal("the abandoned media dir reached the disk")
	}
}

// A corrupt state file must not be silently destroyed by the next successful
// write: Open moves it aside, best effort, and refuses to start.
func TestOpenBacksUpACorruptStateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, stateFile)
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}

	st, err := Open(dir, "admin", "admin12345")
	if err == nil {
		_ = st.Close()
		t.Fatal("Open accepted a corrupt state file")
	}
	matches, globErr := filepath.Glob(path + ".corrupt-*")
	if globErr != nil || len(matches) != 1 {
		t.Fatalf("the damaged file was not backed up: %v %v", matches, globErr)
	}
	content, readErr := os.ReadFile(matches[0])
	if readErr != nil || string(content) != "{ this is not json" {
		t.Fatalf("the backup does not hold the original bytes: %q %v", content, readErr)
	}
}

// AppendAudit only queues a debounced write, so the loop's select used to be
// able to take the closed channel before the dirty one and drop the last
// change. Close must be a real final flush.
func TestCloseFlushesUnsavedChanges(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, "admin", "admin12345")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	st.AppendAudit(&Audit{ID: "final", CreatedAt: time.Now(), KeyName: "probe"})
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	reopened, err := Open(dir, "admin", "admin12345")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if got := reopened.ListAudits(); len(got) != 1 || got[0].ID != "final" {
		t.Fatalf("the last change before Close was lost: %+v", got)
	}
}

// Sessions only leave the map through an explicit revoke or the sweeps, so the
// map used to grow by one entry per login for the life of the process.
func TestSessionMapSweepsExpiredEntries(t *testing.T) {
	st := newTestStore(t)

	st.mu.Lock()
	for i := 0; i < 600; i++ {
		st.sessions["expired-"+strconv.Itoa(i)] = time.Now().Add(-time.Hour)
	}
	st.sessions["still-live"] = time.Now().Add(time.Hour)
	st.mu.Unlock()

	token, _ := st.IssueSession()
	if !st.ValidateSession(token) {
		t.Fatal("the session issued after the sweep does not validate")
	}

	st.mu.Lock()
	count := len(st.sessions)
	_, expiredKept := st.sessions["expired-0"]
	_, liveKept := st.sessions["still-live"]
	st.mu.Unlock()
	if expiredKept {
		t.Fatal("expired entries survived the sweep")
	}
	if !liveKept {
		t.Fatal("the sweep dropped a live session")
	}
	if count != 2 {
		t.Fatalf("session map holds %d entries, want 2", count)
	}

	// ValidateSession drops an expired entry on sight.
	st.mu.Lock()
	st.sessions["stale"] = time.Now().Add(-time.Minute)
	st.mu.Unlock()
	if st.ValidateSession("stale") {
		t.Fatal("an expired session validated")
	}
	st.mu.Lock()
	_, staleKept := st.sessions["stale"]
	st.mu.Unlock()
	if staleKept {
		t.Fatal("ValidateSession left the expired entry in the map")
	}
}

// A state file written by a newer build may carry fields this build does not
// know; loading it would drop them on the next write. Open must refuse and
// leave the file exactly as it is.
func TestOpenRejectsANewerSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	raw, err := json.Marshal(State{
		Version:  schemaVersion + 1,
		Admin:    Admin{Username: "admin", Salt: "seeded", PasswordHash: "seeded"},
		Settings: config.DefaultSettings(dir),
	})
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFile), raw, 0o600); err != nil {
		t.Fatalf("seed %s: %v", stateFile, err)
	}

	st, err := Open(dir, "admin", "admin12345")
	if err == nil {
		_ = st.Close()
		t.Fatal("Open accepted a state file written by a newer schema")
	}
	if !strings.Contains(err.Error(), "更新版本") {
		t.Fatalf("the error does not explain the version refusal: %v", err)
	}

	// The refusal must not have rewritten the version on disk.
	content, readErr := os.ReadFile(filepath.Join(dir, stateFile))
	if readErr != nil {
		t.Fatalf("read back: %v", readErr)
	}
	var got State
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("parse back: %v", err)
	}
	if got.Version != schemaVersion+1 {
		t.Fatalf("the version field was rewritten on disk: %d", got.Version)
	}
}
