package admin

// Model catalogue sync for the MiniMax Code lane.
//
// The upstream catalog is authoritative: `/mavis/api/v1/models` decides which
// model ids exist and what they can do. This file turns that response into
// catalogue entries without ever deleting one — a model the upstream drops is
// disabled, so its usage counters and any operator notes survive, and a model
// the operator turned off stays off when the sync touches it again.

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"minimax2api/internal/minimax"
	"minimax2api/internal/store"
)

// mcodeModelCapabilities is the part of an entry the sync owns. Everything else
// on the entry — name, enabled, description, counters — belongs to the operator.
type mcodeModelCapabilities struct {
	ContextLimit   int
	ContextWindows []int
	ThinkingMode   string
	EffortOptions  []string
	DefaultEffort  string
}

// mcodeModelUpdate carries one existing entry's refreshed capabilities.
type mcodeModelUpdate struct {
	ID  string
	Cap mcodeModelCapabilities
}

// planMCodeSync diffs the upstream catalog against the local catalogue.
//
// Matching is by `UpstreamModel` (what the Messages API is actually sent), not
// by local id: the id is stable across syncs precisely because it is derived
// once, when the entry is created.
func planMCodeSync(existing []*store.ModelConfig, catalog []minimax.MCodeModel) (
	adds []*store.ModelConfig,
	updates []mcodeModelUpdate,
	disabled []string,
) {
	known := make(map[string]*store.ModelConfig, len(existing))
	ids := make(map[string]bool, len(existing))
	for _, model := range existing {
		ids[model.ID] = true
		if model.Upstream == store.UpstreamMCode && strings.TrimSpace(model.UpstreamModel) != "" {
			known[strings.ToLower(strings.TrimSpace(model.UpstreamModel))] = model
		}
	}

	seen := make(map[string]bool, len(catalog))
	for _, upstream := range catalog {
		key := strings.ToLower(strings.TrimSpace(upstream.ID))
		if key == "" {
			continue
		}
		seen[key] = true
		capabilities := mcodeCapabilitiesOf(upstream)

		if model, ok := known[key]; ok {
			updates = append(updates, mcodeModelUpdate{ID: model.ID, Cap: capabilities})
			continue
		}
		id := mcodeModelID(upstream.ID, ids)
		ids[id] = true
		adds = append(adds, &store.ModelConfig{
			ID:             id,
			Name:           "MiniMax Code " + upstream.ID,
			Upstream:       store.UpstreamMCode,
			UpstreamModel:  upstream.ID,
			Type:           store.ModelTypeChat,
			Enabled:        true,
			Description:    "由 MiniMax Code 目录自动同步（/mavis/api/v1/models）",
			ContextLimit:   capabilities.ContextLimit,
			ContextWindows: capabilities.ContextWindows,
			ThinkingMode:   capabilities.ThinkingMode,
			EffortOptions:  capabilities.EffortOptions,
			DefaultEffort:  capabilities.DefaultEffort,
		})
	}

	for key, model := range known {
		if seen[key] || !model.Enabled {
			continue
		}
		disabled = append(disabled, model.ID)
	}
	sort.Strings(disabled)
	return adds, updates, disabled
}

// mcodeModelID derives a local id from an upstream id, avoiding collisions with
// entries the operator added by hand.
func mcodeModelID(upstreamID string, taken map[string]bool) string {
	base := strings.TrimSpace(upstreamID)
	if len(base) >= len("MiniMax-") && strings.EqualFold(base[:len("MiniMax-")], "MiniMax-") {
		base = base[len("MiniMax-"):]
	}
	var builder strings.Builder
	lastDash := true
	for _, char := range strings.ToLower(base) {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9':
			builder.WriteRune(char)
			lastDash = false
		case !lastDash:
			builder.WriteByte('-')
			lastDash = true
		}
	}
	slug := strings.Trim(builder.String(), "-")
	if slug == "" {
		slug = "model"
	}
	id := "mcode-" + slug
	if !taken[id] {
		return id
	}
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s-%d", id, suffix)
		if !taken[candidate] {
			return candidate
		}
	}
}

// mcodeCapabilitiesOf keeps only values the catalogue can enforce.
func mcodeCapabilitiesOf(upstream minimax.MCodeModel) mcodeModelCapabilities {
	thinking := strings.TrimSpace(upstream.Thinking)
	switch thinking {
	case "switchable", "forced_on", "forced_off":
	default:
		thinking = ""
	}
	var effort []string
	for _, option := range upstream.EffortOptions {
		if option = strings.TrimSpace(option); option != "" {
			effort = append(effort, option)
		}
	}
	contextWindows := make([]int, 0, len(upstream.ContextWindows))
	for _, window := range upstream.ContextWindows {
		if window > 0 {
			contextWindows = append(contextWindows, window)
		}
	}
	contextLimit := upstream.ContextLimit
	if contextLimit <= 0 && len(contextWindows) > 0 {
		contextLimit = contextWindows[0]
	}
	return mcodeModelCapabilities{
		ContextLimit:   contextLimit,
		ContextWindows: contextWindows,
		ThinkingMode:   thinking,
		EffortOptions:  effort,
		DefaultEffort:  strings.TrimSpace(upstream.DefaultEffort),
	}
}

// syncMCodeModels pulls the upstream catalog and applies the diff.
func (a *API) syncMCodeModels(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	catalog, account, err := a.loadMCodeCatalog(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	adds, updates, disabled := planMCodeSync(a.store.ListModels(), catalog)

	added, updated := 0, 0
	for _, model := range adds {
		if err := a.store.AddModel(model); err == nil {
			added++
		}
	}
	for _, update := range updates {
		if _, err := a.store.UpdateModel(update.ID, func(model *store.ModelConfig) {
			model.ContextLimit = update.Cap.ContextLimit
			model.ContextWindows = update.Cap.ContextWindows
			model.ThinkingMode = update.Cap.ThinkingMode
			model.EffortOptions = update.Cap.EffortOptions
			model.DefaultEffort = update.Cap.DefaultEffort
		}); err == nil {
			updated++
		}
	}
	for _, id := range disabled {
		if _, err := a.store.UpdateModel(id, func(model *store.ModelConfig) {
			model.Enabled = false
		}); err == nil {
			// Counted through the slice length below.
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accountId": account.ID,
		"region":    account.Region,
		"catalog":   len(catalog),
		"added":     added,
		"updated":   updated,
		"disabled":  len(disabled),
		"models":    catalog,
	})
}
