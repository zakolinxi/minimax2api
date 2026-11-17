package admin

// MiniMax Code account onboarding.
//
// The desktop product logs in with OAuth 2.0 device authorization: the console
// starts the flow, shows the user code, and polls until the operator finishes
// in a browser. The resulting pair is an opaque bearer that only the Code lane
// accepts, so these endpoints create accounts of kind "mcode" rather than
// reusing the web-token importer.
//
// A second path is kept for operators who already have the pair on disk or in a
// password manager: paste it, or point the import at a desktop auth directory.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"minimax2api/internal/minimax"
	"minimax2api/internal/store"
)

// mcodeDeviceFlow is one in-flight authorization. The prompt carries the device
// code and PKCE verifier, which never leave this struct.
type mcodeDeviceFlow struct {
	ID        string
	Region    string
	Prompt    *minimax.MCodeDevicePrompt
	Status    string // pending | authorized | denied | expired | failed | cancelled
	Error     string
	AccountID string
	CreatedAt time.Time
	Deadline  time.Time
	cancel    context.CancelFunc
}

// mcodeFlowView is the projection the console polls.
type mcodeFlowView struct {
	ID                      string             `json:"id"`
	Region                  string             `json:"region"`
	Status                  string             `json:"status"`
	Error                   string             `json:"error,omitempty"`
	UserCode                string             `json:"userCode,omitempty"`
	VerificationURI         string             `json:"verificationUri,omitempty"`
	VerificationURIComplete string             `json:"verificationUriComplete,omitempty"`
	ExpiresIn               int                `json:"expiresIn,omitempty"`
	Interval                int                `json:"interval,omitempty"`
	Account                 *store.AccountView `json:"account,omitempty"`
}

// startMCodeDevice begins a device authorization and polls it in the
// background. The response is what the operator needs to authorize; the poll
// result is fetched from the id it returns.
func (a *API) startMCodeDevice(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Region string `json:"region"`
	}
	_ = decode(r, &payload)

	region := normalizeRegion(payload.Region)
	if isAutoRegion(payload.Region) || region == "" {
		// The account host is the only thing this decides, and there is no
		// cheap probe that says which deployment owns an account we have not
		// authenticated yet. The international host is the safer default for
		// this gateway, which already defaults to the global deployment.
		region = store.RegionGlobal
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	prompt, err := a.client.MCodeStartDevice(ctx, region)
	if err != nil {
		cancel()
		writeError(w, http.StatusBadGateway, fmt.Sprintf("MiniMax Code 设备码请求失败：%v", err))
		return
	}

	flow := &mcodeDeviceFlow{
		ID:        "mcode_" + randomID(10),
		Region:    region,
		Prompt:    prompt,
		Status:    "pending",
		CreatedAt: time.Now(),
		Deadline:  time.Now().Add(time.Duration(prompt.ExpiresIn) * time.Second),
		cancel:    cancel,
	}
	a.putMCodeFlow(flow)
	go a.pollMCodeFlow(ctx, flow)

	writeJSON(w, http.StatusOK, mcodeFlowView{
		ID:                      flow.ID,
		Region:                  region,
		Status:                  flow.Status,
		UserCode:                prompt.UserCode,
		VerificationURI:         prompt.VerificationURI,
		VerificationURIComplete: prompt.VerificationURIComplete,
		ExpiresIn:               prompt.ExpiresIn,
		Interval:                prompt.Interval,
	})
}

// pollMCodeFlow drives the token endpoint until the operator finishes, the code
// expires, or the flow is cancelled.
func (a *API) pollMCodeFlow(ctx context.Context, flow *mcodeDeviceFlow) {
	defer flow.cancel()
	interval := time.Duration(flow.Prompt.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	for {
		select {
		case <-ctx.Done():
			a.finishMCodeFlow(flow, "expired", "授权超时或已取消", "")
			return
		case <-time.After(interval):
		}

		tokens, err := a.client.MCodePollDevice(ctx, flow.Prompt)
		if err == nil {
			account, addErr := a.addMCodeAccount(tokens, flow.Region, "", "设备码登录")
			if addErr != nil {
				a.finishMCodeFlow(flow, "failed", addErr.Error(), "")
				return
			}
			a.finishMCodeFlow(flow, "authorized", "", account.ID)
			return
		}
		switch {
		case errors.Is(err, minimax.ErrMCodePending):
			continue
		case errors.Is(err, minimax.ErrMCodeSlowDown):
			interval += 5 * time.Second
			continue
		case errors.Is(err, minimax.ErrMCodeDenied):
			a.finishMCodeFlow(flow, "denied", "用户拒绝了授权", "")
			return
		case errors.Is(err, minimax.ErrMCodeExpired):
			a.finishMCodeFlow(flow, "expired", "设备码已过期", "")
			return
		default:
			a.finishMCodeFlow(flow, "failed", err.Error(), "")
			return
		}
	}
}

func (a *API) finishMCodeFlow(flow *mcodeDeviceFlow, status, message, accountID string) {
	a.mcodeMu.Lock()
	defer a.mcodeMu.Unlock()
	// A cancelled flow's context fires at the same moment the cancel handler
	// records its verdict; both paths must not overwrite each other. Only a
	// still-pending flow can move to a terminal state.
	if current, ok := a.mcodeFlows[flow.ID]; ok && current.Status == "pending" {
		current.Status = status
		current.Error = message
		current.AccountID = accountID
	}
}

func (a *API) putMCodeFlow(flow *mcodeDeviceFlow) {
	a.mcodeMu.Lock()
	defer a.mcodeMu.Unlock()
	// Finished flows are kept for ten minutes so a console that lost the start
	// response can still read the outcome, then dropped.
	cutoff := time.Now().Add(-10 * time.Minute)
	for id, existing := range a.mcodeFlows {
		if existing.Status != "pending" && existing.CreatedAt.Before(cutoff) {
			delete(a.mcodeFlows, id)
		}
	}
	a.mcodeFlows[flow.ID] = flow
}

func (a *API) getMCodeFlow(id string) (*mcodeDeviceFlow, bool) {
	a.mcodeMu.Lock()
	defer a.mcodeMu.Unlock()
	flow, ok := a.mcodeFlows[id]
	return flow, ok
}

func (a *API) getMCodeDevice(w http.ResponseWriter, r *http.Request) {
	flow, ok := a.getMCodeFlow(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "授权会话不存在或已过期")
		return
	}
	view := mcodeFlowView{
		ID:                      flow.ID,
		Region:                  flow.Region,
		Status:                  flow.Status,
		Error:                   flow.Error,
		UserCode:                flow.Prompt.UserCode,
		VerificationURI:         flow.Prompt.VerificationURI,
		VerificationURIComplete: flow.Prompt.VerificationURIComplete,
		ExpiresIn:               flow.Prompt.ExpiresIn,
		Interval:                flow.Prompt.Interval,
	}
	if flow.AccountID != "" {
		if account, ok := a.store.AccountByID(flow.AccountID); ok {
			accountView := store.NewAccountView(account, 0)
			view.Account = &accountView
		}
	}
	writeJSON(w, http.StatusOK, view)
}

func (a *API) cancelMCodeDevice(w http.ResponseWriter, r *http.Request) {
	flow, ok := a.getMCodeFlow(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "授权会话不存在或已过期")
		return
	}
	flow.cancel()
	a.finishMCodeFlow(flow, "cancelled", "已取消", "")
	writeJSON(w, http.StatusOK, map[string]any{"status": "cancelled"})
}

// importMCodeToken accepts a credential pair copied from another installation.
//
// A refresh is attempted whenever a refresh token is present: it both validates
// the pair and returns the expiry, which the access token cannot be asked for.
// With only an access token the catalogue call is the validation, and the
// account carries no expiry — it works until the upstream rejects it.
func (a *API) importMCodeToken(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		Region       string `json:"region"`
		Name         string `json:"name"`
		Remark       string `json:"remark"`
		// Refresh opts into rotating the pair. It is required when only a
		// refresh token is supplied, and it logs out whichever desktop app owns
		// that pair, so it is never the default.
		Refresh bool `json:"refresh"`
	}
	if err := decode(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	access := strings.TrimSpace(payload.AccessToken)
	refresh := strings.TrimSpace(payload.RefreshToken)
	if access == "" && refresh == "" {
		writeError(w, http.StatusBadRequest, "需要 accessToken 或 refreshToken")
		return
	}
	region := normalizeRegion(payload.Region)
	if isAutoRegion(payload.Region) || region == "" {
		region = store.RegionGlobal
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	tokens := &minimax.MCodeTokens{AccessToken: access, RefreshToken: refresh}
	// Refreshing is opt-in on purpose. A successful refresh rotates the pair,
	// which logs the desktop app that owns it out; importing a credential from
	// a live installation must not do that behind the operator's back. The
	// default validates the access token instead, which touches nothing.
	if payload.Refresh || access == "" {
		if refresh == "" {
			writeError(w, http.StatusBadRequest, "refresh=true 需要 refreshToken")
			return
		}
		refreshed, err := a.client.MCodeRefresh(ctx, region, refresh)
		if err != nil {
			writeError(w, http.StatusBadGateway, fmt.Sprintf("刷新令牌校验失败：%v", err))
			return
		}
		if tokens.AccessToken == "" {
			tokens.AccessToken = refreshed.AccessToken
		}
		tokens.RefreshToken = refreshed.RefreshToken
		tokens.ExpiresAt = refreshed.ExpiresAt
	} else {
		models, err := a.client.MCodeModels(ctx, minimax.Credential{Kind: store.KindMCode, Region: region, Token: access})
		if err != nil {
			writeError(w, http.StatusBadGateway, fmt.Sprintf(
				"访问令牌校验失败：%v（若确认 refreshToken 可用，可带 refresh=true；那会轮换桌面端凭据）", err))
			return
		}
		if len(models) == 0 {
			writeError(w, http.StatusBadGateway, "访问令牌校验失败：模型列表为空")
			return
		}
	}

	account, err := a.addMCodeAccount(tokens, region, payload.Name, payload.Remark)
	if err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			writeError(w, http.StatusConflict, "该令牌已存在于账号池")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	view := store.NewAccountView(account, 0)
	writeJSON(w, http.StatusOK, view)
}

// addMCodeAccount persists a validated credential pair as an account.
func (a *API) addMCodeAccount(tokens *minimax.MCodeTokens, region, name, remark string) (*store.Account, error) {
	if tokens == nil || strings.TrimSpace(tokens.AccessToken) == "" {
		return nil, errors.New("mcode credential is empty")
	}
	if name == "" {
		name = "MiniMax Code " + strings.ToUpper(region) + " " + store.MaskToken(tokens.AccessToken)
	}
	account := &store.Account{
		Name:           name,
		Kind:           store.KindMCode,
		Region:         region,
		Token:          tokens.AccessToken,
		RefreshToken:   tokens.RefreshToken,
		TokenExpiresAt: tokens.ExpiresAt,
		DeviceID:       newDeviceID(),
		UUID:           newUUID(),
		ScreenWidth:    1536,
		ScreenHeight:   864,
		Enabled:        true,
		Group:          "mcode",
		Remark:         remark,
	}
	if err := a.store.AddAccount(account); err != nil {
		return nil, err
	}
	return account, nil
}

// refreshMCodeAccount renews one account on demand.
func (a *API) refreshMCodeAccount(w http.ResponseWriter, r *http.Request) {
	account, ok := a.store.AccountByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "账号不存在")
		return
	}
	if account.Kind != store.KindMCode {
		writeError(w, http.StatusBadRequest, "该账号不是 MiniMax Code 账号")
		return
	}
	if account.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "该账号没有 refreshToken")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	tokens, err := a.client.MCodeRefresh(ctx, account.Region, account.RefreshToken)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("刷新失败：%v", err))
		return
	}
	refreshToken := tokens.RefreshToken
	if refreshToken == "" {
		refreshToken = account.RefreshToken
	}
	updated, err := a.store.UpdateAccount(account.ID, func(stored *store.Account) {
		stored.Token = tokens.AccessToken
		stored.RefreshToken = refreshToken
		stored.TokenExpiresAt = tokens.ExpiresAt
		stored.LastError = ""
		stored.Status = store.StatusActive
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	view := store.NewAccountView(updated, 0)
	writeJSON(w, http.StatusOK, view)
}

// errNoMCodeAccount marks a catalog request with no account to read it with.
var errNoMCodeAccount = fmt.Errorf("号池里还没有可用的 MiniMax Code 账号")

// loadMCodeCatalog picks the first usable mcode account and reads the upstream
// catalog with it, refreshing once when the access token is rejected. The
// catalog endpoint is read-only and cheap, so one account answers for the pool.
func (a *API) loadMCodeCatalog(ctx context.Context) ([]minimax.MCodeModel, *store.Account, error) {
	var chosen *store.Account
	for _, account := range a.store.ListAccounts() {
		if account.Kind == store.KindMCode && account.Enabled {
			chosen = account
			break
		}
	}
	if chosen == nil {
		return nil, nil, errNoMCodeAccount
	}

	fetch := func(token string) ([]minimax.MCodeModel, error) {
		return a.client.MCodeModels(ctx, minimax.Credential{
			Kind: store.KindMCode, Region: chosen.Region, Token: token, BaseURL: chosen.BaseURL,
		})
	}

	models, err := fetch(chosen.Token)
	if err != nil && errors.Is(err, minimax.ErrInvalidCredential) && chosen.RefreshToken != "" {
		tokens, refreshErr := a.client.MCodeRefresh(ctx, chosen.Region, chosen.RefreshToken)
		if refreshErr == nil {
			refreshToken := tokens.RefreshToken
			if refreshToken == "" {
				refreshToken = chosen.RefreshToken
			}
			if _, updateErr := a.store.UpdateAccount(chosen.ID, func(stored *store.Account) {
				stored.Token = tokens.AccessToken
				stored.RefreshToken = refreshToken
				stored.TokenExpiresAt = tokens.ExpiresAt
				stored.LastError = ""
			}); updateErr == nil {
				models, err = fetch(tokens.AccessToken)
			}
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("获取模型目录失败：%w", err)
	}
	return models, chosen, nil
}

// mcodeCatalog reports the model catalog the MiniMax Code lane actually serves.
//
// The endpoint is `/mavis/api/v1/models?region=&buildEnv=`, which is also what
// the desktop runtime pulls and caches into config.yaml.
func (a *API) mcodeCatalog(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	models, account, err := a.loadMCodeCatalog(ctx)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errNoMCodeAccount) {
			status = http.StatusBadRequest
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accountId": account.ID,
		"region":    account.Region,
		"models":    models,
	})
}

// importLocalMCode imports every MiniMax Code credential found under a desktop
// auth directory (default: ~/.minimax/auth).
//
// The layout is {root}/{buildEnv}/{region}/mcode-public/auth.json, and the file
// holds a records map keyed by service. Only the token pair is read; nothing is
// written back.
func (a *API) importLocalMCode(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Path string `json:"path"`
		// Refresh opts into rotating the pairs found on disk. It logs the
		// desktop app that owns them out, so it is off unless asked for.
		Refresh bool `json:"refresh"`
	}
	_ = decode(r, &payload)
	refresh := payload.Refresh
	root := strings.TrimSpace(payload.Path)
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "无法定位用户目录")
			return
		}
		root = filepath.Join(home, ".minimax", "auth")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		writeError(w, http.StatusBadRequest, "目录不存在："+root)
		return
	}

	type result struct {
		Path      string `json:"path"`
		Status    string `json:"status"`
		AccountID string `json:"accountId,omitempty"`
		Error     string `json:"error,omitempty"`
	}
	results := make([]result, 0, 4)

	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}
		if !strings.EqualFold(entry.Name(), "auth.json") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		// {region}/mcode-public/auth.json
		if len(parts) < 3 || parts[len(parts)-2] != "mcode-public" {
			return nil
		}
		region := normalizeRegion(parts[len(parts)-3])
		if region == "" {
			region = store.RegionGlobal
		}

		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			results = append(results, result{Path: rel, Status: "failed", Error: readErr.Error()})
			return nil
		}
		var parsed struct {
			Records map[string]struct {
				AccessToken  string `json:"accessToken"`
				RefreshToken string `json:"refreshToken"`
				ExpiresAtMs  int64  `json:"expiresAtMs"`
			} `json:"records"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			results = append(results, result{Path: rel, Status: "failed", Error: "auth.json 解析失败"})
			return nil
		}
		if len(parsed.Records) == 0 {
			results = append(results, result{Path: rel, Status: "skipped", Error: "没有凭据记录"})
			return nil
		}

		for _, record := range parsed.Records {
			if strings.TrimSpace(record.AccessToken) == "" {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			tokens := &minimax.MCodeTokens{AccessToken: record.AccessToken, RefreshToken: record.RefreshToken}
			if record.ExpiresAtMs > 0 {
				tokens.ExpiresAt = time.UnixMilli(record.ExpiresAtMs)
			}
			if refresh {
				// Opt-in: this rotates the pair and logs the desktop app out.
				if record.RefreshToken == "" {
					cancel()
					results = append(results, result{Path: rel, Status: "failed", Error: "没有 refreshToken"})
					continue
				}
				refreshed, err := a.client.MCodeRefresh(ctx, region, record.RefreshToken)
				if err != nil {
					cancel()
					results = append(results, result{Path: rel, Status: "failed", Error: "刷新失败：" + err.Error()})
					continue
				}
				tokens = refreshed
			} else {
				// Validate without touching the pair: the access token is checked
				// against the catalogue, and no refresh is spent. An expired
				// access token needs refresh=true, which the caller has to ask for.
				models, err := a.client.MCodeModels(ctx, minimax.Credential{
					Kind: store.KindMCode, Region: region, Token: record.AccessToken,
				})
				if err != nil || len(models) == 0 {
					cancel()
					reason := "访问令牌无效"
					if err != nil {
						reason += "：" + err.Error()
					}
					results = append(results, result{Path: rel, Status: "failed", Error: reason})
					continue
				}
			}
			account, addErr := a.addMCodeAccount(tokens, region, "", "从 MiniMax Code 客户端导入")
			cancel()
			if addErr != nil {
				status := "failed"
				if errors.Is(addErr, store.ErrAlreadyExists) {
					status = "skipped"
				}
				results = append(results, result{Path: rel, Status: status, Error: addErr.Error()})
				continue
			}
			results = append(results, result{Path: rel, Status: "added", AccountID: account.ID})
		}
		return nil
	})

	writeJSON(w, http.StatusOK, map[string]any{"root": root, "results": results})
}
