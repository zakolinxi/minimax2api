package admin

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"minimax2api/internal/minimax"
	"minimax2api/internal/store"
)

// The automatic re-login loop.
//
// A web token cannot be renewed after it expires — the renewal endpoint answers
// 401 for a dead token (verified against the live upstream) — so recovering a
// pool means signing in again. The account's login credential is the only thing
// that makes that possible without a human, and the browser bridge is the only
// component that can replay the web login: the site's login product is a form,
// not an API the gateway can call with a password. See tools/browser-login-bridge.mjs.
const (
	// autoLoginLead is how long before expiry an account is re-logged-in. The
	// point is to stay ahead of an expiry rather than react to a 401, so a
	// rotation never takes capacity out of the pool.
	autoLoginLead = 72 * time.Hour
	// autoLoginRetryGap keeps a bad password from becoming a request loop.
	autoLoginRetryGap = 30 * time.Minute
	// autoLoginInterval is how often the pool is checked for due accounts.
	autoLoginInterval = 10 * time.Minute
	// autoLoginStartDelay lets the process finish starting (and the check-in
	// sweep take its turn on the account) before the first pass.
	autoLoginStartDelay = 2 * time.Minute
	// autoLoginBudget bounds one browser login end to end.
	autoLoginBudget = 150 * time.Second
	// browserLoginPollInterval is how often the browser session is polled.
	browserLoginPollInterval = 1500 * time.Millisecond
)

// StartAutoLogin launches the background loop. It stops when ctx is cancelled.
//
// The loop is deliberately silent when the bridge is not configured: a
// deployment that logs in by hand has nothing to recover automatically, and a
// warning every ten minutes would be noise about a feature that was never on.
func (a *API) StartAutoLogin(ctx context.Context) {
	if a.browserLoginBridge == "" {
		return
	}
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(autoLoginStartDelay):
		}
		a.autoLoginSweep(ctx)
		ticker := time.NewTicker(autoLoginInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.autoLoginSweep(ctx)
			}
		}
	}()
}

// autoLoginSweep re-logs-in every account that is due, one at a time.
//
// Accounts are visited serially because the bridge owns a single Chrome profile:
// two logins at once would fight over it, and a burst of logins from one address
// is exactly the pattern the site's risk control watches for.
func (a *API) autoLoginSweep(ctx context.Context) {
	now := time.Now()
	for _, account := range a.store.ListAccounts() {
		if ctx.Err() != nil {
			return
		}
		if !autoLoginDue(account, now) {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, autoLoginBudget+browserLoginStatusTimeout)
		err := a.relogin(attemptCtx, account)
		cancel()
		if err != nil {
			log.Printf("自动重登失败 %s（%s）：%v", account.Name, account.ID, err)
			continue
		}
		log.Printf("自动重登成功 %s（%s）", account.Name, account.ID)
	}
}

// autoLoginDue reports whether one account needs a fresh token now.
//
// Invalid is the obvious case. The other is a token that is still working but
// close to its expiry: waiting for the 401 would take the account out of the
// pool for as long as the login takes, and the expiry is in the token itself.
func autoLoginDue(account *store.Account, now time.Time) bool {
	if account == nil || !account.Enabled || !account.AutoLogin {
		return false
	}
	if strings.TrimSpace(account.Email) == "" || account.Password == "" {
		return false
	}
	if !account.LastLoginAt.IsZero() && now.Sub(account.LastLoginAt) < autoLoginRetryGap {
		return false
	}
	if account.Status == store.StatusInvalid {
		return true
	}
	info, err := minimax.ParseToken(account.Token)
	if err != nil || info.ExpiresAt.IsZero() {
		return false
	}
	return now.Add(autoLoginLead).After(info.ExpiresAt)
}

// relogin signs in once and stores the token it produces.
//
// The token is verified before it replaces the stored one: a login that
// produced something the upstream rejects must not overwrite a working token,
// and the verification call is also what supplies realUserID — the value every
// signed endpoint needs and the JWT never carries.
func (a *API) relogin(ctx context.Context, account *store.Account) error {
	if a.browserLoginBridge == "" {
		return errors.New("浏览器登录服务未配置，无法自动重登")
	}
	if strings.TrimSpace(account.Email) == "" || account.Password == "" {
		return errors.New("账号未配置登录邮箱/密码")
	}

	recordFailure := func(err error) {
		a.store.SaveAccountState(account.ID, func(target *store.Account) {
			target.LastLoginAt = time.Now()
			target.LastLoginError = truncate(err.Error(), 200)
		})
	}

	token, err := a.bridgeAutoLogin(ctx, account)
	if err != nil {
		recordFailure(err)
		return err
	}

	info, verifyErr := a.client.FetchUserInfo(ctx, minimax.Credential{Token: token})
	if verifyErr != nil || info == nil || info.RealUserID == "" {
		if verifyErr == nil {
			verifyErr = errors.New("上游没有返回用户信息")
		}
		err = fmt.Errorf("重登成功但新令牌未通过校验: %w", verifyErr)
		recordFailure(err)
		return err
	}
	// The browser is a shared profile, and a session it still remembered would
	// otherwise be adopted as this account's. The identity the upstream reports
	// has to be the one that was asked to sign in.
	if !sameLoginIdentity(account, info) {
		err = fmt.Errorf("重登得到的是另一个账号（%s），已拒绝替换令牌", info.Label())
		recordFailure(err)
		return err
	}

	if _, err := a.store.UpdateAccount(account.ID, func(target *store.Account) {
		target.Token = token
		target.UserID = info.RealUserID
		if label := info.Label(); label != "" {
			target.Identifier = label
		}
		target.Status = store.StatusActive
		target.CooldownUntil = time.Time{}
		target.FailCount = 0
		target.LastError = ""
		target.LastLoginAt = time.Now()
		target.LastLoginError = ""
	}); err != nil {
		return err
	}

	a.goSyncQuotaDetached(account.ID)
	return nil
}

// sameLoginIdentity reports whether the identity the upstream reported is the
// account that was asked for.
//
// A blank identifier on either side is treated as unknown rather than as a
// mismatch: the upstream does not always echo the email, and refusing every
// login it did not label would take working accounts out of rotation. A value
// it does report, however, has to agree — that is the case where a shared
// browser profile would otherwise swap two accounts' tokens.
func sameLoginIdentity(account *store.Account, info *minimax.UserInfo) bool {
	want := strings.TrimSpace(account.Email)
	if want == "" || info == nil {
		return true
	}
	if strings.Contains(want, "@") {
		got := strings.TrimSpace(info.Email)
		return got == "" || strings.EqualFold(got, want)
	}
	got := strings.TrimSpace(info.Phone)
	if got == "" {
		return true
	}
	return digitsOf(got) == digitsOf(want) && digitsOf(want) != ""
}

// digitsOf keeps only the digits of a phone number, so "+1 415-555-0123" and
// "14155550123" compare equal.
func digitsOf(value string) string {
	var out strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// bridgeAutoLogin runs one automated login through the local browser bridge and
// returns the token the agent site stored.
func (a *API) bridgeAutoLogin(ctx context.Context, account *store.Account) (string, error) {
	target := browserLoginTargets[account.Region]
	if target == "" {
		target = browserLoginTargets[store.RegionGlobal]
	}
	payload := map[string]any{
		"target":   target,
		"email":    strings.TrimSpace(account.Email),
		"password": account.Password,
	}
	if proxy := strings.TrimSpace(a.settings().Upstream.Proxy); proxy != "" {
		payload["proxy"] = proxy
	}

	startCtx, cancelStart := context.WithTimeout(ctx, browserLoginStartTimeout)
	defer cancelStart()
	var session bridgeLoginSession
	if err := a.bridgeJSON(startCtx, http.MethodPost, "/login", payload, &session); err != nil {
		return "", fmt.Errorf("浏览器登录服务不可用：%w", err)
	}
	if session.SessionID == "" {
		return "", errors.New("浏览器登录服务没有返回会话 ID")
	}

	// The bridge owns one Chrome profile, so this session is closed by whoever
	// started it. That is the difference from the manual flow, where the
	// operator's browser is left open for them.
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), browserLoginStatusTimeout)
		defer cancel()
		_ = a.bridgeJSON(closeCtx, http.MethodDelete, "/login/"+url.PathEscape(session.SessionID), nil, nil)
	}()

	deadline := time.Now().Add(autoLoginBudget)
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(browserLoginPollInterval):
		}
		if time.Now().After(deadline) {
			return "", errors.New("自动登录超时")
		}

		pollCtx, cancel := context.WithTimeout(ctx, browserLoginStatusTimeout)
		var status bridgeLoginStatus
		err := a.bridgeJSON(pollCtx, http.MethodGet, "/login/"+url.PathEscape(session.SessionID), nil, &status)
		cancel()
		if err != nil {
			return "", err
		}
		switch status.Status {
		case "ok":
			token := strings.TrimSpace(status.Token)
			if token == "" {
				return "", errors.New("浏览器登录返回了空令牌")
			}
			return token, nil
		case "pending":
			continue
		default:
			reason := strings.TrimSpace(status.Error)
			if reason == "" {
				reason = status.Status
			}
			return "", errors.New("自动登录失败：" + reason)
		}
	}
}

// reloginAccount is the console's manual trigger for one account.
func (a *API) reloginAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	account, ok := a.store.AccountByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "账号不存在")
		return
	}
	if a.browserLoginBridge == "" {
		writeError(w, http.StatusServiceUnavailable, "浏览器登录服务未配置")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), autoLoginBudget+browserLoginStatusTimeout)
	defer cancel()
	if err := a.relogin(ctx, account); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.recordAdminAction(r, "自动重登账号", account.Name+"（"+id+"）")
	writeJSON(w, http.StatusOK, map[string]any{"account": a.view(id)})
}
