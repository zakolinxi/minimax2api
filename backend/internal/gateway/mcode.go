package gateway

// MiniMax Code credential maintenance.
//
// The desktop lane's access token is short-lived (~12h) and opaque: there is no
// expiry claim to read, so the store keeps the `expires_in` the OAuth endpoint
// returned. Refreshing here — before the turn is built — keeps the pool's
// health accounting meaningful: a token that expired between two requests would
// otherwise be reported as an invalid account and retired.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"minimax2api/internal/minimax"
	"minimax2api/internal/store"
)

// mcodeRefreshWindow is how long before expiry the token is renewed. It has to
// exceed the longest turn a caller may run, or a token could expire mid-stream.
const mcodeRefreshWindow = 10 * time.Minute

// ensureMCodeToken renews a MiniMax Code account's access token when it is
// missing or close to expiry. Accounts of any other kind are left untouched.
func (g *Gateway) ensureMCodeToken(ctx context.Context, account *store.Account) error {
	if account == nil || account.Kind != store.KindMCode {
		return nil
	}
	if account.RefreshToken == "" {
		// A pasted access token with no refresh pair can only be used until it
		// expires. Fail loudly once it is gone rather than sending a dead token
		// upstream and blaming the account.
		if account.Token != "" && (account.TokenExpiresAt.IsZero() || time.Until(account.TokenExpiresAt) > 0) {
			return nil
		}
		return fmt.Errorf("%w: mcode account has no refresh token", minimax.ErrInvalidCredential)
	}
	if account.Token != "" && !account.TokenExpiresAt.IsZero() &&
		time.Until(account.TokenExpiresAt) > mcodeRefreshWindow {
		return nil
	}

	tokens, err := g.client.MCodeRefresh(ctx, account.Region, account.RefreshToken)
	if err != nil {
		// A refused refresh means the pair is dead: retrying it on the same
		// account cannot help, so it is reported as an invalid credential and
		// the pool retires it.
		if errors.Is(err, minimax.ErrMCodeDenied) || errors.Is(err, minimax.ErrMCodeExpired) || isOAuthRefusal(err) {
			return fmt.Errorf("%w: %v", minimax.ErrInvalidCredential, err)
		}
		return err
	}
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = account.RefreshToken
	}

	account.Token = tokens.AccessToken
	account.RefreshToken = tokens.RefreshToken
	account.TokenExpiresAt = tokens.ExpiresAt
	account.LastError = ""
	g.store.SaveAccountState(account.ID, func(stored *store.Account) {
		stored.Token = account.Token
		stored.RefreshToken = account.RefreshToken
		stored.TokenExpiresAt = account.TokenExpiresAt
		stored.LastError = ""
	})
	return nil
}

// isOAuthRefusal reports whether err is an OAuth error the server will keep
// refusing (invalid_grant / invalid_client) rather than a transient one.
func isOAuthRefusal(err error) bool {
	var oauthErr *minimax.MCodeOAuthError
	if !errors.As(err, &oauthErr) {
		return false
	}
	switch oauthErr.Code {
	case "invalid_grant", "invalid_client", "invalid_request", "unauthorized_client":
		return true
	}
	return oauthErr.Status == 400 || oauthErr.Status == 401
}

// outputTokenCap picks the caller's output cap. OpenAI's newer
// max_completion_tokens wins over max_tokens when both are present.
func outputTokenCap(request chatRequest) int {
	if request.MaxCompletionTokens > 0 {
		return request.MaxCompletionTokens
	}
	return request.MaxTokens
}
