package minimax

// MiniMax Code (desktop) lane.
//
// MiniMax Code is the same product as the web agent but a different wire
// protocol. The reverse engineering that established this file's constants is
// recorded here because none of it is discoverable from a 4xx:
//
//   - Login is OAuth 2.0 device authorization with PKCE(S256). The public
//     client is `mcode-public`, the scope `agent.default`, the audience
//     `agent-backend`. The account host is `account.minimax.io` for the
//     international build and `account.minimax.cn` for the mainland one; the
//     requested scope and audience are the same on both.
//   - The result is an opaque pair, `mmoat_…` / `mmort_…`. It is not a JWT, so
//     ParseToken cannot describe it, and it is not accepted by the web agent
//     endpoints — a web JWT and an mcode bearer are not interchangeable.
//   - Inference is `POST {agent}/mavis/api/v1/llm/v1/messages` in Anthropic
//     Messages format, authenticated with `Authorization: Bearer`. This path
//     does **not** use `x-signature`/`yy`: a live request with only the bearer
//     and `anthropic-version` answers 200 (the signed `/matrix` and
//     `/minimax-cloud` gateways are a different edge).
//   - Streaming is standard Anthropic SSE: message_start, ping,
//     content_block_start/delta/stop, message_delta, message_stop.
//   - The catalogue is `GET {agent}/mavis/api/v1/models?region={cn|en}&buildEnv=prod`
//     and needs nothing but the bearer.
//
// Region matters twice: it selects the account host for the OAuth pair and the
// agent host for inference. A global token sent to the mainland edge is
// answered with `{"error":"invalid access token"}` — the same symptom as an
// expired token, which is why the region travels with the account.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"minimax2api/internal/config"
)

const (
	// KindMCode matches store.KindMCode. The minimax package does not import
	// store (the dependency runs the other way), so the literal is repeated and
	// a mismatch is caught by the gateway wiring rather than by a cycle.
	KindMCode = "mcode"

	MCodeClientID = "mcode-public"
	MCodeScope    = "agent.default"
	MCodeAudience = "agent-backend"

	mcodeDevicePath   = "/oauth2/device/code"
	mcodeTokenPath    = "/oauth2/token"
	mcodeRevokePath   = "/oauth2/revoke"
	mcodeLLMPath      = "/mavis/api/v1/llm/v1/messages"
	mcodeModelsPath   = "/mavis/api/v1/models"
	mcodeDeviceGrant  = "urn:ietf:params:oauth:grant-type:device_code"
	mcodeAnthropicVer = "2023-06-01"
	// mcodeAnthropicMaxTokens is the fallback output budget. The Messages API
	// requires the field; the catalogue's per-model limit is 128000, which is a
	// ceiling rather than a sensible default for an API gateway.
	mcodeAnthropicMaxTokens = 8192
	mcodeFallbackModel      = "MiniMax-M3.1-Flash"
	// mcodeAgentUserAgent is what the desktop runtime sends. It is only a
	// fallback for an operator who cleared the console's user agent.
	mcodeAgentUserAgent = "MiniMaxAgent"
)

// The account hosts are variables rather than constants so tests can point the
// OAuth calls at an httptest server. Production never reassigns them.
var (
	mcodeAccountHostGlobal = "https://account.minimax.io"
	mcodeAccountHostCN     = "https://account.minimax.cn"
)

// MCodeTokens is one issued credential pair.
type MCodeTokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Scope        string
}

// MCodeDevicePrompt is what the console shows while the operator authorizes in
// a browser. DeviceCode and CodeVerifier are secrets for the polling call and
// must never be projected into an API view.
type MCodeDevicePrompt struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int
	Interval                int
	CodeVerifier            string
	Region                  string
}

// ErrMCode* are the OAuth error codes the poll loop has to tell apart.
var (
	ErrMCodePending  = errors.New("mcode authorization pending")
	ErrMCodeSlowDown = errors.New("mcode slow down")
	ErrMCodeDenied   = errors.New("mcode access denied")
	ErrMCodeExpired  = errors.New("mcode device code expired")
)

// MCodeOAuthError carries the upstream `error` code of a rejected OAuth call.
type MCodeOAuthError struct {
	Code        string
	Status      int
	Description string
}

func (e *MCodeOAuthError) Error() string {
	message := e.Description
	if message == "" {
		message = e.Code
	}
	if message == "" {
		message = "rejected"
	}
	return fmt.Sprintf("mcode oauth HTTP %d: %s", e.Status, message)
}

// MCodeAccountHost returns the OAuth host for a region.
func MCodeAccountHost(region string) string {
	if region == RegionCN {
		return mcodeAccountHostCN
	}
	return mcodeAccountHostGlobal
}

// mcodeRegionTag is the catalogue's region spelling (en/cn).
func mcodeRegionTag(region string) string {
	if region == RegionCN {
		return "cn"
	}
	return "en"
}

// isMCodeCredential reports whether a credential belongs to the desktop lane.
func isMCodeCredential(cred Credential) bool {
	return strings.EqualFold(strings.TrimSpace(cred.Kind), KindMCode)
}

// MCodeBaseURL resolves the agent host used for inference and discovery.
func MCodeBaseURL(settings config.Settings, cred Credential) string {
	if base := strings.TrimSpace(cred.BaseURL); base != "" {
		return strings.TrimRight(base, "/")
	}
	if cred.Region == RegionCN && strings.TrimSpace(settings.Upstream.BaseURLCN) != "" {
		return strings.TrimRight(settings.Upstream.BaseURLCN, "/")
	}
	return strings.TrimRight(settings.Upstream.BaseURL, "/")
}

// ------------------------------------------------------------- device flow

// MCodeStartDevice begins a device authorization. The returned prompt carries
// the verifier because the token exchange needs it; it is not part of what the
// operator sees.
func (c *Client) MCodeStartDevice(ctx context.Context, region string) (*MCodeDevicePrompt, error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	form := url.Values{}
	form.Set("client_id", MCodeClientID)
	form.Set("scope", MCodeScope)
	form.Set("audience", MCodeAudience)
	form.Set("code_challenge", challenge)
	form.Set("code_challenge_method", "S256")

	body, status, err := c.mcodePostForm(ctx, MCodeAccountHost(region)+mcodeDevicePath, form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &MCodeOAuthError{Code: byteField(body, "error"), Status: status,
			Description: byteField(body, "error_description")}
	}

	prompt := &MCodeDevicePrompt{
		DeviceCode:              byteField(body, "device_code"),
		UserCode:                byteField(body, "user_code"),
		VerificationURI:         firstNonEmptyString(byteField(body, "verification_uri"), byteField(body, "verification_url")),
		VerificationURIComplete: byteField(body, "verification_uri_complete"),
		CodeVerifier:            verifier,
		Region:                  region,
	}
	prompt.ExpiresIn = byteInt(body, "expires_in")
	prompt.Interval = byteInt(body, "interval")
	if prompt.Interval <= 0 {
		prompt.Interval = 5
	}
	// The account service has been observed reporting the interval in
	// milliseconds on its user_code polling variant. Anything that large is not
	// a plausible seconds value, so it is normalised rather than trusted.
	if prompt.Interval > 1000 {
		prompt.Interval /= 1000
	}
	if prompt.VerificationURIComplete == "" {
		prompt.VerificationURIComplete = prompt.VerificationURI
	}
	if prompt.DeviceCode == "" || prompt.UserCode == "" || prompt.VerificationURI == "" {
		return nil, errors.New("mcode device authorization: incomplete response")
	}
	return prompt, nil
}

// MCodePollDevice performs one token poll. Callers loop on ErrMCodePending and
// ErrMCodeSlowDown.
func (c *Client) MCodePollDevice(ctx context.Context, prompt *MCodeDevicePrompt) (*MCodeTokens, error) {
	form := url.Values{}
	form.Set("grant_type", mcodeDeviceGrant)
	form.Set("device_code", prompt.DeviceCode)
	form.Set("client_id", MCodeClientID)
	form.Set("code_verifier", prompt.CodeVerifier)

	return c.mcodeToken(ctx, prompt.Region, form)
}

// MCodeRefresh exchanges a refresh token for a fresh pair.
func (c *Client) MCodeRefresh(ctx context.Context, region, refreshToken string) (*MCodeTokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", MCodeClientID)
	form.Set("scope", MCodeScope)
	form.Set("audience", MCodeAudience)

	return c.mcodeToken(ctx, region, form)
}

// MCodeRevoke revokes a refresh token. Errors are reported so a logout can be
// honest about it, but a caller may treat them as best-effort.
func (c *Client) MCodeRevoke(ctx context.Context, region, refreshToken string) error {
	form := url.Values{}
	form.Set("token", refreshToken)
	form.Set("token_type_hint", "refresh_token")
	form.Set("client_id", MCodeClientID)
	body, status, err := c.mcodePostForm(ctx, MCodeAccountHost(region)+mcodeRevokePath, form)
	if err != nil {
		return err
	}
	if status >= 400 {
		return &MCodeOAuthError{Code: byteField(body, "error"), Status: status}
	}
	return nil
}

func (c *Client) mcodeToken(ctx context.Context, region string, form url.Values) (*MCodeTokens, error) {
	body, status, err := c.mcodePostForm(ctx, MCodeAccountHost(region)+mcodeTokenPath, form)
	if err != nil {
		return nil, err
	}
	if status >= 400 || byteField(body, "error") != "" {
		code := byteField(body, "error")
		description := byteField(body, "error_description")
		switch code {
		case "authorization_pending":
			return nil, fmt.Errorf("%w: %s", ErrMCodePending, description)
		case "slow_down":
			return nil, fmt.Errorf("%w: %s", ErrMCodeSlowDown, description)
		case "access_denied", "denied":
			return nil, fmt.Errorf("%w: %s", ErrMCodeDenied, description)
		case "expired_token", "expired":
			return nil, fmt.Errorf("%w: %s", ErrMCodeExpired, description)
		}
		return nil, &MCodeOAuthError{Code: code, Status: status, Description: description}
	}

	access := byteField(body, "access_token")
	refresh := byteField(body, "refresh_token")
	if access == "" {
		return nil, errors.New("mcode token: response carries no access_token")
	}
	if tokenType := byteField(body, "token_type"); tokenType != "" && !strings.EqualFold(tokenType, "bearer") {
		return nil, fmt.Errorf("mcode token: unexpected token_type %q", tokenType)
	}
	tokens := &MCodeTokens{
		AccessToken:  access,
		RefreshToken: refresh,
		Scope:        byteField(body, "scope"),
	}
	if expiresIn := byteInt(body, "expires_in"); expiresIn > 0 {
		tokens.ExpiresAt = c.clock().Add(time.Duration(expiresIn) * time.Second)
	}
	return tokens, nil
}

// mcodePostForm posts a form to the account host. It reuses the transport (and
// therefore the console proxy) but none of the signed-agent headers.
func (c *Client) mcodePostForm(ctx context.Context, endpoint string, form url.Values) ([]byte, int, error) {
	settings := c.settings()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("user-agent", orDefault(settings.Upstream.UserAgent, mcodeAgentUserAgent))
	resp, err := c.do(req, settings)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, nil
}

// ------------------------------------------------------------- inference

// mcodeCompletion runs one turn against the Messages endpoint and adapts it to
// the same Result the web lane returns.
func (c *Client) mcodeCompletion(ctx context.Context, opts Options) (*Result, error) {
	settings := c.settings()
	if strings.TrimSpace(opts.Credential.Token) == "" {
		return nil, ErrInvalidCredential
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = settings.RequestTimeout()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stream := opts.OnDelta != nil || opts.OnThinking != nil
	payload, err := mcodeRequestPayload(opts, stream)
	if err != nil {
		return nil, err
	}

	endpoint := MCodeBaseURL(settings, opts.Credential) + mcodeLLMPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "text/event-stream, application/json")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-version", mcodeAnthropicVer)
	req.Header.Set("user-agent", orDefault(settings.Upstream.UserAgent, mcodeAgentUserAgent))
	req.Header.Set("authorization", "Bearer "+opts.Credential.Token)

	resp, err := c.do(req, settings)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrInvalidCredential
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if rejectsRequest(resp.StatusCode) {
			return nil, &UpstreamRejection{Prefix: "mcode message", Status: resp.StatusCode, Body: snippet(body)}
		}
		return nil, fmt.Errorf("mcode message HTTP %d: %s", resp.StatusCode, snippet(body))
	}

	if stream {
		return c.mcodeReadStream(ctx, resp.Body, opts)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return parseMCodeMessage(body)
}

// mcodeRequestPayload renders the Anthropic Messages body.
func mcodeRequestPayload(opts Options, stream bool) ([]byte, error) {
	model := strings.TrimSpace(opts.Model)
	if model == "" {
		model = mcodeFallbackModel
	}
	maxTokens := opts.MaxTokens
	if maxTokens <= 0 {
		maxTokens = mcodeAnthropicMaxTokens
	}

	content := make([]any, 0, 1+len(opts.Images))
	if opts.Text != "" {
		content = append(content, map[string]any{"type": "text", "text": opts.Text})
	}
	for _, image := range opts.Images {
		if len(image.Data) == 0 {
			// The web lane uploads first and carries an object key; there is
			// nothing inline to forward, and inventing an empty image block
			// would be rejected by the upstream.
			continue
		}
		media := image.MimeType
		if strings.TrimSpace(media) == "" {
			media = "image/png"
		}
		content = append(content, map[string]any{
			"type": "image",
			"source": map[string]any{
				"type":       "base64",
				"media_type": media,
				"data":       base64.StdEncoding.EncodeToString(image.Data),
			},
		})
	}
	if len(content) == 0 {
		return nil, errors.New("empty prompt")
	}

	body := map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"messages": []any{map[string]any{
			"role":    "user",
			"content": content,
		}},
	}
	if stream {
		body["stream"] = true
	}
	return json.Marshal(body)
}

// mcodeReadStream consumes the Anthropic SSE sequence.
//
// The events are the whole protocol: text and reasoning arrive as deltas on a
// content block, and the stop reason closes the message. A stream that ends
// without message_stop still carries usable text, so it is returned rather
// than discarded.
func (c *Client) mcodeReadStream(ctx context.Context, body io.Reader, opts Options) (*Result, error) {
	settings := c.settings()
	idle := opts.IdleTimeout
	if idle <= 0 {
		idle = settings.StreamIdleTimeout()
	}

	reader := bufio.NewReaderSize(body, 64*1024)
	result := &Result{}

	var (
		event        string
		data         strings.Builder
		lastActivity = time.Now()
	)

	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if idle > 0 && time.Since(lastActivity) > idle {
			return nil, fmt.Errorf("mcode stream idle for %s", idle)
		}
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			lastActivity = time.Now()
			trimmed := strings.TrimRight(line, "\r\n")
			switch {
			case trimmed == "":
				if dispatchErr := mcodeDispatchSSE(event, data.String(), result, opts); dispatchErr != nil {
					return result, dispatchErr
				}
				event, data = "", strings.Builder{}
			case strings.HasPrefix(trimmed, "event:"):
				event = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
			case strings.HasPrefix(trimmed, "data:"):
				if data.Len() > 0 {
					data.WriteString("\n")
				}
				data.WriteString(strings.TrimSpace(strings.TrimPrefix(trimmed, "data:")))
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				// Flush a trailing event that arrived without its blank line.
				if data.Len() > 0 {
					if dispatchErr := mcodeDispatchSSE(event, data.String(), result, opts); dispatchErr != nil {
						return result, dispatchErr
					}
				}
				result.Completed = result.Text
				result.CompletedThinking = result.Thinking
				return result, nil
			}
			return result, readErr
		}
	}
}

// mcodeDispatchSSE applies one decoded event to result and the callbacks.
func mcodeDispatchSSE(event, data string, result *Result, opts Options) error {
	if data == "" {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		return nil // keep-alive or comment payload
	}
	kind := stringField(parsed, "type")
	if kind == "" {
		kind = event
	}

	switch kind {
	case "message_start":
		if message, ok := parsed["message"].(map[string]any); ok {
			result.MessageID = stringField(message, "id")
		}
	case "content_block_start":
		if block, ok := parsed["content_block"].(map[string]any); ok {
			if text := stringField(block, "text"); text != "" && stringField(block, "type") == "text" {
				result.Text += text
				if opts.OnDelta != nil {
					opts.OnDelta(text)
				}
			}
		}
	case "content_block_delta":
		delta, ok := parsed["delta"].(map[string]any)
		if !ok {
			return nil
		}
		switch stringField(delta, "type") {
		case "text_delta":
			if text := stringField(delta, "text"); text != "" {
				result.Text += text
				if opts.OnDelta != nil {
					opts.OnDelta(text)
				}
			}
		case "thinking_delta":
			if text := stringField(delta, "thinking"); text != "" {
				result.Thinking += text
				if opts.OnThinking != nil {
					opts.OnThinking(text)
				}
			}
		}
	case "message_delta":
		if delta, ok := parsed["delta"].(map[string]any); ok {
			if stop := stringField(delta, "stop_reason"); stop != "" {
				result.StopReason = stop
			}
		}
	case "error":
		message := stringField(parsed, "message")
		if message == "" {
			if detail, ok := parsed["error"].(map[string]any); ok {
				message = stringField(detail, "message")
			}
		}
		if message == "" {
			message = "mcode stream error"
		}
		return errors.New(message)
	}
	return nil
}

// parseMCodeMessage adapts a non-streaming Messages response.
func parseMCodeMessage(body []byte) (*Result, error) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("mcode message: invalid JSON: %w", err)
	}
	if stringField(parsed, "type") == "error" {
		detail, _ := parsed["error"].(map[string]any)
		message := firstNonEmptyString(stringField(detail, "message"), stringField(parsed, "message"))
		if message == "" {
			message = "mcode message rejected"
		}
		return nil, errors.New(message)
	}
	result := &Result{
		MessageID:  stringField(parsed, "id"),
		StopReason: stringField(parsed, "stop_reason"),
	}
	blocks, _ := parsed["content"].([]any)
	for _, raw := range blocks {
		block, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		switch stringField(block, "type") {
		case "text":
			result.Text += stringField(block, "text")
		case "thinking":
			result.Thinking += stringField(block, "thinking")
		}
	}
	if result.Text == "" && result.Thinking == "" {
		return nil, errors.New("mcode message: response carried no text")
	}
	result.Completed = result.Text
	result.CompletedThinking = result.Thinking
	return result, nil
}

// MCodeModel is the slice of a catalogue entry the console needs.
type MCodeModel struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Reasoning    bool   `json:"reasoning,omitempty"`
	Attachment   bool   `json:"attachment,omitempty"`
	ToolCall     bool   `json:"toolCall,omitempty"`
	ContextLimit int    `json:"contextLimit,omitempty"`
	MaxOutput    int    `json:"maxOutput,omitempty"`
	// Input is the accepted modality list (text/image/video/audio/pdf).
	Input []string `json:"input,omitempty"`
	// Thinking mirrors `thinking_config.mode`: switchable / forced_on / forced_off.
	Thinking string `json:"thinking,omitempty"`
	// EffortOptions and DefaultEffort mirror `effort_options` / `default_effort`.
	EffortOptions []string `json:"effortOptions,omitempty"`
	DefaultEffort string   `json:"defaultEffort,omitempty"`
	// MaxAttachments is `capabilities.max_attachments_count`.
	MaxAttachments int   `json:"maxAttachments,omitempty"`
	ContextWindows []int `json:"contextWindows,omitempty"`
}

// MCodeModels lists the models the account may use. It doubles as the cheapest
// credential check: a bearer that cannot list models cannot complete either.
func (c *Client) MCodeModels(ctx context.Context, cred Credential) ([]MCodeModel, error) {
	settings := c.settings()
	endpoint := fmt.Sprintf("%s%s?region=%s&buildEnv=prod",
		MCodeBaseURL(settings, cred), mcodeModelsPath, mcodeRegionTag(cred.Region))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("user-agent", orDefault(settings.Upstream.UserAgent, mcodeAgentUserAgent))
	req.Header.Set("authorization", "Bearer "+cred.Token)

	resp, err := c.do(req, settings)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrInvalidCredential
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("mcode models HTTP %d: %s", resp.StatusCode, snippet(body))
	}
	return parseMCodeModels(body), nil
}

// parseMCodeModels flattens providers[].config.models into a list.
func parseMCodeModels(body []byte) []MCodeModel {
	var parsed struct {
		Providers []struct {
			Config struct {
				Models map[string]struct {
					Name       string `json:"name"`
					Reasoning  bool   `json:"reasoning"`
					Attachment bool   `json:"attachment"`
					ToolCall   bool   `json:"tool_call"`
					Limit      struct {
						Context int `json:"context"`
						Output  int `json:"output"`
					} `json:"limit"`
					Modalities struct {
						Input []string `json:"input"`
					} `json:"modalities"`
					ThinkingConfig struct {
						Mode string `json:"mode"`
					} `json:"thinking_config"`
					EffortOptions []string `json:"effort_options"`
					DefaultEffort string   `json:"default_effort"`
					Capabilities  struct {
						MaxAttachments int `json:"max_attachments_count"`
					} `json:"capabilities"`
					ContextWindowOptions []int `json:"context_window_options"`
				} `json:"models"`
			} `json:"config"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	var models []MCodeModel
	for _, provider := range parsed.Providers {
		for id, model := range provider.Config.Models {
			models = append(models, MCodeModel{
				ID:             id,
				Name:           firstNonEmptyString(model.Name, id),
				Reasoning:      model.Reasoning,
				Attachment:     model.Attachment,
				ToolCall:       model.ToolCall,
				ContextLimit:   model.Limit.Context,
				MaxOutput:      model.Limit.Output,
				Input:          model.Modalities.Input,
				Thinking:       model.ThinkingConfig.Mode,
				EffortOptions:  model.EffortOptions,
				DefaultEffort:  model.DefaultEffort,
				MaxAttachments: model.Capabilities.MaxAttachments,
				ContextWindows: model.ContextWindowOptions,
			})
		}
	}
	return models
}

// ------------------------------------------------------------- helpers

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// intField reads a positive integer from a decoded JSON object.
func intField(parsed map[string]any, key string) int {
	switch value := parsed[key].(type) {
	case float64:
		if value > 0 && value == float64(int(value)) {
			return int(value)
		}
	case int:
		if value > 0 {
			return value
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// byteField decodes body as an object and reads one string field.
func byteField(body []byte, key string) string {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}
	return stringField(parsed, key)
}

// byteInt decodes body as an object and reads one positive integer field.
func byteInt(body []byte, key string) int {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0
	}
	return intField(parsed, key)
}
