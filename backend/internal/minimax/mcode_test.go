package minimax

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"minimax2api/internal/config"
)

// withMCodeAccountHost points the OAuth host at a test server for one test.
func withMCodeAccountHost(t *testing.T, url string) {
	t.Helper()
	oldGlobal, oldCN := mcodeAccountHostGlobal, mcodeAccountHostCN
	mcodeAccountHostGlobal, mcodeAccountHostCN = url, url
	t.Cleanup(func() { mcodeAccountHostGlobal, mcodeAccountHostCN = oldGlobal, oldCN })
}

func mcodeTestClient() *Client {
	settings := config.Settings{Upstream: config.UpstreamSettings{
		RequestTimeoutSec:    30,
		StreamIdleTimeoutSec: 30,
		UserAgent:            "MiniMaxAgent",
	}}
	return New(func() config.Settings { return settings })
}

// The device request is the whole login: public client, scope, audience and a
// PKCE S256 challenge. A wrong value here is answered with an OAuth error, not
// a hint, so the form fields are asserted exactly.
func TestMCodeStartDeviceSendsTheDocumentedForm(t *testing.T) {
	var form url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != mcodeDevicePath {
			t.Errorf("path = %q, want %q", r.URL.Path, mcodeDevicePath)
		}
		_ = r.ParseForm()
		form = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dev-123",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          "https://account.minimax.io/oauth-authorize",
			"verification_uri_complete": "https://account.minimax.io/oauth-authorize?user_code=ABCD-EFGH",
			"expires_in":                300,
			"interval":                  3,
		})
	}))
	defer server.Close()
	withMCodeAccountHost(t, server.URL)

	prompt, err := mcodeTestClient().MCodeStartDevice(context.Background(), RegionGlobal)
	if err != nil {
		t.Fatalf("start device: %v", err)
	}
	if form.Get("client_id") != MCodeClientID || form.Get("scope") != MCodeScope || form.Get("audience") != MCodeAudience {
		t.Fatalf("form = %v", form)
	}
	if form.Get("code_challenge_method") != "S256" || form.Get("code_challenge") == "" {
		t.Fatalf("PKCE missing: %v", form)
	}
	if prompt.UserCode != "ABCD-EFGH" || prompt.Interval != 3 || prompt.ExpiresIn != 300 {
		t.Fatalf("prompt = %+v", prompt)
	}
	if prompt.CodeVerifier == "" || prompt.DeviceCode != "dev-123" {
		t.Fatalf("secrets not carried: %+v", prompt)
	}
}

func TestMCodePollDeviceReportsPending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":             "authorization_pending",
			"error_description": "the user has not finished authorizing yet",
		})
	}))
	defer server.Close()
	withMCodeAccountHost(t, server.URL)

	_, err := mcodeTestClient().MCodePollDevice(context.Background(), &MCodeDevicePrompt{
		DeviceCode: "dev-123", CodeVerifier: "verifier", Region: RegionGlobal,
	})
	if !errors.Is(err, ErrMCodePending) {
		t.Fatalf("err = %v, want ErrMCodePending", err)
	}
}

// A successful poll must carry both halves and a derived expiry: the access
// token is opaque, so expires_in is the only lifetime information there is.
func TestMCodePollDeviceParsesTokensAndExpiry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != mcodeDeviceGrant {
			t.Errorf("grant_type = %q", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("code_verifier") != "verifier" {
			t.Errorf("code_verifier = %q", r.PostForm.Get("code_verifier"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "test-access-token",
			"refresh_token": "test-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "agent.default",
		})
	}))
	defer server.Close()
	withMCodeAccountHost(t, server.URL)

	before := time.Now()
	tokens, err := mcodeTestClient().MCodePollDevice(context.Background(), &MCodeDevicePrompt{
		DeviceCode: "dev-123", CodeVerifier: "verifier", Region: RegionGlobal,
	})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if tokens.AccessToken != "test-access-token" || tokens.RefreshToken != "test-refresh-token" {
		t.Fatalf("tokens = %+v", tokens)
	}
	if d := tokens.ExpiresAt.Sub(before); d < 3500*time.Second || d > 3700*time.Second {
		t.Fatalf("expiry = %s, want ~1h from now", d)
	}
}

func TestMCodeRefreshSendsTheRefreshGrant(t *testing.T) {
	var form url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-new", "refresh_token": "test-refresh-new",
			"token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer server.Close()
	withMCodeAccountHost(t, server.URL)

	tokens, err := mcodeTestClient().MCodeRefresh(context.Background(), RegionGlobal, "mmort_old")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "mmort_old" {
		t.Fatalf("form = %v", form)
	}
	if form.Get("client_id") != MCodeClientID || form.Get("scope") != MCodeScope || form.Get("audience") != MCodeAudience {
		t.Fatalf("form = %v", form)
	}
	if tokens.AccessToken != "test-access-new" {
		t.Fatalf("tokens = %+v", tokens)
	}
}

// The Messages endpoint authenticates with the bearer alone. This test pins that
// down because the signed web headers are the natural (and wrong) thing to add:
// the mcode edge never computes them, and a request carrying a stray `yy` is a
// different request.
func TestMCodeCompletionUsesBearerWithoutSignatureHeaders(t *testing.T) {
	var (
		sawAuth      string
		sawVersion   string
		sawSignature string
		sawYY        string
		sawLegacy    string
		body         map[string]any
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != mcodeLLMPath {
			t.Errorf("path = %q, want %q", r.URL.Path, mcodeLLMPath)
		}
		sawAuth = r.Header.Get("authorization")
		sawVersion = r.Header.Get("anthropic-version")
		sawSignature = r.Header.Get("x-signature")
		sawYY = r.Header.Get("yy")
		sawLegacy = r.Header.Get("token")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant",
			"model": "MiniMax-M3.1-Flash", "stop_reason": "end_turn",
			"content": []any{
				map[string]any{"type": "thinking", "thinking": "weighing it"},
				map[string]any{"type": "text", "text": "hello"},
			},
		})
	}))
	defer server.Close()

	client := mcodeTestClient()
	result, err := client.Completion(context.Background(), Options{
		Credential: Credential{Kind: KindMCode, Token: "test-access-abc", BaseURL: server.URL},
		Text:       "hi",
		Model:      "MiniMax-M3.1-Flash",
		MaxTokens:  64,
	})
	if err != nil {
		t.Fatalf("completion: %v", err)
	}
	if sawAuth != "Bearer test-access-abc" || sawVersion != mcodeAnthropicVer {
		t.Fatalf("auth=%q version=%q", sawAuth, sawVersion)
	}
	if sawSignature != "" || sawYY != "" || sawLegacy != "" {
		t.Fatalf("signed headers must not be sent: sig=%q yy=%q token=%q", sawSignature, sawYY, sawLegacy)
	}
	if body["model"] != "MiniMax-M3.1-Flash" || body["max_tokens"] != float64(64) {
		t.Fatalf("body = %v", body)
	}
	if _, streamed := body["stream"]; streamed {
		t.Fatalf("a non-streaming call must not ask for a stream: %v", body)
	}
	if result.Text != "hello" || result.Thinking != "weighing it" {
		t.Fatalf("result = %+v", result)
	}
}

// The stream is the Anthropic sequence, and reasoning arrives on
// thinking_delta while the answer arrives on text_delta.
func TestMCodeCompletionStreamsAnthropicEvents(t *testing.T) {
	frames := strings.Join([]string{
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"msg_2","model":"MiniMax-M3.1-Flash"}}`,
		"",
		"event: ping",
		`data: {"type":"ping"}`,
		"",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"step"}}`,
		"",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"hel"}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"lo"}}`,
		"",
		"event: message_delta",
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}`,
		"",
		"event: message_stop",
		`data: {"type":"message_stop"}`,
		"",
	}, "\n")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if body["stream"] != true {
			t.Errorf("streaming call must ask for a stream: %v", body)
		}
		w.Header().Set("content-type", "text/event-stream")
		_, _ = io.WriteString(w, frames)
	}))
	defer server.Close()

	var text, thinking string
	client := mcodeTestClient()
	result, err := client.Completion(context.Background(), Options{
		Credential: Credential{Kind: KindMCode, Token: "test-access-abc", BaseURL: server.URL},
		Text:       "hi",
		OnDelta:    func(s string) { text += s },
		OnThinking: func(s string) { thinking += s },
	})
	if err != nil {
		t.Fatalf("completion: %v", err)
	}
	if text != "hello" || thinking != "step" {
		t.Fatalf("streamed text=%q thinking=%q", text, thinking)
	}
	if result.Text != "hello" || result.Thinking != "step" || result.StopReason != "end_turn" {
		t.Fatalf("result = %+v", result)
	}
	if result.MessageID != "msg_2" {
		t.Fatalf("message id = %q", result.MessageID)
	}
}

func TestMCodeModelsReadsTheCatalogue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer test-access-abc" {
			t.Errorf("authorization = %q", r.Header.Get("authorization"))
		}
		if r.URL.Query().Get("region") != "en" || r.URL.Query().Get("buildEnv") != "prod" {
			t.Errorf("query = %v", r.URL.Query())
		}
		_, _ = io.WriteString(w, `{"providers":[{"providerId":"minimax","config":{"models":{
			"MiniMax-M3.1-Flash":{"name":"M3.1-Flash","limit":{"context":512000}},
			"MiniMax-M3":{"name":"M3","limit":{"context":400000}}}}}]}`)
	}))
	defer server.Close()

	models, err := mcodeTestClient().MCodeModels(context.Background(),
		Credential{Kind: KindMCode, Token: "test-access-abc", BaseURL: server.URL})
	if err != nil {
		t.Fatalf("models: %v", err)
	}
	if len(models) != 2 {
		t.Fatalf("models = %+v", models)
	}
	seen := map[string]bool{}
	for _, model := range models {
		seen[model.ID] = true
	}
	if !seen["MiniMax-M3.1-Flash"] || !seen["MiniMax-M3"] {
		t.Fatalf("models = %+v", models)
	}
}

// A 401 from the Messages endpoint is a credential failure, not a transient one:
// the pool must retire the account instead of retrying it.
func TestMCodeCompletionMaps401ToInvalidCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid access token"}`)
	}))
	defer server.Close()

	_, err := mcodeTestClient().Completion(context.Background(), Options{
		Credential: Credential{Kind: KindMCode, Token: "test-access-abc", BaseURL: server.URL},
		Text:       "hi",
	})
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}
