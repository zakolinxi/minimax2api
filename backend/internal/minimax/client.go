package minimax

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"minimax2api/internal/config"
)

// Region values. MiniMax runs two independent deployments behind the same
// product: the mainland one (agent.minimaxi.com) and the international one
// (agent.minimax.io). Accounts registered with a mainland phone number live on
// the former, accounts registered with an email or an overseas number on the
// latter, and a token from one is rejected by the other — so the region is a
// per-account property, not a global setting.
const (
	RegionCN     = "cn"
	RegionGlobal = "global"
)

// Default paths. Both are exposed as runtime settings because the upstream
// bundle is free to rename them; a capture that disagrees can be pasted into
// the console without a rebuild.
const (
	// DefaultSessionPath opens a conversation.
	//
	// The `/minimax-cloud/api/v1` prefix is load-bearing. Drop it and the
	// request still answers **200 — with a page of the SPA's HTML** — because it
	// lands on the Next.js catch-all route. Nothing about that response says
	// "wrong path", so the mistake survives every check that only looks at the
	// status code.
	DefaultSessionPath = "/minimax-cloud/api/v1/agent/{agent_id}/session"
	// DefaultMessagePath sends one turn. It shares a prefix with the session
	// path but answers on a different host, which is derived rather than
	// hardcoded — see streamHostFor.
	DefaultMessagePath = "/minimax-cloud/api/v1/session/{session_id}/message"
)

// DefaultAgentID is deliberately empty.
//
// The obvious-looking "general" is an agent *role*, not an id. The upstream
// accepts it with a 200 that carries no session at all — a failure shaped
// exactly like a success. The real id is a number (`443154487857417` for the
// general agent of one account) and differs per account, so it is discovered
// from the agent list rather than guessed. See Client.FetchAgents.
const DefaultAgentID = ""

// ErrInvalidCredential marks a token the upstream rejected.
var ErrInvalidCredential = errors.New("minimax credential rejected")

// ErrAgentIDUnknown marks an account whose agent id has not been resolved yet.
//
// It is separate from ErrInvalidCredential on purpose. Both look like "this
// account cannot be used", but one is the token's fault and the other is a
// missing piece of preparation — and the pool retires an account that reports
// the first. An account that has simply never been prepared must not be
// retired for it.
var ErrAgentIDUnknown = errors.New("minimax agent id unknown")

// ErrUpstreamRejected marks a call the upstream refused because of the request
// itself — `400 invalid_params` and friends.
//
// It is a third kind of failure, and the one that used to be missing. Before it
// existed, every non-401 4xx fell through to a bare fmt.Errorf, which is
// indistinguishable from a transient 5xx: the gateway retried it on another
// account and the pool charged the failure to whichever accounts it landed on.
// A request the upstream will never accept cannot be fixed by another account,
// so one client sending a bad attachment URL was enough to walk the whole pool
// into cooldown and then answer everyone with "all accounts are busy".
var ErrUpstreamRejected = errors.New("minimax rejected the request")

// ErrEmptyResponse marks a turn the upstream ended without producing anything.
// It is neither a refusal (another account may answer) nor an account fault
// (the pool must not cool the account down for it).
var ErrEmptyResponse = errors.New("upstream returned an empty response")

// UpstreamRejection carries the status the upstream answered with, so callers
// can hand the caller back the real reason instead of a blanket 502.
type UpstreamRejection struct {
	// Prefix names the call that was refused, so a log line still says which
	// hop failed. Empty means the message path.
	Prefix string
	Status int
	Body   string
}

func (e *UpstreamRejection) Error() string {
	hop := e.Prefix
	if hop == "" {
		hop = "message"
	}
	return fmt.Sprintf("minimax %s HTTP %d: %s", hop, e.Status, e.Body)
}

func (e *UpstreamRejection) Is(target error) bool { return target == ErrUpstreamRejected }

// UpstreamStatus reports the HTTP status behind an upstream refusal, or 0 when
// err is not one. A caller that gets 0 should keep its own gateway status.
func UpstreamStatus(err error) int {
	var rej *UpstreamRejection
	if errors.As(err, &rej) {
		return rej.Status
	}
	return 0
}

// rejectsRequest reports whether a 4xx is the request's fault rather than the
// account's.
//
// 401 and 403 mean the credential is dead. 429 means the account is out of
// room right now. 408 is a timeout, which the next account may well answer.
// Everything else in the 4xx range describes the call itself, and repeating it
// somewhere else only spends another account to learn the same thing.
func rejectsRequest(status int) bool {
	if status < 400 || status > 499 {
		return false
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden,
		http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return true
}

// MediaRef is a generated image or video returned inside the SSE stream.
type MediaRef struct {
	Kind string `json:"kind"`
	URL  string `json:"url"`
}

// Credential is everything needed to impersonate one browser session.
//
// The metadata fields (UUID, DeviceID, screen size) are not decoration: the
// `yy` header is computed over the query string built from them, so a token
// only works when it travels with the fingerprint it was issued to.
type Credential struct {
	// Kind selects the upstream protocol: "" / "token" / "guest" are the web
	// agent (JWT + x-signature/yy), "mcode" is the MiniMax Code desktop lane
	// (OAuth bearer + Anthropic Messages).
	Kind         string
	Region       string
	Token        string
	UserID       string
	AgentID      string
	DeviceID     string
	UUID         string
	ScreenWidth  int
	ScreenHeight int
	// BaseURL optionally pins this account to a specific host, which is how a
	// self-hosted relay or a captured alternative domain gets used.
	BaseURL string
}

// Label returns a stable human-readable identifier for logs and audits.
func (c Credential) Label() string {
	if c.UserID != "" {
		return c.UserID
	}
	if len(c.Token) > 12 {
		return c.Token[:12] + "…"
	}
	return c.Token
}

// ToolCall is one entry of a chunk's `tool_calls`, as the upstream reports it.
//
// These are the *agent's* own tool invocations — the same events the web UI
// renders as "using the video plugin" — not function calls the API caller
// declared. They are collected for observability, not re-emitted as OpenAI
// tool_calls: doing the latter would hand a client a name it never registered.
type ToolCall struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// Args accumulates `argsDelta`; `args` replaces it when the upstream sends
	// the whole payload in one frame.
	Args       string `json:"args,omitempty"`
	Status     string `json:"status,omitempty"`
	Result     string `json:"result,omitempty"`
	DurationMS int64  `json:"durationMs,omitempty"`
}

// Result is the aggregated outcome of one completion.
type Result struct {
	Text       string
	Thinking   string
	Media      []MediaRef
	SessionID  string
	MessageID  string
	TurnID     string
	StopReason string

	// ToolCalls are the agent-side tool invocations seen in this turn, keyed by
	// id and in first-seen order. Empty for a plain answer.
	ToolCalls []ToolCall

	// Completed and CompletedThinking hold the whole-message restatement that
	// closes a turn (see messageFrameOf). They are a fallback for a stream that
	// never chunked — not a second copy of the answer.
	Completed         string
	CompletedThinking string
}

// Options describes one upstream call.
type Options struct {
	Credential Credential
	Text       string
	Mode       string
	// ClientIntent labels the kind of turn for the backend.
	//
	// The field and the value are both real — the web client sends
	// `client_intent`, and the bundle's tool-type table maps the four video
	// tools onto `video_generation` (see internal/minimax/video.go). What has
	// never been demonstrated is that it *changes anything*: the one live test
	// of it produced no tool call and no file, exactly like the turns that
	// omitted it. It is sent on video turns because the web client sends it,
	// not because it has been shown to unlock the video service. Do not read
	// this field as the switch that turns generation on.
	ClientIntent string
	// Model is the upstream selector for this turn: the catalogue entry's
	// UpstreamModel. Empty means the turn names no model, which is what the
	// agent entry does.
	Model string
	// Variant is the model object's `variant`: "thinking" turns the reasoning
	// variant on and "" turns it off. Nil omits the field entirely, which lets
	// the upstream apply its own default — that is the difference a plain
	// `thinking` boolean cannot express, and the reason this is a pointer.
	Variant *string
	// ContextLimit asks for a context window, in tokens. Zero omits the field
	// and leaves the upstream default in place.
	ContextLimit int
	// Reasoning is the model object's `reasoning` flag. Nil omits the field.
	//
	// The web client's serialiser (module 81775) forwards it whenever the
	// selection carries one, but the current `/config` catalogue never sets it
	// and no live request has been captured with it. It is therefore plumbed
	// through faithfully and left off unless a caller asks for it — inventing a
	// value here would be a guess with a 400 as its only feedback.
	Reasoning *bool
	// ThinkingEffort is the model object's `thinking.effort`. Empty omits the
	// field, which is what the upstream treats as its `default_effort`.
	//
	// The catalogue reports the accepted values per model (`effort_options`),
	// e.g. default/low/medium/high/xhigh/max on M3.1-Flash. See
	// gateway.thinkingEffort for the repair rule.
	ThinkingEffort string
	Images         []UploadedImage
	// Files ride along as `meta`/`cloud` attachment envelopes after being
	// pushed to the object store with the turn's own credential. See
	// PendingAttachment for why the upload cannot happen earlier.
	Files       []PendingAttachment
	Timeout     time.Duration
	IdleTimeout time.Duration
	// MaxTokens caps the reply on protocols that require an output budget
	// (Anthropic Messages does). Zero leaves the default to the client.
	MaxTokens  int
	OnDelta    func(string)
	OnThinking func(string)
	// OnFrame sees every decoded frame, before anything decides what it means.
	//
	// Dispatch is driven by payload keys, which is what keeps the adapter
	// working when the upstream renumbers its event enum — and it is also why a
	// frame nobody recognises disappears without a trace. This hook is how a
	// diagnostic gets to ask the question that keeps coming up: *what does the
	// upstream actually send?* Nil means nothing is watching.
	OnFrame       func(map[string]any)
	DisableStream bool
}

// UploadedImage is a picture the turn carries.
//
// It used to be a bare URL: the upstream resolved the reference server-side and
// that was the entire integration. That path is closed. The upstream now
// answers a URL-only attachment with
//
//	[1406010011]: attachment requires one owned object_key or allowed legacy URL
//
// so a picture has to travel exactly the way a document does — prepared, pushed
// to the object store with the turn's own credential, and referenced by the
// object key that comes back. Only the envelope differs, and only in one field;
// see buildMessageBody.
//
// It is an alias rather than a second struct because the payload is genuinely
// the same one, and two copies of it would be two places to forget a field.
type UploadedImage = PendingAttachment

// Client talks to the MiniMax Agent web API.
type Client struct {
	http     *http.Client
	settings func() config.Settings
	// now is a test seam. `unix` and `yy` have to come from a single clock
	// reading, and the only way to prove they do is to hand the client a clock
	// that does not move. Nil means time.Now.
	now func() time.Time
	// uploads remembers object keys per (account token, file content). A
	// retried turn on the same account must not push the same bytes upstream
	// twice. See upload.go.
	uploads uploadCache
	// proxyMu guards the lazily built proxied client. do() used to construct a
	// fresh http.Client and Transport for every proxied request — a new TCP and
	// TLS handshake per call and an idle pool nobody reused. The client is
	// rebuilt only when the console changes the proxy address; the outgoing
	// transport's idle connections are closed so the old address does not keep
	// sockets open until they time out.
	proxyMu        sync.Mutex
	proxyClient    *http.Client
	proxyTransport *http.Transport
	proxyFor       string
}

// clock returns the client's time source. A zero-value Client is usable, which
// is why the nil case is handled here rather than at construction.
func (c *Client) clock() time.Time {
	if c.now == nil {
		return time.Now()
	}
	return c.now()
}

// New builds a client. settingsFn is re-read on every request so runtime
// configuration changes apply without a restart.
func New(settingsFn func() config.Settings) *Client {
	transport := &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Client{
		http: &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 5 {
					return errors.New("too many redirects")
				}
				return nil
			},
		},
		settings: settingsFn,
	}
}

// ------------------------------------------------------------------ endpoint

func (c *Client) baseURL(settings config.Settings, cred Credential) string {
	if cred.BaseURL != "" {
		return strings.TrimRight(cred.BaseURL, "/")
	}
	if cred.Region == RegionCN && settings.Upstream.BaseURLCN != "" {
		return strings.TrimRight(settings.Upstream.BaseURLCN, "/")
	}
	return strings.TrimRight(settings.Upstream.BaseURL, "/")
}

// agentID resolves the agent to drive: the account's own id, else the global
// setting, else the default.
//
// A role name is never an id, and is skipped rather than used. The upstream
// answers one with a 200 that carries no session, so accepting `general` here
// makes every request look successful and produce nothing — and a settings file
// written by an earlier build holds exactly that value, because it was that
// build's default. Skipping it means such a file cannot take effect even before
// Normalize has repaired it.
func (c *Client) agentID(settings config.Settings, cred Credential) string {
	for _, candidate := range []string{cred.AgentID, settings.Upstream.AgentID} {
		if id := strings.TrimSpace(candidate); id != "" && !isAgentRole(id) {
			return id
		}
	}
	return DefaultAgentID
}

func sessionPath(settings config.Settings) string {
	if path := strings.TrimSpace(settings.Upstream.SessionPath); path != "" {
		return path
	}
	return DefaultSessionPath
}

func messagePath(settings config.Settings) string {
	if path := strings.TrimSpace(settings.Upstream.MessagePath); path != "" {
		return path
	}
	return DefaultMessagePath
}

// clientQuery renders the client metadata in the exact order the captured web
// client sends it, and returns it twice.
//
// The two strings differ on purpose, and that difference is the single most
// common way a hand-written client gets `yy` wrong:
//
//   - wire goes on the request URL. It is what axios actually transmits, and
//     axios drops `null`/`undefined` parameters.
//   - signed is what the bundle hashes. It is built with
//     `new URLSearchParams(params)`, which stringifies those same absent values
//     as "null"/"undefined" — so the signed string carries `uuid=null`,
//     `op_ticket=undefined` and `token=null` even though the wire URL carries
//     none of them.
//
// Reusing one string for both produces a digest the upstream never computes.
// Deliberately so, or at least unavoidably so: `yy` covers the client's own
// parameter map, not the request it becomes.
//
// The order is part of the contract too. url.Values.Encode() sorts keys and
// therefore cannot be used here.
//
// Values are encoded the way URLSearchParams encodes them — a space becomes
// "+", not "%20" — because the signed string is hashed verbatim. `unix` comes
// from the caller's clock rather than a reading taken here: it has to be the
// same reading that feeds `yy`, and a second time.Now() would sign an instant
// that was never sent.
func clientQuery(settings config.Settings, cred Credential, now time.Time) (wire, signed string) {
	width := cred.ScreenWidth
	if width <= 0 {
		width = settings.Upstream.ScreenWidth
	}
	height := cred.ScreenHeight
	if height <= 0 {
		height = settings.Upstream.ScreenHeight
	}

	// Every entry carries both readings. `wireValue` empty means axios would
	// have dropped it; `signedValue` is what URLSearchParams would have
	// printed, which for an absent credential field is the literal "null".
	type pair struct{ key, wireValue, signedValue string }
	unixMillis := strconv.FormatInt(signatureMillis(now), 10)
	pairs := []pair{
		{"device_platform", "web", "web"},
		{"biz_id", "3", "3"},
		{"app_id", "3001", "3001"},
		{"version_code", "22201", "22201"},
		{"unix", unixMillis, unixMillis},
		{"timezone_offset", "28800", "28800"},
		{"sys_language", "en", "en"},
		{"lang", "en", "en"},
		{"uuid", cred.UUID, orLiteral(cred.UUID, "null")},
		{"device_id", orLiteral(cred.DeviceID, "0"), orLiteral(cred.DeviceID, "0")},
		{"os_name", "Windows", "Windows"},
		{"browser_name", "Chrome", "Chrome"},
		{"device_memory", "16", "16"},
		{"cpu_core_num", "8", "8"},
		{"browser_language", "zh-CN", "zh-CN"},
		{"browser_platform", "Win32", "Win32"},
		{"user_id", orLiteral(cred.UserID, "0"), orLiteral(cred.UserID, "0")},
		// op_ticket is `d?.op_ticket` upstream: absent for a cloud web session,
		// which URLSearchParams prints as "undefined". It is never transmitted,
		// because axios drops undefined params.
		{"op_ticket", "", "undefined"},
		{"screen_width", strconv.Itoa(width), strconv.Itoa(width)},
		{"screen_height", strconv.Itoa(height), strconv.Itoa(height)},
		{"token", cred.Token, orLiteral(cred.Token, "null")},
		{"client", "web", "web"},
		{"region", "en", "en"},
	}

	wirePairs := make([]string, 0, len(pairs))
	signedPairs := make([]string, 0, len(pairs))
	for _, item := range pairs {
		if item.wireValue != "" {
			wirePairs = append(wirePairs, item.key+"="+formEncode(item.wireValue))
		}
		signedPairs = append(signedPairs, item.key+"="+formEncode(item.signedValue))
	}
	return strings.Join(wirePairs, "&"), strings.Join(signedPairs, "&")
}

// orLiteral returns value when it is set and fallback otherwise.
func orLiteral(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// buildURLWith assembles the exact URL that will be requested.
//
// It also returns the *signed target* — the path plus the signed query string —
// because `yy` covers that and not the URL. The two differ in more than the
// host: the signed query keeps the "null"/"undefined" placeholders the URL must
// not carry. See clientQuery.
func (c *Client) buildURLWith(base string, settings config.Settings, cred Credential, path, sessionID string, now time.Time) (rawURL, signedTarget string) {
	path = strings.ReplaceAll(path, "{agent_id}", c.agentID(settings, cred))
	path = strings.ReplaceAll(path, "{session_id}", sessionID)

	wireQuery, signedQuery := clientQuery(settings, cred, now)

	signedTarget = path
	if signedQuery != "" {
		signedTarget += joinQuery(path, signedQuery)
	}

	rawURL = strings.TrimRight(base, "/") + path
	if wireQuery != "" {
		rawURL += joinQuery(path, wireQuery)
	}
	return rawURL, signedTarget
}

// joinQuery appends a query string to a path that may already carry one.
//
// The difference between "?" and "&" is one byte and invisible in the URL, but
// `yy` covers the string verbatim, so getting it wrong rejects the request for
// a reason that names nothing.
func joinQuery(path, query string) string {
	if strings.Contains(path, "?") {
		return "&" + query
	}
	return "?" + query
}

// buildURL targets the account's API host.
func (c *Client) buildURL(settings config.Settings, cred Credential, path, sessionID string, now time.Time) string {
	rawURL, _ := c.buildURLWith(c.baseURL(settings, cred), settings, cred, path, sessionID, now)
	return rawURL
}

// streamBaseURL is the host the conversation endpoint answers on.
//
// The captured web client posts turns to `agent-stream.<domain>` while every
// other call stays on `agent.<domain>`. The gateway used the API host for both
// for a long time, and the two are not interchangeable: the same path there is a
// *different entry point*, one that reaches the agent but hands it no rendering
// tool — so every turn came back as a plausible reply with no video and no
// error to explain why.
//
// An explicit setting wins, so a capture that disagrees can be pasted into the
// console without a rebuild.
func streamBaseURL(settings config.Settings, fallback string) string {
	if explicit := strings.TrimSpace(settings.Upstream.StreamBaseURL); explicit != "" {
		return strings.TrimRight(explicit, "/")
	}
	return streamHostFor(fallback)
}

// streamHostFor maps an API host to its streaming counterpart.
//
// Only the `agent.<domain>` shape is recognised, because that is the only one
// that has been observed — and the alternative to deriving it is hardcoding a
// hostname, which would then be wrong for every other deployment. A self-hosted
// relay and a test server therefore keep their own address rather than having a
// name invented for them.
//
// The mainland deployment runs the same web client, so the same shape is applied
// to it. That is an inference rather than a capture, which is why it is allowed
// to stand: a hostname that does not exist is a DNS error, not a silent success,
// so being wrong about it is loud. Setting StreamBaseURL overrides all of this.
func streamHostFor(base string) string {
	parsed, err := url.Parse(base)
	if err != nil {
		return base
	}
	host := parsed.Hostname()
	if !strings.HasPrefix(host, "agent.") {
		return base
	}
	target := "agent-stream." + strings.TrimPrefix(host, "agent.")
	if port := parsed.Port(); port != "" {
		target = net.JoinHostPort(target, port)
	}
	parsed.Host = target
	return parsed.String()
}

// requestTarget names the endpoint a request is aimed at.
//
// Paths carry {agent_id} / {session_id} placeholders, which are substituted
// without going through net/url so the query order survives byte for byte.
type requestTarget struct {
	// Path is the endpoint template.
	Path string
	// SessionID fills {session_id}.
	SessionID string
	// Stream routes the call to the conversation host, which is a different
	// entry point from the API host rather than another address for the same
	// one. See streamBaseURL.
	Stream bool
}

// newRequest builds and signs a request.
//
// It takes a target rather than a finished URL because `unix`, `x-timestamp`
// and `yy` all have to come from one clock reading, and `yy` covers the encoded
// URL: assembling the URL anywhere else would need a second reading, and a few
// milliseconds of drift would make the digest describe a URL that was never
// sent. Keeping both halves here makes that impossible to get wrong from the
// outside.
func (c *Client) newRequest(ctx context.Context, settings config.Settings, cred Credential, method string, target requestTarget, body []byte) (*http.Request, error) {
	now := c.clock()

	base := c.baseURL(settings, cred)
	if target.Stream {
		base = streamBaseURL(settings, base)
	}
	rawURL, signedTarget := c.buildURLWith(base, settings, cred, target.Path, target.SessionID, now)

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		// A malformed URL puts the whole signed URL — token query included —
		// into the error text, and this error reaches pool.LastError and the
		// API response. Strip the query the way transportError does.
		sanitized := err.Error()
		if parsed, parseErr := url.Parse(rawURL); parseErr == nil {
			parsed.RawQuery = ""
			sanitized = strings.ReplaceAll(sanitized, rawURL, parsed.String())
		}
		return nil, errors.New(sanitized)
	}

	bodyText := string(body)

	req.Header.Set("accept", "text/event-stream, application/json, */*")
	req.Header.Set("accept-language", settings.Upstream.Language)
	req.Header.Set("content-type", "application/json")
	req.Header.Set("origin", c.baseURL(settings, cred))
	req.Header.Set("referer", c.baseURL(settings, cred)+"/")
	req.Header.Set("user-agent", settings.Upstream.UserAgent)

	// The three headers the web bundle attaches to every API call.
	//
	// x-timestamp and yy come from one reading, and yy's target is the signed
	// path — not rawURL. Signing the URL is the mistake this client shipped
	// with for a long time; see YY.
	req.Header.Set("token", cred.Token)
	req.Header.Set("x-timestamp", strconv.FormatInt(now.Unix(), 10))
	req.Header.Set("x-signature", XSignature(now, bodyText))
	req.Header.Set("yy", YY(signedTarget, yyBody(method, body), now))
	return req, nil
}

func (c *Client) do(req *http.Request, settings config.Settings) (*http.Response, error) {
	if settings.Upstream.Proxy == "" {
		// A zero-value Client is usable, matching the clock seam: a nil
		// unproxied client falls back to the default one.
		client := c.http
		if client == nil {
			client = http.DefaultClient
		}
		resp, err := client.Do(req)
		return resp, transportError(err)
	}
	client, err := c.clientForProxy(settings.Upstream.Proxy)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	return resp, transportError(err)
}

// clientForProxy returns the shared HTTP client for one proxy address, building
// it on first use and rebuilding only when the configured address changes.
func (c *Client) clientForProxy(raw string) (*http.Client, error) {
	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	if c.proxyClient != nil && c.proxyFor == raw {
		return c.proxyClient, nil
	}
	proxyURL, err := parseProxy(raw)
	if err != nil {
		return nil, err
	}
	if c.proxyTransport != nil {
		c.proxyTransport.CloseIdleConnections()
	}
	c.proxyTransport = &http.Transport{
		Proxy: func(target *http.Request) (*url.URL, error) {
			// Loopback never goes through the proxy.
			//
			// A proxy is configured to reach the internet, and an upstream
			// on 127.0.0.1 is by definition not there. Sending it anyway
			// hands the request to a proxy that cannot reach it and gets
			// back `502` with an empty body — which reads as the upstream
			// being down rather than as a misrouted request. That is
			// exactly how a local test upstream fails when the console has
			// a proxy set, and it is worth being correct about beyond the
			// test: a per-account base URL pointing at a local mirror is a
			// supported thing to configure.
			if isLoopbackHost(target.URL.Hostname()) {
				return nil, nil
			}
			return proxyURL, nil
		},
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
	}
	c.proxyClient = &http.Client{Transport: c.proxyTransport}
	c.proxyFor = raw
	return c.proxyClient, nil
}

// transportError strips the request URL out of a transport failure.
//
// net/http puts the whole URL into its error message, and this client's URLs
// carry the credential in their query — so an error passed along verbatim writes
// the token into whatever reads it next: a log line, an audit record, or an API
// response. The host and path survive because they are what makes a transport
// failure diagnosable at all; the query does not, because it is a credential.
//
// This is not hypothetical: it is how a failed balance check during a manual
// run printed a live token.
func transportError(err error) error {
	if err == nil {
		return nil
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err
	}
	if parsed, parseErr := url.Parse(urlErr.URL); parseErr == nil {
		parsed.RawQuery = ""
		return fmt.Errorf("%s %s: %w", urlErr.Op, parsed.String(), urlErr.Err)
	}
	return fmt.Errorf("%s: %w", urlErr.Op, urlErr.Err)
}

// isLoopbackHost reports whether a host names the local machine.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// ------------------------------------------------------------ session create

// CreateSession opens a fresh upstream conversation and returns its id.
//
// One session per request is deliberate: the OpenAI surface is stateless, the
// client resends the whole history every turn, and reusing sessions would let
// context leak between unrelated callers.
func (c *Client) CreateSession(ctx context.Context, cred Credential) (string, error) {
	settings := c.settings()
	if strings.TrimSpace(cred.Token) == "" {
		return "", ErrInvalidCredential
	}
	// Refuse before spending a request. An empty agent id makes the URL
	// `/…/agent//session`, which the SPA catch-all answers with HTML and a 200 —
	// so the call would "succeed" while producing nothing usable.
	if agentID := c.agentID(settings, cred); strings.TrimSpace(agentID) == "" {
		return "", fmt.Errorf("%w: agent id unknown; the account has not been prepared", ErrAgentIDUnknown)
	}
	payload, err := json.Marshal(map[string]any{
		"agent_id":     c.agentID(settings, cred),
		"worktreeMode": false,
	})
	if err != nil {
		return "", err
	}

	req, err := c.newRequest(ctx, settings, cred, http.MethodPost,
		requestTarget{Path: sessionPath(settings)}, payload)
	if err != nil {
		return "", err
	}
	resp, err := c.do(req, settings)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", ErrInvalidCredential
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		if rejectsRequest(resp.StatusCode) {
			return "", &UpstreamRejection{Prefix: "session", Status: resp.StatusCode, Body: snippet(body)}
		}
		return "", fmt.Errorf("minimax session HTTP %d: %s", resp.StatusCode, snippet(body))
	}

	id := sessionIDFrom(body)
	if id == "" {
		// A 200 without a session id is never a usable session: either the path
		// is wrong (an HTML shell came back) or the agent id is one the upstream
		// does not recognise. Say so, because the response itself will not.
		return "", fmt.Errorf("minimax session: no session id in the response (path %q, agent %q): %s",
			sessionPath(settings), c.agentID(settings, cred), snippet(body))
	}
	return id, nil
}

// sessionIDFrom digs a session identifier out of a create-session response.
//
// The shape has been observed as {"data":{"session_id":...}} but the field has
// also appeared at the top level, and a bare string body is possible, so all
// three are accepted rather than failing on a cosmetic upstream change.
func sessionIDFrom(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}
	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		// Not JSON at all. A wrong path is answered with the SPA's HTML shell
		// and a 200, and treating that page as the session id builds a URL out
		// of an entire web page — which the edge then rejects with a 400 that
		// looks like an upstream block rather than a bug on this side. Refuse
		// to guess instead.
		return ""
	}
	// A bare JSON string is a legitimate shape for this field upstream.
	if text, ok := parsed.(string); ok {
		return strings.TrimSpace(text)
	}
	for _, key := range []string{"session_id", "sessionId", "id", "sessionID"} {
		if found := deepString(parsed, key); found != "" {
			return found
		}
	}
	return ""
}

// ------------------------------------------------------------------ message

// Completion performs one upstream call and returns the aggregated result.
func (c *Client) Completion(ctx context.Context, opts Options) (*Result, error) {
	settings := c.settings()
	if strings.TrimSpace(opts.Credential.Token) == "" {
		return nil, ErrInvalidCredential
	}
	if opts.Text == "" && len(opts.Images) == 0 && len(opts.Files) == 0 {
		return nil, errors.New("empty prompt")
	}

	// MiniMax Code speaks a different protocol on the same product: an OAuth
	// bearer, the Anthropic Messages wire format, and no signature headers. It
	// is dispatched here rather than in the gateway so retries, cooldowns and
	// audits keep the single path they were built around.
	if isMCodeCredential(opts.Credential) {
		return c.mcodeCompletion(ctx, opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = settings.RequestTimeout()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Upload before the session is opened: an attachment that cannot reach the
	// object store should not spend a session (and the opening sequence behind
	// it). Object keys cache per credential, so a retried turn on the same
	// account does not push the same bytes twice.
	//
	// Pictures go through the same pipeline as documents. They did not always:
	// a picture used to be a URL the upstream fetched for itself, and the
	// upstream stopped accepting those. See UploadedImage.
	for i := range opts.Images {
		if err := c.UploadAttachment(ctx, opts.Credential, &opts.Images[i]); err != nil {
			return nil, err
		}
	}
	for i := range opts.Files {
		if err := c.UploadAttachment(ctx, opts.Credential, &opts.Files[i]); err != nil {
			return nil, err
		}
	}

	sessionID, err := c.CreateSession(ctx, opts.Credential)
	if err != nil {
		return nil, err
	}
	return c.sendMessage(ctx, opts, sessionID)
}

// sendMessage posts the prompt to an existing session and consumes the stream.
func (c *Client) sendMessage(ctx context.Context, opts Options, sessionID string) (*Result, error) {
	settings := c.settings()
	cred := opts.Credential

	turnID := randomUUID()
	payload, err := json.Marshal(buildMessageBody(settings, opts, turnID))
	if err != nil {
		return nil, err
	}

	// Stream: the conversation endpoint answers on `agent-stream.<domain>`, and
	// the same path on the API host is a different entry point. See
	// streamBaseURL.
	req, err := c.newRequest(ctx, settings, cred, http.MethodPost, requestTarget{
		Path:      messagePath(settings),
		SessionID: sessionID,
		Stream:    true,
	}, payload)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req, settings)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrInvalidCredential
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if rejectsRequest(resp.StatusCode) {
			return nil, &UpstreamRejection{Status: resp.StatusCode, Body: snippet(body)}
		}
		return nil, fmt.Errorf("minimax message HTTP %d: %s", resp.StatusCode, snippet(body))
	}

	result := &Result{SessionID: sessionID, TurnID: turnID}
	if err := c.consumeStream(resp.Body, opts, result); err != nil {
		return result, err
	}
	result.Media = dedupeMedia(result.Media)
	if result.Text == "" && result.Thinking == "" && len(result.Media) == 0 {
		// ErrEmptyResponse, not a bare error: an empty stream is usually a
		// content filter or a hiccup, and as a bare error it charged the
		// account a cooldown for it. It is deliberately not
		// ErrUpstreamRejected either — the gateway may still try another
		// account, which a refusal forbids.
		return result, ErrEmptyResponse
	}
	return result, nil
}

// imageAttachmentKind is what a picture says it is, on the wire.
//
// The string, not a number. The bundle does contain a numeric enum
// (`Image = 1`, `Doc = 2`) and a reader that compares against 1, but both
// belong to the *legacy* attachment shape. The cloud envelope this gateway
// sends is written by `f`, which copies the composer's own type straight
// through — and a captured request from the real web client carries
//
//	"meta": { "attachment_type": "image", ... }
//
// so the composer's type is a string. A document says "file", which is the same
// vocabulary and is what this gateway has always sent; the numeric enum would
// have been the odd one out, and reading it off the enum instead of off a
// request was a mistake worth remembering.
const imageAttachmentKind = "image"

// upstreamProviderID is the `provider_id` the config endpoint reports for every
// model it lists. The model object is rejected without one, so it is sent
// verbatim rather than guessed per model.
const upstreamProviderID = "minimax"

// buildMessageBody renders the request body for one turn.
//
// The agent expects the whole conversation in a single `content` string, which
// is what the gateway already produces when it flattens OpenAI messages.
//
// Both kinds of attachment use the same `meta`/`cloud` envelope the web client
// sends once its own upload has landed: `attachment_type`, name, mime and size
// under `meta`, the object key under `cloud`. They differ in exactly one field
// — see imageAttachmentKind. A turn that carries an attachment but no words
// still sends a non-empty `content`: a captured attachment-only turn sent
// spaces, and anything non-empty keeps the two shapes distinguishable.
func buildMessageBody(settings config.Settings, opts Options, turnID string) map[string]any {
	// An attachment-only turn still needs a non-empty `content` — the captured
	// file upload turn sent a single space, and that is what goes out.
	text := opts.Text
	if strings.TrimSpace(text) == "" && (len(opts.Images) > 0 || len(opts.Files) > 0) {
		text = " "
	}
	body := map[string]any{
		"content":      text,
		"turn_id":      turnID,
		"worktreeMode": false,
	}

	attachments := make([]any, 0, len(opts.Images)+len(opts.Files))
	for _, image := range opts.Images {
		if image.ObjectKey == "" {
			// Same rule as a document: an attachment with no key is one the
			// upstream refuses, and Completion has already uploaded everything
			// it was given. Reaching here means a caller built Options by hand.
			continue
		}
		attachments = append(attachments, map[string]any{
			"meta": map[string]any{
				"attachment_type": imageAttachmentKind,
				"file_name":       image.Name,
				"mime_type":       image.MimeType,
				"size_bytes":      image.Size,
			},
			"cloud": map[string]any{"object_key": image.ObjectKey},
		})
	}
	for _, file := range opts.Files {
		if file.ObjectKey == "" {
			// Uploaded inside Completion; a file without a key here would be
			// dropped silently by the upstream, which is worse than failing.
			continue
		}
		attachments = append(attachments, map[string]any{
			"meta": map[string]any{
				"attachment_type": "file",
				"file_name":       file.Name,
				"mime_type":       file.MimeType,
				"size_bytes":      file.Size,
			},
			"cloud": map[string]any{
				"object_key": file.ObjectKey,
			},
		})
	}
	if len(attachments) > 0 {
		body["attachments"] = attachments
	}

	// `model` is an object upstream, not a string, and a synthesized
	// {"id": ...} earned a 400 "invalid model selection" (1406010011) from the
	// live upstream. The shape below is the client's own serialiser, read from
	// the bundle (module 91766): provider_id, model_id, variant, thinking and
	// context_limit, each omitted when it has no value.
	//
	// The console template still wins when one is configured: it was the only
	// sanctioned way to fill this field before the shape was known, and an
	// operator who set it meant it.
	switch {
	case strings.TrimSpace(settings.Upstream.ModelPayload) != "":
		var parsed map[string]any
		if err := json.Unmarshal([]byte(settings.Upstream.ModelPayload), &parsed); err == nil {
			body["model"] = parsed
		}
	case opts.Model != "":
		selection := map[string]any{
			"provider_id": upstreamProviderID,
			"model_id":    opts.Model,
		}
		if opts.Reasoning != nil {
			selection["reasoning"] = *opts.Reasoning
		}
		if opts.Variant != nil {
			selection["variant"] = *opts.Variant
		}
		if effort := strings.TrimSpace(opts.ThinkingEffort); effort != "" {
			selection["thinking"] = map[string]any{"effort": effort}
		}
		if opts.ContextLimit > 0 {
			selection["context_limit"] = opts.ContextLimit
		}
		body["model"] = selection
	}
	if opts.Mode != "" {
		body["mode"] = opts.Mode
	}
	// Only sent when the caller names one. An invented intent would be worse
	// than no intent, and the plain chat path has always worked without it.
	if intent := strings.TrimSpace(opts.ClientIntent); intent != "" {
		body["client_intent"] = intent
	}
	return body
}

// ------------------------------------------------------------------- stream

func (c *Client) consumeStream(body io.ReadCloser, opts Options, result *Result) error {
	settings := c.settings()
	idle := opts.IdleTimeout
	if idle <= 0 {
		idle = settings.StreamIdleTimeout()
	}

	reader := bufio.NewReaderSize(body, 64*1024)
	var buffer strings.Builder
	idleTimer := time.AfterFunc(idle, func() { _ = body.Close() })
	defer idleTimer.Stop()

	chunk := make([]byte, 16*1024)
	for {
		n, err := reader.Read(chunk)
		if n > 0 {
			idleTimer.Reset(idle)
			buffer.Write(chunk[:n])
			// SSE allows \r\n line endings; the spec's framing is then
			// "\r\n\r\n", which contains no "\n\n" substring. Normalising the
			// line endings before scanning is what the spec itself does, and it
			// cannot corrupt a payload: an SSE data line never carries a raw
			// newline. Without this, a CRLF stream fails to frame, falls
			// through to the tail handler as one giant frame, and the answer
			// disappears without an error.
			text := strings.ReplaceAll(buffer.String(), "\r\n", "\n")
			for {
				index := strings.Index(text, "\n\n")
				if index < 0 {
					break
				}
				frame := text[:index]
				text = text[index+2:]
				if err := c.handleFrame(frame, opts, result); err != nil {
					return err
				}
			}
			buffer.Reset()
			buffer.WriteString(text)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}
	if tail := strings.TrimSpace(buffer.String()); tail != "" {
		if err := c.handleFrame(tail, opts, result); err != nil {
			return err
		}
	}

	// A stream that never chunked — or one cut off before its first chunk —
	// still described its answer in the closing whole-message frame.
	c.adoptCompleted(opts, result)
	return nil
}

// adoptCompleted falls back to the whole-message restatement when no chunk
// supplied the text. A stream that did chunk ignores it entirely, which is what
// keeps the answer from arriving twice.
func (c *Client) adoptCompleted(opts Options, result *Result) {
	if result.Text == "" && result.Completed != "" {
		result.Text = result.Completed
		if opts.OnDelta != nil {
			opts.OnDelta(result.Completed)
		}
	}
	if result.Thinking == "" && result.CompletedThinking != "" {
		result.Thinking = result.CompletedThinking
		if opts.OnThinking != nil {
			opts.OnThinking(result.CompletedThinking)
		}
	}
}

type sseFrame struct {
	Event string
	Data  map[string]any
	Raw   string
}

func parseFrame(block string) sseFrame {
	frame := sseFrame{Event: "message"}
	var data strings.Builder
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "event:"):
			frame.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	frame.Raw = data.String()
	if frame.Raw != "" && frame.Raw != "[DONE]" {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(frame.Raw), &parsed); err == nil {
			frame.Data = parsed
		}
	}
	return frame
}

// handleFrame dispatches one SSE frame.
//
// The documented shape is `{"type":6,"agent_message_chunk":{"msg_content":"…"}}`,
// but the frame types are numeric and undocumented, so dispatch is driven by
// the payload keys instead of the type code. That keeps the adapter working
// when the bundle renumbers its event enum.
//
// Text is only ever taken out of a chunk, and only from the model. Both halves
// of that are load-bearing — see messageFrameOf.
func (c *Client) handleFrame(block string, opts Options, result *Result) error {
	frame := parseFrame(block)
	if frame.Data == nil {
		if frame.Raw != "" && !strings.HasPrefix(frame.Raw, "{") {
			// Some frames carry a bare token or a keep-alive comment.
			if message := strings.TrimSpace(frame.Raw); message != "" && message != "[DONE]" && frame.Event != "message" {
				return errors.New(message)
			}
		}
		return nil
	}

	// Seen before anything interprets it, so a frame that is about to be read as
	// an error, or ignored as unrecognised, is still visible.
	if opts.OnFrame != nil {
		opts.OnFrame(frame.Data)
	}

	if message := upstreamError(frame.Data); message != "" {
		return errors.New(message)
	}

	for _, key := range []string{"session_id", "sessionId"} {
		if found := deepString(frame.Data, key); found != "" && result.SessionID == "" {
			result.SessionID = found
		}
	}
	for _, key := range []string{"message_id", "messageId", "msg_id"} {
		if found := deepString(frame.Data, key); found != "" {
			result.MessageID = found
		}
	}

	content, role, chunked, isMessage := messageFrameOf(frame.Data)
	switch {
	case isMessage && role == "user":
		// The caller's own turn, restated by the upstream. Dropping it is the
		// whole point: it carries back the exact `content` this gateway sent —
		// the flattened conversation, persona and history included — so reading
		// its `msg_content` as answer text is what makes a bot's own prompt
		// come out as the reply.
	case isMessage && chunked:
		c.appendMessageText(content, opts, result)
	case isMessage:
		// The whole message, restated once the turn is over. It is not new
		// text: the chunks already carried it. Held as a fallback for a stream
		// that never chunked, so accepting it here would deliver every answer
		// twice.
		result.Completed = firstDeepString(content, contentKeys)
		result.CompletedThinking = firstDeepString(content, thinkingKeys)
	default:
		// Not a message frame. Keep the tolerant generic path for any shape
		// this build has not seen: an unrecognised payload with answer text in
		// it is still better read than dropped.
		if thinking := firstDeepString(frame.Data, thinkingKeys); thinking != "" {
			result.Thinking += thinking
			if opts.OnThinking != nil {
				opts.OnThinking(thinking)
			}
		}
		if text := firstDeepString(frame.Data, contentKeys); text != "" {
			result.Text += text
			if opts.OnDelta != nil {
				opts.OnDelta(text)
			}
		}
	}

	// Tool invocations ride inside the same message containers as the text.
	// They are recorded rather than streamed on: see ToolCall.
	if content != nil {
		collectToolCalls(content, result)
	} else {
		collectToolCalls(frame.Data, result)
	}

	collectMediaDeep(frame.Data, result)
	if status := deepString(frame.Data, "finish_reason"); status != "" {
		result.StopReason = status
	}
	return nil
}

// messageFrameOf unpacks the container upstream uses to report a message.
//
// Two shapes carry text, and they do not mean the same thing:
//
//   - `agent_message_chunk` — the incremental stream, one delta per frame. It
//     is the only source of live answer text.
//   - `agent_message` — a whole message, restated. Two of these close a turn:
//     the caller's own turn (role "user", carrying exactly the `content` this
//     gateway sent) and the finished answer (role "assistant").
//
// A plain deep search for `msg_content` finds the key in both, which collects
// the echoed request as if the model had said it — a bot's persona and history
// come back out attached to the answer — and then collects the closing
// restatement too, so the answer arrives twice. Both symptoms, one cause.
func messageFrameOf(payload map[string]any) (content map[string]any, role string, chunked, ok bool) {
	if chunk, found := payload["agent_message_chunk"].(map[string]any); found {
		return chunk, stringField(chunk, "role"), true, true
	}
	if message, found := payload["agent_message"].(map[string]any); found {
		return message, stringField(message, "role"), false, true
	}
	return nil, "", false, false
}

// stringField reads a plain string field out of a decoded object.
func stringField(payload map[string]any, key string) string {
	text, _ := payload[key].(string)
	return text
}

// appendMessageText records one chunk of answer text, keeping reasoning out of
// the visible reply. It reports whether the chunk carried anything, which keeps
// an empty frame from being mistaken for progress.
func (c *Client) appendMessageText(content map[string]any, opts Options, result *Result) bool {
	found := false
	if thinking := firstDeepString(content, thinkingKeys); thinking != "" {
		result.Thinking += thinking
		found = true
		if opts.OnThinking != nil {
			opts.OnThinking(thinking)
		}
	}
	if text := firstDeepString(content, contentKeys); text != "" {
		result.Text += text
		found = true
		if opts.OnDelta != nil {
			opts.OnDelta(text)
		}
	}
	return found
}

// contentKeys are the payload fields that carry visible answer text, in
// priority order. msg_content is the one confirmed by the web client.
var contentKeys = []string{"msg_content", "msgContent", "content", "text", "delta", "answer"}

// thinkingKeys are the reasoning equivalents.
var thinkingKeys = []string{"reasoning_content", "thinking_content", "reason_content", "think_content", "reasoning", "thinking"}

// upstreamError extracts an error message from a frame, if it carries one.
func upstreamError(payload map[string]any) string {
	if raw, ok := payload["error"].(map[string]any); ok {
		if message, ok := raw["message"].(string); ok && message != "" {
			return message
		}
	}
	if raw, ok := payload["error"].(string); ok && raw != "" {
		return raw
	}
	for _, key := range []string{"error_msg", "error_message", "err_msg", "status_msg"} {
		if message, ok := payload[key].(string); ok && message != "" {
			// status_msg is "success" on the happy path.
			if strings.EqualFold(message, "success") || message == "ok" {
				continue
			}
			return message
		}
	}
	// Numeric status codes: anything non-zero in these fields is a failure.
	for _, key := range []string{"status_code", "code", "ret_code"} {
		if value, ok := payload[key].(float64); ok && value != 0 {
			return fmt.Sprintf("upstream status %d", int(value))
		}
	}
	return ""
}

// firstDeepString returns the first non-empty string stored under any of the
// given keys, searching nested objects breadth-first.
func firstDeepString(payload any, keys []string) string {
	for _, key := range keys {
		if found := deepString(payload, key); found != "" {
			return found
		}
	}
	return ""
}

// deepString finds a string value for key anywhere in a decoded JSON tree.
func deepString(payload any, key string) string {
	switch node := payload.(type) {
	case map[string]any:
		if value, ok := node[key].(string); ok && value != "" {
			return value
		}
		for _, value := range node {
			if found := deepString(value, key); found != "" {
				return found
			}
		}
	case []any:
		for _, value := range node {
			if found := deepString(value, key); found != "" {
				return found
			}
		}
	}
	return ""
}

// collectToolCalls records the agent-side tool invocations carried by a frame.
//
// The stream reports them incrementally: a first frame names the tool and
// usually carries an empty `args`, later frames append `argsDelta`. Frames are
// merged by id, in first-seen order, so a caller reading Result.ToolCalls sees
// one entry per invocation rather than one per chunk.
//
// A missing id is not a parse failure — some event kinds omit it — so an entry
// without one is matched against the last unfinished call of the same name.
func collectToolCalls(payload any, result *Result) {
	var entries []map[string]any
	switch node := payload.(type) {
	case map[string]any:
		if list, ok := node["tool_calls"].([]any); ok {
			for _, item := range list {
				if entry, ok := item.(map[string]any); ok {
					entries = append(entries, entry)
				}
			}
		}
		if single, ok := node["tool_call"].(map[string]any); ok {
			entries = append(entries, single)
		}
	}
	for _, entry := range entries {
		id := stringField(entry, "id")
		name := stringField(entry, "name")
		index := -1
		for i := range result.ToolCalls {
			call := &result.ToolCalls[i]
			if id != "" && call.ID == id {
				index = i
				break
			}
			if id == "" && call.Name == name && !toolCallFinished(call.Status) {
				index = i
			}
		}
		if index < 0 {
			result.ToolCalls = append(result.ToolCalls, ToolCall{ID: id, Name: name})
			index = len(result.ToolCalls) - 1
		}
		call := &result.ToolCalls[index]
		if call.ID == "" {
			call.ID = id
		}
		if call.Name == "" {
			call.Name = name
		}
		if whole := stringField(entry, "args"); whole != "" {
			call.Args = whole
		}
		if delta := stringField(entry, "argsDelta"); delta != "" {
			call.Args += delta
		}
		if status := stringField(entry, "status"); status != "" {
			call.Status = status
		}
		if value := stringField(entry, "result"); value != "" {
			call.Result = value
		}
		if value, ok := int64Field(entry, "durationMs"); ok {
			call.DurationMS = value
		}
	}
}

// toolCallFinished reports whether a status means the invocation is over, which
// stops an id-less delta from attaching to it.
func toolCallFinished(status string) bool {
	switch strings.ToLower(status) {
	case "success", "succeeded", "error", "failed", "cancelled", "canceled", "finished", "completed":
		return true
	}
	return false
}

// int64Field reads a whole number that may arrive as float64 (the default for
// encoding/json) or as a string.
func int64Field(payload map[string]any, key string) (int64, bool) {
	switch value := payload[key].(type) {
	case float64:
		return int64(value), true
	case int64:
		return value, true
	case json.Number:
		if parsed, err := value.Int64(); err == nil {
			return parsed, true
		}
	case string:
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

// collectMediaDeep walks the payload for finished image or video URLs.
func collectMediaDeep(payload any, result *Result) {
	switch node := payload.(type) {
	case map[string]any:
		for key, value := range node {
			lower := strings.ToLower(key)
			if raw, ok := value.(string); ok {
				if strings.HasPrefix(raw, "http") && looksLikeMediaKey(lower) {
					result.Media = append(result.Media, MediaRef{Kind: mediaKind(lower), URL: raw})
				}
				continue
			}
			collectMediaDeep(value, result)
		}
	case []any:
		for _, value := range node {
			collectMediaDeep(value, result)
		}
	}
}

// looksLikeMediaKey is deliberately narrow: a bare "url" field appears on
// avatars and citation links as often as on generated media, so only explicit
// media-suffixed keys are trusted.
func looksLikeMediaKey(key string) bool {
	if strings.Contains(key, "icon") || strings.Contains(key, "avatar") {
		return false
	}
	return strings.Contains(key, "image_url") || strings.Contains(key, "video_url") ||
		strings.Contains(key, "cover_url") || strings.Contains(key, "file_url")
}

func mediaKind(key string) string {
	if strings.Contains(key, "video") {
		return "video"
	}
	return "image"
}

func dedupeMedia(items []MediaRef) []MediaRef {
	seen := make(map[string]struct{}, len(items))
	out := make([]MediaRef, 0, len(items))
	for _, item := range items {
		key := item.URL
		if index := strings.Index(key, "?"); index >= 0 {
			key = key[:index]
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

// ------------------------------------------------------------------- probe

// Probe validates a credential by opening a session and immediately discarding
// it. Creating a session is the cheapest authenticated call available: it
// proves the token and fingerprint pair is accepted without spending a
// conversation turn.
func (c *Client) Probe(ctx context.Context, cred Credential) (int64, error) {
	started := time.Now()
	settings := c.settings()
	timeout := 30 * time.Second
	if settings.Upstream.RequestTimeoutSec > 0 && settings.Upstream.RequestTimeoutSec < 60 {
		timeout = settings.RequestTimeout()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if _, err := c.CreateSession(ctx, cred); err != nil {
		return 0, err
	}
	return time.Since(started).Milliseconds(), nil
}

// ------------------------------------------------------------------ helpers

func snippet(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 300 {
		text = text[:300] + "…"
	}
	return text
}
