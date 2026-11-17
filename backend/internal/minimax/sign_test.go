package minimax

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"minimax2api/internal/config"
)

// configWithUpstream returns the built-in settings, which already point at the
// two real hosts. Reusing them keeps the tests honest about the defaults.
func configWithUpstream() config.Settings {
	return config.DefaultSettings("/tmp/minimax2api-test")
}

// The salt is public - it ships inside the web bundle - so these vectors exist
// to pin the formula, not to protect a secret.

func TestXSignatureFollowsFormula(t *testing.T) {
	// Fixed inputs so the expected digest is reproducible by hand.
	stamp := time.Unix(1780470413, 0)
	body := `{"content":"你好"}`

	got := XSignature(stamp, body)
	want := md5Hex("1780470413" + signatureSalt + body)
	if got != want {
		t.Fatalf("XSignature = %q, want %q", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("digest length = %d, want 32 hex characters", len(got))
	}
}

func TestXSignatureDependsOnTimestampAndBody(t *testing.T) {
	stamp := time.Unix(1780470413, 0)
	if XSignature(stamp, "a") != XSignature(stamp, "a") {
		t.Fatal("the signature must be deterministic")
	}
	if XSignature(stamp, "a") == XSignature(stamp, "b") {
		t.Fatal("the body must affect the signature")
	}
	if XSignature(stamp, "a") == XSignature(time.Unix(1780470414, 0), "a") {
		t.Fatal("the timestamp must affect the signature")
	}
}

func TestYYFollowsFormula(t *testing.T) {
	// The offset has to be a whole number of milliseconds: UnixMilli truncates,
	// so a 500-nanosecond offset would collapse onto the same instant.
	stamp := time.Unix(1780470413, 500*int64(time.Millisecond))
	target := "/minimax-cloud/api/v1/session/s1/message?token=t&uuid=u"
	body := `{"content":"hi"}`

	got := YY(target, body, stamp)
	want := md5Hex(encodeURIComponent(target) + "_" + body + md5Hex("1780470413000") + "ooui")
	if got != want {
		t.Fatalf("YY = %q, want %q", got, want)
	}
}

// The digest is over the path plus query, never the absolute URL. The bundle
// keeps baseURL separate from url (module 52724), so anything the host
// contributes is outside the signature — a distinction that only shows up as a
// rejected request when it is wrong.
func TestYYSignsThePathNotTheURL(t *testing.T) {
	stamp := time.Unix(1780470413, 0)
	target := "/minimax-cloud/api/v1/config?uuid=null&token=null"

	if YY(target, "{}", stamp) == YY("https://agent.minimax.io"+target, "{}", stamp) {
		t.Fatal("the host must not take part in the digest")
	}
}

// yyBody is not the request body. A GET signs "{}" even though it sends
// nothing, and a bodyless POST does too; only a POST with a body signs that
// body. x-signature is the one that covers the raw bytes.
func TestYYBodyFollowsTheBundle(t *testing.T) {
	cases := []struct {
		method string
		body   string
		want   string
	}{
		{"GET", "", "{}"},
		{"get", `{"a":1}`, "{}"},
		{"POST", "", "{}"},
		{"POST", `{"content":"hi"}`, `{"content":"hi"}`},
		{"post", `{}`, `{}`},
	}
	for _, tc := range cases {
		if got := yyBody(tc.method, []byte(tc.body)); got != tc.want {
			t.Errorf("yyBody(%q, %q) = %q, want %q", tc.method, tc.body, got, tc.want)
		}
	}
}

// The captured config request, byte for byte. It is the one vector that can be
// checked without a token: an unauthenticated call carries `uuid=null` and
// `token=null` in the signed string, and the path is all that is hashed.
func TestYYMatchesTheLiveCapture(t *testing.T) {
	const signedTarget = "/minimax-cloud/api/v1/config?device_platform=web&biz_id=3&app_id=3001" +
		"&version_code=22201&unix=1794579564000&timezone_offset=28800&sys_language=en&lang=en" +
		"&uuid=null&device_id=53809372&os_name=Windows&browser_name=Chrome&device_memory=16" +
		"&cpu_core_num=8&browser_language=zh-CN&browser_platform=Win32&user_id=0" +
		"&op_ticket=undefined&screen_width=800&screen_height=600&token=null&client=web&region=en"

	stamp := time.UnixMilli(1794579564000)
	if got, want := YY(signedTarget, "{}", stamp), "78d261f4a67eb4572eb33abb666d9fc2"; got != want {
		t.Fatalf("yy = %q, want %q", got, want)
	}
	if got, want := YY(signedTarget, "{}", time.Unix(1794579564, 999*int64(time.Millisecond))),
		"78d261f4a67eb4572eb33abb666d9fc2"; got != want {
		t.Fatalf("sub-second drift must not change the digest: %q, want %q", got, want)
	}
	if got, want := XSignature(time.Unix(1794579564, 0), ""), "089fe6407dc8fc9b427fbbfa8fa0bbe8"; got != want {
		t.Fatalf("x-signature = %q, want %q", got, want)
	}
}

// yy is the only header that binds the signed target, which is what makes the
// query string order significant.
func TestYYBindsTargetAndSeconds(t *testing.T) {
	stamp := time.Unix(1780470413, 500*int64(time.Millisecond))
	target := "/minimax-cloud/api/v1/session/s1/message?token=t"
	body := `{"content":"hi"}`
	base := YY(target, body, stamp)

	if YY(target+"&uuid=u", body, stamp) == base {
		t.Fatal("the query string must affect the signature")
	}
	if YY(target, body, time.Unix(1780470414, 500*int64(time.Millisecond))) == base {
		t.Fatal("the second must affect the signature")
	}
	// Milliseconds do not: `Date.parse(new Date().toString())` has whole-second
	// resolution, so two readings inside one second sign the same instant.
	if YY(target, body, time.Unix(1780470413, 600*int64(time.Millisecond))) != base {
		t.Fatal("sub-second drift must not change the signature")
	}
}

// encodeURIComponent diverges from net/url.QueryEscape on exactly the
// characters below. Any difference silently changes the yy digest, so the
// behaviour is pinned rather than assumed.
func TestEncodeURIComponentMatchesJavaScript(t *testing.T) {
	cases := map[string]string{
		"abcXYZ019":           "abcXYZ019",
		"-_.!~*'()":           "-_.!~*'()",
		"a b":                 "a%20b", // QueryEscape would produce "a+b"
		"a+b":                 "a%2Bb",
		"a=b&c":               "a%3Db%26c",
		"a/b?c#d":             "a%2Fb%3Fc%23d",
		"a~b":                 "a~b", // QueryEscape leaves "~" alone too, but escapes "!*'()"
		"你好":                  "%E4%BD%A0%E5%A5%BD",
		`{}[]|\^` + "`" + `"`: "%7B%7D%5B%5D%7C%5C%5E%60%22",
	}
	for input, want := range cases {
		if got := encodeURIComponent(input); got != want {
			t.Errorf("encodeURIComponent(%q) = %q, want %q", input, got, want)
		}
	}
}

// formEncode is the other encoder: URLSearchParams, which builds the query
// itself. It is not encodeURIComponent — the safe set is smaller and a space is
// "+". The signed string is hashed verbatim, so this is pinned too.
func TestFormEncodeMatchesURLSearchParams(t *testing.T) {
	cases := map[string]string{
		"abcXYZ019": "abcXYZ019",
		"*-._":      "*-._",
		"a b":       "a+b",
		"a+b":       "a%2Bb",
		"a=b&c":     "a%3Db%26c",
		"a/b?c#d":   "a%2Fb%3Fc%23d",
		"a~b":       "a%7Eb", // encodeURIComponent would leave "~" alone
		"!*'()":     "%21*%27%28%29",
		"你好":        "%E4%BD%A0%E5%A5%BD",
	}
	for input, want := range cases {
		if got := formEncode(input); got != want {
			t.Errorf("formEncode(%q) = %q, want %q", input, got, want)
		}
	}
}

// The query string is signed verbatim, so its *order* is part of the protocol:
// `yy` digests the signed target, and the captured web client sends these 22
// parameters in exactly this order — `unix` fifth, `op_ticket` just before the
// screen size, `client`/`region` last. Reordering them would sign a request the
// browser never sends, and the upstream would reject it with a bare "invalid
// signature" that names no cause.
func TestClientQueryMatchesTheCapturedWebClient(t *testing.T) {
	settings := configWithUpstream()
	stamp := time.Unix(1780470413, 250*int64(time.Millisecond))
	cred := Credential{
		Token: "a+b/c", UUID: "u-1", DeviceID: "d 2", UserID: "42",
		ScreenWidth: 1920, ScreenHeight: 1080,
	}

	wire, signed := clientQuery(settings, cred, stamp)

	wantWire := strings.Join([]string{
		"device_platform=web", "biz_id=3", "app_id=3001", "version_code=22201",
		// `unix` is milliseconds rounded down to the second, because that is the
		// reading the bundle signs.
		"unix=1780470413000",
		"timezone_offset=28800", "sys_language=en", "lang=en",
		"uuid=u-1", "device_id=d+2",
		"os_name=Windows", "browser_name=Chrome", "device_memory=16", "cpu_core_num=8",
		"browser_language=zh-CN", "browser_platform=Win32",
		"user_id=42", "screen_width=1920", "screen_height=1080",
		"token=a%2Bb%2Fc",
		"client=web", "region=en",
	}, "&")
	if wire != wantWire {
		t.Fatalf("wire query =\n %s\nwant\n %s", wire, wantWire)
	}

	// The signed string differs by exactly one parameter here: op_ticket is
	// absent from the wire but URLSearchParams prints it as "undefined".
	wantSigned := strings.Replace(wantWire, "user_id=42&screen_width", "user_id=42&op_ticket=undefined&screen_width", 1)
	if signed != wantSigned {
		t.Fatalf("signed query =\n %s\nwant\n %s", signed, wantSigned)
	}
}

// Absent credential fields are the one place the two query strings disagree,
// and the disagreement is deliberate: axios drops null/undefined, while
// URLSearchParams prints them. Signing the wire string instead of this one is
// the mistake that makes `yy` unverifiable upstream.
func TestClientQueryStringifiesAbsentFieldsOnlyForTheSignature(t *testing.T) {
	settings := configWithUpstream()
	stamp := time.Unix(1780470413, 250*int64(time.Millisecond))
	wire, signed := clientQuery(settings, Credential{Token: "t"}, stamp)

	for _, dropped := range []string{"uuid=", "op_ticket="} {
		if strings.Contains(wire, dropped) {
			t.Errorf("wire query should omit %q: %s", dropped, wire)
		}
	}
	// Real client-side defaults are zeros, not omissions: `device_id` falls back
	// to a generated value and `user_id` to 0.
	for _, want := range []string{"device_id=0", "user_id=0", "&token=t&client=web&region=en"} {
		if !strings.Contains(wire, want) {
			t.Errorf("wire query is missing %q: %s", want, wire)
		}
	}
	for _, want := range []string{"uuid=null", "op_ticket=undefined", "token=t"} {
		if !strings.Contains(signed, want) {
			t.Errorf("signed query is missing the placeholder %q: %s", want, signed)
		}
	}
	if !strings.Contains(signed, "uuid=null&device_id") {
		t.Errorf("uuid must stay in position in the signed query: %s", signed)
	}
	for _, want := range []string{
		"device_platform=web", "timezone_offset=28800", "browser_platform=Win32",
	} {
		if !strings.Contains(signed, want) {
			t.Errorf("signed query is missing the constant %q: %s", want, signed)
		}
	}
}

// `unix` and `yy` have to describe the same request. They come from one clock
// reading, and `yy` covers the signed target rather than the URL, so a second
// reading — even a few milliseconds later — would sign an instant that was
// never sent. The failure mode is a bare "invalid signature" that points at
// nothing, so the seam is pinned rather than trusted.
func TestUnixAndYYComeFromOneClockReading(t *testing.T) {
	settings := configWithUpstream()
	stamp := time.Unix(1780470413, 250*int64(time.Millisecond))
	client := &Client{now: func() time.Time { return stamp }}
	cred := Credential{Token: "t", UUID: "u", DeviceID: "12345678", UserID: "42"}

	body := []byte(`{}`)
	target := requestTarget{Path: messagePath(settings), SessionID: "s1", Stream: true}
	req, err := client.newRequest(context.Background(), settings, cred, http.MethodPost, target, body)
	if err != nil {
		t.Fatalf("newRequest: %v", err)
	}

	if !strings.Contains(req.URL.RawQuery, "unix=1780470413000") {
		t.Fatalf("request URL should carry the second-aligned clock: %q", req.URL.String())
	}
	if got, want := req.Header.Get("x-timestamp"), "1780470413"; got != want {
		t.Errorf("x-timestamp = %q, want %q", got, want)
	}

	// Rebuild the signed target independently and check the header against it.
	path := strings.ReplaceAll(target.Path, "{session_id}", target.SessionID)
	_, signedTarget := client.buildURLWith(client.baseURL(settings, cred), settings, cred, target.Path, target.SessionID, stamp)
	if !strings.HasPrefix(signedTarget, path+"?") {
		t.Fatalf("signed target should be path-based: %q", signedTarget)
	}
	if strings.Contains(signedTarget, "://") {
		t.Fatalf("signed target must not carry the host: %q", signedTarget)
	}
	if got, want := req.Header.Get("yy"), YY(signedTarget, "{}", stamp); got != want {
		t.Errorf("yy = %q, want %q (over %q)", got, want, signedTarget)
	}
	if got := req.Header.Get("yy"); got == YY(req.URL.String(), "{}", stamp) {
		t.Error("yy must not be computed over the absolute URL")
	}
}

// The conversation endpoint answers on its own host, and the captured web client
// posts turns to `agent-stream.<domain>`. The mapping is derived rather than
// hardcoded so that everything which is *not* that shape keeps its own address —
// a self-hosted relay and a test server would otherwise be pointed at a
// hostname they do not have.
func TestStreamBaseURLFollowsTheCapture(t *testing.T) {
	settings := configWithUpstream()

	cases := []struct {
		name string
		cred Credential
		want string
	}{
		{"international", Credential{Region: RegionGlobal}, "https://agent-stream.minimax.io"},
		{"mainland", Credential{Region: RegionCN}, "https://agent-stream.minimaxi.com"},
		{"relay", Credential{Region: RegionGlobal, BaseURL: "https://relay.local"}, "https://relay.local"},
		{"relay with port", Credential{BaseURL: "http://127.0.0.1:8080"}, "http://127.0.0.1:8080"},
	}
	client := &Client{}
	for _, tc := range cases {
		base := client.baseURL(settings, tc.cred)
		if got := streamBaseURL(settings, base); got != tc.want {
			t.Errorf("%s: streamBaseURL = %q, want %q", tc.name, got, tc.want)
		}
	}

	// An explicit setting wins, which is how a capture that disagrees gets
	// applied without a rebuild.
	pinned := settings
	pinned.Upstream.StreamBaseURL = "https://captured.example"
	cred := Credential{Region: RegionGlobal}
	if got := streamBaseURL(pinned, client.baseURL(pinned, cred)); got != "https://captured.example" {
		t.Errorf("an explicit StreamBaseURL should win, got %q", got)
	}
}

// A transport failure must not carry the credential.
//
// net/http includes the whole URL in its error message, and every URL this
// client builds carries the token in its query — so an error passed along
// verbatim writes the token into whatever reads it next: a log line, an audit
// record, or an API response. This is not hypothetical: it is exactly how a
// failed balance check during a manual run printed a live token.
func TestTransportErrorsDoNotCarryTheCredential(t *testing.T) {
	settings := configWithUpstream()
	// A closed port, so the failure is a transport error rather than a status.
	settings.Upstream.BaseURL = "http://127.0.0.1:1"
	settings.Upstream.StreamBaseURL = ""
	client := New(func() config.Settings { return settings })

	cred := Credential{
		Token: "SECRET-TOKEN-VALUE", UUID: "u", DeviceID: "12345678", UserID: "42",
	}
	_, err := client.ProbeEndpoint(context.Background(), cred, http.MethodGet,
		"/minimax-cloud/api/v1/config", nil, false)
	if err == nil {
		t.Fatal("expected a transport error against a closed port")
	}
	if strings.Contains(err.Error(), cred.Token) {
		t.Fatalf("the error carries the token: %v", err)
	}
	// The host and path stay: without them the error says nothing about which
	// upstream was unreachable, which is the one thing it is for.
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("the error lost the host: %v", err)
	}
	if !strings.Contains(err.Error(), "/minimax-cloud/api/v1/config") {
		t.Fatalf("the error lost the path: %v", err)
	}
}

// The agent id and session id are substituted without going through net/url,
// so the query order survives byte for byte.
func TestBuildURLSubstitutesPathPlaceholders(t *testing.T) {
	settings := configWithUpstream()
	stamp := time.Unix(1780470413, 0)
	client := &Client{}
	cred := Credential{Token: "t", UUID: "u", DeviceID: "d"}

	got := client.buildURL(settings, cred, "/minimax-cloud/api/v1/session/{session_id}/message", "sess-9", stamp)
	if !strings.HasPrefix(got, "https://agent.minimax.io/minimax-cloud/api/v1/session/sess-9/message?") {
		t.Fatalf("buildURL = %q", got)
	}
	if !strings.Contains(got, "token=t") {
		t.Fatalf("buildURL should carry the credential query: %q", got)
	}
}

// A path that already carries a query must be joined with "&", not a second
// "?". The two differ by one byte and `yy` covers the encoded URL, so getting it
// wrong rejects the request for a reason that says nothing about the mistake.
func TestBuildURLAppendsToAnExistingQuery(t *testing.T) {
	settings := configWithUpstream()
	client := &Client{}

	got := client.buildURL(settings, Credential{Token: "t"},
		"/minimax-cloud/api/v1/skill?agent_name=1&include_plugin_skills=true", "", time.Unix(1780470413, 0))
	if strings.Contains(got, "?agent_name=1?") {
		t.Fatalf("buildURL joined a second \"?\": %q", got)
	}
	if !strings.Contains(got, "include_plugin_skills=true&device_platform=web") {
		t.Fatalf("buildURL should append with \"&\": %q", got)
	}
}

// Mainland accounts must be routed to the mainland host, which is the whole
// reason the region travels with the account.
func TestBuildURLSelectsHostByRegion(t *testing.T) {
	settings := configWithUpstream()
	stamp := time.Unix(1780470413, 0)
	client := &Client{}

	global := client.buildURL(settings, Credential{Region: RegionGlobal, Token: "t"}, "/x", "", stamp)
	mainland := client.buildURL(settings, Credential{Region: RegionCN, Token: "t"}, "/x", "", stamp)
	pinned := client.buildURL(settings, Credential{Region: RegionCN, Token: "t", BaseURL: "https://relay.local"}, "/x", "", stamp)

	if !strings.HasPrefix(global, "https://agent.minimax.io/") {
		t.Fatalf("global = %q", global)
	}
	if !strings.HasPrefix(mainland, "https://agent.minimaxi.com/") {
		t.Fatalf("mainland = %q", mainland)
	}
	if !strings.HasPrefix(pinned, "https://relay.local/") {
		t.Fatalf("account-level override should win: %q", pinned)
	}
}
