package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"minimax2api/internal/config"
	"minimax2api/internal/pool"
	"minimax2api/internal/store"
)

// unsignedToken builds a JWT-shaped credential with the given claims. Nothing
// verifies the signature, so a stub one is enough to exercise the decoder.
func unsignedToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		blob, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(blob)
	}
	return encode(map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + encode(claims) + ".signature"
}

// A record is searched by everything an operator can see in it. The payload
// fields matter most: they are the only way to find a request after the fact,
// since nobody remembers the generated id of the call they want to inspect.
func TestAuditSearchCoversPayloadAndMetadata(t *testing.T) {
	audit := &store.Audit{
		ID: "req_4f2a", Model: "minimax-m3", KeyName: "desk", AccountName: "matrix",
		Status: 502, IP: "10.1.2.3", UserAgent: "curl/8.5.0",
		Error:        "upstream timed out",
		RequestBody:  `{"messages":[{"content":"how do I reindex"}]}`,
		ResponseBody: `{"error":"boom"}`,
	}
	cases := []struct {
		needle string
		want   bool
	}{
		{"req_4f2a", true},
		{"minimax-m3", true},
		{"m3.1 flash", true}, // model display name, supplied separately
		{"desk", true},
		{"matrix", true},
		{"10.1.2.3", true},
		{"curl", true},
		{"502", true},
		{"timed out", true},
		{"reindex", true},
		{"boom", true},
		{"missing", false},
	}
	for _, tc := range cases {
		if got := auditMatchesSearch(audit, tc.needle, "MiniMax M3.1 Flash"); got != tc.want {
			t.Errorf("auditMatchesSearch(%q) = %v, want %v", tc.needle, got, tc.want)
		}
	}
}

func TestBuildAccountInfersRegionFromPhone(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"mainland phone", map[string]any{"user_id": "1", "phone": "+8613800138000"}, store.RegionCN},
		{"international phone", map[string]any{"user_id": "2", "phone": "+14155550123"}, store.RegionGlobal},
		{"email only", map[string]any{"user_id": "3", "email": "a@b.com"}, store.RegionGlobal},
		{"no claims", map[string]any{"user_id": "4"}, store.RegionGlobal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			account, err := buildAccount(accountPayload{Token: unsignedToken(t, tc.claims)})
			if err != nil {
				t.Fatalf("buildAccount: %v", err)
			}
			if account.Region != tc.want {
				t.Fatalf("region = %q, want %q", account.Region, tc.want)
			}
		})
	}
}

// The auto sentinel has to be distinguishable from "leave it alone", otherwise
// an operator cannot move an account between deployments through the console.
func TestBuildAccountAutoSentinelDefersToToken(t *testing.T) {
	token := unsignedToken(t, map[string]any{"user_id": "1", "phone": "+8613800138000"})

	for _, sentinel := range []string{"auto", "AUTO", " auto ", "infer", "detect", "自动识别"} {
		account, err := buildAccount(accountPayload{Token: token, Region: sentinel})
		if err != nil {
			t.Fatalf("buildAccount(%q): %v", sentinel, err)
		}
		if account.Region != store.RegionCN {
			t.Fatalf("region for sentinel %q = %q, want %q", sentinel, account.Region, store.RegionCN)
		}
	}
}

func TestBuildAccountHonoursExplicitRegion(t *testing.T) {
	// An explicit region beats the token's own claim: the operator may be
	// routing through a proxy whose tokens do not carry a usable phone.
	token := unsignedToken(t, map[string]any{"user_id": "1", "phone": "+8613800138000"})
	account, err := buildAccount(accountPayload{Token: token, Region: "global"})
	if err != nil {
		t.Fatalf("buildAccount: %v", err)
	}
	if account.Region != store.RegionGlobal {
		t.Fatalf("region = %q, want %q", account.Region, store.RegionGlobal)
	}

	if _, err := buildAccount(accountPayload{Token: token, Region: "moon"}); err == nil {
		t.Fatal("expected an unknown region to be rejected")
	}
}

func TestBuildAccountGeneratesFingerprint(t *testing.T) {
	account, err := buildAccount(accountPayload{Token: unsignedToken(t, map[string]any{"user_id": "1"})})
	if err != nil {
		t.Fatalf("buildAccount: %v", err)
	}
	// The signature covers uuid and device_id, so an account without them can
	// never be routed. Generating a self-consistent pair is what makes a bare
	// token paste work.
	//
	// The two fields have *different* shapes, and this test used to assert the
	// opposite — 32 hex characters each — because one generator was used for
	// both. That assertion is what kept the defect invisible: it described the
	// implementation instead of the upstream, so it passed while every
	// `/minimax-cloud/…` call failed with an error that named no field.
	if _, err := strconv.Atoi(account.DeviceID); err != nil {
		t.Fatalf("device id %q is not a number: %v", account.DeviceID, err)
	}
	if !strings.Contains(account.UUID, "-") {
		t.Fatalf("uuid = %q, want the site's dashed UUID shape", account.UUID)
	}
	if account.UUID == account.DeviceID {
		t.Fatal("uuid and device_id should not be identical")
	}
	if account.Kind != store.KindToken {
		t.Fatalf("kind = %q, want %q", account.Kind, store.KindToken)
	}
	if account.Name == "" {
		t.Fatal("expected a generated name")
	}
}

func TestBuildAccountRejectsMalformedToken(t *testing.T) {
	cases := map[string]string{
		"empty":      "",
		"whitespace": "abc def ghi jkl mno",
		"too short":  "short",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := buildAccount(accountPayload{Token: token}); err == nil {
				t.Fatalf("expected %q to be rejected", token)
			}
		})
	}
}

func TestRegionFromToken(t *testing.T) {
	cn := unsignedToken(t, map[string]any{"user_id": "1", "phone": "+8613800138000"})
	if got := regionFromToken(cn); got != store.RegionCN {
		t.Fatalf("regionFromToken(cn) = %q", got)
	}
	if got := regionFromToken("not-a-jwt"); got != "" {
		t.Fatalf("regionFromToken(garbage) = %q, want empty", got)
	}
	// The mainland site prefixes the token with realUserID, joined by a plus.
	if got := regionFromToken("450234567894+" + cn); got != store.RegionCN {
		t.Fatalf("regionFromToken(realUserID+token) = %q", got)
	}
}

func TestIsAutoRegion(t *testing.T) {
	for _, value := range []string{"auto", "Auto", " infer ", "detect", "自动", "自动识别"} {
		if !isAutoRegion(value) {
			t.Fatalf("isAutoRegion(%q) = false, want true", value)
		}
	}
	for _, value := range []string{"", "cn", "global", "国内", "国际"} {
		if isAutoRegion(value) {
			t.Fatalf("isAutoRegion(%q) = true, want false", value)
		}
	}
}

func TestParseImportShapes(t *testing.T) {
	cn := unsignedToken(t, map[string]any{"user_id": "1", "phone": "+8613800138000"})
	global := unsignedToken(t, map[string]any{"user_id": "2", "email": "a@b.com"})

	entries := parseImport(
		"# comment\n\n"+cn+"\n"+
			"named----"+global+"\n"+
			"regional----"+global+"----cn\n"+
			"cn:"+cn+"\n",
		nil,
	)
	if len(entries) != 4 {
		t.Fatalf("parsed %d entries, want 4: %+v", len(entries), entries)
	}
	if entries[0].Token != cn || entries[0].Name != "" {
		t.Fatalf("bare token parsed as %+v", entries[0])
	}
	if entries[1].Name != "named" || entries[1].Token != global {
		t.Fatalf("name----token parsed as %+v", entries[1])
	}
	if entries[2].Name != "regional" || entries[2].Region != store.RegionCN {
		t.Fatalf("name----token----region parsed as %+v", entries[2])
	}
	if entries[3].Token != cn || entries[3].Region != store.RegionCN {
		t.Fatalf("cn: prefix parsed as %+v", entries[3])
	}
}

// JSON input wins over the text box, which is what makes an export/import round
// trip lossless including fingerprints.
func TestParseImportPrefersJSON(t *testing.T) {
	blob, err := json.Marshal(map[string]any{
		"accounts": []map[string]any{{"token": "from-json-token", "region": "cn", "uuid": "u"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	entries := parseImport("from-text-token", blob)
	if len(entries) != 1 || entries[0].Token != "from-json-token" {
		t.Fatalf("entries = %+v, want the JSON payload", entries)
	}
}

func TestDefaultAccountNameCarriesRegion(t *testing.T) {
	cn := defaultAccountName("13800138000", store.RegionCN)
	global := defaultAccountName("someone@example.com", store.RegionGlobal)
	if cn == global {
		t.Fatalf("names should differ by region: %q", cn)
	}
	if cn[:3] != "cn-" || global[:7] != "global-" {
		t.Fatalf("unexpected names: %q / %q", cn, global)
	}
}

// describeToken is what keeps a token from leaking into an error message shown
// in the console.
func TestDescribeTokenMasksSecret(t *testing.T) {
	token := unsignedToken(t, map[string]any{"user_id": "1"})
	described := describeToken(token)
	if len(token) > 16 && strings.Contains(described, token[:20]) {
		t.Fatalf("describeToken leaked the token: %q", described)
	}
}

// jsonKeys returns a struct's json field names, skipping anything untagged.
func jsonKeys(t *testing.T, value any) map[string]bool {
	t.Helper()
	kind := reflect.TypeOf(value)
	keys := make(map[string]bool, kind.NumField())
	for i := range kind.NumField() {
		name := strings.Split(kind.Field(i).Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		keys[name] = true
	}
	return keys
}

// getSettings builds its response by hand rather than marshalling config.Settings.
// That is deliberate — the console must not receive every internal knob — but it
// means a new setting is invisible to the console until someone remembers to add
// it here. This test is that reminder: it would have caught `userInfoPath` going
// missing, which is exactly the kind of omission that shows up as a blank field
// in the settings page and nowhere else.
func TestGetSettingsExposesEveryUpstreamAndServerField(t *testing.T) {
	st, err := store.Open(t.TempDir(), "admin", "admin12345")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	settings := config.DefaultSettings(t.TempDir())
	api := &API{
		store:    st,
		settings: func() config.Settings { return settings },
		started:  time.Now(),
	}

	recorder := httptest.NewRecorder()
	api.getSettings(recorder, httptest.NewRequest("GET", "/admin/api/settings", nil))

	var body map[string]map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, recorder.Body.String())
	}

	// Only the two sections that are written out field by field; the rest are
	// handed to the encoder wholesale and cannot drift.
	cases := []struct {
		section string
		value   any
	}{
		{"server", settings.Server},
		{"upstream", settings.Upstream},
	}
	for _, tc := range cases {
		want := jsonKeys(t, tc.value)
		got := body[tc.section]
		for key := range want {
			if _, ok := got[key]; !ok {
				t.Errorf("%s is missing %q, so the console cannot show or edit it", tc.section, key)
			}
		}
		for key := range got {
			if !want[key] {
				t.Errorf("%s exposes %q, which is not a field of the settings struct", tc.section, key)
			}
		}
	}

	// Every section of the struct has to appear, including the ones that are
	// handed to the encoder wholesale.
	//
	// The per-field checks above cannot see a section that was never added: a
	// new settings group is one more line in getSettings, and forgetting that
	// line produces a console that simply has no such panel and no error
	// anywhere. Comparing against the struct's own json tags is what makes
	// "added a settings group" and "wired it up" the same act.
	for _, section := range structJSONTags(t, config.Settings{}) {
		if _, ok := body[section]; !ok {
			t.Errorf("settings section %q is not exposed by getSettings, so the console cannot show or edit it", section)
		}
	}
}

// structJSONTags returns the json tag of every field of a struct value.
func structJSONTags(t *testing.T, value any) []string {
	t.Helper()
	kind := reflect.TypeOf(value)
	if kind.Kind() != reflect.Struct {
		t.Fatalf("structJSONTags needs a struct, got %s", kind.Kind())
	}
	tags := make([]string, 0, kind.NumField())
	for i := 0; i < kind.NumField(); i++ {
		field := kind.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			t.Errorf("settings field %s has no json tag", field.Name)
			continue
		}
		tags = append(tags, name)
	}
	return tags
}

// --- generated device fingerprints -----------------------------------------

// TestGeneratedDeviceIDIsAllDigits pins the one property the upstream checks.
//
// A device id that is not a number answers
//
//	400 {"error":"internal error","errorCode":50001,"base_resp":{"status_code":1406011050}}
//
// on every `/minimax-cloud/…` call, and nothing in that response says which
// field is wrong — it reads as an upstream outage. The check-in endpoints and
// `/v1/api/user/info` accept anything, so a wrong value here fails exactly the
// requests that were never exercised against the real server.
func TestGeneratedDeviceIDIsAllDigits(t *testing.T) {
	for i := 0; i < 200; i++ {
		got := newDeviceID()
		if _, err := strconv.Atoi(got); err != nil {
			t.Fatalf("device id %q is not a number: %v", got, err)
		}
		// The site's own fallback is `1e7 + rand(9e7)`, so eight digits and no
		// leading zero. Any digit string is accepted, but matching the site
		// keeps a generated value indistinguishable from a captured one.
		if len(got) != 8 {
			t.Fatalf("device id %q has %d digits, want 8", got, len(got))
		}
		if got[0] == '0' {
			t.Fatalf("device id %q has a leading zero, so it renders as fewer than eight digits", got)
		}
	}
}

// TestGeneratedUUIDLooksLikeAUUID: the upstream tolerates any string here, but a
// value in the site's own shape is worth keeping — a future stricter check
// should not be able to tell a generated fingerprint from a captured one.
func TestGeneratedUUIDLooksLikeAUUID(t *testing.T) {
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := make(map[string]bool, 200)
	for i := 0; i < 200; i++ {
		got := newUUID()
		if !pattern.MatchString(got) {
			t.Fatalf("uuid %q is not a v4 UUID", got)
		}
		if seen[got] {
			t.Fatalf("uuid %q was generated twice", got)
		}
		seen[got] = true
	}
}

// TestTheTwoFingerprintFieldsAreNotInterchangeable guards the actual defect: one
// generator was used for both fields, so the device id came out as 32 hex
// characters. Sharing a generator is the obvious-looking thing to do and is
// wrong.
func TestTheTwoFingerprintFieldsAreNotInterchangeable(t *testing.T) {
	device := newDeviceID()
	if strings.ContainsAny(device, "abcdef") {
		t.Errorf("the device id %q contains hex letters, so it is not a number", device)
	}
	uuid := newUUID()
	if _, err := strconv.Atoi(uuid); err == nil {
		t.Errorf("the uuid %q parses as a number; the two fields have different shapes", uuid)
	}
}

// A client key's concurrency is either a positive ceiling or unlimited, and
// zero is how the console asks for the latter. Clamping zero up to one — the
// old behaviour — left no way to create an unrestricted key at all.
func TestConcurrencyLimitKeepsZeroAsUnlimited(t *testing.T) {
	cases := []struct {
		name  string
		value int
		want  int
	}{
		{"unlimited", 0, 0},
		{"negative is also unlimited", -1, 0},
		{"a real ceiling", 8, 8},
		{"the upper bound still applies", 4096, 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := concurrencyLimit(tc.value); got != tc.want {
				t.Fatalf("concurrencyLimit(%d) = %d, want %d", tc.value, got, tc.want)
			}
		})
	}
}

// --- handlers over a live store ----------------------------------------------

// newTestAPI builds an API over a fresh store with a live pool: the minimum
// the listing, login and dashboard handlers touch. The client and signin
// service stay nil because none of these tests reach the upstream.
func newTestAPI(t *testing.T) (*API, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir(), "admin", "admin12345")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	dir := t.TempDir()
	settings := func() config.Settings { return config.DefaultSettings(dir) }
	api := New(st, pool.New(st, settings), nil, nil, settings, "")
	return api, st
}

// addAccount stores one built account, failing the test on the way.
func addAccount(t *testing.T, st *store.Store, claims map[string]any, region string) *store.Account {
	t.Helper()
	account, err := buildAccount(accountPayload{Token: unsignedToken(t, claims), Region: region})
	if err != nil {
		t.Fatalf("buildAccount: %v", err)
	}
	if err := st.AddAccount(account); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	return account
}

// TestListPagesTolerateHugePageValues pins the pagination overflow fix. A page
// of math.MaxInt used to make (page-1)*pageSize wrap negative, slip past the
// start>total guard and panic slicing a slice with negative bounds.
func TestListPagesTolerateHugePageValues(t *testing.T) {
	api, st := newTestAPI(t)
	for i := 1; i <= 3; i++ {
		addAccount(t, st, map[string]any{"user_id": strconv.Itoa(i), "phone": "+8613800138000"}, "")
	}
	// The audits listing filters the same way, so give it records to page over.
	for i := 0; i < 3; i++ {
		st.AppendAudit(&store.Audit{ID: "req_" + strconv.Itoa(i), CreatedAt: time.Now(), Model: "minimax-agent"})
	}

	cases := []struct {
		path   string
		handle func(w http.ResponseWriter, r *http.Request)
	}{
		{"/admin/api/accounts?page=9223372036854775807", api.listAccounts},
		{"/admin/api/audits?page=9223372036854775807", api.listAudits},
		{"/admin/api/accounts?page=2000000", api.listAccounts}, // past the clamp
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handle(rec, httptest.NewRequest("GET", tc.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			var body struct {
				Items []any `json:"items"`
				Total int   `json:"total"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
			}
			if body.Total != 3 {
				t.Errorf("total = %d, want 3 (an over-range page must not hide the data)", body.Total)
			}
			if len(body.Items) != 0 {
				t.Errorf("got %d items, want none past the last page", len(body.Items))
			}
		})
	}
}

// TestLoginLocksAfterRepeatedFailures: five consecutive bad passwords from one
// address lock the endpoint, and the lock holds even for the right password —
// otherwise the lockout would announce when to retry the brute force with the
// correct credential.
func TestLoginLocksAfterRepeatedFailures(t *testing.T) {
	api, _ := newTestAPI(t)
	attempt := func(password string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
		rec := httptest.NewRecorder()
		api.login(rec, httptest.NewRequest("POST", "/admin/api/auth/login", bytes.NewReader(body)))
		return rec
	}

	for i := 1; i <= 5; i++ {
		if rec := attempt("wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d, want 401", i, rec.Code)
		}
	}

	rec := attempt("wrong")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt: status %d, want 429 (body %s)", rec.Code, rec.Body.String())
	}
	if retryAfter := rec.Header().Get("retry-after"); retryAfter == "" {
		t.Error("the 429 should carry a Retry-After header")
	}
	if rec := attempt("admin12345"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("correct password while locked: status %d, want 429", rec.Code)
	}
}

// TestLoginSuccessResetsFailureCountAndAudits: a real login clears the
// address's counter and lands an auditable record, so a operator's own typo
// streak cannot lock them out after the next sign-in.
func TestLoginSuccessResetsFailureCountAndAudits(t *testing.T) {
	api, st := newTestAPI(t)
	attempt := func(password string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
		rec := httptest.NewRecorder()
		api.login(rec, httptest.NewRequest("POST", "/admin/api/auth/login", bytes.NewReader(body)))
		return rec
	}

	for i := 1; i <= 4; i++ {
		if rec := attempt("wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d, want 401", i, rec.Code)
		}
	}
	if rec := attempt("admin12345"); rec.Code != http.StatusOK {
		t.Fatalf("correct login after 4 failures: status %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	audited := false
	for _, audit := range st.ListAudits() {
		if audit.Action == "登录成功" {
			audited = true
		}
	}
	if !audited {
		t.Error("a successful login should leave an audit record")
	}

	// The counter was wiped: four more failures are still 401, not a 429 left
	// over from before the successful login.
	for i := 1; i <= 4; i++ {
		if rec := attempt("wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d after re-login: status %d, want 401", i, rec.Code)
		}
	}
}

// TestExportImportRoundTripPreservesKindEnabledRegion: the export is the
// import format, so kind, enabled flag and region must survive a full round
// trip — through both the update path (token already known) and a fresh store.
func TestExportImportRoundTripPreservesKindEnabledRegion(t *testing.T) {
	api, st := newTestAPI(t)
	account := addAccount(t, st, map[string]any{"user_id": "7", "phone": "+8613800138000"}, store.RegionCN)
	if _, err := st.UpdateAccount(account.ID, func(target *store.Account) {
		// Shape an account no newer build would create by default: a guest kind
		// and a disabled flag, exactly what the old export used to drop.
		target.Kind = store.KindGuest
		target.Enabled = false
	}); err != nil {
		t.Fatalf("seed kind/enabled: %v", err)
	}

	rec := httptest.NewRecorder()
	api.exportAccounts(rec, httptest.NewRequest("GET", "/admin/api/accounts/export", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export: status %d, body %s", rec.Code, rec.Body.String())
	}
	var exported struct {
		Accounts []map[string]any `json:"accounts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &exported); err != nil {
		t.Fatalf("decode export: %v (body=%s)", err, rec.Body.String())
	}
	if len(exported.Accounts) != 1 {
		t.Fatalf("exported %d accounts, want 1", len(exported.Accounts))
	}

	importBlob := func(api2 *API, accounts []map[string]any) (created, updated, failed int) {
		// The import endpoint takes the exported array inside its "json" field,
		// exactly the shape the console posts back.
		payload, err := json.Marshal(map[string]any{"json": map[string]any{"accounts": accounts}})
		if err != nil {
			t.Fatalf("marshal import payload: %v", err)
		}
		rec := httptest.NewRecorder()
		api2.importAccounts(rec, httptest.NewRequest("POST", "/admin/api/accounts/import", bytes.NewReader(payload)))
		if rec.Code != http.StatusOK {
			t.Fatalf("import: status %d, body %s", rec.Code, rec.Body.String())
		}
		var result struct {
			Created int `json:"created"`
			Updated int `json:"updated"`
			Failed  int `json:"failed"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatalf("decode import: %v", err)
		}
		return result.Created, result.Updated, result.Failed
	}

	// Re-import over the existing token: an update, not a duplicate.
	if created, updated, failed := importBlob(api, exported.Accounts); created != 0 || updated != 1 || failed != 0 {
		t.Fatalf("re-import = created %d updated %d failed %d, want 0/1/0", created, updated, failed)
	}
	after, ok := st.AccountByID(account.ID)
	if !ok {
		t.Fatal("account vanished after re-import")
	}
	if after.Kind != store.KindGuest {
		t.Errorf("kind = %q, want %q preserved through the round trip", after.Kind, store.KindGuest)
	}
	if after.Enabled {
		t.Error("enabled = true, want the exported false preserved")
	}
	if after.Region != store.RegionCN {
		t.Errorf("region = %q, want %q preserved", after.Region, store.RegionCN)
	}

	// A region-less re-import must not stomp a manually chosen region — not
	// even with the token's own inference.
	if _, err := st.UpdateAccount(account.ID, func(target *store.Account) {
		target.Region = store.RegionGlobal
	}); err != nil {
		t.Fatalf("move region: %v", err)
	}
	if _, updated, failed := importBlob(api, []map[string]any{{"token": account.Token}}); updated != 1 || failed != 0 {
		t.Fatalf("region-less re-import = updated %d failed %d, want 1/0", updated, failed)
	}
	if after, _ = st.AccountByID(account.ID); after.Region != store.RegionGlobal {
		t.Errorf("region = %q, want %q: a region-less re-import must not overwrite it", after.Region, store.RegionGlobal)
	}

	// A fresh store rebuilds the account with the same shape.
	st2, err := store.Open(t.TempDir(), "admin", "admin12345")
	if err != nil {
		t.Fatalf("open second store: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	api2 := &API{store: st2}
	if created, _, failed := importBlob(api2, exported.Accounts); created != 1 || failed != 0 {
		t.Fatalf("fresh import = created %d failed %d, want 1/0", created, failed)
	}
	if rebuilt := st2.ListAccounts(); len(rebuilt) != 1 {
		t.Fatalf("rebuilt %d accounts, want 1", len(rebuilt))
	} else if candidate := rebuilt[0]; candidate.Kind != store.KindGuest || candidate.Enabled || candidate.Region != store.RegionCN {
		t.Errorf("rebuilt account = kind %q enabled %v region %q, want guest/false/cn",
			candidate.Kind, candidate.Enabled, candidate.Region)
	}
}

// TestUpdateAccountValidatesRegionAndToken pins the PATCH-time validation: an
// unknown region and a truncated token are refused instead of stored.
func TestUpdateAccountValidatesRegionAndToken(t *testing.T) {
	api, st := newTestAPI(t)
	account := addAccount(t, st, map[string]any{"user_id": "1", "phone": "+8613800138000"}, "")

	// updateAccount reads the id from the route pattern, so the request has to
	// travel through a mux for {id} to be populated.
	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /admin/api/accounts/{id}", api.updateAccount)
	patch := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPatch, "/admin/api/accounts/"+account.ID, strings.NewReader(body)))
		return rec
	}

	if rec := patch(`{"region":"moon"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("region moon: status %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if rec := patch(`{"token":"short"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("short token: status %d, want 400", rec.Code)
	}
	if rec := patch(`{"token":"aaaa bbbb cccc dddd eeee"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("token with whitespace: status %d, want 400", rec.Code)
	}

	// A valid region applies, and the account is otherwise untouched.
	if rec := patch(`{"region":"global"}`); rec.Code != http.StatusOK {
		t.Fatalf("region global: status %d, body %s", rec.Code, rec.Body.String())
	}
	after, ok := st.AccountByID(account.ID)
	if !ok {
		t.Fatal("account vanished")
	}
	if after.Region != store.RegionGlobal {
		t.Errorf("region = %q, want %q", after.Region, store.RegionGlobal)
	}
}

// TestAdminResponsesAreNoStore: every /admin/api response — guarded or not —
// must be marked uncacheable, because session tokens travel in the bodies.
func TestAdminResponsesAreNoStore(t *testing.T) {
	api, _ := newTestAPI(t)
	mux := http.NewServeMux()
	api.Register(mux)

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "admin12345"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/api/auth/login", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status %d, body %s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("cache-control"); cc != "no-store" {
		t.Errorf("login cache-control = %q, want no-store", cc)
	}

	// A guarded route answers 401 here, and the header must be present on that
	// response too — the middleware wraps the route, not the handler outcome.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/api/dashboard", nil))
	if cc := rec.Header().Get("cache-control"); cc != "no-store" {
		t.Errorf("dashboard cache-control = %q, want no-store", cc)
	}
}

// TestDashboardDropsFakeUsageFields: reasoningTokens was declared but never
// accumulated, and the throughput/cost pair was hardcoded zero. Real numbers or
// no numbers — the dashboard must not report fiction.
func TestDashboardDropsFakeUsageFields(t *testing.T) {
	api, _ := newTestAPI(t)
	rec := httptest.NewRecorder()
	api.dashboard(rec, httptest.NewRequest("GET", "/admin/api/dashboard", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard: status %d, body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	for _, key := range []string{"reasoningTokens", "estimatedCostUsd", "averageOutputTokensPerSecond", "throughputSamples"} {
		if _, ok := body.Usage[key]; ok {
			t.Errorf("usage.%s should be gone: it was never computed", key)
		}
	}
}
