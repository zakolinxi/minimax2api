package minimax

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// signatureSalt is the static key baked into the MiniMax Agent web bundle.
// It ships with the frontend, so it is public by construction: any browser can
// read it out of the page chunk. Treat it as a protocol constant, not a secret.
const signatureSalt = "I*7Cf%WZ#S&%1RlZJ&C2"

// signatureSuffix is appended to the yy digest input.
const signatureSuffix = "ooui"

// md5Hex returns the lowercase 32-character hex MD5 of value.
func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

// XSignature reproduces the upstream `x-signature` header:
//
//	MD5( unix_seconds + salt + raw_request_body )
//
// The digest covers the timestamp, the static salt and the exact body bytes
// that will be sent. It is independent of the URL.
func XSignature(timestamp time.Time, body string) string {
	return md5Hex(strconv.FormatInt(timestamp.Unix(), 10) + signatureSalt + body)
}

// YY reproduces the upstream `yy` header:
//
//	MD5( encodeURIComponent(path_with_query) + "_" + body + MD5(str(ms)) + "ooui" )
//
// Two details of that formula are easy to get wrong, and both are silent when
// they are:
//
//   - The signed target is the *path and query* the axios call names, never the
//     absolute URL. The bundle keeps `baseURL` separate and signs `e.url`
//     (module 52724, fed by the interceptor in module 2503), so anything the
//     host contributes is not covered. This is the opposite of what the header
//     name suggests.
//   - `ms` is `Date.parse(new Date().toString())`: milliseconds, but rounded
//     down to the whole second. The same reading becomes `x-timestamp` after
//     another division by 1000, which is why the two headers always agree.
//
// The body half is not simply the request body either; see yyBody.
func YY(signedTarget string, body string, timestamp time.Time) string {
	millis := strconv.FormatInt(signatureMillis(timestamp), 10)
	return md5Hex(encodeURIComponent(signedTarget) + "_" + body + md5Hex(millis) + signatureSuffix)
}

// signatureMillis is the timestamp the web client actually signs.
//
// `Date.parse(new Date().toString())` drops the sub-second part: toString has
// whole-second resolution, so the milliseconds always end in 000. Reproducing
// that here keeps `unix` in the query and the digest below describing the same
// instant — a clock value with real milliseconds would sign a time the browser
// never sends.
func signatureMillis(timestamp time.Time) int64 {
	return timestamp.Truncate(time.Second).UnixMilli()
}

// yyBody reports the string the bundle feeds into the yy digest (module 52724):
//
//	o = "{}"
//	if method is POST { o = body ? JSON.stringify(body) : "{}" }
//
// So a GET signs "{}" no matter what, and a bodyless POST signs "{}" too. Only
// a POST with a body signs the serialised body. x-signature uses a different
// input — the raw request bytes, empty for a GET — which is why the two digests
// cannot share a helper.
func yyBody(method string, body []byte) string {
	if !strings.EqualFold(method, "post") || len(body) == 0 {
		return "{}"
	}
	return string(body)
}

// encodeURIComponent mirrors the JavaScript built-in of the same name.
//
// net/url.QueryEscape is not a substitute: it encodes spaces as "+" and leaves
// "~" alone while escaping "!*'()", which is the opposite of what
// encodeURIComponent does for those characters. Any mismatch changes the digest
// and the upstream rejects the request.
func encodeURIComponent(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); i++ {
		char := value[i]
		switch {
		case char >= 'A' && char <= 'Z',
			char >= 'a' && char <= 'z',
			char >= '0' && char <= '9',
			char == '-', char == '_', char == '.', char == '!',
			char == '~', char == '*', char == '\'', char == '(', char == ')':
			builder.WriteByte(char)
		default:
			// Non-ASCII bytes are emitted one at a time, which is exactly how
			// the JS built-in percent-encodes UTF-8 input.
			fmt.Fprintf(&builder, "%%%02X", char)
		}
	}
	return builder.String()
}
