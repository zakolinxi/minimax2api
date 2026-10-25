package minimax

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"minimax2api/internal/config"
)

// randomUUID returns a RFC 4122 v4 UUID string.
func randomUUID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		now := time.Now().UnixNano()
		return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", now>>32, (now>>16)&0xffff, (now)&0xffff, now&0xffff, now)
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(buf[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

// parseProxy accepts the proxy URL configured in the console.
func parseProxy(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy %q: %w", raw, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid proxy %q: missing host", raw)
	}
	return parsed, nil
}

// ErrPrivateAddress reports a fetch refused because the target resolved into
// loopback, private or link-local address space. Callers match it with
// errors.Is to answer generically instead of leaking which address was tried.
var ErrPrivateAddress = errors.New("target resolves to a private address")

// DownloadClient returns an HTTP client for fetching generated media.
//
// Generated images and videos are served from MiniMax's CDN, and the same
// egress fence that applies to the API applies to it: an account is only usable
// from an overseas IP, so a download attempted from the local one fails — and it
// fails as a timeout or a reset, which reads as the CDN being down rather than
// as the request having gone out the wrong door. The console's proxy is
// therefore used here too, not just for API calls.
//
// Loopback is exempt from the proxy for the same reason it is exempt on the API
// path: a proxy cannot reach 127.0.0.1, and sending it there turns a local
// mirror into an empty-bodied 502.
//
// Unless settings.Security.AllowPrivateFetch is set, every target — including
// each redirect hop — is resolved before it is dialled and refused when any of
// its addresses is loopback, private or link-local. Reference URLs come from
// API callers, and a client key must not be able to point the gateway at the
// cloud metadata service or an intranet admin panel. The proxy's own address is
// exempt from the check: a local proxy is the common shape of an egress setup,
// and what the proxy does on its far side is the operator's configuration, not
// a caller's URL.
func DownloadClient(settings config.Settings) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
	}
	proxyHost := ""
	if raw := strings.TrimSpace(settings.Upstream.Proxy); raw != "" {
		if proxyURL, err := parseProxy(raw); err == nil {
			proxyHost = strings.TrimSpace(proxyURL.Hostname())
			transport.Proxy = func(target *http.Request) (*url.URL, error) {
				if isLoopbackHost(target.URL.Hostname()) {
					return nil, nil
				}
				return proxyURL, nil
			}
		}
	}
	if !settings.Security.AllowPrivateFetch {
		var dialer net.Dialer
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if proxyHost != "" && strings.EqualFold(host, proxyHost) {
				return dialer.DialContext(ctx, network, addr)
			}
			if err := ensurePublicHost(ctx, host); err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// ensurePublicHost resolves host and refuses it when any address it points at
// is loopback, private or link-local. Resolving here — rather than trusting the
// dialer's own resolution — checks every address the name carries before the
// connection is attempted, so a name cannot slip through on the one record the
// dialer happens to pick. The connection itself still resolves a second time,
// which leaves a theoretical rebinding window between check and dial; closing
// it entirely would mean dialling pinned addresses by hand, which the threat
// model does not need.
func ensurePublicHost(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if privateIP(ip) {
			return fmt.Errorf("%w: %s", ErrPrivateAddress, host)
		}
		return nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		// A name that does not resolve is a caller mistake, not a policy hit —
		// report it as the resolution failure it is.
		return err
	}
	if len(addresses) == 0 {
		return fmt.Errorf("%w: %s has no addresses", ErrPrivateAddress, host)
	}
	for _, item := range addresses {
		if privateIP(item.IP) {
			return fmt.Errorf("%w: %s points at %s", ErrPrivateAddress, host, item.IP)
		}
	}
	return nil
}

func privateIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
