package spnego

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/jbvmio/krbhttp/negotiate"
)

// Transport is an http.RoundTripper that proactively adds a SPNEGO Negotiate
// Authorization header to every outgoing request, mirroring the behaviour of
// curl --negotiate --location-trusted.
//
// Why proactive rather than challenge-response (401-retry):
//
//	The target server uses an OIDC redirect flow that spans two hosts:
//	  1. server1.example.com  → 302 → auth-oidc.example.com (needs Negotiate)
//	  2. auth-oidc.example.com    → 302 → server1.example.com/oidc/cb
//	  3. server1.example.com  → 302 → /api/endpoint  (sets session cookie)
//	  4. /api/endpoint + session cookie → 200
//
//	In this flow the servers respond with 302 (not 401) when they receive a
//	valid token, so a 401-triggered retry only covers the first hop. Each
//	subsequent redirect destination also requires Kerberos auth, and
//	Go's http.Client strips the Authorization header on cross-host redirects.
//	Adding the token proactively in the transport means every hop — including
//	cross-host redirect destinations — gets a freshly generated, host-specific
//	token without any special redirect handling needed.
//
// Token generation is lightweight after the first call for a given SPN because
// the OS GSSAPI caches the Kerberos service ticket. Once a session cookie is
// established subsequent requests succeed via cookie alone and the Negotiate
// header is redundant (but harmless).
//
// If the caller has already set an Authorization header the transport leaves it
// unchanged, allowing manual credential override. If negotiate.Token returns an
// error (no matching service ticket, credentials expired, etc.) the request is
// forwarded without any Authorization header and the server's response —
// typically 401 — is returned directly to the caller.
//
// Base defaults to http.DefaultTransport if nil.
//
// TokenErrFunc, if non-nil, is called whenever negotiate.Token fails. The
// request is still forwarded without an Authorization header (fail-open), but
// the callback gives callers visibility into why authentication was skipped.
// Set via client.WithTokenErrorHandler.
type Transport struct {
	Base         http.RoundTripper
	TokenErrFunc func(error)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Caller already set an explicit Authorization header — don't override it.
	if req.Header.Get("Authorization") != "" {
		return t.base().RoundTrip(req)
	}

	host := extractHost(req.URL.Host)
	tokenBytes, err := negotiate.Token(host)
	if err != nil && t.TokenErrFunc != nil {
		t.TokenErrFunc(err)
	}

	// Clone once for all header mutations. We always need a clone because
	// http.RoundTripper must not mutate the caller's request.
	out := req.Clone(req.Context())

	// Default Accept to */* if the caller has not set it.
	// Some servers (e.g. Apache mod_auth_openidc) return 401 instead of
	// initiating the OIDC redirect flow when Accept is absent.
	if out.Header.Get("Accept") == "" {
		out.Header.Set("Accept", "*/*")
	}

	if err == nil {
		out.Header.Set("Authorization",
			"Negotiate "+base64.StdEncoding.EncodeToString(tokenBytes))
	}
	// If Token() errored we still forward (with Accept set) and let the
	// server respond — typically a 302 redirect that the cookie jar handles.
	return t.base().RoundTrip(out)
}

// extractHost strips the port (if present) from a host:port string.
// Handles IPv6 literals ([::1]:port → ::1).
func extractHost(hostport string) string {
	if len(hostport) == 0 {
		return hostport
	}
	if hostport[0] == '[' {
		end := strings.LastIndex(hostport, "]")
		if end < 0 {
			return hostport
		}
		return hostport[1:end]
	}
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i]
		}
	}
	return hostport
}
