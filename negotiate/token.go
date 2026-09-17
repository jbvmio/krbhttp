package negotiate

import (
	"errors"
	"fmt"
)

// Canonicalization selects how the SPN host is derived from the URL host.
type Canonicalization int

const (
	// CanonicalizeFallback tries the URL host verbatim and only resolves the
	// CNAME chain if the KDC/mechanism rejects it as an unknown SPN. This
	// mirrors MIT krb5's dns_canonicalize_hostname=fallback and is the default.
	CanonicalizeFallback Canonicalization = iota
	// CanonicalizeNever always uses the URL host verbatim and never resolves.
	CanonicalizeNever
	// CanonicalizeAlways resolves the CNAME chain first (legacy behaviour).
	CanonicalizeAlways
)

// Overridable seams for tests; production values are the real implementations.
var (
	generateToken = tokenForHost
	resolveHost   = resolveCNAME
)

// Token generates a raw SPNEGO/Kerberos token for an HTTP Negotiate header
// targeting hostname. mode selects how the SPN host is derived:
//
//   - CanonicalizeFallback (default): try HTTP/<hostname> verbatim, and only if
//     that is rejected as an unknown SPN, retry with the CNAME-resolved
//     canonical hostname. Correct for both GSLB/alias-registered services and
//     canonical-A-record-registered services (gokrb5 issue #527 topology).
//   - CanonicalizeNever: use HTTP/<hostname> verbatim, never resolve.
//   - CanonicalizeAlways: resolve the CNAME chain first, then build the SPN.
//
// verbose, if non-nil, receives an informational message when the literal SPN
// is rejected and the canonical fallback is attempted.
func Token(hostname string, mode Canonicalization, verbose func(string)) ([]byte, error) {
	switch mode {
	case CanonicalizeNever:
		return generateToken(hostname)
	case CanonicalizeAlways:
		if resolved, err := resolveHost(hostname); err == nil {
			hostname = resolved
		}
		return generateToken(hostname)
	default:
		return tokenFallback(hostname, verbose)
	}
}

func tokenFallback(hostname string, verbose func(string)) ([]byte, error) {
	tok, err := generateToken(hostname)
	if err == nil {
		return tok, nil
	}

	// Only an unknown-SPN rejection triggers fallback; anything else (expired
	// TGT, missing ccache, etc.) is returned as-is.
	var ne *NegotiateError
	if !errors.As(err, &ne) || !ne.IsUnsupportedMech() {
		return nil, err
	}

	resolved, rerr := resolveHost(hostname)
	if rerr != nil || resolved == hostname {
		return nil, err // no distinct canonical name to fall back to
	}

	if verbose != nil {
		verbose(fmt.Sprintf("negotiate: SPN HTTP/%s rejected; retrying canonical HTTP/%s", hostname, resolved))
	}
	return generateToken(resolved)
}
