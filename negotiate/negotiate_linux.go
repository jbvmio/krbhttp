//go:build linux

package negotiate

// negotiate_linux.go — SPNEGO token generation on Linux via gokrb5.
//
// Uses github.com/jcmturner/gokrb5/v8 to load a Kerberos ccache, obtain a
// service ticket, and produce a SPNEGO NegTokenInit token.
//
// Key design decision: the SPN is constructed explicitly as "HTTP/"+hostname
// and passed directly to gokrb5. gokrb5/spnego/http.go SetSPNEGOHeader only
// calls net.LookupCNAME when the SPN argument is empty (the auto-derive path);
// by always supplying an explicit SPN we skip that block entirely.
//
// The hostname itself is pre-resolved by resolveCNAME() in resolve.go, which
// iterates net.LookupCNAME until the result stabilises. A single call to
// net.LookupCNAME can stop at an intermediate CNAME for multi-hop chains
// (jcmturner/gokrb5#527); neither cgo nor PreferGo resolvers reliably avoid
// this — empirically both exhibit the same non-determinism. Iterating to
// stability is the only approach that consistently reaches the A-record.
//
// The ccache path is resolved from the package-level SetCCachePath function
// (or defaults are used). On Linux the caller (client.NewClient) sets the
// path from the WithCCachePath option. If no path is set, the same environment
// variable and default path logic from sampleKrb5App is used.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	krbclient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/jbvmio/krbhttp/krb"
)

// linuxGSSAPIPaths is the dlopen search order: MIT first, then Heimdal.
var linuxGSSAPIPaths = []string{
	"libgssapi_krb5.so.2", "libgssapi_krb5.so", // MIT
	"libgssapi.so.3", "libgssapi.so", // Heimdal
}

func init() { loadGSSAPI(linuxGSSAPIPaths) } // best-effort; gokrb5 is the fallback

var (
	mu         sync.RWMutex
	ccachePath string // set by SetCCachePath; empty = use defaults
	confPath   string // set by SetConfPath; empty = use defaults
)

// SetCCachePath overrides the ccache file path used on Linux.
// The default resolution order is: KRB5CCNAME env var → /tmp/krb5cc_<uid>.
// The pure-Go gokrb5 path reads this path directly; the libgssapi path honors
// it via the KRB5CCNAME environment variable, which this function also sets.
// This function is called by client.NewClient when WithCCachePath is used.
// It is safe to call from multiple goroutines.
func SetCCachePath(path string) {
	mu.Lock()
	ccachePath = path
	mu.Unlock()
	if path != "" {
		_ = os.Setenv("KRB5CCNAME", path) // the libgssapi path reads the ccache via env
	}
}

// SetConfPath overrides the krb5.conf file path used on Linux.
// The default resolution order is: KRB5_CONFIG env var → ~/.krb5.conf → /etc/krb5.conf.
// The pure-Go gokrb5 path reads this path directly; the libgssapi path honors
// it via the KRB5_CONFIG environment variable, which this function also sets.
// It is safe to call from multiple goroutines.
func SetConfPath(path string) {
	mu.Lock()
	confPath = path
	mu.Unlock()
	if path != "" {
		_ = os.Setenv("KRB5_CONFIG", path) // the libgssapi path reads krb5.conf via env
	}
}

// tokenForHost prefers the system GSSAPI library (curl parity: it canonicalizes
// the hostbased SPN itself), falling back to the pure-Go gokrb5 path when no
// libgssapi is present.
func tokenForHost(hostname string) ([]byte, error) {
	if gssapiLoaded {
		return gssapiTokenForHost(hostname)
	}
	return tokenForHostGokrb5(hostname)
}

// Backend reports the active token backend for diagnostics.
func Backend() string {
	if gssapiLoaded {
		return "gssapi (" + gssapiLibPath + ")"
	}
	return "gokrb5 (pure-Go)"
}

// tokenForHostGokrb5 generates a raw SPNEGO/Kerberos token for the SPN
// HTTP/hostname built from hostname verbatim (no DNS canonicalization).
//
// The SPN is constructed as "HTTP/hostname" and passed explicitly to gokrb5,
// bypassing the broken net.LookupCNAME path entirely.
//
// The ccache and krb5.conf paths are resolved at call time so that calls to
// SetCCachePath / SetConfPath take effect without restarting.
func tokenForHostGokrb5(hostname string) ([]byte, error) {
	mu.RLock()
	cc := ccachePath
	cf := confPath
	mu.RUnlock()

	// Resolve ccache and config paths, applying defaults.
	resolvedCache, err := krb.ResolveCCachePath(cc)
	if err != nil {
		return nil, fmt.Errorf("negotiate: %w", err)
	}
	resolvedConf, err := krb.ResolveConfPath(cf)
	if err != nil {
		return nil, fmt.Errorf("negotiate: %w", err)
	}

	// Load the ccache from disk.
	ccache, err := credentials.LoadCCache(resolvedCache)
	if err != nil {
		return nil, fmt.Errorf("negotiate: loading ccache %q: %w", resolvedCache, err)
	}

	// Load the krb5.conf.
	cfg, err := config.Load(resolvedConf)
	if err != nil {
		return nil, fmt.Errorf("negotiate: loading krb5 config %q: %w", resolvedConf, err)
	}

	// Create a gokrb5 client from the ccache.
	cl, err := krbclient.NewFromCCache(ccache, cfg,
		krbclient.DisablePAFXFAST(true),
		krbclient.AssumePreAuthentication(true),
	)
	if err != nil {
		return nil, fmt.Errorf("negotiate: creating kerberos client: %w", err)
	}
	defer cl.Destroy()

	// Build the SPNEGO client with an explicit SPN.
	// Using "HTTP/hostname" (slash, not at-sign) because this is the MIT
	// Kerberos / gokrb5 convention. The GSSAPI convention uses "HTTP@hostname"
	// which maps to the same SPN, but gokrb5 expects the slash form.
	spn := "HTTP/" + hostname
	s := spnego.SPNEGOClient(cl, spn)

	if err := s.AcquireCred(); err != nil {
		return nil, classifyKRBError(fmt.Errorf("negotiate: acquiring SPNEGO credential for %s: %w", spn, err))
	}

	st, err := s.InitSecContext()
	if err != nil {
		return nil, classifyKRBError(fmt.Errorf("negotiate: initialising security context for %s: %w", spn, err))
	}

	// Marshal the NegTokenInit to bytes.
	tokenBytes, err := st.Marshal()
	if err != nil {
		return nil, fmt.Errorf("negotiate: marshalling SPNEGO token: %w", err)
	}

	if len(tokenBytes) == 0 {
		return nil, fmt.Errorf("negotiate: marshalled SPNEGO token is empty")
	}
	return tokenBytes, nil
}

// classifyKRBError flags the unknown-SPN KDC codes (the gokrb5 equivalent of
// GSS_S_BAD_MECH) as unsupportedMech so Token can fall back to the canonical
// hostname. gokrb5 wraps KDC errors in *krberror.Krberror, which does NOT
// Unwrap to messages.KRBError, so the text is matched directly as well.
func classifyKRBError(err error) error {
	var krbErr messages.KRBError
	if errors.As(err, &krbErr) && isUnknownSPNCode(krbErr.ErrorCode) {
		return &NegotiateError{msg: err.Error(), unsupportedMech: true}
	}
	up := strings.ToUpper(err.Error())
	if strings.Contains(up, "KDC_ERR_S_PRINCIPAL_UNKNOWN") ||
		strings.Contains(up, "KDC_ERR_PRINCIPAL_NOT_UNIQUE") ||
		strings.Contains(up, "KDC_ERR_SVC_UNAVAILABLE") {
		return &NegotiateError{msg: err.Error(), unsupportedMech: true}
	}
	return err
}

func isUnknownSPNCode(c int32) bool {
	return c == errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN ||
		c == errorcode.KDC_ERR_PRINCIPAL_NOT_UNIQUE ||
		c == errorcode.KDC_ERR_SVC_UNAVAILABLE
}
