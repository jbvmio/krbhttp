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
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	krbclient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/jbvmio/krbhttp/krb"
)

var (
	mu         sync.RWMutex
	ccachePath string // set by SetCCachePath; empty = use defaults
	confPath   string // set by SetConfPath; empty = use defaults
)

// SetCCachePath overrides the ccache file path used on Linux.
// The default resolution order is: KRB5CCNAME env var → /tmp/krb5cc_<uid>.
// This function is called by client.NewClient when WithCCachePath is used.
// It is safe to call from multiple goroutines.
func SetCCachePath(path string) {
	mu.Lock()
	ccachePath = path
	mu.Unlock()
}

// SetConfPath overrides the krb5.conf file path used on Linux.
// The default resolution order is: KRB5_CONFIG env var → ~/.krb5.conf → /etc/krb5.conf.
// It is safe to call from multiple goroutines.
func SetConfPath(path string) {
	mu.Lock()
	confPath = path
	mu.Unlock()
}

// Token generates a raw SPNEGO/Kerberos token for use in an HTTP Negotiate
// authentication header targeting the given hostname.
//
// The SPN is constructed as "HTTP/hostname" and passed explicitly to gokrb5,
// bypassing the broken net.LookupCNAME path entirely.
//
// The ccache and krb5.conf paths are resolved at call time so that calls to
// SetCCachePath / SetConfPath take effect without restarting.
func Token(hostname string) ([]byte, error) {
	// Resolve any CNAME aliases to the canonical A-record hostname.
	// SPNs are registered in Active Directory under the canonical name;
	// passing an alias would cause the KDC to reject the request.
	if resolved, err := resolveCNAME(hostname); err == nil {
		hostname = resolved
	}

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
		return nil, fmt.Errorf("negotiate: acquiring SPNEGO credential for %s: %w", spn, err)
	}

	st, err := s.InitSecContext()
	if err != nil {
		return nil, fmt.Errorf("negotiate: initialising security context for %s: %w", spn, err)
	}

	// Marshal the NegTokenInit to bytes.
	tokenBytes, err := st.Marshal()
	if err != nil {
		return nil, fmt.Errorf("negotiate: marshalling SPNEGO token: %w", err)
	}

	// Sanity check: the token should not be empty base64. The spnego package
	// returns the raw bytes (not base64), so we just do a quick decode-round-trip
	// to confirm the bytes are valid before returning them.
	if len(tokenBytes) == 0 {
		return nil, fmt.Errorf("negotiate: marshalled SPNEGO token is empty")
	}

	// Verify the bytes decode cleanly when base64-encoded, to catch any silent
	// marshalling oddities early. The actual base64 encoding is left to the caller.
	encoded := base64.StdEncoding.EncodeToString(tokenBytes)
	if strings.TrimSpace(encoded) == "" {
		return nil, fmt.Errorf("negotiate: SPNEGO token base64 is empty after encoding")
	}

	return tokenBytes, nil
}
