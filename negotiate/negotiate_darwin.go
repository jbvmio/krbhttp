//go:build darwin

package negotiate

// negotiate_darwin.go — macOS token backend.
//
// macOS always has Apple's GSS.framework (Heimdal GSSAPI), so the shared
// purego backend in gssapi_unix.go is used unconditionally. The framework
// sources credentials from the macOS store (FILE and API-type ccaches) and
// canonicalizes the hostbased SPN itself.

import "fmt"

const gssFrameworkPath = "/System/Library/Frameworks/GSS.framework/GSS"

func init() {
	if !loadGSSAPI([]string{gssFrameworkPath}) {
		panic(fmt.Sprintf("negotiate: failed to load GSS.framework at %s", gssFrameworkPath))
	}
}

func tokenForHost(hostname string) ([]byte, error) { return gssapiTokenForHost(hostname) }

// Backend reports the active token backend for diagnostics.
func Backend() string { return "gssapi (" + gssapiLibPath + ")" }
