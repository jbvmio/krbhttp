package negotiate

import (
	"net"
	"strings"
)

// resolveCNAME follows the full CNAME chain for hostname and returns the
// canonical A-record hostname. If any resolution step fails the error is
// returned and the caller falls back to the original hostname.
//
// Kerberos service tickets are registered in Active Directory under the
// canonical hostname (the final A-record target), not under CNAME aliases.
// Passing an alias directly to gss_init_sec_context or gokrb5 causes the KDC
// to reject the request because that SPN is not registered.
//
// Why iterate rather than call net.LookupCNAME once:
//
//	net.LookupCNAME is documented to return the "final canonical name" but in
//	practice — particularly through corporate or CDN DNS infrastructure — it
//	can stop at an intermediate CNAME entry. Using net.Resolver{PreferGo: true}
//	does not fix this: empirical testing shows both the cgo and pure-Go
//	resolvers exhibit identical non-deterministic behaviour for multi-hop chains.
//	Recursing until net.LookupCNAME returns the same name as its input (meaning
//	no further CNAME record exists) reliably reaches the final A-record.
//
// The implementation uses an unexported helper with a remaining-hops counter
// to guard against malformed CNAME cycles in broken DNS configurations.
func resolveCNAME(hostname string) (string, error) {
	return resolveCNAMEHops(hostname, 10)
}

func resolveCNAMEHops(hostname string, remaining int) (string, error) {
	if remaining == 0 {
		return hostname, nil
	}
	next, err := net.LookupCNAME(hostname)
	if err != nil {
		return hostname, err
	}
	// Strip trailing dot (absolute DNS name form returned by Go's resolver).
	next = strings.TrimSuffix(next, ".")
	// net.LookupCNAME returns the input name when no CNAME record exists —
	// i.e. we have reached the final A-record target.
	if next == hostname {
		return hostname, nil
	}
	return resolveCNAMEHops(next, remaining-1)
}
