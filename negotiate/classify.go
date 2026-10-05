package negotiate

import (
	"bytes"
	"strings"
)

var ntlmSignature = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

// isNTLMToken reports whether b begins with the NTLMSSP signature — i.e. an
// SSPI package produced an NTLM token instead of a Kerberos one.
func isNTLMToken(b []byte) bool {
	return len(b) >= len(ntlmSignature) && bytes.Equal(b[:len(ntlmSignature)], ntlmSignature)
}

// minorIndicatesUnknownSPN reports whether a GSSAPI mechanism (krb5) minor
// status string signals an unknown/unregistered service principal.
func minorIndicatesUnknownSPN(minorText string) bool {
	up := strings.ToUpper(minorText)
	return strings.Contains(up, "PRINCIPAL_UNKNOWN") ||
		strings.Contains(up, "UNKNOWN_SERVER") ||
		strings.Contains(up, "SERVER NOT FOUND") ||
		strings.Contains(up, "S_PRINCIPAL_UNKNOWN")
}
