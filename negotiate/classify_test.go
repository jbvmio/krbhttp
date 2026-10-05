package negotiate

import "testing"

func TestIsNTLMToken(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"ntlm signature", []byte("NTLMSSP\x00\x01\x00\x00\x00"), true},
		{"kerberos ap-req", []byte{0x60, 0x82, 0x04, 0x00}, false},
		{"empty", nil, false},
		{"short prefix", []byte("NTLM"), false},
		{"signature only", []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isNTLMToken(c.in); got != c.want {
				t.Fatalf("isNTLMToken(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestMinorIndicatesUnknownSPN(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"mit principal unknown", "Server krbtgt/... unknown while looking up 'HTTP/x': KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN", true},
		{"server not found text", "Server not found in Kerberos database", true},
		{"unknown server", "UNKNOWN_SERVER", true},
		{"lowercase", "server not found in kerberos database", true},
		{"clock skew (unrelated)", "Clock skew too great", false},
		{"empty", "", false},
		{"expired tgt (unrelated)", "Ticket expired", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := minorIndicatesUnknownSPN(c.in); got != c.want {
				t.Fatalf("minorIndicatesUnknownSPN(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
