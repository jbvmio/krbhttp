package negotiate

// NegotiateError is returned by Token when the platform GSSAPI or SSPI
// mechanism reports a token-generation failure. Use IsUnsupportedMech to
// distinguish benign "no ticket for this host" failures from actionable
// credential errors such as an expired TGT.
type NegotiateError struct {
	msg             string
	unsupportedMech bool
}

func (e *NegotiateError) Error() string { return e.msg }

// IsUnsupportedMech reports whether the failure is GSS_S_BAD_MECH or
// equivalent: the target host's SPN is not registered, or the SPNEGO
// mechanism is unavailable for this host. This class of error is benign
// when a valid session cookie covers the request; curl buries the same
// message in --verbose output only.
func (e *NegotiateError) IsUnsupportedMech() bool { return e.unsupportedMech }
