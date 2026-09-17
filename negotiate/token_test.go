package negotiate

import (
	"errors"
	"testing"
)

// withStubs swaps the token/resolve seams for the duration of a test.
func withStubs(t *testing.T, gen func(string) ([]byte, error), res func(string) (string, error)) {
	t.Helper()
	origGen, origRes := generateToken, resolveHost
	generateToken, resolveHost = gen, res
	t.Cleanup(func() { generateToken, resolveHost = origGen, origRes })
}

func TestToken_FallbackLiteralSucceeds(t *testing.T) {
	resolveCalled := false
	withStubs(t,
		func(host string) ([]byte, error) {
			if host != "auth.example.com" {
				t.Fatalf("expected literal host, got %q", host)
			}
			return []byte("literal-token"), nil
		},
		func(host string) (string, error) { resolveCalled = true; return host, nil },
	)

	tok, err := Token("auth.example.com", CanonicalizeFallback, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(tok) != "literal-token" {
		t.Fatalf("got %q", tok)
	}
	if resolveCalled {
		t.Fatal("resolveHost must not be called when the literal SPN succeeds")
	}
}

func TestToken_FallbackRetriesOnUnknownSPN(t *testing.T) {
	var verboseMsg string
	withStubs(t,
		func(host string) ([]byte, error) {
			if host == "auth.example.com" {
				return nil, &NegotiateError{msg: "bad mech", unsupportedMech: true}
			}
			return []byte("canonical-token"), nil
		},
		func(host string) (string, error) { return "lbvip-1.dc1.example.com", nil },
	)

	tok, err := Token("auth.example.com", CanonicalizeFallback, func(m string) { verboseMsg = m })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(tok) != "canonical-token" {
		t.Fatalf("got %q", tok)
	}
	if verboseMsg == "" {
		t.Fatal("expected a verbose fallback message")
	}
}

func TestToken_FallbackDoesNotRetryOnOtherError(t *testing.T) {
	sentinel := errors.New("expired TGT")
	resolveCalled := false
	withStubs(t,
		func(host string) ([]byte, error) { return nil, sentinel },
		func(host string) (string, error) { resolveCalled = true; return host, nil },
	)

	_, err := Token("auth.example.com", CanonicalizeFallback, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	if resolveCalled {
		t.Fatal("resolveHost must not be called for non-mech errors")
	}
}

func TestToken_FallbackNoDistinctCanonicalName(t *testing.T) {
	mechErr := &NegotiateError{msg: "bad mech", unsupportedMech: true}
	withStubs(t,
		func(host string) ([]byte, error) { return nil, mechErr },
		func(host string) (string, error) { return host, nil }, // resolves to itself
	)

	_, err := Token("auth.example.com", CanonicalizeFallback, nil)
	if !errors.Is(err, mechErr) {
		t.Fatalf("expected original mech error, got %v", err)
	}
}

func TestToken_NeverDoesNotResolve(t *testing.T) {
	resolveCalled := false
	withStubs(t,
		func(host string) ([]byte, error) {
			return nil, &NegotiateError{msg: "bad mech", unsupportedMech: true}
		},
		func(host string) (string, error) { resolveCalled = true; return host, nil },
	)

	_, err := Token("auth.example.com", CanonicalizeNever, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if resolveCalled {
		t.Fatal("CanonicalizeNever must never resolve")
	}
}

func TestToken_AlwaysResolvesFirst(t *testing.T) {
	var seen string
	withStubs(t,
		func(host string) ([]byte, error) { seen = host; return []byte("t"), nil },
		func(host string) (string, error) { return "canonical.example.com", nil },
	)

	if _, err := Token("auth.example.com", CanonicalizeAlways, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seen != "canonical.example.com" {
		t.Fatalf("CanonicalizeAlways should resolve first; token host was %q", seen)
	}
}
