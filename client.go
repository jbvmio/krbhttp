package krbhttp

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"sort"

	"github.com/jbvmio/krbhttp/spnego"
)

type Option func(*options)

type options struct {
	caPath          string
	certPath        string
	keyPath         string
	insecure        bool
	ccachePath      string
	confPath        string
	cookieFile      string
	customJar       http.CookieJar
	hasCustomJar    bool // distinguishes WithCookieJar(nil) from unset
	tokenErrFunc    func(error)
	verboseReqFunc  func(*http.Request)
	verboseRespFunc func(*http.Response)
}

func WithCA(caPath string) Option {
	return func(o *options) { o.caPath = caPath }
}

func WithClientCert(certPath, keyPath string) Option {
	return func(o *options) {
		o.certPath = certPath
		o.keyPath = keyPath
	}
}

func WithInsecure(skip bool) Option {
	return func(o *options) { o.insecure = skip }
}

func WithCCachePath(path string) Option {
	return func(o *options) { o.ccachePath = path }
}

func WithConfPath(path string) Option {
	return func(o *options) { o.confPath = path }
}

// WithCookieFile sets a Netscape/curl-format cookie file for the client.
// Existing cookies are loaded at startup; cookies received during HTTP
// exchanges are written back to the file after each Set-Cookie response.
// The file is created if it does not exist. An in-memory jar is the default
// when this option is omitted.
func WithCookieFile(path string) Option {
	return func(o *options) { o.cookieFile = path }
}

// WithCookieJar sets a caller-supplied http.CookieJar on the client.
// Passing nil disables the cookie jar entirely (http.Client.Jar = nil),
// which forces a fresh SPNEGO exchange on every request with no cookie state.
// Use this to share a jar across multiple clients or to inject a pre-populated
// jar without file backing.
func WithCookieJar(jar http.CookieJar) Option {
	return func(o *options) {
		o.customJar = jar
		o.hasCustomJar = true
	}
}

// WithTokenErrorHandler registers a callback that is invoked whenever the
// SPNEGO transport fails to obtain a Kerberos token. The request is still
// forwarded without an Authorization header (fail-open), but the callback
// gives callers visibility into why authentication was skipped.
//
// Typical use: log the error, or surface it to the user on first failure.
//
//	client.WithTokenErrorHandler(func(err error) {
//	    log.Printf("SPNEGO token error: %v", err)
//	})
func WithTokenErrorHandler(fn func(error)) Option {
	return func(o *options) { o.tokenErrFunc = fn }
}

func WithVerboseReq(fn func(*http.Request)) Option {
	return func(o *options) { o.verboseReqFunc = fn }
}

func WithVerboseResp(fn func(*http.Response)) Option {
	return func(o *options) { o.verboseRespFunc = fn }
}

// DefaultVerboseReq writes curl-style request tracing to os.Stderr.
// Each request line and header is prefixed with "> ", matching curl --verbose
// output.
//
// Use directly with WithVerboseReq:
//
//	krbhttp.NewClient(krbhttp.WithVerboseReq(krbhttp.DefaultVerboseReq))
func DefaultVerboseReq(r *http.Request) {
	proto := r.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(os.Stderr, "> %s %s %s\n", r.Method, r.URL.RequestURI(), proto)
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	fmt.Fprintf(os.Stderr, "> Host: %s\n", host)
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			fmt.Fprintf(os.Stderr, "> %s: %s\n", k, v)
		}
	}
	fmt.Fprintln(os.Stderr, ">")
}

// DefaultVerboseResp writes curl-style response tracing to os.Stderr.
// The status line and each response header is prefixed with "< ", matching
// curl --verbose output.
//
// Use directly with WithVerboseResp:
//
//	krbhttp.NewClient(krbhttp.WithVerboseResp(krbhttp.DefaultVerboseResp))
func DefaultVerboseResp(r *http.Response) {
	proto := r.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(os.Stderr, "< %s %s\n", proto, r.Status)
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			fmt.Fprintf(os.Stderr, "< %s: %s\n", k, v)
		}
	}
	fmt.Fprintln(os.Stderr, "<")
}

// NewClient creates an *http.Client pre-configured with SPNEGO authentication.
func NewClient(opts ...Option) (*http.Client, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	applyPlatformConfig(o)
	var certs []tls.Certificate
	if o.certPath != "" || o.keyPath != "" {
		cert, err := tls.LoadX509KeyPair(o.certPath, o.keyPath)
		if err != nil {
			return nil, fmt.Errorf("client: loading client certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	baseTr, err := buildTLSTransport(o.caPath, o.insecure, certs)
	if err != nil {
		return nil, fmt.Errorf("client: building TLS transport: %w", err)
	}
	spnegoTr := &spnego.Transport{Base: baseTr, TokenErrFunc: o.tokenErrFunc}
	var finalTr http.RoundTripper = spnegoTr
	if o.verboseReqFunc != nil || o.verboseRespFunc != nil {
		finalTr = &verboseTransport{
			base:            spnegoTr,
			verboseReqFunc:  o.verboseReqFunc,
			verboseRespFunc: o.verboseRespFunc,
		}
	}
	var jar http.CookieJar
	switch {
	case o.hasCustomJar:
		jar = o.customJar // may be nil — disables the jar on http.Client
	case o.cookieFile != "":
		jar, err = newFileJar(o.cookieFile)
		if err != nil {
			return nil, fmt.Errorf("client: cookie jar: %w", err)
		}
	default:
		jar, err = newMemoryJar()
		if err != nil {
			return nil, fmt.Errorf("client: cookie jar: %w", err)
		}
	}
	return &http.Client{Transport: finalTr, Jar: jar}, nil
}
