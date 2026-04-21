package krbhttp

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"sort"

	"github.com/jbvmio/krbhttp/spnego"
)

type Option func(*Options)

// Options holds the configuration for a krbhttp client.
// Use NewOptions to create an instance, configure it with builder methods,
// and call NewClient when ready. All builder methods return *Options to allow
// chaining.
//
//	opts := krbhttp.NewOptions()
//	opts.WithCA(caPath)
//	opts.WithInsecure(true)
//	c, err := opts.NewClient()
//
//	// or chained:
//	c, err := krbhttp.NewOptions().WithCA(caPath).WithInsecure(true).NewClient()
type Options struct {
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

// NewOptions returns a new zero-value Options ready for configuration.
func NewOptions() *Options {
	return &Options{}
}

func (o *Options) WithCA(caPath string) *Options {
	o.caPath = caPath
	return o
}

func (o *Options) WithClientCert(certPath, keyPath string) *Options {
	o.certPath = certPath
	o.keyPath = keyPath
	return o
}

func (o *Options) WithInsecure(skip bool) *Options {
	o.insecure = skip
	return o
}

func (o *Options) WithCCachePath(path string) *Options {
	o.ccachePath = path
	return o
}

func (o *Options) WithConfPath(path string) *Options {
	o.confPath = path
	return o
}

// WithCookieFile sets a Netscape/curl-format cookie file on the Options.
// Existing cookies are loaded at startup; cookies received during HTTP
// exchanges are written back to the file after each Set-Cookie response.
// The file is created if it does not exist.
func (o *Options) WithCookieFile(path string) *Options {
	o.cookieFile = path
	return o
}

// WithCookieJar sets a caller-supplied http.CookieJar on the Options.
// Passing nil disables the cookie jar entirely (http.Client.Jar = nil),
// which forces a fresh SPNEGO exchange on every request with no cookie state.
func (o *Options) WithCookieJar(jar http.CookieJar) *Options {
	o.customJar = jar
	o.hasCustomJar = true
	return o
}

// WithTokenErrorHandler registers a callback invoked whenever the SPNEGO
// transport fails to obtain a Kerberos token.
func (o *Options) WithTokenErrorHandler(fn func(error)) *Options {
	o.tokenErrFunc = fn
	return o
}

func (o *Options) WithVerboseReq(fn func(*http.Request)) *Options {
	o.verboseReqFunc = fn
	return o
}

func (o *Options) WithVerboseResp(fn func(*http.Response)) *Options {
	o.verboseRespFunc = fn
	return o
}

// NewClient creates an *http.Client using the accumulated Options.
func (o *Options) NewClient() (*http.Client, error) {
	return buildClient(o)
}

func WithCA(caPath string) Option {
	return func(o *Options) { o.caPath = caPath }
}

func WithClientCert(certPath, keyPath string) Option {
	return func(o *Options) {
		o.certPath = certPath
		o.keyPath = keyPath
	}
}

func WithInsecure(skip bool) Option {
	return func(o *Options) { o.insecure = skip }
}

func WithCCachePath(path string) Option {
	return func(o *Options) { o.ccachePath = path }
}

func WithConfPath(path string) Option {
	return func(o *Options) { o.confPath = path }
}

// WithCookieFile sets a Netscape/curl-format cookie file for the client.
// Existing cookies are loaded at startup; cookies received during HTTP
// exchanges are written back to the file after each Set-Cookie response.
// The file is created if it does not exist. An in-memory jar is the default
// when this option is omitted.
func WithCookieFile(path string) Option {
	return func(o *Options) { o.cookieFile = path }
}

// WithCookieJar sets a caller-supplied http.CookieJar on the client.
// Passing nil disables the cookie jar entirely (http.Client.Jar = nil),
// which forces a fresh SPNEGO exchange on every request with no cookie state.
// Use this to share a jar across multiple clients or to inject a pre-populated
// jar without file backing.
func WithCookieJar(jar http.CookieJar) Option {
	return func(o *Options) {
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
	return func(o *Options) { o.tokenErrFunc = fn }
}

func WithVerboseReq(fn func(*http.Request)) Option {
	return func(o *Options) { o.verboseReqFunc = fn }
}

func WithVerboseResp(fn func(*http.Response)) Option {
	return func(o *Options) { o.verboseRespFunc = fn }
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
	o := &Options{}
	for _, opt := range opts {
		opt(o)
	}
	return buildClient(o)
}

// buildClient constructs the *http.Client from a fully populated Options.
func buildClient(o *Options) (*http.Client, error) {
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
