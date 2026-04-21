# krbhttp

Pure-Go SPNEGO/Kerberos HTTP authentication for Go's `net/http` — no CGo, no external dependencies beyond the standard Kerberos tooling already on your machine.

Drop in a single `krbhttp.NewClient()` call and get back a standard `*http.Client` that transparently handles Kerberos `HTTP/Negotiate` authentication on macOS, Linux, and Windows using the same API on all three platforms.

- Reads your existing Kerberos credentials automatically — no extra configuration in most cases
- Handles OIDC redirect chains that span multiple Kerberos-protected hosts
- Persists session cookies to a curl-compatible file so repeat calls skip the full auth handshake

---

## Installation

```bash
go get github.com/jbvmio/krbhttp
```

If `go get` must pass through an intranet proxy:

```bash
HTTPS_PROXY=http://proxy.corp.example.com:8080 go get github.com/jbvmio/krbhttp
```

---

## Quick start

```go
package main

import (
    "fmt"
    "io"
    "log"

    "github.com/jbvmio/krbhttp"
)

func main() {
    // NewClient with no options:
    //   - SPNEGO Negotiate auth (reads existing Kerberos credentials)
    //   - In-memory cookie jar (sessions survive for the life of the client)
    //   - System TLS roots
    c, err := krbhttp.NewClient()
    if err != nil {
        log.Fatal(err)
    }

    resp, err := c.Get("https://internal-api.corp.example.com/api/v1/status")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Printf("Status: %d\n%s\n", resp.StatusCode, body)
}
```

If `klist` shows a valid TGT, the request authenticates automatically.

---

## Options styles

There are three equivalent ways to configure a client.

### Inline options (original style)

```go
c, err := krbhttp.NewClient(
    krbhttp.WithCA("/etc/ssl/certs/corporate-ca.pem"),
    krbhttp.WithCookieFile("~/.config/myapp/session.cookie"),
)
```

### Pre-configured Options struct

Build an `*Options` value ahead of time, then call `NewClient` on it when ready.
Useful when configuration is spread across multiple functions or conditionally assembled.

```go
opts := krbhttp.NewOptions()
opts.WithCA("/etc/ssl/certs/corporate-ca.pem")
opts.WithCookieFile("~/.config/myapp/session.cookie")

c, err := opts.NewClient()
```

### Chained builder

```go
c, err := krbhttp.NewOptions().
    WithCA("/etc/ssl/certs/corporate-ca.pem").
    WithCookieFile("~/.config/myapp/session.cookie").
    NewClient()
```

---

## Platform support

All three platforms are CGo-free:

| Platform | Mechanism | Notes |
|---|---|---|
| **macOS** | `GSS.framework` via [ebitengine/purego](https://github.com/ebitengine/purego) | Apple's Heimdal GSSAPI; reads both FILE and API-type (CCAPI) ccaches — corporate SSO credentials are picked up automatically |
| **Linux** | [jcmturner/gokrb5](https://github.com/jcmturner/gokrb5) (pure Go) | Reads `KRB5CCNAME` or `/tmp/krb5cc_$(id -u)`; passes an explicit SPN to avoid gokrb5's internal `net.LookupCNAME` call (see [jcmturner/gokrb5#527](https://github.com/jcmturner/gokrb5/issues/527)) |
| **Windows** | `secur32.dll` / SSPI | Loaded at runtime via `golang.org/x/sys/windows`; SSPI handles credential lookup and CNAME resolution internally |

---

## Design notes

### Proactive token injection (not 401-retry)

The transport adds a fresh, host-specific Kerberos token to _every_ outgoing request — including every redirect hop — rather than waiting for a `401 WWW-Authenticate: Negotiate` challenge. This is necessary for OIDC redirect flows (Apache `mod_auth_openidc`, Keycloak, Azure AD Proxy, etc.) where:

1. The server returns **302**, not 401, when it needs authentication.
2. Go's `http.Client` strips the `Authorization` header on cross-host redirects.
3. Each host in the OIDC chain requires a token issued specifically for _its_ hostname.

This mirrors the behavior of `curl --negotiate --location-trusted`.

### CNAME resolution

SPNs in Active Directory are registered under canonical A-record hostnames, not CNAME aliases. Passing an alias gets a `KDC_ERR_S_PRINCIPAL_UNKNOWN` rejection. Before constructing any SPN, `krbhttp` iterates `net.LookupCNAME` until the result stabilises — a single call is not sufficient because both the CGo and pure-Go resolvers can stop at intermediate hops for multi-level CNAME chains.
https://github.com/golang/go/issues/59943

---

## Cookie jar modes

Without cookie persistence, every call to an OIDC-protected endpoint re-runs the full redirect chain. Four modes are available:

### In-memory (default)

Cookies survive for the lifetime of the `*http.Client`. Good for short-lived programs.

```go
c, err := krbhttp.NewClient()

// or
c, err := krbhttp.NewOptions().NewClient()
```

### File-backed

Cookies are loaded from a Netscape/curl-format file at startup and written back after every `Set-Cookie` response. The file is created if it doesn't exist. Compatible with `curl -c`/`-b`.

```go
c, err := krbhttp.NewClient(
    krbhttp.WithCookieFile("/home/alice/.config/myapp/session.cookie"),
)

// or
opts := krbhttp.NewOptions()
opts.WithCookieFile("/home/alice/.config/myapp/session.cookie")
c, err := opts.NewClient()
```

### Bring-your-own jar

Useful when multiple clients share a session or when you need custom jar logic.

```go
import "net/http/cookiejar"
import "golang.org/x/net/publicsuffix"

jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})

c, err := krbhttp.NewClient(
    krbhttp.WithCookieJar(jar),
)
```

### No jar (stateless)

Passing `nil` forces a fresh SPNEGO exchange on every request.

```go
c, err := krbhttp.NewClient(
    krbhttp.WithCookieJar(nil),
)
```

---

## All options

All options are available through both the `NewClient` functional style and the `*Options` builder style.

```go
// Functional style — pass options directly to NewClient
c, err := krbhttp.NewClient(
    // TLS
    krbhttp.WithCA("/etc/ssl/certs/corporate-ca.pem"),    // add a custom CA bundle
    krbhttp.WithClientCert("client.crt", "client.key"),  // mutual TLS
    krbhttp.WithInsecure(true),                           // skip TLS verify (dev/debug only)

    // Cookie jar (choose one)
    krbhttp.WithCookieFile("~/.config/myapp/session.cookie"), // file-backed
    krbhttp.WithCookieJar(myJar),                             // bring-your-own
    krbhttp.WithCookieJar(nil),                               // disable entirely

    // Linux-specific: Kerberos credential paths
    krbhttp.WithCCachePath("/tmp/krb5cc_1000"),  // override default ccache
    krbhttp.WithConfPath("/etc/krb5.conf"),      // override default krb5.conf

    // Observability
    krbhttp.WithTokenErrorHandler(func(err error) {
        log.Printf("SPNEGO token error: %v", err)
    }),
    krbhttp.WithVerboseReq(krbhttp.DefaultVerboseReq),
    krbhttp.WithVerboseResp(krbhttp.DefaultVerboseResp),
)

// Options struct style — configure ahead of time, build later
opts := krbhttp.NewOptions()
opts.WithCA("/etc/ssl/certs/corporate-ca.pem")
opts.WithClientCert("client.crt", "client.key")
opts.WithInsecure(true)
opts.WithCookieFile("~/.config/myapp/session.cookie")
opts.WithCCachePath("/tmp/krb5cc_1000")
opts.WithConfPath("/etc/krb5.conf")
opts.WithTokenErrorHandler(func(err error) {
    log.Printf("SPNEGO token error: %v", err)
})
opts.WithVerboseReq(krbhttp.DefaultVerboseReq)
opts.WithVerboseResp(krbhttp.DefaultVerboseResp)
c, err := opts.NewClient()
```

`DefaultVerboseReq` and `DefaultVerboseResp` print curl `--verbose`-style output to stderr. For example, an authenticated redirect flow looks like:

```
> GET /api/user HTTP/1.1
> Host: internal-api.corp.example.com
> Accept: */*
> Authorization: Negotiate YIIFjgYGKwYBBQUCoIIFgjCCBX6gMDAuBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYK…
>
< HTTP/1.1 302 Found
< Location: https://auth-oidc.corp.example.com/authorization?...
< Set-Cookie: oidc_state=…; Path=/; HttpOnly
<
> GET /authorization?... HTTP/1.1
> Host: auth-oidc.corp.example.com
> Accept: */*
> Authorization: Negotiate YIIFjgYGKwYBBQUCoIIFgjCCBX6gMDAuBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYK…
>
< HTTP/1.1 302 Found
< Location: https://internal-api.corp.example.com/oidc/cb?code=…
<
> GET /oidc/cb?code=… HTTP/1.1
> Host: internal-api.corp.example.com
> Accept: */*
> Cookie: oidc_state=…
>
< HTTP/1.1 200 OK
< Content-Type: application/json
<
```

If you need more control — writing to a logger, filtering certain headers — pass your own function to `WithVerboseReq`/`WithVerboseResp` instead.

---

## Using only the SPNEGO transport

If you already have an `*http.Client` configured and just need SPNEGO added to it, wrap your existing transport directly:

```go
import (
    "net/http"
    "github.com/jbvmio/krbhttp/spnego"
)

c := &http.Client{
    Transport: &spnego.Transport{
        Base: myExistingTransport, // nil falls back to http.DefaultTransport
    },
    Jar: myExistingJar,
}
```

`spnego.Transport` is a standard `http.RoundTripper`. It handles CNAME resolution and token injection internally. If the caller has already set an `Authorization` header it is left untouched.

---

## Example

The [example/](example/) directory contains a runnable program with simple verbose tracing. Point it at any SPNEGO-protected endpoint:

```bash
export TARGET_URL=https://internal-api.corp.example.com/api/user
cd example && go run .
```

First run (cold cache — OIDC flow):

```
-> GET https://internal-api.corp.example.com/api/user
<- 302 Found
-> GET https://auth-oidc.corp.example.com/authorization?...
<- 302 Found
-> GET https://internal-api.corp.example.com/oidc/cb?code=...
<- 302 Found
-> GET https://internal-api.corp.example.com/api/user
<- 200 OK
```

Subsequent runs (session cookie cached):

```
-> GET https://internal-api.corp.example.com/api/user
<- 200 OK
```

---

## Architecture

```
krbhttp/
  (root package — github.com/jbvmio/krbhttp)
    client.go         — NewClient factory and functional options
    cookiejar.go      — persistingJar (file-backed), newMemoryJar, newFileJar
    tls.go            — buildTLSTransport, verboseTransport wrapper
    platform_linux.go — sets ccache/conf paths on the negotiate package
    platform_other.go — no-op on macOS and Windows
  spnego/
    transport.go      — http.RoundTripper: proactive Negotiate header injection
  negotiate/
    types.go               — shared GSSAPI types (gssBufferDesc, gssOIDDesc, etc.)
    resolve.go             — resolveCNAME: iterative CNAME chain resolution
    negotiate_darwin.go    — GSS.framework binding via purego
    negotiate_linux.go     — gokrb5 binding (pure Go)
    negotiate_windows.go   — SSPI / secur32.dll binding
  krb/
    ccache.go         — Linux ccache path resolution
  example/
    main.go           — runnable end-to-end example
```

Data flow:

```
krbhttp.NewClient(opts...)
  └─► *http.Client{
        Transport: spnego.Transport → base http.Transport (TLS configured)
        Jar:       persistingJar | memoryJar | nil
      }

c.Do(req)
  └─► spnego.Transport.RoundTrip(req)
        ├─ resolveCNAME(req.URL.Host)       — follow DNS aliases to canonical host
        ├─ negotiate.Token(canonical host)  — platform-specific Kerberos call
        ├─ clone request, set Accept: */*   — mod_auth_openidc compatibility
        ├─ set Authorization: Negotiate …   — attach token
        └─► base transport sends request
              └─ http.Client follows redirects; each hop gets a fresh token
                   └─ CookieJar stores Set-Cookie responses
```

---

## Prerequisites

### macOS
- macOS 10.7+ (GSS.framework is present on all modern systems)
- A valid Kerberos ticket (`klist` should show a TGT). Corporate SSO / AD login typically creates one automatically; otherwise: `kinit user@REALM`

### Linux
- `krb5-user` (Debian/Ubuntu) or `krb5-workstation` (RHEL/Fedora)
- A valid ccache (`klist` shows a TGT); if not: `kinit user@REALM`
- `/etc/krb5.conf` configured for your realm

### Windows
- Domain-joined machine, or MIT Kerberos for Windows with an explicit `kinit`
- `secur32.dll` is a standard Windows system DLL — no additional installation needed

---

## Roadmap

- [ ] **Kerberos proxy authentication** — `Proxy-Authorization: Negotiate` for environments where the HTTP proxy itself requires Kerberos auth
- [ ] **Windows end-to-end testing** — the SSPI binding compiles cleanly but needs validation against a real AD environment
- [ ] **Context-aware cancellation** — propagate `context.Context` through GSSAPI calls (currently cancellation only reaches the HTTP transport layer)
- [ ] **Mock GSSAPI for unit tests** — a fake `negotiate.Token` injector so downstream consumers can test their integration code without a live KDC
- [ ] **Kerberos delegation** — opt-in `GSS_C_DELEG_FLAG` for S4U2Self / constrained delegation scenarios
- [ ] **FreeBSD support** — Heimdal is available on FreeBSD; the macOS purego approach should translate

---

## Contributing

```bash
git clone https://github.com/jbvmio/krbhttp
cd krbhttp
go build ./...

# Cross-compile (both are CGo-free)
GOOS=linux GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
```

To test the public API as an external consumer without publishing, use a `replace` directive:

```
# go.mod in your test module
module test/myapp
go 1.21
require github.com/jbvmio/krbhttp v0.0.0
replace github.com/jbvmio/krbhttp => /path/to/local/krbhttp
```

---

## License

See [LICENSE](LICENSE) in the root of this repository.
