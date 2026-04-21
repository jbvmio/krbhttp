package krbhttp

// cookiejar.go — Cookie jar implementations for the HTTP client.
//
// Three modes are supported:
//
//   - In-memory (default): cookies survive the lifetime of the http.Client
//     but are never written to disk. Safe for one-shot calls or when cookie
//     persistence is not required.
//
//   - File-backed (WithCookieFile): cookies are loaded from a Netscape/curl
//     cookie file at startup and written back after every Set-Cookie exchange.
//     The file is created on first write if it does not already exist.
//
//   - Bring-your-own (WithCookieJar): caller provides an http.CookieJar
//     directly — e.g. a pre-populated jar shared across multiple clients.
//     Passing nil disables the jar entirely (http.Client.Jar = nil), which
//     forces a fresh SPNEGO exchange on every request with no cookie state.
//
// Implementation note: Go's cookiejar.Jar.Cookies() returns only Name+Value
// and strips all metadata (Domain, Path, Secure, HttpOnly, Expires). A shadow
// map of full *http.Cookie values is therefore maintained in persistingJar so
// those attributes are preserved across save/load cycles.

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// newMemoryJar returns a new empty in-memory cookie jar. Cookies are valid
// for the lifetime of the jar only and are never written to disk.
func newMemoryJar() (http.CookieJar, error) {
	return cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
}

// newFileJar creates a file-backed cookie jar. If path exists its cookies are
// loaded immediately. The jar writes its full state back to path after every
// SetCookies call; path is created if it does not exist.
func newFileJar(path string) (http.CookieJar, error) {
	inner, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	pj := &persistingJar{
		inner:   inner,
		path:    path,
		entries: make(map[cookieKey]*http.Cookie),
	}
	if err := pj.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("cookiejar: loading %s: %w", path, err)
	}
	return pj, nil
}

// cookieKey uniquely identifies a stored cookie within a jar.
type cookieKey struct {
	domain string
	name   string
	path   string
}

// persistingJar wraps a cookiejar.Jar and maintains a shadow copy of full
// cookie attributes so they survive serialisation. cookiejar.Jar.Cookies()
// only returns Name+Value; the shadow map preserves Domain, Path, Secure,
// HttpOnly and Expires across save/load cycles.
type persistingJar struct {
	inner   *cookiejar.Jar
	path    string
	mu      sync.Mutex
	entries map[cookieKey]*http.Cookie
}

// Cookies implements http.CookieJar.
func (p *persistingJar) Cookies(u *url.URL) []*http.Cookie {
	return p.inner.Cookies(u)
}

// SetCookies implements http.CookieJar. It updates the inner jar, merges the
// full cookie attributes into the shadow map, then persists to disk.
func (p *persistingJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	p.inner.SetCookies(u, cookies)
	p.mu.Lock()
	for _, c := range cookies {
		domain := c.Domain
		if domain == "" {
			domain = u.Host
		}
		cookiePath := c.Path
		if cookiePath == "" {
			cookiePath = "/"
		}
		k := cookieKey{domain: domain, name: c.Name, path: cookiePath}
		// MaxAge < 0 or an expiry in the past signals cookie deletion.
		if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())) {
			delete(p.entries, k)
		} else {
			clone := *c
			clone.Domain = domain
			clone.Path = cookiePath
			p.entries[k] = &clone
		}
	}
	p.mu.Unlock()
	_ = p.save() // best-effort — a write error must not break the HTTP exchange
}

// load reads cookies from p.path into both the inner jar and the shadow map.
func (p *persistingJar) load() error {
	buckets, err := parseCookieFile(p.path)
	if err != nil {
		return err
	}
	// Populate inner jar without holding p.mu; cookiejar.Jar is independently thread-safe.
	for _, b := range buckets {
		p.inner.SetCookies(b.u, b.cookies)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range buckets {
		for _, c := range b.cookies {
			k := cookieKey{domain: c.Domain, name: c.Name, path: c.Path}
			clone := *c
			p.entries[k] = &clone
		}
	}
	return nil
}

// save snapshots the shadow map under a short lock and writes to p.path.
func (p *persistingJar) save() error {
	p.mu.Lock()
	snapshot := make(map[cookieKey]*http.Cookie, len(p.entries))
	for k, v := range p.entries {
		c := *v
		snapshot[k] = &c
	}
	p.mu.Unlock()
	return writeNetscapeCookies(p.path, snapshot)
}

// --- File I/O helpers ---

// cookieBucket groups cookies that share the same host URL.
type cookieBucket struct {
	u       *url.URL
	cookies []*http.Cookie
}

// parseCookieFile reads a Netscape/curl cookie file and returns cookies grouped
// by host URL. Returns a wrapped os.ErrNotExist if path does not exist.
// The scanner buffer is sized to 256 KiB to handle large JWT cookie values.
func parseCookieFile(path string) (map[string]*cookieBucket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buckets := map[string]*cookieBucket{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)

	for sc.Scan() {
		line := sc.Text()
		// libcurl writes HttpOnly cookies as "#HttpOnly_<domain>\t..." rather
		// than using a separate field. Detect and strip that prefix first.
		httpOnly := false
		if strings.HasPrefix(line, "#HttpOnly_") {
			line = strings.TrimPrefix(line, "#HttpOnly_")
			httpOnly = true
		} else if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}
		domain := fields[0]
		cookiePath := fields[2]
		secure := strings.EqualFold(fields[3], "TRUE")
		expiry, _ := strconv.ParseInt(fields[4], 10, 64)
		name := fields[5]
		value := fields[6]

		scheme := "http"
		if secure {
			scheme = "https"
		}
		host := strings.TrimPrefix(domain, ".")
		key := scheme + "://" + host
		if _, ok := buckets[key]; !ok {
			u, err := url.Parse(key)
			if err != nil {
				continue
			}
			buckets[key] = &cookieBucket{u: u}
		}
		c := &http.Cookie{
			Name:     name,
			Value:    value,
			Path:     cookiePath,
			Domain:   domain,
			Secure:   secure,
			HttpOnly: httpOnly,
		}
		if expiry > 0 {
			c.Expires = time.Unix(expiry, 0)
		}
		buckets[key].cookies = append(buckets[key].cookies, c)
	}
	return buckets, sc.Err()
}

// writeNetscapeCookies serialises entries to path in Netscape/curl format,
// creating or truncating the file. Expired cookies are skipped.
func writeNetscapeCookies(path string, entries map[cookieKey]*http.Cookie) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintln(f, "# Netscape HTTP Cookie File")
	fmt.Fprintln(f, "# https://curl.se/docs/http-cookies.html")
	fmt.Fprintln(f, "# This file was generated by krbhttp. Edit at your own risk.")
	fmt.Fprintln(f)

	now := time.Now()
	for _, c := range entries {
		if !c.Expires.IsZero() && c.Expires.Before(now) {
			continue
		}
		prefix := ""
		if c.HttpOnly {
			prefix = "#HttpOnly_"
		}
		subdomains := "FALSE"
		if strings.HasPrefix(c.Domain, ".") {
			subdomains = "TRUE"
		}
		secure := "FALSE"
		if c.Secure {
			secure = "TRUE"
		}
		expiry := int64(0)
		if !c.Expires.IsZero() {
			expiry = c.Expires.Unix()
		}
		fmt.Fprintf(f, "%s%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			prefix, c.Domain, subdomains, c.Path, secure, expiry, c.Name, c.Value)
	}
	return nil
}
