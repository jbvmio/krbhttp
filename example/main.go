package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jbvmio/krbhttp"
)

func main() {
	// TARGET_URL is required: the SPNEGO-protected endpoint to call.
	//   export TARGET_URL=https://internal-api.corp.example.com/api/user
	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		log.Fatal("TARGET_URL environment variable is required")
	}

	// Optional: persist cookies across runs (curl-compatible format).
	//   export COOKIE_FILE=$HOME/.krbhttp.cookie
	var cookieOpts []krbhttp.Option
	if cookieFile := os.Getenv("COOKIE_FILE"); cookieFile != "" {
		cookieOpts = append(cookieOpts, krbhttp.WithCookieFile(cookieFile))
	} else {
		cookieOpts = append(cookieOpts, krbhttp.WithCookieFile(
			filepath.Join(os.Getenv("HOME"), ".krbhttp.cookie"),
		))
	}

	c, err := krbhttp.NewClient(
		append(cookieOpts,
			krbhttp.WithVerboseReq(func(r *http.Request) {
				fmt.Fprintf(os.Stderr, "-> %s %s\n", r.Method, r.URL)
				for k, v := range r.Header {
					fmt.Fprintf(os.Stderr, "  %s: %v\n", k, v)
				}
			}),
			krbhttp.WithVerboseResp(func(r *http.Response) {
				fmt.Fprintf(os.Stderr, "<- %d %s\n", r.StatusCode, r.Status)
			}),
		)...,
	)
	if err != nil {
		log.Fatalf("creating client: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		log.Fatalf("creating request: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("reading response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "status %d: %s\n", resp.StatusCode, body)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
