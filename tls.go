package krbhttp

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
)

type verboseTransport struct {
	base            http.RoundTripper
	verboseReqFunc  func(*http.Request)
	verboseRespFunc func(*http.Response)
}

func (t *verboseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.verboseReqFunc != nil {
		t.verboseReqFunc(req)
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if t.verboseRespFunc != nil {
		t.verboseRespFunc(resp)
	}
	return resp, nil
}

func buildTLSTransport(caPath string, insecure bool, certs []tls.Certificate) (*http.Transport, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool.AppendCertsFromPEM(pem)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateFreelyAsClient,
			RootCAs:            pool,
			Certificates:       certs,
			InsecureSkipVerify: insecure,
		},
	}
	return tr, nil
}
