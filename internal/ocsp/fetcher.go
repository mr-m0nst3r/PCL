package ocsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// GetOCSPURLFromCert extracts OCSP URL from certificate's AIA extension.
// Returns empty string if no OCSP URL is present.
func GetOCSPURLFromCert(cert *x509.Certificate) string {
	if cert == nil || len(cert.OCSPServer) == 0 {
		return ""
	}
	return cert.OCSPServer[0]
}

// FetchOCSP sends an OCSP request to the specified URL and returns the response.
// Requires issuer certificate to compute IssuerNameHash and IssuerKeyHash per RFC 6960.
// The response is parsed but signature is not verified (nil issuer passed to ParseResponse).
// Signature verification should be done by operators (ocspValid operator).
func FetchOCSP(cert, issuer *x509.Certificate, url string, timeout time.Duration) (*ocsp.Response, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if issuer == nil {
		return nil, fmt.Errorf("issuer certificate is required for OCSP request")
	}
	if url == "" {
		return nil, fmt.Errorf("OCSP URL is required")
	}

	// Create OCSP request
	req, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{
		Hash: crypto.SHA256, // Use SHA256 for issuer hash
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Send HTTP POST request
	client := &http.Client{
		Timeout: timeout,
	}
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send OCSP request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP server returned status %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	// Parse response without signature verification
	// Signature verification is done by ocspValid operator with chain context
	resp, err := ocsp.ParseResponse(body, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	return resp, nil
}

// FetchOCSPFromChain automatically fetches OCSP response for the leaf certificate.
// Uses the first OCSP URL from leaf cert's AIA extension and the issuer from chain.
// Returns nil if no OCSP URL is present or chain is insufficient.
func FetchOCSPFromChain(chain []*x509.Certificate, timeout time.Duration) (*ocsp.Response, string, error) {
	if len(chain) < 2 {
		return nil, "", fmt.Errorf("chain must have at least 2 certificates (leaf + issuer)")
	}

	leaf := chain[0]
	issuer := chain[1]

	url := GetOCSPURLFromCert(leaf)
	if url == "" {
		return nil, "", nil // No OCSP URL, not an error
	}

	resp, err := FetchOCSP(leaf, issuer, url, timeout)
	if err != nil {
		return nil, url, err
	}

	return resp, url, nil
}