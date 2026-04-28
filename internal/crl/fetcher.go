package crl

import (
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/zmap/zcrypto/x509"
)

// Format represents the CRL format fetched from CRL Distribution Points URL.
type Format string

const (
	FormatDER Format = "DER" // RFC required format
	FormatPEM Format = "PEM" // Fallback format
)

// FetchResult contains the fetched CRL and format information.
type FetchResult struct {
	CRL    *x509.RevocationList
	Format Format
	URL    string
}

// FetchCRL downloads and parses a CRL from a CRL Distribution Points URL.
// Per RFC 5280, CRL Distribution Points must point to DER format CRLs.
func FetchCRL(url string, timeout time.Duration) (*FetchResult, error) {
	if url == "" {
		return nil, fmt.Errorf("CRL URL is required")
	}

	client := &http.Client{
		Timeout: timeout,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRL from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL response: %w", err)
	}

	// Try DER format first (RFC requirement)
	crl, err := x509.ParseRevocationList(body)
	if err == nil {
		return &FetchResult{CRL: crl, Format: FormatDER, URL: url}, nil
	}

	// Try PEM format as fallback
	block, _ := pem.Decode(body)
	if block != nil && block.Type == "X509 CRL" {
		crl, err = x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM CRL: %w", err)
		}
		return &FetchResult{CRL: crl, Format: FormatPEM, URL: url}, nil
	}

	return nil, fmt.Errorf("failed to parse CRL as DER/BER format")
}

// FetchCRLs downloads CRLs from multiple CRL Distribution Points URLs.
// Returns results and any errors encountered.
// Network failures are returned as errors, not as policy failures.
func FetchCRLs(urls []string, timeout time.Duration) ([]*FetchResult, []error) {
	var results []*FetchResult
	var errs []error

	for _, url := range urls {
		result, err := FetchCRL(url, timeout)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, result)
	}

	return results, errs
}