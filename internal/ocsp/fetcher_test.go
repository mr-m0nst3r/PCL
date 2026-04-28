package ocsp

import (
	"crypto/x509"
	"testing"
)

func TestGetOCSPURLFromCert_NilCert(t *testing.T) {
	url := GetOCSPURLFromCert(nil)
	if url != "" {
		t.Errorf("Expected empty URL for nil cert, got %s", url)
	}
}

func TestGetOCSPURLFromCert_NoOCSPServer(t *testing.T) {
	cert := &x509.Certificate{
		OCSPServer: nil,
	}
	url := GetOCSPURLFromCert(cert)
	if url != "" {
		t.Errorf("Expected empty URL for cert with no OCSP server, got %s", url)
	}
}

func TestGetOCSPURLFromCert_EmptyOCSPServer(t *testing.T) {
	cert := &x509.Certificate{
		OCSPServer: []string{},
	}
	url := GetOCSPURLFromCert(cert)
	if url != "" {
		t.Errorf("Expected empty URL for cert with empty OCSP server list, got %s", url)
	}
}

func TestGetOCSPURLFromCert_SingleOCSPServer(t *testing.T) {
	cert := &x509.Certificate{
		OCSPServer: []string{"http://ocsp.example.com"},
	}
	url := GetOCSPURLFromCert(cert)
	if url != "http://ocsp.example.com" {
		t.Errorf("Expected http://ocsp.example.com, got %s", url)
	}
}

func TestGetOCSPURLFromCert_MultipleOCSPServers(t *testing.T) {
	cert := &x509.Certificate{
		OCSPServer: []string{"http://ocsp1.example.com", "http://ocsp2.example.com"},
	}
	url := GetOCSPURLFromCert(cert)
	// Should return the first URL
	if url != "http://ocsp1.example.com" {
		t.Errorf("Expected http://ocsp1.example.com, got %s", url)
	}
}

func TestFetchOCSP_NilCert(t *testing.T) {
	_, err := FetchOCSP(nil, &x509.Certificate{}, "http://example.com", 5)
	if err == nil {
		t.Error("Expected error for nil cert")
	}
}

func TestFetchOCSP_NilIssuer(t *testing.T) {
	_, err := FetchOCSP(&x509.Certificate{}, nil, "http://example.com", 5)
	if err == nil {
		t.Error("Expected error for nil issuer")
	}
}

func TestFetchOCSP_EmptyURL(t *testing.T) {
	_, err := FetchOCSP(&x509.Certificate{}, &x509.Certificate{}, "", 5)
	if err == nil {
		t.Error("Expected error for empty URL")
	}
}

func TestFetchOCSPFromChain_TooShort(t *testing.T) {
	chain := []*x509.Certificate{&x509.Certificate{}}
	_, _, err := FetchOCSPFromChain(chain, 5)
	if err == nil {
		t.Error("Expected error for chain with less than 2 certificates")
	}
}

func TestFetchOCSPFromChain_EmptyChain(t *testing.T) {
	chain := []*x509.Certificate{}
	_, _, err := FetchOCSPFromChain(chain, 5)
	if err == nil {
		t.Error("Expected error for empty chain")
	}
}

func TestFetchOCSPFromChain_NoOCSPURL(t *testing.T) {
	chain := []*x509.Certificate{
		&x509.Certificate{OCSPServer: nil},
		&x509.Certificate{},
	}
	resp, url, err := FetchOCSPFromChain(chain, 5)
	if err != nil {
		t.Errorf("Expected no error for cert without OCSP URL, got %v", err)
	}
	if resp != nil {
		t.Error("Expected nil response for cert without OCSP URL")
	}
	if url != "" {
		t.Errorf("Expected empty URL for cert without OCSP URL, got %s", url)
	}
}