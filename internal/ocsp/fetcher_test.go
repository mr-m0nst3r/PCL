package ocsp

import (
	"bytes"
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
	_, err := FetchOCSP(nil, &x509.Certificate{}, "http://example.com", 5, nil)
	if err == nil {
		t.Error("Expected error for nil cert")
	}
}

func TestFetchOCSP_NilIssuer(t *testing.T) {
	_, err := FetchOCSP(&x509.Certificate{}, nil, "http://example.com", 5, nil)
	if err == nil {
		t.Error("Expected error for nil issuer")
	}
}

func TestFetchOCSP_EmptyURL(t *testing.T) {
	_, err := FetchOCSP(&x509.Certificate{}, &x509.Certificate{}, "", 5, nil)
	if err == nil {
		t.Error("Expected error for empty URL")
	}
}

func TestFetchOCSPFromChain_TooShort(t *testing.T) {
	chain := []*x509.Certificate{&x509.Certificate{}}
	_, _, err := FetchOCSPFromChain(chain, 5, nil)
	if err == nil {
		t.Error("Expected error for chain with less than 2 certificates")
	}
}

func TestFetchOCSPFromChain_EmptyChain(t *testing.T) {
	chain := []*x509.Certificate{}
	_, _, err := FetchOCSPFromChain(chain, 5, nil)
	if err == nil {
		t.Error("Expected error for empty chain")
	}
}

func TestFetchOCSPFromChain_NoOCSPURL(t *testing.T) {
	chain := []*x509.Certificate{
		&x509.Certificate{OCSPServer: nil},
		&x509.Certificate{},
	}
	resp, url, err := FetchOCSPFromChain(chain, 5, nil)
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

func TestNonceOptions_GenerateNonce(t *testing.T) {
	nonce, err := generateNonce(32)
	if err != nil {
		t.Errorf("Failed to generate nonce: %v", err)
	}
	if len(nonce) != 32 {
		t.Errorf("Expected nonce length 32, got %d", len(nonce))
	}
}

func TestNonceOptions_ParseNonceHex(t *testing.T) {
	hexValue := "aabbccdd12345678"
	nonce, err := parseNonceHex(hexValue)
	if err != nil {
		t.Errorf("Failed to parse nonce hex: %v", err)
	}
	expected := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x12, 0x34, 0x56, 0x78}
	if !bytes.Equal(nonce, expected) {
		t.Errorf("Expected %v, got %v", expected, nonce)
	}
}

func TestAddNonceExtension(t *testing.T) {
	// Create a minimal OCSPRequest for testing
	// OCSPRequest ::= SEQUENCE { TBSRequest }
	// TBSRequest ::= SEQUENCE { requestList }
	// requestList ::= SEQUENCE OF Request

	// Minimal TBSRequest content (just requestList)
	requestList := encodeSequence(encodeSequence([]byte{}))
	tbsRequest := encodeSequence(requestList)
	ocspRequest := encodeSequence(tbsRequest)

	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	result, err := addNonceToOCSPRequest(ocspRequest, nonce)
	if err != nil {
		t.Errorf("Failed to add nonce extension: %v", err)
	}

	// Verify the result is valid DER
	if len(result) < len(ocspRequest)+10 {
		t.Errorf("Result too short, nonce extension may not be added properly")
	}

	// Check that result starts with SEQUENCE tag (0x30)
	if result[0] != 0x30 {
		t.Errorf("Expected SEQUENCE tag (0x30), got 0x%02x", result[0])
	}

	// Verify it can be parsed back
	_, contentStart := parseDERLength(result, 1)
	if contentStart >= len(result) {
		t.Errorf("Invalid result structure")
	}
}