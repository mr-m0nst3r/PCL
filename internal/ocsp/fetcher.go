package ocsp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Nonce OID: id-pkix-ocsp-nonce (1.3.6.1.5.5.7.48.1.2)
const nonceOID = "1.3.6.1.5.5.7.48.1.2"

// NonceOptions configures nonce in OCSP requests (RFC 9654).
type NonceOptions struct {
	Length    int    // Length of nonce to generate (default 32, per RFC 9654)
	Value     string // Custom nonce value in hex format (optional)
	Disabled  bool   // Disable nonce in requests
	Hash      string // Hash algorithm for CertID: "sha1" or "sha256" (default)
}

// encodeOctetString wraps content in OCTET STRING tag (04).
func encodeOctetString(content []byte) []byte {
	return encodeTagged(0x04, content)
}

// encodeContextTagged wraps content in context-specific tag.
func encodeContextTagged(tag int, content []byte) []byte {
	return encodeTagged(byte(0xA0|tag), content) // context-specific, constructed
}

// encodeTagged wraps content with tag and length.
func encodeTagged(tag byte, content []byte) []byte {
	length := len(content)
	var result []byte
	result = append(result, tag)
	if length < 128 {
		result = append(result, byte(length))
	} else {
		// Long form length encoding
		lenBytes := encodeLengthBytes(length)
		result = append(result, byte(0x80|len(lenBytes)))
		result = append(result, lenBytes...)
	}
	result = append(result, content...)
	return result
}

// encodeLengthBytes encodes length as bytes for long form.
func encodeLengthBytes(length int) []byte {
	var result []byte
	for length > 0 {
		result = append([]byte{byte(length & 0xFF)}, result...)
		length >>= 8
	}
	return result
}

// encodeOID encodes an OID string like "1.3.6.1.5.5.7.48.1.2" to DER bytes.
func encodeOID(oid string) []byte {
	// Pre-encoded nonce OID: 06 09 2B 06 01 05 05 07 30 01 02
	// OID 1.3.6.1.5.5.7.48.1.2
	return []byte{0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02}
}

// encodeSequence wraps content in SEQUENCE tag (30).
func encodeSequence(content []byte) []byte {
	return encodeTagged(0x30, content)
}

// generateNonce generates a random nonce of specified length.
func generateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// parseNonceHex parses a hex string to bytes.
func parseNonceHex(hexValue string) ([]byte, error) {
	return hex.DecodeString(hexValue)
}

// FetchResult contains OCSP response and request debug info.
type FetchResult struct {
	Response    *ocsp.Response
	RequestInfo *RequestInfo
}

// RequestInfo contains OCSP request debug information.
type RequestInfo struct {
	Nonce           []byte // Nonce sent in request (nil if no nonce)
	NonceHex        string // Hex representation of nonce
	NonceLen        int    // Length of nonce in request (0 if no nonce)
	RequestLen      int    // Length of raw OCSP request bytes
	HashAlgorithm   string // Hash algorithm used for CertID (e.g., "SHA256")
}

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
// nonceOpts configures nonce extension in request (RFC 9654) and hash algorithm for CertID.
func FetchOCSPWithInfo(cert, issuer *x509.Certificate, url string, timeout time.Duration, nonceOpts *NonceOptions) (*FetchResult, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if issuer == nil {
		return nil, fmt.Errorf("issuer certificate is required for OCSP request")
	}
	if url == "" {
		return nil, fmt.Errorf("OCSP URL is required")
	}

	// Determine hash algorithm for CertID
	var hashAlgorithm crypto.Hash
	var hashName string
	if nonceOpts != nil && nonceOpts.Hash == "sha1" {
		hashAlgorithm = crypto.SHA1
		hashName = "SHA1"
	} else {
		hashAlgorithm = crypto.SHA256 // Default, modern and more secure
		hashName = "SHA256"
	}

	// Create OCSP request
	req, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{
		Hash: hashAlgorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Track request info
	reqInfo := &RequestInfo{
		RequestLen:    len(req),
		HashAlgorithm: hashName,
	}

	// Add nonce extension if configured
	if nonceOpts != nil && !nonceOpts.Disabled {
		var nonce []byte
		if nonceOpts.Value != "" {
			// Use custom nonce value
			nonce, err = parseNonceHex(nonceOpts.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid nonce hex value: %w", err)
			}
		} else {
			// Generate random nonce
			length := nonceOpts.Length
			if length <= 0 {
				length = 32 // Default per RFC 9654
			}
			if length < 1 || length > 128 {
				return nil, fmt.Errorf("nonce length must be 1-128 bytes (RFC 9654)")
			}
			nonce, err = generateNonce(length)
			if err != nil {
				return nil, err
			}
		}

		// The request from ocsp.CreateRequest is the full OCSPRequest bytes.
		// We need to extract TBSRequest and add nonce extension.
		// OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, optionalSignature [0] Signature OPTIONAL }
		// The request bytes are the full OCSPRequest SEQUENCE.
		// We decode the SEQUENCE to get TBSRequest content.
		req, err = addNonceToOCSPRequest(req, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to add nonce extension: %w", err)
		}

		// Update request info with nonce details
		reqInfo.Nonce = nonce
		reqInfo.NonceHex = hex.EncodeToString(nonce)
		reqInfo.NonceLen = len(nonce)
		reqInfo.RequestLen = len(req)
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

	return &FetchResult{
		Response:    resp,
		RequestInfo: reqInfo,
	}, nil
}

// FetchOCSP is the legacy function that returns just the response.
// Deprecated: Use FetchOCSPWithInfo for debug info support.
func FetchOCSP(cert, issuer *x509.Certificate, url string, timeout time.Duration, nonceOpts *NonceOptions) (*ocsp.Response, error) {
	result, err := FetchOCSPWithInfo(cert, issuer, url, timeout, nonceOpts)
	if err != nil {
		return nil, err
	}
	return result.Response, nil
}

// addNonceToOCSPRequest adds nonce extension to an OCSP request.
// The OCSPRequest is SEQUENCE { TBSRequest, [0] optionalSignature }
// We extract TBSRequest content, add nonce extension, and rebuild with correct length.
func addNonceToOCSPRequest(ocspRequest []byte, nonce []byte) ([]byte, error) {
	// Decode OCSPRequest SEQUENCE
	if len(ocspRequest) < 2 || ocspRequest[0] != 0x30 {
		return nil, fmt.Errorf("invalid OCSP request: expected SEQUENCE tag")
	}

	// Parse OCSPRequest SEQUENCE length
	ocspLen, contentStart := parseDERLength(ocspRequest, 1)
	if contentStart+ocspLen > len(ocspRequest) {
		return nil, fmt.Errorf("invalid OCSP request: length mismatch")
	}

	// TBSRequest is the first element in OCSPRequest
	tbsBytes := ocspRequest[contentStart:contentStart+ocspLen]

	// Verify TBSRequest is SEQUENCE
	if len(tbsBytes) < 2 || tbsBytes[0] != 0x30 {
		return nil, fmt.Errorf("invalid TBSRequest: expected SEQUENCE tag")
	}

	// Extract TBSRequest content (after tag and length)
	tbsLen, tbsContentStart := parseDERLength(tbsBytes, 1)
	tbsContent := tbsBytes[tbsContentStart:tbsContentStart+tbsLen]

	// Build nonce extension
	nonceOctetString := encodeOctetString(nonce)
	extensionContent := append(encodeOID(nonceOID), nonceOctetString...)
	extension := encodeSequence(extensionContent)
	extensions := encodeSequence(extension)
	requestExtensions := encodeContextTagged(2, extensions)

	// Append nonce extension to TBSRequest content
	newTbsContent := append(tbsContent, requestExtensions...)

	// Rebuild TBSRequest with correct length
	newTbsRequest := encodeSequence(newTbsContent)

	// Rebuild OCSPRequest as SEQUENCE { TBSRequest }
	return encodeSequence(newTbsRequest), nil
}

// parseDERLength parses DER length encoding starting at pos.
// Returns the length value and the start position of content.
func parseDERLength(data []byte, pos int) (int, int) {
	if data[pos] < 128 {
		// Short form: length in single byte
		return int(data[pos]), pos + 1
	}
	// Long form: length in following bytes
	lenBytes := int(data[pos] & 0x7F)
	length := 0
	for i := 0; i < lenBytes; i++ {
		length = (length << 8) | int(data[pos+1+i])
	}
	return length, pos + 1 + lenBytes
}

// FetchOCSPFromChain automatically fetches OCSP response for the leaf certificate.
// Uses the first OCSP URL from leaf cert's AIA extension and the issuer from chain.
// Returns nil if no OCSP URL is present or chain is insufficient.
// nonceOpts configures nonce extension in request (RFC 9654).
func FetchOCSPFromChainWithInfo(chain []*x509.Certificate, timeout time.Duration, nonceOpts *NonceOptions) (*FetchResult, string, error) {
	if len(chain) < 2 {
		return nil, "", fmt.Errorf("chain must have at least 2 certificates (leaf + issuer)")
	}

	leaf := chain[0]
	issuer := chain[1]

	url := GetOCSPURLFromCert(leaf)
	if url == "" {
		return nil, "", nil // No OCSP URL, not an error
	}

	result, err := FetchOCSPWithInfo(leaf, issuer, url, timeout, nonceOpts)
	if err != nil {
		return nil, url, err
	}

	return result, url, nil
}

// FetchOCSPFromChain is the legacy function.
// Deprecated: Use FetchOCSPFromChainWithInfo for debug info support.
func FetchOCSPFromChain(chain []*x509.Certificate, timeout time.Duration, nonceOpts *NonceOptions) (*ocsp.Response, string, error) {
	result, url, err := FetchOCSPFromChainWithInfo(chain, timeout, nonceOpts)
	if err != nil {
		return nil, url, err
	}
	if result == nil {
		return nil, url, nil
	}
	return result.Response, url, nil
}