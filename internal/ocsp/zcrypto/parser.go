package zcrypto

import (
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/asn1"
)

// ParseOCSPSignatureAlgorithmParams parses the signatureAlgorithm
// from an OCSP response and returns the parameters state.
// OCSP structure: OCSPResponse -> responseBytes -> BasicOCSPResponse -> signatureAlgorithm
func ParseOCSPSignatureAlgorithmParams(rawOCSP []byte) asn1.ParamsState {
	input := cryptobyte.String(rawOCSP)

	// Read OCSPResponse SEQUENCE
	var ocspResp cryptobyte.String
	if !input.ReadASN1(&ocspResp, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Read ResponseStatus (ENUMERATED - Tag(10))
	var status cryptobyte.String
	if !ocspResp.ReadASN1(&status, cryptobyte_asn1.ENUM) {
		return asn1.ParamsState{}
	}

	// Read ResponseBytes (context-specific [0] EXPLICIT)
	// The [0] tag is context-specific and constructed (EXPLICIT means wrapped in another SEQUENCE)
	var responseBytesOuter cryptobyte.String
	if !ocspResp.ReadASN1(&responseBytesOuter, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		return asn1.ParamsState{}
	}

	// Inside the [0] wrapper, we have ResponseBytes SEQUENCE
	var responseBytes cryptobyte.String
	if !responseBytesOuter.ReadASN1(&responseBytes, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Skip responseType OID
	var responseType cryptobyte.String
	if !responseBytes.ReadASN1(&responseType, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return asn1.ParamsState{}
	}

	// Read response OCTET STRING (contains BasicOCSPResponse)
	var responseOctet cryptobyte.String
	if !responseBytes.ReadASN1(&responseOctet, cryptobyte_asn1.OCTET_STRING) {
		return asn1.ParamsState{}
	}

	// Parse BasicOCSPResponse from OCTET STRING
	var basicResp cryptobyte.String
	if !responseOctet.ReadASN1(&basicResp, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Skip TBSResponseData SEQUENCE
	var tbsResp cryptobyte.String
	if !basicResp.ReadASN1(&tbsResp, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Read signatureAlgorithm (AlgorithmIdentifier after TBSResponseData)
	var sigAlgo cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !basicResp.ReadAnyASN1Element(&sigAlgo, &tag) {
		return asn1.ParamsState{}
	}

	return asn1.ParseAlgorithmIDParams(sigAlgo)
}