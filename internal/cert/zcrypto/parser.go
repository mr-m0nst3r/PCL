package zcrypto

import (
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/asn1"
)

// ParseTBSCertSignatureParams parses the signature AlgorithmIdentifier
// from TBSCertificate and returns the parameters state.
func ParseTBSCertSignatureParams(rawTBSCertificate []byte) asn1.ParamsState {
	input := cryptobyte.String(rawTBSCertificate)

	var tbsCert cryptobyte.String
	if !input.ReadASN1(&tbsCert, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Skip version (optional, context-specific tag 0)
	if !tbsCert.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return asn1.ParamsState{}
	}

	// Skip serialNumber (INTEGER)
	if !tbsCert.SkipASN1(cryptobyte_asn1.INTEGER) {
		return asn1.ParamsState{}
	}

	// Read signature AlgorithmIdentifier
	var sigAlgoID cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !tbsCert.ReadAnyASN1Element(&sigAlgoID, &tag) {
		return asn1.ParamsState{}
	}

	return asn1.ParseAlgorithmIDParams(sigAlgoID)
}

// ParseCertSignatureAlgorithmParams parses the outer signatureAlgorithm
// from a certificate and returns the parameters state.
func ParseCertSignatureAlgorithmParams(rawCertificate []byte) asn1.ParamsState {
	input := cryptobyte.String(rawCertificate)

	var cert cryptobyte.String
	if !input.ReadASN1(&cert, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Skip TBSCertificate
	var tbs cryptobyte.String
	if !cert.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Read signatureAlgorithm
	var sigAlgo cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !cert.ReadAnyASN1Element(&sigAlgo, &tag) {
		return asn1.ParamsState{}
	}

	return asn1.ParseAlgorithmIDParams(sigAlgo)
}

// ParseSubjectPublicKeyInfoParams parses the algorithm AlgorithmIdentifier
// from SubjectPublicKeyInfo and returns the parameters state.
func ParseSubjectPublicKeyInfoParams(rawSubjectPublicKeyInfo []byte) asn1.ParamsState {
	input := cryptobyte.String(rawSubjectPublicKeyInfo)

	var spki cryptobyte.String
	if !input.ReadASN1(&spki, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Read algorithm AlgorithmIdentifier
	var algoID cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !spki.ReadAnyASN1Element(&algoID, &tag) {
		return asn1.ParamsState{}
	}

	return asn1.ParseAlgorithmIDParams(algoID)
}