package asn1

import (
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ParamsState represents the state of an AlgorithmIdentifier parameters field.
type ParamsState struct {
	IsNull   bool   // parameters is ASN.1 NULL
	IsAbsent bool   // parameters field is absent
	OID      string // algorithm OID

	// RSASSA-PSS parameters (OID 1.2.840.113549.1.1.10)
	PSS *PSSParams

	// RSAES-OAEP parameters (OID 1.2.840.113549.1.1.7)
	OAEP *OAEPParams
}

// PSSParams represents RSASSA-PSS-params structure.
type PSSParams struct {
	HashAlgorithm      AlgorithmIdentifier // [0] DEFAULT sha1
	MaskGenAlgorithm   AlgorithmIdentifier // [1] DEFAULT mgf1SHA1
	SaltLength         int                 // [2] DEFAULT 20
	TrailerField       int                 // [3] DEFAULT 1
	HashAlgorithmSet   bool                // whether hashAlgorithm was explicitly set
	MaskGenAlgorithmSet bool               // whether maskGenAlgorithm was explicitly set
	SaltLengthSet      bool                // whether saltLength was explicitly set
	TrailerFieldSet    bool                // whether trailerField was explicitly set
}

// OAEPParams represents RSAES-OAEP-params structure.
type OAEPParams struct {
	HashAlgorithm     AlgorithmIdentifier // [0] DEFAULT sha1
	MaskGenAlgorithm  AlgorithmIdentifier // [1] DEFAULT mgf1SHA1
	PSourceAlgorithm  AlgorithmIdentifier // [2] DEFAULT pSpecifiedEmpty
	HashAlgorithmSet  bool                // whether hashAlgorithm was explicitly set
	MaskGenAlgorithmSet bool               // whether maskGenAlgorithm was explicitly set
	PSourceAlgorithmSet bool               // whether pSourceAlgorithm was explicitly set
}

// AlgorithmIdentifier represents an AlgorithmIdentifier structure.
type AlgorithmIdentifier struct {
	OID    string
	Params ParamsState // nested params for MGF1, etc.
}

// ParseAlgorithmIDParams parses an AlgorithmIdentifier from DER bytes
// and returns the parameters state and OID.
func ParseAlgorithmIDParams(derBytes []byte) ParamsState {
	result := ParamsState{}

	input := cryptobyte.String(derBytes)

	var algoID cryptobyte.String
	if !input.ReadASN1(&algoID, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	var oid cryptobyte.String
	if !algoID.ReadASN1(&oid, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return result
	}

	// Convert OID to string representation
	result.OID = oidString(oid)

	if algoID.Empty() {
		result.IsAbsent = true
		return result
	}

	var params cryptobyte.String
	var paramsTag cryptobyte_asn1.Tag
	if !algoID.ReadAnyASN1Element(&params, &paramsTag) {
		return result
	}

	if paramsTag == cryptobyte_asn1.NULL {
		result.IsNull = true
		return result
	}

	// Parse RSASSA-PSS parameters (OID 1.2.840.113549.1.1.10)
	if result.OID == "1.2.840.113549.1.1.10" {
		result.PSS = parsePSSParams(params)
		return result
	}

	// Parse RSAES-OAEP parameters (OID 1.2.840.113549.1.1.7)
	if result.OID == "1.2.840.113549.1.1.7" {
		result.OAEP = parseOAEPParams(params)
		return result
	}

	return result
}

// parsePSSParams parses RSASSA-PSS-params from a SEQUENCE.
func parsePSSParams(params cryptobyte.String) *PSSParams {
	result := &PSSParams{
		HashAlgorithm:    AlgorithmIdentifier{OID: "1.3.14.3.2.26"}, // sha1 default
		MaskGenAlgorithm: AlgorithmIdentifier{OID: "1.2.840.113549.1.1.8", Params: ParamsState{OID: "1.3.14.3.2.26"}},
		SaltLength:       20,
		TrailerField:     1,
	}

	var seq cryptobyte.String
	if !params.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	// hashAlgorithm [0] EXPLICIT HashAlgorithm OPTIONAL
	if !seq.Empty() {
		var hashAlgo cryptobyte.String
		if seq.PeekASN1Tag(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			result.HashAlgorithmSet = true
			if !seq.ReadASN1(&hashAlgo, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
				return result
			}
			result.HashAlgorithm = parseNestedAlgorithmIdentifier(hashAlgo)
		}
	}

	// maskGenAlgorithm [1] EXPLICIT MaskGenAlgorithm OPTIONAL
	if !seq.Empty() {
		var mgfAlgo cryptobyte.String
		if seq.PeekASN1Tag(cryptobyte_asn1.Tag(1).Constructed().ContextSpecific()) {
			result.MaskGenAlgorithmSet = true
			if !seq.ReadASN1(&mgfAlgo, cryptobyte_asn1.Tag(1).Constructed().ContextSpecific()) {
				return result
			}
			result.MaskGenAlgorithm = parseNestedAlgorithmIdentifier(mgfAlgo)
		}
	}

	// saltLength [2] EXPLICIT INTEGER OPTIONAL
	if !seq.Empty() {
		var saltLen cryptobyte.String
		if seq.PeekASN1Tag(cryptobyte_asn1.Tag(2).Constructed().ContextSpecific()) {
			result.SaltLengthSet = true
			if !seq.ReadASN1(&saltLen, cryptobyte_asn1.Tag(2).Constructed().ContextSpecific()) {
				return result
			}
			if !saltLen.ReadASN1Integer(&result.SaltLength) {
				return result
			}
		}
	}

	// trailerField [3] EXPLICIT TrailerField OPTIONAL
	if !seq.Empty() {
		var trailer cryptobyte.String
		if seq.PeekASN1Tag(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) {
			result.TrailerFieldSet = true
			if !seq.ReadASN1(&trailer, cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) {
				return result
			}
			if !trailer.ReadASN1Integer(&result.TrailerField) {
				return result
			}
		}
	}

	return result
}

// parseOAEPParams parses RSAES-OAEP-params from a SEQUENCE.
func parseOAEPParams(params cryptobyte.String) *OAEPParams {
	result := &OAEPParams{
		HashAlgorithm:    AlgorithmIdentifier{OID: "1.3.14.3.2.26"}, // sha1 default
		MaskGenAlgorithm: AlgorithmIdentifier{OID: "1.2.840.113549.1.1.8", Params: ParamsState{OID: "1.3.14.3.2.26"}},
		PSourceAlgorithm: AlgorithmIdentifier{OID: "1.2.840.113549.1.1.9"}, // pSpecified with empty P
	}

	var seq cryptobyte.String
	if !params.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	// hashAlgorithm [0] EXPLICIT HashAlgorithm OPTIONAL
	if !seq.Empty() {
		var hashAlgo cryptobyte.String
		if seq.PeekASN1Tag(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			result.HashAlgorithmSet = true
			if !seq.ReadASN1(&hashAlgo, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
				return result
			}
			result.HashAlgorithm = parseNestedAlgorithmIdentifier(hashAlgo)
		}
	}

	// maskGenAlgorithm [1] EXPLICIT MaskGenAlgorithm OPTIONAL
	if !seq.Empty() {
		var mgfAlgo cryptobyte.String
		if seq.PeekASN1Tag(cryptobyte_asn1.Tag(1).Constructed().ContextSpecific()) {
			result.MaskGenAlgorithmSet = true
			if !seq.ReadASN1(&mgfAlgo, cryptobyte_asn1.Tag(1).Constructed().ContextSpecific()) {
				return result
			}
			result.MaskGenAlgorithm = parseNestedAlgorithmIdentifier(mgfAlgo)
		}
	}

	// pSourceAlgorithm [2] EXPLICIT PSourceAlgorithm OPTIONAL
	if !seq.Empty() {
		var pSource cryptobyte.String
		if seq.PeekASN1Tag(cryptobyte_asn1.Tag(2).Constructed().ContextSpecific()) {
			result.PSourceAlgorithmSet = true
			if !seq.ReadASN1(&pSource, cryptobyte_asn1.Tag(2).Constructed().ContextSpecific()) {
				return result
			}
			result.PSourceAlgorithm = parseNestedAlgorithmIdentifier(pSource)
		}
	}

	return result
}

// parseNestedAlgorithmIdentifier parses an AlgorithmIdentifier structure.
func parseNestedAlgorithmIdentifier(input cryptobyte.String) AlgorithmIdentifier {
	result := AlgorithmIdentifier{}

	var algoID cryptobyte.String
	if !input.ReadASN1(&algoID, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	var oid cryptobyte.String
	if !algoID.ReadASN1(&oid, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return result
	}

	result.OID = oidString(oid)

	if algoID.Empty() {
		result.Params.IsAbsent = true
		return result
	}

	var params cryptobyte.String
	var paramsTag cryptobyte_asn1.Tag
	if !algoID.ReadAnyASN1Element(&params, &paramsTag) {
		return result
	}

	if paramsTag == cryptobyte_asn1.NULL {
		result.Params.IsNull = true
		result.Params.OID = result.OID
		return result
	}

	// For MGF1, the parameter is another AlgorithmIdentifier (hash algorithm)
	if result.OID == "1.2.840.113549.1.1.8" { // id-mgf1
		result.Params = ParseAlgorithmIDParams(params)
	}

	return result
}

// oidString converts a cryptobyte OID to standard string format (e.g., "1.2.840.113549.1.1.11")
func oidString(oid cryptobyte.String) string {
	var components []int

	// First two components are encoded in first byte
	var first byte
	if !oid.ReadUint8(&first) {
		return ""
	}
	components = append(components, int(first/40), int(first%40))

	// Read remaining components (variable length encoding)
	for !oid.Empty() {
		var val int
		if !readOIDComponent(&oid, &val) {
			break
		}
		components = append(components, val)
	}

	// Build string representation
	result := ""
	for i, c := range components {
		if i > 0 {
			result += "."
		}
		result += intToStr(c)
	}
	return result
}

func readOIDComponent(oid *cryptobyte.String, val *int) bool {
	var v int
	for {
		var b byte
		if !oid.ReadUint8(&b) {
			return false
		}
		v = (v << 7) | int(b&0x7f)
		if b&0x80 == 0 {
			break
		}
	}
	*val = v
	return true
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	// Reverse digits
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}