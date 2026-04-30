package asn1

import (
	stdasn1 "encoding/asn1"
	"fmt"
	"strings"
	"time"
)

// TimeFormatInfo contains information about ASN.1 time encoding.
type TimeFormatInfo struct {
	Tag         int    // ASN.1 tag: 23 for UTCTime, 24 for GeneralizedTime
	Format      string // Time format string
	RawBytes    []byte // Raw DER bytes of the time value
	RawString   string // Raw string representation from DER
	IsUTC       bool   // true for UTCTime, false for GeneralizedTime
	HasSeconds  bool   // whether seconds are present
	HasFraction bool   // whether fractional seconds are present
	HasZulu     bool   // whether 'Z' suffix is present (required by RFC 5280)
}

// ParseUTCTime parses UTCTime DER bytes and returns format info.
// UTCTime format: YYMMDDHHMMSSZ (RFC 5280 requires Z suffix)
// Tag: 23 (0x17)
func ParseUTCTime(derBytes []byte) (*TimeFormatInfo, error) {
	info := &TimeFormatInfo{
		Tag:      23,
		IsUTC:    true,
		RawBytes: derBytes,
	}

	// Decode the raw string from DER
	// DER encoding: tag (1 byte) + length + value
	if len(derBytes) < 2 {
		return nil, fmt.Errorf("invalid UTCTime: too short")
	}

	tag := int(derBytes[0])
	if tag != 23 {
		return nil, fmt.Errorf("invalid UTCTime tag: expected 23, got %d", tag)
	}

	length := int(derBytes[1])
	if len(derBytes) < 2+length {
		return nil, fmt.Errorf("invalid UTCTime: length mismatch")
	}

	valueBytes := derBytes[2:2+length]
	info.RawString = string(valueBytes)

	// Parse format characteristics
	// Valid formats per RFC 5280:
	// - YYMMDDHHMMSSZ (13 chars, must have Z)
	// Seconds are required per RFC 5280 Section 4.1.2.5.1
	info.HasZulu = strings.HasSuffix(info.RawString, "Z")
	info.HasSeconds = len(info.RawString) >= 12 // YYMMDDHHMMSS has 12 chars before Z

	// Parse the actual time to validate
	var t time.Time
	// Go's asn1 package can parse UTCTime
	rest, err := stdasn1.UnmarshalWithParams(derBytes, &t, "utctime")
	if err != nil {
		return nil, fmt.Errorf("failed to parse UTCTime: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in UTCTime")
	}

	return info, nil
}

// ParseGeneralizedTime parses GeneralizedTime DER bytes and returns format info.
// GeneralizedTime format: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS.fffZ
// Tag: 24 (0x18)
func ParseGeneralizedTime(derBytes []byte) (*TimeFormatInfo, error) {
	info := &TimeFormatInfo{
		Tag:         24,
		IsUTC:       false,
		RawBytes:    derBytes,
		HasSeconds:  true, // GeneralizedTime always has seconds
	}

	// Decode the raw string from DER
	if len(derBytes) < 2 {
		return nil, fmt.Errorf("invalid GeneralizedTime: too short")
	}

	tag := int(derBytes[0])
	if tag != 24 {
		return nil, fmt.Errorf("invalid GeneralizedTime tag: expected 24, got %d", tag)
	}

	length := int(derBytes[1])
	if len(derBytes) < 2+length {
		return nil, fmt.Errorf("invalid GeneralizedTime: length mismatch")
	}

	valueBytes := derBytes[2:2+length]
	info.RawString = string(valueBytes)

	// Parse format characteristics
	info.HasZulu = strings.HasSuffix(info.RawString, "Z")
	info.HasFraction = strings.Contains(info.RawString, ".")

	// Parse the actual time to validate
	var t time.Time
	// Go's asn1 package can parse GeneralizedTime
	rest, err := stdasn1.UnmarshalWithParams(derBytes, &t, "generalized")
	if err != nil {
		return nil, fmt.Errorf("failed to parse GeneralizedTime: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in GeneralizedTime")
	}

	return info, nil
}

// EncodingType represents ASN.1 string encoding types.
type EncodingType int

const (
	EncodingUnknown EncodingType = iota
	EncodingIA5String
	EncodingPrintableString
	EncodingUTF8String
	EncodingBMPString
	EncodingUniversalString
)

// EncodingInfo contains information about ASN.1 string encoding.
type EncodingInfo struct {
	Type         EncodingType
	TagName      string
	RawBytes     []byte
	StringValue  string
	ValidChars   bool   // whether all characters are valid for the encoding type
	InvalidChars []byte // characters that violate encoding rules
}

// ValidateIA5String validates that a byte sequence conforms to IA5String encoding.
// IA5String is equivalent to ASCII (0x00-0x7F).
func ValidateIA5String(derBytes []byte) (*EncodingInfo, error) {
	info := &EncodingInfo{
		Type:        EncodingIA5String,
		TagName:     "IA5String",
		RawBytes:    derBytes,
		ValidChars:  true,
	}

	// DER encoding: tag (1 byte) + length + value
	if len(derBytes) < 2 {
		return nil, fmt.Errorf("invalid IA5String: too short")
	}

	tag := int(derBytes[0])
	if tag != 22 { // IA5String tag
		return nil, fmt.Errorf("invalid IA5String tag: expected 22, got %d", tag)
	}

	length := int(derBytes[1])
	if len(derBytes) < 2+length {
		return nil, fmt.Errorf("invalid IA5String: length mismatch")
	}

	valueBytes := derBytes[2:2+length]
	info.StringValue = string(valueBytes)

	// Check each character is in ASCII range (0x00-0x7F)
	for _, b := range valueBytes {
		if b > 0x7F {
			info.ValidChars = false
			info.InvalidChars = append(info.InvalidChars, b)
		}
	}

	return info, nil
}

// ValidatePrintableString validates that a byte sequence conforms to PrintableString encoding.
// PrintableString allows: A-Z, a-z, 0-9, space, '(),./:=?- and special chars
// Per RFC 5280 Appendix A.1: PrintableString character set
func ValidatePrintableString(derBytes []byte) (*EncodingInfo, error) {
	info := &EncodingInfo{
		Type:        EncodingPrintableString,
		TagName:     "PrintableString",
		RawBytes:    derBytes,
		ValidChars:  true,
	}

	// DER encoding: tag (1 byte) + length + value
	if len(derBytes) < 2 {
		return nil, fmt.Errorf("invalid PrintableString: too short")
	}

	tag := int(derBytes[0])
	if tag != 19 { // PrintableString tag
		return nil, fmt.Errorf("invalid PrintableString tag: expected 19, got %d", tag)
	}

	length := int(derBytes[1])
	if len(derBytes) < 2+length {
		return nil, fmt.Errorf("invalid PrintableString: length mismatch")
	}

	valueBytes := derBytes[2:2+length]
	info.StringValue = string(valueBytes)

	// PrintableString valid characters per ASN.1:
	// A-Z, a-z, 0-9, space, apostrophe, (, ), +, comma, -, ., /, :, =, ?
	for _, b := range valueBytes {
		if !isPrintableStringChar(b) {
			info.ValidChars = false
			info.InvalidChars = append(info.InvalidChars, b)
		}
	}

	return info, nil
}

// isPrintableStringChar checks if a byte is valid in PrintableString.
func isPrintableStringChar(b byte) bool {
	// Upper case letters
	if b >= 'A' && b <= 'Z' {
		return true
	}
	// Lower case letters
	if b >= 'a' && b <= 'z' {
		return true
	}
	// Digits
	if b >= '0' && b <= '9' {
		return true
	}
	// Special characters allowed in PrintableString
	switch b {
	case ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?', '&', '[', ']', '#', '@', '!', '"', '%', '*', ';', '<', '>', '_', '\\', '{', '}', '|', '~', '^':
		return true
	}
	return false
}

// GetEncodingType returns the encoding type from ASN.1 tag.
func GetEncodingType(tag int) EncodingType {
	switch tag {
	case 22:
		return EncodingIA5String
	case 19:
		return EncodingPrintableString
	case 12:
		return EncodingUTF8String
	case 30:
		return EncodingBMPString
	case 28:
		return EncodingUniversalString
	default:
		return EncodingUnknown
	}
}