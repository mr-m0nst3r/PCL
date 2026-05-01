package zcrypto

import (
	"fmt"
	"strings"

	"github.com/cavoq/PCL/internal/node"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// AIA OID: 1.3.6.1.5.5.7.1.1
const aiaOID = "1.3.6.1.5.5.7.1.1"

// CRL Distribution Points OID: 2.5.29.31
const crlDPOID = "2.5.29.31"

// ParseAIA parses the Authority Information Access extension (OID 1.3.6.1.5.5.7.1.1)
// and returns a node tree with accessDescriptions.
//
// ASN.1 structure (RFC 5280 4.2.2.1):
//   AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
//   AccessDescription ::= SEQUENCE {
//       accessMethod    OBJECT IDENTIFIER,
//       accessLocation  GeneralName }
//
// GeneralName context-specific tags:
//   0: otherName, 1: rfc822Name, 2: dNSName, 3: x400Address,
//   4: directoryName, 5: ediPartyName, 6: uniformResourceIdentifier,
//   7: iPAddress, 8: registeredID
func ParseAIA(extValue []byte) *node.Node {
	n := node.New("authorityInfoAccess", nil)
	accessDescriptionsNode := node.New("accessDescriptions", nil)
	n.Children["accessDescriptions"] = accessDescriptionsNode

	input := cryptobyte.String(extValue)

	var ads cryptobyte.String
	if !input.ReadASN1(&ads, cryptobyte_asn1.SEQUENCE) {
		return n
	}

	// Empty AIA is invalid per BR
	if len(ads) == 0 {
		n.Children["empty"] = node.New("empty", true)
		return n
	}

	n.Children["empty"] = node.New("empty", false)

	idx := 0
	for len(ads) > 0 {
		var ad cryptobyte.String
		if !ads.ReadASN1(&ad, cryptobyte_asn1.SEQUENCE) {
			break
		}

		adNode := node.New(fmt.Sprintf("%d", idx), nil)

		// Read accessMethod (OID)
		var accessMethod cryptobyte.String
		if !ad.ReadASN1(&accessMethod, cryptobyte_asn1.OBJECT_IDENTIFIER) {
			break
		}
		methodOID := oidString(accessMethod)
		adNode.Children["accessMethod"] = node.New("accessMethod", methodOID)

		// Read accessLocation (GeneralName - context-specific tagged)
		var location cryptobyte.String
		var locationTag cryptobyte_asn1.Tag
		if !ad.ReadAnyASN1(&location, &locationTag) {
			break
		}

		locationNode := node.New("accessLocation", nil)
		contextTag := int(locationTag & 0x1F)
		locationType := generalNameType(contextTag)
		locationNode.Children["type"] = node.New("type", locationType)
		locationNode.Children["tag"] = node.New("tag", contextTag)

		// For URI (tag 6), extract the URI string
		if contextTag == 6 {
			uri := string(location)
			locationNode.Children["value"] = node.New("value", uri)
			// Extract scheme for convenience
			if strings.Contains(uri, ":") {
				scheme := strings.Split(uri, ":")[0]
				locationNode.Children["scheme"] = node.New("scheme", scheme)
			}
		} else if contextTag == 2 {
			// DNS name
			locationNode.Children["value"] = node.New("value", string(location))
		} else if contextTag == 7 {
			// IP address - 4 bytes for IPv4, 16 bytes for IPv6
			if len(location) == 4 || len(location) == 16 {
				locationNode.Children["value"] = node.New("value", location)
			}
		} else {
			// Other types - store raw bytes
			locationNode.Children["value"] = node.New("value", location)
		}

		adNode.Children["accessLocation"] = locationNode
		accessDescriptionsNode.Children[fmt.Sprintf("%d", idx)] = adNode
		idx++
	}

	n.Children["count"] = node.New("count", idx)

	// Convenience: check if contains OCSP and/or CA Issuers
	hasOCSP := false
	hasCaIssuers := false
	for i := 0; i < idx; i++ {
		if adNode, ok := accessDescriptionsNode.Children[fmt.Sprintf("%d", i)]; ok {
			if methodNode, ok := adNode.Children["accessMethod"]; ok {
				method := methodNode.Value.(string)
				if method == "1.3.6.1.5.5.7.48.1" { // id-ad-ocsp
					hasOCSP = true
				}
				if method == "1.3.6.1.5.5.7.48.2" { // id-ad-caIssuers
					hasCaIssuers = true
				}
			}
		}
	}
	n.Children["containsOCSP"] = node.New("containsOCSP", hasOCSP)
	n.Children["containsCaIssuers"] = node.New("containsCaIssuers", hasCaIssuers)

	return n
}

// ParseCRLDP parses the CRL Distribution Points extension (OID 2.5.29.31)
// and returns a node tree with distributionPoints.
//
// ASN.1 structure (RFC 5280 4.2.1.13):
//   CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
//   DistributionPoint ::= SEQUENCE {
//       distributionPoint [0] DistributionPointName OPTIONAL,
//       reasons           [1] ReasonFlags OPTIONAL,
//       cRLIssuer         [2] GeneralNames OPTIONAL }
//   DistributionPointName ::= CHOICE {
//       fullName [0] GeneralNames,
//       nameRelativeToCRLIssuer [1] RelativeDistinguishedName }
func ParseCRLDP(extValue []byte) *node.Node {
	n := node.New("cRLDistributionPoints", nil)
	distributionPointsNode := node.New("distributionPoints", nil)
	n.Children["distributionPoints"] = distributionPointsNode

	input := cryptobyte.String(extValue)

	var dps cryptobyte.String
	if !input.ReadASN1(&dps, cryptobyte_asn1.SEQUENCE) {
		return n
	}

	// Empty CRL DP is invalid per BR
	if len(dps) == 0 {
		n.Children["empty"] = node.New("empty", true)
		return n
	}

	n.Children["empty"] = node.New("empty", false)

	idx := 0
	for len(dps) > 0 {
		var dp cryptobyte.String
		if !dps.ReadASN1(&dp, cryptobyte_asn1.SEQUENCE) {
			break
		}

		dpNode := node.New(fmt.Sprintf("%d", idx), nil)

		// Parse DistributionPoint fields
		// [0] distributionPoint, [1] reasons, [2] cRLIssuer
		hasFullName := false
		hasReasons := false
		hasCRLIssuer := false

		for len(dp) > 0 {
			var field cryptobyte.String
			var tag cryptobyte_asn1.Tag
			if !dp.ReadAnyASN1(&field, &tag) {
				break
			}

			contextTag := int(tag & 0x1F)

			switch contextTag {
			case 0: // distributionPoint [0]
				dpNameNode := node.New("distributionPoint", nil)
				// Check if fullName [0] or nameRelativeToCRLIssuer [1]
				var inner cryptobyte.String
				var innerTag cryptobyte_asn1.Tag
				if field.ReadAnyASN1(&inner, &innerTag) {
					innerTagNum := int(innerTag & 0x1F)
					if innerTagNum == 0 {
						// fullName [0] GeneralNames
						fullNameNode := node.New("fullName", nil)
						generalNamesNode := node.New("generalNames", nil)
						uriIdx := 0
						for len(inner) > 0 {
							var name cryptobyte.String
							var nameTag cryptobyte_asn1.Tag
							if !inner.ReadAnyASN1(&name, &nameTag) {
								break
							}
							nameTagNum := int(nameTag & 0x1F)
							gnNode := node.New(fmt.Sprintf("%d", uriIdx), nil)
							gnNode.Children["type"] = node.New("type", generalNameType(nameTagNum))
							gnNode.Children["tag"] = node.New("tag", nameTagNum)
							if nameTagNum == 6 {
								uri := string(name)
								gnNode.Children["value"] = node.New("value", uri)
								if strings.Contains(uri, ":") {
									scheme := strings.Split(uri, ":")[0]
									gnNode.Children["scheme"] = node.New("scheme", scheme)
								}
							} else {
								gnNode.Children["value"] = node.New("value", name)
							}
							generalNamesNode.Children[fmt.Sprintf("%d", uriIdx)] = gnNode
							uriIdx++
							hasFullName = true
						}
						fullNameNode.Children["generalNames"] = generalNamesNode
						fullNameNode.Children["count"] = node.New("count", uriIdx)
						dpNameNode.Children["fullName"] = fullNameNode
					} else if innerTagNum == 1 {
						// nameRelativeToCRLIssuer [1]
						dpNameNode.Children["nameRelativeToCRLIssuer"] = node.New("nameRelativeToCRLIssuer", field)
					}
				}
				dpNode.Children["distributionPoint"] = dpNameNode

			case 1: // reasons [1] ReasonFlags
				reasonsNode := node.New("reasons", nil)
				reasonsNode.Children["present"] = node.New("present", true)
				reasonsNode.Children["raw"] = node.New("raw", field)
				// ReasonFlags is BIT STRING - parse the bits
				if len(field) >= 2 {
					unusedBits := int(field[0])
					reasonsNode.Children["unusedBits"] = node.New("unusedBits", unusedBits)
					if len(field) > 1 {
						reasonsBytes := field[1:]
						reasonsNode.Children["value"] = node.New("value", reasonsBytes)
						// Decode individual reasons (bits 0-9)
						decodeReasonFlags(reasonsNode, reasonsBytes, unusedBits)
					}
				}
				dpNode.Children["reasons"] = reasonsNode
				hasReasons = true

			case 2: // cRLIssuer [2] GeneralNames
				crlIssuerNode := node.New("cRLIssuer", nil)
				crlIssuerNode.Children["present"] = node.New("present", true)
				gnIdx := 0
				for len(field) > 0 {
					var name cryptobyte.String
					var nameTag cryptobyte_asn1.Tag
					if !field.ReadAnyASN1(&name, &nameTag) {
						break
					}
					nameTagNum := int(nameTag & 0x1F)
					gnNode := node.New(fmt.Sprintf("%d", gnIdx), nil)
					gnNode.Children["type"] = node.New("type", generalNameType(nameTagNum))
					gnNode.Children["tag"] = node.New("tag", nameTagNum)
					gnNode.Children["value"] = node.New("value", name)
					crlIssuerNode.Children[fmt.Sprintf("%d", gnIdx)] = gnNode
					gnIdx++
				}
				crlIssuerNode.Children["count"] = node.New("count", gnIdx)
				dpNode.Children["cRLIssuer"] = crlIssuerNode
				hasCRLIssuer = true
			}
		}

		// Mark presence/absence of optional fields
		dpNode.Children["hasFullName"] = node.New("hasFullName", hasFullName)
		dpNode.Children["hasReasons"] = node.New("hasReasons", hasReasons)
		dpNode.Children["hasCRLIssuer"] = node.New("hasCRLIssuer", hasCRLIssuer)

		distributionPointsNode.Children[fmt.Sprintf("%d", idx)] = dpNode
		idx++
	}

	n.Children["count"] = node.New("count", idx)

	return n
}

// generalNameType returns the GeneralName type string for a context-specific tag number
func generalNameType(tag int) string {
	switch tag {
	case 0:
		return "otherName"
	case 1:
		return "rfc822Name"
	case 2:
		return "dNSName"
	case 3:
		return "x400Address"
	case 4:
		return "directoryName"
	case 5:
		return "ediPartyName"
	case 6:
		return "uniformResourceIdentifier"
	case 7:
		return "iPAddress"
	case 8:
		return "registeredID"
	default:
		return "unknown"
	}
}

// decodeReasonFlags decodes the CRL revocation reason flags
// Bits: 0=unused, 1=keyCompromise, 2=cACompromise, 3=affiliationChanged,
// 4=superseded, 5=cessationOfOperation, 6=certificateHold,
// 8=removeFromCRL, 9=privilegeWithdrawn, 10=aACompromise
func decodeReasonFlags(n *node.Node, bytes []byte, unusedBits int) {
	reasonNames := []string{
		"unused",           // bit 0
		"keyCompromise",    // bit 1
		"cACompromise",     // bit 2
		"affiliationChanged", // bit 3
		"superseded",       // bit 4
		"cessationOfOperation", // bit 5
		"certificateHold",  // bit 6
		"",                 // bit 7 (unused)
		"removeFromCRL",    // bit 8
		"privilegeWithdrawn", // bit 9
		"aACompromise",     // bit 10
	}

	for bit := 0; bit < len(reasonNames) && bit < len(bytes)*8-unusedBits; bit++ {
		if reasonNames[bit] == "" {
			continue
		}
		byteIdx := bit / 8
		bitIdx := 7 - (bit % 8)
		if byteIdx < len(bytes) && (bytes[byteIdx]&(1<<bitIdx)) != 0 {
			n.Children[reasonNames[bit]] = node.New(reasonNames[bit], true)
		}
	}
}