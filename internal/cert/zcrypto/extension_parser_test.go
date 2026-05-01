package zcrypto

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Helper to build valid AIA extension value
func buildAIAValue(ocspURI, caIssuersURI string) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// AccessDescription for OCSP
		if ocspURI != "" {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// accessMethod: id-ad-ocsp (1.3.6.1.5.5.7.48.1)
				b.AddASN1(cryptobyte_asn1.OBJECT_IDENTIFIER, func(b *cryptobyte.Builder) {
					b.AddBytes([]byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01})
				})
				// accessLocation: uniformResourceIdentifier (context tag 6)
				b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(ocspURI))
				})
			})
		}
		// AccessDescription for CA Issuers
		if caIssuersURI != "" {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// accessMethod: id-ad-caIssuers (1.3.6.1.5.5.7.48.2)
				b.AddASN1(cryptobyte_asn1.OBJECT_IDENTIFIER, func(b *cryptobyte.Builder) {
					b.AddBytes([]byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02})
				})
				// accessLocation: uniformResourceIdentifier (context tag 6)
				b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(caIssuersURI))
				})
			})
		}
	})
	return b.BytesOrPanic()
}

// Helper to build AIA with non-URI GeneralName (DNS name, tag 2)
func buildAIAWithDNSName() []byte {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// accessMethod: id-ad-ocsp
			b.AddASN1(cryptobyte_asn1.OBJECT_IDENTIFIER, func(b *cryptobyte.Builder) {
				b.AddBytes([]byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01})
			})
			// accessLocation: dNSName (context tag 2)
			b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes([]byte("ocsp.example.com"))
			})
		})
	})
	return b.BytesOrPanic()
}

func TestParseAIA(t *testing.T) {
	tests := []struct {
		name       string
		extValue   []byte
		checkFunc  func(*node.Node) bool
		expected   bool
	}{
		{
			name:     "valid AIA with HTTP OCSP and CA Issuers",
			extValue: buildAIAValue("http://ocsp.example.com", "http://ca.example.com/cert.der"),
			checkFunc: func(n *node.Node) bool {
				// Check count
				if countNode, ok := n.Children["count"]; ok {
					if countNode.Value.(int) != 2 {
						return false
					}
				}
				// Check first accessDescription (OCSP)
				ad0, ok := n.Children["accessDescriptions"].Children["0"]
				if !ok {
					return false
				}
				// Check accessMethod
				method, ok := ad0.Children["accessMethod"]
				if !ok || method.Value.(string) != "1.3.6.1.5.5.7.48.1" {
					return false
				}
				// Check accessLocation type is URI
				loc, ok := ad0.Children["accessLocation"]
				if !ok {
					return false
				}
				locType, ok := loc.Children["type"]
				if !ok || locType.Value.(string) != "uniformResourceIdentifier" {
					return false
				}
				locTag, ok := loc.Children["tag"]
				if !ok || locTag.Value.(int) != 6 {
					return false
				}
				scheme, ok := loc.Children["scheme"]
				if !ok || scheme.Value.(string) != "http" {
					return false
				}
				return true
			},
			expected: true,
		},
		{
			name:     "AIA with DNS name instead of URI",
			extValue: buildAIAWithDNSName(),
			checkFunc: func(n *node.Node) bool {
				ad0, ok := n.Children["accessDescriptions"].Children["0"]
				if !ok {
					return false
				}
				loc, ok := ad0.Children["accessLocation"]
				if !ok {
					return false
				}
				locType, ok := loc.Children["type"]
				if !ok {
					return false
				}
				// Should be dNSName, not uniformResourceIdentifier
				return locType.Value.(string) == "dNSName"
			},
			expected: true,
		},
		{
			name:     "empty AIA",
			extValue: buildAIAValue("", ""),
			checkFunc: func(n *node.Node) bool {
				empty, ok := n.Children["empty"]
				if !ok {
					return false
				}
				return empty.Value.(bool) == true
			},
			expected: true,
		},
		{
			name:     "contains OCSP check",
			extValue: buildAIAValue("http://ocsp.example.com", ""),
			checkFunc: func(n *node.Node) bool {
				hasOCSP, ok := n.Children["containsOCSP"]
				if !ok {
					return false
				}
				return hasOCSP.Value.(bool) == true
			},
			expected: true,
		},
		{
			name:     "contains CA Issuers check",
			extValue: buildAIAValue("", "http://ca.example.com"),
			checkFunc: func(n *node.Node) bool {
				hasCaIssuers, ok := n.Children["containsCaIssuers"]
				if !ok {
					return false
				}
				return hasCaIssuers.Value.(bool) == true
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := ParseAIA(tt.extValue)
			if n == nil {
				t.Fatalf("ParseAIA returned nil")
			}
			got := tt.checkFunc(n)
			if got != tt.expected {
				t.Errorf("check failed: got %v, want %v", got, tt.expected)
			}
		})
	}
}

// Helper to build valid CRL DP extension value
func buildCRLDPValue(uris []string) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, uri := range uris {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// distributionPoint [0] DistributionPointName
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					// fullName [0] GeneralNames
					b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						// GeneralName [6] IA5String (URI)
						b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(uri))
						})
					})
				})
			})
		}
	})
	return b.BytesOrPanic()
}

// Helper to build CRL DP with reasons field
func buildCRLDPWithReasons() []byte {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// distributionPoint [0]
			b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte("http://crl.example.com"))
					})
				})
			})
			// reasons [1] BIT STRING
			b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes([]byte{0x03, 0x01, 0x80}) // BIT STRING with unused bits = 1
			})
		})
	})
	return b.BytesOrPanic()
}

// Helper to build CRL DP with cRLIssuer field
func buildCRLDPWithCRLIssuer() []byte {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// distributionPoint [0]
			b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte("http://crl.example.com"))
					})
				})
			})
			// cRLIssuer [2] GeneralNames
			b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					// directoryName [4] Name
					b.AddASN1(cryptobyte_asn1.Tag(4).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {}) // Empty Name
					})
				})
			})
		})
	})
	return b.BytesOrPanic()
}

func TestParseCRLDP(t *testing.T) {
	tests := []struct {
		name       string
		extValue   []byte
		checkFunc  func(*node.Node) bool
		expected   bool
	}{
		{
			name:     "valid CRL DP with HTTP URI",
			extValue: buildCRLDPValue([]string{"http://crl.example.com/ca.crl"}),
			checkFunc: func(n *node.Node) bool {
				// Check not empty
				empty, ok := n.Children["empty"]
				if ok && empty.Value.(bool) {
					return false
				}
				// Check first distributionPoint
				dp0, ok := n.Children["distributionPoints"].Children["0"]
				if !ok {
					return false
				}
				// Check hasFullName
				hasFullName, ok := dp0.Children["hasFullName"]
				if !ok || !hasFullName.Value.(bool) {
					return false
				}
				// Check no reasons
				hasReasons, ok := dp0.Children["hasReasons"]
				if ok && hasReasons.Value.(bool) {
					return false
				}
				// Check no cRLIssuer
				hasCRLIssuer, ok := dp0.Children["hasCRLIssuer"]
				if ok && hasCRLIssuer.Value.(bool) {
					return false
				}
				// Check URI type
				dp, ok := dp0.Children["distributionPoint"]
				if !ok {
					return false
				}
				fullName, ok := dp.Children["fullName"]
				if !ok {
					return false
				}
				gn0, ok := fullName.Children["generalNames"].Children["0"]
				if !ok {
					return false
				}
				gnType, ok := gn0.Children["type"]
				if !ok || gnType.Value.(string) != "uniformResourceIdentifier" {
					return false
				}
				scheme, ok := gn0.Children["scheme"]
				if !ok || scheme.Value.(string) != "http" {
					return false
				}
				return true
			},
			expected: true,
		},
		{
			name:     "CRL DP with reasons field",
			extValue: buildCRLDPWithReasons(),
			checkFunc: func(n *node.Node) bool {
				dp0, ok := n.Children["distributionPoints"].Children["0"]
				if !ok {
					return false
				}
				hasReasons, ok := dp0.Children["hasReasons"]
				if !ok {
					return false
				}
				return hasReasons.Value.(bool) == true
			},
			expected: true,
		},
		{
			name:     "CRL DP with cRLIssuer field",
			extValue: buildCRLDPWithCRLIssuer(),
			checkFunc: func(n *node.Node) bool {
				dp0, ok := n.Children["distributionPoints"].Children["0"]
				if !ok {
					return false
				}
				hasCRLIssuer, ok := dp0.Children["hasCRLIssuer"]
				if !ok {
					return false
				}
				return hasCRLIssuer.Value.(bool) == true
			},
			expected: true,
		},
		{
			name: "empty CRL DP",
			extValue: func() []byte {
				var b cryptobyte.Builder
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {})
				return b.BytesOrPanic()
			}(),
			checkFunc: func(n *node.Node) bool {
				empty, ok := n.Children["empty"]
				if !ok {
					return false
				}
				return empty.Value.(bool) == true
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := ParseCRLDP(tt.extValue)
			if n == nil {
				t.Fatalf("ParseCRLDP returned nil")
			}
			got := tt.checkFunc(n)
			if got != tt.expected {
				t.Errorf("check failed: got %v, want %v", got, tt.expected)
			}
		})
	}
}