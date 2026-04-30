package zcrypto

import (
	stdx509 "crypto/x509"

	zx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/node"
)

func ToStdCert(cert *zx509.Certificate) (*stdx509.Certificate, error) {
	if cert == nil {
		return nil, nil
	}
	return stdx509.ParseCertificate(cert.Raw)
}

func FromStdCert(cert *stdx509.Certificate) (*zx509.Certificate, error) {
	if cert == nil {
		return nil, nil
	}
	return zx509.ParseCertificate(cert.Raw)
}

func BuildPkixName(name string, pkixName pkix.Name) *node.Node {
	n := node.New(name, nil)

	if len(pkixName.Country) > 0 {
		n.Children["countryName"] = node.New("countryName", pkixName.Country[0])
	}
	if len(pkixName.Organization) > 0 {
		n.Children["organizationName"] = node.New("organizationName", pkixName.Organization[0])
	}
	if len(pkixName.OrganizationalUnit) > 0 {
		n.Children["organizationalUnitName"] = node.New("organizationalUnitName", pkixName.OrganizationalUnit[0])
	}
	if pkixName.CommonName != "" {
		n.Children["commonName"] = node.New("commonName", pkixName.CommonName)
	}
	if len(pkixName.Locality) > 0 {
		n.Children["localityName"] = node.New("localityName", pkixName.Locality[0])
	}
	if len(pkixName.Province) > 0 {
		n.Children["stateOrProvinceName"] = node.New("stateOrProvinceName", pkixName.Province[0])
	}
	if len(pkixName.StreetAddress) > 0 {
		n.Children["streetAddress"] = node.New("streetAddress", pkixName.StreetAddress[0])
	}
	if len(pkixName.PostalCode) > 0 {
		n.Children["postalCode"] = node.New("postalCode", pkixName.PostalCode[0])
	}
	if pkixName.SerialNumber != "" {
		n.Children["serialNumber"] = node.New("serialNumber", pkixName.SerialNumber)
	}
	if len(pkixName.OrganizationIDs) > 0 {
		n.Children["organizationIdentifier"] = node.New("organizationIdentifier", pkixName.OrganizationIDs[0])
	}

	// EV-specific fields
	if len(pkixName.JurisdictionCountry) > 0 {
		n.Children["jurisdictionCountryName"] = node.New("jurisdictionCountryName", pkixName.JurisdictionCountry[0])
	}
	if len(pkixName.JurisdictionProvince) > 0 {
		n.Children["jurisdictionStateOrProvinceName"] = node.New("jurisdictionStateOrProvinceName", pkixName.JurisdictionProvince[0])
	}
	if len(pkixName.JurisdictionLocality) > 0 {
		n.Children["jurisdictionLocalityName"] = node.New("jurisdictionLocalityName", pkixName.JurisdictionLocality[0])
	}

	// Parse additional attributes from Names (e.g., businessCategory)
	// OID 2.5.4.15 = businessCategory
	for _, atv := range pkixName.Names {
		if len(atv.Type) == 4 && atv.Type[0] == 2 && atv.Type[1] == 5 && atv.Type[2] == 4 {
			switch atv.Type[3] {
			case 15: // businessCategory (2.5.4.15)
				if val, ok := atv.Value.(string); ok {
					n.Children["businessCategory"] = node.New("businessCategory", val)
				}
			}
		}
	}

	return n
}

func BuildExtensions(extensions []pkix.Extension) *node.Node {
	n := node.New("extensions", nil)

	for _, ext := range extensions {
		extNode := node.New(ext.Id.String(), nil)
		extNode.Children["oid"] = node.New("oid", ext.Id.String())
		extNode.Children["critical"] = node.New("critical", ext.Critical)
		extNode.Children["value"] = node.New("value", ext.Value)
		n.Children[ext.Id.String()] = extNode
	}

	return n
}
