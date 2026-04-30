package operator

import (
	"fmt"

	"github.com/cavoq/PCL/internal/node"
)

// NoDuplicateAttributes checks that subject DN does not contain
// duplicate AttributeTypeAndValue instances per CABF BR 7.1.4.1
type NoDuplicateAttributes struct{}

func (NoDuplicateAttributes) Name() string { return "noDuplicateAttributes" }

func (NoDuplicateAttributes) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Subject DN attributes that must be unique (single instance)
	// Per CABF BR 7.1.4.1 and zlint implementation
	singleInstanceOIDs := map[string]string{
		"2.5.4.3":                  "commonName",
		"2.5.4.4":                  "surname",
		"2.5.4.5":                  "serialNumber",
		"2.5.4.6":                  "countryName",
		"2.5.4.7":                  "localityName",
		"2.5.4.8":                  "stateOrProvinceName",
		"2.5.4.10":                 "organizationName",
		"2.5.4.15":                 "businessCategory",
		"2.5.4.42":                 "givenName",
		"2.5.4.97":                 "organizationIdentifier",
		"1.3.6.1.4.1.311.60.2.1.1": "jurisdictionLocality",
		"1.3.6.1.4.1.311.60.2.1.2": "jurisdictionStateOrProvince",
		"1.3.6.1.4.1.311.60.2.1.3": "jurisdictionCountry",
	}

	// Attributes exempt from single-instance requirement
	// domainComponent and streetAddress can have multiple instances
	exemptOIDs := map[string]bool{
		"0.9.2342.19200300.100.1.25": true, // domainComponent (DC)
		"2.5.4.9":                   true, // streetAddress
		"2.5.4.11":                  true, // organizationalUnitName (deprecated but exempt)
	}

	// Check children of subject node for duplicates
	// Subject node structure: subject.commonName, subject.organizationName, etc.
	foundOIDs := make(map[string]int)

	for childName, child := range n.Children {
		// childName is the attribute name (e.g., "commonName", "organizationName")
		// Check if this attribute appears multiple times

		// Get OID from child if available
		oidNode := child.Children["oid"]
		var oid string
		if oidNode != nil && oidNode.Value != nil {
			oid = fmt.Sprintf("%v", oidNode.Value)
		}

		// If no OID from node, try to map name to OID
		if oid == "" {
			nameToOID := map[string]string{
				"commonName":              "2.5.4.3",
				"surname":                 "2.5.4.4",
				"serialNumber":            "2.5.4.5",
				"countryName":             "2.5.4.6",
				"localityName":            "2.5.4.7",
				"stateOrProvinceName":     "2.5.4.8",
				"organizationName":        "2.5.4.10",
				"businessCategory":        "2.5.4.15",
				"givenName":               "2.5.4.42",
				"organizationIdentifier":  "2.5.4.97",
			}
			oid = nameToOID[childName]
		}

		// Skip if no OID found
		if oid == "" {
			continue
		}

		// Skip exempt attributes
		if exemptOIDs[oid] {
			continue
		}

		// Only check single-instance OIDs
		if singleInstanceOIDs[oid] != "" {
			foundOIDs[oid]++
			if foundOIDs[oid] > 1 {
				return false, nil
			}
		}
	}

	return true, nil
}