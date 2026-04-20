package forge

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// Microsoft and PKIX extension OIDs used when forging AD CS certificates.
var (
	// OIDNTDSCASecurityExt is the Microsoft szOID_NTDS_CA_SECURITY_EXT,
	// used to bind a certificate to an AD SID. Required for modern Windows
	// AD CS (2022+) strong certificate binding enforcement.
	OIDNTDSCASecurityExt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2}

	// OIDNTDSObjectSID is the inner OID embedded inside the NTDS security
	// extension's AnotherName structure.
	OIDNTDSObjectSID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2, 1}

	// OIDUPNSAN is the Microsoft otherName OID for userPrincipalName
	// entries in a subjectAltName (RFC 4556 PKINIT / MS-WCCE).
	OIDUPNSAN = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

	// OIDExtSubjectAltName is 2.5.29.17 (RFC 5280).
	OIDExtSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

	// OIDExtCRLDistributionPoints is 2.5.29.31 (RFC 5280).
	OIDExtCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}

	// OIDExtCertificatePolicies is 2.5.29.32 (RFC 5280).
	OIDExtCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}

	// OIDExtExtendedKeyUsage is 2.5.29.37 (RFC 5280).
	OIDExtExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// ntdsInnerValue mirrors the [0] EXPLICIT OCTET STRING that wraps the SID
// ASCII bytes inside the AnotherName structure.
type ntdsInnerValue struct {
	SID []byte `asn1:"tag:0,explicit,octet"`
}

// ntdsAnotherName is the AnotherName SEQUENCE embedded as a [0] otherName
// GeneralName inside the extnValue SEQUENCE.
type ntdsAnotherName struct {
	TypeID asn1.ObjectIdentifier
	Value  ntdsInnerValue
}

// NTDSCASecurityExt returns the DER-encoded extension value for OID
// 1.3.6.1.4.1.311.25.2 binding the certificate to sid (an AD SID string,
// e.g. "S-1-5-21-1-2-3-500").
//
// The value is encoded as a GeneralNames SEQUENCE with a single [0] otherName
// entry whose AnotherName wraps the SID ASCII as an OCTET STRING:
//
//	SEQUENCE {                           -- GeneralNames
//	    [0] IMPLICIT {                   -- otherName (AnotherName)
//	        OID 1.3.6.1.4.1.311.25.2.1
//	        [0] EXPLICIT OCTET STRING <sid ascii>
//	    }
//	}
//
// This matches Certipy's certipy/commands/forge.py create_sid_extension().
func NTDSCASecurityExt(sid string) ([]byte, error) {
	if sid == "" {
		return nil, fmt.Errorf("forge: NTDSCASecurityExt: empty SID")
	}

	inner, err := asn1.Marshal(ntdsAnotherName{
		TypeID: OIDNTDSObjectSID,
		Value:  ntdsInnerValue{SID: []byte(sid)},
	})
	if err != nil {
		return nil, fmt.Errorf("forge: marshal NTDS AnotherName: %w", err)
	}

	// Re-tag the outer SEQUENCE as [0] IMPLICIT (otherName in GeneralName).
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(inner, &raw); err != nil {
		return nil, fmt.Errorf("forge: re-parse NTDS AnotherName: %w", err)
	}
	raw.Class = asn1.ClassContextSpecific
	raw.Tag = 0
	raw.IsCompound = true
	raw.FullBytes = nil

	// Wrap in outer GeneralNames SEQUENCE.
	return asn1.Marshal([]asn1.RawValue{raw})
}

// upnOtherName mirrors the AnotherName SEQUENCE from RFC 5280 with the UPN
// value wrapped in a [0] EXPLICIT tag (UTF8String).
type upnOtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  upnValue `asn1:"tag:0,explicit"`
}

type upnValue struct {
	UPN string `asn1:"utf8"`
}

// UPNSANExtension builds a SubjectAltName extension (OID 2.5.29.17) containing
// one otherName entry per upn (OID 1.3.6.1.4.1.311.20.2.3) plus any dnsNames.
// Returns an empty pkix.Extension (zero Id) when both slices are empty, so
// callers can skip when there is nothing to emit.
func UPNSANExtension(upns []string, dnsNames []string) (pkix.Extension, error) {
	if len(upns) == 0 && len(dnsNames) == 0 {
		return pkix.Extension{}, nil
	}

	var rawValues []asn1.RawValue

	for _, dns := range dnsNames {
		if dns == "" {
			continue
		}
		rawValues = append(rawValues, asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   2, // dNSName [2] IMPLICIT IA5String
			Bytes: []byte(dns),
		})
	}

	for _, upn := range upns {
		if upn == "" {
			continue
		}
		inner, err := asn1.Marshal(upnOtherName{
			TypeID: OIDUPNSAN,
			Value:  upnValue{UPN: upn},
		})
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("forge: marshal UPN otherName: %w", err)
		}
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(inner, &raw); err != nil {
			return pkix.Extension{}, fmt.Errorf("forge: re-parse UPN otherName: %w", err)
		}
		raw.Class = asn1.ClassContextSpecific
		raw.Tag = 0 // otherName [0] IMPLICIT
		raw.IsCompound = true
		raw.FullBytes = nil
		rawValues = append(rawValues, raw)
	}

	if len(rawValues) == 0 {
		return pkix.Extension{}, nil
	}

	extBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("forge: marshal SAN sequence: %w", err)
	}

	return pkix.Extension{
		Id:       OIDExtSubjectAltName,
		Critical: false,
		Value:    extBytes,
	}, nil
}

// policyInformation models the PolicyInformation SEQUENCE from RFC 5280.
// We omit the optional policyQualifiers field, matching Certipy's emission.
type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
}

// CertificatePoliciesExt builds a certificatePolicies extension (OID 2.5.29.32)
// with one policyIdentifier per supplied OID string, each with no qualifiers.
// Returns a zero-value Extension when templateOIDs is empty.
func CertificatePoliciesExt(templateOIDs []string) (pkix.Extension, error) {
	if len(templateOIDs) == 0 {
		return pkix.Extension{}, nil
	}

	policies := make([]policyInformation, 0, len(templateOIDs))
	for _, s := range templateOIDs {
		if s == "" {
			continue
		}
		oid, err := parseOID(s)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("forge: parse template OID %q: %w", s, err)
		}
		policies = append(policies, policyInformation{PolicyIdentifier: oid})
	}
	if len(policies) == 0 {
		return pkix.Extension{}, nil
	}

	der, err := asn1.Marshal(policies)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("forge: marshal certificatePolicies: %w", err)
	}
	return pkix.Extension{
		Id:       OIDExtCertificatePolicies,
		Critical: false,
		Value:    der,
	}, nil
}

// distributionPoint mirrors the RFC 5280 DistributionPoint SEQUENCE with only
// the distributionPoint field populated (fullName via URI GeneralName).
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
}

type distributionPointName struct {
	FullName []asn1.RawValue `asn1:"optional,tag:0"`
}

// CRLDistributionExt builds a cRLDistributionPoints extension (OID 2.5.29.31)
// with one DistributionPoint per URL, each of which carries a single URI-form
// GeneralName. Returns a zero-value Extension when urls is empty.
func CRLDistributionExt(urls []string) (pkix.Extension, error) {
	if len(urls) == 0 {
		return pkix.Extension{}, nil
	}

	points := make([]distributionPoint, 0, len(urls))
	for _, u := range urls {
		if u == "" {
			continue
		}
		points = append(points, distributionPoint{
			DistributionPoint: distributionPointName{
				FullName: []asn1.RawValue{{
					Class: asn1.ClassContextSpecific,
					Tag:   6, // uniformResourceIdentifier [6] IMPLICIT IA5String
					Bytes: []byte(u),
				}},
			},
		})
	}
	if len(points) == 0 {
		return pkix.Extension{}, nil
	}

	der, err := asn1.Marshal(points)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("forge: marshal CRL distribution points: %w", err)
	}
	return pkix.Extension{
		Id:       OIDExtCRLDistributionPoints,
		Critical: false,
		Value:    der,
	}, nil
}

// parseOID parses a dotted-decimal OID string (e.g. "1.3.6.1.4.1.311.21.8")
// into asn1.ObjectIdentifier.
func parseOID(s string) (asn1.ObjectIdentifier, error) {
	if s == "" {
		return nil, fmt.Errorf("empty OID")
	}
	var out asn1.ObjectIdentifier
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if start == i {
				return nil, fmt.Errorf("empty component at position %d", i)
			}
			var n int
			for j := start; j < i; j++ {
				c := s[j]
				if c < '0' || c > '9' {
					return nil, fmt.Errorf("invalid character %q", c)
				}
				n = n*10 + int(c-'0')
			}
			out = append(out, n)
			start = i + 1
		}
	}
	return out, nil
}
