package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// NewCSRRequest describes a certificate signing request to be produced by
// BuildCSR. DNSNames and UPNs are both emitted inside a single
// subjectAltName extension (OID 2.5.29.17).
type NewCSRRequest struct {
	Subject            pkix.Name
	DNSNames           []string
	UPNs               []string // encoded as otherName 1.3.6.1.4.1.311.20.2.3
	ExtraExtensions    []pkix.Extension
	SignatureAlgorithm x509.SignatureAlgorithm
}

// oidUPN is the Microsoft otherName OID used for userPrincipalName values
// in the subjectAltName extension (MS-SPEC, RFC 4556 PKINIT reference).
var oidUPN = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

// oidExtensionSubjectAltName is 2.5.29.17 from RFC 5280.
var oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// BuildCSR builds a DER-encoded PKCS#10 CertificateRequest signed with the
// provided private key.
//
// If req contains UPNs, BuildCSR constructs a custom subjectAltName
// extension that bundles any DNSNames plus one otherName entry per UPN, and
// adds it via ExtraExtensions (rather than relying on
// x509.CertificateRequest.DNSNames) so that both names share a single SAN
// extension. If only DNSNames are supplied, the stdlib's native handling is
// used.
func BuildCSR(key crypto.PrivateKey, req NewCSRRequest) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("pki: BuildCSR requires a private key")
	}

	tmpl := &x509.CertificateRequest{
		Subject:            req.Subject,
		SignatureAlgorithm: req.SignatureAlgorithm,
		ExtraExtensions:    append([]pkix.Extension(nil), req.ExtraExtensions...),
	}

	if len(req.UPNs) == 0 {
		// Stdlib path: DNS names go via the typed field so x509 builds the
		// SAN extension automatically.
		tmpl.DNSNames = req.DNSNames
	} else {
		sanExt, err := buildSANExtension(req.DNSNames, req.UPNs)
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, sanExt)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CSR: %w", err)
	}
	return der, nil
}

// upnOtherName mirrors the AnotherName SEQUENCE from RFC 5280 with the UPN
// value carried as a [0] EXPLICIT UTF8String.
//
// Wire format per MS-ADTS (and what certipy emits):
//
//   AnotherName ::= SEQUENCE {
//     type-id  OBJECT IDENTIFIER,      -- 1.3.6.1.4.1.311.20.2.3
//     value    [0] EXPLICIT UTF8String -- "user@domain"
//   }
//
// Earlier Go code wrapped the UPN string in an inner SEQUENCE (upnValue)
// before the explicit tag, producing
//   AnotherName { OID, [0] EXPLICIT SEQUENCE { UTF8String } }
// which Windows / certipy refused to parse — `Subject Alternative Name`
// rendered as raw bytes and PKINIT failed with KRB-ERR-GENERIC because
// the KDC saw no parseable UPN identity. The string field carries the
// `utf8` ASN.1 tag directly so the encoded value is just the
// UTF8String, no inner SEQUENCE.
type upnOtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  string `asn1:"tag:0,explicit,utf8"`
}

// buildSANExtension returns a pkix.Extension holding a SEQUENCE of
// GeneralName entries for the supplied DNS names and UPN otherNames.
// RFC 5280 GeneralName tags: [2] dNSName (IMPLICIT IA5String),
// [0] otherName (IMPLICIT AnotherName).
func buildSANExtension(dnsNames, upns []string) (pkix.Extension, error) {
	var rawValues []asn1.RawValue

	for _, dns := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   2, // dNSName [2] IMPLICIT IA5String
			Bytes: []byte(dns),
		})
	}

	for _, upn := range upns {
		inner, err := asn1.Marshal(upnOtherName{
			TypeID: oidUPN,
			Value:  upn,
		})
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("pki: marshal UPN otherName: %w", err)
		}
		// asn1.Marshal produced a plain SEQUENCE. Replace the outer tag with
		// the context-specific [0] IMPLICIT (constructed) tag required for
		// otherName inside GeneralName.
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(inner, &raw); err != nil {
			return pkix.Extension{}, fmt.Errorf("pki: re-parse UPN otherName: %w", err)
		}
		raw.Class = asn1.ClassContextSpecific
		raw.Tag = 0 // otherName [0] IMPLICIT
		raw.IsCompound = true
		// Clear FullBytes so Marshal recomputes using the new tag/class.
		raw.FullBytes = nil
		rawValues = append(rawValues, raw)
	}

	extBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("pki: marshal SAN sequence: %w", err)
	}

	return pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: false,
		Value:    extBytes,
	}, nil
}
