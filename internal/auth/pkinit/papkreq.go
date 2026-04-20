package pkinit

import (
	"encoding/asn1"
	"fmt"
)

// paPkAsReq is the on-wire PA-PK-AS-REQ structure from RFC 4556 §3.2.1:
//
//	PA-PK-AS-REQ ::= SEQUENCE {
//	    signedAuthPack          [0] IMPLICIT OCTET STRING,
//	    trustedCertifiers       [1] SEQUENCE OF TrustedCA OPTIONAL,
//	    kdcPkId                 [2] IMPLICIT OCTET STRING OPTIONAL
//	}
//
// We always emit signedAuthPack and leave the two optional fields absent -
// Active Directory KDCs do not require them for the typical client-cert flow
// and supplying them invites spurious "unknown trusted-CA" errors.
type paPkAsReq struct {
	SignedAuthPack    []byte        `asn1:"tag:0"`
	TrustedCertifiers asn1.RawValue `asn1:"optional,tag:1"`
	KDCPKID           []byte        `asn1:"optional,tag:2"`
}

// MarshalPAPKASReq wraps a CMS-SignedData-encoded AuthPack into the
// PA-PK-AS-REQ SEQUENCE that ends up as the pa-data value for
// PADATA-TYPE 16 (PA_PK_AS_REQ). signedAuthPack is the DER output of
// BuildSignedData with eContentType == OIDPKINITAuthData.
func MarshalPAPKASReq(signedAuthPack []byte) ([]byte, error) {
	if len(signedAuthPack) == 0 {
		return nil, fmt.Errorf("pkinit: MarshalPAPKASReq: empty signedAuthPack")
	}
	der, err := asn1.Marshal(paPkAsReq{SignedAuthPack: signedAuthPack})
	if err != nil {
		return nil, fmt.Errorf("pkinit: marshal PA-PK-AS-REQ: %w", err)
	}
	return der, nil
}

// UnmarshalPAPKASReq parses a PA-PK-AS-REQ blob and returns the embedded
// signedAuthPack OCTET STRING. The trustedCertifiers / kdcPkId fields are
// ignored.
func UnmarshalPAPKASReq(der []byte) ([]byte, error) {
	var v paPkAsReq
	if _, err := asn1.Unmarshal(der, &v); err != nil {
		return nil, fmt.Errorf("pkinit: unmarshal PA-PK-AS-REQ: %w", err)
	}
	return v.SignedAuthPack, nil
}

// dhRepInfo is the RFC 4556 §3.2.3.2 DHRepInfo SEQUENCE carried in
// PA-PK-AS-REP's dhInfo [0] alternative:
//
//	DHRepInfo ::= SEQUENCE {
//	    dhSignedData            [0] IMPLICIT OCTET STRING,
//	    serverDHNonce           [1] DHNonce OPTIONAL
//	}
//
// dhSignedData wraps a CMS SignedData whose eContent is a DER-encoded
// KDCDHKeyInfo carrying the KDC's DH public Y value.
type dhRepInfo struct {
	DHSignedData  []byte `asn1:"tag:0"`
	ServerDHNonce []byte `asn1:"explicit,optional,tag:1"`
}

// kdcDHKeyInfo is RFC 4556 §3.2.3.1 - the payload wrapped inside
// dhSignedData's eContent. SubjectPublicKey is the DH Y value encoded as an
// INTEGER then wrapped in a BIT STRING, matching the client's AuthPack.
type kdcDHKeyInfo struct {
	SubjectPublicKey asn1.BitString `asn1:"explicit,tag:0"`
	Nonce            int            `asn1:"explicit,tag:1"`
	DHKeyExpiration  asn1.RawValue  `asn1:"explicit,optional,tag:2"`
}

// PAPKASRepDHInfo extracts the inner SignedData bytes and server DH nonce
// from a PA-PK-AS-REP whose content is the dhInfo [0] alternative. The
// CHOICE outer tag is [0] so the caller passes just the inner SEQUENCE
// bytes (what ParseDHInfoFromPAData returns).
func PAPKASRepDHInfo(der []byte) (dhSignedData []byte, serverDHNonce []byte, err error) {
	var info dhRepInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, nil, fmt.Errorf("pkinit: unmarshal DHRepInfo: %w", err)
	}
	return info.DHSignedData, info.ServerDHNonce, nil
}

// ParsePAPKASRep parses a PA-PK-AS-REP blob and - for the dhInfo [0]
// alternative only - returns the inner dhSignedData bytes and the optional
// serverDHNonce. RFC 4556 §3.2.3 permits a second [1] encKeyPack variant
// that we do not use; callers encountering it receive a descriptive error.
func ParsePAPKASRep(der []byte) (dhSignedData, serverDHNonce []byte, err error) {
	// The outer PA-PK-AS-REP is a CHOICE, not a SEQUENCE. Peek the tag to
	// see which branch the KDC chose.
	var choice asn1.RawValue
	if _, err := asn1.Unmarshal(der, &choice); err != nil {
		return nil, nil, fmt.Errorf("pkinit: unmarshal PA-PK-AS-REP choice: %w", err)
	}
	if choice.Class != asn1.ClassContextSpecific {
		return nil, nil, fmt.Errorf("pkinit: PA-PK-AS-REP unexpected class %d tag %d", choice.Class, choice.Tag)
	}
	switch choice.Tag {
	case 0:
		return PAPKASRepDHInfo(choice.Bytes)
	case 1:
		return nil, nil, fmt.Errorf("pkinit: encKeyPack PA-PK-AS-REP variant is not supported; DH variant expected")
	default:
		return nil, nil, fmt.Errorf("pkinit: unknown PA-PK-AS-REP variant tag %d", choice.Tag)
	}
}

// ParseKDCDHKeyInfo reads the eContent of a PA-PK-AS-REP dhSignedData and
// returns the KDC's DH public value Y together with the nonce the KDC
// chained from the client's PKAuthenticator.
func ParseKDCDHKeyInfo(der []byte) (yBytes []byte, nonce int, err error) {
	var k kdcDHKeyInfo
	if _, err := asn1.Unmarshal(der, &k); err != nil {
		return nil, 0, fmt.Errorf("pkinit: unmarshal KDCDHKeyInfo: %w", err)
	}
	return k.SubjectPublicKey.Bytes, k.Nonce, nil
}
