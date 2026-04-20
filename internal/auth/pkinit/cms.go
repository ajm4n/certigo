package pkinit

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// CMS / PKCS#7 ASN.1 schema used for PKINIT (RFC 5652). We only implement
// the subset the KDC needs to see and return: a SignedData containing one
// signer, one certificate, and no CRLs.

// contentInfo is the outer RFC 5652 ContentInfo wrapper. ContentType is set
// to id-signedData; Content is the SignedData encoded as an ANY.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// signedData implements RFC 5652 §5.1 SignedData.
type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

// encapContentInfo is RFC 5652 §5.2 EncapsulatedContentInfo. The eContent
// field is encoded as an EXPLICIT [0] OCTET STRING so we carry the raw
// bytes.
type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

// algorithmIdentifier is RFC 5280 AlgorithmIdentifier. Parameters are
// optional and may be NULL or absent.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// issuerAndSerialNumber identifies the signer's certificate by (issuer DN,
// serial). For PKINIT we always reference the certificate we just included
// in the outer SignedData.
type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// signerInfo implements RFC 5652 §5.3 SignerInfo (CMS version, no attributes,
// no unsigned attributes).
type signerInfo struct {
	Version            int
	SID                issuerAndSerialNumber
	DigestAlgorithm    algorithmIdentifier
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
}

// nullRawValue is an ASN.1 NULL (05 00) used as Parameters in
// algorithmIdentifier slots where the algorithm takes no parameters.
var nullRawValue = asn1.RawValue{Tag: asn1.TagNull, Class: asn1.ClassUniversal, IsCompound: false, Bytes: nil, FullBytes: []byte{0x05, 0x00}}

// BuildSignedData wraps data into a CMS SignedData (RFC 5652) signed by
// signerKey, with signerCert embedded in the certificates field. We always
// use SHA-256 for both the digest and the RSA signature (PKCS#1 v1.5).
// eContentType is carried verbatim as the EncapsulatedContentInfo's OID -
// for PKINIT AuthPack payloads this is id-pkinit-authData.
func BuildSignedData(eContentType asn1.ObjectIdentifier, data []byte,
	signerCert *x509.Certificate, signerKey crypto.Signer) ([]byte, error) {
	if signerCert == nil {
		return nil, errors.New("pkinit: BuildSignedData requires a signer certificate")
	}
	if signerKey == nil {
		return nil, errors.New("pkinit: BuildSignedData requires a signer key")
	}

	// RFC 5652 §5.4: when eContentType is not id-data, the message digest
	// attribute is computed over the eContent octets. We sign the digest of
	// the encap content directly since we're emitting no signed attributes.
	digest := sha256.Sum256(data)
	sig, err := signerKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("pkinit: sign CMS content: %w", err)
	}

	// The certificates SET wraps a sequence of Certificate values; we need
	// to emit the raw DER cert with the SET-OF [0] IMPLICIT tag.
	certsBlob, err := buildCertificatesField(signerCert)
	if err != nil {
		return nil, err
	}

	// Parse the issuer DN as a raw ASN.1 value so we preserve its exact
	// encoding (DN comparison is bit-exact in CMS).
	var issuerRV asn1.RawValue
	if _, err := asn1.Unmarshal(signerCert.RawIssuer, &issuerRV); err != nil {
		return nil, fmt.Errorf("pkinit: parse signer issuer DN: %w", err)
	}

	sd := signedData{
		Version: 1,
		DigestAlgorithms: []algorithmIdentifier{{
			Algorithm:  OIDSHA256,
			Parameters: nullRawValue,
		}},
		EncapContentInfo: encapContentInfo{
			EContentType: eContentType,
			EContent:     data,
		},
		Certificates: certsBlob,
		SignerInfos: []signerInfo{{
			Version: 1,
			SID: issuerAndSerialNumber{
				Issuer:       issuerRV,
				SerialNumber: signerCert.SerialNumber,
			},
			DigestAlgorithm: algorithmIdentifier{
				Algorithm:  OIDSHA256,
				Parameters: nullRawValue,
			},
			SignatureAlgorithm: algorithmIdentifier{
				Algorithm:  OIDRSASignatureSHA256,
				Parameters: nullRawValue,
			},
			Signature: sig,
		}},
	}

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("pkinit: marshal SignedData: %w", err)
	}

	outer := contentInfo{
		ContentType: OIDCMSSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	}
	der, err := asn1.Marshal(outer)
	if err != nil {
		return nil, fmt.Errorf("pkinit: marshal ContentInfo: %w", err)
	}
	return der, nil
}

// buildCertificatesField returns the bytes that populate the
// certificates [0] IMPLICIT SET OF Certificate field in a SignedData. We
// only ever emit a single cert; encoding.asn1 does not natively support the
// implicit SET OF over a heterogeneous ANY, so we assemble the tag by hand.
func buildCertificatesField(cert *x509.Certificate) (asn1.RawValue, error) {
	// The cert's Raw field is already DER-encoded - concatenate them into
	// the SET body.
	body := append([]byte{}, cert.Raw...)
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      body,
	}, nil
}

// ParseSignedData reads a DER-encoded CMS SignedData blob, returning the
// inner eContent octets and the first embedded signer certificate. Signature
// verification is intentionally out of scope - callers that need to pin the
// KDC's CA should verify signerCert themselves.
func ParseSignedData(der []byte) (eContent []byte, signerCert *x509.Certificate, err error) {
	var outer contentInfo
	if _, err = asn1.Unmarshal(der, &outer); err != nil {
		return nil, nil, fmt.Errorf("pkinit: unmarshal ContentInfo: %w", err)
	}
	if !outer.ContentType.Equal(OIDCMSSignedData) {
		return nil, nil, fmt.Errorf("pkinit: expected id-signedData, got %v", outer.ContentType)
	}
	var sd signedData
	if _, err = asn1.Unmarshal(outer.Content.Bytes, &sd); err != nil {
		return nil, nil, fmt.Errorf("pkinit: unmarshal SignedData: %w", err)
	}

	eContent = sd.EncapContentInfo.EContent

	// The certificates field is a [0] IMPLICIT SET OF Certificate. Iterate
	// the body as a sequence of concatenated DER certificate bodies and
	// return the first one that parses as an X.509 certificate.
	raw := sd.Certificates.Bytes
	for len(raw) > 0 {
		var rv asn1.RawValue
		rest, perr := asn1.Unmarshal(raw, &rv)
		if perr != nil {
			return eContent, nil, fmt.Errorf("pkinit: scan SignedData cert: %w", perr)
		}
		if rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagSequence {
			c, perr := x509.ParseCertificate(rv.FullBytes)
			if perr == nil {
				signerCert = c
				break
			}
		}
		raw = rest
	}

	return eContent, signerCert, nil
}
