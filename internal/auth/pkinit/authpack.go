package pkinit

import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// PKINIT ASN.1 schema (RFC 4556 §3.2.1). Go's encoding/asn1 cannot decode
// Kerberos GeneralizedTime with the "generalized" tag used by gokrb5's
// gofork package, so we roll our own minimal structs here and marshal them
// into the PA-PK-AS-REQ payload by hand.

// pkAuthenticator wraps the four time-and-identity fields that the KDC
// chains into the AS reply's nonce (RFC 4556 §3.2.1).
type pkAuthenticator struct {
	CUSec      int       `asn1:"explicit,tag:0"`
	CTime      time.Time `asn1:"generalized,explicit,tag:1"`
	Nonce      int32     `asn1:"explicit,tag:2"`
	PAChecksum []byte    `asn1:"explicit,optional,tag:3"`
}

// subjectPublicKeyInfo wraps the DH parameters + Y public value in the
// X.509 SubjectPublicKeyInfo format (RFC 5280 §4.1.2.7).
type subjectPublicKeyInfo struct {
	Algorithm        algorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// dhDomainParameters is PKCS#3 DHParameter (prime, base) wrapped into the
// SubjectPublicKeyInfo.Algorithm.Parameters slot. Q is omitted; Windows KDCs
// do not require it for the well-known MODP groups.
type dhDomainParameters struct {
	P *big.Int
	G *big.Int
}

// authPack is the RFC 4556 §3.2.1 AuthPack - exactly the payload wrapped in
// CMS SignedData and inserted into the PA-PK-AS-REQ.
type authPack struct {
	PKAuthenticator   pkAuthenticator       `asn1:"explicit,tag:0"`
	ClientPublicValue subjectPublicKeyInfo  `asn1:"explicit,optional,tag:1"`
	SupportedCMSTypes []algorithmIdentifier `asn1:"explicit,optional,tag:2"`
	ClientDHNonce     []byte                `asn1:"explicit,optional,tag:3"`
}

// BuildAuthPack serializes an AuthPack for a PA-PK-AS-REQ. paChecksum MUST
// be the SHA-1 digest computed over the DER-encoded KDC-REQ-BODY (RFC 4556
// §3.2.1 step 1). The returned clientDHNonce is 16 random bytes that the
// caller must persist - it is fed back into octetstring2key during AS-REP
// key derivation.
func BuildAuthPack(dh DHParams, dhPub *big.Int, paChecksum []byte, nonce int32) ([]byte, []byte, error) {
	if dh.P == nil || dh.G == nil {
		return nil, nil, fmt.Errorf("pkinit: BuildAuthPack: DH params missing")
	}
	if dhPub == nil {
		return nil, nil, fmt.Errorf("pkinit: BuildAuthPack: nil DH public")
	}

	// Encode the DH parameters - PKCS#3 DHParameter form (SEQUENCE { p, g }).
	paramsDER, err := asn1.Marshal(dhDomainParameters{P: dh.P, G: dh.G})
	if err != nil {
		return nil, nil, fmt.Errorf("pkinit: encode DH params: %w", err)
	}

	// Encode the public value as INTEGER (Y), then wrap into the BIT STRING
	// slot of SubjectPublicKeyInfo per RFC 4556 §3.2.1.
	yDER, err := asn1.Marshal(dhPub)
	if err != nil {
		return nil, nil, fmt.Errorf("pkinit: encode DH public: %w", err)
	}

	now := time.Now().UTC()
	cusec := int(now.Nanosecond()/1000) % 1_000_000
	dhNonce := make([]byte, 16)
	if _, err := rand.Read(dhNonce); err != nil {
		return nil, nil, fmt.Errorf("pkinit: gen client DH nonce: %w", err)
	}

	ap := authPack{
		PKAuthenticator: pkAuthenticator{
			CUSec:      cusec,
			CTime:      now.Truncate(time.Second),
			Nonce:      nonce,
			PAChecksum: paChecksum,
		},
		ClientPublicValue: subjectPublicKeyInfo{
			Algorithm: algorithmIdentifier{
				Algorithm: OIDDHKeyAgreement,
				Parameters: asn1.RawValue{
					FullBytes: paramsDER,
				},
			},
			SubjectPublicKey: asn1.BitString{
				Bytes:     yDER,
				BitLength: len(yDER) * 8,
			},
		},
		SupportedCMSTypes: []algorithmIdentifier{{
			Algorithm:  OIDRSASignatureSHA256,
			Parameters: nullRawValue,
		}},
		ClientDHNonce: dhNonce,
	}

	b, err := asn1.Marshal(ap)
	if err != nil {
		return nil, nil, fmt.Errorf("pkinit: marshal AuthPack: %w", err)
	}
	return b, dhNonce, nil
}
