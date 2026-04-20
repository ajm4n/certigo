package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParsePEM parses a PEM-encoded byte slice into a Certificate. It accepts any
// combination of CERTIFICATE blocks (leaf + chain) and a single private-key
// block in PKCS#1 ("RSA PRIVATE KEY"), PKCS#8 ("PRIVATE KEY"), or SEC1
// ("EC PRIVATE KEY") form. Unknown block types (for example "DH PARAMETERS")
// are skipped silently. An error is returned only when no certificate and no
// key were found.
func ParsePEM(data []byte) (*Certificate, error) {
	var certs []*x509.Certificate
	var key crypto.PrivateKey

	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pki: parse certificate block: %w", err)
			}
			certs = append(certs, c)
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pki: parse RSA private key: %w", err)
			}
			if key != nil {
				return nil, fmt.Errorf("pki: multiple private keys in PEM data")
			}
			key = k
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pki: parse PKCS#8 private key: %w", err)
			}
			if key != nil {
				return nil, fmt.Errorf("pki: multiple private keys in PEM data")
			}
			key = k
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pki: parse EC private key: %w", err)
			}
			if key != nil {
				return nil, fmt.Errorf("pki: multiple private keys in PEM data")
			}
			key = k
		default:
			// ignore unknown block types (e.g. DH PARAMETERS, CERTIFICATE REQUEST)
		}
	}

	if len(certs) == 0 && key == nil {
		return nil, fmt.Errorf("pki: PEM data contained no certificate or private key")
	}

	out := &Certificate{Key: key}
	if len(certs) > 0 {
		out.Cert = certs[0]
		if len(certs) > 1 {
			out.Chain = certs[1:]
		}
	}
	return out, nil
}

// EncodePEM renders a Certificate as PEM. Order: leaf CERTIFICATE, PRIVATE
// KEY (PKCS#8), then any chain CERTIFICATE blocks. Either the cert or the
// key may be nil, but not both.
func EncodePEM(c *Certificate) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("pki: EncodePEM requires non-nil Certificate")
	}
	if c.Cert == nil && c.Key == nil {
		return nil, fmt.Errorf("pki: EncodePEM requires at least a cert or key")
	}

	var buf bytes.Buffer

	if c.Cert != nil {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw}); err != nil {
			return nil, fmt.Errorf("pki: encode certificate: %w", err)
		}
	}

	if c.Key != nil {
		if !isSupportedKey(c.Key) {
			return nil, fmt.Errorf("pki: EncodePEM: unsupported key type %T", c.Key)
		}
		der, err := x509.MarshalPKCS8PrivateKey(c.Key)
		if err != nil {
			return nil, fmt.Errorf("pki: marshal PKCS#8 key: %w", err)
		}
		if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
			return nil, fmt.Errorf("pki: encode key: %w", err)
		}
	}

	for _, extra := range c.Chain {
		if extra == nil {
			continue
		}
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: extra.Raw}); err != nil {
			return nil, fmt.Errorf("pki: encode chain certificate: %w", err)
		}
	}

	return buf.Bytes(), nil
}

func isSupportedKey(k crypto.PrivateKey) bool {
	switch k.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return true
	default:
		return false
	}
}
