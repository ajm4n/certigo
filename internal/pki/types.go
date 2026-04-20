package pki

import (
	"crypto"
	"crypto/x509"
)

// Certificate wraps an X.509 cert + matching private key. Key may be nil
// for public-only operations (e.g., parsing a cert chain). Chain holds
// any intermediate/root certs loaded alongside the primary cert.
type Certificate struct {
	Cert  *x509.Certificate
	Key   crypto.PrivateKey
	Chain []*x509.Certificate
}
