package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// GenerateRSAKey returns a fresh RSA key. Valid sizes: 2048, 3072, 4096.
// 2048 is Certipy's default.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	switch bits {
	case 2048, 3072, 4096:
		// ok
	default:
		return nil, fmt.Errorf("pki: invalid RSA key size %d (want 2048/3072/4096)", bits)
	}
	return rsa.GenerateKey(rand.Reader, bits)
}
