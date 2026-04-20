package pki

import (
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// LoadPFX decodes a PFX/PKCS#12 blob into a Certificate. Password may be "".
// The first certificate in the blob is the leaf; any additional certificates
// populate Chain.
func LoadPFX(data []byte, password string) (*Certificate, error) {
	key, leaf, chain, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("pki: decode pfx: %w", err)
	}
	if leaf == nil {
		return nil, fmt.Errorf("pki: pfx contained no leaf certificate")
	}
	return &Certificate{
		Cert:  leaf,
		Key:   key,
		Chain: chain,
	}, nil
}

// SavePFX encodes a Certificate as a PFX/PKCS#12 blob. It uses go-pkcs12's
// Modern2023 encoder, which emits AES-256 + SHA-256 output compatible with
// current Windows/OpenSSL stacks. Impacket's pyOpenSSL-based reader also
// handles this format; if a target tool ever rejects it, swap to
// pkcs12.Legacy.Encode for RC2 + 3DES output.
func SavePFX(c *Certificate, password string) ([]byte, error) {
	if c == nil || c.Cert == nil {
		return nil, fmt.Errorf("pki: SavePFX requires a certificate")
	}
	data, err := pkcs12.Modern2023.Encode(c.Key, c.Cert, c.Chain, password)
	if err != nil {
		return nil, fmt.Errorf("pki: encode pfx: %w", err)
	}
	return data, nil
}
