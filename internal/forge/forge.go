package forge

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ajm4n/certigo/internal/pki"
)

// Options controls certificate forging. A nil CA is invalid; an empty SID
// simply omits the NTDS-CA-Security-Ext extension.
type Options struct {
	CA           *pki.Certificate
	Subject      pkix.Name
	UPN          string
	DNSNames     []string
	SID          string
	SerialHex    string   // empty = random 16 bytes
	CRLs         []string // CRL distribution URLs
	TemplateOIDs []string
	ExtraExts    []pkix.Extension
	ValidityDays int // default 3650
	KeySize      int // default 2048
}

// Forge produces a new *pki.Certificate (cert + freshly-generated RSA key)
// signed by opts.CA. Caller saves via pki.SavePFX.
func Forge(opts Options) (*pki.Certificate, error) {
	if opts.CA == nil || opts.CA.Cert == nil || opts.CA.Key == nil {
		return nil, fmt.Errorf("forge: CA cert + key required")
	}
	keySize := opts.KeySize
	if keySize == 0 {
		keySize = 2048
	}
	validity := opts.ValidityDays
	if validity == 0 {
		validity = 3650
	}

	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("forge: key gen: %w", err)
	}

	serial, err := resolveSerial(opts.SerialHex)
	if err != nil {
		return nil, err
	}

	subject := opts.Subject
	if subject.CommonName == "" {
		subject.CommonName = opts.UPN
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Collect extensions.
	var exts []pkix.Extension
	if opts.UPN != "" || len(opts.DNSNames) > 0 {
		san, err := UPNSANExtension([]string{opts.UPN}, opts.DNSNames)
		if err != nil {
			return nil, err
		}
		if opts.UPN == "" {
			// DNS-only; use built-in SAN path.
			tmpl.DNSNames = opts.DNSNames
		} else {
			exts = append(exts, san)
		}
	}
	if opts.SID != "" {
		raw, err := NTDSCASecurityExt(opts.SID)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{
			Id:    []int{1, 3, 6, 1, 4, 1, 311, 25, 2},
			Value: raw,
		})
	}
	if len(opts.TemplateOIDs) > 0 {
		cp, err := CertificatePoliciesExt(opts.TemplateOIDs)
		if err != nil {
			return nil, err
		}
		exts = append(exts, cp)
	}
	if len(opts.CRLs) > 0 {
		cp, err := CRLDistributionExt(opts.CRLs)
		if err != nil {
			return nil, err
		}
		exts = append(exts, cp)
	}
	exts = append(exts, opts.ExtraExts...)
	tmpl.ExtraExtensions = exts

	caCert := opts.CA.Cert
	caKey, ok := opts.CA.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("forge: CA key must be *rsa.PrivateKey (got %T)", opts.CA.Key)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("forge: CreateCertificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("forge: parse: %w", err)
	}
	return &pki.Certificate{Cert: parsed, Key: key}, nil
}

// resolveSerial parses the hex flag into a big.Int, or returns a random
// 16-byte positive serial if the input is empty.
func resolveSerial(hexStr string) (*big.Int, error) {
	if hexStr == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("forge: serial rand: %w", err)
		}
		raw[0] &= 0x7f // clear sign bit for positive serial
		return new(big.Int).SetBytes(raw), nil
	}
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("forge: bad serial hex: %w", err)
	}
	return new(big.Int).SetBytes(raw), nil
}
