package pki

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestPEMRoundTrip(t *testing.T) {
	orig := selfSignedCert(t)

	data, err := EncodePEM(orig)
	if err != nil {
		t.Fatalf("EncodePEM: %v", err)
	}
	if !bytes.Contains(data, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("EncodePEM output missing CERTIFICATE block")
	}
	if !bytes.Contains(data, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("EncodePEM output missing PRIVATE KEY block")
	}

	loaded, err := ParsePEM(data)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if loaded.Cert == nil {
		t.Fatal("ParsePEM returned nil Cert")
	}
	if loaded.Key == nil {
		t.Fatal("ParsePEM returned nil Key")
	}
	if got, want := loaded.Cert.Subject.CommonName, orig.Cert.Subject.CommonName; got != want {
		t.Fatalf("CommonName = %q, want %q", got, want)
	}
	if _, ok := loaded.Key.(*rsa.PrivateKey); !ok {
		t.Fatalf("Key type = %T, want *rsa.PrivateKey", loaded.Key)
	}
}

func TestParsePEMKeyOnly(t *testing.T) {
	orig := selfSignedCert(t)
	rsaKey, ok := orig.Key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("helper returned non-RSA key: %T", orig.Key)
	}

	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	loaded, err := ParsePEM(data)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if loaded.Cert != nil {
		t.Fatalf("ParsePEM returned non-nil Cert for key-only input")
	}
	if loaded.Key == nil {
		t.Fatal("ParsePEM returned nil Key for key-only input")
	}
}

func TestParsePEMIgnoresUnknownBlocks(t *testing.T) {
	orig := selfSignedCert(t)

	data, err := EncodePEM(orig)
	if err != nil {
		t.Fatalf("EncodePEM: %v", err)
	}

	// Prepend a bogus DH PARAMETERS block.
	bogus := pem.EncodeToMemory(&pem.Block{Type: "DH PARAMETERS", Bytes: []byte{0x01, 0x02, 0x03}})
	combined := append(bogus, data...)

	loaded, err := ParsePEM(combined)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if loaded.Cert == nil || loaded.Key == nil {
		t.Fatal("ParsePEM failed to pick up cert/key after DH PARAMETERS block")
	}
}

func TestParsePEMEmpty(t *testing.T) {
	if _, err := ParsePEM([]byte("garbage without any PEM blocks")); err == nil {
		t.Fatal("ParsePEM(garbage) returned nil error")
	}
}
