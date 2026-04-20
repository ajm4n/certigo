package certcmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ajm4n/certigo/internal/pki"
)

// selfSigned builds a minimal self-signed certificate with a fresh 2048-bit
// RSA key. It mirrors internal/pki's test helper since that helper is
// unexported.
func selfSigned(t *testing.T) *pki.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "certcmd-test",
			Organization: []string{"certigo"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return &pki.Certificate{Cert: cert, Key: key}
}

// writePFX saves a fresh self-signed cert as a PFX file in dir and returns
// the path plus the cert used so callers can assert roundtrip identity.
func writePFX(t *testing.T, dir, password string) (string, *pki.Certificate) {
	t.Helper()
	cert := selfSigned(t)
	data, err := pki.SavePFX(cert, password)
	if err != nil {
		t.Fatalf("SavePFX: %v", err)
	}
	path := filepath.Join(dir, "input.pfx")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write pfx: %v", err)
	}
	return path, cert
}

// writePEM saves a fresh self-signed cert as a PEM file in dir and returns
// the path.
func writePEM(t *testing.T, dir string) string {
	t.Helper()
	cert := selfSigned(t)
	data, err := pki.EncodePEM(cert)
	if err != nil {
		t.Fatalf("EncodePEM: %v", err)
	}
	path := filepath.Join(dir, "input.pem")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return path
}

func TestRun_PFXToPEM(t *testing.T) {
	dir := t.TempDir()
	pfxPath, _ := writePFX(t, dir, "hunter2")
	pemPath := filepath.Join(dir, "out.pem")

	err := Run(Options{
		PFXIn:         pfxPath,
		PFXInPassword: "hunter2",
		PEMOut:        pemPath,
		NoOut:         true,
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	out, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("output missing CERTIFICATE block:\n%s", s)
	}
	if !strings.Contains(s, "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("output missing PRIVATE KEY block:\n%s", s)
	}
}

func TestRun_PEMToPFX(t *testing.T) {
	dir := t.TempDir()
	pemPath := writePEM(t, dir)
	pfxPath := filepath.Join(dir, "out.pfx")

	err := Run(Options{
		PEMIn:          pemPath,
		PFXOut:         pfxPath,
		PFXOutPassword: "pw",
		NoOut:          true,
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	data, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	got, err := pki.LoadPFX(data, "pw")
	if err != nil {
		t.Fatalf("LoadPFX: %v", err)
	}
	if got.Cert == nil {
		t.Error("round-tripped PFX missing cert")
	}
	if got.Key == nil {
		t.Error("round-tripped PFX missing key")
	}
}

func TestRun_ExtractKey(t *testing.T) {
	dir := t.TempDir()
	pfxPath, _ := writePFX(t, dir, "")

	var buf bytes.Buffer
	err := Run(Options{
		PFXIn:      pfxPath,
		ExtractKey: true,
	}, &buf)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	s := buf.String()
	if !strings.Contains(s, "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("stdout missing PRIVATE KEY block:\n%s", s)
	}
	if strings.Contains(s, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("stdout unexpectedly contained CERTIFICATE block:\n%s", s)
	}
}

func TestRun_ExtractCert(t *testing.T) {
	dir := t.TempDir()
	pfxPath, _ := writePFX(t, dir, "")

	var buf bytes.Buffer
	err := Run(Options{
		PFXIn:       pfxPath,
		ExtractCert: true,
	}, &buf)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	s := buf.String()
	if !strings.Contains(s, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("stdout missing CERTIFICATE block:\n%s", s)
	}
	if strings.Contains(s, "PRIVATE KEY") {
		t.Errorf("stdout unexpectedly contained private key material:\n%s", s)
	}
}

func TestRun_MissingInput(t *testing.T) {
	err := Run(Options{}, nil)
	if err == nil {
		t.Fatal("expected error for missing input, got nil")
	}
	if !strings.Contains(err.Error(), "--pfx") && !strings.Contains(err.Error(), "--pem") {
		t.Errorf("error message should mention --pfx/--pem: %v", err)
	}
}

func TestRun_ExclusiveExtractFlags(t *testing.T) {
	dir := t.TempDir()
	pfxPath, _ := writePFX(t, dir, "")
	err := Run(Options{
		PFXIn:       pfxPath,
		ExtractKey:  true,
		ExtractCert: true,
	}, nil)
	if err == nil {
		t.Fatal("expected error for mutually exclusive flags")
	}
}
