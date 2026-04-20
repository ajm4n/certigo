package pki

import "testing"

func TestPFXRoundTrip(t *testing.T) {
	orig := selfSignedCert(t)

	data, err := SavePFX(orig, "hunter2")
	if err != nil {
		t.Fatalf("SavePFX: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("SavePFX returned empty data")
	}

	loaded, err := LoadPFX(data, "hunter2")
	if err != nil {
		t.Fatalf("LoadPFX: %v", err)
	}
	if loaded.Cert == nil {
		t.Fatal("LoadPFX returned nil Cert")
	}
	if loaded.Key == nil {
		t.Fatal("LoadPFX returned nil Key")
	}
	if got, want := loaded.Cert.Subject.CommonName, orig.Cert.Subject.CommonName; got != want {
		t.Fatalf("CommonName = %q, want %q", got, want)
	}
}
