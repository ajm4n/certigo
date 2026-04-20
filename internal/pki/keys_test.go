package pki

import "testing"

func TestGenerateRSAKey_Valid(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKey(2048) returned error: %v", err)
	}
	if key == nil {
		t.Fatal("GenerateRSAKey(2048) returned nil key")
	}
	if got := key.N.BitLen(); got != 2048 {
		t.Fatalf("RSA key bit length = %d, want 2048", got)
	}
}

func TestGenerateRSAKey_Invalid(t *testing.T) {
	if _, err := GenerateRSAKey(1024); err == nil {
		t.Fatal("GenerateRSAKey(1024) returned nil error, want error")
	}
}
