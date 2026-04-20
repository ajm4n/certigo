package shadow

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestBcryptRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	blob := EncodeRSABcryptBlob(&key.PublicKey)
	if len(blob) == 0 {
		t.Fatalf("EncodeRSABcryptBlob returned empty blob")
	}

	exp, mod, err := DecodeRSABcryptBlob(blob)
	if err != nil {
		t.Fatalf("DecodeRSABcryptBlob: %v", err)
	}
	if exp != key.E {
		t.Errorf("exponent mismatch: got %d want %d", exp, key.E)
	}
	if !bytes.Equal(mod, key.N.Bytes()) {
		t.Errorf("modulus mismatch:\n got %x\nwant %x", mod, key.N.Bytes())
	}
}

func TestBcryptDecodeBadMagic(t *testing.T) {
	blob := make([]byte, bcryptRSAHeaderLen+4)
	if _, _, err := DecodeRSABcryptBlob(blob); err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

func TestBcryptDecodeShort(t *testing.T) {
	if _, _, err := DecodeRSABcryptBlob([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for truncated blob, got nil")
	}
}
