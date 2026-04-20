package shadow

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	kc, err := NewRSAKeyCredential(&key.PublicKey)
	if err != nil {
		t.Fatalf("NewRSAKeyCredential: %v", err)
	}
	// Pin creation time to avoid sub-microsecond precision drift after the
	// FILETIME round-trip.
	kc.CreationTime = time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)

	blob, err := kc.MarshalBlob()
	if err != nil {
		t.Fatalf("MarshalBlob: %v", err)
	}

	parsed, err := UnmarshalBlob(blob)
	if err != nil {
		t.Fatalf("UnmarshalBlob: %v", err)
	}

	if !bytes.Equal(parsed.KeyID, kc.KeyID) {
		t.Errorf("KeyID mismatch:\n got %x\nwant %x", parsed.KeyID, kc.KeyID)
	}
	if parsed.DeviceID != kc.DeviceID {
		t.Errorf("DeviceID mismatch: got %x want %x", parsed.DeviceID, kc.DeviceID)
	}
	if !bytes.Equal(parsed.KeyMaterial, kc.KeyMaterial) {
		t.Errorf("KeyMaterial mismatch (%d vs %d bytes)", len(parsed.KeyMaterial), len(kc.KeyMaterial))
	}
	if parsed.KeyUsage != kc.KeyUsage {
		t.Errorf("KeyUsage mismatch: got %#x want %#x", parsed.KeyUsage, kc.KeyUsage)
	}
	if parsed.KeySource != kc.KeySource {
		t.Errorf("KeySource mismatch: got %#x want %#x", parsed.KeySource, kc.KeySource)
	}
	if !parsed.CreationTime.Equal(kc.CreationTime) {
		t.Errorf("CreationTime mismatch: got %v want %v", parsed.CreationTime, kc.CreationTime)
	}
	if len(parsed.KeyHash) != 32 {
		t.Errorf("KeyHash wrong size: got %d want 32", len(parsed.KeyHash))
	}
}

func TestDNBinaryRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	kc, err := NewRSAKeyCredential(&key.PublicKey)
	if err != nil {
		t.Fatalf("NewRSAKeyCredential: %v", err)
	}
	kc.CreationTime = time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)

	ownerDN := "CN=target,CN=Users,DC=corp,DC=local"
	encoded := kc.MarshalDNBinary(ownerDN)
	if !strings.HasPrefix(encoded, "B:") {
		t.Fatalf("DNBinary missing 'B:' prefix: %q", encoded[:min(32, len(encoded))])
	}
	if !strings.HasSuffix(encoded, ":"+ownerDN) {
		t.Fatalf("DNBinary missing DN suffix, got tail %q", encoded[len(encoded)-32:])
	}

	parts := strings.SplitN(encoded, ":", 4)
	if len(parts) != 4 {
		t.Fatalf("expected 4 colon-separated fields, got %d", len(parts))
	}
	// Length field must equal the number of hex characters, NOT the byte
	// count - this is DNBinary syntax per RFC 4517.
	var declared int
	if _, err := fmt.Sscanf(parts[1], "%d", &declared); err != nil {
		t.Fatalf("parse declared length: %v", err)
	}
	if declared != len(parts[2]) {
		t.Errorf("declared length %d != hex chars %d", declared, len(parts[2]))
	}

	parsed, gotDN, err := ParseDNBinary(encoded)
	if err != nil {
		t.Fatalf("ParseDNBinary: %v", err)
	}
	if gotDN != ownerDN {
		t.Errorf("ownerDN mismatch: got %q want %q", gotDN, ownerDN)
	}
	if parsed.DeviceID != kc.DeviceID {
		t.Errorf("DeviceID mismatch after DNBinary round-trip")
	}
	if !bytes.Equal(parsed.KeyID, kc.KeyID) {
		t.Errorf("KeyID mismatch after DNBinary round-trip")
	}
}

func TestParseDNBinaryRejectsBadInput(t *testing.T) {
	cases := []string{
		"",
		"X:4:DEAD:CN=x",
		"B:4:DEAD",
		"B:5:DEAD:CN=x", // length mismatch.
	}
	for _, c := range cases {
		if _, _, err := ParseDNBinary(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}
