package pkinit

import (
	"bytes"
	"crypto/sha1"
	"encoding/asn1"
	"testing"

	gokrb5asn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
)

// TestPAPKASREQ_Roundtrip verifies that a PA-PK-AS-REQ wrapper survives a
// marshal/unmarshal cycle with the embedded signedAuthPack byte-equal. The
// pad fields (trustedCertifiers, kdcPkId) are intentionally not populated
// because we never emit them in live traffic.
func TestPAPKASREQ_Roundtrip(t *testing.T) {
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0xDE, 0xAD, 0xBE, 0xEF}
	der, err := MarshalPAPKASReq(want)
	if err != nil {
		t.Fatalf("MarshalPAPKASReq: %v", err)
	}
	got, err := UnmarshalPAPKASReq(der)
	if err != nil {
		t.Fatalf("UnmarshalPAPKASReq: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("signedAuthPack mismatch:\n got: %x\nwant: %x", got, want)
	}

	// An empty payload must be rejected - signed data of length zero is
	// nonsensical and the KDC would reject it, so we refuse at encode time.
	if _, err := MarshalPAPKASReq(nil); err == nil {
		t.Fatalf("MarshalPAPKASReq(nil) unexpectedly succeeded")
	}
}

// TestKDCKeyDerivation pins the RFC 4556 §3.2.3.1 octetstring2key output
// against a hand-computed vector. When the shared secret is 32 zero bytes
// and no DH nonces are present, the derived AES256 key is
// SHA1(0x00 || 0x00*32) || SHA1(0x01 || 0x00*32), truncated to 32 bytes.
func TestKDCKeyDerivation(t *testing.T) {
	shared := make([]byte, 32) // all zeros

	// Recompute expected output from first principles.
	h0 := sha1.New()
	h0.Write([]byte{0x00})
	h0.Write(shared)
	b0 := h0.Sum(nil)
	h1 := sha1.New()
	h1.Write([]byte{0x01})
	h1.Write(shared)
	b1 := h1.Sum(nil)
	want := append(append([]byte{}, b0...), b1...)[:32]

	key, err := DeriveASReplyKey(etypeID.AES256_CTS_HMAC_SHA1_96, shared, nil, nil)
	if err != nil {
		t.Fatalf("DeriveASReplyKey: %v", err)
	}
	if key.KeyType != etypeID.AES256_CTS_HMAC_SHA1_96 {
		t.Fatalf("KeyType = %d, want %d", key.KeyType, etypeID.AES256_CTS_HMAC_SHA1_96)
	}
	if len(key.KeyValue) != 32 {
		t.Fatalf("KeyValue length = %d, want 32", len(key.KeyValue))
	}
	if !bytes.Equal(key.KeyValue, want) {
		t.Fatalf("derived key mismatch:\n got: %x\nwant: %x", key.KeyValue, want)
	}

	// AES128 path - 16-byte truncation of the same SHA1 stream.
	key128, err := DeriveASReplyKey(etypeID.AES128_CTS_HMAC_SHA1_96, shared, nil, nil)
	if err != nil {
		t.Fatalf("DeriveASReplyKey AES128: %v", err)
	}
	if len(key128.KeyValue) != 16 {
		t.Fatalf("AES128 key length = %d, want 16", len(key128.KeyValue))
	}
	if !bytes.Equal(key128.KeyValue, b0[:16]) {
		t.Fatalf("AES128 key mismatch:\n got: %x\nwant: %x", key128.KeyValue, b0[:16])
	}
}

// TestKDCKeyDerivation_WithNonces verifies that x includes the client/server
// DH nonces when supplied, producing a different key than the bare shared
// secret would.
func TestKDCKeyDerivation_WithNonces(t *testing.T) {
	shared := bytes.Repeat([]byte{0xAB}, 32)
	cnonce := bytes.Repeat([]byte{0x11}, 16)
	snonce := bytes.Repeat([]byte{0x22}, 16)

	key, err := DeriveASReplyKey(etypeID.AES256_CTS_HMAC_SHA1_96, shared, cnonce, snonce)
	if err != nil {
		t.Fatalf("DeriveASReplyKey: %v", err)
	}

	// Compare with a bare-shared derivation - should differ when nonces
	// are folded in.
	bare, err := DeriveASReplyKey(etypeID.AES256_CTS_HMAC_SHA1_96, shared, nil, nil)
	if err != nil {
		t.Fatalf("DeriveASReplyKey bare: %v", err)
	}
	if bytes.Equal(key.KeyValue, bare.KeyValue) {
		t.Fatalf("key with nonces matched bare-shared key; expected different output")
	}
}

// TestPAPKASREP_DHInfoParse hand-builds a minimal PA-PK-AS-REP containing
// the dhInfo [0] alternative with a non-empty dhSignedData and verifies
// that ParsePAPKASRep returns that exact payload.
func TestPAPKASREP_DHInfoParse(t *testing.T) {
	wantSigned := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x11}

	// Build DHRepInfo first: SEQUENCE { [0] IMPLICIT OCTET STRING }.
	info := dhRepInfo{
		DHSignedData: wantSigned,
	}
	infoDER, err := asn1.Marshal(info)
	if err != nil {
		t.Fatalf("marshal dhRepInfo: %v", err)
	}

	// Wrap in [0] EXPLICIT to form the CHOICE dhInfo arm. We prepend the
	// tag bytes by hand because encoding/asn1 cannot express a CHOICE
	// directly.
	outer := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      infoDER,
	}
	outerDER, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("marshal CHOICE: %v", err)
	}

	got, serverNonce, err := ParsePAPKASRep(outerDER)
	if err != nil {
		t.Fatalf("ParsePAPKASRep: %v", err)
	}
	if !bytes.Equal(got, wantSigned) {
		t.Fatalf("dhSignedData mismatch:\n got: %x\nwant: %x", got, wantSigned)
	}
	if len(serverNonce) != 0 {
		t.Fatalf("unexpected serverDHNonce: %x", serverNonce)
	}
}

// TestKDCDHKeyInfoParse round-trips the inner KDCDHKeyInfo payload to make
// sure the ASN.1 tag map matches what a real KDC emits.
func TestKDCDHKeyInfoParse(t *testing.T) {
	y := []byte{0x02, 0x03, 0x04}
	info := kdcDHKeyInfo{
		SubjectPublicKey: asn1.BitString{
			Bytes:     y,
			BitLength: len(y) * 8,
		},
		Nonce: 0x1234,
	}
	der, err := asn1.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	gotY, gotNonce, err := ParseKDCDHKeyInfo(der)
	if err != nil {
		t.Fatalf("ParseKDCDHKeyInfo: %v", err)
	}
	if !bytes.Equal(gotY, y) {
		t.Fatalf("Y mismatch: got %x want %x", gotY, y)
	}
	if gotNonce != 0x1234 {
		t.Fatalf("nonce mismatch: got %d want %d", gotNonce, 0x1234)
	}
}

// helper so the gokrb5 gofork asn1 import is exercised; keeps the imports
// aligned between tests that touch both stdlib encoding/asn1 and the
// gokrb5-specific gofork fork.
var _ = gokrb5asn1.BitString{}
