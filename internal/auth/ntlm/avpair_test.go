package ntlm

import (
	"bytes"
	"testing"
)

// MS-NLMP §4.2.4.1.3 — TargetInfo has NbDomainName="Domain", NbComputerName="Server".
func TestDecodeTargetInfoNLMPVector(t *testing.T) {
	raw := []byte{
		0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00,
		0x69, 0x00, 0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	ti, err := DecodeTargetInfo(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := ti.Get(AvIDNbDomainName); !bytes.Equal(got, utf16LE("Domain")) {
		t.Errorf("NbDomainName = %x, want %x", got, utf16LE("Domain"))
	}
	if got := ti.Get(AvIDNbComputerName); !bytes.Equal(got, utf16LE("Server")) {
		t.Errorf("NbComputerName = %x, want %x", got, utf16LE("Server"))
	}
}

func TestEncodeTargetInfoRoundTrip(t *testing.T) {
	ti := TargetInfo{}
	ti.Set(AvIDNbDomainName, utf16LE("Domain"))
	ti.Set(AvIDNbComputerName, utf16LE("Server"))
	enc := ti.Encode()
	dec, err := DecodeTargetInfo(enc)
	if err != nil {
		t.Fatalf("round-trip decode: %v", err)
	}
	if !bytes.Equal(dec.Get(AvIDNbDomainName), utf16LE("Domain")) {
		t.Error("round-trip lost NbDomainName")
	}
	if !bytes.Equal(dec.Get(AvIDNbComputerName), utf16LE("Server")) {
		t.Error("round-trip lost NbComputerName")
	}
}
