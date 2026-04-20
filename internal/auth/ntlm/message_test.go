package ntlm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSecurityBufferEncode(t *testing.T) {
	sb := securityBuffer{length: 12, allocated: 12, offset: 56}
	got := sb.encode()
	want := []byte{0x0c, 0x00, 0x0c, 0x00, 0x38, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("securityBuffer.encode = %x, want %x", got, want)
	}
}

// Hand-build a minimal valid CHALLENGE_MESSAGE and round-trip it through decode.
func TestChallengeMessageDecode(t *testing.T) {
	ti := &TargetInfo{}
	ti.Set(AvIDNbDomainName, utf16LE("Domain"))
	ti.Set(AvIDNbComputerName, utf16LE("Server"))
	tiBytes := ti.Encode()

	flags := uint32(NegotiateUnicode | NegotiateNTLM | NegotiateTargetInfo)

	// Fixed-header layout (MS-NLMP §2.2.1.2): signature(8), type(4), targetNameFields(8),
	// negotiateFlags(4), serverChallenge(8), reserved(8), targetInfoFields(8), version(8) = 56 bytes.
	payload := make([]byte, 0, 56+len(tiBytes))
	payload = append(payload, Signature[:]...)
	payload = append(payload, u32(MessageTypeChallenge)...)
	// targetName: empty, offset 56
	payload = append(payload, u16(0)...)
	payload = append(payload, u16(0)...)
	payload = append(payload, u32(56)...)
	payload = append(payload, u32(flags)...)
	srvChal, _ := hex.DecodeString("0123456789abcdef")
	payload = append(payload, srvChal...)
	payload = append(payload, make([]byte, 8)...) // reserved
	payload = append(payload, u16(uint16(len(tiBytes)))...)
	payload = append(payload, u16(uint16(len(tiBytes)))...)
	payload = append(payload, u32(56)...)         // offset
	payload = append(payload, make([]byte, 8)...) // version
	payload = append(payload, tiBytes...)

	msg, err := DecodeChallengeMessage(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(msg.ServerChallenge[:], srvChal) {
		t.Errorf("ServerChallenge = %x, want %x", msg.ServerChallenge, srvChal)
	}
	if msg.NegotiateFlags != flags {
		t.Errorf("NegotiateFlags = %x, want %x", msg.NegotiateFlags, flags)
	}
	if !bytes.Equal(msg.TargetInfo.Get(AvIDNbDomainName), utf16LE("Domain")) {
		t.Error("TargetInfo NbDomainName missing")
	}
	if !bytes.Equal(msg.TargetInfo.Get(AvIDNbComputerName), utf16LE("Server")) {
		t.Error("TargetInfo NbComputerName missing")
	}
}

func TestNegotiateMessageEncode(t *testing.T) {
	msg := &NegotiateMessage{
		NegotiateFlags: uint32(NegotiateUnicode | NegotiateNTLM | RequestTarget),
	}
	out := msg.Encode()
	if len(out) < 32 {
		t.Fatalf("encoded length = %d, want >= 32", len(out))
	}
	if !bytes.HasPrefix(out, Signature[:]) {
		t.Error("missing signature prefix")
	}
	if got := leU32(out[8:12]); got != MessageTypeNegotiate {
		t.Errorf("MessageType = %d, want %d", got, MessageTypeNegotiate)
	}
	if got := leU32(out[12:16]); got != msg.NegotiateFlags {
		t.Errorf("NegotiateFlags = %x, want %x", got, msg.NegotiateFlags)
	}
}

// test helpers
func u16(v uint16) []byte {
	b := make([]byte, 2)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	return b
}
func u32(v uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return b
}
func leU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
