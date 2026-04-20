package spnego

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"unicode/utf16"

	"github.com/ajm4n/certigo/internal/auth/ntlm"
)

// buildTestChallenge mirrors internal/auth/ntlm/session_test.go's helper: a
// minimal CHALLENGE_MESSAGE with a fixed server challenge and a two-entry
// TargetInfo (domain + server).
func buildTestChallenge(t *testing.T) []byte {
	t.Helper()

	// Encode TargetInfo = [NbDomainName="Domain", NbComputerName="Server", EOL].
	var ti bytes.Buffer
	writeAV := func(id uint16, val []byte) {
		_ = binary.Write(&ti, binary.LittleEndian, id)
		_ = binary.Write(&ti, binary.LittleEndian, uint16(len(val)))
		ti.Write(val)
	}
	writeAV(ntlm.AvIDNbDomainName, utf16LE("Domain"))
	writeAV(ntlm.AvIDNbComputerName, utf16LE("Server"))
	writeAV(ntlm.AvIDEOL, nil)
	tiBytes := ti.Bytes()

	flags := uint32(ntlm.NegotiateUnicode | ntlm.NegotiateNTLM | ntlm.NegotiateTargetInfo)

	var cm bytes.Buffer
	cm.Write(ntlm.Signature[:])
	_ = binary.Write(&cm, binary.LittleEndian, ntlm.MessageTypeChallenge)
	// targetName empty @ offset 56
	_ = binary.Write(&cm, binary.LittleEndian, uint16(0))
	_ = binary.Write(&cm, binary.LittleEndian, uint16(0))
	_ = binary.Write(&cm, binary.LittleEndian, uint32(56))
	_ = binary.Write(&cm, binary.LittleEndian, flags)
	srvChal, _ := hex.DecodeString("0123456789abcdef")
	cm.Write(srvChal)
	cm.Write(make([]byte, 8))
	_ = binary.Write(&cm, binary.LittleEndian, uint16(len(tiBytes)))
	_ = binary.Write(&cm, binary.LittleEndian, uint16(len(tiBytes)))
	_ = binary.Write(&cm, binary.LittleEndian, uint32(56))
	cm.Write(make([]byte, 8)) // version
	cm.Write(tiBytes)
	return cm.Bytes()
}

// utf16LE mirrors the private helper in the ntlm package so we can build
// test fixtures without reaching into unexported identifiers.
func utf16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(runes))
	for i, r := range runes {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}

func TestNTLMNegotiator_Handshake(t *testing.T) {
	c := ntlm.NewClient("Domain", "User", "Password", "")

	n := NewNTLM(c)
	if got := n.Mechanism(); got != MechanismNTLM {
		t.Fatalf("Mechanism = %q, want %q", got, MechanismNTLM)
	}

	neg, done, err := n.Initial()
	if err != nil {
		t.Fatalf("Initial: %v", err)
	}
	if done {
		t.Fatal("Initial returned done=true; expected another round")
	}
	if !bytes.HasPrefix(neg, ntlm.Signature[:]) {
		t.Fatal("NEGOTIATE_MESSAGE missing NTLMSSP signature")
	}

	auth, done, err := n.Accept(buildTestChallenge(t))
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if !done {
		t.Fatal("Accept did not finish the handshake")
	}
	if !bytes.HasPrefix(auth, ntlm.Signature[:]) {
		t.Fatal("AUTHENTICATE_MESSAGE missing NTLMSSP signature")
	}

	if key := n.SessionKey(); len(key) == 0 {
		t.Fatal("SessionKey empty after successful handshake")
	}
}

func TestNTLMNegotiator_InitialTwice(t *testing.T) {
	c := ntlm.NewClient("Domain", "User", "Password", "")
	n := NewNTLM(c)
	if _, _, err := n.Initial(); err != nil {
		t.Fatalf("first Initial: %v", err)
	}
	if _, _, err := n.Initial(); err == nil {
		t.Fatal("expected error calling Initial twice")
	}
}

func TestNTLMNegotiator_AcceptBeforeInitial(t *testing.T) {
	c := ntlm.NewClient("Domain", "User", "Password", "")
	n := NewNTLM(c)
	if _, _, err := n.Accept([]byte{0}); err == nil {
		t.Fatal("expected error calling Accept before Initial")
	}
}

func TestNTLMNegotiator_NilClient(t *testing.T) {
	n := NewNTLM(nil)
	if _, _, err := n.Initial(); err == nil {
		t.Fatal("expected error for nil client")
	}
	if n.Mechanism() != MechanismNTLM {
		t.Fatal("Mechanism should report ntlm even with nil client")
	}
	if n.SessionKey() != nil {
		t.Fatal("SessionKey should be nil for nil client")
	}
}
