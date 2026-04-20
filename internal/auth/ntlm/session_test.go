package ntlm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Build a minimal CHALLENGE_MESSAGE identical to Task 4's test vector
// (serverChallenge=0x0123456789abcdef, TargetInfo = Domain+Server).
func buildTestChallenge(t *testing.T) []byte {
	t.Helper()
	ti := &TargetInfo{}
	ti.Set(AvIDNbDomainName, utf16LE("Domain"))
	ti.Set(AvIDNbComputerName, utf16LE("Server"))
	tiBytes := ti.Encode()
	flags := uint32(NegotiateUnicode | NegotiateNTLM | NegotiateTargetInfo)

	var cm bytes.Buffer
	cm.Write(Signature[:])
	cm.Write(u32(MessageTypeChallenge))
	// targetName empty @ offset 56
	cm.Write(u16(0))
	cm.Write(u16(0))
	cm.Write(u32(56))
	cm.Write(u32(flags))
	srvChal, _ := hex.DecodeString("0123456789abcdef")
	cm.Write(srvChal)
	cm.Write(make([]byte, 8))
	cm.Write(u16(uint16(len(tiBytes))))
	cm.Write(u16(uint16(len(tiBytes))))
	cm.Write(u32(56))
	cm.Write(make([]byte, 8)) // version
	cm.Write(tiBytes)
	return cm.Bytes()
}

// End-to-end: "Domain"/"User"/"Password" + MS-NLMP deterministic inputs should
// produce session key 0x8de40ccadbc14a82f15cb0ad0de95ca3 (MS-NLMP §4.2.4.2).
func TestClientEndToEndVector(t *testing.T) {
	c := NewClient("Domain", "User", "Password", "")
	c.fixedClientChallenge = mustHex("aaaaaaaaaaaaaaaa")
	c.fixedTimestamp = make([]byte, 8)
	c.fixedExportedSessionKey = mustHex("8de40ccadbc14a82f15cb0ad0de95ca3")

	authBytes, err := c.Authenticate(buildTestChallenge(t))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if len(authBytes) < 64 {
		t.Fatalf("auth message too short: %d", len(authBytes))
	}
	if !bytes.HasPrefix(authBytes, Signature[:]) {
		t.Error("missing signature prefix")
	}
	want := mustHex("8de40ccadbc14a82f15cb0ad0de95ca3")
	if !bytes.Equal(c.SessionKey(), want) {
		t.Errorf("SessionKey = %x, want %x", c.SessionKey(), want)
	}
}

func TestClientNegotiateBytes(t *testing.T) {
	c := NewClient("Domain", "User", "Password", "WORKSTATION")
	neg := c.Negotiate()
	if !bytes.HasPrefix(neg, Signature[:]) {
		t.Error("negotiate missing signature")
	}
}

func TestClientSignRoundTrip(t *testing.T) {
	c := NewClient("Domain", "User", "Password", "")
	c.fixedClientChallenge = mustHex("aaaaaaaaaaaaaaaa")
	c.fixedTimestamp = make([]byte, 8)
	c.fixedExportedSessionKey = mustHex("8de40ccadbc14a82f15cb0ad0de95ca3")
	if _, err := c.Authenticate(buildTestChallenge(t)); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	sig1 := c.Sign([]byte("hello"))
	sig2 := c.Sign([]byte("hello"))
	if bytes.Equal(sig1, sig2) {
		t.Error("signatures must differ across calls due to seq counter")
	}
	if len(sig1) != 16 {
		t.Errorf("signature length = %d, want 16", len(sig1))
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
