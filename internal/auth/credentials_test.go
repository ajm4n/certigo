package auth

import (
	"strings"
	"testing"
)

func TestCredentialsValidate_Minimal(t *testing.T) {
	c := &Credentials{Username: "alice", Domain: "CTG.LOCAL", Password: "x"}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestCredentialsValidate_MissingUser(t *testing.T) {
	c := &Credentials{Domain: "CTG.LOCAL", Password: "x"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "username") {
		t.Errorf("expected username error, got %v", err)
	}
}

func TestCredentialsValidate_MissingSecret(t *testing.T) {
	c := &Credentials{Username: "alice", Domain: "CTG.LOCAL"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Errorf("expected secret error, got %v", err)
	}
}

func TestCredentialsValidate_NTHashOK(t *testing.T) {
	c := &Credentials{
		Username: "alice",
		Domain:   "CTG.LOCAL",
		NTHash:   hexBytes("a4f49c406510bdcab6824ee7c30fd852"),
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestCredentialsValidate_BadNTHashLen(t *testing.T) {
	c := &Credentials{Username: "alice", Domain: "CTG.LOCAL", NTHash: []byte{0x01, 0x02}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "NT hash") {
		t.Errorf("expected NT hash length error, got %v", err)
	}
}

func TestParseHashes_NTOnly(t *testing.T) {
	lm, nt, err := ParseHashes(":a4f49c406510bdcab6824ee7c30fd852")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if lm != nil {
		t.Errorf("expected nil LM, got %x", lm)
	}
	if len(nt) != 16 {
		t.Errorf("NT len = %d, want 16", len(nt))
	}
}

func TestParseHashes_Both(t *testing.T) {
	lm, nt, err := ParseHashes("aad3b435b51404eeaad3b435b51404ee:a4f49c406510bdcab6824ee7c30fd852")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(lm) != 16 {
		t.Errorf("LM len = %d, want 16", len(lm))
	}
	if len(nt) != 16 {
		t.Errorf("NT len = %d, want 16", len(nt))
	}
}

func TestParseHashes_Invalid(t *testing.T) {
	if _, _, err := ParseHashes("not a hash"); err == nil {
		t.Error("expected error for missing colon")
	}
	if _, _, err := ParseHashes(":xyz"); err == nil {
		t.Error("expected error for non-hex")
	}
}

func hexBytes(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		hi := hexNibble(s[2*i])
		lo := hexNibble(s[2*i+1])
		b[i] = hi<<4 | lo
	}
	return b
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
