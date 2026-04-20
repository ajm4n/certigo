// Package auth unifies credential handling for certigo subcommands.
//
// A single Credentials value spans every authentication mode certigo supports:
// plaintext password, NT hash, Kerberos TGT (via ccache/kirbi), and
// certificate (PFX or PEM+key). Subcommand packages build a Credentials from
// CLI flags via ParseFlags and pass it to LDAP, RPC, and HTTP layers.
package auth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Credentials is the unified auth context for a single certigo invocation.
//
// Not all fields are populated: e.g., a cert-only auth leaves Password/NTHash
// empty. Consumers should check which credential mode applies via the helper
// methods (HasPassword, HasNTHash, HasCertificate, HasKerberosTicket).
type Credentials struct {
	// Identity.
	Username string
	Domain   string // NetBIOS or DNS form; subcommands normalize per call

	// Secret material — exactly one of these groups is typically set.
	Password string
	LMHash   []byte // 16 bytes; often zero (AAD3B435 sentinel)
	NTHash   []byte // 16 bytes

	// Kerberos options.
	UseKerberos bool
	NoPass      bool   // -no-pass: pull creds from KRB5CCNAME instead
	KDCHost     string // -dc-ip / explicit KDC; overrides krb5.conf lookup
	DNSHost     string // -ns: nameserver override

	// Certificate-based auth (PKINIT or Schannel path).
	PFXPath     string
	PFXPassword string
	PEMCertPath string
	PEMKeyPath  string

	// Ticket cache path — empty = use $KRB5CCNAME / default. Written by `auth`
	// subcommand after PKINIT/AS-REQ succeeds.
	CCachePath string

	// Kirbi output path for Windows-style ticket export.
	KirbiPath string

	// Target resolution knobs.
	TargetIP   string // explicit server IP if DNS unreachable
	TargetHost string // canonical hostname for SPN construction
}

// Validate confirms the credential set is coherent enough to attempt auth.
// It does not verify the secrets against a KDC — that happens at bind time.
func (c *Credentials) Validate() error {
	if c == nil {
		return errors.New("auth: nil credentials")
	}
	if c.Username == "" && !c.NoPass {
		return errors.New("auth: username required")
	}
	if !c.hasAnySecret() {
		return errors.New("auth: at least one secret required (password, NT hash, PFX, or ccache)")
	}
	if len(c.NTHash) > 0 && len(c.NTHash) != 16 {
		return fmt.Errorf("auth: NT hash must be 16 bytes, got %d", len(c.NTHash))
	}
	if len(c.LMHash) > 0 && len(c.LMHash) != 16 {
		return fmt.Errorf("auth: LM hash must be 16 bytes, got %d", len(c.LMHash))
	}
	return nil
}

// HasPassword reports whether a plaintext password is available.
func (c *Credentials) HasPassword() bool { return c.Password != "" }

// HasNTHash reports whether an NT hash is available.
func (c *Credentials) HasNTHash() bool { return len(c.NTHash) == 16 }

// HasCertificate reports whether PFX or PEM+key material is referenced.
func (c *Credentials) HasCertificate() bool {
	return c.PFXPath != "" || (c.PEMCertPath != "" && c.PEMKeyPath != "")
}

// HasKerberosTicket reports whether an existing ccache/kirbi should be loaded.
func (c *Credentials) HasKerberosTicket() bool { return c.NoPass || c.CCachePath != "" }

func (c *Credentials) hasAnySecret() bool {
	return c.HasPassword() || c.HasNTHash() || c.HasCertificate() || c.HasKerberosTicket()
}

// ParseHashes splits a "LMHASH:NTHASH" flag value into its two 16-byte halves.
// The LM half may be empty (":NTHASH" form). Both halves are lowercased hex
// of exactly 32 characters when present.
func ParseHashes(raw string) (lm, nt []byte, err error) {
	if !strings.Contains(raw, ":") {
		return nil, nil, fmt.Errorf("auth: hashes must be LMHASH:NTHASH (got %q)", raw)
	}
	parts := strings.SplitN(raw, ":", 2)
	if parts[0] != "" {
		lm, err = hex.DecodeString(strings.ToLower(parts[0]))
		if err != nil {
			return nil, nil, fmt.Errorf("auth: bad LM hex: %w", err)
		}
		if len(lm) != 16 {
			return nil, nil, fmt.Errorf("auth: LM hash length %d (want 16)", len(lm))
		}
	}
	if parts[1] != "" {
		nt, err = hex.DecodeString(strings.ToLower(parts[1]))
		if err != nil {
			return nil, nil, fmt.Errorf("auth: bad NT hex: %w", err)
		}
		if len(nt) != 16 {
			return nil, nil, fmt.Errorf("auth: NT hash length %d (want 16)", len(nt))
		}
	}
	return lm, nt, nil
}
