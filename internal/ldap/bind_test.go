package ldap

import (
	"errors"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/ajm4n/certigo/internal/auth"
)

// withStubs swaps out the package-level bind hooks for the duration of a
// test and returns a restore function.
func withStubs(t *testing.T) *stubs {
	t.Helper()
	s := &stubs{}

	origSimple := simpleBindFn
	origNTLM := ntlmBindFn
	origNTLMHash := ntlmHashBindFn
	origGSS := gssapiBindFn

	simpleBindFn = func(_ *goldap.Conn, _ *auth.Credentials) error { s.simple++; return nil }
	ntlmBindFn = func(_ *goldap.Conn, _ *auth.Credentials) error { s.ntlm++; return nil }
	ntlmHashBindFn = func(_ *goldap.Conn, _ *auth.Credentials) error { s.ntlmHash++; return nil }
	gssapiBindFn = func(_ *goldap.Conn, _ *auth.Credentials, _ string) error { s.gss++; return nil }

	t.Cleanup(func() {
		simpleBindFn = origSimple
		ntlmBindFn = origNTLM
		ntlmHashBindFn = origNTLMHash
		gssapiBindFn = origGSS
	})
	return s
}

type stubs struct {
	simple, ntlm, ntlmHash, gss int
}

func TestBind_SelectsPassword(t *testing.T) {
	s := withStubs(t)
	creds := &auth.Credentials{
		Username: "alice",
		Domain:   "CTG.LOCAL",
		Password: "hunter2",
	}
	if err := Bind(nil, creds, ""); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if s.simple != 1 || s.ntlm+s.ntlmHash+s.gss != 0 {
		t.Fatalf("expected simple bind only, got %+v", s)
	}
}

func TestBind_SelectsNTLMHash(t *testing.T) {
	s := withStubs(t)
	creds := &auth.Credentials{
		Username: "alice",
		Domain:   "CTG",
		NTHash:   make([]byte, 16),
	}
	if err := Bind(nil, creds, ""); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if s.ntlmHash != 1 || s.simple+s.ntlm+s.gss != 0 {
		t.Fatalf("expected ntlm-hash bind only, got %+v", s)
	}
}

func TestBind_SelectsKerberos(t *testing.T) {
	s := withStubs(t)
	creds := &auth.Credentials{
		Username:    "alice",
		Domain:      "CTG.LOCAL",
		Password:    "hunter2",
		UseKerberos: true,
	}
	if err := Bind(nil, creds, "ldap/dc01.ctg.local"); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if s.gss != 1 || s.simple+s.ntlm+s.ntlmHash != 0 {
		t.Fatalf("expected gssapi bind only, got %+v", s)
	}
}

func TestBind_KerberosRequiresSPN(t *testing.T) {
	_ = withStubs(t)
	creds := &auth.Credentials{
		Username:    "alice",
		Domain:      "CTG.LOCAL",
		Password:    "hunter2",
		UseKerberos: true,
	}
	if err := Bind(nil, creds, ""); err == nil {
		t.Fatal("expected error when Kerberos bind invoked without SPN")
	}
}

func TestBind_Unsupported(t *testing.T) {
	_ = withStubs(t)
	creds := &auth.Credentials{
		Username: "alice",
		Domain:   "CTG.LOCAL",
		PFXPath:  "/tmp/identity.pfx",
	}
	err := Bind(nil, creds, "")
	if !errors.Is(err, ErrCertAuthDeferred) {
		t.Fatalf("expected ErrCertAuthDeferred, got %v", err)
	}
}

func TestBind_MissingSecret(t *testing.T) {
	_ = withStubs(t)
	creds := &auth.Credentials{Username: "alice", Domain: "CTG.LOCAL"}
	if err := Bind(nil, creds, ""); err == nil {
		t.Fatal("expected Validate-style error for empty credentials")
	}
}

func TestBind_NilCredentials(t *testing.T) {
	_ = withStubs(t)
	if err := Bind(nil, nil, ""); err == nil {
		t.Fatal("expected error for nil credentials")
	}
}

func TestBindUsername_AppendsDomain(t *testing.T) {
	creds := &auth.Credentials{Username: "alice", Domain: "CTG.LOCAL"}
	if got, want := bindUsername(creds), "alice@CTG.LOCAL"; got != want {
		t.Errorf("bindUsername = %q, want %q", got, want)
	}
}

func TestBindUsername_PreservesExplicitForms(t *testing.T) {
	cases := []struct {
		name, user, want string
	}{
		{"upn", "alice@ctg.local", "alice@ctg.local"},
		{"dn", "CN=Alice,DC=ctg,DC=local", "CN=Alice,DC=ctg,DC=local"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			creds := &auth.Credentials{Username: tc.user, Domain: "CTG.LOCAL"}
			if got := bindUsername(creds); got != tc.want {
				t.Errorf("bindUsername = %q, want %q", got, tc.want)
			}
		})
	}
}
