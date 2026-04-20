package ldap

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gokrb5/v8/client"

	"github.com/ajm4n/certigo/internal/auth"
	"github.com/ajm4n/certigo/internal/auth/krb"
)

// ErrCertAuthDeferred is returned when Credentials carry only certificate
// material; Schannel / PKINIT-driven binds are scheduled for M3.
var ErrCertAuthDeferred = errors.New("ldap: certificate-based bind deferred to M3")

// Bind function hooks let tests replace the heavy work with fakes without
// needing a live LDAP server.
var (
	simpleBindFn   = doSimpleBind
	ntlmBindFn     = doNTLMBind
	ntlmHashBindFn = doNTLMBindWithHash
	gssapiBindFn   = doGSSAPIBind
)

// Bind authenticates the connection using the given Credentials.
//   - If Credentials.UseKerberos       → SPNEGO/GSSAPI bind with a gokrb5 client
//   - If Credentials.HasNTHash()       → NTLM bind via go-ldap's built-in helper
//   - If Credentials.HasPassword()     → SimpleBind
//   - If Credentials.HasCertificate()  → deferred (M3); return an error
//
// The spn argument is required for Kerberos (e.g. "ldap/dc01.ctg.local").
func Bind(conn *goldap.Conn, creds *auth.Credentials, spn string) error {
	if err := creds.Validate(); err != nil {
		return err
	}

	switch {
	case creds.UseKerberos || creds.HasKerberosTicket():
		if spn == "" {
			return errors.New("ldap: bind: Kerberos requires an SPN")
		}
		return gssapiBindFn(conn, creds, spn)

	case creds.HasNTHash():
		return ntlmHashBindFn(conn, creds)

	case creds.HasPassword():
		return simpleBindFn(conn, creds)

	case creds.HasCertificate():
		return ErrCertAuthDeferred

	default:
		// Validate() should have caught this, but be defensive.
		return errors.New("ldap: bind: no usable secret in credentials")
	}
}

// doSimpleBind performs a DN-or-UPN + password bind.
func doSimpleBind(conn *goldap.Conn, creds *auth.Credentials) error {
	username := bindUsername(creds)
	req := goldap.NewSimpleBindRequest(username, creds.Password, nil)
	if _, err := conn.SimpleBind(req); err != nil {
		return fmt.Errorf("ldap: simple bind as %s: %w", username, err)
	}
	return nil
}

// doNTLMBind performs an NTLM bind using a plaintext password.
func doNTLMBind(conn *goldap.Conn, creds *auth.Credentials) error {
	if err := conn.NTLMBind(creds.Domain, creds.Username, creds.Password); err != nil {
		return fmt.Errorf("ldap: NTLM bind: %w", err)
	}
	return nil
}

// doNTLMBindWithHash performs pass-the-hash NTLM bind.
func doNTLMBindWithHash(conn *goldap.Conn, creds *auth.Credentials) error {
	hashHex := hex.EncodeToString(creds.NTHash)
	if err := conn.NTLMBindWithHash(creds.Domain, creds.Username, hashHex); err != nil {
		return fmt.Errorf("ldap: NTLM bind (hash): %w", err)
	}
	return nil
}

// doGSSAPIBind performs a SPNEGO / Kerberos bind using a gokrb5 client that
// we plug into go-ldap's GSSAPIClient interface via the gssapi subpackage.
func doGSSAPIBind(conn *goldap.Conn, creds *auth.Credentials, spn string) error {
	krbClient, err := buildKrbClient(creds)
	if err != nil {
		return err
	}
	if err := krbClient.Login(); err != nil {
		return fmt.Errorf("ldap: kerberos login: %w", err)
	}
	gssCl := &gssapi.Client{Client: krbClient}
	if err := conn.GSSAPIBind(gssCl, spn, ""); err != nil {
		return fmt.Errorf("ldap: GSSAPI bind: %w", err)
	}
	return nil
}

// buildKrbClient constructs a gokrb5 *client.Client honoring the credential
// mode (password or NT hash). CCache / PKINIT-driven flows flow through
// separate higher-level code and reach us as an already-prepared client.
func buildKrbClient(creds *auth.Credentials) (*client.Client, error) {
	realm := strings.ToUpper(strings.TrimSpace(creds.Domain))
	cfg, err := krb.LoadConfig(realm, creds.KDCHost)
	if err != nil {
		return nil, fmt.Errorf("ldap: load krb5 config: %w", err)
	}
	cl, err := krb.NewClient(creds, cfg)
	if err != nil {
		return nil, fmt.Errorf("ldap: build kerberos client: %w", err)
	}
	return cl, nil
}

// bindUsername derives the DN-or-UPN form for a simple bind. If Username
// already contains "@" or "=", assume the caller passed a fully-qualified
// identity. Otherwise fall back to UPN (user@DOMAIN).
func bindUsername(creds *auth.Credentials) string {
	u := strings.TrimSpace(creds.Username)
	if u == "" {
		return ""
	}
	if strings.ContainsAny(u, "@=") {
		return u
	}
	if creds.Domain == "" {
		return u
	}
	return u + "@" + creds.Domain
}
