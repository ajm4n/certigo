package ldap

import (
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/ajm4n/certigo/internal/auth"
)

// AutoOptions bundles the inputs DialAndBind needs. Most subcommands populate
// these directly from their CLI flags; the helper does the rest.
type AutoOptions struct {
	DCHost             string // host or IP, no port
	Port               int    // default 389 (or 636 with UseTLS)
	UseTLS             bool   // force LDAPS
	Scheme             string // "ldap" or "ldaps"; overrides UseTLS when set
	InsecureSkipVerify bool
}

// normalize reconciles Scheme/UseTLS/Port so downstream callers can treat
// Scheme as authoritative. When Scheme is "ldaps" we force UseTLS=true and
// default Port to 636; "ldap" forces UseTLS=false. Unknown scheme values
// are left alone for explicit error-raising in DialAndBind.
func (o *AutoOptions) normalize() {
	switch strings.ToLower(strings.TrimSpace(o.Scheme)) {
	case "ldaps":
		o.UseTLS = true
		if o.Port == 0 || o.Port == 389 {
			o.Port = 636
		}
	case "ldap":
		o.UseTLS = false
		if o.Port == 0 {
			o.Port = 389
		}
	}
}

// DialAndBind is the certipy-style "do the right thing" front door for
// subcommands: resolve the DC endpoint, dial, bind with the supplied
// Credentials, and on signing-related failures against plain LDAP
// automatically retry over LDAPS. The returned *goldap.Conn is bound and
// ready for use. Callers close it with conn.Close().
//
// It also normalizes Credentials in-place: if Username is "user@realm" and
// Domain is empty, Domain is extracted; trailing "$" on a machine account
// name is preserved verbatim for NTLM.
func DialAndBind(creds *auth.Credentials, opts AutoOptions) (*goldap.Conn, error) {
	if opts.DCHost == "" {
		return nil, fmt.Errorf("ldap: --dc-host required")
	}
	s := strings.ToLower(strings.TrimSpace(opts.Scheme))
	if s != "" && s != "ldap" && s != "ldaps" {
		return nil, fmt.Errorf("ldap: invalid --scheme %q (want ldap or ldaps)", opts.Scheme)
	}
	opts.normalize()

	normalizeCreds(creds)

	port := opts.Port
	if port == 0 {
		port = 389
		if opts.UseTLS {
			port = 636
		}
	}

	tryTLS := opts.UseTLS || port == 636

	conn, err := dialWith(opts, port, tryTLS)
	if err != nil {
		return nil, err
	}

	spn := ""
	if creds.UseKerberos {
		spn = "ldap/" + opts.DCHost
	}

	if err := Bind(conn, creds, spn); err != nil {
		_ = conn.Close()
		// If we just tried plain LDAP and the server rejected us with a
		// signing / integrity error, transparently retry over LDAPS on 636.
		if !tryTLS && shouldRetryLDAPS(err) {
			retryOpts := opts
			retryOpts.UseTLS = true
			retryOpts.InsecureSkipVerify = true
			conn2, err2 := dialWith(retryOpts, 636, true)
			if err2 != nil {
				return nil, fmt.Errorf("ldap: %w (retry over LDAPS also failed: %v)", err, err2)
			}
			if err3 := Bind(conn2, creds, spn); err3 != nil {
				_ = conn2.Close()
				return nil, fmt.Errorf("ldap: bind failed on 389 (%v) and 636 (%v)", err, err3)
			}
			return conn2, nil
		}
		return nil, err
	}
	return conn, nil
}

func dialWith(opts AutoOptions, port int, useTLS bool) (*goldap.Conn, error) {
	return Dial(DialOptions{
		Server:             fmt.Sprintf("%s:%d", opts.DCHost, port),
		UseTLS:             useTLS,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	})
}

// normalizeCreds extracts Domain from a user@domain username if Domain is
// empty. Machine account names ending in "$" are left as-is.
func normalizeCreds(creds *auth.Credentials) {
	if creds == nil {
		return
	}
	u := strings.TrimSpace(creds.Username)
	if creds.Domain == "" && strings.Contains(u, "@") {
		at := strings.LastIndex(u, "@")
		creds.Username = u[:at]
		creds.Domain = u[at+1:]
	}
}

// shouldRetryLDAPS reports whether the failed plain-LDAP bind is likely to
// succeed over LDAPS. AD typically returns "strongerAuthRequired" (LDAP
// result code 8) or "confidentialityRequired" (code 13) when signing /
// sealing is enforced and the bind came in clear.
func shouldRetryLDAPS(err error) bool {
	if err == nil {
		return false
	}
	if lerr, ok := asLDAPError(err); ok {
		switch lerr.ResultCode {
		case goldap.LDAPResultStrongAuthRequired, goldap.LDAPResultConfidentialityRequired:
			return true
		}
	}
	msg := err.Error()
	for _, needle := range []string{"strongerAuthRequired", "confidentialityRequired", "000004DC", "000004DC:"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

func asLDAPError(err error) (*goldap.Error, bool) {
	for e := err; e != nil; {
		if le, ok := e.(*goldap.Error); ok {
			return le, true
		}
		unwrapped, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = unwrapped.Unwrap()
	}
	return nil, false
}
