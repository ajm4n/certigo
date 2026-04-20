// Package spnego bridges certigo's native NTLM implementation and the
// gokrb5 Kerberos/SPNEGO stack behind a single Negotiator interface so that
// upper-layer protocol bindings (LDAP, RPC, HTTP) can drive either mechanism
// with the same token-exchange loop. The package does not own transport:
// callers supply raw bytes in and receive raw bytes out, matching the
// primitives exposed by the underlying crypto libraries.
package spnego
