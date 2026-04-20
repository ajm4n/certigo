// Package ldap wraps github.com/go-ldap/ldap/v3 with a thin dial helper and
// a credential-driven Bind that selects between simple bind, NTLM bind
// (via go-ldap's built-in NTLMBind / NTLMBindWithHash), and GSSAPI/SPNEGO
// bind (via gokrb5's spnego.SPNEGOClient plugged into the go-ldap
// GSSAPIClient interface). Higher-level subcommands hold onto the returned
// *ldap.Conn for subsequent search / modify operations.
package ldap
