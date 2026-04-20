// Package certcmd implements the business logic for certigo's "cert"
// subcommand: converting between PFX and PEM, extracting just the key or
// just the certificate, and re-encrypting PFX output with a different
// password. It mirrors the semantics of Certipy's cert command
// (certipy-ad v5.0.3) so that flag combinations produce equivalent output.
//
// All I/O flows through Run, which accepts an Options struct describing
// inputs/outputs and a stdout io.Writer used when no -out target is set.
// The package intentionally performs no LDAP or AD CS operations; it is a
// pure-local PKI utility layer on top of internal/pki.
package certcmd
