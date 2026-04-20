// Package shadow implements Certipy's "shadow" attack: manipulating the
// msDS-KeyCredentialLink attribute on a target user or computer account in
// Active Directory (Shadow Credentials, per Michael Grafnetter / @_dirkjan).
//
// The package provides:
//
//   - A codec for the KEYCREDENTIALLINK_BLOB binary format (MS-KPP §2.2.2)
//     with the LDAP DNBinary wrapper used by msDS-KeyCredentialLink values.
//   - A BCRYPT_RSAKEY_BLOB encoder/decoder used as the KeyMaterial payload
//     for RSA public keys.
//   - LDAP action helpers (Add / List / Info / Clear / Remove) that build or
//     mutate KeyCredential entries and push them to the directory.
//
// The command-line wrapper in cmd/certigo/shadow.go dispatches the various
// actions; the "auth" subcommand (separate) consumes the PFX produced by
// Add to perform PKINIT against the target principal.
package shadow
