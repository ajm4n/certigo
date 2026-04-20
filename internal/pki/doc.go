// Package pki provides X.509 + PFX + CSR primitives used across certigo subcommands.
//
// The pki package is deliberately narrow: parse/build certificates, read/write
// PFX blobs, generate RSA keys, and construct CSRs with arbitrary extensions
// (including UPN-in-SAN for AD CS enrollment). Higher-level features like
// certificate forging or Schannel TLS are in other packages.
package pki
