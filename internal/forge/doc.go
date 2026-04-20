// Package forge implements the "Golden Certificate" attack: minting arbitrary
// X.509 certificates signed by a compromised Certificate Authority (CA)
// private key.
//
// forge mirrors Certipy's forge subcommand (see certipy/commands/forge.py).
// Given a CA PFX, it produces a new RSA keypair and certificate bound to an
// attacker-chosen UPN / DNS / AD SID, signed by the CA. The resulting
// certificate authenticates to AD CS-backed services (PKINIT, Schannel) as
// the impersonated user.
//
// The most important Microsoft extension emitted by forge is the
// NTDS-CA-Security-Ext (OID 1.3.6.1.4.1.311.25.2), which binds a certificate
// to a specific AD SID. Since Windows 2022, StrongCertificateBindingEnforcement
// requires this extension for certificate-based AD authentication to succeed
// when the UPN does not already match the target account.
package forge
