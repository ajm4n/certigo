// Package adcs models Active Directory Certificate Services objects and
// provides LDAP-backed enumeration helpers.
//
// Enumeration mirrors Certipy's find module (certipy/lib/find.py). Two
// LDAP searches feed the pipeline:
//
//  1. pKIEnrollmentService objects under
//     CN=Enrollment Services,CN=Public Key Services,CN=Services,<configNC>
//     - one per CA, listing published templates, DNS name, and signing
//     certificate (see EnumCAs).
//
//  2. pKICertificateTemplate objects under
//     CN=Certificate Templates,CN=Public Key Services,CN=Services,<configNC>
//     - one per defined template, with EKUs, ms-PKI flag words, and an
//     nTSecurityDescriptor whose DACL encodes Enroll / AutoEnroll /
//     WriteDacl / WriteOwner rights per principal (see EnumTemplates).
//
// Types (CertificateAuthority, Template, Ace, Finding) live in types.go
// and form the contract consumed by the ESC rule engine in internal/esc.
package adcs
