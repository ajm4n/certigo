// Package template implements certigo's `template` subcommand backend:
// read, write, backup, and restore of AD CS pKICertificateTemplate LDAP
// objects under CN=Certificate Templates,CN=Public Key Services,CN=Services,
// <configNC>.
//
// The operations here are the building blocks of Certipy's ESC4 exploitation
// path (an attacker with Write-DACL / WriteProperty on a template rewrites
// its msPKI-* flag attributes and EKU OIDs to make it ESC1-style
// vulnerable, enrolls, then restores the original attribute set).
//
// Shape mirrors Certipy's certipy/commands/template.py:
//
//  1. Read  - return every LDAP attribute of the target template entry.
//  2. Write - apply a map[attr][]value REPLACE delta via ldap.ModifyRequest.
//  3. Backup - JSON-marshal the full attribute set for later rollback.
//  4. Restore - apply a previously-captured Backup blob.
//
// A helper VulnerableAttrs returns the exact ms-PKI flag values Certipy
// writes when "making" a template vulnerable; the integer constants are
// mirrored verbatim from Certipy so parity diffs stay clean.
package template
