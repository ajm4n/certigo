package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC5 - Writable PKI object paths (CA cert, AIA container, NTAuthStore,
// root trust). These are object-level issues that live outside the
// per-template scope. The Rule below is a no-op placeholder so the
// coverage matrix is explicit and the scan registry has a stable entry;
// a dedicated object-level scanner should surface real ESC5 findings.
//
// Marked INCOMPLETE: ESC5 detection requires enumerating and evaluating
// the ACLs on the PKI object containers (CN=Public Key Services,...)
// which this per-template rule has no access to.
type ESC5 struct{}

// Name implements Rule.
func (ESC5) Name() string { return "ESC5" }

// Check implements Rule. It never emits findings at the template level.
func (ESC5) Check(_ *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
	return nil
}
