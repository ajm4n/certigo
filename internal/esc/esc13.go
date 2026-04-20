package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC13 - Template issuance policy contains a certificate policy OID
// that is linked to a privileged universal/domain group (via the
// msDS-OIDToGroupLink attribute on the OID object). Enrolling the
// template confers group membership in the linked group through
// AuthZ-certmap.
//
// INCOMPLETE (partial): detecting the link requires resolving the OID
// object under CN=OID,CN=Public Key Services,... to check for a
// populated msDS-OIDToGroupLink. This rule flags templates carrying
// non-empty issuance policies (MsPKICertificatePolicies) so the caller
// can resolve them. A subsequent pass should escalate severity when
// the linked group is privileged.
type ESC13 struct{}

// Name implements Rule.
func (ESC13) Name() string { return "ESC13" }

// Check implements Rule.
func (ESC13) Check(tpl *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil {
		return nil
	}
	if len(tpl.MsPKICertificatePolicies) == 0 {
		return nil
	}
	lowPriv := templateEnrollableByLowPriv(tpl)
	if len(lowPriv) == 0 {
		return nil
	}
	return []adcs.Finding{{
		ESC:      "ESC13",
		Severity: "medium",
		Title:    "Template has issuance policy OIDs (ESC13 candidate)",
		Description: "The template publishes issuance policy OIDs and is " +
			"enrollable by low-privilege principals. ESC13 applies if " +
			"any of these OIDs is linked to a privileged group via " +
			"msDS-OIDToGroupLink. Resolve the OID objects to confirm.",
		Evidence: map[string]any{
			"issuance_policies":  tpl.MsPKICertificatePolicies,
			"low_priv_enrollees": aceSIDs(lowPriv),
			"incomplete":         "msDS-OIDToGroupLink lookup required to confirm",
		},
	}}
}
