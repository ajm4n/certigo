package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC16 - Template carries application-policy restrictions whose OIDs
// may map to a universal group via msDS-OIDToGroupLink. Enrolment yields
// unintended group membership in authorization decisions.
//
// Scope note: issuance-policy OIDs (msPKI-Certificate-Policy) are
// covered by ESC13. ESC16 is narrowed to ApplicationPolicies only so the
// two rules don't both fire on the same template.
//
// INCOMPLETE (partial): full determination requires resolving the OID
// objects and inspecting msDS-OIDToGroupLink / group scope. This rule
// flags candidates with populated ApplicationPolicies AND low-priv
// enrol, and tags the evidence with "incomplete".
type ESC16 struct{}

// Name implements Rule.
func (ESC16) Name() string { return "ESC16" }

// Check implements Rule.
func (ESC16) Check(tpl *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil {
		return nil
	}
	// ESC13 already covers MsPKICertificatePolicies (issuance policy OIDs).
	// Restrict ESC16 to the application-policy axis so the two rules don't
	// double-fire on every template that sets both attributes.
	if len(tpl.ApplicationPolicies) == 0 {
		return nil
	}
	lowPriv := templateEnrollableByLowPriv(tpl)
	if len(lowPriv) == 0 {
		return nil
	}
	return []adcs.Finding{{
		ESC:      "ESC16",
		Severity: "low",
		Title:    "Template is an ESC16 candidate (application policies present)",
		Description: "The template publishes application policy OIDs and is " +
			"enrollable by low-privilege principals. ESC16 applies if any " +
			"of these OIDs maps to a universal group via " +
			"msDS-OIDToGroupLink. Resolve the OID objects to confirm. " +
			"(ESC13 covers the issuance-policy axis separately.)",
		Evidence: map[string]any{
			"application_policies": tpl.ApplicationPolicies,
			"low_priv_enrollees":   aceSIDs(lowPriv),
			"incomplete":           "msDS-OIDToGroupLink lookup required to confirm universal-group linkage",
		},
	}}
}
