package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC16 - Template's issuance policy includes a universal-group OID
// (an application policy / issuance policy OID that maps to a universal
// group). Enrolment yields unintended universal-group membership in
// authorization decisions.
//
// INCOMPLETE (partial): like ESC13, full determination requires
// resolving MsPKICertificatePolicies OIDs to their corresponding OID
// objects and inspecting msDS-OIDToGroupLink / group scope. This rule
// flags candidates by surfacing every template with issuance policies
// AND low-priv enrol, and tags the evidence with "incomplete".
type ESC16 struct{}

// Name implements Rule.
func (ESC16) Name() string { return "ESC16" }

// Check implements Rule.
func (ESC16) Check(tpl *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil {
		return nil
	}
	if len(tpl.MsPKICertificatePolicies) == 0 && len(tpl.ApplicationPolicies) == 0 {
		return nil
	}
	lowPriv := templateEnrollableByLowPriv(tpl)
	if len(lowPriv) == 0 {
		return nil
	}
	return []adcs.Finding{{
		ESC:      "ESC16",
		Severity: "low",
		Title:    "Template is an ESC16 candidate (issuance / application policies present)",
		Description: "The template publishes issuance or application policy OIDs " +
			"and is enrollable by low-privilege principals. ESC16 " +
			"applies if any of these OIDs maps to a universal group via " +
			"msDS-OIDToGroupLink. Resolve the OID objects to confirm.",
		Evidence: map[string]any{
			"issuance_policies":    tpl.MsPKICertificatePolicies,
			"application_policies": tpl.ApplicationPolicies,
			"low_priv_enrollees":   aceSIDs(lowPriv),
			"incomplete":           "msDS-OIDToGroupLink lookup required to confirm universal-group linkage",
		},
	}}
}
