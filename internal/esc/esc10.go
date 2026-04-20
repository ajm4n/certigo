package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC10 — DC has StrongCertificateBindingEnforcement weak (== 0) OR
// CertificateMappingMethods allows weak UPN/implicit mapping, combined
// with a template that allows the requester to dictate the SAN/UPN.
//
// INCOMPLETE: the DC-side registry values cannot be inspected from LDAP
// alone. This rule flags the *template-side* prerequisite: templates
// whose SAN is requester-specifiable (either via
// CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME or
// CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT). Actual ESC10 exploitability
// requires a DC registry probe.
type ESC10 struct{}

// Name implements Rule.
func (ESC10) Name() string { return "ESC10" }

// Check implements Rule.
func (ESC10) Check(tpl *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil {
		return nil
	}
	sanByRequester := tpl.MsPKICertificateNameFlag&CTFlagEnrolleeSuppliesSubjectAltName != 0 ||
		tpl.MsPKICertificateNameFlag&CTFlagEnrolleeSuppliesSubject != 0
	if !sanByRequester {
		return nil
	}
	if !containsAny(tpl.EKUs, ClientAuthEKUs) {
		return nil
	}
	lowPriv := templateEnrollableByLowPriv(tpl)
	if len(lowPriv) == 0 {
		return nil
	}
	return []adcs.Finding{{
		ESC:      "ESC10",
		Severity: "medium",
		Title:    "Template is an ESC10 candidate (SAN specifiable by requester)",
		Description: "The template permits the requester to supply its subject " +
			"or SAN and is usable for client authentication. If the DC's " +
			"StrongCertificateBindingEnforcement or " +
			"CertificateMappingMethods registry values are weak, ESC10 " +
			"applies. Confirm via DC registry probe.",
		Evidence: map[string]any{
			"msPKI-Certificate-Name-Flag": tpl.MsPKICertificateNameFlag,
			"EKUs":                        tpl.EKUs,
			"low_priv_enrollees":          aceSIDs(lowPriv),
			"incomplete":                  "requires DC registry probe for definitive exploitability",
		},
	}}
}
