package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC6 — The CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set in its
// EditFlags. Any enrollee can embed a SAN in their request regardless
// of template-level restrictions, effectively turning every template
// into ESC1 for SAN-based impersonation.
type ESC6 struct{}

// Name implements Rule.
func (ESC6) Name() string { return "ESC6" }

// Check implements Rule.
func (ESC6) Check(tpl *adcs.Template, ca *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil || ca == nil {
		return nil
	}
	if ca.EditFlags&EditFlagAttributeSubjectAltName2 == 0 {
		return nil
	}
	// Only interesting if the template itself is usable for client auth;
	// otherwise the SAN injection has no Kerberos impact.
	if !containsAny(tpl.EKUs, ClientAuthEKUs) && len(tpl.EKUs) > 0 {
		return nil
	}
	return []adcs.Finding{{
		ESC:      "ESC6",
		Severity: "critical",
		Title:    "CA accepts requester-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)",
		Description: "The publishing CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set in " +
			"its EditFlags. Any enrollee, on any template usable for " +
			"client authentication, can include an arbitrary SAN in the " +
			"request and impersonate another principal.",
		Evidence: map[string]any{
			"ca":            ca.Name,
			"ca_edit_flags": ca.EditFlags,
			"template_ekus": tpl.EKUs,
			"san_flag_bit":  EditFlagAttributeSubjectAltName2,
		},
	}}
}
