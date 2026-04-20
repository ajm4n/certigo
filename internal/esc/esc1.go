package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC1 - Enrollee supplies subject + client-authentication EKU + low-priv
// principal holds Enroll right. Result: any low-priv user can request a
// cert with an arbitrary Subject / UPN SAN usable for Kerberos PKINIT
// impersonation.
type ESC1 struct{}

// Name implements Rule.
func (ESC1) Name() string { return "ESC1" }

// Check implements Rule.
func (ESC1) Check(tpl *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil {
		return nil
	}
	if tpl.MsPKICertificateNameFlag&CTFlagEnrolleeSuppliesSubject == 0 {
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
		ESC:      "ESC1",
		Severity: "critical",
		Title:    "Template allows enrollee-supplied subject with client-auth EKU",
		Description: "The template grants Enroll (or AutoEnroll) to low-privilege " +
			"principals, permits the requester to specify the subject, and " +
			"grants a client-authentication EKU. A low-priv user can enrol " +
			"a certificate with an arbitrary UPN / SAN and authenticate as " +
			"any domain principal.",
		Evidence: map[string]any{
			"msPKI-Certificate-Name-Flag": tpl.MsPKICertificateNameFlag,
			"EKUs":                        tpl.EKUs,
			"low_priv_enrollees":          aceSIDs(lowPriv),
		},
	}}
}
