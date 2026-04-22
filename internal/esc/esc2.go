package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC2 - Template has "Any Purpose" EKU (or no EKU restriction) AND
// low-priv enrol. The resulting cert can be repurposed for client
// authentication (or arbitrary uses) even without an explicit clientAuth
// OID.
type ESC2 struct{}

// Name implements Rule.
func (ESC2) Name() string { return "ESC2" }

// Check implements Rule.
func (ESC2) Check(tpl *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil {
		return nil
	}
	hasAnyPurpose := containsAny(tpl.EKUs, AnyPurposeEKUs)
	// "No EKU restriction" - per MS-WCCE, an empty pkiExtendedKeyUsage
	// means the cert has no EKU constraint and is usable for any purpose.
	noEKU := len(tpl.EKUs) == 0
	if !hasAnyPurpose && !noEKU {
		return nil
	}
	// Manager approval defeats the attack: reviewer sees the request
	// before a cert usable for any purpose is issued.
	if tpl.RequiresManagerApproval {
		return nil
	}
	lowPriv := templateEnrollableByLowPriv(tpl)
	if len(lowPriv) == 0 {
		return nil
	}
	reason := "any-purpose EKU (2.5.29.37.0) present"
	if noEKU {
		reason = "no EKU restriction on template (any purpose)"
	}
	return []adcs.Finding{{
		ESC:      "ESC2",
		Severity: "high",
		Title:    "Template has any-purpose EKU with low-priv enrol",
		Description: "The template grants Enroll (or AutoEnroll) to low-privilege " +
			"principals and imposes no application-specific EKU " +
			"restriction (" + reason + "). The resulting certificate is " +
			"usable for client authentication and other purposes.",
		Evidence: map[string]any{
			"EKUs":                      tpl.EKUs,
			"low_priv_enrollees":        aceSIDs(lowPriv),
			"requires_manager_approval": false,
			"reason":                    reason,
		},
	}}
}
