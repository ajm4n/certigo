package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC3 — Template grants the Certificate Request Agent EKU
// (1.3.6.1.4.1.311.20.2.1) to low-priv principals, enabling "enrol on
// behalf of" attacks against another (possibly privileged) target.
type ESC3 struct{}

// Name implements Rule.
func (ESC3) Name() string { return "ESC3" }

// Check implements Rule.
func (ESC3) Check(tpl *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil {
		return nil
	}
	if !contains(tpl.EKUs, CertRequestAgentEKU) {
		return nil
	}
	lowPriv := templateEnrollableByLowPriv(tpl)
	if len(lowPriv) == 0 {
		return nil
	}
	return []adcs.Finding{{
		ESC:      "ESC3",
		Severity: "high",
		Title:    "Template grants Certificate Request Agent EKU to low-priv",
		Description: "The template carries the Certificate Request Agent EKU " +
			"(1.3.6.1.4.1.311.20.2.1) and permits enrolment by " +
			"low-privilege principals. A holder of the resulting cert " +
			"can sign enrolment requests on behalf of arbitrary users.",
		Evidence: map[string]any{
			"EKUs":               tpl.EKUs,
			"low_priv_enrollees": aceSIDs(lowPriv),
		},
	}}
}
