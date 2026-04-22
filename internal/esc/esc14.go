package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC14 - Template lets the requester dictate altSecurityIdentities
// (explicit certificate-to-account mapping). When the DC honours weak
// altSecurityIdentities mappings, a cert crafted by a low-priv user
// can be mapped to a privileged account.
//
// This detection is currently a heuristic overlap with ESC1/ESC10:
// templates that allow enrollee-supplied subject/SAN and grant
// client-auth EKUs are tagged as ESC14 candidates.
//
// INCOMPLETE: confirming exploitability requires inspecting the DC's
// altSecurityIdentities handling (registry / schannel settings).
type ESC14 struct{}

// Name implements Rule.
func (ESC14) Name() string { return "ESC14" }

// Check implements Rule.
func (ESC14) Check(tpl *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil {
		return nil
	}
	supplies := tpl.MsPKICertificateNameFlag&CTFlagEnrolleeSuppliesSubject != 0 ||
		tpl.MsPKICertificateNameFlag&CTFlagEnrolleeSuppliesSubjectAltName != 0
	if !supplies {
		return nil
	}
	if !containsAny(tpl.EKUs, ClientAuthEKUs) {
		return nil
	}
	// Manager approval defeats the mapping-abuse attack: a reviewer sees
	// the crafted subject/SAN before issuance.
	if tpl.RequiresManagerApproval {
		return nil
	}
	lowPriv := templateEnrollableByLowPriv(tpl)
	if len(lowPriv) == 0 {
		return nil
	}
	return []adcs.Finding{{
		ESC:      "ESC14",
		Severity: "medium",
		Title:    "Template is an ESC14 candidate (requester supplies identity)",
		Description: "The template permits enrollee-supplied subject/SAN and " +
			"is usable for client authentication. If the DC honours " +
			"explicit altSecurityIdentities mappings without strong " +
			"binding, an attacker can enrol a cert that maps to an " +
			"arbitrary account.",
		Evidence: map[string]any{
			"msPKI-Certificate-Name-Flag": tpl.MsPKICertificateNameFlag,
			"EKUs":                        tpl.EKUs,
			"requires_manager_approval":   false,
			"low_priv_enrollees":          aceSIDs(lowPriv),
			"incomplete":                  "requires DC altSecurityIdentities / schannel probe",
		},
	}}
}
