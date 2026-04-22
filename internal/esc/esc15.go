package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC15 - Certificate-Based Authentication via Schannel (UPN/DNS SAN
// with weak mapping). The defect enables using a certificate with a
// requester-specified UPN/DNS SAN to authenticate via Schannel when
// the binding is weak.
//
// INCOMPLETE: the exploit depends on DC Schannel configuration
// (SCHANNEL registry keys, StrongCertificateBindingEnforcement). This
// rule flags the template-side precondition: client-auth capable
// template where the requester can dictate the SAN and the
// SID-binding security extension is absent.
type ESC15 struct{}

// Name implements Rule.
func (ESC15) Name() string { return "ESC15" }

// Check implements Rule.
func (ESC15) Check(tpl *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
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
	noSIDExt := tpl.MsPKICertificateNameFlag&CTFlagNoSecurityExtension != 0
	if !noSIDExt {
		return nil
	}
	// Manager approval defeats the attack: the reviewer catches crafted
	// SAN/UPN values before the cert is issued.
	if tpl.RequiresManagerApproval {
		return nil
	}
	lowPriv := templateEnrollableByLowPriv(tpl)
	if len(lowPriv) == 0 {
		return nil
	}
	return []adcs.Finding{{
		ESC:      "ESC15",
		Severity: "high",
		Title:    "Template is an ESC15 candidate (Schannel weak-mapping)",
		Description: "The template combines requester-supplied subject/SAN, " +
			"client-authentication EKU, and a disabled SID security " +
			"extension. Under weak Schannel certificate binding, an " +
			"attacker can authenticate as another principal via " +
			"UPN/DNS SAN spoofing.",
		Evidence: map[string]any{
			"msPKI-Certificate-Name-Flag": tpl.MsPKICertificateNameFlag,
			"EKUs":                        tpl.EKUs,
			"requires_manager_approval":   false,
			"low_priv_enrollees":          aceSIDs(lowPriv),
			"incomplete":                  "requires DC schannel binding probe",
		},
	}}
}
