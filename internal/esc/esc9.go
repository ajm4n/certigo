package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC9 - Template has CT_FLAG_NO_SECURITY_EXTENSION
// (0x80000000 in ms-PKI-Certificate-Name-Flag) set. The resulting
// certificate will NOT contain the szOID_NTDS_CA_SECURITY_EXT
// (1.3.6.1.4.1.311.25.2) SID-binding extension, so a weak DC mapping
// (StrongCertificateBindingEnforcement == 1) can be abused to
// authenticate as another user via UPN spoofing.
type ESC9 struct{}

// Name implements Rule.
func (ESC9) Name() string { return "ESC9" }

// Check implements Rule.
func (ESC9) Check(tpl *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil {
		return nil
	}
	if tpl.MsPKICertificateNameFlag&CTFlagNoSecurityExtension == 0 {
		return nil
	}
	lowPriv := templateEnrollableByLowPriv(tpl)
	if len(lowPriv) == 0 {
		return nil
	}
	return []adcs.Finding{{
		ESC:      "ESC9",
		Severity: "high",
		Title:    "Template disables SID-binding security extension",
		Description: "The template has CT_FLAG_NO_SECURITY_EXTENSION set. " +
			"Certificates issued from this template omit the " +
			"szOID_NTDS_CA_SECURITY_EXT SID extension, exposing the " +
			"deployment to UPN-based authentication spoofing when the " +
			"DC's StrongCertificateBindingEnforcement is not set to 2 " +
			"(Full Enforcement).",
		Evidence: map[string]any{
			"msPKI-Certificate-Name-Flag": tpl.MsPKICertificateNameFlag,
			"low_priv_enrollees":          aceSIDs(lowPriv),
			"incomplete":                  "requires DC registry probe to confirm exploitability",
		},
	}}
}
