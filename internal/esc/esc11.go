package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC11 - The CA does not require ICPR packet encryption
// (IF_ENFORCEENCRYPTICERTREQUEST is not set on the CA's interface
// flags). An unauthenticated attacker on the network path can relay /
// replay request RPC traffic.
type ESC11 struct{}

// Name implements Rule.
func (ESC11) Name() string { return "ESC11" }

// Check implements Rule.
func (ESC11) Check(tpl *adcs.Template, ca *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil || ca == nil {
		return nil
	}
	if ca.Flags&CAFlagEnforceEncryptICertRequest != 0 {
		return nil // enforcement is on - not vulnerable
	}
	// Require that ca.Flags was actually populated; a zero value that
	// reflects "we didn't read the flags" would create false positives.
	// We treat a nil/zero Flags as "unknown" and skip.
	if ca.Flags == 0 {
		return nil
	}
	return []adcs.Finding{{
		ESC:      "ESC11",
		Severity: "medium",
		Title:    "CA does not enforce ICPR request encryption",
		Description: "The CA (" + ca.Name + ") has not set " +
			"IF_ENFORCEENCRYPTICERTREQUEST, permitting unencrypted " +
			"ICertPassage RPC traffic. An attacker able to observe or " +
			"relay the network path can impersonate the requester.",
		Evidence: map[string]any{
			"ca":       ca.Name,
			"ca_flags": ca.Flags,
		},
	}}
}
