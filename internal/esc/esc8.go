package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC8 — CA web enrollment endpoint reachable over HTTP (no TLS) and
// NTLM allowed, enabling NTLM relay into /certsrv/ to coerce certificate
// issuance as a relayed principal.
//
// INCOMPLETE: a full determination requires probing:
//   - HTTP auth schemes offered at /certsrv/ (NTLM vs Negotiate-only),
//   - channel-binding (EPA) configuration,
//   - Extended Protection state.
//
// This rule tags CAs whose web-enrollment endpoint is reachable WITHOUT
// HTTPS; those are definitively vulnerable to cleartext NTLM relay.
// A CA with HTTPS but no EPA is a separate, probe-based detection not
// implemented here.
type ESC8 struct{}

// Name implements Rule.
func (ESC8) Name() string { return "ESC8" }

// Check implements Rule.
func (ESC8) Check(tpl *adcs.Template, ca *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil || ca == nil {
		return nil
	}
	if !ca.WebEnrollment || ca.HTTPS {
		return nil
	}
	// Only surface per-template when the template is client-auth capable.
	if !containsAny(tpl.EKUs, ClientAuthEKUs) && len(tpl.EKUs) > 0 {
		return nil
	}
	return []adcs.Finding{{
		ESC:      "ESC8",
		Severity: "critical",
		Title:    "CA web enrollment reachable over cleartext HTTP",
		Description: "The CA (" + ca.Name + ") exposes the /certsrv/ web " +
			"enrollment endpoint over HTTP without TLS. Combined with " +
			"NTLM relay (HTTP to /certsrv/), an attacker can coerce " +
			"issuance of a client-auth certificate as any relayed " +
			"principal. Note: full ESC8 validation also requires " +
			"confirming NTLM is offered and EPA is disabled; this rule " +
			"flags the cleartext-transport prerequisite only.",
		Evidence: map[string]any{
			"ca":             ca.Name,
			"web_enrollment": ca.WebEnrollment,
			"https":          ca.HTTPS,
			"incomplete":     "NTLM/EPA probes not performed",
		},
	}}
}
