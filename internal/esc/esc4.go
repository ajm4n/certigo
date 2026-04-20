package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC4 — Low-privilege principal holds WRITE_OWNER, WRITE_DACL,
// WRITE_PROPERTY, or FULL_CONTROL over the template object itself. Such
// a principal can rewrite the template into an ESC1 configuration at
// will.
type ESC4 struct{}

// Name implements Rule.
func (ESC4) Name() string { return "ESC4" }

// Check implements Rule.
func (ESC4) Check(tpl *adcs.Template, _ *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil {
		return nil
	}
	writeOwner := lowPrivAces(tpl.WriteOwner)
	writeDacl := lowPrivAces(tpl.WriteDacl)
	writeProp := lowPrivAces(tpl.WriteProperty)
	fullCtrl := lowPrivAces(tpl.FullControl)

	if len(writeOwner)+len(writeDacl)+len(writeProp)+len(fullCtrl) == 0 {
		return nil
	}

	evidence := map[string]any{}
	if len(writeOwner) > 0 {
		evidence["write_owner"] = aceSIDs(writeOwner)
	}
	if len(writeDacl) > 0 {
		evidence["write_dacl"] = aceSIDs(writeDacl)
	}
	if len(writeProp) > 0 {
		evidence["write_property"] = aceSIDs(writeProp)
	}
	if len(fullCtrl) > 0 {
		evidence["full_control"] = aceSIDs(fullCtrl)
	}

	return []adcs.Finding{{
		ESC:      "ESC4",
		Severity: "critical",
		Title:    "Low-priv principals can modify template object",
		Description: "One or more low-privilege principals hold WRITE_OWNER, " +
			"WRITE_DACL, WRITE_PROPERTY, or FULL_CONTROL on this " +
			"template. Such a principal can rewrite the template into " +
			"an ESC1 configuration and achieve domain-wide escalation.",
		Evidence: evidence,
	}}
}
