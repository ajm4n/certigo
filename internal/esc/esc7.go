package esc

import "github.com/ajm4n/certigo/internal/adcs"

// ESC7 — Manage-CA or Manage-Certificates rights held by a low-priv
// principal. Manage-CA permits granting oneself Manage-Certificates;
// Manage-Certificates permits approving pending requests (bypassing the
// "CA certificate manager approval" flag), enabling arbitrary issuance.
//
// This rule is CA-centric. The finding is attached to every published
// template on the affected CA (the caller can dedup by ca.Name if
// desired).
type ESC7 struct{}

// Name implements Rule.
func (ESC7) Name() string { return "ESC7" }

// Check implements Rule.
func (ESC7) Check(tpl *adcs.Template, ca *adcs.CertificateAuthority) []adcs.Finding {
	if tpl == nil || ca == nil {
		return nil
	}
	manageCA := lowPrivAces(ca.ManageCARights)
	manageCert := lowPrivAces(ca.ManageCertRights)
	if len(manageCA) == 0 && len(manageCert) == 0 {
		return nil
	}
	evidence := map[string]any{"ca": ca.Name}
	if len(manageCA) > 0 {
		evidence["manage_ca"] = aceSIDs(manageCA)
	}
	if len(manageCert) > 0 {
		evidence["manage_certificates"] = aceSIDs(manageCert)
	}
	return []adcs.Finding{{
		ESC:      "ESC7",
		Severity: "high",
		Title:    "Low-priv principals hold Manage-CA or Manage-Certificates",
		Description: "Low-privilege principals can manage the CA (" + ca.Name +
			") or approve pending certificate requests. Either right " +
			"is sufficient to bypass manager-approval templates and " +
			"issue arbitrary certificates.",
		Evidence: evidence,
	}}
}
