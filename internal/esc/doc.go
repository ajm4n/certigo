// Package esc implements detection rules for Active Directory Certificate
// Services (AD CS) template and CA misconfigurations commonly known as the
// "ESCx" escalation classes (ESC1 through ESC16) documented in
// SpecterOps's "Certified Pre-Owned" paper and expanded by the Certipy
// project.
//
// Each rule implements the Rule interface and takes a single *adcs.Template
// plus its publishing *adcs.CertificateAuthority (which may be nil when the
// template is unpublished). Rules are side-effect-free on their inputs and
// return zero or more adcs.Finding values describing the detected issue.
//
// The Scan helper orchestrates every registered rule against a slice of
// templates, appending findings onto each Template's Findings field.
//
// Detection coverage matrix:
//
//	ESC1-ESC7     fully detectable from Template + CA fields
//	ESC8          partial - flagged when WebEnrollment && !HTTPS; NTLM
//	              channel-binding/EPA probes are out of scope here
//	ESC9, ESC14   fully detectable from template name-flag bits
//	ESC10, ESC15  heuristic - require DC registry probes; we flag templates
//	              whose SAN is requester-specifiable as *candidates*
//	ESC11         partial - requires CA flag bit; we inspect
//	              CertificateAuthority.Flags
//	ESC13, ESC16  detected by inspecting issuance-policy OIDs referenced by
//	              the template; privileged-group/universal-group linkage is
//	              surfaced with the OID so the caller can resolve it
//
// Rules NEVER mutate their input beyond what Scan does (it appends to
// Template.Findings). Do not place detection logic outside this package.
package esc
