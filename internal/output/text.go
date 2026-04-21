package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ajm4n/certigo/internal/adcs"
	"github.com/ajm4n/certigo/internal/esc"
)

// TextFormatter renders a human-readable report closely modelled after
// Certipy's `find -text` output. The layout is intentionally verbose and
// section-oriented so that an operator can scan results without tooling.
type TextFormatter struct{}

// Name returns the format identifier.
func (TextFormatter) Name() string { return "text" }

func init() { register(TextFormatter{}) }

// keyWidth is the label column width used for all `    key : value` rows.
// Certipy uses roughly 40 characters; we match that.
const keyWidth = 40

// Format writes the report to w.
func (TextFormatter) Format(w io.Writer, cas []*adcs.CertificateAuthority, templates []*adcs.Template) error {
	bw := newBufWriter(w)

	bw.section("Certificate Authorities")
	if len(cas) == 0 {
		bw.line("  (no certificate authorities discovered)")
		bw.blank()
	}
	for i, ca := range cas {
		if ca == nil {
			continue
		}
		bw.line(fmt.Sprintf("  %d", i))
		writeCA(bw, ca)
		bw.blank()
	}

	bw.section("Certificate Templates")
	if len(templates) == 0 {
		bw.line("  (no certificate templates discovered)")
		bw.blank()
	}
	for i, t := range templates {
		if t == nil {
			continue
		}
		bw.line(fmt.Sprintf("  %d", i))
		writeTemplate(bw, t)
		bw.blank()
	}

	return bw.err
}

func writeCA(bw *bufWriter, ca *adcs.CertificateAuthority) {
	bw.kv(1, "CA Name", ca.Name)
	if ca.DNSName != "" {
		bw.kv(1, "DNS Name", ca.DNSName)
	}
	if ca.Certificate != nil {
		bw.kv(1, "Certificate Subject", ca.Certificate.Subject.String())
		bw.kv(1, "Certificate Serial Number", fmt.Sprintf("%X", ca.Certificate.SerialNumber))
		bw.kv(1, "Certificate Validity Start", ca.Certificate.NotBefore.UTC().Format("2006-01-02 15:04:05Z"))
		bw.kv(1, "Certificate Validity End", ca.Certificate.NotAfter.UTC().Format("2006-01-02 15:04:05Z"))
	}
	bw.kv(1, "Web Enrollment", yesNo(ca.WebEnrollment))
	bw.kv(1, "Web Enrollment HTTPS", yesNo(ca.HTTPS))
	if ca.Flags != 0 {
		bw.kv(1, "CA Flags", fmt.Sprintf("0x%08x", ca.Flags))
	}
	if ca.EditFlags != 0 {
		bw.kv(1, "Edit Flags", fmt.Sprintf("0x%08x", ca.EditFlags))
	}
	if ca.RequestDisposition != 0 {
		bw.kv(1, "Request Disposition", fmt.Sprintf("0x%08x", ca.RequestDisposition))
	}

	writeAces(bw, 1, "Enrollment Rights", ca.EnrollmentRights)
	writeAces(bw, 1, "Manage CA Rights", ca.ManageCARights)
	writeAces(bw, 1, "Manage Certificates Rights", ca.ManageCertRights)

	if len(ca.EnrollmentAgents) > 0 {
		bw.kv(1, "Enrollment Agents", "")
		for _, a := range ca.EnrollmentAgents {
			bw.line(indent(2) + a)
		}
	}
	if len(ca.Templates) > 0 {
		bw.kv(1, "Published Templates", fmt.Sprintf("%d", len(ca.Templates)))
		for _, t := range ca.Templates {
			bw.line(indent(2) + t)
		}
	}
}

func writeTemplate(bw *bufWriter, t *adcs.Template) {
	name := t.DisplayName
	if name == "" {
		name = t.Name
	}
	bw.kv(1, "Template Name", name)
	if t.Name != "" && t.Name != name {
		bw.kv(1, "Template CN", t.Name)
	}
	bw.kv(1, "Enabled", yesNo(t.Enabled))
	bw.kv(1, "Schema Version", fmt.Sprintf("%d", t.SchemaVersion))
	if t.ValidityPeriod > 0 {
		bw.kv(1, "Validity Period", t.ValidityPeriod.String())
	}
	if t.RenewalPeriod > 0 {
		bw.kv(1, "Renewal Period", t.RenewalPeriod.String())
	}
	if t.MinRSAKeyLength > 0 {
		bw.kv(1, "Minimum RSA Key Length", fmt.Sprintf("%d", t.MinRSAKeyLength))
	}
	bw.kv(1, "Enrollee Supplies Subject", yesNo(t.EnrolleeSuppliesSubject))
	bw.kv(1, "Requires Manager Approval", yesNo(t.RequiresManagerApproval))
	if t.AuthorizedSignatures > 0 {
		bw.kv(1, "Authorized Signatures Required", fmt.Sprintf("%d", t.AuthorizedSignatures))
	}
	bw.kv(1, "Certificate Name Flag", fmt.Sprintf("0x%08x", t.MsPKICertificateNameFlag))
	bw.kv(1, "Enrollment Flag", fmt.Sprintf("0x%08x", t.MsPKIEnrollmentFlag))
	bw.kv(1, "Private Key Flag", fmt.Sprintf("0x%08x", t.MsPKIPrivateKeyFlag))

	if len(t.EKUs) > 0 {
		bw.kv(1, "Extended Key Usage", "")
		for _, e := range t.EKUs {
			bw.line(indent(2) + formatOID(e))
		}
	}
	if len(t.ApplicationPolicies) > 0 {
		bw.kv(1, "Application Policies", "")
		for _, e := range t.ApplicationPolicies {
			bw.line(indent(2) + formatOID(e))
		}
	}
	if len(t.MsPKICertificatePolicies) > 0 {
		bw.kv(1, "Certificate Policies", "")
		for _, e := range t.MsPKICertificatePolicies {
			bw.line(indent(2) + formatOID(e))
		}
	}
	if len(t.PublishedBy) > 0 {
		bw.kv(1, "Published By", "")
		for _, c := range t.PublishedBy {
			bw.line(indent(2) + c)
		}
	}

	writeAces(bw, 1, "Enrollment Rights", t.EnrollmentRights)
	writeAces(bw, 1, "Auto Enrollment Rights", t.AutoEnrollRights)
	writeAces(bw, 1, "Write Owner Principals", t.WriteOwner)
	writeAces(bw, 1, "Write Dacl Principals", t.WriteDacl)
	writeAces(bw, 1, "Write Property Principals", t.WriteProperty)
	writeAces(bw, 1, "Full Control Principals", t.FullControl)

	if len(t.Findings) > 0 {
		bw.line(indent(1) + "[!] Vulnerabilities")
		for _, f := range sortedFindings(t.Findings) {
			title := f.Title
			if title == "" {
				title = f.Description
			}
			line := fmt.Sprintf("%s[!] %s", indent(2), f.ESC)
			if title != "" {
				line = fmt.Sprintf("%s - %s", line, title)
			}
			if f.Severity != "" {
				line = fmt.Sprintf("%s (%s)", line, f.Severity)
			}
			bw.line(line)

			if ShowHowto {
				var ca *adcs.CertificateAuthority
				// Cheapest lookup: ACL-less caller pass; hints tolerate nil CA.
				if hint := esc.ExploitHint(f, t, ca); hint != "" {
					bw.line(indent(3) + "To exploit, run:")
					for _, l := range strings.Split(hint, "\n") {
						bw.line(indent(4) + l)
					}
				}
			}
		}
	}
}

func writeAces(bw *bufWriter, depth int, label string, aces []adcs.Ace) {
	if len(aces) == 0 {
		return
	}
	bw.kv(depth, label, "")
	for _, a := range aces {
		name := a.Name
		if name == "" {
			name = a.SID
		}
		line := indent(depth+1) + name
		if a.Rights != "" {
			line = fmt.Sprintf("%s (%s)", line, a.Rights)
		}
		bw.line(line)
	}
}

func sortedFindings(findings []adcs.Finding) []adcs.Finding {
	out := make([]adcs.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ESC < out[j].ESC })
	return out
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func indent(depth int) string { return strings.Repeat("  ", depth) }

// formatOID returns "<Friendly Name> (<oid>)" when the OID is in the known
// AD CS/X.509 map, or the bare OID otherwise. Used to print EKUs and
// application / certificate policies in a way that's readable without
// cross-referencing Microsoft's OID registry.
func formatOID(oid string) string {
	name := adcs.OIDName(oid)
	if name == oid {
		return oid
	}
	return name + " (" + oid + ")"
}

// bufWriter is a tiny io.Writer wrapper that remembers the first error so we
// can keep the write helpers expression-free.
type bufWriter struct {
	w   io.Writer
	err error
}

func newBufWriter(w io.Writer) *bufWriter { return &bufWriter{w: w} }

func (b *bufWriter) write(s string) {
	if b.err != nil {
		return
	}
	_, b.err = io.WriteString(b.w, s)
}

func (b *bufWriter) line(s string) { b.write(s + "\n") }

func (b *bufWriter) blank() { b.write("\n") }

func (b *bufWriter) section(title string) {
	b.line(fmt.Sprintf("====== %s ======", title))
	b.blank()
}

func (b *bufWriter) kv(depth int, key, value string) {
	prefix := indent(depth)
	// key left-padded to keyWidth (minus indent depth so key+indent aligns).
	pad := keyWidth - len(prefix) - len(key)
	if pad < 1 {
		pad = 1
	}
	b.line(fmt.Sprintf("%s%s%s: %s", prefix, key, strings.Repeat(" ", pad), value))
}
