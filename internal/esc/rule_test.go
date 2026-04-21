package esc

import (
	"testing"

	"github.com/ajm4n/certigo/internal/adcs"
)

// lowPrivSID is an example domain-scoped SID that is NOT privileged -
// trailing RID 1103 is outside the privileged-RID set.
const lowPrivSID = "S-1-5-21-1111111111-2222222222-3333333333-1103"

// domainAdminsSID is a representative privileged SID (trailing -512).
const domainAdminsSID = "S-1-5-21-1111111111-2222222222-3333333333-512"

// baseEnrollable returns a Template that a low-priv user can enrol but
// is otherwise innocuous - tests tweak individual fields.
func baseEnrollable() *adcs.Template {
	return &adcs.Template{
		Name:        "Test",
		DisplayName: "Test Template",
		EnrollmentRights: []adcs.Ace{
			{SID: lowPrivSID, Name: "CORP\\alice", Rights: "ControlAccess"},
		},
	}
}

func findingByESC(t *testing.T, findings []adcs.Finding, name string) *adcs.Finding {
	t.Helper()
	for i := range findings {
		if findings[i].ESC == name {
			return &findings[i]
		}
	}
	return nil
}

func TestIsPrivileged(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sid  string
		want bool
	}{
		{"", false},
		{"S-1-5-18", true},
		{"S-1-5-32-544", true},
		{"S-1-5-32-548", true},
		{"S-1-5-32-549", true},
		{"S-1-5-32-550", true},
		{"S-1-5-32-551", true},
		{"S-1-5-9", true},
		{domainAdminsSID, true},
		{"S-1-5-21-1-2-3-519", true}, // Enterprise Admins
		{"S-1-5-21-1-2-3-518", true}, // Schema Admins
		{lowPrivSID, false},
		{"S-1-5-21-1-2-3-1000", false},
	}
	for _, tc := range cases {
		if got := IsPrivileged(tc.sid); got != tc.want {
			t.Errorf("IsPrivileged(%q) = %v, want %v", tc.sid, got, tc.want)
		}
	}
}

func TestESC1(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.MsPKICertificateNameFlag = CTFlagEnrolleeSuppliesSubject
	tpl.EKUs = []string{"1.3.6.1.5.5.7.3.2"} // clientAuth

	findings := ESC1{}.Check(tpl, nil)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].ESC != "ESC1" || findings[0].Severity != "critical" {
		t.Errorf("unexpected finding: %+v", findings[0])
	}

	// Negative: remove enrollee-supplies-subject bit.
	tpl.MsPKICertificateNameFlag = 0
	if got := (ESC1{}).Check(tpl, nil); len(got) != 0 {
		t.Errorf("expected no finding without enrollee-supplies-subject, got %v", got)
	}

	// Negative: privileged-only enrol.
	tpl.MsPKICertificateNameFlag = CTFlagEnrolleeSuppliesSubject
	tpl.EnrollmentRights = []adcs.Ace{{SID: domainAdminsSID}}
	if got := (ESC1{}).Check(tpl, nil); len(got) != 0 {
		t.Errorf("expected no finding with privileged-only enrol, got %v", got)
	}

	// Negative: manager approval is required.
	tpl = baseEnrollable()
	tpl.MsPKICertificateNameFlag = CTFlagEnrolleeSuppliesSubject
	tpl.EKUs = []string{"1.3.6.1.5.5.7.3.2"}
	tpl.RequiresManagerApproval = true
	if got := (ESC1{}).Check(tpl, nil); len(got) != 0 {
		t.Errorf("expected no finding when manager approval is required, got %v", got)
	}
}

func TestESC2(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.EKUs = []string{"2.5.29.37.0"}

	findings := ESC2{}.Check(tpl, nil)
	if len(findings) != 1 || findings[0].ESC != "ESC2" {
		t.Fatalf("want ESC2 finding, got %v", findings)
	}

	// Empty EKUs = no EKU restriction also triggers.
	tpl.EKUs = nil
	findings = ESC2{}.Check(tpl, nil)
	if len(findings) != 1 {
		t.Fatalf("want finding with no EKUs, got %v", findings)
	}
}

func TestESC3(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.EKUs = []string{CertRequestAgentEKU}

	findings := ESC3{}.Check(tpl, nil)
	if len(findings) != 1 || findings[0].ESC != "ESC3" {
		t.Fatalf("want ESC3 finding, got %v", findings)
	}

	tpl.EKUs = []string{"1.3.6.1.5.5.7.3.2"}
	if got := (ESC3{}).Check(tpl, nil); len(got) != 0 {
		t.Errorf("expected no finding without CRA EKU, got %v", got)
	}
}

func TestESC4(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.WriteDacl = []adcs.Ace{{SID: lowPrivSID}}

	findings := ESC4{}.Check(tpl, nil)
	if len(findings) != 1 || findings[0].ESC != "ESC4" {
		t.Fatalf("want ESC4 finding, got %v", findings)
	}

	tpl.WriteDacl = []adcs.Ace{{SID: domainAdminsSID}}
	if got := (ESC4{}).Check(tpl, nil); len(got) != 0 {
		t.Errorf("expected no finding with only privileged WRITE_DACL, got %v", got)
	}
}

func TestESC5(t *testing.T) {
	t.Parallel()
	if got := (ESC5{}).Check(baseEnrollable(), nil); len(got) != 0 {
		t.Errorf("ESC5 should not emit template-level findings, got %v", got)
	}
}

func TestESC6(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.EKUs = []string{"1.3.6.1.5.5.7.3.2"}
	ca := &adcs.CertificateAuthority{
		Name:      "CORP-CA",
		EditFlags: EditFlagAttributeSubjectAltName2,
	}
	findings := ESC6{}.Check(tpl, ca)
	if len(findings) != 1 || findings[0].ESC != "ESC6" {
		t.Fatalf("want ESC6 finding, got %v", findings)
	}

	ca.EditFlags = 0
	if got := (ESC6{}).Check(tpl, ca); len(got) != 0 {
		t.Errorf("expected no finding when SAN2 flag cleared, got %v", got)
	}
}

func TestESC7(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	ca := &adcs.CertificateAuthority{
		Name:           "CORP-CA",
		ManageCARights: []adcs.Ace{{SID: lowPrivSID}},
	}
	findings := ESC7{}.Check(tpl, ca)
	if len(findings) != 1 || findings[0].ESC != "ESC7" {
		t.Fatalf("want ESC7 finding, got %v", findings)
	}

	ca.ManageCARights = []adcs.Ace{{SID: domainAdminsSID}}
	ca.ManageCertRights = nil
	if got := (ESC7{}).Check(tpl, ca); len(got) != 0 {
		t.Errorf("expected no finding with privileged-only Manage-CA, got %v", got)
	}
}

func TestESC8(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.EKUs = []string{"1.3.6.1.5.5.7.3.2"}
	ca := &adcs.CertificateAuthority{
		Name:          "CORP-CA",
		WebEnrollment: true,
		HTTPS:         false,
	}
	findings := ESC8{}.Check(tpl, ca)
	if len(findings) != 1 || findings[0].ESC != "ESC8" {
		t.Fatalf("want ESC8 finding, got %v", findings)
	}

	ca.HTTPS = true
	if got := (ESC8{}).Check(tpl, ca); len(got) != 0 {
		t.Errorf("expected no finding with HTTPS=true, got %v", got)
	}
}

func TestESC9(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.MsPKICertificateNameFlag = CTFlagNoSecurityExtension
	findings := ESC9{}.Check(tpl, nil)
	if len(findings) != 1 || findings[0].ESC != "ESC9" {
		t.Fatalf("want ESC9 finding, got %v", findings)
	}

	tpl.MsPKICertificateNameFlag = 0
	if got := (ESC9{}).Check(tpl, nil); len(got) != 0 {
		t.Errorf("expected no finding without CT_FLAG_NO_SECURITY_EXTENSION, got %v", got)
	}
}

func TestESC10(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.MsPKICertificateNameFlag = CTFlagEnrolleeSuppliesSubjectAltName
	tpl.EKUs = []string{"1.3.6.1.5.5.7.3.2"}

	findings := ESC10{}.Check(tpl, nil)
	if len(findings) != 1 || findings[0].ESC != "ESC10" {
		t.Fatalf("want ESC10 finding, got %v", findings)
	}
	if findings[0].Evidence["incomplete"] == nil {
		t.Error("ESC10 evidence should carry 'incomplete' marker")
	}
}

func TestESC11(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	// CA has some flags set, but NOT the encrypt-ICPR bit.
	ca := &adcs.CertificateAuthority{
		Name:  "CORP-CA",
		Flags: 0x00000100, // arbitrary non-zero, bit 0x200 is absent
	}
	findings := ESC11{}.Check(tpl, ca)
	if len(findings) != 1 || findings[0].ESC != "ESC11" {
		t.Fatalf("want ESC11 finding, got %v", findings)
	}

	ca.Flags = CAFlagEnforceEncryptICertRequest | 0x100
	if got := (ESC11{}).Check(tpl, ca); len(got) != 0 {
		t.Errorf("expected no finding when encrypt flag set, got %v", got)
	}

	// Flags=0 means unknown -> skip.
	ca.Flags = 0
	if got := (ESC11{}).Check(tpl, ca); len(got) != 0 {
		t.Errorf("expected no finding with unknown CA flags, got %v", got)
	}
}

func TestESC13(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.MsPKICertificatePolicies = []string{"1.2.3.4.5.6"}
	findings := ESC13{}.Check(tpl, nil)
	if len(findings) != 1 || findings[0].ESC != "ESC13" {
		t.Fatalf("want ESC13 finding, got %v", findings)
	}
	if findings[0].Evidence["incomplete"] == nil {
		t.Error("ESC13 evidence should mark incomplete")
	}
}

func TestESC14(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.MsPKICertificateNameFlag = CTFlagEnrolleeSuppliesSubject
	tpl.EKUs = []string{"1.3.6.1.5.5.7.3.2"}
	findings := ESC14{}.Check(tpl, nil)
	if len(findings) != 1 || findings[0].ESC != "ESC14" {
		t.Fatalf("want ESC14 finding, got %v", findings)
	}
}

func TestESC15(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.MsPKICertificateNameFlag = CTFlagEnrolleeSuppliesSubject | CTFlagNoSecurityExtension
	tpl.EKUs = []string{"1.3.6.1.5.5.7.3.2"}
	findings := ESC15{}.Check(tpl, nil)
	if len(findings) != 1 || findings[0].ESC != "ESC15" {
		t.Fatalf("want ESC15 finding, got %v", findings)
	}

	// Drop NO_SECURITY_EXTENSION -> not ESC15.
	tpl.MsPKICertificateNameFlag = CTFlagEnrolleeSuppliesSubject
	if got := (ESC15{}).Check(tpl, nil); len(got) != 0 {
		t.Errorf("expected no ESC15 without NO_SECURITY_EXTENSION, got %v", got)
	}
}

func TestESC16(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.ApplicationPolicies = []string{"1.2.3.4"}
	findings := ESC16{}.Check(tpl, nil)
	if len(findings) != 1 || findings[0].ESC != "ESC16" {
		t.Fatalf("want ESC16 finding, got %v", findings)
	}
}

func TestScan_AccumulatesFindings(t *testing.T) {
	t.Parallel()
	tpl := baseEnrollable()
	tpl.PublishedBy = []string{"CORP-CA"}
	tpl.MsPKICertificateNameFlag = CTFlagEnrolleeSuppliesSubject
	tpl.EKUs = []string{"1.3.6.1.5.5.7.3.2"}
	ca := &adcs.CertificateAuthority{
		Name:      "CORP-CA",
		EditFlags: EditFlagAttributeSubjectAltName2,
	}

	n := Scan([]*adcs.Template{tpl}, []*adcs.CertificateAuthority{ca})
	if n == 0 {
		t.Fatal("Scan returned 0 findings")
	}
	if len(tpl.Findings) != n {
		t.Errorf("Scan returned %d but attached %d findings", n, len(tpl.Findings))
	}
	if f := findingByESC(t, tpl.Findings, "ESC1"); f == nil {
		t.Error("expected ESC1 in scan output")
	}
	if f := findingByESC(t, tpl.Findings, "ESC6"); f == nil {
		t.Error("expected ESC6 in scan output")
	}
}

func TestAllRules_Order(t *testing.T) {
	t.Parallel()
	want := []string{
		"ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC7",
		"ESC8", "ESC9", "ESC10", "ESC11", "ESC13", "ESC14", "ESC15", "ESC16",
	}
	rules := AllRules()
	if len(rules) != len(want) {
		t.Fatalf("AllRules length = %d, want %d", len(rules), len(want))
	}
	for i, r := range rules {
		if r.Name() != want[i] {
			t.Errorf("AllRules[%d] = %s, want %s", i, r.Name(), want[i])
		}
	}
}
