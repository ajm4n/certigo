package output

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/ajm4n/certigo/internal/adcs"
)

// buildFixture constructs a single-CA / single-Template / single-Finding
// fixture used by every formatter test. Keeping it in one place makes it
// easy to extend when new fields land.
func buildFixture(t *testing.T) ([]*adcs.CertificateAuthority, []*adcs.Template) {
	t.Helper()
	cert := &x509.Certificate{
		Raw:          []byte{0x30, 0x82, 0x00, 0x01}, // not a real DER cert - just non-empty bytes
		SerialNumber: big.NewInt(0xdeadbeef),
		Subject:      pkix.Name{CommonName: "CORP-CA"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	ca := &adcs.CertificateAuthority{
		Name:          "CORP-CA",
		DNSName:       "ca.corp.local",
		Certificate:   cert,
		Templates:     []string{"User", "VulnTemplate"},
		WebEnrollment: true,
		HTTPS:         false,
		Flags:         0x10,
		EditFlags:     0x00040000,
		EnrollmentRights: []adcs.Ace{
			{SID: "S-1-5-11", Name: "NT AUTHORITY\\Authenticated Users", Rights: "Enroll"},
		},
	}
	tmpl := &adcs.Template{
		Name:                     "VulnTemplate",
		DisplayName:              "Vulnerable Template",
		SchemaVersion:            2,
		ValidityPeriod:           8760 * time.Hour,
		MinRSAKeyLength:          2048,
		EnrolleeSuppliesSubject:  true,
		EKUs:                     []string{"1.3.6.1.5.5.7.3.2"},
		MsPKICertificateNameFlag: 0x00000001,
		EnrollmentRights: []adcs.Ace{
			{SID: "S-1-5-21-111-222-333-1104", Name: "CORP\\alice", Rights: "Enroll"},
		},
		PublishedBy: []string{"CORP-CA"},
		Findings: []adcs.Finding{{
			ESC:         "ESC1",
			Severity:    "critical",
			Title:       "Enrollee Can Supply Subject",
			Description: "Template allows low-priv enrollees to supply an arbitrary SAN.",
			Evidence:    map[string]any{"flag": "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT"},
		}},
	}
	return []*adcs.CertificateAuthority{ca}, []*adcs.Template{tmpl}
}

func TestGetUnknownFormat(t *testing.T) {
	if _, err := Get("xml"); err == nil {
		t.Fatalf("Get(xml) should error")
	}
}

func TestGetKnownFormats(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatalf("Names() returned empty slice; expected at least one registered formatter")
	}
	for _, name := range names {
		f, err := Get(name)
		if err != nil {
			t.Fatalf("Get(%q) error: %v", name, err)
		}
		if f.Name() != name {
			t.Fatalf("formatter %q reports Name()=%q", name, f.Name())
		}
	}
}
