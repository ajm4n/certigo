package adcs

import (
	"encoding/binary"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// buildEntry fabricates a *goldap.Entry whose attribute values can be
// set either as strings or as raw byte slices. Used by tests to exercise
// parseCA / parseTemplate against synthetic LDAP responses.
func buildEntry(dn string, stringAttrs map[string][]string, byteAttrs map[string][][]byte) *goldap.Entry {
	e := goldap.NewEntry(dn, stringAttrs)
	for name, vals := range byteAttrs {
		// Mirror the string values to reuse GetAttributeValue if any
		// test reaches for them; primary consumer is GetRawAttributeValue.
		strs := make([]string, len(vals))
		for i, v := range vals {
			strs[i] = string(v)
		}
		e.Attributes = append(e.Attributes, &goldap.EntryAttribute{
			Name:       name,
			Values:     strs,
			ByteValues: vals,
		})
	}
	return e
}

func TestParseCA_MinimalFields(t *testing.T) {
	entry := buildEntry(
		"CN=CORP-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
		map[string][]string{
			AttrCN:                   {"CORP-CA"},
			AttrName:                 {"CORP-CA"},
			AttrDNSHostName:          {"dc01.corp.local"},
			AttrCertificateTemplates: {"User", "Machine"},
			AttrFlags:                {"10"},
		},
		nil,
	)
	ca, err := parseCA(entry)
	if err != nil {
		t.Fatalf("parseCA: %v", err)
	}
	if ca.Name != "CORP-CA" {
		t.Errorf("Name = %q, want CORP-CA", ca.Name)
	}
	if ca.DNSName != "dc01.corp.local" {
		t.Errorf("DNSName = %q, want dc01.corp.local", ca.DNSName)
	}
	if len(ca.Templates) != 2 || ca.Templates[0] != "User" || ca.Templates[1] != "Machine" {
		t.Errorf("Templates = %v, want [User Machine]", ca.Templates)
	}
	if ca.Flags != 10 {
		t.Errorf("Flags = %d, want 10", ca.Flags)
	}
	if ca.RawAttrs == nil {
		t.Error("RawAttrs should be populated")
	}
}

func TestParseCA_MissingNameErrors(t *testing.T) {
	entry := buildEntry("CN=broken", map[string][]string{}, nil)
	if _, err := parseCA(entry); err == nil {
		t.Fatal("parseCA should error on entry without cn/name")
	}
}

func TestParseCA_NilEntry(t *testing.T) {
	if _, err := parseCA(nil); err == nil {
		t.Fatal("parseCA(nil) should error")
	}
}

func TestParseTemplate_Fields(t *testing.T) {
	// pKIExpirationPeriod for ~1 year, encoded as a negative FILETIME
	// delta (100-ns ticks). 1 year ≈ 365 * 24 * 3600 * 10_000_000 ticks.
	oneYearTicks := int64(365) * 24 * 60 * 60 * 10_000_000
	expirationRaw := make([]byte, 8)
	binary.LittleEndian.PutUint64(expirationRaw, uint64(-oneYearTicks))

	// 6-week renewal window, same sign convention.
	sixWeekTicks := int64(42) * 24 * 60 * 60 * 10_000_000
	overlapRaw := make([]byte, 8)
	binary.LittleEndian.PutUint64(overlapRaw, uint64(-sixWeekTicks))

	entry := buildEntry(
		"CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
		map[string][]string{
			AttrCN:                              {"User"},
			AttrName:                            {"User"},
			AttrDisplayName:                     {"User Template"},
			AttrPKITemplateSchemaVersion:        {"2"},
			AttrPKIMinimalKeySize:               {"2048"},
			AttrPKIRASignature:                  {"0"},
			AttrExtKeyUsage:                     {"1.3.6.1.5.5.7.3.2"},
			AttrPKICertificateApplicationPolicy: {"1.3.6.1.5.5.7.3.2"},
			AttrPKICertificatePolicy:            {"1.3.6.1.4.1.311.21.8.1"},
			// 0x00000001 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
			AttrPKICertificateNameFlag: {"1"},
			// 0x00000002 = CT_FLAG_PEND_ALL_REQUESTS (manager approval)
			AttrPKIEnrollmentFlag:  {"2"},
			AttrPKIPrivateKeyFlag: {"16"},
		},
		map[string][][]byte{
			AttrPKIExpirationPeriod: {expirationRaw},
			AttrPKIOverlapPeriod:    {overlapRaw},
		},
	)

	tpl, err := parseTemplate(entry)
	if err != nil {
		t.Fatalf("parseTemplate: %v", err)
	}
	if tpl.Name != "User" {
		t.Errorf("Name = %q, want User", tpl.Name)
	}
	if tpl.DisplayName != "User Template" {
		t.Errorf("DisplayName = %q", tpl.DisplayName)
	}
	if tpl.SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d, want 2", tpl.SchemaVersion)
	}
	if tpl.MinRSAKeyLength != 2048 {
		t.Errorf("MinRSAKeyLength = %d, want 2048", tpl.MinRSAKeyLength)
	}
	if !tpl.EnrolleeSuppliesSubject {
		t.Error("EnrolleeSuppliesSubject should be true")
	}
	if !tpl.RequiresManagerApproval {
		t.Error("RequiresManagerApproval should be true")
	}
	if len(tpl.EKUs) != 1 || tpl.EKUs[0] != "1.3.6.1.5.5.7.3.2" {
		t.Errorf("EKUs = %v", tpl.EKUs)
	}
	if tpl.MsPKICertificateNameFlag != 1 {
		t.Errorf("MsPKICertificateNameFlag = %d", tpl.MsPKICertificateNameFlag)
	}

	// Validity should be about 365 days; allow a small tolerance.
	wantValidity := 365 * 24 * time.Hour
	if delta := tpl.ValidityPeriod - wantValidity; delta < -time.Hour && delta > time.Hour {
		t.Errorf("ValidityPeriod = %s, want ~%s", tpl.ValidityPeriod, wantValidity)
	}
	wantRenewal := 42 * 24 * time.Hour
	if delta := tpl.RenewalPeriod - wantRenewal; delta < -time.Hour && delta > time.Hour {
		t.Errorf("RenewalPeriod = %s, want ~%s", tpl.RenewalPeriod, wantRenewal)
	}
}

func TestParseTemplate_MissingName(t *testing.T) {
	entry := buildEntry("CN=x", map[string][]string{}, nil)
	if _, err := parseTemplate(entry); err == nil {
		t.Fatal("parseTemplate should error on entry without cn/name")
	}
}

func TestParseUint32_SignedNegative(t *testing.T) {
	// Some DCs return msPKI-Certificate-Name-Flag as a signed int
	// (e.g. "-2147483648" for 0x80000000). parseUint32 must accept it.
	got := parseUint32("-2147483648")
	if got != 0x80000000 {
		t.Errorf("parseUint32(-2147483648) = 0x%x, want 0x80000000", got)
	}
}

func TestParseFileTimeDelta_Short(t *testing.T) {
	if d := parseFileTimeDelta([]byte{0x00, 0x00, 0x00}); d != 0 {
		t.Errorf("short input should return 0, got %s", d)
	}
}

func TestJoinDN(t *testing.T) {
	if got := JoinDN("CN=X", "DC=corp,DC=local"); got != "CN=X,DC=corp,DC=local" {
		t.Errorf("JoinDN = %q", got)
	}
	if got := JoinDN("CN=X", ""); got != "CN=X" {
		t.Errorf("JoinDN empty base = %q", got)
	}
}
