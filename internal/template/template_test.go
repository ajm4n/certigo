package template

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestTemplateDN verifies the DN-assembly helper for a mix of inputs,
// including the empty-configNC fallback used by unit tests.
func TestTemplateDN(t *testing.T) {
	tests := []struct {
		name   string
		config string
		tpl    string
		want   string
	}{
		{
			name:   "standard corp NC",
			config: "CN=Configuration,DC=corp,DC=local",
			tpl:    "User",
			want:   "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
		},
		{
			name:   "nested forest NC",
			config: "CN=Configuration,DC=sub,DC=forest,DC=example,DC=com",
			tpl:    "Machine",
			want:   "CN=Machine,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sub,DC=forest,DC=example,DC=com",
		},
		{
			name:   "empty config NC returns relative DN",
			config: "",
			tpl:    "WebServer",
			want:   "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services",
		},
		{
			name:   "template name with spaces",
			config: "CN=Configuration,DC=corp,DC=local",
			tpl:    "Domain Controller",
			want:   "CN=Domain Controller,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TemplateDN(tc.config, tc.tpl)
			if got != tc.want {
				t.Errorf("TemplateDN(%q,%q)\n  got:  %s\n  want: %s", tc.config, tc.tpl, got, tc.want)
			}
		})
	}
}

// TestBackupRestoreRoundTrip_Logic exercises the JSON marshal/unmarshal
// path used by Backup/Restore without touching LDAP. We feed a synthetic
// attribute map through the same codec and confirm the round-trip is
// lossless.
func TestBackupRestoreRoundTrip_Logic(t *testing.T) {
	original := map[string][]string{
		"cn":                            {"VulnTemplate"},
		"msPKI-Certificate-Name-Flag":   {"-1509949440"},
		"msPKI-Enrollment-Flag":         {"0"},
		"msPKI-Template-Schema-Version": {"2"},
		"pKIExtendedKeyUsage": {
			"1.3.6.1.5.5.7.3.2",
			"1.3.6.1.5.2.3.4",
			"1.3.6.1.4.1.311.20.2.2",
		},
		// Empty-slice sentinel - should survive round-trip as []string{}.
		"msPKI-RA-Signature": {},
	}

	raw, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var restored map[string][]string
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// json.Unmarshal turns an empty JSON array into an empty (non-nil)
	// slice, so we normalize before comparing.
	for k, v := range restored {
		if v == nil {
			restored[k] = []string{}
		}
	}
	for k, v := range original {
		if v == nil {
			original[k] = []string{}
		}
	}

	if !reflect.DeepEqual(original, restored) {
		t.Errorf("round-trip mismatch\n  orig:     %#v\n  restored: %#v", original, restored)
	}

	// Sanity-check the marshaled form is human-readable JSON (Backup
	// produces indented output).
	if !strings.Contains(string(raw), "msPKI-Certificate-Name-Flag") {
		t.Errorf("marshaled backup missing attribute key:\n%s", raw)
	}
}

// TestVulnerableAttrs_ShapeCheck ensures VulnerableAttrs returns the
// ESC4-critical attribute set Certipy writes. We don't compare by full
// equality (so the package stays free to refine constants) but we do
// assert the mandatory keys and key-flag bits are present.
func TestVulnerableAttrs_ShapeCheck(t *testing.T) {
	got := VulnerableAttrs()

	mandatory := []string{
		"msPKI-Certificate-Name-Flag",
		"msPKI-Enrollment-Flag",
		"pKIExtendedKeyUsage",
		"msPKI-RA-Signature",
		"msPKI-Template-Schema-Version",
	}
	for _, k := range mandatory {
		if _, ok := got[k]; !ok {
			t.Errorf("VulnerableAttrs missing mandatory key %q", k)
		}
	}

	// Client Authentication EKU must be present - this is the bit that
	// makes an issued cert usable for PKINIT against the DC.
	const clientAuthOID = "1.3.6.1.5.5.7.3.2"
	foundClientAuth := false
	for _, v := range got["pKIExtendedKeyUsage"] {
		if v == clientAuthOID {
			foundClientAuth = true
			break
		}
	}
	if !foundClientAuth {
		t.Errorf("pKIExtendedKeyUsage missing Client Authentication OID %q; got %v",
			clientAuthOID, got["pKIExtendedKeyUsage"])
	}

	// Schema version must be "2" (v1 templates cannot hold the
	// name-flag bits we rewrite).
	if v := got["msPKI-Template-Schema-Version"]; len(v) != 1 || v[0] != "2" {
		t.Errorf("msPKI-Template-Schema-Version want [\"2\"], got %v", v)
	}

	// Name flag must be the exact Certipy-parity integer so find/parse
	// round-trips see the same value.
	if v := got["msPKI-Certificate-Name-Flag"]; len(v) != 1 || v[0] != "-1509949440" {
		t.Errorf("msPKI-Certificate-Name-Flag want [\"-1509949440\"], got %v", v)
	}
}

// TestWrite_NilConnRejected guards the validate() path - Write with a
// nil connection must fail fast rather than panic inside go-ldap.
func TestWrite_NilConnRejected(t *testing.T) {
	err := Write(Options{Name: "User", ConfigNC: "CN=Configuration,DC=x,DC=y"}, map[string][]string{"a": {"b"}})
	if err == nil {
		t.Fatal("Write with nil conn returned nil error")
	}
	if !strings.Contains(err.Error(), "nil ldap connection") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestRestore_NilConnRejected guards the validate() path for Restore.
func TestRestore_NilConnRejected(t *testing.T) {
	err := Restore(Options{Name: "User", ConfigNC: "CN=Configuration,DC=x,DC=y"}, []byte(`{"cn":["x"]}`))
	if err == nil {
		t.Fatal("Restore with nil conn returned nil error")
	}
	if !strings.Contains(err.Error(), "nil ldap connection") {
		t.Errorf("unexpected error: %v", err)
	}
}
