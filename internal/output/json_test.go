package output

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJSONFormatter(t *testing.T) {
	cas, tmpls := buildFixture(t)
	var buf bytes.Buffer
	if err := (JSONFormatter{}).Format(&buf, cas, tmpls); err != nil {
		t.Fatalf("JSONFormatter.Format: %v", err)
	}
	var doc jsonDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal JSON output: %v", err)
	}
	if len(doc.CAs) != 1 || doc.CAs[0].Name != "CORP-CA" {
		t.Fatalf("CAs = %+v, want single CORP-CA", doc.CAs)
	}
	if len(doc.Templates) != 1 || doc.Templates[0].Name != "VulnTemplate" {
		t.Fatalf("Templates = %+v, want single VulnTemplate", doc.Templates)
	}
	if len(doc.Findings) != 1 || doc.Findings[0].ESC != "ESC1" {
		t.Fatalf("Findings = %+v, want single ESC1", doc.Findings)
	}
	if doc.Stats.CACount != 1 || doc.Stats.TemplateCount != 1 || doc.Stats.FindingCount != 1 {
		t.Fatalf("Stats = %+v, want 1/1/1", doc.Stats)
	}
}
