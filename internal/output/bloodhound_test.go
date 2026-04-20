package output

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestBloodHoundFormatter(t *testing.T) {
	cas, tmpls := buildFixture(t)
	var buf bytes.Buffer
	if err := (BloodHoundFormatter{}).Format(&buf, cas, tmpls); err != nil {
		t.Fatalf("BloodHoundFormatter.Format: %v", err)
	}
	var doc bhDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal bloodhound: %v", err)
	}
	if len(doc.Graph.Edges) == 0 {
		t.Fatalf("expected at least 1 edge, got 0")
	}
	foundESC1 := false
	for _, e := range doc.Graph.Edges {
		if e.Kind == "ADCSESC1" {
			foundESC1 = true
			if e.Start.Value == "" || e.End.Value == "" {
				t.Errorf("edge missing endpoints: %+v", e)
			}
			if tn, _ := e.Properties["templateName"].(string); tn != "VulnTemplate" {
				t.Errorf("edge templateName = %v, want VulnTemplate", e.Properties["templateName"])
			}
		}
	}
	if !foundESC1 {
		t.Fatalf("no ADCSESC1 edge in output: %+v", doc.Graph.Edges)
	}
	if len(doc.Graph.Nodes) == 0 {
		t.Fatalf("expected at least 1 node, got 0")
	}
}
