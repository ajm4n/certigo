package output

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func TestZipFormatter(t *testing.T) {
	cas, tmpls := buildFixture(t)
	var buf bytes.Buffer
	if err := (ZipFormatter{}).Format(&buf, cas, tmpls); err != nil {
		t.Fatalf("ZipFormatter.Format: %v", err)
	}
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range r.File {
		seen[f.Name] = true
	}
	for _, want := range []string{
		"certigo_find.txt",
		"certigo_find.json",
		"ca/CORP-CA.crt",
		"templates/VulnTemplate.json",
	} {
		if !seen[want] {
			t.Errorf("zip missing %q; have %v", want, mapKeys(seen))
		}
	}

	// Sanity-check that a contained file is readable.
	for _, f := range r.File {
		if f.Name != "certigo_find.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %q: %v", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read %q: %v", f.Name, err)
		}
		var doc jsonDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("parse zipped json: %v", err)
		}
		if len(doc.Findings) != 1 {
			t.Fatalf("zipped json findings = %d, want 1", len(doc.Findings))
		}
	}
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
