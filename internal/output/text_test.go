package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestTextFormatter(t *testing.T) {
	cas, tmpls := buildFixture(t)
	var buf bytes.Buffer
	if err := (TextFormatter{}).Format(&buf, cas, tmpls); err != nil {
		t.Fatalf("TextFormatter.Format: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Certificate Authorities",
		"Certificate Templates",
		"CORP-CA",
		"VulnTemplate",
		"ESC1",
		"Enrollee Can Supply Subject",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n---\n%s", want, out)
		}
	}
}
