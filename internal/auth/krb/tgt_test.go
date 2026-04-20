package krb

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestGetTGTFromCCache_Missing covers the "no path, no env" error surface.
// A synthetic positive-path roundtrip is intentionally skipped: gokrb5 v8
// doesn't expose enough of credentials.CCache to build a valid cache entry
// without a live KDC, so the happy path lives in the Tier-2 integration
// suite.
func TestGetTGTFromCCache_Missing(t *testing.T) {
	t.Setenv("KRB5CCNAME", "")
	_, err := GetTGTFromCCache("")
	if err == nil {
		t.Fatal("expected error when no path and no KRB5CCNAME, got nil")
	}
	if !strings.Contains(err.Error(), "KRB5CCNAME") {
		t.Fatalf("error should mention KRB5CCNAME, got %v", err)
	}
}

func TestGetTGTFromCCache_EnvMissingFile(t *testing.T) {
	dir := t.TempDir()
	bogus := filepath.Join(dir, "does-not-exist")
	t.Setenv("KRB5CCNAME", bogus)

	_, err := GetTGTFromCCache("")
	if err == nil {
		t.Fatal("expected error for missing ccache file, got nil")
	}
	if !strings.Contains(err.Error(), "load ccache") {
		t.Fatalf("error should mention load ccache, got %v", err)
	}
}

func TestGetTGTFromCCache_EnvFileStripsFILEPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc")
	// Point KRB5CCNAME at a missing file with the "FILE:" prefix. If the
	// prefix is stripped, we should see a "load ccache" / "no such file"
	// wrapped error referencing the bare path. If the prefix leaks
	// through, the resolved path would contain "FILE:" and that would
	// show up in the error message.
	t.Setenv("KRB5CCNAME", "FILE:"+path)

	_, err := GetTGTFromCCache("")
	if err == nil {
		t.Fatal("expected load error for missing ccache, got nil")
	}
	if strings.Contains(err.Error(), "FILE:"+path) {
		t.Fatalf("FILE: prefix not stripped: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error should reference resolved path %q, got %v", path, err)
	}
}

func TestSaveTGTToCCache_NilClient(t *testing.T) {
	if err := SaveTGTToCCache(nil, "/tmp/ignored"); err == nil {
		t.Fatal("expected error for nil client, got nil")
	}
}
