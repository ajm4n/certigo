package parse

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseReg_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.reg")
	body := `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CTG-CA]
"EditFlags"=dword:00150040
"CAServerName"="ca.ctg.local"

[HKEY_LOCAL_MACHINE\Another]
"Flag"=dword:00000001
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := ParseFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[0].Fields["_path"] != `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CTG-CA` {
		t.Errorf("first path = %q", events[0].Fields["_path"])
	}
	if events[0].Fields["EditFlags"] != "dword:00150040" {
		t.Errorf("EditFlags = %q", events[0].Fields["EditFlags"])
	}
	if events[0].Fields["CAServerName"] != `"ca.ctg.local"` {
		t.Errorf("CAServerName = %q", events[0].Fields["CAServerName"])
	}
}

func TestParseFile_UnknownExt(t *testing.T) {
	_, err := ParseFile("/tmp/nope.txt")
	if err == nil {
		t.Error("expected error for unknown ext")
	}
}

func TestParseFile_EVTX(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.evtx")
	if err := os.WriteFile(path, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ParseFile(path)
	if err != ErrEVTXUnimplemented {
		t.Errorf("want ErrEVTXUnimplemented, got %v", err)
	}
}
