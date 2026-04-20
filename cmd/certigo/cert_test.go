package main

import "testing"

// TestCertCmdFlags verifies the cert subcommand is wired with the Certipy-
// equivalent flags the user interface promises.
func TestCertCmdFlags(t *testing.T) {
	cmd := newCertCmd()
	for _, name := range []string{
		"pfx", "pem", "out-pfx", "out-pem",
		"extract-key", "extract-cert",
		"pfx-password", "out-password",
		"out", "noout",
	} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("cert cmd missing --%s flag", name)
		}
	}
}

func TestCertCmdUse(t *testing.T) {
	cmd := newCertCmd()
	if cmd.Use != "cert" {
		t.Errorf("cert cmd Use = %q, want %q", cmd.Use, "cert")
	}
}
