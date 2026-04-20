package main

import (
	"bytes"
	"strings"
	"testing"
)

// All twelve Certipy subcommands must appear in root --help output.
var expectedSubcommands = []string{
	"account", "auth", "ca", "cert", "find", "forge",
	"parse", "ptt", "relay", "req", "shadow", "template",
}

func TestRootHelpListsAllSubcommands(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, sub := range expectedSubcommands {
		if !strings.Contains(out, sub) {
			t.Errorf("help output missing subcommand %q\nfull output:\n%s", sub, out)
		}
	}
}

func TestRootVersionFlag(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("--version produced no output")
	}
}

func TestRootPersistentFlags(t *testing.T) {
	cmd := NewRootCmd()
	for _, name := range []string{"debug", "timeout"} {
		if cmd.PersistentFlags().Lookup(name) == nil {
			t.Errorf("root missing persistent flag --%s", name)
		}
	}
}
