package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

type parseFlags struct {
	file string
}

func newParseCmd() *cobra.Command {
	f := &parseFlags{}
	cmd := &cobra.Command{
		Use:   "parse",
		Short: "Offline parsing of AD CS EVTX logs and registry hives",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runParse(f)
		},
	}
	cmd.Flags().StringVar(&f.file, "file", "", "input file (.evtx or .reg) — required")
	return cmd
}

func runParse(f *parseFlags) error {
	if f.file == "" {
		return fmt.Errorf("parse: --file required")
	}
	ext := strings.ToLower(filepath.Ext(f.file))
	switch ext {
	case ".evtx":
		return fmt.Errorf("parse: EVTX parsing not yet implemented — use Certipy's parse command for EVTX until a pure-Go library lands")
	case ".reg":
		return fmt.Errorf("parse: registry (.reg) parsing not yet implemented — use Certipy's parse command in the meantime")
	default:
		return fmt.Errorf("parse: unknown file extension %q (want .evtx or .reg)", ext)
	}
}
