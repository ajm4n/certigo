package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/parse"
)

type parseFlags struct {
	file   string
	format string
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
	cmd.Flags().StringVar(&f.file, "file", "", "input file (.reg or .evtx)")
	cmd.Flags().StringVar(&f.format, "format", "text", "output format: text|json")
	return cmd
}

func runParse(f *parseFlags) error {
	if f.file == "" {
		return fmt.Errorf("parse: --file required")
	}
	events, err := parse.ParseFile(f.file)
	if err != nil {
		return err
	}
	switch f.format {
	case "json":
		out, _ := json.MarshalIndent(events, "", "  ")
		fmt.Println(string(out))
	default:
		for _, e := range events {
			fmt.Printf("== %s\n", e.Fields["_path"])
			keys := make([]string, 0, len(e.Fields))
			for k := range e.Fields {
				if k == "_path" {
					continue
				}
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("  %s = %s\n", k, e.Fields[k])
			}
		}
	}
	return nil
}
