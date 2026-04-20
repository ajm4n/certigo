package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newParseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "parse",
		Short: "Offline parsing of AD CS EVTX logs and registry hives",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("parse: not yet implemented (planned for M6)")
		},
	}
}
