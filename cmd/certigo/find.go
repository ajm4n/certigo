package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newFindCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "find",
		Short: "Enumerate AD CS CAs, templates, and detect ESC1-16 vulnerabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("find: not yet implemented (planned for M2)")
		},
	}
}
