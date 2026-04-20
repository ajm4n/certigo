package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newCertCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cert",
		Short: "Convert, extract, and export certificates between PFX and PEM",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("cert: not yet implemented (planned for M3)")
		},
	}
}
