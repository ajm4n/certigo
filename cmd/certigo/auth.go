package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newAuthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "auth",
		Short: "Authenticate using a certificate (PKINIT or Schannel) and return a TGT or NT hash",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("auth: not yet implemented (planned for M3)")
		},
	}
}
