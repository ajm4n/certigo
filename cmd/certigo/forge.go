package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newForgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "forge",
		Short: "Forge a certificate from a CA private key (Golden Certificate)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("forge: not yet implemented (planned for M4)")
		},
	}
}
