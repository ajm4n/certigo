package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newShadowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shadow",
		Short: "Add, list, clear, info, or remove msDS-KeyCredentialLink entries (Shadow Credentials)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("shadow: not yet implemented (planned for M3)")
		},
	}
}
