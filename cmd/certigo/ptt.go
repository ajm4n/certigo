package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newPttCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ptt",
		Short: "Pass-the-ticket: write ccache (all platforms); inject into LSA (Windows only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("ptt: not yet implemented (planned for M6)")
		},
	}
}
