package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newCACmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ca",
		Short: "Manage a Certificate Authority (backup, approve/deny requests, add officers, template admin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("ca: not yet implemented (planned for M5)")
		},
	}
}
