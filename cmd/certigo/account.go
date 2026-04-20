package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newAccountCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "account",
		Short: "Create, modify, or delete AD user and computer accounts via LDAP",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("account: not yet implemented (planned for M5)")
		},
	}
}
