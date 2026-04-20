package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newTemplateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "template",
		Short: "Read, write, or backup certificate template objects via LDAP (ESC4)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("template: not yet implemented (planned for M5)")
		},
	}
}
