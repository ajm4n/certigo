package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newRelayCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "relay",
		Short: "Relay NTLM authentication to AD CS HTTP/RPC enrollment endpoints",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("relay: not yet implemented (planned for M7)")
		},
	}
}
