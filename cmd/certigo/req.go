package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newReqCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "req",
		Short: "Request a certificate via RPC, web enrollment, DCOM, KDC-Proxy, or Schannel",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("req: not yet implemented (planned for M4)")
		},
	}
}
