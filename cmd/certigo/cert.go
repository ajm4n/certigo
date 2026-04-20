package main

import (
	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/certcmd"
)

func newCertCmd() *cobra.Command {
	opts := certcmd.Options{}

	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Convert, extract, and export certificates between PFX and PEM",
		Long: "Cert mirrors Certipy's certificate utility. It loads a PFX or PEM input " +
			"and can re-emit it in the other format, extract just the private key, or " +
			"extract just the certificate. Output is written to stdout unless an output " +
			"path is supplied.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return certcmd.Run(opts, cmd.OutOrStdout())
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.PFXIn, "pfx", "", "input PFX/PKCS#12 file")
	f.StringVar(&opts.PEMIn, "pem", "", "input PEM file")
	f.StringVar(&opts.PFXOut, "out-pfx", "", "write PFX output to this path")
	f.StringVar(&opts.PEMOut, "out-pem", "", "write PEM output to this path")
	f.BoolVar(&opts.ExtractKey, "extract-key", false, "emit only the private key")
	f.BoolVar(&opts.ExtractCert, "extract-cert", false, "emit only the certificate")
	f.StringVar(&opts.PFXInPassword, "pfx-password", "", "password for encrypted PFX input")
	f.StringVar(&opts.PFXOutPassword, "out-password", "", "password for encrypted PFX output")
	f.StringVar(&opts.Out, "out", "", "generic output file (format follows the input)")
	f.BoolVar(&opts.NoOut, "noout", false, "suppress stdout output")

	return cmd
}
