package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/auth/krb"
)

type pttFlags struct {
	kirbiPath  string
	ccachePath string
	outCCache  string
}

func newPttCmd() *cobra.Command {
	f := &pttFlags{}
	cmd := &cobra.Command{
		Use:   "ptt",
		Short: "Pass-the-ticket: write ccache (all platforms); inject into LSA (Windows only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPtt(f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.kirbiPath, "kirbi", "", "input .kirbi path (mutually exclusive with --ccache)")
	fl.StringVar(&f.ccachePath, "ccache", "", "input ccache path (mutually exclusive with --kirbi)")
	fl.StringVar(&f.outCCache, "out-ccache", "", "output ccache path (default $KRB5CCNAME or ./certigo.ccache)")
	return cmd
}

func runPtt(f *pttFlags) error {
	if (f.kirbiPath == "") == (f.ccachePath == "") {
		return fmt.Errorf("ptt: exactly one of --kirbi or --ccache required")
	}

	out := f.outCCache
	if out == "" {
		if v := os.Getenv("KRB5CCNAME"); v != "" {
			out = v
		} else {
			out = "./certigo.ccache"
		}
	}

	if f.kirbiPath != "" {
		// Round-trip through our kirbi codec to validate the input parses.
		if _, err := krb.ReadKirbi(f.kirbiPath); err != nil {
			return fmt.Errorf("ptt: read kirbi: %w", err)
		}
		// NOTE: kirbi → MIT ccache marshaling is not yet implemented.
		// Copy the kirbi bytes verbatim; caller can use a .kirbi-aware consumer.
		data, err := os.ReadFile(f.kirbiPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(out, data, 0o600); err != nil {
			return err
		}
		fmt.Printf("kirbi copied to %s (full ccache conversion pending)\n", out)
		return nil
	}

	// Passing ccache through: copy input -> output.
	src, err := os.ReadFile(f.ccachePath)
	if err != nil {
		return fmt.Errorf("ptt: read ccache: %w", err)
	}
	if err := os.WriteFile(out, src, 0o600); err != nil {
		return err
	}
	fmt.Printf("ticket written to %s\n", out)
	return nil
}
