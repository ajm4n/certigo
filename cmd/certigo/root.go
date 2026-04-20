package main

import (
	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/version"
)

// rootFlags holds persistent flags attached to the root cobra command.
// Subcommands read these via cmd.Flags().Lookup or by capturing the vars.
type rootFlags struct {
	debug   bool
	timeout int
}

// NewRootCmd constructs the root cobra command with all subcommands wired in.
// It's a constructor (not a package-level var) so tests can build fresh trees.
func NewRootCmd() *cobra.Command {
	flags := &rootFlags{}

	root := &cobra.Command{
		Use:           "certigo",
		Short:         "Active Directory Certificate Services enumeration and abuse (Go port of Certipy)",
		Long:          "Certigo is a pure-Go 1:1 port of Certipy (certipy-ad v5.0.3) providing AD CS enumeration and abuse capabilities in a single static binary.",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().BoolVar(&flags.debug, "debug", false, "enable debug logging")
	root.PersistentFlags().IntVar(&flags.timeout, "timeout", 10, "connection timeout in seconds")

	root.AddCommand(
		newAccountCmd(),
		newAuthCmd(),
		newCACmd(),
		newCertCmd(),
		newFindCmd(),
		newForgeCmd(),
		newParseCmd(),
		newPttCmd(),
		newRelayCmd(),
		newReqCmd(),
		newShadowCmd(),
		newTemplateCmd(),
	)

	return root
}
