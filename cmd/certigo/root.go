package main

import (
	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/version"
)

// rootFlags holds persistent flags attached to the root cobra command.
// Subcommands read these via globalDebug() / globalTimeout() accessors.
type rootFlags struct {
	debug   bool
	timeout int
}

// root-level flag state stored at package scope so subcommands can read
// --debug and --timeout without plumbing the struct through every call.
var globalRootFlags = &rootFlags{timeout: 30}

func globalDebug() bool { return globalRootFlags.debug }
func globalTimeout() int {
	if globalRootFlags.timeout <= 0 {
		return 30
	}
	return globalRootFlags.timeout
}

// NewRootCmd constructs the root cobra command with all subcommands wired in.
// It's a constructor (not a package-level var) so tests can build fresh trees.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "certigo",
		Short:         "ADCS enumeration and exploitation tool in Go",
		Long:          "Certigo is an ADCS enumeration and exploitation tool in Go. Heavily based on ly4k's Certipy.",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().BoolVar(&globalRootFlags.debug, "debug", false, "enable debug logging")
	root.PersistentFlags().IntVar(&globalRootFlags.timeout, "timeout", 30, "connection timeout in seconds")

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
