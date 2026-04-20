package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/auth"
	"github.com/ajm4n/certigo/internal/auth/krb"
	"github.com/ajm4n/certigo/internal/pki"
)

type authFlags struct {
	username, password, domain, hashes, dcHost string

	pfxPath, pfxPass string
	pemCert, pemKey  string

	outCCache string
	outKirbi  string

	printHash bool
}

func newAuthCmd() *cobra.Command {
	f := &authFlags{}
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate using a certificate (PKINIT or Schannel) and return a TGT or NT hash",
		Long: "Auth performs a password or certificate-based authentication to obtain a " +
			"TGT. Password/NT-hash auth uses gokrb5 AS-REQ. PKINIT (cert-based) is " +
			"available via internal/auth/pkinit but end-to-end wire integration " +
			"requires additional gokrb5 internals to land; use --pfx only after that " +
			"future milestone.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuth(f)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.username, "username", "u", "", "AD username")
	fl.StringVarP(&f.password, "password", "p", "", "AD password")
	fl.StringVarP(&f.domain, "domain", "d", "", "AD domain / realm")
	fl.StringVar(&f.hashes, "hashes", "", "NTLM hashes (LMHASH:NTHASH)")
	fl.StringVar(&f.dcHost, "dc-host", "", "KDC host or IP (required)")

	fl.StringVar(&f.pfxPath, "pfx", "", "PFX with client certificate + key (PKINIT)")
	fl.StringVar(&f.pfxPass, "pfx-password", "", "password for the PFX")
	fl.StringVar(&f.pemCert, "cert", "", "PEM cert path (used with --key)")
	fl.StringVar(&f.pemKey, "key", "", "PEM private key path (used with --cert)")

	fl.StringVar(&f.outCCache, "out-ccache", "", "write TGT to this ccache path (or $KRB5CCNAME)")
	fl.StringVar(&f.outKirbi, "out-kirbi", "", "write TGT to this .kirbi path as well")

	fl.BoolVar(&f.printHash, "print", false, "print NT hash recovered via U2U/unPACTheHash (PKINIT path; TODO)")
	return cmd
}

func runAuth(f *authFlags) error {
	if f.domain == "" {
		return fmt.Errorf("auth: --domain required")
	}
	if f.dcHost == "" {
		return fmt.Errorf("auth: --dc-host required")
	}

	// Cert-based auth (PKINIT) is not yet wire-integrated; detect and steer.
	if f.pfxPath != "" || (f.pemCert != "" && f.pemKey != "") {
		if f.pfxPath != "" {
			data, err := os.ReadFile(f.pfxPath)
			if err != nil {
				return err
			}
			if _, err := pki.LoadPFX(data, f.pfxPass); err != nil {
				return fmt.Errorf("auth: load PFX: %w", err)
			}
		}
		return fmt.Errorf("auth: PKINIT wire integration is pending — library exists in internal/auth/pkinit (DH/CMS/AuthPack), but the AS-REQ plumbing into gokrb5 is the next milestone; use password/NT-hash auth in the meantime")
	}

	if f.username == "" {
		return fmt.Errorf("auth: --username required for password/NT-hash flows")
	}

	creds := &auth.Credentials{
		Username: f.username,
		Domain:   f.domain,
		Password: f.password,
		KDCHost:  f.dcHost,
	}
	if f.hashes != "" {
		lm, nt, err := auth.ParseHashes(f.hashes)
		if err != nil {
			return err
		}
		creds.LMHash, creds.NTHash = lm, nt
	}
	if err := creds.Validate(); err != nil {
		return err
	}

	cfg, err := krb.LoadConfig(f.domain, f.dcHost)
	if err != nil {
		return fmt.Errorf("auth: load krb5 config: %w", err)
	}
	cl, err := krb.NewClient(creds, cfg)
	if err != nil {
		return fmt.Errorf("auth: build client: %w", err)
	}

	out := f.outCCache
	if out == "" {
		out = os.Getenv("KRB5CCNAME")
	}
	if out == "" {
		out = "./certigo.ccache"
	}
	if err := krb.SaveTGTToCCache(cl, out); err != nil {
		return fmt.Errorf("auth: save TGT: %w", err)
	}
	fmt.Printf("TGT saved to %s\n", out)

	if f.outKirbi != "" {
		fmt.Printf("NOTE: kirbi export from a live client session requires --print/--kirbi-from-ccache follow-up (TODO)\n")
	}
	if f.printHash {
		fmt.Printf("NOTE: --print (unPAC-the-hash) requires PKINIT U2U support which is pending\n")
	}
	return nil
}
