package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/adcs"
	"github.com/ajm4n/certigo/internal/auth"
	"github.com/ajm4n/certigo/internal/esc"
	"github.com/ajm4n/certigo/internal/ldap"
	"github.com/ajm4n/certigo/internal/output"
)

type findFlags struct {
	username string
	password string
	domain   string
	hashes   string
	dcHost   string
	port     int
	useTLS   bool
	insecure bool
	useKrb   bool
	format   string
	out      string
}

func newFindCmd() *cobra.Command {
	f := &findFlags{}
	cmd := &cobra.Command{
		Use:   "find",
		Short: "Enumerate AD CS CAs, templates, and detect ESC1-16 vulnerabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFind(f)
		},
	}
	cmd.Flags().StringVarP(&f.username, "username", "u", "", "AD username")
	cmd.Flags().StringVarP(&f.password, "password", "p", "", "AD password")
	cmd.Flags().StringVarP(&f.domain, "domain", "d", "", "AD domain (e.g. ctg.local)")
	cmd.Flags().StringVar(&f.hashes, "hashes", "", "NTLM hashes (LMHASH:NTHASH)")
	cmd.Flags().StringVar(&f.dcHost, "dc-host", "", "domain controller host or IP")
	cmd.Flags().IntVar(&f.port, "port", 389, "LDAP port (636 = LDAPS)")
	cmd.Flags().BoolVar(&f.useTLS, "ldaps", false, "use LDAPS (auto-enabled for port 636)")
	cmd.Flags().BoolVar(&f.insecure, "ldap-insecure", false, "skip TLS certificate verification")
	cmd.Flags().BoolVarP(&f.useKrb, "kerberos", "k", false, "use Kerberos GSSAPI bind")
	cmd.Flags().StringVar(&f.format, "format", "text", "output format: text|json|zip|bloodhound")
	cmd.Flags().StringVarP(&f.out, "output", "o", "", "write output to file instead of stdout")
	return cmd
}

func runFind(f *findFlags) error {
	creds := &auth.Credentials{
		Username:    f.username,
		Domain:      f.domain,
		Password:    f.password,
		UseKerberos: f.useKrb,
		KDCHost:     f.dcHost,
	}
	if f.hashes != "" {
		lm, nt, err := auth.ParseHashes(f.hashes)
		if err != nil {
			return fmt.Errorf("find: %w", err)
		}
		creds.LMHash = lm
		creds.NTHash = nt
	}
	if err := creds.Validate(); err != nil {
		return fmt.Errorf("find: %w", err)
	}

	server := f.dcHost
	if server == "" {
		return fmt.Errorf("find: --dc-host required")
	}
	useTLS := f.useTLS || f.port == 636

	conn, err := ldap.Dial(ldap.DialOptions{
		Server:             fmt.Sprintf("%s:%d", server, f.port),
		UseTLS:             useTLS,
		InsecureSkipVerify: f.insecure,
	})
	if err != nil {
		return fmt.Errorf("find: ldap dial: %w", err)
	}
	defer conn.Close()

	spn := ""
	if creds.UseKerberos {
		spn = fmt.Sprintf("ldap/%s", server)
	}
	if err := ldap.Bind(conn, creds, spn); err != nil {
		return fmt.Errorf("find: ldap bind: %w", err)
	}

	_, configNC, err := adcs.RootDSE(conn)
	if err != nil {
		return fmt.Errorf("find: rootDSE: %w", err)
	}

	cas, err := adcs.EnumCAs(conn, configNC)
	if err != nil {
		return fmt.Errorf("find: enum CAs: %w", err)
	}

	templates, err := adcs.EnumTemplates(conn, configNC)
	if err != nil {
		return fmt.Errorf("find: enum templates: %w", err)
	}

	esc.Scan(templates, cas)

	formatter, err := output.Get(f.format)
	if err != nil {
		return fmt.Errorf("find: %w", err)
	}

	w := os.Stdout
	if f.out != "" {
		file, err := os.Create(f.out)
		if err != nil {
			return fmt.Errorf("find: open output: %w", err)
		}
		defer file.Close()
		w = file
	}

	return formatter.Format(w, cas, templates)
}
