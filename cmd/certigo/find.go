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
	username   string
	password   string
	domain     string
	hashes     string
	dcHost     string
	port       int
	useTLS     bool
	insecure   bool
	useKrb     bool
	simpleBind bool
	format     string
	out        string

	onlyEnabled    bool
	onlyVulnerable bool
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
	cmd.Flags().BoolVar(&f.simpleBind, "simple-bind", false, "use LDAP simple bind instead of NTLM (default: NTLM)")
	cmd.Flags().StringVar(&f.format, "format", "text", "output format: text|json|zip|bloodhound")
	cmd.Flags().StringVarP(&f.out, "output", "o", "", "write output to file instead of stdout")
	cmd.Flags().BoolVar(&f.onlyEnabled, "enabled", false, "only return templates published on at least one CA")
	cmd.Flags().BoolVar(&f.onlyVulnerable, "vulnerable", false, "only return templates with at least one ESC finding")
	return cmd
}

func runFind(f *findFlags) error {
	creds := &auth.Credentials{
		Username:      f.username,
		Domain:        f.domain,
		Password:      f.password,
		UseKerberos:   f.useKrb,
		UseSimpleBind: f.simpleBind,
		KDCHost:       f.dcHost,
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

	conn, err := ldap.DialAndBind(creds, ldap.AutoOptions{
		DCHost:             f.dcHost,
		Port:               f.port,
		UseTLS:             f.useTLS,
		InsecureSkipVerify: f.insecure,
	})
	if err != nil {
		return fmt.Errorf("find: %w", err)
	}
	defer func() { _ = conn.Close() }()

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

	adcs.LinkPublishedTemplates(cas, templates)
	esc.Scan(templates, cas)

	templates = filterTemplates(templates, f.onlyEnabled, f.onlyVulnerable)

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
		defer func() { _ = file.Close() }()
		w = file
	}

	return formatter.Format(w, cas, templates)
}

// filterTemplates narrows the output per --enabled / --vulnerable. Both
// flags are AND-ed when both are set.
func filterTemplates(in []*adcs.Template, onlyEnabled, onlyVulnerable bool) []*adcs.Template {
	if !onlyEnabled && !onlyVulnerable {
		return in
	}
	out := make([]*adcs.Template, 0, len(in))
	for _, t := range in {
		if t == nil {
			continue
		}
		if onlyEnabled && !t.Enabled {
			continue
		}
		if onlyVulnerable && len(t.Findings) == 0 {
			continue
		}
		out = append(out, t)
	}
	return out
}
