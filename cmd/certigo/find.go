package main

import (
	"fmt"
	"os"
	"strings"

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
	onlyEnrollable bool
	short          bool
	howto          bool
	scheme         string
	ldapShell      bool
	escOnly        []string
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
	cmd.Flags().BoolVar(&f.onlyEnrollable, "enrollable", false, "only return templates the current user can enroll in")
	cmd.Flags().BoolVar(&f.short, "short", false, "compact one-line-per-template summary output (equivalent to --format short)")
	cmd.Flags().BoolVar(&f.howto, "howto", false, "with --vulnerable, print a suggested exploit command under each ESC finding")
	cmd.Flags().StringVar(&f.scheme, "scheme", "", "LDAP scheme: ldap or ldaps (defaults to ldap; 636 implies ldaps)")
	cmd.Flags().BoolVar(&f.ldapShell, "ldap-shell", false, "after enumeration, drop into an interactive LDAP REPL bound as the current principal")
	cmd.Flags().StringSliceVar(&f.escOnly, "esc", nil, "only keep templates with findings of these ESCs (comma-separated or repeatable; e.g. --esc ESC1 or --esc ESC1,ESC4). Implies --vulnerable and filters the Findings list down to the matching ESCs.")
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

	p := newProgress(os.Stderr)

	p.Infof("Connecting to %s", f.dcHost)
	conn, err := ldap.DialAndBind(creds, ldap.AutoOptions{
		DCHost:             f.dcHost,
		Port:               f.port,
		UseTLS:             f.useTLS,
		Scheme:             f.scheme,
		InsecureSkipVerify: f.insecure,
	})
	if err != nil {
		return fmt.Errorf("find: %w", err)
	}
	defer func() { _ = conn.Close() }()
	p.OKf("Bound to %s as %s", f.dcHost, creds.Username)

	p.Infof("Discovering naming contexts via RootDSE")
	domainNC, configNC, err := adcs.RootDSE(conn)
	if err != nil {
		return fmt.Errorf("find: rootDSE: %w", err)
	}
	p.OKf("Configuration NC: %s", configNC)

	p.Infof("Enumerating certificate authorities")
	cas, err := adcs.EnumCAs(conn, configNC)
	if err != nil {
		return fmt.Errorf("find: enum CAs: %w", err)
	}
	p.OKf("Found %d certificate %s", len(cas), plural(len(cas), "authority", "authorities"))

	p.Infof("Enumerating certificate templates")
	templates, err := adcs.EnumTemplates(conn, configNC)
	if err != nil {
		return fmt.Errorf("find: enum templates: %w", err)
	}
	p.OKf("Found %d certificate %s", len(templates), plural(len(templates), "template", "templates"))

	p.Infof("Linking templates to publishing CAs")
	adcs.LinkPublishedTemplates(cas, templates)

	p.Infof("Resolving ACE principal SIDs")
	// Cross-domain / foreign-security-principal SIDs only resolve through
	// the Global Catalog. Best-effort dial on port 3268 - if the bound
	// DC isn't also a GC, or 3268 is firewalled, silently continue with
	// domain-only resolution.
	var gcConn *goldapConn
	if gc, gerr := ldap.DialAndBind(creds, ldap.AutoOptions{
		DCHost:             f.dcHost,
		Port:               3268,
		Scheme:             "ldap",
		InsecureSkipVerify: f.insecure,
	}); gerr == nil {
		gcConn = gc
		defer func() { _ = gc.Close() }()
		p.Infof("Global Catalog bound on :3268 for cross-domain SID resolution")
	}
	adcs.ResolveSIDs(adcs.NewLDAPSIDResolver(conn, domainNC, gcConn), cas, templates)

	p.Infof("Resolving current user group memberships")
	if idents, err := adcs.IdentitySet(conn, creds.Username, domainNC); err == nil {
		adcs.MarkEnrollableTemplates(templates, idents)
		p.OKf("Current principal in %d groups", len(idents))
	} else {
		p.Warnf("Could not resolve identity set: %v", err)
	}

	p.Infof("Running ESC1-16 detection rules")
	total := esc.Scan(templates, cas)
	vulnCount := 0
	for _, t := range templates {
		if t != nil && len(t.Findings) > 0 {
			vulnCount++
		}
	}
	p.OKf("Found %d potential %s across %d %s", total, plural(total, "finding", "findings"),
		vulnCount, plural(vulnCount, "template", "templates"))

	if len(f.escOnly) > 0 {
		templates = filterByESC(templates, f.escOnly)
		f.onlyVulnerable = true
	}
	before := len(templates)
	templates = filterTemplates(templates, f.onlyEnabled, f.onlyVulnerable, f.onlyEnrollable)
	if before != len(templates) {
		p.Infof("Applied filters: %d of %d templates remain", len(templates), before)
	}

	format := f.format
	if f.short {
		format = "short"
	}
	output.ShowHowto = f.howto && f.onlyVulnerable
	formatter, err := output.Get(format)
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

	if err := formatter.Format(w, cas, templates); err != nil {
		return err
	}

	if f.ldapShell {
		baseDN := domainToBaseDN(f.domain)
		if baseDN == "" {
			// Discover from RootDSE if --domain wasn't supplied.
			baseDN = domainNC
		}
		shell := &ldap.Shell{
			Conn:     conn,
			BaseDN:   baseDN,
			Username: creds.Username,
		}
		return shell.Run()
	}
	return nil
}

// filterByESC keeps only templates that have at least one finding whose
// ESC matches one of the requested kinds, and also trims each surviving
// template's Findings list to just those ESCs. This gives the operator
// a focused view: `--esc ESC1` shows ESC1-vulnerable templates and only
// the ESC1 line under each template's [!] Vulnerabilities block.
func filterByESC(in []*adcs.Template, kinds []string) []*adcs.Template {
	wanted := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		wanted[normalizeESC(k)] = true
	}
	out := make([]*adcs.Template, 0, len(in))
	for _, t := range in {
		if t == nil {
			continue
		}
		matched := make([]adcs.Finding, 0, len(t.Findings))
		for _, f := range t.Findings {
			if wanted[normalizeESC(f.ESC)] {
				matched = append(matched, f)
			}
		}
		if len(matched) == 0 {
			continue
		}
		t.Findings = matched
		out = append(out, t)
	}
	return out
}

// normalizeESC uppercases and trims user input so --esc esc1 / --esc ESC1
// / --esc esc01 all match.
func normalizeESC(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	return s
}

// filterTemplates narrows the output per --enabled / --vulnerable /
// --enrollable. Flags are AND-ed when more than one is set.
func filterTemplates(in []*adcs.Template, onlyEnabled, onlyVulnerable, onlyEnrollable bool) []*adcs.Template {
	if !onlyEnabled && !onlyVulnerable && !onlyEnrollable {
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
		if onlyEnrollable && !t.EnrollableByCurrentUser {
			continue
		}
		out = append(out, t)
	}
	return out
}
