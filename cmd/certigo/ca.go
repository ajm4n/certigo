package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/adcs"
	"github.com/ajm4n/certigo/internal/auth"
	"github.com/ajm4n/certigo/internal/ca"
	"github.com/ajm4n/certigo/internal/ldap"
)

type caFlags struct {
	username, password, domain, hashes, dcHost string
	port                                       int
	useTLS, insecure, useKrb                   bool

	caName       string
	addTemplate  string
	removeTpl    string
	listTpl      bool
	listOfficers bool

	backup       bool
	issueRequest int
	denyRequest  int
	addOfficer   string
	removeOfficer string
}

func newCACmd() *cobra.Command {
	f := &caFlags{}
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage a Certificate Authority (backup, approve/deny requests, add officers, template admin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCA(f)
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

	fl.StringVar(&f.caName, "ca-name", "", "Enterprise CA common name (required)")
	fl.StringVar(&f.addTemplate, "add-template", "", "publish this template on the CA")
	fl.StringVar(&f.removeTpl, "disable-template", "", "unpublish this template on the CA")
	fl.BoolVar(&f.listTpl, "list-templates", false, "list published templates")
	fl.BoolVar(&f.listOfficers, "list-officers", false, "list CA officers (ACE holders)")
	fl.BoolVar(&f.backup, "backup", false, "backup CA cert+key (RPC, not yet implemented)")
	fl.IntVar(&f.issueRequest, "issue-request", 0, "issue pending request ID (RPC, not yet implemented)")
	fl.IntVar(&f.denyRequest, "deny-request", 0, "deny pending request ID (RPC, not yet implemented)")
	fl.StringVar(&f.addOfficer, "add-officer", "", "grant Manage-Certificates to SID (RPC, not yet implemented)")
	fl.StringVar(&f.removeOfficer, "remove-officer", "", "revoke Manage-Certificates from SID (RPC, not yet implemented)")
	return cmd
}

func runCA(f *caFlags) error {
	if f.caName == "" {
		return fmt.Errorf("ca: --ca-name required")
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
		return fmt.Errorf("ca: --dc-host required")
	}

	conn, err := ldap.Dial(ldap.DialOptions{
		Server:             fmt.Sprintf("%s:%d", f.dcHost, f.port),
		UseTLS:             f.useTLS || f.port == 636,
		InsecureSkipVerify: f.insecure,
	})
	if err != nil {
		return fmt.Errorf("ca: dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	spn := ""
	if creds.UseKerberos {
		spn = "ldap/" + f.dcHost
	}
	if err := ldap.Bind(conn, creds, spn); err != nil {
		return fmt.Errorf("ca: bind: %w", err)
	}

	_, configNC, err := adcs.RootDSE(conn)
	if err != nil {
		return err
	}

	// Dispatch
	switch {
	case f.addTemplate != "":
		if err := ca.AddTemplate(conn, configNC, f.caName, f.addTemplate); err != nil {
			return err
		}
		fmt.Printf("published template %q on %s\n", f.addTemplate, f.caName)
	case f.removeTpl != "":
		if err := ca.RemoveTemplate(conn, configNC, f.caName, f.removeTpl); err != nil {
			return err
		}
		fmt.Printf("unpublished template %q from %s\n", f.removeTpl, f.caName)
	case f.listTpl:
		tpls, err := ca.ListTemplates(conn, configNC, f.caName)
		if err != nil {
			return err
		}
		for _, t := range tpls {
			fmt.Println(t)
		}
	case f.listOfficers:
		aces, err := ca.ListOfficers(conn, configNC, f.caName)
		if err != nil {
			return err
		}
		for _, a := range aces {
			fmt.Printf("SID=%s  rights=%s\n", a.SID, strings.TrimSpace(a.Rights))
		}
	case f.backup, f.addOfficer != "", f.removeOfficer != "", f.issueRequest > 0, f.denyRequest > 0:
		return fmt.Errorf("ca: RPC operations (backup/approve/deny/officer-edit) not yet implemented — use Certipy for these until go-msrpc ICertAdminD2 bindings land")
	default:
		return fmt.Errorf("ca: no action specified — see --list-templates, --add-template, --disable-template, --list-officers")
	}
	return nil
}
