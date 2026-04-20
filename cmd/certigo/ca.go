package main

import (
	"fmt"
	"os"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/adcs"
	"github.com/ajm4n/certigo/internal/auth"
	"github.com/ajm4n/certigo/internal/ca"
	"github.com/ajm4n/certigo/internal/ldap"
	"github.com/ajm4n/certigo/internal/pki"
)

// goldapConn is a short alias used inside this file only; keeps the
// runCARPC signature readable without pulling goldap into the rpc code.
type goldapConn = goldap.Conn

type caFlags struct {
	username, password, domain, hashes, dcHost string
	port                                       int
	useTLS, insecure, useKrb                   bool

	caName       string
	caHost       string // --ca-host override; normally resolved via LDAP.
	backupOut    string // --backup-out path for the emitted PFX.
	backupPass   string // --backup-password passphrase for the PFX.
	addTemplate  string
	removeTpl    string
	listTpl      bool
	listOfficers bool

	backup        bool
	issueRequest  int
	denyRequest   int
	addOfficer    string
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
	fl.StringVar(&f.caHost, "ca-host", "", "CA DNS hostname for DCOM (auto-resolved from LDAP if omitted)")
	fl.StringVar(&f.addTemplate, "add-template", "", "publish this template on the CA")
	fl.StringVar(&f.removeTpl, "disable-template", "", "unpublish this template on the CA")
	fl.BoolVar(&f.listTpl, "list-templates", false, "list published templates")
	fl.BoolVar(&f.listOfficers, "list-officers", false, "list CA officers (ACE holders)")
	fl.BoolVar(&f.backup, "backup", false, "retrieve CA signing certificate via RPC (PFX without key)")
	fl.StringVar(&f.backupOut, "backup-out", "", "output path for --backup PFX (default: <caName>.pfx)")
	fl.StringVar(&f.backupPass, "backup-password", "", "PFX passphrase for --backup output")
	fl.IntVar(&f.issueRequest, "issue-request", 0, "issue pending request ID via RPC")
	fl.IntVar(&f.denyRequest, "deny-request", 0, "deny pending request ID via RPC")
	fl.StringVar(&f.addOfficer, "add-officer", "", "grant Manage-Certificates (Officer role) to SID via RPC")
	fl.StringVar(&f.removeOfficer, "remove-officer", "", "revoke Manage-Certificates (Officer role) from SID via RPC")
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
		return runCARPC(f, conn, configNC, creds)
	default:
		return fmt.Errorf("ca: no action specified — see --list-templates, --add-template, --disable-template, --list-officers")
	}
	return nil
}

// runCARPC handles the DCOM-backed subcommands. It resolves the CA's
// dNSHostName (preferring --ca-host when supplied), dials DCOM, and
// dispatches the selected operation. Credentials are reused from the
// LDAP stage — hash-bound creds take precedence over password-bound.
func runCARPC(f *caFlags, conn *goldapConn, configNC string, creds *auth.Credentials) error {
	host := strings.TrimSpace(f.caHost)
	if host == "" {
		resolved, err := ca.LookupCADNSHostName(conn, configNC, f.caName)
		if err != nil {
			return err
		}
		host = resolved
	}
	if host == "" {
		return fmt.Errorf("ca: could not resolve CA DNS hostname — pass --ca-host")
	}

	user := creds.Username
	if creds.Domain != "" {
		user = creds.Domain + `\` + creds.Username
	}

	var cli *ca.Client
	var dialErr error
	if len(creds.NTHash) == 16 {
		cli, dialErr = ca.DialRPCWithNTHash(host, f.caName, user, creds.NTHash)
	} else {
		cli, dialErr = ca.DialRPC(host, f.caName, user, creds.Password)
	}
	if dialErr != nil {
		return dialErr
	}
	defer func() { _ = cli.Close() }()

	switch {
	case f.backup:
		cert, err := cli.Backup()
		if err != nil {
			return err
		}
		out := f.backupOut
		if out == "" {
			// Output PEM when we don't hold the private key (the
			// current ICertAdminD2::GetCAProperty-based Backup path)
			// and PFX when we eventually gain BackupPrepare/Read.
			if cert.Key == nil {
				out = f.caName + ".pem"
			} else {
				out = f.caName + ".pfx"
			}
		}
		var blob []byte
		if cert.Key == nil {
			blob, err = pki.EncodePEM(cert)
			if err != nil {
				return fmt.Errorf("ca: encode PEM: %w", err)
			}
		} else {
			blob, err = pki.SavePFX(cert, f.backupPass)
			if err != nil {
				return fmt.Errorf("ca: encode PFX: %w", err)
			}
		}
		if err := os.WriteFile(out, blob, 0o600); err != nil {
			return fmt.Errorf("ca: write %s: %w", out, err)
		}
		note := ""
		if cert.Key == nil {
			note = " (cert only — private key requires BackupPrepare flow; use certutil -backupkey on the CA host)"
		}
		fmt.Printf("wrote %d bytes of CA signing material%s to %s\n", len(blob), note, out)
	case f.issueRequest > 0:
		if err := cli.IssueRequest(uint32(f.issueRequest)); err != nil {
			return err
		}
		fmt.Printf("issued request %d on %s\n", f.issueRequest, f.caName)
	case f.denyRequest > 0:
		if err := cli.DenyRequest(uint32(f.denyRequest)); err != nil {
			return err
		}
		fmt.Printf("denied request %d on %s\n", f.denyRequest, f.caName)
	case f.addOfficer != "":
		if err := cli.AddOfficer(f.addOfficer); err != nil {
			return err
		}
		fmt.Printf("granted Manage-Certificates to %s on %s\n", f.addOfficer, f.caName)
	case f.removeOfficer != "":
		if err := cli.RemoveOfficer(f.removeOfficer); err != nil {
			return err
		}
		fmt.Printf("revoked Manage-Certificates from %s on %s\n", f.removeOfficer, f.caName)
	}
	return nil
}

