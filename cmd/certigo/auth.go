package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	gokrbclient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/credentials"

	"github.com/ajm4n/certigo/internal/auth"
	"github.com/ajm4n/certigo/internal/auth/krb"
	"github.com/ajm4n/certigo/internal/auth/pkinit"
	"github.com/ajm4n/certigo/internal/ldap"
	"github.com/ajm4n/certigo/internal/pki"
)

type authFlags struct {
	username, password, domain, hashes, dcHost string

	pfxPath, pfxPass string
	pemCert, pemKey  string

	outCCache string
	outKirbi  string

	printHash bool

	ldapShell bool
	ldapHost  string
	ldaps     bool
	insecure  bool
}

func newAuthCmd() *cobra.Command {
	f := &authFlags{}
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate using a certificate (PKINIT or Schannel) and return a TGT or NT hash",
		Long: "Auth performs a password, NT-hash, or certificate-based (PKINIT) " +
			"authentication to obtain a TGT. Password/NT-hash auth runs through " +
			"gokrb5's standard AS-REQ path; --pfx / --cert+--key engage the PKINIT " +
			"AS-REQ flow in internal/auth/pkinit (RFC 4556) which negotiates DH " +
			"keys with the KDC and writes the resulting TGT to the ccache.",
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
	fl.BoolVar(&f.ldapShell, "ldap-shell", false, "after auth, bind to LDAP as the authenticated principal and drop into a REPL")
	fl.StringVar(&f.ldapHost, "ldap-host", "", "LDAP target for --ldap-shell (defaults to --dc-host)")
	fl.BoolVar(&f.ldaps, "ldaps", true, "use LDAPS for --ldap-shell (default true; many DCs reject plain LDAP + GSSAPI)")
	fl.BoolVar(&f.insecure, "ldap-insecure", true, "skip LDAPS certificate verification for --ldap-shell (default true)")
	return cmd
}

func runAuth(f *authFlags) error {
	if f.domain == "" {
		return fmt.Errorf("auth: --domain required")
	}
	if f.dcHost == "" {
		return fmt.Errorf("auth: --dc-host required")
	}

	// Cert-based auth (PKINIT) - load the cert + key and perform the
	// AS-REQ/AS-REP exchange defined in RFC 4556.
	if f.pfxPath != "" || (f.pemCert != "" && f.pemKey != "") {
		return runPKINITAuth(f)
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

	if f.ldapShell {
		return runLDAPShellFromCCache(f, out)
	}
	return nil
}

// runPKINITAuth drives the --pfx / --cert+--key path: it loads the client
// certificate, calls pkinit.AuthenticateWithPKINITResult to perform the
// AS-REQ/AS-REP exchange, and persists the resulting TGT via the
// PKINIT-specific ccache helper.
func runPKINITAuth(f *authFlags) error {
	if f.username == "" {
		return fmt.Errorf("auth: --username required for PKINIT (used as Kerberos principal name)")
	}

	var cert *pki.Certificate
	switch {
	case f.pfxPath != "":
		data, err := os.ReadFile(f.pfxPath)
		if err != nil {
			return fmt.Errorf("auth: read PFX: %w", err)
		}
		cert, err = pki.LoadPFX(data, f.pfxPass)
		if err != nil {
			return fmt.Errorf("auth: load PFX: %w", err)
		}
	case f.pemCert != "" && f.pemKey != "":
		return fmt.Errorf("auth: PEM cert+key PKINIT loader not yet implemented; use --pfx")
	default:
		return fmt.Errorf("auth: PKINIT requires either --pfx or --cert+--key")
	}

	cfg, err := krb.LoadConfig(f.domain, f.dcHost)
	if err != nil {
		return fmt.Errorf("auth: load krb5 config: %w", err)
	}

	res, err := pkinit.AuthenticateWithPKINITResult(pkinit.Options{
		Realm:      f.domain,
		Principal:  f.username,
		Cert:       cert,
		Config:     cfg,
		RequestPAC: true,
	})
	if err != nil {
		return fmt.Errorf("auth: PKINIT AS-REQ: %w", err)
	}

	out := f.outCCache
	if out == "" {
		out = os.Getenv("KRB5CCNAME")
	}
	if out == "" {
		out = "./certigo.ccache"
	}
	// gokrb5's *client.Client has no public hooks to inject externally
	// obtained TGTs, so we use the PKINIT-specific ccache writer.
	if err := pkinit.SavePKINITTGTToCCache(out, res.CName, res.Realm, res.Ticket, res.DecryptedEncKDC); err != nil {
		return fmt.Errorf("auth: save PKINIT TGT: %w", err)
	}
	fmt.Printf("TGT saved to %s\n", out)

	if f.outKirbi != "" {
		fmt.Printf("NOTE: kirbi export from PKINIT-obtained TGT requires ccache-to-kirbi follow-up (TODO)\n")
	}
	if f.printHash {
		fmt.Printf("NOTE: --print (unPAC-the-hash) requires PKINIT U2U support which is pending\n")
	}

	if f.ldapShell {
		return runLDAPShellFromCCache(f, out)
	}
	return nil
}

// runLDAPShellFromCCache loads the TGT from ccache, builds a gokrb5 client,
// does a GSSAPI/SPNEGO bind against --ldap-host (defaulting to --dc-host),
// and drops the user into the certigo LDAP shell. This is what closes the
// PKINIT -> LDAP-as-target-user loop: you pop a PFX, get a TGT, and
// immediately start running LDAP commands as that principal.
func runLDAPShellFromCCache(f *authFlags, ccachePath string) error {
	target := f.ldapHost
	if target == "" {
		target = f.dcHost
	}
	if target == "" {
		return fmt.Errorf("auth: --ldap-host or --dc-host required for --ldap-shell")
	}

	cc, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return fmt.Errorf("auth: load ccache %s: %w", ccachePath, err)
	}

	cfg, err := krb.LoadConfig(f.domain, f.dcHost)
	if err != nil {
		return fmt.Errorf("auth: load krb5 config: %w", err)
	}
	krbClient, err := gokrbclient.NewFromCCache(cc, cfg)
	if err != nil {
		return fmt.Errorf("auth: build kerberos client from ccache: %w", err)
	}

	creds := &auth.Credentials{
		Username:    "",
		Domain:      strings.ToUpper(f.domain),
		UseKerberos: true,
		KDCHost:     f.dcHost,
		CCachePath:  ccachePath,
	}

	port := 389
	if f.ldaps {
		port = 636
	}
	conn, err := ldap.DialWithKerberos(creds, krbClient, ldap.AutoOptions{
		DCHost:             target,
		Port:               port,
		UseTLS:             f.ldaps,
		InsecureSkipVerify: f.insecure,
	})
	if err != nil {
		return fmt.Errorf("auth: ldap-shell bind: %w", err)
	}
	defer func() { _ = conn.Close() }()

	baseDN := domainToBaseDN(f.domain)
	shell := &ldap.Shell{
		Conn:     conn,
		BaseDN:   baseDN,
		Username: f.username,
	}
	return shell.Run()
}
