package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/adcs"
	"github.com/ajm4n/certigo/internal/auth"
	"github.com/ajm4n/certigo/internal/ldap"
	"github.com/ajm4n/certigo/internal/pki"
	"github.com/ajm4n/certigo/internal/req"
)

type reqFlags struct {
	ca             string
	caName         string
	template       string
	method         string
	upn            string
	subject        string
	dns            []string
	keySize        int
	username       string
	password       string
	hashes         string
	outPFX         string
	outPass        string
	insecure       bool
	domain         string
	dcHost         string
	noAutoFallback bool
	webOnDenied    bool
}

func newReqCmd() *cobra.Command {
	f := &reqFlags{}
	cmd := &cobra.Command{
		Use:   "req",
		Short: "Request a certificate via DCOM, ICPR RPC, or /certsrv/ web enrollment",
		Long: "By default, req discovers every CA that publishes the template " +
			"(when --dc-host + --domain are supplied) and tries each in order. " +
			"If every DCOM attempt fails with ACCESS_DENIED, req automatically " +
			"falls back to /certsrv/ web enrollment against each CA - that path " +
			"often succeeds even when the 'Certificate Service DCOM Access' " +
			"ACL denies the principal. Disable with --no-auto-fallback.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReq(f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.ca, "ca", "", "CA hostname (https:// prefix optional)")
	fl.StringVar(&f.caName, "ca-name", "", "Enterprise CA common name")
	fl.StringVar(&f.template, "template", "User", "certificate template name")
	fl.StringVar(&f.method, "method", "dcom", "submit method: dcom|rpc|web (dcom matches certipy's default)")
	fl.StringVar(&f.upn, "upn", "", "userPrincipalName for SAN")
	fl.StringVar(&f.subject, "subject", "", "subject DN (default derived from --upn)")
	fl.StringArrayVar(&f.dns, "dns", nil, "DNS name for SAN (repeatable)")
	fl.IntVar(&f.keySize, "key-size", 2048, "RSA key size")
	fl.StringVarP(&f.username, "username", "u", "", "AD username")
	fl.StringVarP(&f.password, "password", "p", "", "AD password")
	fl.StringVar(&f.hashes, "hashes", "", "NTLM hashes (LMHASH:NTHASH)")
	fl.StringVar(&f.outPFX, "out", "", "output PFX path (required)")
	fl.StringVar(&f.outPass, "out-password", "", "output PFX password")
	fl.BoolVar(&f.insecure, "insecure-tls", false, "skip TLS verify")
	fl.StringVarP(&f.domain, "domain", "d", "", "AD domain (enables CA fallback discovery)")
	fl.StringVar(&f.dcHost, "dc-host", "", "domain controller (enables CA fallback discovery + DNS resolution)")
	fl.BoolVar(&f.noAutoFallback, "no-auto-fallback", false, "don't discover other CAs publishing the template")
	fl.BoolVar(&f.webOnDenied, "web-on-denied", false, "on ACCESS_DENIED from DCOM, retry every CA via /certsrv/ web enrollment")
	return cmd
}

func runReq(f *reqFlags) error {
	if f.outPFX == "" {
		return fmt.Errorf("req: --out required")
	}
	req.Debug = globalDebug()
	req.Timeout = time.Duration(globalTimeout()) * time.Second

	type target struct{ host, name string }
	targets := []target{}
	if f.ca != "" {
		targets = append(targets, target{host: f.ca, name: f.caName})
	}

	canDiscover := f.dcHost != "" && f.domain != ""
	if !f.noAutoFallback && canDiscover {
		extras, err := discoverPublishers(f)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[!] auto-fallback discovery failed: %v\n", err)
		} else {
			for _, t := range extras {
				if t.host == f.ca || (t.name == f.caName && f.caName != "") {
					continue
				}
				targets = append(targets, target{host: t.host, name: t.name})
			}
			_, _ = fmt.Fprintf(os.Stderr, "[*] auto-fallback: %d CAs publish %q\n", len(targets), f.template)
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("req: --ca required (or --dc-host + --domain for auto-discovery)")
	}

	// Pass 1: whatever method the operator picked (dcom by default).
	seenAccessDenied := false
	var lastErr error
	for i, t := range targets {
		if i > 0 {
			_, _ = fmt.Fprintf(os.Stderr, "[*] auto-fallback: trying %s (%s)\n", t.name, t.host)
		}
		cert, err := req.Submit(buildOpts(f, f.method, t.host, t.name))
		if err == nil {
			return savePFX(f, cert, t.name)
		}
		_, _ = fmt.Fprintf(os.Stderr, "[!] %s failed: %v\n", t.name, err)
		if isReqAccessDenied(err) {
			seenAccessDenied = true
		}
		lastErr = err
	}

	// Pass 2: DCOM ACCESS_DENIED is the local "Certificate Service DCOM
	// Access" ACL rejecting us. Web enrollment is a different code path
	// that only checks CA enrollment ACL + IIS auth, so it often works.
	if f.webOnDenied && seenAccessDenied && f.method != "web" {
		_, _ = fmt.Fprintf(os.Stderr, "[*] every DCOM attempt hit ACCESS_DENIED; retrying via /certsrv/ web enrollment\n")
		for _, t := range targets {
			_, _ = fmt.Fprintf(os.Stderr, "[*] web: trying %s (%s)\n", t.name, t.host)
			opts := buildOpts(f, "web", t.host, t.name)
			opts.TLSInsecure = true
			cert, err := req.Submit(opts)
			if err == nil {
				return savePFX(f, cert, t.name+" (web)")
			}
			_, _ = fmt.Fprintf(os.Stderr, "[!] %s web failed: %v\n", t.name, err)
			lastErr = err
		}
	}

	return fmt.Errorf("req: every CA attempt failed; last error: %w", lastErr)
}

func buildOpts(f *reqFlags, method, host, name string) req.Options {
	return req.Options{
		Method:      req.Method(method),
		CA:          host,
		CAName:      name,
		Template:    f.template,
		Subject:     f.subject,
		UPN:         f.upn,
		DNSNames:    f.dns,
		KeySize:     f.keySize,
		Username:    f.username,
		Password:    f.password,
		TLSInsecure: f.insecure,
		DCHost:      f.dcHost,
	}
}

func savePFX(f *reqFlags, cert *pki.Certificate, via string) error {
	pfx, err := pki.SavePFX(cert, f.outPass)
	if err != nil {
		return err
	}
	if err := writeFile(f.outPFX, pfx); err != nil {
		return err
	}
	fmt.Printf("cert issued for %s via %s, saved to %s\n",
		cert.Cert.Subject.CommonName, via, f.outPFX)
	return nil
}

// isReqAccessDenied checks an error returned from req.Submit for a DCOM /
// ACCESS_DENIED signature. Kept here (not in internal/req) so the CLI
// doesn't need to import private error kinds.
func isReqAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return (indexOf(s, "ERROR_ACCESS_DENIED") >= 0) ||
		(indexOf(s, "Access is denied") >= 0) ||
		(indexOf(s, "0x00000005") >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// discoverPublishers queries AD for every CA that publishes f.template.
func discoverPublishers(f *reqFlags) ([]struct{ host, name string }, error) {
	creds := &auth.Credentials{
		Username: f.username,
		Domain:   f.domain,
		Password: f.password,
		KDCHost:  f.dcHost,
	}
	if f.hashes != "" {
		lm, nt, err := auth.ParseHashes(f.hashes)
		if err != nil {
			return nil, err
		}
		creds.LMHash, creds.NTHash = lm, nt
	}
	if err := creds.Validate(); err != nil {
		return nil, err
	}

	conn, err := ldap.DialAndBind(creds, ldap.AutoOptions{
		DCHost:             f.dcHost,
		Port:               389,
		InsecureSkipVerify: f.insecure,
	})
	if err != nil {
		return nil, fmt.Errorf("ldap dial/bind: %w", err)
	}
	defer func() { _ = conn.Close() }()

	_, configNC, err := adcs.RootDSE(conn)
	if err != nil {
		return nil, err
	}
	cas, err := adcs.EnumCAs(conn, configNC)
	if err != nil {
		return nil, err
	}

	out := []struct{ host, name string }{}
	for _, ca := range cas {
		if ca == nil {
			continue
		}
		for _, t := range ca.Templates {
			if t == f.template {
				out = append(out, struct{ host, name string }{ca.DNSName, ca.Name})
				break
			}
		}
	}
	return out, nil
}
