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
	ca           string
	caName       string
	template     string
	method       string
	upn          string
	subject      string
	dns          []string
	keySize      int
	username     string
	password     string
	outPFX       string
	outPass      string
	insecure     bool
	autoFallback bool
	domain       string
	dcHost       string
	hashes       string
}

func newReqCmd() *cobra.Command {
	f := &reqFlags{}
	cmd := &cobra.Command{
		Use:   "req",
		Short: "Request a certificate via DCOM, ICPR RPC, or /certsrv/ web enrollment",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReq(f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.ca, "ca", "", "CA hostname or URL (https:// prefix optional)")
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
	fl.BoolVar(&f.autoFallback, "auto-fallback", false, "on failure, walk every other CA that publishes --template")
	fl.StringVarP(&f.domain, "domain", "d", "", "AD domain (required for --auto-fallback)")
	fl.StringVar(&f.dcHost, "dc-host", "", "domain controller (required for --auto-fallback)")
	return cmd
}

func runReq(f *reqFlags) error {
	if f.outPFX == "" {
		return fmt.Errorf("req: --out required")
	}
	req.Debug = globalDebug()
	req.Timeout = time.Duration(globalTimeout()) * time.Second

	// Ordered list of (ca-host, ca-name) pairs to try. Starts with the
	// operator's --ca (if given), then any LDAP-discovered fallbacks.
	type target struct{ host, name string }
	targets := []target{}
	if f.ca != "" {
		targets = append(targets, target{host: f.ca, name: f.caName})
	}

	if f.autoFallback {
		if f.dcHost == "" || f.domain == "" {
			return fmt.Errorf("req: --auto-fallback requires --dc-host and --domain")
		}
		extras, err := discoverPublishers(f)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[!] auto-fallback discovery failed: %v\n", err)
		} else {
			for _, t := range extras {
				if t.host == f.ca || (t.name == f.caName && f.caName != "") {
					continue // already first in list
				}
				targets = append(targets, target{host: t.host, name: t.name})
			}
			_, _ = fmt.Fprintf(os.Stderr, "[*] auto-fallback: %d CAs publish %q\n", len(targets), f.template)
		}
	}

	if len(targets) == 0 {
		return fmt.Errorf("req: --ca required (or --auto-fallback with --dc-host + --domain)")
	}

	var lastErr error
	for i, t := range targets {
		if i > 0 {
			_, _ = fmt.Fprintf(os.Stderr, "[*] auto-fallback: trying %s (%s)\n", t.name, t.host)
		}
		opts := req.Options{
			Method:      req.Method(f.method),
			CA:          t.host,
			CAName:      t.name,
			Template:    f.template,
			Subject:     f.subject,
			UPN:         f.upn,
			DNSNames:    f.dns,
			KeySize:     f.keySize,
			Username:    f.username,
			Password:    f.password,
			TLSInsecure: f.insecure,
		}
		cert, err := req.Submit(opts)
		if err == nil {
			pfx, perr := pki.SavePFX(cert, f.outPass)
			if perr != nil {
				return perr
			}
			if werr := writeFile(f.outPFX, pfx); werr != nil {
				return werr
			}
			fmt.Printf("cert issued for %s via %s, saved to %s\n",
				cert.Cert.Subject.CommonName, t.name, f.outPFX)
			return nil
		}
		_, _ = fmt.Fprintf(os.Stderr, "[!] %s failed: %v\n", t.name, err)
		lastErr = err
	}
	return fmt.Errorf("req: all %d CA attempts failed; last error: %w", len(targets), lastErr)
}

// discoverPublishers queries AD for every CA that publishes f.template.
// Results include the operator's already-specified CA (if any) so the
// caller can de-dup. Order preserved from LDAP.
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
			// Template publish entries may be display-name or CN-form; accept
			// either when they match f.template.
			if t == f.template {
				out = append(out, struct{ host, name string }{ca.DNSName, ca.Name})
				break
			}
		}
	}
	return out, nil
}
