package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/pki"
	"github.com/ajm4n/certigo/internal/req"
)

type reqFlags struct {
	ca       string
	caName   string
	template string
	method   string
	upn      string
	subject  string
	dns      []string
	keySize  int
	username string
	password string
	outPFX   string
	outPass  string
	insecure bool
}

func newReqCmd() *cobra.Command {
	f := &reqFlags{}
	cmd := &cobra.Command{
		Use:   "req",
		Short: "Request a certificate via RPC, web enrollment, DCOM, KDC-Proxy, or Schannel",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReq(f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.ca, "ca", "", "CA hostname or URL (https:// prefix optional)")
	fl.StringVar(&f.caName, "ca-name", "", "Enterprise CA common name")
	fl.StringVar(&f.template, "template", "User", "certificate template name")
	fl.StringVar(&f.method, "method", "rpc", "submit method: rpc|web (rpc matches certipy's default)")
	fl.StringVar(&f.upn, "upn", "", "userPrincipalName for SAN")
	fl.StringVar(&f.subject, "subject", "", "subject DN (default derived from --upn)")
	fl.StringArrayVar(&f.dns, "dns", nil, "DNS name for SAN (repeatable)")
	fl.IntVar(&f.keySize, "key-size", 2048, "RSA key size")
	fl.StringVarP(&f.username, "username", "u", "", "HTTP Basic username (domain\\\\user)")
	fl.StringVarP(&f.password, "password", "p", "", "HTTP Basic password")
	fl.StringVar(&f.outPFX, "out", "", "output PFX path (required)")
	fl.StringVar(&f.outPass, "out-password", "", "output PFX password")
	fl.BoolVar(&f.insecure, "insecure-tls", false, "skip TLS verify")
	return cmd
}

func runReq(f *reqFlags) error {
	if f.outPFX == "" {
		return fmt.Errorf("req: --out required")
	}
	// Hook the global --debug + --timeout flags into the req package.
	req.Debug = globalDebug()
	req.Timeout = time.Duration(globalTimeout()) * time.Second
	opts := req.Options{
		Method:      req.Method(f.method),
		CA:          f.ca,
		CAName:      f.caName,
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
	if err != nil {
		return err
	}
	pfx, err := pki.SavePFX(cert, f.outPass)
	if err != nil {
		return err
	}
	if err := writeFile(f.outPFX, pfx); err != nil {
		return err
	}
	fmt.Printf("cert issued for %s, saved to %s\n", cert.Cert.Subject.CommonName, f.outPFX)
	return nil
}
