package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/forge"
	"github.com/ajm4n/certigo/internal/pki"
)

type forgeFlags struct {
	caPFX, caPass         string
	outPFX, outPass       string
	upn, sid, subject     string
	dns                   []string
	serialHex             string
	crl                   string
	templates             []string
	validityDays, keySize int
}

func newForgeCmd() *cobra.Command {
	f := &forgeFlags{}
	cmd := &cobra.Command{
		Use:   "forge",
		Short: "Forge a certificate from a CA private key (Golden Certificate)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runForge(f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.caPFX, "ca-pfx", "", "CA PFX file (with private key) - required")
	fl.StringVar(&f.caPass, "ca-password", "", "CA PFX password")
	fl.StringVar(&f.outPFX, "out", "forged.pfx", "output PFX path")
	fl.StringVar(&f.outPass, "out-password", "", "output PFX password")
	fl.StringVar(&f.upn, "upn", "", "userPrincipalName for SAN")
	fl.StringArrayVar(&f.dns, "dns", nil, "DNS name for SAN (repeatable)")
	fl.StringVar(&f.sid, "sid", "", "AD SID for NTDS-CA-Security-Ext (strongly recommended)")
	fl.StringVar(&f.subject, "subject", "", "subject DN (default derived from UPN)")
	fl.StringVar(&f.serialHex, "serial", "", "serial number hex (default random)")
	fl.StringVar(&f.crl, "crl", "", "CRL distribution point URL")
	fl.StringArrayVar(&f.templates, "template", nil, "certificatePolicies template OID (repeatable)")
	fl.IntVar(&f.validityDays, "validity-days", 3650, "validity in days")
	fl.IntVar(&f.keySize, "key-size", 2048, "RSA key size")
	return cmd
}

func runForge(f *forgeFlags) error {
	if f.caPFX == "" {
		return fmt.Errorf("forge: --ca-pfx required")
	}
	caData, err := readFile(f.caPFX)
	if err != nil {
		return err
	}
	ca, err := pki.LoadPFX(caData, f.caPass)
	if err != nil {
		return fmt.Errorf("forge: load CA: %w", err)
	}

	opts := forge.Options{
		CA:           ca,
		UPN:          f.upn,
		DNSNames:     f.dns,
		SID:          f.sid,
		SerialHex:    f.serialHex,
		TemplateOIDs: f.templates,
		ValidityDays: f.validityDays,
		KeySize:      f.keySize,
	}
	if f.crl != "" {
		opts.CRLs = []string{f.crl}
	}
	if f.subject != "" {
		opts.Subject.CommonName = strings.TrimPrefix(f.subject, "CN=")
	}

	cert, err := forge.Forge(opts)
	if err != nil {
		return fmt.Errorf("forge: %w", err)
	}

	out, err := pki.SavePFX(cert, f.outPass)
	if err != nil {
		return fmt.Errorf("forge: save PFX: %w", err)
	}
	if err := writeFile(f.outPFX, out); err != nil {
		return err
	}
	fmt.Printf("forged certificate written to %s\n", f.outPFX)
	return nil
}
