package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ajm4n/certigo/internal/account"
	"github.com/ajm4n/certigo/internal/auth"
	"github.com/ajm4n/certigo/internal/ldap"
)

type accountFlags struct {
	// Auth.
	username string
	password string
	domain   string
	hashes   string
	useKrb   bool
	dcHost   string
	port     int
	useTLS   bool
	insecure bool
	baseDN   string

	// Action.
	action     string
	target     string
	accType    string
	acctPwd    string
	spns       []string
	upn        string
	dnsHost    string
	container  string
}

func newAccountCmd() *cobra.Command {
	f := &accountFlags{}
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Create, modify, or delete AD user and computer accounts via LDAP",
		Long: "Account manages AD user and computer objects for abuse scenarios (e.g. " +
			"adding a computer account to bypass MachineAccountQuota, setting SPNs, " +
			"or adding UPNs). Supported actions: create, update, delete, read.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAccount(cmd, f)
		},
	}

	fl := cmd.Flags()
	fl.StringVarP(&f.username, "username", "u", "", "AD username")
	fl.StringVarP(&f.password, "password", "p", "", "AD password")
	fl.StringVarP(&f.domain, "domain", "d", "", "AD domain (e.g. ctg.local)")
	fl.StringVar(&f.hashes, "hashes", "", "NTLM hashes (LMHASH:NTHASH)")
	fl.BoolVarP(&f.useKrb, "kerberos", "k", false, "use Kerberos GSSAPI bind")
	fl.StringVar(&f.dcHost, "dc-host", "", "domain controller host or IP")
	fl.IntVar(&f.port, "port", 389, "LDAP port (636 = LDAPS)")
	fl.BoolVar(&f.useTLS, "ldaps", false, "use LDAPS (auto-enabled for port 636)")
	fl.BoolVar(&f.insecure, "ldap-insecure", false, "skip TLS certificate verification")
	fl.StringVar(&f.baseDN, "base-dn", "", "domain naming context (e.g. DC=ctg,DC=local); derived from --domain if empty")

	fl.StringVar(&f.action, "action", "", "one of: create|update|delete|read (required)")
	fl.StringVar(&f.target, "target", "", "sAMAccountName or DN (required)")
	fl.StringVar(&f.accType, "type", "", "account type for create: user|computer")
	fl.StringVar(&f.acctPwd, "password-new", "", "password to set on the account (create/update)")
	fl.StringArrayVar(&f.spns, "spn", nil, "servicePrincipalName (repeatable)")
	fl.StringVar(&f.upn, "upn", "", "userPrincipalName")
	fl.StringVar(&f.dnsHost, "dns-host", "", "dNSHostName (for computers)")
	fl.StringVar(&f.container, "container-dn", "", "container DN for create (default: CN=Users/CN=Computers)")

	return cmd
}

func runAccount(cmd *cobra.Command, f *accountFlags) error {
	action := strings.ToLower(strings.TrimSpace(f.action))
	if action == "" {
		return fmt.Errorf("account: --action required (create|update|delete|read)")
	}
	switch action {
	case "create", "update", "delete", "read":
	default:
		return fmt.Errorf("account: unknown action %q", f.action)
	}
	if strings.TrimSpace(f.target) == "" {
		return fmt.Errorf("account: --target required")
	}

	creds := &auth.Credentials{
		Username:    f.username,
		Domain:      f.domain,
		Password:    f.password,
		UseKerberos: f.useKrb,
		KDCHost:     f.dcHost,
	}
	if f.hashes != "" {
		lm, nt, err := auth.ParseHashes(f.hashes)
		if err != nil {
			return fmt.Errorf("account: %w", err)
		}
		creds.LMHash = lm
		creds.NTHash = nt
	}
	if err := creds.Validate(); err != nil {
		return fmt.Errorf("account: %w", err)
	}

	server := f.dcHost
	if server == "" {
		return fmt.Errorf("account: --dc-host required")
	}
	useTLS := f.useTLS || f.port == 636

	conn, err := ldap.Dial(ldap.DialOptions{
		Server:             fmt.Sprintf("%s:%d", server, f.port),
		UseTLS:             useTLS,
		InsecureSkipVerify: f.insecure,
	})
	if err != nil {
		return fmt.Errorf("account: ldap dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	spn := ""
	if creds.UseKerberos {
		spn = fmt.Sprintf("ldap/%s", server)
	}
	if err := ldap.Bind(conn, creds, spn); err != nil {
		return fmt.Errorf("account: ldap bind: %w", err)
	}

	baseDN := f.baseDN
	if baseDN == "" {
		baseDN = domainToBaseDN(f.domain)
	}
	if baseDN == "" {
		return fmt.Errorf("account: --base-dn or --domain required")
	}

	opts := account.Options{
		Conn:        conn,
		BaseDN:      baseDN,
		Target:      f.target,
		ContainerDN: f.container,
		Password:    f.acctPwd,
		SPNs:        f.spns,
		UPN:         f.upn,
		DNSHost:     f.dnsHost,
	}

	out := cmd.OutOrStdout()
	switch action {
	case "create":
		t, err := parseAccountType(f.accType)
		if err != nil {
			return fmt.Errorf("account: %w", err)
		}
		opts.Type = t
		dn, err := account.Create(opts)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "created: %s\n", dn)

	case "update":
		if err := account.Update(opts); err != nil {
			return err
		}
		fmt.Fprintf(out, "updated: %s\n", f.target)

	case "delete":
		if err := account.Delete(opts); err != nil {
			return err
		}
		fmt.Fprintf(out, "deleted: %s\n", f.target)

	case "read":
		attrs, err := account.Read(opts)
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
				fmt.Fprintf(out, "%s: %s\n", k, v)
			}
		}
	}
	return nil
}

// parseAccountType converts the --type flag into an account.AccountType.
func parseAccountType(s string) (account.AccountType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "user":
		return account.TypeUser, nil
	case "computer":
		return account.TypeComputer, nil
	case "":
		return 0, fmt.Errorf("--type required for create (user|computer)")
	default:
		return 0, fmt.Errorf("unknown --type %q (want user|computer)", s)
	}
}

// domainToBaseDN converts "ctg.local" → "DC=ctg,DC=local". Empty in → empty out.
func domainToBaseDN(domain string) string {
	d := strings.TrimSpace(domain)
	if d == "" {
		return ""
	}
	parts := strings.Split(d, ".")
	for i, p := range parts {
		parts[i] = "DC=" + p
	}
	return strings.Join(parts, ",")
}
