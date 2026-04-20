package account

import (
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// AccountType selects between user and computer account creation semantics.
type AccountType int

// Account types recognised by Create. Values are deliberately non-zero so a
// zero-valued Options.Type is detected as "unset" for Create.
const (
	TypeUser     AccountType = 1
	TypeComputer AccountType = 2
)

// userAccountControl flag values used by Create/Update.
const (
	uacAccountDisable        = 0x0002
	uacNormalAccount         = 0x0200                               // 512
	uacWorkstationTrust      = 0x1000                               // 4096
	uacNormalAccountEnabled  = uacNormalAccount                     // 512
	uacNormalAccountDisabled = uacNormalAccount | uacAccountDisable // 514
)

// Options bundles every knob the account package needs. Not all fields are
// meaningful for every action — e.g. Type only applies to Create, SPNs /
// UPN / DNSHost only apply to Create or Update.
type Options struct {
	Conn        *goldap.Conn
	BaseDN      string      // e.g. "DC=ctg,DC=local"
	Target      string      // sAMAccountName (user or computer) or DN
	Type        AccountType // required for Create
	ContainerDN string      // default: CN=Computers,<BaseDN> / CN=Users,<BaseDN>
	Password    string
	SPNs        []string
	UPN         string
	DNSHost     string
	ExtraAttrs  map[string][]string
}

// Create provisions a new user or computer account under Options.ContainerDN
// (defaulting to CN=Computers/CN=Users per type) and returns the DN of the
// newly-created entry.
//
// For computer accounts the sAMAccountName is forced to end in "$". When a
// password is supplied Create performs a two-phase flow: first an Add with
// userAccountControl=514 (disabled) so the new object exists before the
// password write, then a Modify that sets unicodePwd and flips UAC to the
// enabled value (512 for users, 4096 for computers).
func Create(opts Options) (string, error) {
	if opts.Conn == nil {
		return "", fmt.Errorf("account: create: nil connection")
	}
	if opts.BaseDN == "" {
		return "", fmt.Errorf("account: create: BaseDN required")
	}
	name := strings.TrimSpace(opts.Target)
	if name == "" {
		return "", fmt.Errorf("account: create: Target (account name) required")
	}

	var (
		container     string
		sam           string
		objectClasses []string
		enabledUAC    int
	)

	switch opts.Type {
	case TypeComputer:
		bare := strings.TrimSuffix(name, "$")
		sam = bare + "$"
		container = opts.ContainerDN
		if container == "" {
			container = "CN=Computers," + opts.BaseDN
		}
		objectClasses = []string{"top", "person", "organizationalPerson", "user", "computer"}
		enabledUAC = uacWorkstationTrust

	case TypeUser:
		sam = name
		container = opts.ContainerDN
		if container == "" {
			container = "CN=Users," + opts.BaseDN
		}
		objectClasses = []string{"top", "person", "organizationalPerson", "user"}
		enabledUAC = uacNormalAccountEnabled

	default:
		return "", fmt.Errorf("account: create: Type must be TypeUser or TypeComputer")
	}

	cn := strings.TrimSuffix(sam, "$")
	dn := fmt.Sprintf("CN=%s,%s", goldap.EscapeDN(cn), container)

	add := goldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", objectClasses)
	add.Attribute("cn", []string{cn})
	add.Attribute("sAMAccountName", []string{sam})
	// Start disabled so the object exists before we set a password.
	add.Attribute("userAccountControl", []string{fmt.Sprintf("%d", uacNormalAccountDisabled)})
	if opts.UPN != "" {
		add.Attribute("userPrincipalName", []string{opts.UPN})
	}
	if opts.DNSHost != "" {
		add.Attribute("dNSHostName", []string{opts.DNSHost})
	}
	if len(opts.SPNs) > 0 {
		add.Attribute("servicePrincipalName", opts.SPNs)
	}
	for k, v := range opts.ExtraAttrs {
		add.Attribute(k, v)
	}

	if err := opts.Conn.Add(add); err != nil {
		return "", fmt.Errorf("account: create %s: add: %w", dn, err)
	}

	// Second phase: set the password (if any) and flip UAC to enabled.
	if opts.Password != "" {
		mod := goldap.NewModifyRequest(dn, nil)
		pwdVal := string(UnicodePwd(opts.Password))
		mod.Replace("unicodePwd", []string{pwdVal})
		mod.Replace("userAccountControl", []string{fmt.Sprintf("%d", enabledUAC)})
		if err := opts.Conn.Modify(mod); err != nil {
			return "", fmt.Errorf("account: create %s: set password: %w", dn, err)
		}
	}

	return dn, nil
}

// Update modifies attributes on an existing account. Only non-empty fields
// in Options trigger a change. Password writes use unicodePwd in its UTF-16LE
// quoted form.
func Update(opts Options) error {
	if opts.Conn == nil {
		return fmt.Errorf("account: update: nil connection")
	}
	dn, err := targetDN(opts)
	if err != nil {
		return fmt.Errorf("account: update: %w", err)
	}

	mod := goldap.NewModifyRequest(dn, nil)
	touched := false

	if opts.Password != "" {
		mod.Replace("unicodePwd", []string{string(UnicodePwd(opts.Password))})
		touched = true
	}
	if opts.UPN != "" {
		mod.Replace("userPrincipalName", []string{opts.UPN})
		touched = true
	}
	if opts.DNSHost != "" {
		mod.Replace("dNSHostName", []string{opts.DNSHost})
		touched = true
	}
	if len(opts.SPNs) > 0 {
		mod.Replace("servicePrincipalName", opts.SPNs)
		touched = true
	}
	for k, v := range opts.ExtraAttrs {
		mod.Replace(k, v)
		touched = true
	}

	if !touched {
		return fmt.Errorf("account: update %s: no attributes supplied", dn)
	}
	if err := opts.Conn.Modify(mod); err != nil {
		return fmt.Errorf("account: update %s: %w", dn, err)
	}
	return nil
}

// Delete removes the target account entry by DN (resolving the target if a
// bare sAMAccountName was supplied).
func Delete(opts Options) error {
	if opts.Conn == nil {
		return fmt.Errorf("account: delete: nil connection")
	}
	dn, err := targetDN(opts)
	if err != nil {
		return fmt.Errorf("account: delete: %w", err)
	}
	if err := opts.Conn.Del(goldap.NewDelRequest(dn, nil)); err != nil {
		return fmt.Errorf("account: delete %s: %w", dn, err)
	}
	return nil
}

// Read dumps every attribute on the target object. Values are returned as
// strings — callers needing raw bytes should drop to ldap.Search directly.
func Read(opts Options) (map[string][]string, error) {
	if opts.Conn == nil {
		return nil, fmt.Errorf("account: read: nil connection")
	}
	dn, err := targetDN(opts)
	if err != nil {
		return nil, fmt.Errorf("account: read: %w", err)
	}

	req := goldap.NewSearchRequest(
		dn,
		goldap.ScopeBaseObject,
		goldap.DerefAlways,
		0, 0, false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	)
	res, err := opts.Conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("account: read %s: %w", dn, err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("account: read %s: no entry returned", dn)
	}

	out := make(map[string][]string, len(res.Entries[0].Attributes))
	for _, a := range res.Entries[0].Attributes {
		out[a.Name] = a.Values
	}
	return out, nil
}

// targetDN resolves Options.Target to a full DN. If Target already looks
// like a DN (contains a comma) it is returned verbatim; otherwise we search
// under BaseDN for a matching sAMAccountName.
func targetDN(opts Options) (string, error) {
	if opts.Target == "" {
		return "", fmt.Errorf("account: target required")
	}
	if strings.Contains(opts.Target, ",") {
		return opts.Target, nil
	}
	if opts.BaseDN == "" {
		return "", fmt.Errorf("account: base DN required to resolve sAMAccountName")
	}
	return ResolveDN(opts.Conn, opts.BaseDN, opts.Target)
}
