package account

import (
	"fmt"
	"strings"
	"unicode/utf16"

	goldap "github.com/go-ldap/ldap/v3"
)

// ResolveDN looks up the DN for a given sAMAccountName under baseDN. The
// sAMAccountName may be supplied with or without the trailing "$" used for
// computer accounts - both forms are searched. The first match wins; an
// error is returned when the search fails or yields zero hits.
func ResolveDN(conn *goldap.Conn, baseDN, samAccountName string) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("account: resolve: nil connection")
	}
	if baseDN == "" {
		return "", fmt.Errorf("account: resolve: baseDN required")
	}
	sam := strings.TrimSpace(samAccountName)
	if sam == "" {
		return "", fmt.Errorf("account: resolve: empty sAMAccountName")
	}

	// Build (sAMAccountName=X)(sAMAccountName=X$) filter covering both
	// user and computer forms. Escape the value for LDAP filter safety.
	bare := strings.TrimSuffix(sam, "$")
	escBare := goldap.EscapeFilter(bare)
	escDollar := goldap.EscapeFilter(bare + "$")
	filter := fmt.Sprintf("(&(objectClass=*)(|(sAMAccountName=%s)(sAMAccountName=%s)))", escBare, escDollar)

	req := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.DerefAlways,
		0, 0, false,
		filter,
		[]string{"distinguishedName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("account: resolve %q: %w", sam, err)
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("account: resolve %q: no match under %s", sam, baseDN)
	}
	return res.Entries[0].DN, nil
}

// UnicodePwd encodes the given password as the on-wire value expected by
// Active Directory's unicodePwd attribute: the password wrapped in ASCII
// double quotes, then encoded as UTF-16LE (little-endian, no BOM). The
// quotes are part of the encoding and MUST be present.
func UnicodePwd(password string) []byte {
	quoted := `"` + password + `"`
	u16 := utf16.Encode([]rune(quoted))
	out := make([]byte, 0, len(u16)*2)
	for _, r := range u16 {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}
