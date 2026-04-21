package adcs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// CurrentUserDN returns the DN of the currently-bound principal. It tries
// the LDAP "Who Am I" extended operation first (RFC 4532), falling back to
// a sAMAccountName search under domainNC when the server does not support
// the extop or returns an empty authzId.
func CurrentUserDN(conn *goldap.Conn, sAMAccountName, domainNC string) (string, error) {
	if conn == nil {
		return "", errors.New("adcs: CurrentUserDN: nil connection")
	}

	// Try RFC 4532 Who Am I.
	whoami, err := conn.WhoAmI(nil)
	if err == nil && whoami != nil && whoami.AuthzID != "" {
		// Typical AD payloads: "u:DOMAIN\\user" or "dn:CN=...".
		id := whoami.AuthzID
		switch {
		case strings.HasPrefix(id, "dn:"):
			return strings.TrimPrefix(id, "dn:"), nil
		case strings.HasPrefix(id, "u:"):
			val := strings.TrimPrefix(id, "u:")
			if i := strings.LastIndex(val, "\\"); i >= 0 {
				sAMAccountName = val[i+1:]
			} else {
				sAMAccountName = val
			}
		}
	}

	// Fall back to LDAP search.
	if sAMAccountName == "" {
		return "", errors.New("adcs: CurrentUserDN: no sAMAccountName available")
	}
	if domainNC == "" {
		return "", errors.New("adcs: CurrentUserDN: domainNC required for fallback search")
	}

	// Strip trailing "$" keeps the computer-account case working - AD stores
	// computer accounts' sAMAccountName WITH the trailing $, so we match
	// literally.
	filter := fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(sAMAccountName))
	req := goldap.NewSearchRequest(
		domainNC,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"distinguishedName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("adcs: CurrentUserDN: search: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("adcs: CurrentUserDN: no entry for sAMAccountName=%q", sAMAccountName)
	}
	return res.Entries[0].DN, nil
}

// TokenGroups returns the SIDs of every security group the principal
// identified by userDN is effectively a member of (direct + nested +
// primary group). The `tokenGroups` attribute is a constructed,
// base-scope-only attribute that AD expands server-side.
//
// Returned values are string-form SIDs ("S-1-5-21-..."), suitable for
// comparison against the SIDs surfaced on template EnrollmentRights.
func TokenGroups(conn *goldap.Conn, userDN string) ([]string, error) {
	if conn == nil {
		return nil, errors.New("adcs: TokenGroups: nil connection")
	}
	if userDN == "" {
		return nil, errors.New("adcs: TokenGroups: userDN required")
	}
	req := goldap.NewSearchRequest(
		userDN,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"tokenGroups", "objectSid"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("adcs: TokenGroups: search %s: %w", userDN, err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("adcs: TokenGroups: %s not found", userDN)
	}
	entry := res.Entries[0]

	var sids []string
	for _, raw := range entry.GetRawAttributeValues("tokenGroups") {
		if s, err := SIDFromBytes(raw); err == nil {
			sids = append(sids, s)
		}
	}
	// Include the user's own objectSid too - enrollment ACEs are often
	// placed on the principal directly.
	if raw := entry.GetRawAttributeValue("objectSid"); len(raw) > 0 {
		if s, err := SIDFromBytes(raw); err == nil {
			sids = append(sids, s)
		}
	}
	return sids, nil
}

// IdentitySet returns the set of SIDs the current principal presents to AD
// for access-check purposes: tokenGroups, own objectSid, plus the well-
// known Authenticated Users (S-1-5-11) and Everyone (S-1-1-0) SIDs.
// A nil error with an empty set means the caller should not filter on
// enrollability.
func IdentitySet(conn *goldap.Conn, sAMAccountName, domainNC string) (map[string]bool, error) {
	dn, err := CurrentUserDN(conn, sAMAccountName, domainNC)
	if err != nil {
		return nil, err
	}
	sids, err := TokenGroups(conn, dn)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(sids)+2)
	for _, s := range sids {
		set[s] = true
	}
	// Implicit memberships every authenticated AD principal holds.
	set["S-1-1-0"] = true  // Everyone
	set["S-1-5-11"] = true // Authenticated Users
	return set, nil
}

// SIDFromBytes decodes the binary SID format used by tokenGroups /
// objectSid LDAP attributes (MS-DTYP §2.4.2.2) into the canonical
// "S-1-...-..." string form.
func SIDFromBytes(b []byte) (string, error) {
	if len(b) < 8 {
		return "", fmt.Errorf("sid: too short (%d bytes)", len(b))
	}
	rev := b[0]
	subAuthCount := int(b[1])
	if len(b) < 8+4*subAuthCount {
		return "", fmt.Errorf("sid: truncated (have %d, want %d)", len(b), 8+4*subAuthCount)
	}
	// IdentifierAuthority is 6 bytes big-endian.
	var idAuth uint64
	for _, c := range b[2:8] {
		idAuth = (idAuth << 8) | uint64(c)
	}
	parts := []string{"S", fmt.Sprintf("%d", rev), fmt.Sprintf("%d", idAuth)}
	for i := 0; i < subAuthCount; i++ {
		off := 8 + 4*i
		sub := uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
		parts = append(parts, fmt.Sprintf("%d", sub))
	}
	return strings.Join(parts, "-"), nil
}

// keep hex symbol imported for future tooling; avoids a silent dead import
// if the package is trimmed.
var _ = hex.EncodeToString
