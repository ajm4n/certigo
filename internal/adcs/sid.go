package adcs

import (
	"fmt"

	goldap "github.com/go-ldap/ldap/v3"
)

// WellKnownSIDs maps built-in Windows SIDs to their friendly names.
// Domain-specific SIDs (S-1-5-21-...) are resolved via LDAP.
var WellKnownSIDs = map[string]string{
	"S-1-0-0":       "Null SID",
	"S-1-1-0":       "Everyone",
	"S-1-2-0":       "Local",
	"S-1-2-1":       "Console Logon",
	"S-1-3-0":       "Creator Owner",
	"S-1-3-1":       "Creator Group",
	"S-1-5-1":       "Dialup",
	"S-1-5-2":       "Network",
	"S-1-5-3":       "Batch",
	"S-1-5-4":       "Interactive",
	"S-1-5-6":       "Service",
	"S-1-5-7":       "Anonymous",
	"S-1-5-9":       "Enterprise Domain Controllers",
	"S-1-5-10":      "Principal Self",
	"S-1-5-11":      "Authenticated Users",
	"S-1-5-12":      "Restricted Code",
	"S-1-5-13":      "Terminal Server Users",
	"S-1-5-14":      "Remote Interactive Logon",
	"S-1-5-15":      "This Organization",
	"S-1-5-17":      "IUsr",
	"S-1-5-18":      "Local System",
	"S-1-5-19":      "NT Authority (Local Service)",
	"S-1-5-20":      "NT Authority (Network Service)",
	"S-1-5-32-544": "BUILTIN\\Administrators",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests",
	"S-1-5-32-547": "BUILTIN\\Power Users",
	"S-1-5-32-548": "BUILTIN\\Account Operators",
	"S-1-5-32-549": "BUILTIN\\Server Operators",
	"S-1-5-32-550": "BUILTIN\\Print Operators",
	"S-1-5-32-551": "BUILTIN\\Backup Operators",
	"S-1-5-32-552": "BUILTIN\\Replicators",
	"S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
	"S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
	"S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
	"S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
	"S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
	"S-1-5-32-559": "BUILTIN\\Performance Log Users",
	"S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
	"S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
	"S-1-5-32-562": "BUILTIN\\Distributed COM Users",
	"S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
	"S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
	"S-1-5-32-573": "BUILTIN\\Event Log Readers",
	"S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
	"S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
	"S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
	"S-1-5-32-577": "BUILTIN\\RDS Management Servers",
	"S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
	"S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
	"S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

// NewLDAPSIDResolver builds a SIDResolver that resolves S-1-5-21-<domain>-<rid>
// SIDs against the given bound LDAP connection. Well-known SIDs are looked
// up in WellKnownSIDs without hitting the wire. Resolution failures return
// the SID itself so the caller can still render something.
//
// Pass one or more conns: the first should be the primary domain LDAP,
// additional conns are tried on miss (typically a Global Catalog on port
// 3268 so cross-domain / foreign-security-principal SIDs resolve too).
func NewLDAPSIDResolver(conn *goldap.Conn, domainNC string, extras ...*goldap.Conn) SIDResolver {
	cache := make(map[string]string)
	conns := append([]*goldap.Conn{conn}, extras...)
	return func(sid string) (string, error) {
		if sid == "" {
			return "", nil
		}
		if name, ok := cache[sid]; ok {
			return name, nil
		}
		if name, ok := WellKnownSIDs[sid]; ok {
			cache[sid] = name
			return name, nil
		}
		for _, c := range conns {
			if c == nil {
				continue
			}
			if name := lookupSIDOnConn(c, sid); name != "" {
				cache[sid] = name
				return name, nil
			}
		}
		cache[sid] = sid
		return sid, nil
	}
}

// lookupSIDOnConn issues a base-scope search with the "<SID=...>" bind DN
// form AD supports. Returns the resolved name or "" on miss / error.
func lookupSIDOnConn(conn *goldap.Conn, sid string) string {
	req := goldap.NewSearchRequest(
		"<SID="+sid+">",
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"sAMAccountName", "name", "objectClass"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return ""
	}
	entry := res.Entries[0]
	if v := entry.GetAttributeValue("sAMAccountName"); v != "" {
		return v
	}
	if v := entry.GetAttributeValue("name"); v != "" {
		return v
	}
	return ""
}

// ResolveSIDs walks every ACE on every CA and Template and populates the
// Ace.Name field using the supplied resolver. Safe to call with a nil
// resolver (in which case it's a no-op).
func ResolveSIDs(resolver SIDResolver, cas []*CertificateAuthority, templates []*Template) {
	if resolver == nil {
		return
	}
	resolveAceSlice := func(aces []Ace) []Ace {
		for i := range aces {
			if aces[i].Name != "" && aces[i].Name != aces[i].SID {
				continue
			}
			if name, err := resolver(aces[i].SID); err == nil && name != "" {
				aces[i].Name = name
			}
		}
		return aces
	}
	for _, ca := range cas {
		if ca == nil {
			continue
		}
		ca.EnrollmentRights = resolveAceSlice(ca.EnrollmentRights)
		ca.ManageCARights = resolveAceSlice(ca.ManageCARights)
		ca.ManageCertRights = resolveAceSlice(ca.ManageCertRights)
	}
	for _, t := range templates {
		if t == nil {
			continue
		}
		t.EnrollmentRights = resolveAceSlice(t.EnrollmentRights)
		t.AutoEnrollRights = resolveAceSlice(t.AutoEnrollRights)
		t.WriteOwner = resolveAceSlice(t.WriteOwner)
		t.WriteDacl = resolveAceSlice(t.WriteDacl)
		t.WriteProperty = resolveAceSlice(t.WriteProperty)
		t.FullControl = resolveAceSlice(t.FullControl)
	}
	_ = fmt.Sprintf // keep fmt import stable for future error wrapping
}
