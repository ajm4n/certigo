package adcs

import (
	"errors"
	"fmt"

	goldap "github.com/go-ldap/ldap/v3"
)

// ErrConfigNCUnknown is returned when a caller asks for enumeration
// against a configuration NC that could not be determined.
var ErrConfigNCUnknown = errors.New("adcs: configuration NC is empty and could not be discovered via RootDSE")

// RootDSE queries the anonymous RootDSE entry for a directory server
// and returns (defaultNamingContext, configurationNamingContext).
//
// It issues one base-scope search at BaseDN="" with filter
// "(objectClass=*)" and no auth required. The returned strings are
// verbatim from the server - e.g. "DC=corp,DC=local" /
// "CN=Configuration,DC=corp,DC=local".
func RootDSE(conn *goldap.Conn) (domainNC, configNC string, err error) {
	if conn == nil {
		return "", "", errors.New("adcs: RootDSE: nil connection")
	}
	req := goldap.NewSearchRequest(
		"",
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		RootDSEAttrs,
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", "", fmt.Errorf("adcs: RootDSE search: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", "", errors.New("adcs: RootDSE: no entries returned")
	}
	e := res.Entries[0]
	domainNC = e.GetAttributeValue("defaultNamingContext")
	configNC = e.GetAttributeValue("configurationNamingContext")
	if configNC == "" {
		// Fall back to the forest-root naming-context attr. Certipy
		// likewise tries several sources before giving up.
		rootDomain := e.GetAttributeValue("rootDomainNamingContext")
		if rootDomain != "" && domainNC == "" {
			domainNC = rootDomain
		}
	}
	return domainNC, configNC, nil
}

// EnumCAs queries the directory for pKIEnrollmentService objects and
// returns one CertificateAuthority per entry. searchBase is the
// configuration NC - e.g. "CN=Configuration,DC=corp,DC=local". If the
// argument is empty, RootDSE is queried to discover it.
func EnumCAs(conn *goldap.Conn, searchBase string) ([]*CertificateAuthority, error) {
	if conn == nil {
		return nil, errors.New("adcs: EnumCAs: nil connection")
	}
	configNC := searchBase
	if configNC == "" {
		_, discovered, err := RootDSE(conn)
		if err != nil {
			return nil, err
		}
		if discovered == "" {
			return nil, ErrConfigNCUnknown
		}
		configNC = discovered
	}

	base := JoinDN(EnrollmentServicesRelDN, configNC)
	req := goldap.NewSearchRequest(
		base,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0,
		0,
		false,
		FilterEnrollmentService,
		CAAttrs,
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("adcs: EnumCAs search (%s): %w", base, err)
	}

	out := make([]*CertificateAuthority, 0, len(res.Entries))
	for _, entry := range res.Entries {
		ca, perr := parseCA(entry)
		if perr != nil {
			// Skip malformed entries but keep going; callers can
			// diff against raw LDAP dumps if needed.
			continue
		}
		out = append(out, ca)
	}
	return out, nil
}

// EnumTemplates queries the directory for pKICertificateTemplate objects
// under CN=Certificate Templates,CN=Public Key Services,CN=Services,
// <configNC>. All templates are returned regardless of publication
// status or perceived vulnerability - the ESC rule engine filters.
func EnumTemplates(conn *goldap.Conn, configNC string) ([]*Template, error) {
	if conn == nil {
		return nil, errors.New("adcs: EnumTemplates: nil connection")
	}
	if configNC == "" {
		_, discovered, err := RootDSE(conn)
		if err != nil {
			return nil, err
		}
		if discovered == "" {
			return nil, ErrConfigNCUnknown
		}
		configNC = discovered
	}

	base := JoinDN(CertificateTemplatesRelDN, configNC)
	req := goldap.NewSearchRequest(
		base,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0,
		0,
		false,
		FilterCertificateTemplate,
		TemplateAttrs,
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("adcs: EnumTemplates search (%s): %w", base, err)
	}

	out := make([]*Template, 0, len(res.Entries))
	for _, entry := range res.Entries {
		tpl, perr := parseTemplate(entry)
		if perr != nil {
			continue
		}
		out = append(out, tpl)
	}
	return out, nil
}
