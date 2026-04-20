// Package ca exposes LDAP-backed management operations for AD CS CAs
// (pKIEnrollmentService objects) plus DCOM / MS-CSRA (ICertAdminD +
// ICertAdminD2) client bindings for Backup, request approval / denial,
// and Officer-rights management. See rpc.go / ops.go for the RPC side.
package ca

import (
	"fmt"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/ajm4n/certigo/internal/adcs"
)

// caDN returns the pKIEnrollmentService object's DN for a given CA name.
func caDN(configNC, name string) string {
	return "CN=" + name + "," + adcs.EnrollmentServicesRelDN + "," + configNC
}

// AddTemplate publishes templateName on the CA by appending to
// certificateTemplates. Idempotent: existing entries are preserved.
func AddTemplate(conn *goldap.Conn, configNC, caName, templateName string) error {
	current, err := ListTemplates(conn, configNC, caName)
	if err != nil {
		return err
	}
	for _, t := range current {
		if t == templateName {
			return nil
		}
	}
	dn := caDN(configNC, caName)
	req := goldap.NewModifyRequest(dn, nil)
	req.Add("certificateTemplates", []string{templateName})
	if err := conn.Modify(req); err != nil {
		return fmt.Errorf("ca: add template: %w", err)
	}
	return nil
}

// RemoveTemplate unpublishes templateName from the CA.
func RemoveTemplate(conn *goldap.Conn, configNC, caName, templateName string) error {
	dn := caDN(configNC, caName)
	req := goldap.NewModifyRequest(dn, nil)
	req.Delete("certificateTemplates", []string{templateName})
	if err := conn.Modify(req); err != nil {
		return fmt.Errorf("ca: remove template: %w", err)
	}
	return nil
}

// ListTemplates returns the certificateTemplates values on the CA object.
func ListTemplates(conn *goldap.Conn, configNC, caName string) ([]string, error) {
	dn := caDN(configNC, caName)
	s := goldap.NewSearchRequest(
		dn,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"certificateTemplates"},
		nil,
	)
	res, err := conn.Search(s)
	if err != nil {
		return nil, fmt.Errorf("ca: list templates: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("ca: no entry at %s", dn)
	}
	return res.Entries[0].GetAttributeValues("certificateTemplates"), nil
}

// ListOfficers extracts SIDs with CA-management rights from the CA object's
// nTSecurityDescriptor. Returns a flat list (ADCS-ESC7-relevant) of ACEs.
func ListOfficers(conn *goldap.Conn, configNC, caName string) ([]adcs.Ace, error) {
	dn := caDN(configNC, caName)
	s := goldap.NewSearchRequest(
		dn,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"nTSecurityDescriptor"},
		[]goldap.Control{},
	)
	res, err := conn.Search(s)
	if err != nil {
		return nil, fmt.Errorf("ca: list officers: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("ca: no entry at %s", dn)
	}
	rawBytes := res.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if len(rawBytes) == 0 {
		return nil, nil
	}
	aces, err := adcs.ParseSecurityDescriptor(rawBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("ca: parse SD: %w", err)
	}
	return aces, nil
}

// LookupCADNSHostName queries LDAP for the pKIEnrollmentService.dNSHostName
// attribute of caName — the canonical target for subsequent DCOM dialing.
// Returns ("", nil) when the attribute is absent so callers can fall back
// to a --ca-host override without treating the missing value as an error.
func LookupCADNSHostName(conn *goldap.Conn, configNC, caName string) (string, error) {
	dn := caDN(configNC, caName)
	s := goldap.NewSearchRequest(
		dn,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{adcs.AttrDNSHostName},
		nil,
	)
	res, err := conn.Search(s)
	if err != nil {
		return "", fmt.Errorf("ca: lookup dNSHostName: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("ca: no entry at %s", dn)
	}
	return res.Entries[0].GetAttributeValue(adcs.AttrDNSHostName), nil
}
