package adcs

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// parseCA converts one *ldap.Entry of class pKIEnrollmentService into a
// *CertificateAuthority. Returns an error only when the minimum set of
// mandatory attributes (cn / name) is missing.
func parseCA(entry *goldap.Entry) (*CertificateAuthority, error) {
	if entry == nil {
		return nil, errors.New("adcs: parseCA: nil entry")
	}

	name := firstNonEmpty(
		entry.GetAttributeValue(AttrName),
		entry.GetAttributeValue(AttrCN),
	)
	if name == "" {
		return nil, fmt.Errorf("adcs: parseCA: entry %q missing name/cn", entry.DN)
	}

	ca := &CertificateAuthority{
		Name:      name,
		DNSName:   entry.GetAttributeValue(AttrDNSHostName),
		Templates: entry.GetAttributeValues(AttrCertificateTemplates),
		RawAttrs:  rawAttrs(entry),
	}

	// cACertificate is a DER-encoded X.509 cert. Earliest value wins;
	// CAs with historic / renewed certs return multiple.
	if raw := entry.GetRawAttributeValue(AttrCACertificate); len(raw) > 0 {
		if cert, err := x509.ParseCertificate(raw); err == nil {
			ca.Certificate = cert
		}
	}

	if flags := entry.GetAttributeValue(AttrFlags); flags != "" {
		if v, err := strconv.ParseUint(flags, 10, 32); err == nil {
			ca.Flags = uint32(v)
		}
	}

	// ACL parsing is best-effort: if the directory withheld the SD
	// (insufficient privilege) we leave the slices nil rather than
	// erroring.
	if sd := entry.GetRawAttributeValue(AttrNTSecurityDescriptor); len(sd) > 0 {
		if aces, err := ParseSecurityDescriptor(sd, nil); err == nil {
			// Callers that want CA-specific categorization can
			// re-parse Rights; we surface every ACE as
			// "enrollment rights" and let higher layers split.
			ca.EnrollmentRights = aces
		}
	}

	return ca, nil
}

// parseTemplate converts one *ldap.Entry of class pKICertificateTemplate
// into a *Template. EKUs and application-policy OIDs come directly
// from LDAP multi-valued string attrs. Flag words are stored as
// stringified uint32 (LDAP syntax 2.5.5.9 / Integer). Validity and
// renewal periods are 8-byte little-endian 100-ns FILETIME deltas
// (stored as a negative duration on the wire).
func parseTemplate(entry *goldap.Entry) (*Template, error) {
	if entry == nil {
		return nil, errors.New("adcs: parseTemplate: nil entry")
	}

	name := firstNonEmpty(
		entry.GetAttributeValue(AttrName),
		entry.GetAttributeValue(AttrCN),
	)
	if name == "" {
		return nil, fmt.Errorf("adcs: parseTemplate: entry %q missing name/cn", entry.DN)
	}

	tpl := &Template{
		Name:                     name,
		DisplayName:              entry.GetAttributeValue(AttrDisplayName),
		SchemaVersion:            int(parseUint32(entry.GetAttributeValue(AttrPKITemplateSchemaVersion))),
		ValidityPeriod:           parseFileTimeDelta(entry.GetRawAttributeValue(AttrPKIExpirationPeriod)),
		RenewalPeriod:            parseFileTimeDelta(entry.GetRawAttributeValue(AttrPKIOverlapPeriod)),
		MinRSAKeyLength:          int(parseUint32(entry.GetAttributeValue(AttrPKIMinimalKeySize))),
		AuthorizedSignatures:     int(parseUint32(entry.GetAttributeValue(AttrPKIRASignature))),
		EKUs:                     entry.GetAttributeValues(AttrExtKeyUsage),
		ApplicationPolicies:      entry.GetAttributeValues(AttrPKICertificateApplicationPolicy),
		MsPKICertificateNameFlag: parseUint32(entry.GetAttributeValue(AttrPKICertificateNameFlag)),
		MsPKIEnrollmentFlag:      parseUint32(entry.GetAttributeValue(AttrPKIEnrollmentFlag)),
		MsPKIPrivateKeyFlag:      parseUint32(entry.GetAttributeValue(AttrPKIPrivateKeyFlag)),
		MsPKICertificatePolicies: entry.GetAttributeValues(AttrPKICertificatePolicy),
		RawAttrs:                 rawAttrs(entry),
	}

	// Derived convenience flags — the underlying bits are defined in
	// internal/esc/flags.go but we re-check the relevant bit here so
	// callers that don't import esc still see the booleans populated.
	const (
		enrolleeSuppliesSubject uint32 = 0x00000001
		requireManagerApproval  uint32 = 0x00000002 // ms-PKI-Enrollment-Flag CT_FLAG_PEND_ALL_REQUESTS
	)
	tpl.EnrolleeSuppliesSubject = tpl.MsPKICertificateNameFlag&enrolleeSuppliesSubject != 0
	tpl.RequiresManagerApproval = tpl.MsPKIEnrollmentFlag&requireManagerApproval != 0

	if sd := entry.GetRawAttributeValue(AttrNTSecurityDescriptor); len(sd) > 0 {
		if aces, err := ParseSecurityDescriptor(sd, nil); err == nil {
			// Template ACL split mirrors Certipy: every ACE is
			// surfaced on EnrollmentRights; higher-level logic
			// partitions by rights-mask/ObjectType.
			tpl.EnrollmentRights = aces
		}
	}

	return tpl, nil
}

// parseUint32 converts a stringified unsigned int (as returned for
// LDAP Integer-syntax attrs) into uint32. Returns 0 on error / empty.
func parseUint32(s string) uint32 {
	if s == "" {
		return 0
	}
	// Some servers return negative signed ints for high-bit-set
	// flag words. Parse as signed int64 first, then truncate.
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return uint32(v)
	}
	if v, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(v)
	}
	return 0
}

// parseFileTimeDelta decodes the 8-byte little-endian FILETIME delta
// stored in pKIExpirationPeriod / pKIOverlapPeriod. Each tick is 100ns
// and the value is stored *negative* so an expiration "one year from
// now" lives on the wire as a negative int64. We return the positive
// absolute duration.
func parseFileTimeDelta(raw []byte) time.Duration {
	if len(raw) < 8 {
		return 0
	}
	v := int64(binary.LittleEndian.Uint64(raw))
	// Flip sign so the returned duration is positive.
	if v < 0 {
		v = -v
	}
	// 100ns ticks → time.Duration (nanoseconds).
	return time.Duration(v) * 100 * time.Nanosecond
}

// rawAttrs flattens the entry's attributes back into map form for
// round-trip debugging.
func rawAttrs(entry *goldap.Entry) map[string][]string {
	if entry == nil {
		return nil
	}
	out := make(map[string][]string, len(entry.Attributes))
	for _, a := range entry.Attributes {
		if a == nil {
			continue
		}
		// Copy the slice so callers can't mutate the entry's
		// underlying storage.
		vs := make([]string, len(a.Values))
		copy(vs, a.Values)
		out[a.Name] = vs
	}
	return out
}

// firstNonEmpty returns the first non-empty string in vs.
func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
