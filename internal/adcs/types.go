// Package adcs models Active Directory Certificate Services objects and
// provides LDAP-backed enumeration helpers. The types declared here are the
// contract consumed by certigo's `find`, `ca`, `template`, and `esc`
// subcommands / packages.
//
// Shape mirrors Certipy's Python dataclasses (`find/find.py:CA`,
// `find/find.py:Template`) so output formatters can round-trip fields
// one-for-one.
package adcs

import (
	"crypto/x509"
	"time"
)

// CertificateAuthority is an AD CS Certification Authority as surfaced via
// pKIEnrollmentService LDAP objects plus their RPC-reachable config.
type CertificateAuthority struct {
	Name             string // CN of the pKIEnrollmentService object
	DNSName          string // dNSHostName
	Certificate      *x509.Certificate
	Templates        []string // cACertificateTemplate values (published templates)
	EnrollmentAgents []string // certificateEnrollmentAgentRights owners (ESC3-related)

	// ACL info parsed from nTSecurityDescriptor, if we could retrieve it.
	EnrollmentRights []Ace // PrincipalSelfRight / EnrollmentRight on the CA
	ManageCARights   []Ace // Manage-CA permission holders
	ManageCertRights []Ace // Manage-Certificates permission holders

	// Configuration fetched via RPC when accessible (EditFlags, flags, etc.).
	Flags              uint32
	EditFlags          uint32
	RequestDisposition uint32

	// WebEnrollment indicates the /certsrv/ HTTP endpoint was reachable.
	WebEnrollment bool
	HTTPS         bool

	// Raw LDAP attributes for debugging / custom formatters.
	RawAttrs map[string][]string
}

// Template is an AD CS certificate template as stored under
// CN=Templates,CN=Public Key Services,CN=Services,CN=Configuration.
type Template struct {
	Name        string
	DisplayName string
	// Enabled is true when at least one enumerated CA publishes this template.
	Enabled bool
	// EnrollableByCurrentUser is true when at least one EnrollmentRights
	// ACE matches the bound principal's IdentitySet. Populated by
	// MarkEnrollableTemplates; zero by default.
	EnrollableByCurrentUser bool
	SchemaVersion           int
	ValidityPeriod          time.Duration
	RenewalPeriod           time.Duration
	MinRSAKeyLength         int
	EnrolleeSuppliesSubject bool
	RequiresManagerApproval bool
	AuthorizedSignatures    int

	// EKU / Application Policy OIDs - the fundamental vulnerability surface.
	EKUs                []string
	ApplicationPolicies []string

	// SAN / requester-supplied subject handling.
	MsPKICertificateNameFlag uint32
	MsPKIEnrollmentFlag      uint32
	MsPKIPrivateKeyFlag      uint32
	MsPKICertificatePolicies []string

	// ACLs derived from nTSecurityDescriptor.
	EnrollmentRights []Ace // EnrollmentRight
	AutoEnrollRights []Ace // AutoEnrollmentRight
	WriteOwner       []Ace // WRITE_OWNER
	WriteDacl        []Ace // WRITE_DAC
	WriteProperty    []Ace // WRITE_PROPERTY (any attr)
	FullControl      []Ace // FULL_CONTROL

	// Published-on list (CA names that publish this template).
	PublishedBy []string

	// Vulnerability findings attached after ESC rules run.
	Findings []Finding

	// Raw LDAP attributes for debugging / custom formatters.
	RawAttrs map[string][]string
}

// Ace is a minimal ACL entry: principal SID (resolved) + display string.
type Ace struct {
	SID    string // S-1-5-21-...
	Name   string // "CORP\\alice" (resolved) or SID if unresolved
	Rights string // human-readable rights summary
}

// Finding is an ESC detection result attached to a Template. One Template may
// accumulate multiple findings (e.g., ESC1 + ESC6 combo).
type Finding struct {
	ESC         string         // "ESC1", "ESC2", ..., "ESC16"
	Severity    string         // "critical", "high", "medium", "low", "info"
	Title       string         // short human title
	Description string         // paragraph explaining the issue
	Evidence    map[string]any // structured evidence (flag bits, SIDs, etc.)
}
