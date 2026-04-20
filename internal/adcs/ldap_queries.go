package adcs

// LDAP class names, attribute names, and base-DN fragments used by the
// Certipy-compatible enumeration flow. The attribute lists mirror the
// Python reference in certipy/lib/find.py (CAS_BASE_QUERY /
// TEMPLATES_BASE_QUERY) so downstream parsing is one-for-one.
const (
	// Object classes (see MS-WCCE / MS-CRTD).
	ClassPKIEnrollmentService   = "pKIEnrollmentService"
	ClassPKICertificateTemplate = "pKICertificateTemplate"

	// Object-category DNs appear only in filter fragments — the
	// pKIEnrollmentService objectCategory literal below is checked in a
	// sub-filter form, but we primarily use (objectClass=...) to avoid
	// dragging in a DN that varies per forest. Certipy uses
	// (objectCategory=pKIEnrollmentService) / (objectCategory=pKICertificateTemplate).
	FilterEnrollmentService   = "(objectCategory=pKIEnrollmentService)"
	FilterCertificateTemplate = "(objectCategory=pKICertificateTemplate)"

	// Common pKIEnrollmentService / pKICertificateTemplate attributes.
	AttrCN                              = "cn"
	AttrName                            = "name"
	AttrDisplayName                     = "displayName"
	AttrDNSHostName                     = "dNSHostName"
	AttrCACertificate                   = "cACertificate"
	AttrCertificateTemplates            = "certificateTemplates"
	AttrNTSecurityDescriptor            = "nTSecurityDescriptor"
	AttrObjectClass                     = "objectClass"
	AttrFlags                           = "flags"
	AttrRevision                        = "revision"
	AttrPKIDefaultKeySpec               = "pKIDefaultKeySpec"
	AttrPKIExpirationPeriod             = "pKIExpirationPeriod"
	AttrPKIOverlapPeriod                = "pKIOverlapPeriod"
	AttrPKIDefaultCSPs                  = "pKIDefaultCSPs"
	AttrPKIMaxIssuingDepth              = "pKIMaxIssuingDepth"
	AttrPKICertificateNameFlag          = "msPKI-Certificate-Name-Flag"
	AttrPKIEnrollmentFlag               = "msPKI-Enrollment-Flag"
	AttrPKIPrivateKeyFlag               = "msPKI-Private-Key-Flag"
	AttrPKICertificatePolicy            = "msPKI-Certificate-Policy"
	AttrPKICertificateApplicationPolicy = "msPKI-Certificate-Application-Policy"
	AttrPKIRAApplicationPolicies        = "msPKI-RA-Application-Policies"
	AttrPKIRASignature                  = "msPKI-RA-Signature"
	AttrPKIMinimalKeySize               = "msPKI-Minimal-Key-Size"
	AttrPKITemplateSchemaVersion        = "msPKI-Template-Schema-Version"
	AttrPKITemplateMinorRevision        = "msPKI-Template-Minor-Revision"
	AttrExtKeyUsage                     = "pKIExtendedKeyUsage"
	AttrPKICriticalExtensions           = "pKICriticalExtensions"
	AttrPKIKeyUsage                     = "pKIKeyUsage"
)

// CAAttrs is the attribute list fetched for each pKIEnrollmentService
// entry. Mirrors Certipy's `CAS_BASE_QUERY` attribute set.
var CAAttrs = []string{
	AttrCN,
	AttrName,
	AttrDNSHostName,
	AttrCACertificate,
	AttrCertificateTemplates,
	AttrNTSecurityDescriptor,
	AttrObjectClass,
	AttrFlags,
}

// TemplateAttrs is the attribute list fetched for each
// pKICertificateTemplate entry. Mirrors Certipy's `TEMPLATES_BASE_QUERY`
// attribute set.
var TemplateAttrs = []string{
	AttrCN,
	AttrName,
	AttrDisplayName,
	AttrObjectClass,
	AttrFlags,
	AttrRevision,
	AttrPKIDefaultKeySpec,
	AttrPKIExpirationPeriod,
	AttrPKIOverlapPeriod,
	AttrPKIDefaultCSPs,
	AttrPKIMaxIssuingDepth,
	AttrPKICertificateNameFlag,
	AttrPKIEnrollmentFlag,
	AttrPKIPrivateKeyFlag,
	AttrPKICertificatePolicy,
	AttrPKICertificateApplicationPolicy,
	AttrPKIRAApplicationPolicies,
	AttrPKIRASignature,
	AttrPKIMinimalKeySize,
	AttrPKITemplateSchemaVersion,
	AttrPKITemplateMinorRevision,
	AttrExtKeyUsage,
	AttrPKICriticalExtensions,
	AttrPKIKeyUsage,
	AttrNTSecurityDescriptor,
}

// RootDSEAttrs are the minimum attributes needed to learn the
// default / configuration naming contexts from an anonymous RootDSE
// lookup.
var RootDSEAttrs = []string{
	"defaultNamingContext",
	"configurationNamingContext",
	"rootDomainNamingContext",
}

// DN fragments for the Public Key Services subtree.
const (
	// PKIServicesRelDN is appended to the configuration NC to reach
	// the PKI services container.
	PKIServicesRelDN = "CN=Public Key Services,CN=Services"

	// EnrollmentServicesRelDN locates the parent of all
	// pKIEnrollmentService objects (one child per CA).
	EnrollmentServicesRelDN = "CN=Enrollment Services," + PKIServicesRelDN

	// CertificateTemplatesRelDN locates the parent of all
	// pKICertificateTemplate objects.
	CertificateTemplatesRelDN = "CN=Certificate Templates," + PKIServicesRelDN
)

// JoinDN composes relativeDN + "," + base when base is non-empty.
// Otherwise returns relativeDN unchanged.
func JoinDN(relativeDN, base string) string {
	if base == "" {
		return relativeDN
	}
	return relativeDN + "," + base
}
