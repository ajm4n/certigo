package esc

// ms-PKI-Certificate-Name-Flag bits (see [MS-CRTD] §2.27 and the
// ms-PKI-Certificate-Name-Flag attribute on certificate templates).
const (
	CTFlagEnrolleeSuppliesSubject        uint32 = 0x00000001
	CTFlagEnrolleeSuppliesSubjectAltName uint32 = 0x00010000
	// CTFlagNoSecurityExtension, when set, suppresses the
	// szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) SID-binding
	// extension - the prerequisite for ESC9.
	CTFlagNoSecurityExtension uint32 = 0x80000000
)

// ms-PKI-Enrollment-Flag bits (see [MS-CRTD] §2.26).
const (
	EnrollFlagIncludeSymmetricAlgorithms         uint32 = 0x00000001
	EnrollFlagAutoenrollment                     uint32 = 0x00000020
	EnrollFlagRequireUserInteraction             uint32 = 0x00000100
	EnrollFlagRemoveInvalidCertFromPersonalStore uint32 = 0x00000400
)

// CA EditFlags bits relevant to ESC6.
const (
	// EditFlagAttributeSubjectAltName2 corresponds to
	// EDITF_ATTRIBUTESUBJECTALTNAME2. When set on a CA, any enrollee can
	// embed a Subject Alternative Name in the request regardless of the
	// template's name-flag settings.
	EditFlagAttributeSubjectAltName2 uint32 = 0x00040000
)

// CertificateAuthority.Flags bits relevant to ESC11. The constant name
// mirrors Microsoft's IF_ENFORCEENCRYPTICERTREQUEST flag on a CA.
const (
	CAFlagEnforceEncryptICertRequest uint32 = 0x00000200
)

// AnyPurposeEKUs enumerates EKU OIDs that grant any application purpose,
// making the template usable for client authentication and therefore
// qualifying it for ESC2.
var AnyPurposeEKUs = []string{
	"2.5.29.37.0", // anyExtendedKeyUsage
}

// ClientAuthEKUs enumerates EKU OIDs whose presence makes the certificate
// usable for domain authentication (ESC1 precondition).
var ClientAuthEKUs = []string{
	"1.3.6.1.5.5.7.3.2",      // id-kp-clientAuth (TLS Web Client Authentication)
	"1.3.6.1.5.2.3.4",        // id-pkinit-KPClientAuth (PKINIT Client Authentication)
	"1.3.6.1.4.1.311.20.2.2", // szOID_KP_SMARTCARD_LOGON
	"2.5.29.37.0",            // anyExtendedKeyUsage
}

// CertRequestAgentEKU is the "Certificate Request Agent" EKU - when present
// in a template that a low-priv user can enrol, ESC3 applies.
const CertRequestAgentEKU = "1.3.6.1.4.1.311.20.2.1"
