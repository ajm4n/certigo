package pkinit

import "encoding/asn1"

// ASN.1 object identifiers used in PKINIT and the surrounding CMS / PKCS
// envelopes. The RFC 4556 identifiers live under the Kerberos arc
// (1.3.6.1.5.2), CMS/PKCS identifiers under RSADSI (1.2.840.113549), and the
// NIST hash / signature identifiers under joint-iso-itu-t(2).
var (
	// OIDPKINITAuthData is id-pkinit-authData - the eContentType used when
	// wrapping an AuthPack in CMS SignedData (RFC 4556 §3.2.1).
	OIDPKINITAuthData = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}
	// OIDPKINITDHKeyData is id-pkinit-DHKeyData - the eContentType the KDC
	// uses to wrap the DH reply payload (RFC 4556 §3.2.3.2).
	OIDPKINITDHKeyData = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}
	// OIDPKINITKPClientAuth is id-pkinit-KPClientAuth - the client EKU that
	// a PKINIT-capable certificate must carry (RFC 4556 §3.2.2).
	OIDPKINITKPClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4}
	// OIDSmartCardLogon is Microsoft's smart-card logon EKU; Active Directory
	// KDCs accept it in lieu of id-pkinit-KPClientAuth.
	OIDSmartCardLogon = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
	// OIDCMSSignedData is id-signedData (PKCS#7 / RFC 5652) - the outer
	// ContentInfo type for a CMS SignedData envelope.
	OIDCMSSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	// OIDCMSData is id-data (PKCS#7 / RFC 5652) - placeholder for an
	// opaque octet-string content.
	OIDCMSData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	// OIDSHA256 is the NIST SHA-256 hash algorithm OID.
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	// OIDRSASignatureSHA256 is sha256WithRSAEncryption (PKCS#1).
	OIDRSASignatureSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	// OIDDHKeyAgreement is dhKeyAgreement (PKCS#3) - identifies a
	// DomainParameters / SubjectPublicKeyInfo as carrying Diffie-Hellman
	// material.
	OIDDHKeyAgreement = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 3, 1}
)
