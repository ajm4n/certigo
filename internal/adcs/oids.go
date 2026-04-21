package adcs

// KnownOIDs maps X.509 / AD CS OID strings to their human-readable names.
// Anything not in this map is rendered as the raw OID.
var KnownOIDs = map[string]string{
	// Extended Key Usages (RFC 5280 + Microsoft extensions).
	"1.3.6.1.5.5.7.3.1":       "Server Authentication",
	"1.3.6.1.5.5.7.3.2":       "Client Authentication",
	"1.3.6.1.5.5.7.3.3":       "Code Signing",
	"1.3.6.1.5.5.7.3.4":       "Secure Email",
	"1.3.6.1.5.5.7.3.5":       "IPSec End System",
	"1.3.6.1.5.5.7.3.6":       "IPSec Tunnel",
	"1.3.6.1.5.5.7.3.7":       "IPSec User",
	"1.3.6.1.5.5.7.3.8":       "Time Stamping",
	"1.3.6.1.5.5.7.3.9":       "OCSP Signing",
	"2.5.29.37.0":             "Any Purpose",
	"1.3.6.1.4.1.311.10.3.1":  "Microsoft Trust List Signing",
	"1.3.6.1.4.1.311.10.3.2":  "Microsoft Time Stamping",
	"1.3.6.1.4.1.311.10.3.3":  "Microsoft Server Gated Crypto",
	"1.3.6.1.4.1.311.10.3.4":  "Encrypting File System",
	"1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
	"1.3.6.1.4.1.311.10.3.5":  "Windows Hardware Driver Verification",
	"1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
	"1.3.6.1.4.1.311.10.3.11": "Key Recovery",
	"1.3.6.1.4.1.311.10.3.12": "Document Signing",
	"1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
	"1.3.6.1.4.1.311.10.3.19": "Revoked List Signer",
	"1.3.6.1.4.1.311.20.2.1":  "Certificate Request Agent",
	"1.3.6.1.4.1.311.20.2.2":  "Smart Card Logon",
	"1.3.6.1.4.1.311.20.2.3":  "User Principal Name",
	"1.3.6.1.4.1.311.21.5":    "Private Key Archival",
	"1.3.6.1.4.1.311.21.6":    "Key Recovery Agent",
	"1.3.6.1.4.1.311.21.19":   "Directory Service Email Replication",
	"1.3.6.1.5.2.3.4":         "PKINIT Client Authentication",
	"1.3.6.1.5.2.3.5":         "PKINIT KDC Authentication",

	// Microsoft Application Policies that aren't EKUs.
	"1.3.6.1.4.1.311.54.1.2":  "Remote Desktop Authentication",
	"1.3.6.1.4.1.311.80.1":    "Document Encryption",
}

// OIDName returns the friendly name for oid, or oid itself if unknown.
func OIDName(oid string) string {
	if name, ok := KnownOIDs[oid]; ok {
		return name
	}
	return oid
}
