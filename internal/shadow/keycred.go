package shadow

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// KeyCredential entry identifiers per MS-KPP §2.2.2.
const (
	entryKeyID                             byte = 0x01
	entryKeyHash                           byte = 0x02
	entryKeyMaterial                       byte = 0x03
	entryKeyUsage                          byte = 0x04
	entryKeySource                         byte = 0x05
	entryDeviceID                          byte = 0x06
	entryCustomKeyInformation              byte = 0x07
	entryKeyApproximateLastLogonTimeStamp  byte = 0x08
	entryKeyCreationTime                   byte = 0x09
)

// Version 2 is the only version used in AD (Windows 10/Server 2016+).
const keyCredentialVersion2 uint32 = 0x00000200

// KeyUsage values per MS-KPP. 0x01 = NGC sign-in is what ShadowCredentials
// requires; Windows recognizes it for PKINIT pre-auth.
const (
	KeyUsageNGC byte = 0x01
)

// KeySource values. 0x00 = created on/for AD.
const (
	KeySourceAD byte = 0x00
)

// defaultCustomKeyInfo is the minimal valid CustomKeyInformation structure
// Certipy/DSInternals emit (Version=1, Flags=0). AD accepts the short form
// (2 bytes: Version + Flags as a single byte) as well as the full struct;
// we emit the short form matching Certipy's behavior.
var defaultCustomKeyInfo = []byte{0x01, 0x00}

// KeyCredential represents one decoded msDS-KeyCredentialLink entry.
type KeyCredential struct {
	Version       uint32
	KeyID         []byte // 32 bytes — SHA-256 of the KeyMaterial (public-key blob).
	KeyHash       []byte // 32 bytes — SHA-256 over the serialized entries that follow.
	KeyMaterial   []byte // BCRYPT_RSAKEY_BLOB for RSA keys.
	KeyUsage      byte
	KeySource     byte
	DeviceID      [16]byte
	CustomKeyInfo []byte
	LastLogonTime time.Time // zero = unset
	CreationTime  time.Time
}

// NewRSAKeyCredential builds a KeyCredential linking an RSA public key to a
// freshly-generated DeviceID, with CreationTime = time.Now().UTC(). The
// caller is expected to Marshal the result and append it to the target's
// msDS-KeyCredentialLink.
func NewRSAKeyCredential(pub *rsa.PublicKey) (*KeyCredential, error) {
	if pub == nil {
		return nil, fmt.Errorf("shadow: NewRSAKeyCredential: nil public key")
	}
	blob := EncodeRSABcryptBlob(pub)
	if len(blob) == 0 {
		return nil, fmt.Errorf("shadow: failed to encode RSA public key")
	}

	keyID := sha256.Sum256(blob)

	var dev [16]byte
	u, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("shadow: generate DeviceID: %w", err)
	}
	copy(dev[:], u[:])

	kc := &KeyCredential{
		Version:       keyCredentialVersion2,
		KeyID:         keyID[:],
		KeyMaterial:   blob,
		KeyUsage:      KeyUsageNGC,
		KeySource:     KeySourceAD,
		DeviceID:      dev,
		CustomKeyInfo: append([]byte(nil), defaultCustomKeyInfo...),
		CreationTime:  time.Now().UTC(),
	}
	return kc, nil
}

// MarshalBlob encodes the KeyCredential to the binary wire format
// (KEYCREDENTIALLINK_BLOB). The KeyHash is recomputed on each call so the
// caller need not populate it ahead of time.
func (k *KeyCredential) MarshalBlob() ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("shadow: MarshalBlob: nil KeyCredential")
	}
	if len(k.KeyMaterial) == 0 {
		return nil, fmt.Errorf("shadow: MarshalBlob: KeyMaterial is required")
	}

	version := k.Version
	if version == 0 {
		version = keyCredentialVersion2
	}

	keyID := k.KeyID
	if len(keyID) == 0 {
		sum := sha256.Sum256(k.KeyMaterial)
		keyID = sum[:]
	}

	customInfo := k.CustomKeyInfo
	if len(customInfo) == 0 {
		customInfo = defaultCustomKeyInfo
	}

	// Serialize the entries that follow KeyHash in the order Windows
	// expects. KeyHash is computed over the concatenation of these
	// entries' TLV bytes.
	var tail bytes.Buffer
	writeEntry(&tail, entryKeyMaterial, k.KeyMaterial)
	writeEntry(&tail, entryKeyUsage, []byte{k.KeyUsage})
	writeEntry(&tail, entryKeySource, []byte{k.KeySource})
	writeEntry(&tail, entryDeviceID, k.DeviceID[:])
	writeEntry(&tail, entryCustomKeyInformation, customInfo)
	if !k.LastLogonTime.IsZero() {
		writeEntry(&tail, entryKeyApproximateLastLogonTimeStamp, fileTimeBytes(k.LastLogonTime))
	}
	creation := k.CreationTime
	if creation.IsZero() {
		creation = time.Now().UTC()
	}
	writeEntry(&tail, entryKeyCreationTime, fileTimeBytes(creation))

	hash := sha256.Sum256(tail.Bytes())

	var out bytes.Buffer
	if err := binary.Write(&out, binary.LittleEndian, version); err != nil {
		return nil, fmt.Errorf("shadow: write version: %w", err)
	}
	writeEntry(&out, entryKeyID, keyID)
	writeEntry(&out, entryKeyHash, hash[:])
	out.Write(tail.Bytes())
	return out.Bytes(), nil
}

// UnmarshalBlob decodes a KEYCREDENTIALLINK_BLOB. Unknown entry
// identifiers are skipped (forward-compatible).
func UnmarshalBlob(raw []byte) (*KeyCredential, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("shadow: KEYCREDENTIALLINK_BLOB too short (%d bytes)", len(raw))
	}
	version := binary.LittleEndian.Uint32(raw[0:4])
	kc := &KeyCredential{Version: version}

	pos := 4
	for pos < len(raw) {
		if pos+3 > len(raw) {
			return nil, fmt.Errorf("shadow: truncated entry header at offset %d", pos)
		}
		length := int(binary.LittleEndian.Uint16(raw[pos : pos+2]))
		ident := raw[pos+2]
		pos += 3
		if pos+length > len(raw) {
			return nil, fmt.Errorf("shadow: entry %#x claims %d bytes but only %d remain", ident, length, len(raw)-pos)
		}
		val := raw[pos : pos+length]
		switch ident {
		case entryKeyID:
			kc.KeyID = append([]byte(nil), val...)
		case entryKeyHash:
			kc.KeyHash = append([]byte(nil), val...)
		case entryKeyMaterial:
			kc.KeyMaterial = append([]byte(nil), val...)
		case entryKeyUsage:
			if length >= 1 {
				kc.KeyUsage = val[0]
			}
		case entryKeySource:
			if length >= 1 {
				kc.KeySource = val[0]
			}
		case entryDeviceID:
			if length == 16 {
				copy(kc.DeviceID[:], val)
			}
		case entryCustomKeyInformation:
			kc.CustomKeyInfo = append([]byte(nil), val...)
		case entryKeyApproximateLastLogonTimeStamp:
			if length == 8 {
				kc.LastLogonTime = fileTimeFromBytes(val)
			}
		case entryKeyCreationTime:
			if length == 8 {
				kc.CreationTime = fileTimeFromBytes(val)
			}
		default:
			// Unknown entry — skip silently for forward compat.
		}
		pos += length
	}
	return kc, nil
}

// MarshalDNBinary returns the LDAP DNBinary value for msDS-KeyCredentialLink.
// Format: "B:<hexlen>:<hex>:<owner-DN>" where hexlen is the number of hex
// characters (i.e. 2 * len(blob)).
func (k *KeyCredential) MarshalDNBinary(ownerDN string) string {
	blob, err := k.MarshalBlob()
	if err != nil {
		return ""
	}
	hexBlob := strings.ToUpper(hex.EncodeToString(blob))
	return fmt.Sprintf("B:%d:%s:%s", len(hexBlob), hexBlob, ownerDN)
}

// ParseDNBinary decodes one msDS-KeyCredentialLink DNBinary value. It
// returns the parsed KeyCredential plus the owner DN suffix.
func ParseDNBinary(s string) (*KeyCredential, string, error) {
	if !strings.HasPrefix(s, "B:") {
		return nil, "", fmt.Errorf("shadow: DNBinary value must begin with 'B:': %q", shortErr(s))
	}
	parts := strings.SplitN(s, ":", 4)
	if len(parts) != 4 {
		return nil, "", fmt.Errorf("shadow: DNBinary value must have 4 colon-separated fields")
	}
	lenStr, hexBlob, ownerDN := parts[1], parts[2], parts[3]
	var declared int
	if _, err := fmt.Sscanf(lenStr, "%d", &declared); err != nil {
		return nil, "", fmt.Errorf("shadow: DNBinary length field %q: %w", lenStr, err)
	}
	if declared != len(hexBlob) {
		return nil, "", fmt.Errorf("shadow: DNBinary length mismatch: declared %d, actual %d", declared, len(hexBlob))
	}
	raw, err := hex.DecodeString(hexBlob)
	if err != nil {
		return nil, "", fmt.Errorf("shadow: DNBinary hex decode: %w", err)
	}
	kc, err := UnmarshalBlob(raw)
	if err != nil {
		return nil, "", err
	}
	return kc, ownerDN, nil
}

// writeEntry appends one TLV entry (2-byte LE length, 1-byte ident, value)
// to w.
func writeEntry(w *bytes.Buffer, ident byte, val []byte) {
	var hdr [3]byte
	binary.LittleEndian.PutUint16(hdr[0:2], uint16(len(val)))
	hdr[2] = ident
	w.Write(hdr[:])
	w.Write(val)
}

// fileTimeBytes converts a Go time.Time to an 8-byte little-endian Windows
// FILETIME (100-ns intervals since 1601-01-01 UTC).
func fileTimeBytes(t time.Time) []byte {
	const unixToFiletime = 116444736000000000 // 100-ns ticks from 1601 to 1970.
	ticks := uint64(t.UTC().UnixNano()/100) + unixToFiletime
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], ticks)
	return buf[:]
}

// fileTimeFromBytes converts an 8-byte little-endian Windows FILETIME to a
// Go time.Time.
func fileTimeFromBytes(b []byte) time.Time {
	if len(b) != 8 {
		return time.Time{}
	}
	const unixToFiletime = 116444736000000000
	ticks := binary.LittleEndian.Uint64(b)
	if ticks < unixToFiletime {
		return time.Time{}
	}
	ns := int64(ticks-unixToFiletime) * 100
	return time.Unix(0, ns).UTC()
}

// shortErr truncates long strings for readable error output.
func shortErr(s string) string {
	if len(s) <= 48 {
		return s
	}
	return s[:48] + "..."
}
