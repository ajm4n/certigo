package krb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"

	"github.com/ajm4n/certigo/internal/auth"
)

// NewClient builds a gokrb5 *client.Client from certigo Credentials. It
// selects the appropriate constructor based on which secret is present:
//   - Password  -> client.NewWithPassword
//   - NT hash   -> client.NewWithKeytab fed a synthetic RC4-HMAC keytab
//     (DisablePAFXFAST = true, matching Impacket's behavior for hash auth).
//
// Kerberos ticket / PKINIT paths are handled by GetTGTFromCCache and the
// M3 PKINIT package respectively.
func NewClient(creds *auth.Credentials, cfg *config.Config) (*client.Client, error) {
	if creds == nil {
		return nil, errors.New("krb: nil credentials")
	}
	if creds.Username == "" {
		return nil, errors.New("krb: username required")
	}
	realm := strings.ToUpper(strings.TrimSpace(creds.Domain))
	if realm == "" {
		return nil, errors.New("krb: domain/realm required")
	}

	switch {
	case creds.HasPassword():
		return client.NewWithPassword(
			creds.Username,
			realm,
			creds.Password,
			cfg,
			client.DisablePAFXFAST(true),
		), nil
	case creds.HasNTHash():
		kt, err := keytabFromNTHash(creds.Username, realm, creds.NTHash)
		if err != nil {
			return nil, fmt.Errorf("krb: build NT-hash keytab: %w", err)
		}
		return client.NewWithKeytab(
			creds.Username,
			realm,
			kt,
			cfg,
			client.DisablePAFXFAST(true),
		), nil
	default:
		return nil, errors.New("krb: credentials carry neither password nor NT hash (ccache/PKINIT paths are handled separately)")
	}
}

// keytabFromNTHash constructs a *keytab.Keytab containing a single RC4-HMAC
// entry whose key bytes are the caller-supplied NT hash. gokrb5's public API
// (Keytab.AddEntry) only accepts a plaintext password, so we marshal the
// entry ourselves using the documented MIT keytab format and unmarshal the
// resulting bytes into a fresh Keytab.
//
// Reference: https://web.mit.edu/kerberos/krb5-devel/doc/formats/keytab_file_format.html
func keytabFromNTHash(username, realm string, ntHash []byte) (*keytab.Keytab, error) {
	if len(ntHash) != 16 {
		return nil, fmt.Errorf("NT hash must be 16 bytes, got %d", len(ntHash))
	}

	// Entry body layout (big-endian, v2):
	//   int16 num_components (excludes realm)
	//   counted_octet realm
	//   counted_octet component[]
	//   int32 name_type
	//   uint32 timestamp (seconds since epoch)
	//   uint8  kvno8
	//   int16  key_type
	//   int16  key_length
	//   bytes  key_value
	//   uint32 kvno (32-bit)
	var body bytes.Buffer
	writeInt16(&body, 1) // one component (the username)
	writeCountedOctet(&body, realm)
	writeCountedOctet(&body, username)
	writeInt32(&body, nametype.KRB_NT_PRINCIPAL)
	writeUint32(&body, uint32(time.Now().Unix()))
	body.WriteByte(0x01) // kvno8
	writeInt16(&body, int16(etypeID.RC4_HMAC))
	writeInt16(&body, int16(len(ntHash)))
	body.Write(ntHash)
	writeUint32(&body, 1) // kvno32

	// Keytab file layout:
	//   uint8 first_byte (0x05)
	//   uint8 version    (0x02)
	//   int32 entry_length
	//   <entry body>
	var buf bytes.Buffer
	buf.WriteByte(0x05)
	buf.WriteByte(0x02)
	writeInt32(&buf, int32(body.Len()))
	buf.Write(body.Bytes())

	kt := keytab.New()
	if err := kt.Unmarshal(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("unmarshal synthetic keytab: %w", err)
	}
	return kt, nil
}

func writeInt16(w *bytes.Buffer, v int16) {
	_ = binary.Write(w, binary.BigEndian, v)
}

func writeInt32(w *bytes.Buffer, v int32) {
	_ = binary.Write(w, binary.BigEndian, v)
}

func writeUint32(w *bytes.Buffer, v uint32) {
	_ = binary.Write(w, binary.BigEndian, v)
}

func writeCountedOctet(w *bytes.Buffer, s string) {
	writeInt16(w, int16(len(s)))
	w.WriteString(s)
}
