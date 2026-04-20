package krb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// GetTGT performs an AS-REQ via cl and returns the encoded TGT credentials
// suitable for feeding into client.NewFromCCache or subsequent TGS requests.
// The underlying session is stashed on cl; callers that need to persist the
// TGT to disk should follow up with SaveTGTToCCache on the same client.
// Caller owns the client lifecycle.
func GetTGT(cl *client.Client) (*credentials.Credentials, error) {
	if cl == nil {
		return nil, errors.New("krb: nil client")
	}
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("krb: AS-REQ: %w", err)
	}
	return cl.Credentials, nil
}

// GetTGTFromCCache loads an existing TGT from the given ccache path (or
// $KRB5CCNAME if path is ""). Returns the gokrb5 Credentials carrying the
// TGT ready to feed into client.NewFromCCache.
func GetTGTFromCCache(path string) (*credentials.Credentials, error) {
	resolved, err := resolveCCachePath(path)
	if err != nil {
		return nil, err
	}
	cc, err := credentials.LoadCCache(resolved)
	if err != nil {
		return nil, fmt.Errorf("krb: load ccache %q: %w", resolved, err)
	}
	return cc.GetClientCredentials(), nil
}

// SaveTGTToCCache writes a fresh TGT obtained via AS-REQ to path as a
// MIT-format ccache v4 file. If path == "" and $KRB5CCNAME is set, that value
// is used; otherwise returns an error.
//
// Note: gokrb5 v8 does not expose the session TGT attached to a live
// *client.Client, so this helper issues its own AS-REQ against the client's
// configured KDC and writes the resulting Ticket / EncKDCRepPart into a
// ccache file. This requires the client's Credentials to still carry
// sufficient secret material (password or keytab) to perform the exchange.
func SaveTGTToCCache(cl *client.Client, path string) error {
	if cl == nil {
		return errors.New("krb: nil client")
	}
	resolved, err := resolveCCachePath(path)
	if err != nil {
		return err
	}

	realm := cl.Credentials.Domain()
	cname := cl.Credentials.CName()
	if realm == "" || len(cname.NameString) == 0 {
		return errors.New("krb: client has no username/realm; cannot AS-REQ")
	}

	asReq, err := messages.NewASReqForTGT(realm, cl.Config, cname)
	if err != nil {
		return fmt.Errorf("krb: build AS-REQ: %w", err)
	}
	asRep, err := cl.ASExchange(realm, asReq, 0)
	if err != nil {
		return fmt.Errorf("krb: AS-REQ exchange: %w", err)
	}

	b, err := marshalCCache(cname, realm, asRep.Ticket, asRep.DecryptedEncPart)
	if err != nil {
		return fmt.Errorf("krb: marshal ccache: %w", err)
	}
	if err := os.WriteFile(resolved, b, 0o600); err != nil {
		return fmt.Errorf("krb: write ccache %q: %w", resolved, err)
	}
	return nil
}

// resolveCCachePath implements the KRB5CCNAME fallback. An explicit path wins;
// otherwise KRB5CCNAME is honored, with any "FILE:" prefix stripped. Returns
// an error when neither is set.
func resolveCCachePath(path string) (string, error) {
	if path != "" {
		return path, nil
	}
	env := os.Getenv("KRB5CCNAME")
	if env == "" {
		return "", errors.New("krb: no ccache path supplied and KRB5CCNAME is unset")
	}
	if strings.HasPrefix(env, "FILE:") {
		return strings.TrimPrefix(env, "FILE:"), nil
	}
	return env, nil
}

// marshalCCache serializes a single TGT entry into MIT ccache v4 format.
//
// The format is documented at
// https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html.
// We emit version 4 with no header fields, a default principal matching
// cname@realm, and exactly one credential covering the TGT.
func marshalCCache(cname types.PrincipalName, realm string, tgt messages.Ticket, dep messages.EncKDCRepPart) ([]byte, error) {
	tktBytes, err := tgt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal ticket: %w", err)
	}

	var buf bytes.Buffer
	// File magic: 0x05, 0x04 (version 4).
	buf.WriteByte(0x05)
	buf.WriteByte(0x04)
	// Header: 16-bit length then zero or more (tag, length, value) triples.
	// We emit an empty header.
	writeUint16BE(&buf, 0)

	// Default principal: cname@realm.
	writePrincipal(&buf, cname, realm)

	// Single credential: TGT (server = krbtgt/REALM@REALM).
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	// Credential body.
	writePrincipal(&buf, cname, realm) // client
	writePrincipal(&buf, sname, realm) // server
	writeKey(&buf, dep.Key)            // session key
	writeUint32BE(&buf, uint32(dep.AuthTime.Unix()))
	writeUint32BE(&buf, uint32(dep.StartTime.Unix()))
	writeUint32BE(&buf, uint32(dep.EndTime.Unix()))
	writeUint32BE(&buf, uint32(dep.RenewTill.Unix()))
	buf.WriteByte(0) // is_skey = false
	writeTicketFlags(&buf, dep.Flags)
	writeUint32BE(&buf, 0) // num_addresses
	writeUint32BE(&buf, 0) // num_authdata
	writeData(&buf, tktBytes)
	writeData(&buf, nil) // second_ticket (empty)

	return buf.Bytes(), nil
}

// writePrincipal emits a MIT ccache principal: int32 name_type, int32
// num_components, counted_octet realm, counted_octet component[].
func writePrincipal(w *bytes.Buffer, pn types.PrincipalName, realm string) {
	writeInt32BE(w, pn.NameType)
	writeInt32BE(w, int32(len(pn.NameString)))
	writeData(w, []byte(realm))
	for _, c := range pn.NameString {
		writeData(w, []byte(c))
	}
}

// writeKey emits a MIT ccache keyblock. Version 4 uses int16 key_type and
// int32 key_length. (Version 3 repeats the type twice; we always emit v4.)
func writeKey(w *bytes.Buffer, k types.EncryptionKey) {
	writeUint16BE(w, uint16(k.KeyType))
	writeData(w, k.KeyValue)
}

// writeTicketFlags emits a 4-byte big-endian representation of asn1.BitString
// ticket flags. If the input is shorter than 4 bytes it's right-padded with
// zeros; if longer, it's truncated (shouldn't happen for well-formed Kerberos
// flags which always fit in 32 bits).
func writeTicketFlags(w *bytes.Buffer, bs asn1.BitString) {
	var out [4]byte
	copy(out[:], bs.Bytes)
	w.Write(out[:])
}

// writeData emits a MIT ccache counted_octet: int32 length followed by the
// raw bytes. A nil or empty payload is emitted as a zero-length record.
func writeData(w *bytes.Buffer, b []byte) {
	writeInt32BE(w, int32(len(b)))
	if len(b) > 0 {
		w.Write(b)
	}
}

func writeUint16BE(w *bytes.Buffer, v uint16) {
	_ = binary.Write(w, binary.BigEndian, v)
}

func writeUint32BE(w *bytes.Buffer, v uint32) {
	_ = binary.Write(w, binary.BigEndian, v)
}

func writeInt32BE(w *bytes.Buffer, v int32) {
	_ = binary.Write(w, binary.BigEndian, v)
}
