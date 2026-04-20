package pkinit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// SavePKINITTGTToCCache writes the PKINIT-obtained TGT to an MIT ccache v4
// file. It mirrors internal/auth/krb.SaveTGTToCCache but operates on raw
// messages.Ticket / messages.EncKDCRepPart values (rather than a live
// *client.Client) because gokrb5's client has no way to accept
// externally-acquired session material.
//
// The written file contains exactly one credential - the TGT - with server
// = krbtgt/REALM@REALM, session key = dep.Key, and the ticket flags /
// lifetimes verbatim from the decrypted AS-REP.
func SavePKINITTGTToCCache(path string, cname types.PrincipalName, realm string, tkt messages.Ticket, dep messages.EncKDCRepPart) error {
	if path == "" {
		return errors.New("pkinit: SavePKINITTGTToCCache requires a path")
	}
	if realm == "" {
		return errors.New("pkinit: SavePKINITTGTToCCache requires a realm")
	}
	if len(cname.NameString) == 0 {
		return errors.New("pkinit: SavePKINITTGTToCCache requires a principal name")
	}

	b, err := marshalCCache(cname, realm, tkt, dep)
	if err != nil {
		return fmt.Errorf("pkinit: marshal ccache: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("pkinit: write ccache %q: %w", path, err)
	}
	return nil
}

// marshalCCache emits a single-credential MIT ccache v4 buffer. Layout:
//
//	0x05 0x04                 file magic + version
//	uint16   header length (we emit 0)
//	principal  default (client)
//	<credential>
//
// and a credential is:
//
//	principal client
//	principal server  (krbtgt/REALM@REALM)
//	keyblock   session key
//	uint32     auth_time
//	uint32     start_time
//	uint32     end_time
//	uint32     renew_till
//	uint8      is_skey (0)
//	uint32     ticket_flags (big-endian)
//	uint32     num_addresses (0)
//	uint32     num_authdata  (0)
//	counted_octet ticket
//	counted_octet second_ticket (empty)
func marshalCCache(cname types.PrincipalName, realm string, tgt messages.Ticket, dep messages.EncKDCRepPart) ([]byte, error) {
	tktBytes, err := tgt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal ticket: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteByte(0x05)
	buf.WriteByte(0x04)
	writeUint16BE(&buf, 0) // empty header

	writePrincipal(&buf, cname, realm) // default principal

	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	writePrincipal(&buf, cname, realm)
	writePrincipal(&buf, sname, realm)
	writeKey(&buf, dep.Key)
	writeUint32BE(&buf, uint32(dep.AuthTime.Unix()))
	writeUint32BE(&buf, uint32(dep.StartTime.Unix()))
	writeUint32BE(&buf, uint32(dep.EndTime.Unix()))
	writeUint32BE(&buf, uint32(dep.RenewTill.Unix()))
	buf.WriteByte(0) // is_skey
	writeTicketFlags(&buf, dep.Flags)
	writeUint32BE(&buf, 0) // num_addresses
	writeUint32BE(&buf, 0) // num_authdata
	writeData(&buf, tktBytes)
	writeData(&buf, nil)

	return buf.Bytes(), nil
}

func writePrincipal(w *bytes.Buffer, pn types.PrincipalName, realm string) {
	writeInt32BE(w, pn.NameType)
	writeInt32BE(w, int32(len(pn.NameString)))
	writeData(w, []byte(realm))
	for _, c := range pn.NameString {
		writeData(w, []byte(c))
	}
}

func writeKey(w *bytes.Buffer, k types.EncryptionKey) {
	writeUint16BE(w, uint16(k.KeyType))
	writeData(w, k.KeyValue)
}

func writeTicketFlags(w *bytes.Buffer, bs asn1.BitString) {
	var out [4]byte
	copy(out[:], bs.Bytes)
	w.Write(out[:])
}

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
