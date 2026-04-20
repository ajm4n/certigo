// Package krb also handles Windows-style exported Kerberos ticket files
// (".kirbi"). A .kirbi file is the DER-encoded ASN.1 KRB_CRED message defined
// by RFC 4120 §5.8.1; there is no additional framing. Mimikatz and Rubeus
// produce these files directly, and the same format is understood by Impacket
// when the ticket is handed off via a ccache wrapper.
package krb

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// marshalKRBCred mirrors gokrb5's internal (unexported) encode-shape for
// KRB_CRED. We need this locally because gokrb5 v8.4.4 only exposes an
// Unmarshal method on messages.KRBCred; see
// messages/KRBCred.go in the gokrb5 v8 module for the original.
type marshalKRBCred struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	Tickets asn1.RawValue       `asn1:"explicit,tag:2"`
	EncPart types.EncryptedData `asn1:"explicit,tag:3"`
}

// ReadKirbi parses a .kirbi file (DER-encoded KRB_CRED) at path and returns
// the unmarshaled message. The EncryptedPart is typically stored with
// etype 0 (plaintext) by Rubeus/Mimikatz — we pass it through verbatim.
func ReadKirbi(path string) (*messages.KRBCred, error) {
	if path == "" {
		return nil, errors.New("krb: kirbi path required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("krb: read kirbi %q: %w", path, err)
	}
	cred := new(messages.KRBCred)
	if err := cred.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("krb: unmarshal kirbi %q: %w", path, err)
	}
	return cred, nil
}

// WriteKirbi marshals cred to path as a .kirbi file. The file is overwritten.
func WriteKirbi(path string, cred *messages.KRBCred) error {
	if path == "" {
		return errors.New("krb: kirbi path required")
	}
	if cred == nil {
		return errors.New("krb: nil KRBCred")
	}
	b, err := marshalKirbi(cred)
	if err != nil {
		return fmt.Errorf("krb: marshal kirbi: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("krb: write kirbi %q: %w", path, err)
	}
	return nil
}

// marshalKirbi encodes a messages.KRBCred into its DER wire form, matching
// the shape produced by RFC 4120 §5.8.1. gokrb5 does not ship a public
// KRBCred.Marshal, so we replicate the layout the library uses internally:
// an SEQUENCE (tag 22, APPLICATION) containing pvno/msg-type/tickets/enc-part.
func marshalKirbi(cred *messages.KRBCred) ([]byte, error) {
	tickets, err := messages.MarshalTicketSequence(cred.Tickets)
	if err != nil {
		return nil, fmt.Errorf("marshal tickets: %w", err)
	}
	// gofork asn1.Marshal takes an early-return path for asn1.RawValue that
	// skips the outer explicit wrapper and instead emits a TLV from the
	// RawValue's own Class/Tag/Bytes fields (see gofork marshal.go:544).
	// Set Tag to 2 so the emitted header is [2] EXPLICIT SEQUENCE-OF-Ticket,
	// matching the KRB_CRED ASN.1 schema. Same idiom is used inside gokrb5
	// for KDC-REQ AdditionalTickets.
	tickets.Tag = 2

	pvno := cred.PVNO
	if pvno == 0 {
		pvno = iana.PVNO
	}
	mt := cred.MsgType
	if mt == 0 {
		mt = msgtype.KRB_CRED
	}

	m := marshalKRBCred{
		PVNO:    pvno,
		MsgType: mt,
		Tickets: tickets,
		EncPart: cred.EncPart,
	}
	b, err := asn1.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal KRB_CRED body: %w", err)
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.KRBCred)
	return b, nil
}

// marshalEncKrbCredPart produces the DER encoding of an EncKrbCredPart
// suitable for embedding as the cipher payload of a plaintext-etype (0)
// KRB_CRED enc-part — the shape Mimikatz/Rubeus emit.
func marshalEncKrbCredPart(p messages.EncKrbCredPart) ([]byte, error) {
	b, err := asn1.Marshal(p)
	if err != nil {
		return nil, err
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.EncKrbCredPart), nil
}

// isTGT reports whether the given server principal looks like a krbtgt
// TGS — i.e. a two-component name starting with "krbtgt". This is how
// ccache entries for TGTs are identified without consulting the realm.
func isTGT(server types.PrincipalName) bool {
	return len(server.NameString) >= 1 && server.NameString[0] == "krbtgt"
}

// CCacheToKirbi converts a gokrb5 CCache (typically loaded from a FILE: ccache
// via credentials.LoadCCache) into a KRBCred for kirbi emission. If the ccache
// contains multiple tickets, the krbtgt TGT is chosen; if no TGT is present
// the first ticket is used. Returns an error if the ccache has no tickets.
func CCacheToKirbi(cc *credentials.CCache) (*messages.KRBCred, error) {
	if cc == nil {
		return nil, errors.New("krb: nil ccache")
	}
	entries := cc.GetEntries()
	if len(entries) == 0 {
		return nil, errors.New("krb: ccache has no tickets")
	}

	// Prefer a TGT when present; otherwise fall back to the first entry.
	chosen := entries[0]
	for _, e := range entries {
		if isTGT(e.Server.PrincipalName) {
			chosen = e
			break
		}
	}

	var tkt messages.Ticket
	if err := tkt.Unmarshal(chosen.Ticket); err != nil {
		return nil, fmt.Errorf("krb: unmarshal ticket from ccache: %w", err)
	}

	info := messages.KrbCredInfo{
		Key:       chosen.Key,
		PRealm:    chosen.Client.Realm,
		PName:     chosen.Client.PrincipalName,
		Flags:     chosen.TicketFlags,
		AuthTime:  chosen.AuthTime,
		StartTime: chosen.StartTime,
		EndTime:   chosen.EndTime,
		RenewTill: chosen.RenewTill,
		SRealm:    chosen.Server.Realm,
		SName:     chosen.Server.PrincipalName,
	}

	enc := messages.EncKrbCredPart{
		TicketInfo: []messages.KrbCredInfo{info},
		Timestamp:  time.Now().UTC(),
	}
	encBytes, err := marshalEncKrbCredPart(enc)
	if err != nil {
		return nil, fmt.Errorf("krb: marshal EncKrbCredPart: %w", err)
	}

	cred := &messages.KRBCred{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_CRED,
		Tickets: []messages.Ticket{tkt},
		// etype 0 == plaintext. Rubeus / Mimikatz encode the EncKrbCredPart
		// directly here without any KDF or cipher transform, which is what
		// Impacket expects when consuming .kirbi blobs.
		EncPart: types.EncryptedData{
			EType:  0,
			Cipher: encBytes,
		},
		DecryptedEncPart: enc,
	}
	return cred, nil
}

// unmarshalEncKrbCredPart undoes marshalEncKrbCredPart. It accepts a DER
// blob with the [APPLICATION 29] wrapper that Rubeus/Mimikatz emit.
func unmarshalEncKrbCredPart(b []byte) (messages.EncKrbCredPart, error) {
	var p messages.EncKrbCredPart
	err := p.Unmarshal(b)
	return p, err
}

// KirbiToCCache converts a KRBCred blob (as loaded from a .kirbi file) into a
// gokrb5 CCache. The default principal is taken from the ticket's client
// field. Suitable for handoff to GetTGTFromCCache-consumers after writing
// to disk via credentials-to-ccache marshal.
//
// gokrb5's credentials.CCache has an unexported `principal` type gating its
// Client/Server fields, so we cannot construct a CCache via struct literals
// from outside the package. Instead we serialize a synthetic MIT ccache v4
// byte stream using the same writers used by SaveTGTToCCache, then
// Unmarshal it to get a proper *credentials.CCache.
func KirbiToCCache(cred *messages.KRBCred) (*credentials.CCache, error) {
	if cred == nil {
		return nil, errors.New("krb: nil KRBCred")
	}
	if len(cred.Tickets) == 0 {
		return nil, errors.New("krb: KRBCred has no tickets")
	}

	tkt := cred.Tickets[0]

	// Recover session key / times / flags from the EncKrbCredPart when
	// present. Rubeus/Mimikatz store this in plaintext (etype 0), so we can
	// decode the cipher bytes directly without a key. If that fails we fall
	// back to zero-valued data — the ticket itself is the load-bearing
	// field for most downstream consumers.
	var (
		sessionKey types.EncryptionKey
		flags      asn1.BitString
		authTime   time.Time
		startTime  time.Time
		endTime    time.Time
		renewTill  time.Time
		clientName types.PrincipalName
		clientReal string
	)
	if cred.EncPart.EType == 0 && len(cred.EncPart.Cipher) > 0 {
		if p, err := unmarshalEncKrbCredPart(cred.EncPart.Cipher); err == nil && len(p.TicketInfo) > 0 {
			info := p.TicketInfo[0]
			sessionKey = info.Key
			flags = info.Flags
			authTime = info.AuthTime
			startTime = info.StartTime
			endTime = info.EndTime
			renewTill = info.RenewTill
			clientName = info.PName
			clientReal = info.PRealm
		}
	}
	// Fall back to the ticket's service realm for the client realm if the
	// EncKrbCredPart didn't carry one (Impacket-style blobs sometimes omit
	// PRealm). Principal name falls back to an empty principal rather than
	// fabricating a name.
	if clientReal == "" {
		clientReal = tkt.Realm
	}
	if len(clientName.NameString) == 0 {
		clientName = types.PrincipalName{NameType: nametype.KRB_NT_UNKNOWN}
	}

	tktBytes, err := tkt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("krb: marshal ticket: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteByte(0x05)
	buf.WriteByte(0x04)
	writeUint16BE(&buf, 0) // empty header

	writePrincipal(&buf, clientName, clientReal) // default principal
	writePrincipal(&buf, clientName, clientReal) // credential client
	writePrincipal(&buf, tkt.SName, tkt.Realm)   // credential server
	writeKey(&buf, sessionKey)
	writeUint32BE(&buf, uint32(authTime.Unix()))
	writeUint32BE(&buf, uint32(startTime.Unix()))
	writeUint32BE(&buf, uint32(endTime.Unix()))
	writeUint32BE(&buf, uint32(renewTill.Unix()))
	buf.WriteByte(0) // is_skey = false
	writeTicketFlags(&buf, flags)
	writeUint32BE(&buf, 0) // num_addresses
	writeUint32BE(&buf, 0) // num_authdata
	writeData(&buf, tktBytes)
	writeData(&buf, nil) // second_ticket empty

	cc := new(credentials.CCache)
	if err := cc.Unmarshal(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("krb: unmarshal synthetic ccache: %w", err)
	}
	return cc, nil
}
