// Package krb also handles Windows-style exported Kerberos ticket files
// (".kirbi"). A .kirbi file is the DER-encoded ASN.1 KRB_CRED message defined
// by RFC 4120 §5.8.1; there is no additional framing. Mimikatz and Rubeus
// produce these files directly, and the same format is understood by Impacket
// when the ticket is handed off via a ccache wrapper.
package krb

import (
	"errors"
	"fmt"
	"os"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// marshalKRBCred mirrors gokrb5's internal (unexported) encode-shape for
// KRB_CRED. We need this locally because gokrb5 v8.4.4 only exposes an
// Unmarshal method on messages.KRBCred; see messages/KRBCred.go in the
// gokrb5 v8 module for the original.
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
