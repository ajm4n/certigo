package spnego

import (
	"errors"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// kerberosNegotiator uses gokrb5's SPNEGO implementation to produce the
// initial Kerberos AP-REQ wrapped in a NegTokenInit. Once the server accepts
// the token there is no follow-up mechToken to send, so the negotiation
// completes in one round trip. An optional server response is consumed for
// completeness but its mechListMIC is not currently validated.
type kerberosNegotiator struct {
	spnegoCl   *spnego.SPNEGO
	spn        string
	sessionKey []byte
	sent       bool
	done       bool
}

// NewKerberos builds a Negotiator that uses a gokrb5 client to produce a
// Kerberos AP-REQ wrapped in a SPNEGO NegTokenInit as the first client
// token. spn is the target service principal name (e.g. "ldap/dc01.ctg.local").
// Uses gokrb5's own spnego package under the hood (github.com/jcmturner/gokrb5/v8/spnego).
func NewKerberos(cl *client.Client, spn string) (Negotiator, error) {
	if cl == nil {
		return nil, errors.New("spnego/kerberos: nil client")
	}
	if spn == "" {
		return nil, errors.New("spnego/kerberos: service principal name required")
	}
	return &kerberosNegotiator{
		spnegoCl: spnego.SPNEGOClient(cl, spn),
		spn:      spn,
	}, nil
}

func (k *kerberosNegotiator) Initial() ([]byte, bool, error) {
	if k.sent {
		return nil, k.done, errors.New("spnego/kerberos: Initial called twice")
	}
	if err := k.spnegoCl.AcquireCred(); err != nil {
		return nil, false, fmt.Errorf("spnego/kerberos: acquire credentials: %w", err)
	}
	tok, err := k.spnegoCl.InitSecContext()
	if err != nil {
		return nil, false, fmt.Errorf("spnego/kerberos: init sec context: %w", err)
	}
	raw, err := tok.Marshal()
	if err != nil {
		return nil, false, fmt.Errorf("spnego/kerberos: marshal token: %w", err)
	}
	// NOTE: gokrb5's spnego.SPNEGO type does not expose the per-session
	// Kerberos subkey directly; callers needing a sealing/signing key must
	// pull it from the service ticket out-of-band. SessionKey() therefore
	// returns nil for now.
	k.sent = true
	// Kerberos handshakes with AD generally complete in one round: the
	// server either accepts (no reply body needed) or rejects. Some peers
	// return a mechListMIC that callers feed back via Accept, but the
	// client side has nothing further to send.
	k.done = true
	return raw, true, nil
}

func (k *kerberosNegotiator) Accept(response []byte) ([]byte, bool, error) {
	// Nothing further to produce on the client side after Initial.
	k.done = true
	return nil, true, nil
}

func (k *kerberosNegotiator) SessionKey() []byte {
	return k.sessionKey
}

func (k *kerberosNegotiator) Mechanism() string {
	return MechanismKerberos
}
