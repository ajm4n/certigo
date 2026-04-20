package spnego

import (
	"errors"

	"github.com/ajm4n/certigo/internal/auth/ntlm"
)

// ntlmNegotiator wraps a certigo ntlm.Client in the Negotiator interface.
type ntlmNegotiator struct {
	client *ntlm.Client
	// sentNegotiate tracks whether the NEGOTIATE_MESSAGE has been emitted.
	sentNegotiate bool
	// done becomes true after the AUTHENTICATE_MESSAGE is produced.
	done bool
}

// NewNTLM wraps a certigo ntlm.Client in the Negotiator interface.
// Initial() emits NEGOTIATE_MESSAGE; Accept() consumes CHALLENGE_MESSAGE
// and emits AUTHENTICATE_MESSAGE; the handshake is done after one round.
func NewNTLM(c *ntlm.Client) Negotiator {
	return &ntlmNegotiator{client: c}
}

func (n *ntlmNegotiator) Initial() ([]byte, bool, error) {
	if n.client == nil {
		return nil, false, errors.New("spnego/ntlm: nil client")
	}
	if n.sentNegotiate {
		return nil, false, errors.New("spnego/ntlm: Initial called twice")
	}
	n.sentNegotiate = true
	return n.client.Negotiate(), false, nil
}

func (n *ntlmNegotiator) Accept(response []byte) ([]byte, bool, error) {
	if n.client == nil {
		return nil, false, errors.New("spnego/ntlm: nil client")
	}
	if !n.sentNegotiate {
		return nil, false, errors.New("spnego/ntlm: Accept called before Initial")
	}
	if n.done {
		return nil, true, nil
	}
	if len(response) == 0 {
		return nil, false, errors.New("spnego/ntlm: empty CHALLENGE_MESSAGE")
	}
	authMsg, err := n.client.Authenticate(response)
	if err != nil {
		return nil, false, err
	}
	n.done = true
	return authMsg, true, nil
}

func (n *ntlmNegotiator) SessionKey() []byte {
	if n.client == nil {
		return nil
	}
	return n.client.SessionKey()
}

func (n *ntlmNegotiator) Mechanism() string {
	return MechanismNTLM
}
