package spnego

// Mechanism name constants returned by Negotiator.Mechanism.
const (
	MechanismNTLM     = "ntlm"
	MechanismKerberos = "kerberos"
)

// Negotiator produces the bytes needed for the client side of a GSS-API
// authentication exchange. The caller runs a simple loop:
//
//	token, done, err := n.Initial()
//	// send token, receive reply
//	for !done {
//	    token, done, err = n.Accept(reply)
//	    // send token, receive reply
//	}
type Negotiator interface {
	// Initial returns the first client token (AP-REQ wrapped in a
	// NegTokenInit for SPNEGO, or the NTLM NEGOTIATE_MESSAGE).
	Initial() ([]byte, bool, error)
	// Accept feeds the server's response token and returns the next
	// client token or nil when done.
	Accept(response []byte) ([]byte, bool, error)
	// SessionKey returns the established session key after a successful
	// handshake. May be empty if the negotiation hasn't completed.
	SessionKey() []byte
	// Mechanism returns "kerberos" or "ntlm" so upper layers can decide
	// whether to enable channel binding or MIC calculation.
	Mechanism() string
}
