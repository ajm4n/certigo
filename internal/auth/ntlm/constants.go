// Package ntlm implements a pure-Go NTLMv2 client per MS-NLMP.
//
// Usage: construct a Client with NewClient, send the bytes from
// Negotiate() as the initial NTLM blob, feed the server's
// CHALLENGE_MESSAGE bytes into Authenticate() to get the
// AUTHENTICATE_MESSAGE bytes to return. Optional Sign/Seal is
// available after Authenticate() if NEGOTIATE_KEY_EXCH was negotiated.
package ntlm

// NegotiateFlags bitfield (MS-NLMP §2.2.2.5).
const (
	NegotiateUnicode                 = 0x00000001
	NegotiateOEM                     = 0x00000002
	RequestTarget                    = 0x00000004
	NegotiateSign                    = 0x00000010
	NegotiateSeal                    = 0x00000020
	NegotiateNTLM                    = 0x00000200
	NegotiateAlwaysSign              = 0x00008000
	NegotiateExtendedSessionSecurity = 0x00080000
	NegotiateTargetInfo              = 0x00800000
	NegotiateVersion                 = 0x02000000
	Negotiate128                     = 0x20000000
	NegotiateKeyExch                 = 0x40000000
	Negotiate56                      = 0x80000000
)

// MessageType values (MS-NLMP §2.2.1.1-3).
const (
	MessageTypeNegotiate    uint32 = 1
	MessageTypeChallenge    uint32 = 2
	MessageTypeAuthenticate uint32 = 3
)

// Signature prefix of every NTLM message (MS-NLMP §2.2.1).
var Signature = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

// AV_PAIR attribute IDs (MS-NLMP §2.2.2.1).
const (
	AvIDEOL             uint16 = 0x0000
	AvIDNbComputerName  uint16 = 0x0001
	AvIDNbDomainName    uint16 = 0x0002
	AvIDDnsComputerName uint16 = 0x0003
	AvIDDnsDomainName   uint16 = 0x0004
	AvIDDnsTreeName     uint16 = 0x0005
	AvIDFlags           uint16 = 0x0006
	AvIDTimestamp       uint16 = 0x0007
	AvIDSingleHost      uint16 = 0x0008
	AvIDTargetName      uint16 = 0x0009
	AvIDChannelBindings uint16 = 0x000a
)

// Signing/sealing key derivation magic constants (MS-NLMP §3.4.5.2-3).
var (
	ClientSigningKeyMagic = []byte("session key to client-to-server signing key magic constant\x00")
	ServerSigningKeyMagic = []byte("session key to server-to-client signing key magic constant\x00")
	ClientSealingKeyMagic = []byte("session key to client-to-server sealing key magic constant\x00")
	ServerSealingKeyMagic = []byte("session key to server-to-client sealing key magic constant\x00")
)
