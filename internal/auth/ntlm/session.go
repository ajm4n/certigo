package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"time"
)

// Client carries NTLMv2 auth state for a single handshake.
type Client struct {
	Domain      string
	Username    string
	Password    string
	Workstation string

	// After Authenticate() succeeds, these are populated.
	sessionKey       []byte // ExportedSessionKey (16 bytes)
	clientSigningKey []byte
	serverSigningKey []byte
	clientSealingKey []byte
	serverSealingKey []byte
	clientSealingCtx *rc4.Cipher
	serverSealingCtx *rc4.Cipher
	negotiatedFlags  uint32
	seqClient        uint32
	// seqServer is reserved for future server-signature verification.
	seqServer uint32 //nolint:unused

	// Test hooks. Leave nil in production.
	fixedClientChallenge    []byte // 8 bytes; nil = crypto/rand
	fixedTimestamp          []byte // 8 bytes; nil = now as FILETIME
	fixedExportedSessionKey []byte // 16 bytes; nil = crypto/rand
}

// NewClient constructs a Client. Workstation may be empty.
func NewClient(domain, username, password, workstation string) *Client {
	return &Client{
		Domain:      domain,
		Username:    username,
		Password:    password,
		Workstation: workstation,
	}
}

// Negotiate returns the NEGOTIATE_MESSAGE bytes to send first.
func (c *Client) Negotiate() []byte {
	flags := uint32(
		NegotiateUnicode |
			RequestTarget |
			NegotiateNTLM |
			NegotiateAlwaysSign |
			NegotiateExtendedSessionSecurity |
			NegotiateTargetInfo |
			Negotiate128 |
			NegotiateKeyExch |
			Negotiate56,
	)
	msg := &NegotiateMessage{NegotiateFlags: flags}
	return msg.Encode()
}

// Authenticate consumes a CHALLENGE_MESSAGE and returns AUTHENTICATE_MESSAGE bytes.
// On success the Client's session keys are derived and ready for Sign/Seal.
func (c *Client) Authenticate(challenge []byte) ([]byte, error) {
	cm, err := DecodeChallengeMessage(challenge)
	if err != nil {
		return nil, err
	}

	clientChal := c.fixedClientChallenge
	if clientChal == nil {
		clientChal = make([]byte, 8)
		if _, err := rand.Read(clientChal); err != nil {
			return nil, fmt.Errorf("ntlm: rand: %w", err)
		}
	}

	timestamp := c.fixedTimestamp
	if timestamp == nil {
		timestamp = windowsFiletime(time.Now())
	}

	tiBytes := cm.TargetInfoRaw
	if tiBytes == nil {
		tiBytes = (&TargetInfo{}).Encode()
	}

	responseKey := NTOWFv2(c.Password, c.Username, c.Domain)
	ntResp := NTLMv2Response(responseKey, cm.ServerChallenge[:], clientChal, timestamp, tiBytes)
	lmResp := LMv2Response(responseKey, cm.ServerChallenge[:], clientChal)

	ntProof := ntResp[:16]
	baseKey := SessionBaseKey(responseKey, ntProof)
	keyExch := baseKey

	var exported []byte
	var encSessKey []byte
	if cm.NegotiateFlags&NegotiateKeyExch != 0 {
		exported = c.fixedExportedSessionKey
		if exported == nil {
			exported = make([]byte, 16)
			if _, err := rand.Read(exported); err != nil {
				return nil, fmt.Errorf("ntlm: rand: %w", err)
			}
		}
		encSessKey = make([]byte, 16)
		rc, err := rc4.NewCipher(keyExch)
		if err != nil {
			return nil, fmt.Errorf("ntlm: rc4: %w", err)
		}
		rc.XORKeyStream(encSessKey, exported)
	} else {
		exported = keyExch
	}

	am := &AuthenticateMessage{
		LmChallengeResponse:       lmResp,
		NtChallengeResponse:       ntResp,
		DomainName:                utf16LE(c.Domain),
		UserName:                  utf16LE(c.Username),
		Workstation:               utf16LE(c.Workstation),
		EncryptedRandomSessionKey: encSessKey,
		NegotiateFlags:            cm.NegotiateFlags,
	}
	out := am.Encode()

	c.sessionKey = exported
	c.negotiatedFlags = cm.NegotiateFlags
	c.deriveSessionKeys()
	return out, nil
}

// SessionKey returns the ExportedSessionKey. Valid after Authenticate().
func (c *Client) SessionKey() []byte {
	return c.sessionKey
}

// Sign returns the MS-NLMP §3.4.4.2 signature for msg.
func (c *Client) Sign(msg []byte) []byte {
	sig := make([]byte, 16)
	binary.LittleEndian.PutUint32(sig[0:4], 0x00000001)
	h := hmac.New(md5.New, c.clientSigningKey)
	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, c.seqClient)
	_, _ = h.Write(seq)
	_, _ = h.Write(msg)
	mac := h.Sum(nil)[:8]
	if c.negotiatedFlags&NegotiateKeyExch != 0 && c.clientSealingCtx != nil {
		encMac := make([]byte, 8)
		c.clientSealingCtx.XORKeyStream(encMac, mac)
		mac = encMac
	}
	copy(sig[4:12], mac)
	binary.LittleEndian.PutUint32(sig[12:16], c.seqClient)
	c.seqClient++
	return sig
}

// Seal encrypts msg and returns (ciphertext, signature). If NEGOTIATE_SEAL
// was not negotiated the msg bytes are returned unchanged with nil sig.
func (c *Client) Seal(msg []byte) (cipher, signature []byte) {
	if c.clientSealingCtx == nil {
		return append([]byte(nil), msg...), nil
	}
	cipher = make([]byte, len(msg))
	c.clientSealingCtx.XORKeyStream(cipher, msg)
	signature = c.Sign(msg)
	return
}

func (c *Client) deriveSessionKeys() {
	c.clientSigningKey = md5sum(c.sessionKey, ClientSigningKeyMagic)
	c.serverSigningKey = md5sum(c.sessionKey, ServerSigningKeyMagic)
	c.clientSealingKey = md5sum(c.sessionKey, ClientSealingKeyMagic)
	c.serverSealingKey = md5sum(c.sessionKey, ServerSealingKeyMagic)
	if ctx, err := rc4.NewCipher(c.clientSealingKey); err == nil {
		c.clientSealingCtx = ctx
	}
	if ctx, err := rc4.NewCipher(c.serverSealingKey); err == nil {
		c.serverSealingCtx = ctx
	}
}

func md5sum(parts ...[]byte) []byte {
	h := md5.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

// windowsFiletime returns t as a FILETIME: 100-ns intervals since 1601-01-01 UTC.
func windowsFiletime(t time.Time) []byte {
	const epochDelta = 11644473600
	ns := uint64(t.UTC().Unix()+epochDelta)*10_000_000 + uint64(t.Nanosecond()/100)
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, ns)
	return out
}
