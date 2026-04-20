package pkinit

import (
	"crypto/sha1"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/types"
)

// DeriveASReplyKey implements the RFC 4556 §3.2.3.1 "octetstring2key"
// transform used to turn a DH-derived shared secret into the AS-reply key.
// The construction is:
//
//	K = truncate(
//	        SHA1(0x00 || x) | SHA1(0x01 || x) | SHA1(0x02 || x) | ... ,
//	        keyBytes)
//	replyKey = random-to-key(K)
//
// For the AES-CTS-HMAC-SHA1 family random-to-key is the identity so the
// truncated SHA1 stream IS the protocol key. x is the DH shared secret on
// its own when neither side sends a DH nonce; when present the nonces are
// concatenated after DHSharedSecret (RFC 4556 §3.2.3.1). We expose both
// forms via clientDHNonce / serverDHNonce parameters — pass nil to use
// the bare shared secret.
func DeriveASReplyKey(etypeID int32, dhSharedSecret, clientDHNonce, serverDHNonce []byte) (types.EncryptionKey, error) {
	et, err := crypto.GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("pkinit: unknown etype %d: %w", etypeID, err)
	}
	keyLen := et.GetKeyByteSize()
	if keyLen <= 0 {
		return types.EncryptionKey{}, fmt.Errorf("pkinit: etype %d reports zero key size", etypeID)
	}

	// x = DHSharedSecret [|| clientDHNonce || serverDHNonce] per RFC 4556.
	// When either nonce is empty we skip it, matching what Windows KDCs
	// actually send back (they omit serverDHNonce entirely in the common
	// DH path with well-known MODP groups).
	x := make([]byte, 0, len(dhSharedSecret)+len(clientDHNonce)+len(serverDHNonce))
	x = append(x, dhSharedSecret...)
	if len(clientDHNonce) > 0 {
		x = append(x, clientDHNonce...)
	}
	if len(serverDHNonce) > 0 {
		x = append(x, serverDHNonce...)
	}

	stream := octetStringToKey(x, keyLen)
	protoKey := et.RandomToKey(stream)

	return types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: protoKey,
	}, nil
}

// octetStringToKey returns the first keyBytes octets of
// SHA1(0x00|x) || SHA1(0x01|x) || SHA1(0x02|x) || ...
// per RFC 4556 §3.2.3.1.
func octetStringToKey(x []byte, keyBytes int) []byte {
	out := make([]byte, 0, keyBytes+sha1.Size)
	var counter byte
	for len(out) < keyBytes {
		h := sha1.New()
		h.Write([]byte{counter})
		h.Write(x)
		out = append(out, h.Sum(nil)...)
		counter++
	}
	return out[:keyBytes]
}

// IsAESEType reports whether etype is one of the AES-CTS-HMAC-SHA1 enctypes
// we issue in the AS-REQ. RFC 4556's DH reply-key construction was defined
// against these; other enctypes either are deprecated (RC4) or require
// alternative KDFs (RFC 8009 for the SHA2 AES family).
func IsAESEType(et int32) bool {
	return et == etypeID.AES256_CTS_HMAC_SHA1_96 || et == etypeID.AES128_CTS_HMAC_SHA1_96
}
