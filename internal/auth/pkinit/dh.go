package pkinit

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// DHParams carries the prime modulus, generator, and (optionally) the
// subgroup order for an ephemeral Diffie-Hellman exchange. Active Directory
// KDCs accept the well-known MODP groups from RFC 2409 / RFC 3526; we expose
// OAKLEY Group 2 (1024-bit) and RFC 3526 Group 14 (2048-bit). Q is set only
// when the group has a known prime-order subgroup (we leave it as nil for
// the pure MODP groups below since Windows KDCs do not expect it).
type DHParams struct {
	P *big.Int // prime modulus
	G *big.Int // generator
	Q *big.Int // subgroup order (optional; nil if unused)
}

// Hex-encoded prime for OAKLEY well-known group 2 (RFC 2409 §6.2). 1024-bit
// MODP with generator 2. This is what Impacket's pkinit.py defaults to and
// what most legacy KDCs will accept.
const oakleyGroup2PrimeHex = "" +
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
	"FFFFFFFFFFFFFFFF"

// Hex-encoded prime for RFC 3526 Group 14 (2048-bit MODP, generator 2).
// More conservative - modern KDCs with heightened crypto policy may require
// at least this group.
const rfc3526Group14PrimeHex = "" +
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
	"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

// WellKnownGroup2 returns OAKLEY well-known group 2: a 1024-bit MODP prime
// with generator 2, defined in RFC 2409 §6.2. It is the default that
// Impacket's PKINIT client uses and the most widely accepted DH group among
// production AD KDCs.
func WellKnownGroup2() DHParams {
	p, _ := new(big.Int).SetString(oakleyGroup2PrimeHex, 16)
	return DHParams{
		P: p,
		G: big.NewInt(2),
	}
}

// WellKnownGroup14 returns RFC 3526 group 14: a 2048-bit MODP prime with
// generator 2. Stronger than Group 2; required by modern KDCs configured to
// reject 1024-bit DH.
func WellKnownGroup14() DHParams {
	p, _ := new(big.Int).SetString(rfc3526Group14PrimeHex, 16)
	return DHParams{
		P: p,
		G: big.NewInt(2),
	}
}

// GeneratePrivate returns a fresh private exponent in [2, P-2]. For MODP
// groups without an explicit subgroup order we treat the full interval as
// admissible - Windows KDCs are happy with any full-length private.
func (d DHParams) GeneratePrivate() (*big.Int, error) {
	if d.P == nil {
		return nil, errors.New("pkinit: DH params missing prime P")
	}
	// Upper bound = P - 3 so that priv = random + 2 lands in [2, P-2].
	bound := new(big.Int).Sub(d.P, big.NewInt(3))
	if bound.Sign() <= 0 {
		return nil, fmt.Errorf("pkinit: DH prime too small")
	}
	x, err := rand.Int(rand.Reader, bound)
	if err != nil {
		return nil, fmt.Errorf("pkinit: generate DH private: %w", err)
	}
	return x.Add(x, big.NewInt(2)), nil
}

// PublicFrom returns g^priv mod p - the value transmitted to the peer as the
// client's DH public key.
func (d DHParams) PublicFrom(priv *big.Int) *big.Int {
	return new(big.Int).Exp(d.G, priv, d.P)
}

// SharedSecret returns peer^priv mod p, zero-padded on the left to len(P) in
// bytes. The padding matches what RFC 4556 calls "DHSharedSecret" - every
// participant produces an identically-sized octet string regardless of the
// integer's leading-zero pattern.
func (d DHParams) SharedSecret(peer, priv *big.Int) []byte {
	secret := new(big.Int).Exp(peer, priv, d.P)
	size := (d.P.BitLen() + 7) / 8
	out := make([]byte, size)
	sb := secret.Bytes()
	copy(out[size-len(sb):], sb)
	return out
}
