package shadow

import (
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"
)

// bcryptRSAPublicMagic is the "RSA1" magic in little-endian byte order that
// introduces a BCRYPT_RSAKEY_BLOB holding a public key (MS-KPP §2.2.2.2 /
// bcrypt.h BCRYPT_RSAPUBLIC_MAGIC).
const bcryptRSAPublicMagic uint32 = 0x31415352

// bcryptRSAHeaderLen is the fixed 24-byte header at the start of a
// BCRYPT_RSAKEY_BLOB: Magic, BitLength, PublicExponentSize, ModulusSize,
// Prime1Size, Prime2Size - six 32-bit little-endian fields.
const bcryptRSAHeaderLen = 24

// EncodeRSABcryptBlob serializes a BCRYPT_RSAKEY_BLOB describing the public
// half of the supplied RSA key. The output is what Windows' msDS-Key-
// CredentialLink KeyMaterial entry carries (Identifier 3) for an RSA
// ShadowCredentials registration.
//
// Layout:
//
//	Magic              (4 LE) = 0x31415352 "RSA1"
//	BitLength          (4 LE)
//	PublicExponentSize (4 LE)
//	ModulusSize        (4 LE)
//	Prime1Size         (4 LE) = 0 (public key)
//	Prime2Size         (4 LE) = 0
//	PublicExponent     (PublicExponentSize bytes, big-endian)
//	Modulus            (ModulusSize bytes, big-endian)
func EncodeRSABcryptBlob(pub *rsa.PublicKey) []byte {
	if pub == nil || pub.N == nil {
		return nil
	}
	modulus := pub.N.Bytes()
	exponent := big.NewInt(int64(pub.E)).Bytes()

	out := make([]byte, bcryptRSAHeaderLen+len(exponent)+len(modulus))
	binary.LittleEndian.PutUint32(out[0:4], bcryptRSAPublicMagic)
	binary.LittleEndian.PutUint32(out[4:8], uint32(pub.N.BitLen()))
	binary.LittleEndian.PutUint32(out[8:12], uint32(len(exponent)))
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(modulus)))
	binary.LittleEndian.PutUint32(out[16:20], 0)
	binary.LittleEndian.PutUint32(out[20:24], 0)
	copy(out[bcryptRSAHeaderLen:], exponent)
	copy(out[bcryptRSAHeaderLen+len(exponent):], modulus)
	return out
}

// DecodeRSABcryptBlob parses a BCRYPT_RSAKEY_BLOB and returns the decoded
// public exponent (as an int) and the raw modulus bytes. Private-key
// material (Prime1 / Prime2 / etc.) is ignored - shadow credentials only
// carry the public key portion.
func DecodeRSABcryptBlob(blob []byte) (exponent int, modulus []byte, err error) {
	if len(blob) < bcryptRSAHeaderLen {
		return 0, nil, fmt.Errorf("shadow: BCRYPT_RSAKEY_BLOB too short (%d < %d)", len(blob), bcryptRSAHeaderLen)
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])
	if magic != bcryptRSAPublicMagic {
		return 0, nil, fmt.Errorf("shadow: bad BCRYPT_RSAKEY_BLOB magic 0x%08x (want 0x%08x)", magic, bcryptRSAPublicMagic)
	}
	expSize := binary.LittleEndian.Uint32(blob[8:12])
	modSize := binary.LittleEndian.Uint32(blob[12:16])
	if expSize == 0 || expSize > 16 {
		return 0, nil, fmt.Errorf("shadow: implausible PublicExponentSize %d", expSize)
	}
	if modSize == 0 {
		return 0, nil, fmt.Errorf("shadow: zero ModulusSize")
	}
	total := uint64(bcryptRSAHeaderLen) + uint64(expSize) + uint64(modSize)
	if uint64(len(blob)) < total {
		return 0, nil, fmt.Errorf("shadow: BCRYPT_RSAKEY_BLOB truncated (have %d, need %d)", len(blob), total)
	}
	expBytes := blob[bcryptRSAHeaderLen : bcryptRSAHeaderLen+expSize]
	modulus = append([]byte(nil), blob[bcryptRSAHeaderLen+expSize:bcryptRSAHeaderLen+expSize+modSize]...)

	expBig := new(big.Int).SetBytes(expBytes)
	if !expBig.IsInt64() {
		return 0, nil, fmt.Errorf("shadow: RSA exponent does not fit in int64")
	}
	exponent = int(expBig.Int64())
	return exponent, modulus, nil
}
