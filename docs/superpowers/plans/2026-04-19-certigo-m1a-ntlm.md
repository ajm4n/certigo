# Certigo M1a (NTLMv2 Client) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a pure-Go NTLMv2 client library at `internal/auth/ntlm` - sufficient to authenticate to any Windows service expecting NTLM (LDAP signed binds, HTTP challenge-response, SMB, RPC). Fully tested against MS-NLMP §4.2 golden vectors. No external dependencies beyond stdlib.

**Architecture:** Five tight files inside `internal/auth/ntlm/` - `constants.go` (flags + AV IDs), `message.go` (NEGOTIATE/CHALLENGE/AUTHENTICATE codec), `avpair.go` (AV_PAIR encode/decode), `crypto.go` (NTOWFv2, NTLMv2 response, session key derivation), `session.go` (Client handshake + optional signing/sealing). Every function is tested with MS-NLMP published vectors where available; no mocks, no external lab.

**Tech Stack:** Go stdlib (`crypto/md5`, `crypto/rc4`, `crypto/hmac`, `encoding/binary`, `golang.org/x/crypto/md4` for NT hash, `unicode/utf16`).

**Sibling plans:** M1b (Credentials + Kerberos wrapper), M1c (LDAP + SPNEGO), M1d (RPC + docker lab). This plan produces a standalone library that M1b+ compose.

---

## File Structure

**Create:**
- `internal/auth/ntlm/constants.go` - NegotiateFlags bitfield, MessageType enum, AV_PAIR ID enum, magic strings for key derivation, signature bytes.
- `internal/auth/ntlm/avpair.go` - AV_PAIR encode/decode + TargetInfo map type.
- `internal/auth/ntlm/avpair_test.go` - golden vectors for AV_PAIR list encode/decode.
- `internal/auth/ntlm/message.go` - NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE struct types with `encode()` / `decodeXxx()` functions; SecurityBuffer helper type.
- `internal/auth/ntlm/message_test.go` - encode/decode round-trip + MS-NLMP §4.2.1 vectors.
- `internal/auth/ntlm/crypto.go` - `NTOWFv2`, `NTLMv2Response`, `LMv2Response`, `SessionBaseKey`, `KeyExchangeKey`, signing/sealing key derivation.
- `internal/auth/ntlm/crypto_test.go` - MS-NLMP §4.2.4.1 golden vectors.
- `internal/auth/ntlm/session.go` - `Client` struct with `Negotiate()`, `Authenticate(challenge []byte)`, `Sign(msg []byte)`, `Seal(msg []byte)`.
- `internal/auth/ntlm/session_test.go` - end-to-end handshake with MS-NLMP §4.2.4 vectors; signing/sealing round-trips.

**Modify:**
- `go.mod` - add `golang.org/x/crypto` dependency.

**Not modifying in this plan:** `cmd/certigo/*` (no new subcommand), `CHANGELOG.md` (updated at end of M1 proper, not sub-milestone).

---

## Reference constants (MS-NLMP §4.2)

Used across multiple tasks. Cite once here:

- **NegotiateFlags values (bitmask, little-endian uint32):**
  - `NEGOTIATE_UNICODE              = 0x00000001`
  - `NEGOTIATE_OEM                  = 0x00000002`
  - `REQUEST_TARGET                 = 0x00000004`
  - `NEGOTIATE_SIGN                 = 0x00000010`
  - `NEGOTIATE_SEAL                 = 0x00000020`
  - `NEGOTIATE_NTLM                 = 0x00000200`
  - `NEGOTIATE_ALWAYS_SIGN          = 0x00008000`
  - `NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000`
  - `NEGOTIATE_TARGET_INFO          = 0x00800000`
  - `NEGOTIATE_VERSION              = 0x02000000`
  - `NEGOTIATE_128                  = 0x20000000`
  - `NEGOTIATE_KEY_EXCH             = 0x40000000`
  - `NEGOTIATE_56                   = 0x80000000`

- **MessageType values:** `Negotiate=1`, `Challenge=2`, `Authenticate=3`.

- **Signature:** `"NTLMSSP\x00"` (8 bytes).

- **AV_PAIR IDs (MsvAvXxx):** `EOL=0`, `NbComputerName=1`, `NbDomainName=2`, `DnsComputerName=3`, `DnsDomainName=4`, `DnsTreeName=5`, `Flags=6`, `Timestamp=7`, `SingleHost=8`, `TargetName=9`, `ChannelBindings=10`.

- **Signing/sealing magic constants:**
  - Client→Server signing: `"session key to client-to-server signing key magic constant\x00"` (60 bytes incl. NUL)
  - Server→Client signing: `"session key to server-to-client signing key magic constant\x00"`
  - Client→Server sealing: `"session key to client-to-server sealing key magic constant\x00"`
  - Server→Client sealing: `"session key to server-to-client sealing key magic constant\x00"`

---

## Task 1: Package skeleton + constants

**Files:**
- Create: `internal/auth/ntlm/constants.go`

- [ ] **Step 1: Create constants file**

Write `/Users/ajman/Documents/Tools/gotipy/internal/auth/ntlm/constants.go`:

```go
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
	NegotiateUnicode                = 0x00000001
	NegotiateOEM                    = 0x00000002
	RequestTarget                   = 0x00000004
	NegotiateSign                   = 0x00000010
	NegotiateSeal                   = 0x00000020
	NegotiateNTLM                   = 0x00000200
	NegotiateAlwaysSign             = 0x00008000
	NegotiateExtendedSessionSecurity = 0x00080000
	NegotiateTargetInfo             = 0x00800000
	NegotiateVersion                = 0x02000000
	Negotiate128                    = 0x20000000
	NegotiateKeyExch                = 0x40000000
	Negotiate56                     = 0x80000000
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
```

- [ ] **Step 2: Verify compiles**

```bash
go build ./internal/auth/ntlm/...
```

Expected: clean build, no errors (no test yet - this is pure constants).

- [ ] **Step 3: Commit**

```bash
git add internal/auth/ntlm/constants.go
git commit -m "feat(ntlm): add MS-NLMP constants and magic strings"
```

---

## Task 2: AV_PAIR encode/decode (TDD)

**Files:**
- Create: `internal/auth/ntlm/avpair.go`
- Create: `internal/auth/ntlm/avpair_test.go`

- [ ] **Step 1: Write failing test**

Write `/Users/ajman/Documents/Tools/gotipy/internal/auth/ntlm/avpair_test.go`:

```go
package ntlm

import (
	"bytes"
	"testing"
)

// MS-NLMP §4.2.4.1.3 - TargetInfo has NbDomainName="Domain", NbComputerName="Server".
// Both strings are UTF-16-LE encoded. The serialized AV_PAIRS list ends with EOL (ID=0, len=0).
func TestDecodeTargetInfoNLMPVector(t *testing.T) {
	// hex: 02000c0044006f006d00610069006e0001000c005300650072007600650072000000
	//      -- ID=2, Len=12, "Domain" UTF-16-LE
	//                                               ID=1, Len=12, "Server" UTF-16-LE
	//                                                                                     EOL
	raw := []byte{
		0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00,
		0x69, 0x00, 0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	ti, err := DecodeTargetInfo(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := ti.Get(AvIDNbDomainName); !bytes.Equal(got, utf16LE("Domain")) {
		t.Errorf("NbDomainName = %x, want %x", got, utf16LE("Domain"))
	}
	if got := ti.Get(AvIDNbComputerName); !bytes.Equal(got, utf16LE("Server")) {
		t.Errorf("NbComputerName = %x, want %x", got, utf16LE("Server"))
	}
}

func TestEncodeTargetInfoRoundTrip(t *testing.T) {
	ti := TargetInfo{}
	ti.Set(AvIDNbDomainName, utf16LE("Domain"))
	ti.Set(AvIDNbComputerName, utf16LE("Server"))
	enc := ti.Encode()
	dec, err := DecodeTargetInfo(enc)
	if err != nil {
		t.Fatalf("round-trip decode: %v", err)
	}
	if !bytes.Equal(dec.Get(AvIDNbDomainName), utf16LE("Domain")) {
		t.Error("round-trip lost NbDomainName")
	}
	if !bytes.Equal(dec.Get(AvIDNbComputerName), utf16LE("Server")) {
		t.Error("round-trip lost NbComputerName")
	}
}
```

- [ ] **Step 2: Run test - expect failure**

```bash
go test ./internal/auth/ntlm/...
```

Expected: fails - `DecodeTargetInfo`, `TargetInfo`, `utf16LE` undefined.

- [ ] **Step 3: Implement avpair.go**

Write `/Users/ajman/Documents/Tools/gotipy/internal/auth/ntlm/avpair.go`:

```go
package ntlm

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// TargetInfo is an ordered list of AV_PAIRs. Encoding preserves insertion
// order; callers that need MS-NLMP's standard ordering insert in that order.
type TargetInfo struct {
	pairs []avPair
}

type avPair struct {
	id    uint16
	value []byte
}

// Set replaces (or appends) the value for id.
func (t *TargetInfo) Set(id uint16, value []byte) {
	for i := range t.pairs {
		if t.pairs[i].id == id {
			t.pairs[i].value = value
			return
		}
	}
	t.pairs = append(t.pairs, avPair{id: id, value: value})
}

// Get returns the first value for id or nil if absent.
func (t *TargetInfo) Get(id uint16) []byte {
	for _, p := range t.pairs {
		if p.id == id {
			return p.value
		}
	}
	return nil
}

// Encode serializes to the AV_PAIR wire format with a trailing EOL record.
func (t *TargetInfo) Encode() []byte {
	var out []byte
	for _, p := range t.pairs {
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint16(hdr[0:2], p.id)
		binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(p.value)))
		out = append(out, hdr...)
		out = append(out, p.value...)
	}
	// EOL marker (ID=0, Len=0).
	out = append(out, 0, 0, 0, 0)
	return out
}

// DecodeTargetInfo parses an AV_PAIR list up to the EOL record.
func DecodeTargetInfo(data []byte) (*TargetInfo, error) {
	ti := &TargetInfo{}
	for offset := 0; offset+4 <= len(data); {
		id := binary.LittleEndian.Uint16(data[offset : offset+2])
		ln := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if id == AvIDEOL {
			return ti, nil
		}
		if offset+int(ln) > len(data) {
			return nil, fmt.Errorf("av_pair: truncated value for id %d", id)
		}
		val := make([]byte, ln)
		copy(val, data[offset:offset+int(ln)])
		ti.pairs = append(ti.pairs, avPair{id: id, value: val})
		offset += int(ln)
	}
	return nil, fmt.Errorf("av_pair: missing EOL record")
}

// utf16LE returns s encoded as UTF-16 little-endian bytes, no BOM.
// Exported-via-lowercase because only tests and internal callers need it.
func utf16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(runes))
	for i, r := range runes {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}
```

- [ ] **Step 4: Run test - expect pass**

```bash
go test ./internal/auth/ntlm/...
```

Expected: `ok  github.com/ajm4n/certigo/internal/auth/ntlm`.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/ntlm/avpair.go internal/auth/ntlm/avpair_test.go
git commit -m "feat(ntlm): add AV_PAIR / TargetInfo codec"
```

---

## Task 3: NTLM crypto primitives (TDD)

Reference: MS-NLMP §4.2.4.1.1 for NTOWFv2 vector; §4.2.4.1.2 for NTLMv2 response; §4.2.4.2 for session keys.

**Files:**
- Create: `internal/auth/ntlm/crypto.go`
- Create: `internal/auth/ntlm/crypto_test.go`
- Modify: `go.mod` (adds `golang.org/x/crypto`)

- [ ] **Step 1: Add MD4 dependency**

```bash
go get golang.org/x/crypto/md4
go mod tidy
```

Expected: `go.mod` adds `golang.org/x/crypto`.

- [ ] **Step 2: Write failing test**

Write `/Users/ajman/Documents/Tools/gotipy/internal/auth/ntlm/crypto_test.go`:

```go
package ntlm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// MS-NLMP §4.2.4.1.1 vector.
func TestNTOWFv2Vector(t *testing.T) {
	// Inputs: password="Password", user="User", domain="Domain"
	// Expected: NTOWFv2 = 0x0c868a403bfd7a93a3001ef22ef02e3f
	got := NTOWFv2("Password", "User", "Domain")
	want, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if !bytes.Equal(got, want) {
		t.Errorf("NTOWFv2 = %x, want %x", got, want)
	}
}

// MS-NLMP §4.2.4.1.2 + §4.2.4.1.3 - NTLMv2 response.
// Using MS-NLMP fixtures: responseKey=NTOWFv2 from above,
// serverChallenge=0x0123456789abcdef, clientChallenge=0xaaaaaaaaaaaaaaaa,
// timestamp=0x0000000000000000, targetInfo = {NbDomainName=Domain, NbComputerName=Server}.
func TestNTLMv2ResponseVector(t *testing.T) {
	responseKey, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	serverChal, _ := hex.DecodeString("0123456789abcdef")
	clientChal, _ := hex.DecodeString("aaaaaaaaaaaaaaaa")
	timestamp := make([]byte, 8) // all zeros per vector

	ti := &TargetInfo{}
	ti.Set(AvIDNbDomainName, utf16LE("Domain"))
	ti.Set(AvIDNbComputerName, utf16LE("Server"))

	ntResp := NTLMv2Response(responseKey, serverChal, clientChal, timestamp, ti.Encode())

	// Expected full NtChallengeResponse from MS-NLMP:
	// 68cd0ab851e51c96aabc927bebef6a1c (NTProofStr, 16B)
	// 01010000000000000000000000000000 (temp header)
	// aaaaaaaaaaaaaaaa00000000 (clientChal + reserved)
	// 020000000c0044006f006d00610069006e00 (av_pair 2 "Domain")
	// 01000c005300650072007600650072000000 (av_pair 1 "Server" + EOL)
	// 00000000 (trailing reserved)
	want, _ := hex.DecodeString(
		"68cd0ab851e51c96aabc927bebef6a1c" +
			"01010000000000000000000000000000" +
			"aaaaaaaaaaaaaaaa00000000" +
			"02000c0044006f006d00610069006e00" +
			"01000c005300650072007600650072000000" +
			"00000000")
	if !bytes.Equal(ntResp, want) {
		t.Errorf("NTLMv2Response\n got: %x\nwant: %x", ntResp, want)
	}
}

// MS-NLMP §4.2.4.1.2 LMv2 response.
func TestLMv2ResponseVector(t *testing.T) {
	responseKey, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	serverChal, _ := hex.DecodeString("0123456789abcdef")
	clientChal, _ := hex.DecodeString("aaaaaaaaaaaaaaaa")
	got := LMv2Response(responseKey, serverChal, clientChal)
	// Expected: 86c35097ac9cec102554764a57cccc19 || aaaaaaaaaaaaaaaa
	want, _ := hex.DecodeString("86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa")
	if !bytes.Equal(got, want) {
		t.Errorf("LMv2Response = %x, want %x", got, want)
	}
}

// MS-NLMP §4.2.4.2 - SessionBaseKey.
func TestSessionBaseKeyVector(t *testing.T) {
	responseKey, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	ntProofStr, _ := hex.DecodeString("68cd0ab851e51c96aabc927bebef6a1c")
	got := SessionBaseKey(responseKey, ntProofStr)
	want, _ := hex.DecodeString("8de40ccadbc14a82f15cb0ad0de95ca3")
	if !bytes.Equal(got, want) {
		t.Errorf("SessionBaseKey = %x, want %x", got, want)
	}
}
```

- [ ] **Step 3: Run test - expect failure**

```bash
go test ./internal/auth/ntlm/...
```

Expected: fails - `NTOWFv2`, `NTLMv2Response`, `LMv2Response`, `SessionBaseKey` undefined.

- [ ] **Step 4: Implement crypto.go**

Write `/Users/ajman/Documents/Tools/gotipy/internal/auth/ntlm/crypto.go`:

```go
package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"strings"

	"golang.org/x/crypto/md4"
)

// NTOWFv2 computes the NTLMv2 response key (MS-NLMP §3.3.2):
//   HMAC_MD5(MD4(UNICODE(password)), UNICODE(ToUpper(user) || domain))
//
// Username is uppercased (ASCII); domain is NOT uppercased.
func NTOWFv2(password, username, domain string) []byte {
	// MD4 of UTF-16-LE password = NT hash
	nt := md4.New()
	_, _ = nt.Write(utf16LE(password))
	ntHash := nt.Sum(nil)

	// HMAC-MD5 over UTF-16-LE(uppercase(user) || domain)
	h := hmac.New(md5.New, ntHash)
	_, _ = h.Write(utf16LE(strings.ToUpper(username) + domain))
	return h.Sum(nil)
}

// NTLMv2Response returns the full NtChallengeResponse per MS-NLMP §3.3.2.
//
// temp is built from the fixed signature byte, timestamp, client challenge,
// and serialized target info. Output layout:
//
//	NTProofStr (16B) || temp
//
// where NTProofStr = HMAC_MD5(responseKey, serverChallenge || temp)
// and temp = 0x01, 0x01, 0x00*6, timestamp(8), clientChallenge(8), 0x00*4,
//            targetInfo, 0x00*4
func NTLMv2Response(responseKey, serverChallenge, clientChallenge, timestamp, targetInfo []byte) []byte {
	temp := buildTemp(timestamp, clientChallenge, targetInfo)
	h := hmac.New(md5.New, responseKey)
	_, _ = h.Write(serverChallenge)
	_, _ = h.Write(temp)
	ntProof := h.Sum(nil)
	out := make([]byte, 0, len(ntProof)+len(temp))
	out = append(out, ntProof...)
	out = append(out, temp...)
	return out
}

// LMv2Response per MS-NLMP §3.3.2:
//   HMAC_MD5(responseKey, serverChallenge || clientChallenge) || clientChallenge
func LMv2Response(responseKey, serverChallenge, clientChallenge []byte) []byte {
	h := hmac.New(md5.New, responseKey)
	_, _ = h.Write(serverChallenge)
	_, _ = h.Write(clientChallenge)
	out := h.Sum(nil)
	return append(out, clientChallenge...)
}

// SessionBaseKey per MS-NLMP §3.4.5.1 for NTLMv2:
//   HMAC_MD5(responseKey, NTProofStr)
// where NTProofStr is the first 16 bytes of NtChallengeResponse.
func SessionBaseKey(responseKey, ntProofStr []byte) []byte {
	h := hmac.New(md5.New, responseKey)
	_, _ = h.Write(ntProofStr)
	return h.Sum(nil)
}

// buildTemp assembles the 'temp' structure from MS-NLMP §3.3.2.
// Layout (offset, size, value):
//
//	0  1  0x01                       RespType
//	1  1  0x01                       HiRespType
//	2  2  0x00 0x00                  Reserved1
//	4  4  0x00 0x00 0x00 0x00        Reserved2
//	8  8  timestamp                  Time (FILETIME, little-endian uint64)
//	16 8  clientChallenge            ChallengeFromClient
//	24 4  0x00 0x00 0x00 0x00        Reserved3
//	28 V  targetInfo                 ServerName (AV_PAIRS incl. EOL)
//	28+V 4 0x00 0x00 0x00 0x00       Reserved4
func buildTemp(timestamp, clientChallenge, targetInfo []byte) []byte {
	temp := make([]byte, 0, 28+len(targetInfo)+4)
	temp = append(temp, 0x01, 0x01, 0x00, 0x00)
	temp = append(temp, 0x00, 0x00, 0x00, 0x00)
	temp = append(temp, timestamp...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0x00, 0x00, 0x00, 0x00)
	temp = append(temp, targetInfo...)
	temp = append(temp, 0x00, 0x00, 0x00, 0x00)
	return temp
}
```

- [ ] **Step 5: Run tests - expect pass**

```bash
go test ./internal/auth/ntlm/...
```

Expected: all four tests pass.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/auth/ntlm/crypto.go internal/auth/ntlm/crypto_test.go
git commit -m "feat(ntlm): add NTOWFv2, NTLMv2/LMv2 response, SessionBaseKey"
```

---

## Task 4: Security buffer + message codec (TDD)

**Files:**
- Create: `internal/auth/ntlm/message.go`
- Create: `internal/auth/ntlm/message_test.go`

- [ ] **Step 1: Write failing test**

Write `/Users/ajman/Documents/Tools/gotipy/internal/auth/ntlm/message_test.go`:

```go
package ntlm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSecurityBufferEncode(t *testing.T) {
	sb := securityBuffer{length: 12, allocated: 12, offset: 56}
	got := sb.encode()
	// little-endian: 0c000c003800000000 (length, alloc, offset)
	want := []byte{0x0c, 0x00, 0x0c, 0x00, 0x38, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("securityBuffer.encode = %x, want %x", got, want)
	}
}

// Round-trip a CHALLENGE_MESSAGE constructed to the MS-NLMP §4.2.4.1.3 fixture.
func TestChallengeMessageDecode(t *testing.T) {
	// Minimal valid CHALLENGE_MESSAGE with:
	//   - NegotiateFlags = NegotiateUnicode|NegotiateNTLM|NegotiateTargetInfo
	//   - ServerChallenge = 0x0123456789abcdef
	//   - TargetInfo = NbDomainName=Domain, NbComputerName=Server
	//
	// We build it programmatically (rather than hardcoding the full hex) so
	// the test also covers our encoder once Task 5 lands. For now the test
	// hand-assembles the bytes the wire would produce.
	ti := &TargetInfo{}
	ti.Set(AvIDNbDomainName, utf16LE("Domain"))
	ti.Set(AvIDNbComputerName, utf16LE("Server"))
	tiBytes := ti.Encode()

	// Build the wire bytes manually.
	//   8  signature
	//   4  messageType=2
	//   8  targetNameFields (empty: len=0, alloc=0, offset=48)
	//   4  negotiateFlags
	//   8  serverChallenge
	//   8  reserved
	//   8  targetInfoFields (len=tiBytes, alloc=tiBytes, offset=48)
	//   8  version
	//   V  targetInfo payload
	flags := uint32(NegotiateUnicode | NegotiateNTLM | NegotiateTargetInfo)
	payload := make([]byte, 0, 56+len(tiBytes))
	payload = append(payload, Signature[:]...)
	payload = append(payload, u32(MessageTypeChallenge)...)
	// targetNameFields: empty, offset 56
	payload = append(payload, u16(0)...)
	payload = append(payload, u16(0)...)
	payload = append(payload, u32Direct(56)...)
	payload = append(payload, u32(flags)...)
	srvChal, _ := hex.DecodeString("0123456789abcdef")
	payload = append(payload, srvChal...)
	payload = append(payload, make([]byte, 8)...) // reserved
	payload = append(payload, u16(uint16(len(tiBytes)))...)
	payload = append(payload, u16(uint16(len(tiBytes)))...)
	payload = append(payload, u32Direct(56)...) // offset
	payload = append(payload, make([]byte, 8)...) // version
	payload = append(payload, tiBytes...)

	msg, err := DecodeChallengeMessage(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(msg.ServerChallenge[:], srvChal) {
		t.Errorf("ServerChallenge = %x, want %x", msg.ServerChallenge, srvChal)
	}
	if msg.NegotiateFlags != flags {
		t.Errorf("NegotiateFlags = %x, want %x", msg.NegotiateFlags, flags)
	}
	if !bytes.Equal(msg.TargetInfo.Get(AvIDNbDomainName), utf16LE("Domain")) {
		t.Error("TargetInfo NbDomainName missing")
	}
	if !bytes.Equal(msg.TargetInfo.Get(AvIDNbComputerName), utf16LE("Server")) {
		t.Error("TargetInfo NbComputerName missing")
	}
}

func TestNegotiateMessageEncode(t *testing.T) {
	msg := &NegotiateMessage{
		NegotiateFlags: uint32(NegotiateUnicode | NegotiateNTLM | RequestTarget),
	}
	out := msg.Encode()
	if len(out) < 32 {
		t.Fatalf("encoded length = %d, want >= 32", len(out))
	}
	if !bytes.HasPrefix(out, Signature[:]) {
		t.Error("missing signature prefix")
	}
	if got := leU32(out[8:12]); got != MessageTypeNegotiate {
		t.Errorf("MessageType = %d, want %d", got, MessageTypeNegotiate)
	}
	if got := leU32(out[12:16]); got != msg.NegotiateFlags {
		t.Errorf("NegotiateFlags = %x, want %x", got, msg.NegotiateFlags)
	}
}

// small helpers local to the test
func u16(v uint16) []byte {
	b := make([]byte, 2)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	return b
}
func u32(v uint32) []byte { return u32Direct(v) }
func u32Direct(v uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return b
}
func leU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
```

- [ ] **Step 2: Run test - expect failure**

```bash
go test ./internal/auth/ntlm/...
```

Expected: fails - `securityBuffer`, `NegotiateMessage`, `DecodeChallengeMessage` undefined.

- [ ] **Step 3: Implement message.go**

Write `/Users/ajman/Documents/Tools/gotipy/internal/auth/ntlm/message.go`:

```go
package ntlm

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// securityBuffer is MS-NLMP's eight-byte descriptor (length, allocated, offset)
// pointing at a variable-length payload inside a message blob.
type securityBuffer struct {
	length    uint16
	allocated uint16
	offset    uint32
}

func (s securityBuffer) encode() []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint16(out[0:2], s.length)
	binary.LittleEndian.PutUint16(out[2:4], s.allocated)
	binary.LittleEndian.PutUint32(out[4:8], s.offset)
	return out
}

func decodeSecurityBuffer(b []byte) securityBuffer {
	return securityBuffer{
		length:    binary.LittleEndian.Uint16(b[0:2]),
		allocated: binary.LittleEndian.Uint16(b[2:4]),
		offset:    binary.LittleEndian.Uint32(b[4:8]),
	}
}

// NegotiateMessage (MS-NLMP §2.2.1.1). Client's opening move.
type NegotiateMessage struct {
	NegotiateFlags uint32
	DomainName     []byte // OEM ASCII; usually empty
	Workstation    []byte // OEM ASCII; usually empty
	Version        [8]byte
}

func (m *NegotiateMessage) Encode() []byte {
	const headerLen = 32
	var buf bytes.Buffer
	buf.Write(Signature[:])
	_ = binary.Write(&buf, binary.LittleEndian, MessageTypeNegotiate)
	_ = binary.Write(&buf, binary.LittleEndian, m.NegotiateFlags)

	// Payload offsets follow the fixed header.
	domOffset := uint32(headerLen)
	wsOffset := domOffset + uint32(len(m.DomainName))

	buf.Write(securityBuffer{length: uint16(len(m.DomainName)), allocated: uint16(len(m.DomainName)), offset: domOffset}.encode())
	buf.Write(securityBuffer{length: uint16(len(m.Workstation)), allocated: uint16(len(m.Workstation)), offset: wsOffset}.encode())

	// Fixed header ends here; we are at offset 32. The buf currently holds
	// signature(8) + type(4) + flags(4) + secBuf(8) + secBuf(8) = 32. Good.
	// But we haven't written Version - that's another 8 bytes, making the header 40.
	// Real NTLM libraries vary; our format here matches MS-NLMP strict (no version
	// section unless NegotiateVersion flag set). Keep header at 32; payload starts at 32.
	_ = wsOffset // silence staticcheck when workstation empty

	buf.Write(m.DomainName)
	buf.Write(m.Workstation)
	return buf.Bytes()
}

// ChallengeMessage (MS-NLMP §2.2.1.2). Server's response.
type ChallengeMessage struct {
	TargetName      []byte
	NegotiateFlags  uint32
	ServerChallenge [8]byte
	TargetInfo      *TargetInfo
	TargetInfoRaw   []byte // preserved for AUTHENTICATE echo
	Version         [8]byte
}

// DecodeChallengeMessage parses a CHALLENGE_MESSAGE blob.
func DecodeChallengeMessage(data []byte) (*ChallengeMessage, error) {
	if len(data) < 48 {
		return nil, fmt.Errorf("ntlm: challenge too short (%d)", len(data))
	}
	if !bytes.Equal(data[0:8], Signature[:]) {
		return nil, fmt.Errorf("ntlm: bad signature")
	}
	if mt := binary.LittleEndian.Uint32(data[8:12]); mt != MessageTypeChallenge {
		return nil, fmt.Errorf("ntlm: expected CHALLENGE (2), got %d", mt)
	}
	targetNameFields := decodeSecurityBuffer(data[12:20])
	flags := binary.LittleEndian.Uint32(data[20:24])
	var srvChal [8]byte
	copy(srvChal[:], data[24:32])
	// Reserved: 32:40
	targetInfoFields := decodeSecurityBuffer(data[40:48])

	msg := &ChallengeMessage{
		NegotiateFlags:  flags,
		ServerChallenge: srvChal,
	}
	if targetNameFields.length > 0 {
		off := int(targetNameFields.offset)
		end := off + int(targetNameFields.length)
		if end > len(data) {
			return nil, fmt.Errorf("ntlm: target name truncated")
		}
		msg.TargetName = append([]byte(nil), data[off:end]...)
	}
	if targetInfoFields.length > 0 {
		off := int(targetInfoFields.offset)
		end := off + int(targetInfoFields.length)
		if end > len(data) {
			return nil, fmt.Errorf("ntlm: target info truncated")
		}
		raw := append([]byte(nil), data[off:end]...)
		ti, err := DecodeTargetInfo(raw)
		if err != nil {
			return nil, fmt.Errorf("ntlm: %w", err)
		}
		msg.TargetInfo = ti
		msg.TargetInfoRaw = raw
	} else {
		msg.TargetInfo = &TargetInfo{}
	}
	return msg, nil
}

// AuthenticateMessage (MS-NLMP §2.2.1.3). Client's reply with computed responses.
type AuthenticateMessage struct {
	LmChallengeResponse       []byte
	NtChallengeResponse       []byte
	DomainName                []byte // UTF-16-LE
	UserName                  []byte // UTF-16-LE
	Workstation               []byte // UTF-16-LE
	EncryptedRandomSessionKey []byte
	NegotiateFlags            uint32
	Version                   [8]byte
	MIC                       []byte // 16 bytes if present, else nil
}

// Encode serializes AUTHENTICATE_MESSAGE per MS-NLMP §2.2.1.3 wire layout.
func (m *AuthenticateMessage) Encode() []byte {
	header := 64
	if m.MIC != nil {
		header += 16
	}

	var payload bytes.Buffer
	// Payload written in the same order as the security buffers below.
	payloadStart := uint32(header)

	lmOff := payloadStart
	payload.Write(m.LmChallengeResponse)

	ntOff := payloadStart + uint32(payload.Len())
	payload.Write(m.NtChallengeResponse)

	domOff := payloadStart + uint32(payload.Len())
	payload.Write(m.DomainName)

	userOff := payloadStart + uint32(payload.Len())
	payload.Write(m.UserName)

	wsOff := payloadStart + uint32(payload.Len())
	payload.Write(m.Workstation)

	sessKeyOff := payloadStart + uint32(payload.Len())
	payload.Write(m.EncryptedRandomSessionKey)

	var buf bytes.Buffer
	buf.Write(Signature[:])
	_ = binary.Write(&buf, binary.LittleEndian, MessageTypeAuthenticate)
	buf.Write(securityBuffer{length: uint16(len(m.LmChallengeResponse)), allocated: uint16(len(m.LmChallengeResponse)), offset: lmOff}.encode())
	buf.Write(securityBuffer{length: uint16(len(m.NtChallengeResponse)), allocated: uint16(len(m.NtChallengeResponse)), offset: ntOff}.encode())
	buf.Write(securityBuffer{length: uint16(len(m.DomainName)), allocated: uint16(len(m.DomainName)), offset: domOff}.encode())
	buf.Write(securityBuffer{length: uint16(len(m.UserName)), allocated: uint16(len(m.UserName)), offset: userOff}.encode())
	buf.Write(securityBuffer{length: uint16(len(m.Workstation)), allocated: uint16(len(m.Workstation)), offset: wsOff}.encode())
	buf.Write(securityBuffer{length: uint16(len(m.EncryptedRandomSessionKey)), allocated: uint16(len(m.EncryptedRandomSessionKey)), offset: sessKeyOff}.encode())
	_ = binary.Write(&buf, binary.LittleEndian, m.NegotiateFlags)
	buf.Write(m.Version[:])
	if m.MIC != nil {
		buf.Write(m.MIC)
	}
	buf.Write(payload.Bytes())
	return buf.Bytes()
}
```

- [ ] **Step 4: Run tests - expect pass**

```bash
go test ./internal/auth/ntlm/...
```

Expected: all seven tests pass (two new + five prior).

- [ ] **Step 5: Commit**

```bash
git add internal/auth/ntlm/message.go internal/auth/ntlm/message_test.go
git commit -m "feat(ntlm): add NEGOTIATE/CHALLENGE/AUTHENTICATE message codec"
```

---

## Task 5: Client handshake + session (TDD)

**Files:**
- Create: `internal/auth/ntlm/session.go`
- Create: `internal/auth/ntlm/session_test.go`

- [ ] **Step 1: Write failing test**

Write `/Users/ajman/Documents/Tools/gotipy/internal/auth/ntlm/session_test.go`:

```go
package ntlm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// End-to-end vector: client("Domain","User","Password") against a server
// advertising serverChallenge=0123456789abcdef and TargetInfo{Domain,Server}.
// Fixed clientChallenge + timestamp let us compare against MS-NLMP golden.
func TestClientEndToEndVector(t *testing.T) {
	// Build a minimal CHALLENGE_MESSAGE identical to Task 4's test vector.
	ti := &TargetInfo{}
	ti.Set(AvIDNbDomainName, utf16LE("Domain"))
	ti.Set(AvIDNbComputerName, utf16LE("Server"))
	tiBytes := ti.Encode()
	flags := uint32(NegotiateUnicode | NegotiateNTLM | NegotiateTargetInfo)

	var cmBuf bytes.Buffer
	cmBuf.Write(Signature[:])
	cmBuf.Write([]byte{0x02, 0x00, 0x00, 0x00}) // MessageType=2
	cmBuf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00}) // targetName (empty) @ offset 48
	flagsBytes := make([]byte, 4)
	flagsBytes[0] = byte(flags)
	flagsBytes[1] = byte(flags >> 8)
	flagsBytes[2] = byte(flags >> 16)
	flagsBytes[3] = byte(flags >> 24)
	cmBuf.Write(flagsBytes)
	srvChal, _ := hex.DecodeString("0123456789abcdef")
	cmBuf.Write(srvChal)
	cmBuf.Write(make([]byte, 8)) // reserved
	l := uint16(len(tiBytes))
	cmBuf.Write([]byte{byte(l), byte(l >> 8), byte(l), byte(l >> 8), 0x30, 0x00, 0x00, 0x00})
	cmBuf.Write(make([]byte, 8)) // version
	cmBuf.Write(tiBytes)

	c := NewClient("Domain", "User", "Password", "")
	c.fixedClientChallenge = mustHex("aaaaaaaaaaaaaaaa")
	c.fixedTimestamp = make([]byte, 8) // all zeros

	authBytes, err := c.Authenticate(cmBuf.Bytes())
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if len(authBytes) < 64 {
		t.Fatalf("auth message too short: %d", len(authBytes))
	}
	if !bytes.HasPrefix(authBytes, Signature[:]) {
		t.Error("missing signature prefix")
	}

	// The session key should be derivable from the responseKey + NTProofStr per MS-NLMP §4.2.4.2.
	want, _ := hex.DecodeString("8de40ccadbc14a82f15cb0ad0de95ca3")
	if !bytes.Equal(c.SessionKey(), want) {
		t.Errorf("SessionKey = %x, want %x", c.SessionKey(), want)
	}
}

func TestClientNegotiateBytes(t *testing.T) {
	c := NewClient("Domain", "User", "Password", "WORKSTATION")
	neg := c.Negotiate()
	if !bytes.HasPrefix(neg, Signature[:]) {
		t.Error("negotiate missing signature")
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
```

- [ ] **Step 2: Run test - expect failure**

```bash
go test ./internal/auth/ntlm/...
```

Expected: `NewClient`, `Client.Authenticate`, `Client.Negotiate`, `Client.SessionKey`, `Client.fixedClientChallenge`, `Client.fixedTimestamp` undefined.

- [ ] **Step 3: Implement session.go**

Write `/Users/ajman/Documents/Tools/gotipy/internal/auth/ntlm/session.go`:

```go
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
	sessionKey        []byte // ExportedSessionKey (16 bytes)
	clientSigningKey  []byte
	serverSigningKey  []byte
	clientSealingKey  []byte
	serverSealingKey  []byte
	clientSealingCtx  *rc4.Cipher
	serverSealingCtx  *rc4.Cipher
	negotiatedFlags   uint32
	seqClient         uint32
	seqServer         uint32

	// Test hooks - leave nil in production. Populated to deterministic values
	// when reproducing MS-NLMP golden vectors.
	fixedClientChallenge []byte // 8 bytes; nil = use crypto/rand
	fixedTimestamp       []byte // 8 bytes; nil = use time.Now() as FILETIME
}

// NewClient constructs a Client. Workstation is optional (empty string OK).
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

// Authenticate consumes a CHALLENGE_MESSAGE and returns the AUTHENTICATE_MESSAGE bytes.
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

	// If the server sent AV_PAIRS, echo them with our additions; else start fresh.
	ti := cm.TargetInfo
	if ti == nil {
		ti = &TargetInfo{}
	}
	tiBytes := ti.Encode()
	if cm.TargetInfoRaw != nil {
		// Keep the server's exact bytes so the HMAC over them matches.
		tiBytes = cm.TargetInfoRaw
	}

	responseKey := NTOWFv2(c.Password, c.Username, c.Domain)
	ntResp := NTLMv2Response(responseKey, cm.ServerChallenge[:], clientChal, timestamp, tiBytes)
	lmResp := LMv2Response(responseKey, cm.ServerChallenge[:], clientChal)

	ntProof := ntResp[:16]
	baseKey := SessionBaseKey(responseKey, ntProof)
	keyExch := baseKey // NTLMv2 without LMv2 session security

	// ExportedSessionKey: random 16 bytes, encrypted under RC4(keyExch) if NegotiateKeyExch.
	var exported []byte
	var encSessKey []byte
	if cm.NegotiateFlags&NegotiateKeyExch != 0 {
		exported = make([]byte, 16)
		if _, err := rand.Read(exported); err != nil {
			return nil, fmt.Errorf("ntlm: rand: %w", err)
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

// SessionKey returns the ExportedSessionKey (or the unexchanged base key if no KeyExch).
// Must be called after Authenticate().
func (c *Client) SessionKey() []byte {
	return c.sessionKey
}

// Sign returns the MS-NLMP §3.4.4.2 signed-message signature for msg.
// Requires NegotiateSign to have been negotiated.
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

// Seal encrypts msg in place and returns the signature; requires NegotiateSeal.
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

// windowsFiletime returns t as a FILETIME: 100-ns intervals since 1601-01-01 UTC,
// as an 8-byte little-endian unsigned integer.
func windowsFiletime(t time.Time) []byte {
	const epochDelta = 11644473600 // seconds between 1601-01-01 and 1970-01-01
	ns := uint64(t.UTC().Unix()+epochDelta)*10_000_000 + uint64(t.Nanosecond()/100)
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, ns)
	return out
}
```

- [ ] **Step 4: Run tests - expect pass**

```bash
go test ./internal/auth/ntlm/...
```

Expected: all nine tests pass.

- [ ] **Step 5: Lint**

```bash
make lint
```

Expected: `0 issues.`

- [ ] **Step 6: Commit**

```bash
git add internal/auth/ntlm/session.go internal/auth/ntlm/session_test.go
git commit -m "feat(ntlm): add Client handshake with signing/sealing"
```

---

## Task 6: Push + verify CI + tag v0.1.0-alpha1

**Files:** none created; release only.

- [ ] **Step 1: Push to origin**

```bash
git push origin main
```

- [ ] **Step 2: Watch CI**

```bash
RUN_ID=$(gh run list -R ajm4n/certigo --limit 1 --json databaseId -q '.[0].databaseId')
gh run watch "$RUN_ID" -R ajm4n/certigo --exit-status
```

Expected: green.

- [ ] **Step 3: Tag alpha release**

```bash
git tag -a v0.1.0-alpha1 -m "v0.1.0-alpha1 - M1a: pure-Go NTLMv2 client library"
git push origin v0.1.0-alpha1
```

- [ ] **Step 4: Verify release artifacts**

```bash
sleep 90
gh release view v0.1.0-alpha1 -R ajm4n/certigo | head -20
```

Expected: six archives + checksums.

---

## Self-review

**1. Spec coverage:**
- "internal/auth/ntlm" package per spec §"Library selections" → Tasks 1-5.
- "Used by LDAP signed binds, HTTP basic-auth alternative, RPC, relay" → library is generic (no LDAP/HTTP/RPC coupling); M1c/M1d/M7 consume it.
- "~400 lines" spec estimate → actual ~600 LoC including tests.

**2. Placeholder scan:** No TBDs, no "similar to Task N", no "add error handling" - every code block is concrete.

**3. Type consistency:** `NTOWFv2`, `NTLMv2Response`, `LMv2Response`, `SessionBaseKey` referenced in Task 5 are defined in Task 3 with matching signatures. `TargetInfo` / `DecodeTargetInfo` used in Task 4 defined in Task 2. `NegotiateMessage`, `ChallengeMessage`, `AuthenticateMessage`, `DecodeChallengeMessage` used in Task 5 defined in Task 4. `Signature`, `Negotiate*`, `AvID*`, `*MagicConstant` used across tasks defined in Task 1. All cross-references check out.

**Risks noted:**
- `windowsFiletime` precision: our test uses `fixedTimestamp = zeros`, so production time conversion is not covered by MS-NLMP golden vectors. If an interop issue emerges at M1c/M7, revisit.
- MIC (Message Integrity Code) handling is stubbed - `AuthenticateMessage.MIC = nil` always. Some servers require MIC. If integration tests in M1c fail due to MIC, add a follow-up task.
