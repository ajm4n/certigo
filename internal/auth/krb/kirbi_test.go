package krb

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// buildSyntheticTicket produces a minimal but ASN.1-valid Ticket that can
// survive marshal/unmarshal round-trips without a live KDC.
func buildSyntheticTicket(t *testing.T, realm string, sname types.PrincipalName) messages.Ticket {
	t.Helper()
	return messages.Ticket{
		TktVNO: iana.PVNO,
		Realm:  realm,
		SName:  sname,
		EncPart: types.EncryptedData{
			EType:  18, // aes256-cts-hmac-sha1-96 — a plausible etype for bytes
			KVNO:   1,
			Cipher: []byte("ciphertext-bytes"),
		},
	}
}

// buildSyntheticCCacheBytes emits a minimal MIT ccache v4 byte stream carrying
// one credential. The body reuses the writers in tgt.go.
func buildSyntheticCCacheBytes(t *testing.T, client types.PrincipalName, clientRealm string, server types.PrincipalName, serverRealm string, tkt messages.Ticket) []byte {
	t.Helper()
	tktBytes, err := tkt.Marshal()
	if err != nil {
		t.Fatalf("marshal ticket: %v", err)
	}
	var buf bytes.Buffer
	buf.WriteByte(0x05)
	buf.WriteByte(0x04)
	writeUint16BE(&buf, 0) // empty header

	writePrincipal(&buf, client, clientRealm) // default principal
	writePrincipal(&buf, client, clientRealm) // credential client
	writePrincipal(&buf, server, serverRealm) // credential server
	writeKey(&buf, types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0xAB}, 32)})
	writeUint32BE(&buf, uint32(time.Now().Add(-time.Minute).Unix()))
	writeUint32BE(&buf, uint32(time.Now().Add(-time.Minute).Unix()))
	writeUint32BE(&buf, uint32(time.Now().Add(8*time.Hour).Unix()))
	writeUint32BE(&buf, uint32(time.Now().Add(24*time.Hour).Unix()))
	buf.WriteByte(0) // is_skey
	writeTicketFlags(&buf, asn1.BitString{Bytes: []byte{0x40, 0xe1, 0x00, 0x00}, BitLength: 32})
	writeUint32BE(&buf, 0) // num_addresses
	writeUint32BE(&buf, 0) // num_authdata
	writeData(&buf, tktBytes)
	writeData(&buf, nil)
	return buf.Bytes()
}

// loadCCacheFromBytes writes b to a temp file and loads it via
// credentials.LoadCCache — required because credentials.CCache.Unmarshal
// is available but LoadCCache is the idiomatic entrypoint.
func loadCCacheFromBytes(t *testing.T, b []byte) *credentials.CCache {
	t.Helper()
	cc := new(credentials.CCache)
	if err := cc.Unmarshal(b); err != nil {
		t.Fatalf("unmarshal ccache: %v", err)
	}
	return cc
}

func TestReadWriteKirbiRoundTrip(t *testing.T) {
	realm := "EXAMPLE.COM"
	client := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"alice"},
	}
	server := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}
	tkt := buildSyntheticTicket(t, realm, server)
	ccBytes := buildSyntheticCCacheBytes(t, client, realm, server, realm, tkt)
	cc := loadCCacheFromBytes(t, ccBytes)

	cred, err := CCacheToKirbi(cc)
	if err != nil {
		t.Fatalf("CCacheToKirbi: %v", err)
	}
	if got, want := cred.MsgType, msgtype.KRB_CRED; got != want {
		t.Fatalf("MsgType = %d, want %d", got, want)
	}
	if len(cred.Tickets) != 1 {
		t.Fatalf("Tickets = %d, want 1", len(cred.Tickets))
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "alice.kirbi")
	if err := WriteKirbi(path, cred); err != nil {
		t.Fatalf("WriteKirbi: %v", err)
	}

	// Sanity: file exists and is non-empty.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatalf("kirbi file is empty")
	}

	got, err := ReadKirbi(path)
	if err != nil {
		t.Fatalf("ReadKirbi: %v", err)
	}
	if got.MsgType != msgtype.KRB_CRED {
		t.Fatalf("round-trip MsgType = %d, want %d", got.MsgType, msgtype.KRB_CRED)
	}
	if got.PVNO != iana.PVNO {
		t.Fatalf("round-trip PVNO = %d, want %d", got.PVNO, iana.PVNO)
	}
	if len(got.Tickets) != 1 {
		t.Fatalf("round-trip Tickets = %d, want 1", len(got.Tickets))
	}
	if got.Tickets[0].Realm != realm {
		t.Fatalf("round-trip ticket realm = %q, want %q", got.Tickets[0].Realm, realm)
	}
	if got.EncPart.EType != 0 {
		t.Fatalf("round-trip etype = %d, want 0 (plaintext)", got.EncPart.EType)
	}
}

func TestCCacheToKirbiNoTickets(t *testing.T) {
	cc := &credentials.CCache{}
	if _, err := CCacheToKirbi(cc); err == nil {
		t.Fatal("expected error for empty ccache, got nil")
	}
}

func TestKirbiToCCacheRoundTrip(t *testing.T) {
	realm := "EXAMPLE.COM"
	client := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"carol"},
	}
	server := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}
	tkt := buildSyntheticTicket(t, realm, server)
	ccBytes := buildSyntheticCCacheBytes(t, client, realm, server, realm, tkt)
	cc := loadCCacheFromBytes(t, ccBytes)

	cred, err := CCacheToKirbi(cc)
	if err != nil {
		t.Fatalf("CCacheToKirbi: %v", err)
	}

	// Serialise and parse to exercise the on-wire form, then convert back.
	dir := t.TempDir()
	path := filepath.Join(dir, "carol.kirbi")
	if err := WriteKirbi(path, cred); err != nil {
		t.Fatalf("WriteKirbi: %v", err)
	}
	re, err := ReadKirbi(path)
	if err != nil {
		t.Fatalf("ReadKirbi: %v", err)
	}

	back, err := KirbiToCCache(re)
	if err != nil {
		t.Fatalf("KirbiToCCache: %v", err)
	}
	if got := back.GetClientRealm(); got != realm {
		t.Fatalf("default principal realm = %q, want %q", got, realm)
	}
	if got := len(back.Credentials); got != 1 {
		t.Fatalf("Credentials = %d, want 1", got)
	}
	if got := back.Credentials[0].Server.PrincipalName.NameString; len(got) == 0 || got[0] != "krbtgt" {
		t.Fatalf("server name = %v, want [krbtgt, ...]", got)
	}
	// The enclosed ticket should still parse as a Ticket and carry the
	// original service principal name.
	var rtTkt messages.Ticket
	if err := rtTkt.Unmarshal(back.Credentials[0].Ticket); err != nil {
		t.Fatalf("unmarshal ticket bytes from round-tripped ccache: %v", err)
	}
	if rtTkt.Realm != realm {
		t.Fatalf("round-tripped ticket realm = %q, want %q", rtTkt.Realm, realm)
	}
	// The EncKrbCredPart carries the client principal, so round-tripping
	// should restore the default principal username as well.
	if got := back.GetClientPrincipalName().NameString; len(got) == 0 || got[0] != "carol" {
		t.Fatalf("default principal = %v, want [carol]", got)
	}
}

func TestCCacheToKirbi_PicksTGT(t *testing.T) {
	realm := "EXAMPLE.COM"
	client := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"bob"},
	}
	tgtSName := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}
	svcSName := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"HTTP", "host.example.com"},
	}
	svcTkt := buildSyntheticTicket(t, realm, svcSName)
	tgtTkt := buildSyntheticTicket(t, realm, tgtSName)

	// Build a ccache with the service ticket first and the TGT second to
	// confirm the picker actively searches rather than returning [0].
	svcBytes := buildSyntheticCCacheBytes(t, client, realm, svcSName, realm, svcTkt)
	// Append a second credential (TGT) to the same buffer. The
	// buildSyntheticCCacheBytes helper emits header+default+cred; we need
	// to append just a second credential body. Rebuild manually.
	tktBytes, err := tgtTkt.Marshal()
	if err != nil {
		t.Fatalf("marshal TGT: %v", err)
	}
	var extra bytes.Buffer
	writePrincipal(&extra, client, realm)
	writePrincipal(&extra, tgtSName, realm)
	writeKey(&extra, types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0xCD}, 32)})
	writeUint32BE(&extra, uint32(time.Now().Add(-time.Minute).Unix()))
	writeUint32BE(&extra, uint32(time.Now().Add(-time.Minute).Unix()))
	writeUint32BE(&extra, uint32(time.Now().Add(8*time.Hour).Unix()))
	writeUint32BE(&extra, uint32(time.Now().Add(24*time.Hour).Unix()))
	extra.WriteByte(0)
	writeTicketFlags(&extra, asn1.BitString{Bytes: []byte{0x40, 0xe1, 0x00, 0x00}, BitLength: 32})
	writeUint32BE(&extra, 0)
	writeUint32BE(&extra, 0)
	writeData(&extra, tktBytes)
	writeData(&extra, nil)

	full := append([]byte{}, svcBytes...)
	full = append(full, extra.Bytes()...)

	cc := loadCCacheFromBytes(t, full)
	if got := len(cc.Credentials); got != 2 {
		t.Fatalf("ccache has %d credentials, want 2", got)
	}

	cred, err := CCacheToKirbi(cc)
	if err != nil {
		t.Fatalf("CCacheToKirbi: %v", err)
	}
	if len(cred.Tickets) != 1 {
		t.Fatalf("Tickets = %d, want 1", len(cred.Tickets))
	}
	got := cred.Tickets[0].SName
	if len(got.NameString) == 0 || got.NameString[0] != "krbtgt" {
		t.Fatalf("CCacheToKirbi did not pick TGT, got SName=%v", got.NameString)
	}
}
