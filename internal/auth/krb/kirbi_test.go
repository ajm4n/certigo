package krb

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestReadWriteKirbiRoundTrip(t *testing.T) {
	realm := "EXAMPLE.COM"
	server := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}
	tkt := buildSyntheticTicket(t, realm, server)

	// Build a plaintext-etype EncKrbCredPart to exercise the marshalers in
	// the same shape Rubeus/Mimikatz emit.
	enc := messages.EncKrbCredPart{
		TicketInfo: []messages.KrbCredInfo{{
			Key: types.EncryptionKey{
				KeyType:  18,
				KeyValue: []byte("01234567890123456789012345678901"),
			},
			PRealm: realm,
			PName: types.PrincipalName{
				NameType:   nametype.KRB_NT_PRINCIPAL,
				NameString: []string{"alice"},
			},
			SRealm:    realm,
			SName:     server,
			AuthTime:  time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
			StartTime: time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
			EndTime:   time.Now().Add(8 * time.Hour).UTC().Truncate(time.Second),
			RenewTill: time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
		}},
	}
	encBytes, err := marshalEncKrbCredPart(enc)
	if err != nil {
		t.Fatalf("marshalEncKrbCredPart: %v", err)
	}

	cred := &messages.KRBCred{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_CRED,
		Tickets: []messages.Ticket{tkt},
		EncPart: types.EncryptedData{
			EType:  0,
			Cipher: encBytes,
		},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "alice.kirbi")
	if err := WriteKirbi(path, cred); err != nil {
		t.Fatalf("WriteKirbi: %v", err)
	}

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
