package ca

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// TestDialRPC_EmptyServer ensures a bare dialRPC call with an empty
// server string fails fast rather than attempting a network dial.
func TestDialRPC_EmptyServer(t *testing.T) {
	t.Parallel()
	if _, err := DialRPC("", "corp-CA", "CORP\\alice", "hunter2"); err == nil {
		t.Fatalf("DialRPC with empty server: want error, got nil")
	} else if !strings.Contains(err.Error(), "server is empty") {
		t.Fatalf("DialRPC error %q: want 'server is empty'", err)
	}

	if _, err := DialRPCWithNTHash("", "corp-CA", "CORP\\alice", make([]byte, 16)); err == nil {
		t.Fatalf("DialRPCWithNTHash with empty server: want error, got nil")
	}
}

// TestDialRPC_EmptyAuthority checks the companion guard rail.
func TestDialRPC_EmptyAuthority(t *testing.T) {
	t.Parallel()
	if _, err := DialRPC("ca.corp.local", "", "alice", "p"); err == nil {
		t.Fatalf("DialRPC with empty authority: want error, got nil")
	} else if !strings.Contains(err.Error(), "authority") {
		t.Fatalf("DialRPC error %q: want mention of authority", err)
	}
}

// TestDialRPC_BadHashLen verifies the NT-hash constructor refuses
// mis-sized hash material before attempting any network work.
func TestDialRPC_BadHashLen(t *testing.T) {
	t.Parallel()
	if _, err := DialRPCWithNTHash("ca.corp.local", "corp-CA", "alice", []byte{1, 2, 3}); err == nil {
		t.Fatalf("DialRPCWithNTHash with 3-byte hash: want error, got nil")
	}
}

// TestErrors makes sure every RPC method returns a descriptive error
// when the client is nil (simulating a failed dialRPC). These calls
// intentionally do not need a live CA.
func TestErrors(t *testing.T) {
	t.Parallel()
	var cli *rpcClient

	if _, err := cli.Backup(); err == nil {
		t.Error("Backup on nil client: want error")
	}
	if err := cli.IssueRequest(1); err == nil {
		t.Error("IssueRequest on nil client: want error")
	}
	if err := cli.DenyRequest(1); err == nil {
		t.Error("DenyRequest on nil client: want error")
	}
	if err := cli.AddOfficer("S-1-5-21-1-2-3-500"); err == nil {
		t.Error("AddOfficer on nil client: want error")
	}
	if err := cli.RemoveOfficer("S-1-5-21-1-2-3-500"); err == nil {
		t.Error("RemoveOfficer on nil client: want error")
	}

	// Close on a nil client must be safe.
	if err := cli.Close(); err != nil {
		t.Errorf("Close on nil client: want nil, got %v", err)
	}
}

// TestIssueDenyZeroID rejects request id == 0 per the MS-CSRA contract.
func TestIssueDenyZeroID(t *testing.T) {
	t.Parallel()
	// Non-nil but unconnected client: the zero-id guard should fire
	// before we touch the wire. We construct a bare struct (no conn)
	// — the zero-id path returns without making a call.
	cli := &rpcClient{authorityName: "corp-CA"}
	if err := cli.IssueRequest(0); err == nil || !strings.Contains(err.Error(), "non-zero") {
		t.Errorf("IssueRequest(0): want non-zero guard, got %v", err)
	}
	if err := cli.DenyRequest(0); err == nil || !strings.Contains(err.Error(), "non-zero") {
		t.Errorf("DenyRequest(0): want non-zero guard, got %v", err)
	}
}

// TestEncodeSID round-trips a few canonical SIDs through the encoder
// and matches the layout documented in MS-DTYP §2.4.2.2.
func TestEncodeSID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want []byte // header bytes we verify; trailing sub-authorities follow
	}{
		{
			in: "S-1-5-21-1-2-3-500",
			// rev=1, subCount=5, authority=5 (big-endian), subs: 21,1,2,3,500
			want: []byte{0x01, 0x05, 0, 0, 0, 0, 0, 0x05},
		},
		{
			in:   "S-1-5-18",
			want: []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0x05},
		},
	}
	for _, c := range cases {
		out, err := encodeSID(c.in)
		if err != nil {
			t.Fatalf("encodeSID(%q): %v", c.in, err)
		}
		if !bytes.HasPrefix(out, c.want) {
			t.Errorf("encodeSID(%q) prefix = %x, want %x", c.in, out[:len(c.want)], c.want)
		}
	}
}

// TestEncodeSID_Invalid ensures the encoder rejects malformed inputs
// without panicking.
func TestEncodeSID_Invalid(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", "not-a-sid", "X-1-5-18", "S-X-5-18", "S-1-X-18", "S-1-5-notnumber"} {
		if _, err := encodeSID(s); err == nil {
			t.Errorf("encodeSID(%q): want error", s)
		}
	}
}

// TestEditOfficerDACL_Add inserts a fresh ACCESS_ALLOWED_ACE into a
// minimal SD and parses the resulting DACL back out to confirm the
// layout matches MS-DTYP.
func TestEditOfficerDACL_Add(t *testing.T) {
	t.Parallel()
	sid, err := encodeSID("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatalf("encodeSID: %v", err)
	}
	sd := emptySelfRelativeSD()
	out, err := editOfficerDACL(sd, sid, 0x00000002, true)
	if err != nil {
		t.Fatalf("editOfficerDACL add: %v", err)
	}

	// DACL offset must be non-zero now.
	daclOff := binary.LittleEndian.Uint32(out[16:20])
	if daclOff == 0 {
		t.Fatal("DACL offset still zero after add")
	}
	ctrl := binary.LittleEndian.Uint16(out[2:4])
	if ctrl&0x0004 == 0 {
		t.Errorf("DP control flag not set, control=0x%04x", ctrl)
	}
	aclStart := int(daclOff)
	aceCount := binary.LittleEndian.Uint16(out[aclStart+4 : aclStart+6])
	if aceCount != 1 {
		t.Errorf("aceCount = %d, want 1", aceCount)
	}

	// Second add for the same SID must be idempotent.
	out2, err := editOfficerDACL(out, sid, 0x00000002, true)
	if err != nil {
		t.Fatalf("editOfficerDACL idempotent add: %v", err)
	}
	aclStart2 := int(binary.LittleEndian.Uint32(out2[16:20]))
	aceCount2 := binary.LittleEndian.Uint16(out2[aclStart2+4 : aclStart2+6])
	if aceCount2 != 1 {
		t.Errorf("second-add aceCount = %d, want 1 (idempotent)", aceCount2)
	}
}

// TestEditOfficerDACL_RemoveMissing reports the expected sentinel error
// when the SID is not present in the DACL.
func TestEditOfficerDACL_RemoveMissing(t *testing.T) {
	t.Parallel()
	sid, _ := encodeSID("S-1-5-21-1-2-3-999")
	sd := emptySelfRelativeSD()
	_, err := editOfficerDACL(sd, sid, 0x00000002, false)
	if !errors.Is(err, errors.New("SID not present in officer DACL")) {
		// errors.Is against fmt.Errorf-wrapped sentinel isn't exact;
		// fall back to string check.
		if err == nil || !strings.Contains(err.Error(), "not present") {
			t.Errorf("remove missing: got %v, want 'not present' error", err)
		}
	}
}

// TestEditOfficerDACL_AddRemove round-trips an ACE into and out of a
// DACL, verifying the count returns to zero.
func TestEditOfficerDACL_AddRemove(t *testing.T) {
	t.Parallel()
	sid, _ := encodeSID("S-1-5-21-1-2-3-1002")
	sd := emptySelfRelativeSD()
	added, err := editOfficerDACL(sd, sid, 0x00000002, true)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	removed, err := editOfficerDACL(added, sid, 0x00000002, false)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	daclOff := binary.LittleEndian.Uint32(removed[16:20])
	if daclOff == 0 {
		t.Fatal("DACL offset went back to zero after remove")
	}
	aclStart := int(daclOff)
	aceCount := binary.LittleEndian.Uint16(removed[aclStart+4 : aclStart+6])
	if aceCount != 0 {
		t.Errorf("aceCount after remove = %d, want 0", aceCount)
	}
}

// TestSplitUser covers the accepted username formats.
func TestSplitUser(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, wantUser, wantDomain string
	}{
		{`CORP\alice`, "alice", "CORP"},
		{`alice@CORP`, "alice", "CORP"},
		{`alice`, "alice", ""},
		{``, "", ""},
	}
	for _, c := range cases {
		u, d := splitUser(c.in)
		if u != c.wantUser || d != c.wantDomain {
			t.Errorf("splitUser(%q) = (%q, %q), want (%q, %q)",
				c.in, u, d, c.wantUser, c.wantDomain)
		}
	}
}
