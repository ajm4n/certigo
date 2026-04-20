package adcs

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildSIDBuiltinAdmins fabricates the binary form of S-1-5-32-544.
func buildSIDBuiltinAdmins() []byte {
	// Revision(1) + SubAuthCount(1) + Authority(6, big-endian) + 2 x SubAuth(4, LE)
	sid := make([]byte, 2+6+4*2)
	sid[0] = 1                                     // revision
	sid[1] = 2                                     // sub-authority count
	sid[2], sid[3] = 0, 0                          // authority high bytes (=0)
	sid[4], sid[5] = 0, 0                          // authority (big-endian) — value 5 lives in bytes 6-7
	sid[6], sid[7] = 0, 5                          // identifier authority = 5
	binary.LittleEndian.PutUint32(sid[8:12], 32)   // sub-authority 0 = BUILTIN
	binary.LittleEndian.PutUint32(sid[12:16], 544) // sub-authority 1 = Administrators
	return sid
}

// buildSecurityDescriptorWithOneAllowedACE wraps the given SID in a
// minimal self-relative SD containing a DACL with a single
// ACCESS_ALLOWED ACE (mask=0x20000 = ReadControl | we also set WriteDACL
// bit to exercise rightsSummary).
func buildSecurityDescriptorWithOneAllowedACE(sid []byte, mask uint32) []byte {
	// ACE body: mask(4) + sid
	aceBody := make([]byte, 4+len(sid))
	binary.LittleEndian.PutUint32(aceBody[:4], mask)
	copy(aceBody[4:], sid)

	// ACE header: type(1)+flags(1)+size(2)
	aceSize := uint16(4 + len(aceBody))
	ace := make([]byte, 4+len(aceBody))
	ace[0] = 0x00 // ACCESS_ALLOWED_ACE
	ace[1] = 0x00
	binary.LittleEndian.PutUint16(ace[2:4], aceSize)
	copy(ace[4:], aceBody)

	// ACL header: rev(1)+sbz1(1)+size(2)+count(2)+sbz2(2)
	aclSize := uint16(8 + len(ace))
	acl := make([]byte, 8+len(ace))
	acl[0] = 2 // AclRevision
	acl[1] = 0
	binary.LittleEndian.PutUint16(acl[2:4], aclSize)
	binary.LittleEndian.PutUint16(acl[4:6], 1) // ACE count
	binary.LittleEndian.PutUint16(acl[6:8], 0) // Sbz2
	copy(acl[8:], ace)

	// Security descriptor header: 20 bytes total.
	sd := make([]byte, 20+len(acl))
	sd[0] = 1 // Revision
	sd[1] = 0 // Sbz1
	// Control: SE_SELF_RELATIVE (0x8000) | SE_DACL_PRESENT (0x0004)
	binary.LittleEndian.PutUint16(sd[2:4], 0x8004)
	// Offsets: owner/group/sacl all zero; DACL starts immediately
	// after the 20-byte header.
	binary.LittleEndian.PutUint32(sd[4:8], 0)
	binary.LittleEndian.PutUint32(sd[8:12], 0)
	binary.LittleEndian.PutUint32(sd[12:16], 0)
	binary.LittleEndian.PutUint32(sd[16:20], 20)
	copy(sd[20:], acl)
	return sd
}

func TestParseSecurityDescriptor_OneAllowedACE(t *testing.T) {
	sd := buildSecurityDescriptorWithOneAllowedACE(
		buildSIDBuiltinAdmins(),
		maskWriteDACL|maskReadControl,
	)
	aces, err := ParseSecurityDescriptor(sd, nil)
	if err != nil {
		t.Fatalf("ParseSecurityDescriptor: %v", err)
	}
	if len(aces) != 1 {
		t.Fatalf("want 1 ACE, got %d", len(aces))
	}
	ace := aces[0]
	if ace.SID != "S-1-5-32-544" {
		t.Errorf("SID = %q, want S-1-5-32-544", ace.SID)
	}
	if ace.Name != "S-1-5-32-544" {
		t.Errorf("Name = %q, want SID verbatim when resolver is nil", ace.Name)
	}
	if !strings.Contains(ace.Rights, "WriteDACL") {
		t.Errorf("Rights = %q, want to include WriteDACL", ace.Rights)
	}
	if !strings.Contains(ace.Rights, "ReadControl") {
		t.Errorf("Rights = %q, want to include ReadControl", ace.Rights)
	}
}

func TestParseSecurityDescriptor_ResolverApplied(t *testing.T) {
	sd := buildSecurityDescriptorWithOneAllowedACE(
		buildSIDBuiltinAdmins(),
		maskGenericAll,
	)
	resolver := func(sid string) (string, error) {
		if sid == "S-1-5-32-544" {
			return `BUILTIN\Administrators`, nil
		}
		return "", nil
	}
	aces, err := ParseSecurityDescriptor(sd, resolver)
	if err != nil {
		t.Fatalf("ParseSecurityDescriptor: %v", err)
	}
	if len(aces) != 1 {
		t.Fatalf("want 1 ACE, got %d", len(aces))
	}
	if aces[0].Name != `BUILTIN\Administrators` {
		t.Errorf("Name = %q, want resolved display name", aces[0].Name)
	}
}

func TestParseSecurityDescriptor_TooShort(t *testing.T) {
	if _, err := ParseSecurityDescriptor([]byte{0x01, 0x00}, nil); err == nil {
		t.Fatal("should error on truncated SD")
	}
}

func TestParseSecurityDescriptor_NoDACL(t *testing.T) {
	// 20-byte header, all offsets zero (no DACL present).
	sd := make([]byte, 20)
	sd[0] = 1
	aces, err := ParseSecurityDescriptor(sd, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(aces) != 0 {
		t.Errorf("want 0 ACEs for NULL DACL, got %d", len(aces))
	}
}

func TestParseSecurityDescriptor_DeniedACEHasDENYLabel(t *testing.T) {
	// Build an ACCESS_DENIED ACE (type 0x01) by hand-editing the
	// single-ACE SD.
	sd := buildSecurityDescriptorWithOneAllowedACE(
		buildSIDBuiltinAdmins(),
		maskWriteDACL,
	)
	// DACL starts at offset 20, ACL header is 8 bytes, then the ACE
	// starts at offset 28. ACE type is the first byte.
	sd[28] = 0x01 // ACCESS_DENIED
	aces, err := ParseSecurityDescriptor(sd, nil)
	if err != nil {
		t.Fatalf("ParseSecurityDescriptor: %v", err)
	}
	if len(aces) != 1 {
		t.Fatalf("want 1 ACE, got %d", len(aces))
	}
	if !strings.HasPrefix(aces[0].Rights, "DENY") {
		t.Errorf("expected DENY prefix in rights, got %q", aces[0].Rights)
	}
}
