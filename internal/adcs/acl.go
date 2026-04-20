package adcs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// SIDResolver turns a string-form SID into a display name like
// "CORP\\alice". Pass nil to skip resolution and have SID strings
// surfaced verbatim as the Ace.Name.
type SIDResolver func(sid string) (string, error)

// MS-DTYP §2.4.4 — ACE types. We decode the four allow/deny variants
// commonly seen on AD objects. Other types are surfaced as "Unknown".
const (
	aceAccessAllowed         byte = 0x00
	aceAccessDenied          byte = 0x01
	aceSystemAudit           byte = 0x02
	aceAccessAllowedObject   byte = 0x05
	aceAccessDeniedObject    byte = 0x06
	aceSystemAuditObject     byte = 0x07
	aceAccessAllowedCallback byte = 0x09
	aceAccessDeniedCallback  byte = 0x0A
)

// Standard access-mask bits we label in the Rights string. See
// MS-ADTS §5.1.3.2 and MS-DTYP §2.4.3.
const (
	maskGenericRead              uint32 = 0x80000000
	maskGenericWrite             uint32 = 0x40000000
	maskGenericExecute           uint32 = 0x20000000
	maskGenericAll               uint32 = 0x10000000
	maskWriteOwner               uint32 = 0x00080000
	maskWriteDACL                uint32 = 0x00040000
	maskReadControl              uint32 = 0x00020000
	maskDelete                   uint32 = 0x00010000
	maskADSRightsDSControlAccess uint32 = 0x00000100
	maskADSRightsDSWriteProp     uint32 = 0x00000020
	maskADSRightsDSReadProp      uint32 = 0x00000010
	maskADSRightsDSCreateChild   uint32 = 0x00000001
)

// ParseSecurityDescriptor decodes an nTSecurityDescriptor blob into a
// flat slice of Ace entries drawn from the DACL. SACL (audit) ACEs are
// skipped. ACEs whose principal SID cannot be decoded are dropped.
//
// resolve is optional; pass nil to leave the Ace.Name set to the raw
// SID string.
func ParseSecurityDescriptor(desc []byte, resolve SIDResolver) ([]Ace, error) {
	if len(desc) < 20 {
		return nil, fmt.Errorf("adcs: security descriptor too short (%d bytes)", len(desc))
	}
	// SECURITY_DESCRIPTOR header (self-relative form assumed — AD
	// stores SDs self-relative in nTSecurityDescriptor).
	//   byte  0   : Revision
	//   byte  1   : Sbz1
	//   bytes 2-3 : Control flags
	//   bytes 4-7 : OffsetOwner
	//   bytes 8-11: OffsetGroup
	//   bytes 12-15: OffsetSacl
	//   bytes 16-19: OffsetDacl
	daclOffset := binary.LittleEndian.Uint32(desc[16:20])
	if daclOffset == 0 {
		// No DACL present — either a NULL DACL (grants everyone
		// everything; unusual for AD objects) or a permission-less
		// object. Return an empty slice rather than erroring.
		return nil, nil
	}
	if int(daclOffset) >= len(desc) {
		return nil, fmt.Errorf("adcs: DACL offset %d out of range (len=%d)", daclOffset, len(desc))
	}

	acl := desc[daclOffset:]
	return parseACL(acl, resolve)
}

// parseACL iterates the ACE array of an ACL. Layout (MS-DTYP §2.4.5):
//
//	AclRevision : 1 byte
//	Sbz1        : 1 byte
//	AclSize     : 2 bytes (little-endian, total ACL size including header)
//	AceCount    : 2 bytes
//	Sbz2        : 2 bytes
//	then AceCount ACEs, each starting with an ACE_HEADER.
func parseACL(acl []byte, resolve SIDResolver) ([]Ace, error) {
	if len(acl) < 8 {
		return nil, errors.New("adcs: ACL header truncated")
	}
	aclSize := binary.LittleEndian.Uint16(acl[2:4])
	aceCount := binary.LittleEndian.Uint16(acl[4:6])
	if int(aclSize) > len(acl) {
		// Some servers hand us an ACL that exactly fills the
		// supplied buffer; tolerate shorter-than-declared blobs by
		// clamping to what we have.
		aclSize = uint16(len(acl))
	}

	aces := make([]Ace, 0, aceCount)
	offset := 8 // skip ACL header
	for i := uint16(0); i < aceCount; i++ {
		if offset+4 > int(aclSize) {
			break
		}
		aceType := acl[offset]
		// aceFlags := acl[offset+1]
		aceSize := binary.LittleEndian.Uint16(acl[offset+2 : offset+4])
		if aceSize < 4 || offset+int(aceSize) > int(aclSize) {
			break
		}
		body := acl[offset+4 : offset+int(aceSize)]

		ace, ok := parseACE(aceType, body, resolve)
		if ok {
			aces = append(aces, ace)
		}
		offset += int(aceSize)
	}
	return aces, nil
}

// parseACE decodes a single ACE body (content after the 4-byte ACE
// header). ok=false signals the ACE should be skipped (unsupported
// type, truncated body, or audit entry).
func parseACE(aceType byte, body []byte, resolve SIDResolver) (Ace, bool) {
	switch aceType {
	case aceAccessAllowed, aceAccessDenied, aceAccessAllowedCallback, aceAccessDeniedCallback:
		return parseSimpleACE(aceType, body, resolve)
	case aceAccessAllowedObject, aceAccessDeniedObject:
		return parseObjectACE(aceType, body, resolve)
	case aceSystemAudit, aceSystemAuditObject:
		// Skip audit entries — we only care about the DACL.
		return Ace{}, false
	default:
		return Ace{}, false
	}
}

// parseSimpleACE decodes an ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE body:
//
//	Mask : 4 bytes
//	Sid  : variable (SID structure)
func parseSimpleACE(aceType byte, body []byte, resolve SIDResolver) (Ace, bool) {
	if len(body) < 4 {
		return Ace{}, false
	}
	mask := binary.LittleEndian.Uint32(body[:4])
	sid, ok := decodeSID(body[4:])
	if !ok {
		return Ace{}, false
	}
	return Ace{
		SID:    sid,
		Name:   resolveSID(sid, resolve),
		Rights: rightsSummary(aceType, mask),
	}, true
}

// parseObjectACE decodes an ACCESS_ALLOWED_OBJECT_ACE body:
//
//	Mask            : 4 bytes
//	Flags           : 4 bytes (bit 0 = ObjectType present,
//	                   bit 1 = InheritedObjectType present)
//	ObjectType      : 16 bytes (if flag bit 0)
//	InheritedType   : 16 bytes (if flag bit 1)
//	Sid             : variable
func parseObjectACE(aceType byte, body []byte, resolve SIDResolver) (Ace, bool) {
	if len(body) < 8 {
		return Ace{}, false
	}
	mask := binary.LittleEndian.Uint32(body[:4])
	flags := binary.LittleEndian.Uint32(body[4:8])
	cursor := 8
	if flags&0x1 != 0 {
		cursor += 16
	}
	if flags&0x2 != 0 {
		cursor += 16
	}
	if cursor > len(body) {
		return Ace{}, false
	}
	sid, ok := decodeSID(body[cursor:])
	if !ok {
		return Ace{}, false
	}
	return Ace{
		SID:    sid,
		Name:   resolveSID(sid, resolve),
		Rights: rightsSummary(aceType, mask),
	}, true
}

// decodeSID parses an MS-DTYP §2.4.2.2 binary SID into its canonical
// string form "S-1-<authority>-<sub1>-<sub2>...".
//
// Layout:
//
//	Revision     : 1 byte  (=1)
//	SubAuthCount : 1 byte
//	Authority    : 6 bytes (big-endian)
//	SubAuth[]    : 4 bytes each, little-endian
func decodeSID(b []byte) (string, bool) {
	if len(b) < 8 {
		return "", false
	}
	rev := b[0]
	subCount := int(b[1])
	// 48-bit big-endian identifier authority.
	authority := uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 |
		uint64(b[6])<<8 | uint64(b[7])
	need := 8 + 4*subCount
	if len(b) < need {
		return "", false
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", rev, authority)
	for i := 0; i < subCount; i++ {
		sub := binary.LittleEndian.Uint32(b[8+4*i : 12+4*i])
		fmt.Fprintf(&sb, "-%d", sub)
	}
	return sb.String(), true
}

// resolveSID turns a SID string into a human display name, falling
// back to the SID if the resolver is nil or returns an error.
func resolveSID(sid string, resolve SIDResolver) string {
	if resolve == nil {
		return sid
	}
	name, err := resolve(sid)
	if err != nil || name == "" {
		return sid
	}
	return name
}

// rightsSummary produces a short human-readable description of the
// access mask. Not exhaustive — we surface the bits that matter for
// AD CS ESC rule evaluation (Enroll, WriteDacl, WriteOwner, etc.).
func rightsSummary(aceType byte, mask uint32) string {
	var parts []string

	switch aceType {
	case aceAccessDenied, aceAccessDeniedObject, aceAccessDeniedCallback:
		parts = append(parts, "DENY")
	}

	if mask&maskGenericAll != 0 {
		parts = append(parts, "GenericAll")
	}
	if mask&maskGenericRead != 0 {
		parts = append(parts, "GenericRead")
	}
	if mask&maskGenericWrite != 0 {
		parts = append(parts, "GenericWrite")
	}
	if mask&maskGenericExecute != 0 {
		parts = append(parts, "GenericExecute")
	}
	if mask&maskWriteOwner != 0 {
		parts = append(parts, "WriteOwner")
	}
	if mask&maskWriteDACL != 0 {
		parts = append(parts, "WriteDACL")
	}
	if mask&maskReadControl != 0 {
		parts = append(parts, "ReadControl")
	}
	if mask&maskDelete != 0 {
		parts = append(parts, "Delete")
	}
	if mask&maskADSRightsDSControlAccess != 0 {
		parts = append(parts, "ControlAccess")
	}
	if mask&maskADSRightsDSWriteProp != 0 {
		parts = append(parts, "WriteProperty")
	}
	if mask&maskADSRightsDSReadProp != 0 {
		parts = append(parts, "ReadProperty")
	}
	if mask&maskADSRightsDSCreateChild != 0 {
		parts = append(parts, "CreateChild")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("mask=0x%08x", mask)
	}
	return strings.Join(parts, "|")
}
