// Package ca - MS-CSRA request and officer-rights operations layered on
// top of the DCOM binding in rpc.go.
package ca

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/csra"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/icertadmind/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/icertadmind2/v0"

	"github.com/ajm4n/certigo/internal/pki"
)

// Backup retrieves the CA signing certificate via MS-CSRA
// ICertAdminD2::GetCAProperty (PropID = CR_PROP_CASIGCERT).
//
// Note: this does NOT pull the CA private key. Doing so requires the
// multi-step BackupPrepare / BackupOpenFile / BackupReadFile flow
// (MS-CSRA §3.1.4.1.14–18), which in turn requires DKMS-encrypted
// key material and a shared key-archival secret - not feasible without
// first convincing the CA you are a holder of a Backup Operators token.
// The returned *pki.Certificate has Key == nil; callers that need the
// full key-pair should fall back to Certipy or, on the CA host itself,
// certutil -backupkey.
func (c *rpcClient) Backup() (*pki.Certificate, error) {
	if c == nil {
		return nil, errors.New("ca: Backup: nil client")
	}
	ctx, cancel := c.callCtx()
	defer cancel()

	resp, err := c.d2().GetCAProperty(ctx, &icertadmind2.GetCAPropertyRequest{
		This:         c.orpcThis(),
		Authority:    c.authorityName,
		PropertyID:   crPropCASigCert,
		PropertyType: 0x00000003, // PROPTYPE_BINARY
	})
	if err != nil {
		return nil, fmt.Errorf("ca: Backup (GetCAProperty CASIGCERT): %w", err)
	}
	if resp.PropertyValue == nil || len(resp.PropertyValue.Buffer) == 0 {
		return nil, errors.New("ca: Backup: CA returned empty CERTTRANSBLOB")
	}
	cert, err := x509.ParseCertificate(resp.PropertyValue.Buffer)
	if err != nil {
		return nil, fmt.Errorf("ca: Backup: parse CA cert: %w", err)
	}
	return &pki.Certificate{Cert: cert}, nil
}

// IssueRequest approves a pending request by its RequestID via
// MS-CSRA ICertAdminD::ResubmitRequest (opnum 7). Returns nil on success.
// A non-zero Return code is surfaced verbatim so the caller can map it
// against [MS-WCCE] disposition values.
func (c *rpcClient) IssueRequest(id uint32) error {
	if c == nil {
		return errors.New("ca: IssueRequest: nil client")
	}
	if id == 0 {
		return errors.New("ca: IssueRequest: request ID must be non-zero")
	}
	ctx, cancel := c.callCtx()
	defer cancel()

	resp, err := c.d().ResubmitRequest(ctx, &icertadmind.ResubmitRequestRequest{
		This:      c.orpcThis(),
		Authority: c.authorityName,
		RequestID: id,
	})
	if err != nil {
		return fmt.Errorf("ca: IssueRequest %d: %w", id, err)
	}
	if resp.Return != 0 {
		return fmt.Errorf("ca: IssueRequest %d returned disposition 0x%08x",
			id, uint32(resp.Return))
	}
	return nil
}

// DenyRequest denies a pending request via MS-CSRA
// ICertAdminD::DenyRequest (opnum 6).
func (c *rpcClient) DenyRequest(id uint32) error {
	if c == nil {
		return errors.New("ca: DenyRequest: nil client")
	}
	if id == 0 {
		return errors.New("ca: DenyRequest: request ID must be non-zero")
	}
	ctx, cancel := c.callCtx()
	defer cancel()

	resp, err := c.d().DenyRequest(ctx, &icertadmind.DenyRequestRequest{
		This:      c.orpcThis(),
		Authority: c.authorityName,
		RequestID: id,
	})
	if err != nil {
		return fmt.Errorf("ca: DenyRequest %d: %w", id, err)
	}
	if resp.Return != 0 {
		return fmt.Errorf("ca: DenyRequest %d returned hresult 0x%08x",
			id, uint32(resp.Return))
	}
	return nil
}

// AddOfficer grants the Certificate-Manager role to the given SID by
// round-tripping the officer-rights security descriptor: fetch current SD
// via GetOfficerRights, append an ACCESS_ALLOWED_ACE for the SID with
// ACCESS_MASK = 2 (Manage Certificates, per MS-CSRA §2.2.1.11.1), and
// push back via SetOfficerRights with fEnable=1.
//
// Idempotency: if an allow-ACE for the same SID already exists, the SD
// is sent back unchanged (still toggling the enable flag on).
func (c *rpcClient) AddOfficer(sid string) error {
	return c.mutateOfficer(sid, true /*add*/)
}

// RemoveOfficer revokes the Certificate-Manager role from the given SID.
// If the SID has no ACE in the current officer SD, RemoveOfficer returns
// a "SID not present" error so callers can distinguish it from a network
// failure.
func (c *rpcClient) RemoveOfficer(sid string) error {
	return c.mutateOfficer(sid, false /*remove*/)
}

// mutateOfficer is the shared Get/modify/Set body for AddOfficer and
// RemoveOfficer. Keeping them in one function guarantees the DACL layout
// we emit is symmetric across the two operations.
func (c *rpcClient) mutateOfficer(sidStr string, add bool) error {
	if c == nil {
		return errors.New("ca: mutateOfficer: nil client")
	}
	if !strings.HasPrefix(sidStr, "S-") {
		return fmt.Errorf("ca: mutateOfficer: %q is not a SID string", sidStr)
	}
	sidBytes, err := encodeSID(sidStr)
	if err != nil {
		return fmt.Errorf("ca: mutateOfficer: encode SID: %w", err)
	}

	ctx, cancel := c.callCtx()
	defer cancel()

	getResp, err := c.d2().GetOfficerRights(ctx, &icertadmind2.GetOfficerRightsRequest{
		This:      c.orpcThis(),
		Authority: c.authorityName,
	})
	if err != nil {
		return fmt.Errorf("ca: GetOfficerRights: %w", err)
	}
	if getResp.Return != 0 {
		return fmt.Errorf("ca: GetOfficerRights returned hresult 0x%08x",
			uint32(getResp.Return))
	}

	var currentSD []byte
	if getResp.SecurityDescriptor != nil && getResp.SecurityDescriptor.Buffer != nil {
		currentSD = getResp.SecurityDescriptor.Buffer
	}
	if len(currentSD) == 0 {
		// No existing SD: synthesize a minimal self-relative one with an
		// empty DACL so we can append the new ACE.
		currentSD = emptySelfRelativeSD()
	}

	// manageCertsMask is the ACCESS_MASK the AD CS UI maps to
	// "Manage Certificates" (officer) rights. MS-CSRA §3.1.1.7 bit 1.
	const manageCertsMask uint32 = 0x00000002

	updated, err := editOfficerDACL(currentSD, sidBytes, manageCertsMask, add)
	if err != nil {
		return fmt.Errorf("ca: edit officer DACL: %w", err)
	}

	setResp, err := c.d2().SetOfficerRights(ctx, &icertadmind2.SetOfficerRightsRequest{
		This:      c.orpcThis(),
		Authority: c.authorityName,
		Enable:    true,
		SecurityDescriptor: &csra.CertTransportBlob{
			Length: uint32(len(updated)),
			Buffer: updated,
		},
	})
	if err != nil {
		return fmt.Errorf("ca: SetOfficerRights: %w", err)
	}
	if setResp.Return != 0 {
		return fmt.Errorf("ca: SetOfficerRights returned hresult 0x%08x",
			uint32(setResp.Return))
	}
	return nil
}

// editOfficerDACL parses a self-relative SECURITY_DESCRIPTOR
// (MS-DTYP §2.4.6), then adds-or-removes an ACCESS_ALLOWED_ACE
// (MS-DTYP §2.4.4.2) for the given SID / mask, and returns the
// re-serialized SD. It is purposely minimal: the CA copies ownership
// and SACL fields straight through when echoing the descriptor back
// to GetOfficerRights.
func editOfficerDACL(sd, sidBin []byte, mask uint32, add bool) ([]byte, error) {
	if len(sd) < 20 {
		return nil, fmt.Errorf("sd too short (%d bytes)", len(sd))
	}
	// Offsets in the self-relative header.
	daclOff := binary.LittleEndian.Uint32(sd[16:20])

	var pre, dacl, post []byte
	if daclOff == 0 {
		// No DACL: we'll construct a fresh one with a single ACE, then
		// splice it onto the end of the SD and patch the offset.
		pre = append([]byte{}, sd...)
		dacl = buildEmptyDACL()
		post = nil
	} else {
		if int(daclOff) >= len(sd) {
			return nil, fmt.Errorf("dacl offset out of range")
		}
		// An ACL header is 8 bytes: Revision, Sbz1, AclSize (LE uint16),
		// AceCount (LE uint16), Sbz2.
		if int(daclOff)+8 > len(sd) {
			return nil, fmt.Errorf("dacl header out of range")
		}
		aclSize := binary.LittleEndian.Uint16(sd[daclOff+2 : daclOff+4])
		if int(daclOff)+int(aclSize) > len(sd) {
			return nil, fmt.Errorf("dacl body out of range")
		}
		pre = append([]byte{}, sd[:daclOff]...)
		dacl = append([]byte{}, sd[daclOff:int(daclOff)+int(aclSize)]...)
		post = append([]byte{}, sd[int(daclOff)+int(aclSize):]...)
	}

	if add {
		var err error
		dacl, err = upsertAllowACE(dacl, sidBin, mask)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		var removed bool
		dacl, removed, err = removeAllowACE(dacl, sidBin, mask)
		if err != nil {
			return nil, err
		}
		if !removed {
			return nil, errors.New("SID not present in officer DACL")
		}
	}

	// Reassemble: pre || dacl || post. Patch DaclOffset to len(pre)
	// because we placed the DACL immediately after the header / owner
	// / group / SACL blocks - which is exactly where it lived before.
	newSD := make([]byte, 0, len(pre)+len(dacl)+len(post))
	newSD = append(newSD, pre...)
	newSD = append(newSD, dacl...)
	newSD = append(newSD, post...)

	if daclOff == 0 {
		// Newly introduced DACL sits at offset len(pre).
		binary.LittleEndian.PutUint32(newSD[16:20], uint32(len(pre)))
		// Toggle Control.DP (DACL Present) = 0x0004.
		ctrl := binary.LittleEndian.Uint16(newSD[2:4])
		ctrl |= 0x0004
		binary.LittleEndian.PutUint16(newSD[2:4], ctrl)
	}

	return newSD, nil
}

// buildEmptyDACL returns a zero-ACE ACL ready to have ACEs appended.
// Revision 2 = standard. AclSize counts itself + all ACEs.
func buildEmptyDACL() []byte {
	b := make([]byte, 8)
	b[0] = 2                                 // AclRevision
	binary.LittleEndian.PutUint16(b[2:4], 8) // AclSize: just the header.
	// AceCount (b[4:6]) and Sbz2 (b[6:8]) default to zero.
	return b
}

// upsertAllowACE appends an ACCESS_ALLOWED_ACE (or replaces an existing
// one matching the same SID) in an ACL buffer. Returns the new ACL.
func upsertAllowACE(acl, sidBin []byte, mask uint32) ([]byte, error) {
	if len(acl) < 8 {
		return nil, errors.New("acl header truncated")
	}
	aceCount := binary.LittleEndian.Uint16(acl[4:6])

	// Walk the ACE list; if we find an allow-ACE with the same SID,
	// overwrite its mask and return.
	off := 8
	for i := 0; i < int(aceCount); i++ {
		if off+4 > len(acl) {
			return nil, errors.New("ace header truncated")
		}
		aceType := acl[off]
		aceSize := int(binary.LittleEndian.Uint16(acl[off+2 : off+4]))
		if aceSize < 8 || off+aceSize > len(acl) {
			return nil, errors.New("ace size invalid")
		}
		if aceType == 0x00 /* ACCESS_ALLOWED_ACE_TYPE */ {
			body := acl[off+4 : off+aceSize]
			if len(body) >= 4+len(sidBin) && sidEqual(body[4:4+len(sidBin)], sidBin) {
				binary.LittleEndian.PutUint32(acl[off+4:off+8], mask)
				return acl, nil
			}
		}
		off += aceSize
	}

	// Append a fresh ACCESS_ALLOWED_ACE:
	//   AceType(1)=0 AceFlags(1)=0 AceSize(2) AccessMask(4) Sid(variable)
	aceSize := 8 + len(sidBin)
	if aceSize > 0xffff {
		return nil, errors.New("ace too large")
	}
	ace := make([]byte, aceSize)
	ace[0] = 0x00 // ACCESS_ALLOWED_ACE_TYPE
	ace[1] = 0x00 // AceFlags
	binary.LittleEndian.PutUint16(ace[2:4], uint16(aceSize))
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	copy(ace[8:], sidBin)

	acl = append(acl, ace...)

	newSize := int(binary.LittleEndian.Uint16(acl[2:4])) + aceSize
	if newSize > 0xffff {
		return nil, errors.New("acl too large after insert")
	}
	binary.LittleEndian.PutUint16(acl[2:4], uint16(newSize))
	binary.LittleEndian.PutUint16(acl[4:6], aceCount+1)
	return acl, nil
}

// removeAllowACE strips the first ACCESS_ALLOWED_ACE whose SID matches
// sidBin. The mask argument is accepted for symmetry with upsert but
// not checked - AD CS treats officer ACEs as SID-keyed, and permissions
// are revoked wholesale.
func removeAllowACE(acl, sidBin []byte, _ uint32) ([]byte, bool, error) {
	if len(acl) < 8 {
		return nil, false, errors.New("acl header truncated")
	}
	aceCount := binary.LittleEndian.Uint16(acl[4:6])
	off := 8
	for i := 0; i < int(aceCount); i++ {
		if off+4 > len(acl) {
			return nil, false, errors.New("ace header truncated")
		}
		aceType := acl[off]
		aceSize := int(binary.LittleEndian.Uint16(acl[off+2 : off+4]))
		if aceSize < 8 || off+aceSize > len(acl) {
			return nil, false, errors.New("ace size invalid")
		}
		if aceType == 0x00 /* ACCESS_ALLOWED_ACE_TYPE */ {
			body := acl[off+4 : off+aceSize]
			if len(body) >= 4+len(sidBin) && sidEqual(body[4:4+len(sidBin)], sidBin) {
				// Splice out [off : off+aceSize].
				newAcl := make([]byte, 0, len(acl)-aceSize)
				newAcl = append(newAcl, acl[:off]...)
				newAcl = append(newAcl, acl[off+aceSize:]...)
				newSize := int(binary.LittleEndian.Uint16(newAcl[2:4])) - aceSize
				binary.LittleEndian.PutUint16(newAcl[2:4], uint16(newSize))
				binary.LittleEndian.PutUint16(newAcl[4:6], aceCount-1)
				return newAcl, true, nil
			}
		}
		off += aceSize
	}
	return acl, false, nil
}

// emptySelfRelativeSD returns a self-relative SECURITY_DESCRIPTOR with
// neither owner, group, SACL, nor DACL. Used as a fallback when a CA
// answers GetOfficerRights with an empty blob (first-run state on some
// fresh AD CS installs).
func emptySelfRelativeSD() []byte {
	sd := make([]byte, 20)
	sd[0] = 1 // Revision
	// Sbz1 = 0; Control = SELF_RELATIVE (0x8000).
	binary.LittleEndian.PutUint16(sd[2:4], 0x8000)
	// OffsetOwner, OffsetGroup, OffsetSacl, OffsetDacl = 0 (absent).
	return sd
}

// sidEqual is a constant-time-unsafe SID comparison - fine here because
// SIDs are public values.
func sidEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// encodeSID converts "S-1-5-21-..." into the MS-DTYP §2.4.2.2 binary
// layout: Revision(1) SubAuthCount(1) IdentifierAuthority(6 BE) SubAuth[](4 LE each).
func encodeSID(s string) ([]byte, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return nil, fmt.Errorf("invalid SID %q", s)
	}
	rev, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid SID revision: %w", err)
	}
	authority, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("invalid SID authority: %w", err)
	}
	subs := make([]uint32, 0, len(parts)-3)
	for _, p := range parts[3:] {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid SID sub-authority %q: %w", p, err)
		}
		subs = append(subs, uint32(v))
	}
	if len(subs) > 15 {
		return nil, fmt.Errorf("SID has %d sub-authorities (max 15)", len(subs))
	}
	out := make([]byte, 8+4*len(subs))
	out[0] = uint8(rev)
	out[1] = uint8(len(subs))
	// IdentifierAuthority: 48 bits, big-endian.
	out[2] = byte(authority >> 40)
	out[3] = byte(authority >> 32)
	out[4] = byte(authority >> 24)
	out[5] = byte(authority >> 16)
	out[6] = byte(authority >> 8)
	out[7] = byte(authority)
	for i, sa := range subs {
		binary.LittleEndian.PutUint32(out[8+4*i:12+4*i], sa)
	}
	return out, nil
}
