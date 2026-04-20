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
}

func (m *NegotiateMessage) Encode() []byte {
	const headerLen = 32
	var buf bytes.Buffer
	buf.Write(Signature[:])
	_ = binary.Write(&buf, binary.LittleEndian, MessageTypeNegotiate)
	_ = binary.Write(&buf, binary.LittleEndian, m.NegotiateFlags)

	domOffset := uint32(headerLen)
	wsOffset := domOffset + uint32(len(m.DomainName))

	buf.Write(securityBuffer{length: uint16(len(m.DomainName)), allocated: uint16(len(m.DomainName)), offset: domOffset}.encode())
	buf.Write(securityBuffer{length: uint16(len(m.Workstation)), allocated: uint16(len(m.Workstation)), offset: wsOffset}.encode())

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
