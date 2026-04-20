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
func utf16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(runes))
	for i, r := range runes {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}
