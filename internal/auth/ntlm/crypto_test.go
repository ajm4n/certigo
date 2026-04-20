package ntlm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// MS-NLMP §4.2.4.1.1 vector.
func TestNTOWFv2Vector(t *testing.T) {
	got := NTOWFv2("Password", "User", "Domain")
	want, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if !bytes.Equal(got, want) {
		t.Errorf("NTOWFv2 = %x, want %x", got, want)
	}
}

// MS-NLMP §4.2.4.1.2 — full NTLMv2 response.
func TestNTLMv2ResponseVector(t *testing.T) {
	responseKey, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	serverChal, _ := hex.DecodeString("0123456789abcdef")
	clientChal, _ := hex.DecodeString("aaaaaaaaaaaaaaaa")
	timestamp := make([]byte, 8)

	ti := &TargetInfo{}
	ti.Set(AvIDNbDomainName, utf16LE("Domain"))
	ti.Set(AvIDNbComputerName, utf16LE("Server"))

	ntResp := NTLMv2Response(responseKey, serverChal, clientChal, timestamp, ti.Encode())

	// Layout: NTProofStr(16) || RespVer+Z(6)+Time(8) || ClientChal(8)+Z(4) ||
	//         Domain av_pair(16) || Server av_pair(16) || EOL(4) || Z(4)
	want, _ := hex.DecodeString(
		"68cd0ab851e51c96aabc927bebef6a1c" +
			"01010000000000000000000000000000" +
			"aaaaaaaaaaaaaaaa00000000" +
			"02000c0044006f006d00610069006e00" +
			"01000c00530065007200760065007200" +
			"00000000" +
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
	want, _ := hex.DecodeString("86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa")
	if !bytes.Equal(got, want) {
		t.Errorf("LMv2Response = %x, want %x", got, want)
	}
}

// MS-NLMP §4.2.4.2 — SessionBaseKey.
func TestSessionBaseKeyVector(t *testing.T) {
	responseKey, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	ntProofStr, _ := hex.DecodeString("68cd0ab851e51c96aabc927bebef6a1c")
	got := SessionBaseKey(responseKey, ntProofStr)
	want, _ := hex.DecodeString("8de40ccadbc14a82f15cb0ad0de95ca3")
	if !bytes.Equal(got, want) {
		t.Errorf("SessionBaseKey = %x, want %x", got, want)
	}
}
