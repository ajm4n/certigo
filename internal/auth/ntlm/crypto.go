package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"strings"

	//lint:ignore SA1019 MD4 is required for the NT hash per MS-NLMP; no replacement exists.
	"golang.org/x/crypto/md4"
)

// NTOWFv2 computes the NTLMv2 response key (MS-NLMP §3.3.2):
//
//	HMAC_MD5(MD4(UNICODE(password)), UNICODE(ToUpper(user) || domain))
//
// Username is uppercased (ASCII); domain is NOT uppercased.
func NTOWFv2(password, username, domain string) []byte {
	nt := md4.New()
	_, _ = nt.Write(utf16LE(password))
	ntHash := nt.Sum(nil)

	h := hmac.New(md5.New, ntHash)
	_, _ = h.Write(utf16LE(strings.ToUpper(username) + domain))
	return h.Sum(nil)
}

// NTLMv2Response returns the full NtChallengeResponse per MS-NLMP §3.3.2.
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

// LMv2Response per MS-NLMP §3.3.2.
func LMv2Response(responseKey, serverChallenge, clientChallenge []byte) []byte {
	h := hmac.New(md5.New, responseKey)
	_, _ = h.Write(serverChallenge)
	_, _ = h.Write(clientChallenge)
	out := h.Sum(nil)
	return append(out, clientChallenge...)
}

// SessionBaseKey per MS-NLMP §3.4.5.1 for NTLMv2.
func SessionBaseKey(responseKey, ntProofStr []byte) []byte {
	h := hmac.New(md5.New, responseKey)
	_, _ = h.Write(ntProofStr)
	return h.Sum(nil)
}

// buildTemp assembles the 'temp' structure from MS-NLMP §3.3.2.
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
