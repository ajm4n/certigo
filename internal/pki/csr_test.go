package pki

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestBuildCSR_BasicDNS(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}

	der, err := BuildCSR(key, NewCSRRequest{
		Subject:  pkix.Name{CommonName: "basic.example.com"},
		DNSNames: []string{"basic.example.com", "alt.example.com"},
	})
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature check failed: %v", err)
	}
	if csr.Subject.CommonName != "basic.example.com" {
		t.Fatalf("Subject.CommonName = %q, want basic.example.com", csr.Subject.CommonName)
	}
	if _, ok := csr.PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("PublicKey type = %T, want *rsa.PublicKey", csr.PublicKey)
	}

	want := map[string]bool{"basic.example.com": false, "alt.example.com": false}
	for _, dns := range csr.DNSNames {
		if _, ok := want[dns]; ok {
			want[dns] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("DNS SAN %q missing from CSR", name)
		}
	}
}

func TestBuildCSR_WithUPN(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}

	const upn = "user@example.local"
	der, err := BuildCSR(key, NewCSRRequest{
		Subject:  pkix.Name{CommonName: "user"},
		DNSNames: []string{"user.example.local"},
		UPNs:     []string{upn},
	})
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature check failed: %v", err)
	}

	var sanExt *pkix.Extension
	for i := range csr.Extensions {
		if csr.Extensions[i].Id.Equal(oidExtensionSubjectAltName) {
			sanExt = &csr.Extensions[i]
			break
		}
	}
	if sanExt == nil {
		t.Fatal("CSR missing subjectAltName extension")
	}

	// The UPN OID bytes should appear inside the SAN extension value.
	upnOIDBytes, err := asn1.Marshal(oidUPN)
	if err != nil {
		t.Fatalf("marshal UPN OID: %v", err)
	}
	if !bytes.Contains(sanExt.Value, upnOIDBytes) {
		t.Fatalf("SAN extension missing UPN OID bytes %x", upnOIDBytes)
	}

	// The UPN string itself should also appear in the DER.
	if !bytes.Contains(sanExt.Value, []byte(upn)) {
		t.Fatalf("SAN extension missing UPN string %q", upn)
	}

	// Walk the SEQUENCE OF GeneralName and confirm we see the [0] otherName
	// entry with the UPN OID. stdlib's parser also exposes DNS names, but it
	// does not decode otherName, so we do it manually.
	var rawValues []asn1.RawValue
	if _, err := asn1.Unmarshal(sanExt.Value, &rawValues); err != nil {
		t.Fatalf("unmarshal SAN sequence: %v", err)
	}

	var sawOtherName bool
	var sawDNS bool
	for _, rv := range rawValues {
		if rv.Class != asn1.ClassContextSpecific {
			continue
		}
		switch rv.Tag {
		case 0:
			// otherName: SEQUENCE { OID, [0] EXPLICIT value }
			var other upnOtherName
			// Re-tag to a universal SEQUENCE so asn1 can parse it.
			seqBytes := append([]byte{}, rv.FullBytes...)
			seqBytes[0] = 0x30 // SEQUENCE, constructed
			if _, err := asn1.Unmarshal(seqBytes, &other); err != nil {
				t.Fatalf("unmarshal otherName: %v", err)
			}
			if !other.TypeID.Equal(oidUPN) {
				t.Fatalf("otherName OID = %v, want %v", other.TypeID, oidUPN)
			}
			if other.Value.UPN != upn {
				t.Fatalf("otherName value = %q, want %q", other.Value.UPN, upn)
			}
			sawOtherName = true
		case 2:
			if string(rv.Bytes) == "user.example.local" {
				sawDNS = true
			}
		}
	}
	if !sawOtherName {
		t.Fatal("no otherName entry found in SAN")
	}
	if !sawDNS {
		t.Fatal("DNS SAN entry missing when combined with UPN")
	}
}
