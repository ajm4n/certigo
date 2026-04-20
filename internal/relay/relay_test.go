package relay

import (
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf16"
)

// TestHealth starts the relay mux against a dummy target and verifies
// /health returns 200 with the expected JSON body.
func TestHealth(t *testing.T) {
	_, mux, err := newServer(Options{
		TargetURL: "http://127.0.0.1:9/certsrv/",
		OutDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("unexpected body: %s", body)
	}
}

// TestNoAuth_Returns401 confirms that a bare GET with no Authorization
// header triggers a 401 + WWW-Authenticate: Negotiate, NTLM.
func TestNoAuth_Returns401(t *testing.T) {
	_, mux, err := newServer(Options{
		TargetURL: "http://127.0.0.1:9/certsrv/",
		OutDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	wa := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wa, "NTLM") || !strings.Contains(wa, "Negotiate") {
		t.Errorf("WWW-Authenticate = %q, want substrings Negotiate and NTLM", wa)
	}
}

// TestNTLMNegotiate_ForwardsToTarget wires up a fake CA server that
// expects our relay to forward a NEGOTIATE token and then reflects back
// a synthetic NTLM CHALLENGE. The relay must pass the challenge through
// to its downstream client unmodified.
func TestNTLMNegotiate_ForwardsToTarget(t *testing.T) {
	const wantChallengeB64 = "TlRMTVNTUAACAAAAAAAAADAAAAABAoEAASNFZ4mrze8AAAAAAAAAAAAAAAAwAAAA"

	var targetHits atomic.Int32
	var sawNegotiate atomic.Bool
	var sawAuthenticate atomic.Bool

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw := strings.TrimPrefix(auth, "NTLM ")
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(b) < 12 {
			http.Error(w, "bad token", http.StatusBadRequest)
			return
		}
		switch binary.LittleEndian.Uint32(b[8:12]) {
		case 1:
			sawNegotiate.Store(true)
			w.Header().Set("WWW-Authenticate", "NTLM "+wantChallengeB64)
			w.WriteHeader(http.StatusUnauthorized)
		case 3:
			sawAuthenticate.Store(true)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		default:
			http.Error(w, "unexpected msg type", http.StatusBadRequest)
		}
	}))
	defer target.Close()

	_, mux, err := newServer(Options{
		TargetURL: target.URL + "/certsrv/",
		OutDir:    t.TempDir(),
		Insecure:  true,
	})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	relaySrv := httptest.NewServer(mux)
	defer relaySrv.Close()

	// Victim sends a hand-rolled NEGOTIATE blob (signature + type=1 + flags=0).
	neg := make([]byte, 32)
	copy(neg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(neg[8:12], 1)
	negB64 := base64.StdEncoding.EncodeToString(neg)

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, relaySrv.URL+"/", nil)
	req.Header.Set("Authorization", "NTLM "+negB64)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("relay GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("relay status = %d, want 401", resp.StatusCode)
	}
	wa := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(wa, "NTLM ") {
		t.Fatalf("WWW-Authenticate = %q, want NTLM prefix", wa)
	}
	got := strings.TrimPrefix(wa, "NTLM ")
	if got != wantChallengeB64 {
		t.Errorf("relay returned challenge %q, want %q", got, wantChallengeB64)
	}

	if !sawNegotiate.Load() {
		t.Error("target never saw NEGOTIATE from relay")
	}
	if sawAuthenticate.Load() {
		t.Error("target unexpectedly saw AUTHENTICATE")
	}
	if n := targetHits.Load(); n == 0 {
		t.Error("target received zero requests")
	}
}

// TestExtractUserName builds a minimal synthetic AUTHENTICATE_MESSAGE with
// only the UserNameFields descriptor populated and confirms extraction.
func TestExtractUserName(t *testing.T) {
	const user = "alice"
	payload := utf16LE(user)

	// Fixed header up to and including UserNameFields is 44 bytes:
	// sig(8) type(4) lmCR(8) ntCR(8) domain(8) user(8).
	header := make([]byte, 44)
	copy(header[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(header[8:12], 3)

	userOff := uint32(len(header))
	binary.LittleEndian.PutUint16(header[36:38], uint16(len(payload))) // len
	binary.LittleEndian.PutUint16(header[38:40], uint16(len(payload))) // allocated
	binary.LittleEndian.PutUint32(header[40:44], userOff)

	msg := append(header, payload...)
	got := extractUserName(msg)
	if got != user {
		t.Errorf("extractUserName = %q, want %q", got, user)
	}
}

func utf16LE(s string) []byte {
	codes := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(codes))
	for i, c := range codes {
		binary.LittleEndian.PutUint16(b[2*i:2*i+2], c)
	}
	return b
}
