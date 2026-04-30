// Package req submits certificate requests to AD CS. Supported methods:
// HTTP web enrollment (/certsrv/) is implemented end-to-end with Basic
// auth + Negotiate/NTLM (including pass-the-hash) and HTTP fallback
// when HTTPS is unavailable; ICPR RPC and DCOM are also supported.
package req

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/ajm4n/certigo/internal/pki"
)

// Debug causes req to dump HTTP request / response metadata to stderr
// when true. Toggled by the CLI --debug flag.
var Debug bool

// Timeout caps every HTTP round trip in submitWeb. Default is 30s.
var Timeout = 30 * time.Second

// progf writes a certipy-style [*] progress line to stderr.
func progf(tag, format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", tag, fmt.Sprintf(format, args...))
}

type Method string

const (
	MethodDCOM Method = "dcom"
	MethodRPC  Method = "rpc"
	MethodWeb  Method = "web"
)

// Options controls one certificate request.
type Options struct {
	Method      Method
	CA          string // hostname for web URL / RPC endpoint
	CAName      string // Enterprise CA common name
	Template    string
	Subject     string
	UPN         string
	DNSNames    []string
	KeySize     int
	Username    string // HTTP user (sAMAccountName, or domain\user, or user@realm)
	Password    string // plaintext password (mutually exclusive with NTHash)
	NTHash      []byte // 16-byte NT hash for pass-the-hash (web flow: NTLM only)
	Domain      string // NetBIOS or DNS domain; auto-prefixed onto Username for NTLM
	TLSInsecure bool
	DCHost      string // optional; used as DNS resolver fallback for CA hostnames
}

// Submit generates a key + CSR, submits via the chosen method, and returns
// the issued *pki.Certificate. The default method is DCOM (MS-WCCE
// ICertRequestD2::Request2) which matches Certipy's default. --method rpc
// uses ICertPassage (simpler MSRPC alternative) and --method web uses
// the /certsrv/ HTTP flow.
func Submit(opts Options) (*pki.Certificate, error) {
	switch opts.Method {
	case MethodDCOM, "":
		return submitDCOM(opts)
	case MethodRPC:
		return submitRPC(opts)
	case MethodWeb:
		return submitWeb(opts)
	default:
		return nil, fmt.Errorf("req: unknown method %q", opts.Method)
	}
}

func submitWeb(opts Options) (*pki.Certificate, error) {
	if opts.CA == "" {
		return nil, fmt.Errorf("req: --ca required")
	}
	if opts.Template == "" {
		opts.Template = "User"
	}
	keySize := opts.KeySize
	if keySize == 0 {
		keySize = 2048
	}

	key, err := pki.GenerateRSAKey(keySize)
	if err != nil {
		return nil, err
	}

	subject := strings.TrimSpace(opts.Subject)
	if subject == "" && opts.UPN != "" {
		subject = "CN=" + opts.UPN
	}

	csrDER, err := buildCSR(key, subject, opts.UPN, opts.DNSNames)
	if err != nil {
		return nil, fmt.Errorf("req: CSR: %w", err)
	}

	cert, err := postCertSrv(opts, csrDER)
	if err != nil {
		return nil, err
	}
	return &pki.Certificate{Cert: cert, Key: key}, nil
}

func buildCSR(key *rsa.PrivateKey, subject, upn string, dns []string) ([]byte, error) {
	name := pkix.Name{}
	if subject != "" {
		name.CommonName = strings.TrimPrefix(subject, "CN=")
	}
	req := pki.NewCSRRequest{Subject: name, DNSNames: dns}
	if upn != "" {
		req.UPNs = []string{upn}
	}
	return pki.BuildCSR(key, req)
}

var reqIDRegexp = regexp.MustCompile(`ReqID=(\d+)`)

// postCertSrv submits to /certsrv/certfnsh.asp and fetches the issued cert.
//
// Transport selection:
//   - If opts.CA carries an explicit scheme (http:// or https://) it's used as
//     given; otherwise we try HTTPS first and on connection refused / dial
//     failure fall back to HTTP. /certsrv/ is fine over HTTP in lab targets
//     where IIS doesn't bind 443 (e.g. GOAD).
//
// Auth selection:
//   - The HTTP transport is always wrapped with go-ntlmssp's Negotiator. When
//     the server responds 401 Negotiate/NTLM, the wrapper handles the
//     challenge-response. When the server speaks Basic, the wrapper passes
//     credentials through (AllowBasicAuth). Both modes coexist.
//   - With opts.NTHash != nil and Password == "", we route through a custom
//     NTLM round-tripper that calls go-ntlmssp's NewAuthenticateMessage with
//     PasswordHashed: true (PtH).
//   - opts.Domain is auto-prefixed onto the username (DOMAIN\user) when the
//     username is bare — required for NTLM domain accounts.
func postCertSrv(opts Options, csrDER []byte) (*x509.Certificate, error) {
	base, allowFallback := normalizeBase(opts.CA)

	// If the host portion parses as an IP, auto-enable InsecureSkipVerify
	// because the CA's cert will be for the DNS name, not the IP.
	if u, err := url.Parse(base); err == nil {
		if ip := net.ParseIP(u.Hostname()); ip != nil && !opts.TLSInsecure {
			progf("[!]", "host %s is an IP; auto-enabling --insecure-tls", ip)
			opts.TLSInsecure = true
		}
	}

	cert, err := tryCertSrv(base, opts, csrDER)
	if err == nil {
		return cert, nil
	}
	// HTTP fallback: only when caller passed a bare hostname (no explicit
	// scheme) AND the failure looks like a network/TLS error rather than an
	// HTTP-level rejection.
	if allowFallback && isDialOrTLSFailure(err) && strings.HasPrefix(base, "https://") {
		alt := "http://" + strings.TrimPrefix(base, "https://")
		progf("[!]", "HTTPS to %s failed (%v); retrying over HTTP", base, err)
		return tryCertSrv(alt, opts, csrDER)
	}
	return nil, err
}

// normalizeBase strips any trailing slash and returns (canonical base URL,
// allowFallback). allowFallback is true only when the operator did not give
// an explicit scheme — then we may try HTTPS first and HTTP second.
func normalizeBase(ca string) (string, bool) {
	ca = strings.TrimSuffix(ca, "/")
	switch {
	case strings.HasPrefix(ca, "http://"), strings.HasPrefix(ca, "https://"):
		return ca, false
	default:
		return "https://" + ca, true
	}
}

// isDialOrTLSFailure returns true when err looks like a transport-layer
// failure where retrying on a different scheme/port could succeed.
func isDialOrTLSFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"),
		strings.Contains(s, "no route to host"),
		strings.Contains(s, "i/o timeout"),
		strings.Contains(s, "tls:"),
		strings.Contains(s, "EOF"),
		strings.Contains(s, "HTTP response to HTTPS client"),
		strings.Contains(s, "server gave HTTP response to HTTPS client"):
		return true
	}
	return false
}

func tryCertSrv(base string, opts Options, csrDER []byte) (*x509.Certificate, error) {
	progf("[*]", "connecting to %s (timeout %s)", base, Timeout)
	client := buildHTTPClient(opts)

	// Step 1 - POST /certsrv/certfnsh.asp with the CSR.
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	form := url.Values{}
	form.Set("Mode", "newreq")
	form.Set("CertRequest", string(csrPEM))
	form.Set("CertAttrib", fmt.Sprintf("CertificateTemplate:%s\r\n", opts.Template))
	form.Set("TargetStoreFlags", "0")
	form.Set("SaveCert", "yes")

	postURL := base + "/certsrv/certfnsh.asp"
	postReq, err := http.NewRequest("POST", postURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("User-Agent", "certigo/0.3")
	applyAuth(postReq, opts)

	progf("[*]", "POST %s", postURL)
	resp, err := client.Do(postReq)
	if err != nil {
		return nil, fmt.Errorf("req: certfnsh POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	progf("[+]", "HTTP %d (%d bytes)", resp.StatusCode, len(body))
	if Debug {
		progf("[debug]", "response headers: %v", resp.Header)
		progf("[debug]", "response body: %s", truncate(string(body), 400))
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("req: certfnsh 401 (auth failed; check creds / NTLM vs Basic): %s",
			truncate(strings.Join(resp.Header.Values("WWW-Authenticate"), ", "), 200))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("req: certfnsh status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	m := reqIDRegexp.FindStringSubmatch(string(body))
	if m == nil {
		return nil, fmt.Errorf("req: ReqID not found in certfnsh response (auth failure or pending approval): %s", truncate(string(body), 200))
	}
	reqID := m[1]

	// Step 2 - GET /certsrv/certnew.cer?ReqID=<id>&Enc=b64 for the PEM cert.
	getURL := fmt.Sprintf("%s/certsrv/certnew.cer?ReqID=%s&Enc=b64", base, reqID)
	getReq, _ := http.NewRequest("GET", getURL, nil)
	getReq.Header.Set("User-Agent", "certigo/0.3")
	applyAuth(getReq, opts)
	getResp, err := client.Do(getReq)
	if err != nil {
		return nil, fmt.Errorf("req: certnew GET: %w", err)
	}
	defer func() { _ = getResp.Body.Close() }()
	certBody, _ := io.ReadAll(getResp.Body)

	// The response is either PEM directly or base64-wrapped. Try PEM first.
	block, _ := pem.Decode(certBody)
	var der []byte
	if block != nil && block.Type == "CERTIFICATE" {
		der = block.Bytes
	} else {
		// Some CA configs return raw base64.
		cleaned := bytes.TrimSpace(certBody)
		if d, err := base64.StdEncoding.DecodeString(string(cleaned)); err == nil {
			der = d
		} else {
			return nil, fmt.Errorf("req: cannot parse certnew response (neither PEM nor base64)")
		}
	}
	return x509.ParseCertificate(der)
}

// buildHTTPClient returns an *http.Client whose RoundTripper handles both
// Basic and NTLM/Negotiate transparently and supports pass-the-hash via the
// NTHash field.
func buildHTTPClient(opts Options) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: opts.TLSInsecure}, // #nosec G402 - opt-in via --insecure-tls
		DialContext:           (&net.Dialer{Timeout: Timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   Timeout,
		ResponseHeaderTimeout: Timeout,
	}
	rt := wrapNTLMTransport(transport, opts)
	return &http.Client{Transport: rt, Timeout: Timeout * 2}
}

// applyAuth attaches credentials to the request. For password mode we call
// SetBasicAuth so the Negotiator round-tripper can pick them up; for hash
// mode we stash the username via SetBasicAuth (with sentinel password) so
// the PtH wrapper recognizes the request.
func applyAuth(req *http.Request, opts Options) {
	user := formatNTLMUser(opts.Username, opts.Domain)
	if user == "" {
		return
	}
	if len(opts.NTHash) > 0 {
		// Sentinel password: empty string. The PtH wrapper detects this
		// based on its own state (it carries the hash out-of-band).
		req.SetBasicAuth(user, "")
		return
	}
	req.SetBasicAuth(user, opts.Password)
}

// formatNTLMUser prefixes Domain onto Username unless Username already
// contains a delimiter (\ or @).
func formatNTLMUser(user, domain string) string {
	user = strings.TrimSpace(user)
	if user == "" {
		return ""
	}
	if domain == "" {
		return user
	}
	if strings.Contains(user, "\\") || strings.Contains(user, "@") {
		return user
	}
	return domain + "\\" + user
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
