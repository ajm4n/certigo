// Package req submits certificate requests to AD CS. Supported methods:
// HTTP web enrollment (/certsrv/) is implemented end-to-end with Basic auth
// over TLS; NTLM/Kerberos over HTTP and ICPR RPC are pending.
package req

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
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
	Username    string // HTTP Basic user (domain\user or user@realm)
	Password    string // plaintext
	TLSInsecure bool
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
// Uses HTTPS with InsecureSkipVerify when TLSInsecure=true. Auth: HTTP Basic
// with the provided username+password. NTLM/Kerberos-over-HTTP is TODO.
func postCertSrv(opts Options, csrDER []byte) (*x509.Certificate, error) {
	base := opts.CA
	if !strings.HasPrefix(base, "http") {
		base = "https://" + base
	}
	base = strings.TrimSuffix(base, "/")

	// If the host portion parses as an IP, auto-enable InsecureSkipVerify
	// because the CA's cert will be for the DNS name, not the IP.
	if u, err := url.Parse(base); err == nil {
		if ip := net.ParseIP(u.Hostname()); ip != nil && !opts.TLSInsecure {
			progf("[!]", "host %s is an IP; auto-enabling --insecure-tls", ip)
			opts.TLSInsecure = true
		}
	}

	progf("[*]", "connecting to %s (timeout %s)", base, Timeout)
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: opts.TLSInsecure}, // #nosec G402 - opt-in via --insecure-tls
		DialContext:       (&net.Dialer{Timeout: Timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: Timeout,
		ResponseHeaderTimeout: Timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   Timeout * 2,
	}

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
	if opts.Username != "" {
		postReq.SetBasicAuth(opts.Username, opts.Password)
	}

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
	if opts.Username != "" {
		getReq.SetBasicAuth(opts.Username, opts.Password)
	}
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
