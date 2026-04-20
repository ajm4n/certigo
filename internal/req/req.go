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
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ajm4n/certigo/internal/pki"
)

type Method string

const (
	MethodWeb Method = "web"
	MethodRPC Method = "rpc"
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
// the issued *pki.Certificate.
func Submit(opts Options) (*pki.Certificate, error) {
	switch opts.Method {
	case MethodWeb, "":
		return submitWeb(opts)
	case MethodRPC:
		return submitRPC(opts)
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

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.TLSInsecure}, // #nosec G402 — opt-in via --insecure-tls
		},
	}

	// Step 1 — POST /certsrv/certfnsh.asp with the CSR.
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

	resp, err := client.Do(postReq)
	if err != nil {
		return nil, fmt.Errorf("req: certfnsh POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("req: certfnsh status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	m := reqIDRegexp.FindStringSubmatch(string(body))
	if m == nil {
		return nil, fmt.Errorf("req: ReqID not found in certfnsh response (auth failure or pending approval): %s", truncate(string(body), 200))
	}
	reqID := m[1]

	// Step 2 — GET /certsrv/certnew.cer?ReqID=<id>&Enc=b64 for the PEM cert.
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
