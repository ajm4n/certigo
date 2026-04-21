package req

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"
	icertpassage "github.com/oiweiwei/go-msrpc/msrpc/icpr/icertpassage/v0"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	"github.com/ajm4n/certigo/internal/pki"
)

// submitRPC dispatches a CSR to the CA via MS-ICPR (ICertPassage) over DCE/RPC.
//
// The RPC binding uses SPNEGO preferring Kerberos, falling back to NTLM. The
// CA's ICPR endpoint is dynamic and discovered via the endpoint mapper (epm)
// at port 135 - no explicit endpoint option is passed.
func submitRPC(opts Options) (*pki.Certificate, error) {
	if opts.CA == "" {
		return nil, fmt.Errorf("req: --ca required")
	}
	if opts.CAName == "" {
		return nil, fmt.Errorf("req: --ca-name required")
	}
	if opts.Username == "" {
		return nil, fmt.Errorf("req: --username required for RPC")
	}

	keySize := opts.KeySize
	if keySize == 0 {
		keySize = 2048
	}

	// Build CSR.
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

	// Credentials: password only (NTLM hashes + Kerberos are out of scope for this
	// first integration; extend once auth.Credentials is plumbed through).
	creds := credential.NewFromPassword(opts.Username, opts.Password)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ctx = gssapi.NewSecurityContext(ctx)

	conn, err := dcerpc.Dial(ctx, opts.CA,
		dcerpc.WithCredentials(creds),
		dcerpc.WithMechanism(ssp.SPNEGO),
		dcerpc.WithSign(),
	)
	if err != nil {
		return nil, fmt.Errorf("req: dcerpc dial %s: %w", opts.CA, err)
	}
	defer func() { _ = conn.Close(ctx) }()

	progf("[*]", "dcerpc dialed %s; binding ICertPassage", opts.CA)
	cli, err := icertpassage.NewCertPassageClient(ctx, conn)
	if err != nil {
		// Certipy's default path is MS-WCCE ICertRequest over DCOM, which
		// go-msrpc can only reach via IRemoteSCMActivator activation. Many
		// AD CS installs expose ICertPassage on SMB named-pipe only; some
		// only over DCOM. Give the operator an actionable hint.
		return nil, fmt.Errorf(
			"req: ICPR bind: %w\n  hint: target may not expose ICertPassage over TCP/EPM; "+
				"try --method web with --insecure-tls, or fall back to certipy req "+
				"(which defaults to DCOM ICertRequest)", err,
		)
	}

	attribString := fmt.Sprintf("CertificateTemplate:%s", opts.Template)
	attribBytes := encodeUTF16LE(attribString, true)

	reqPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	rpcReq := &icertpassage.CertServerRequestRequest{
		Flags:     0x00000000, // CR_IN_BASE64 | CR_IN_PKCS10 are selected via CSR byte prefix
		Authority: opts.CAName,
		Attributes: &wcce.CertTransportBlob{
			Length: uint32(len(attribBytes)),
			Buffer: attribBytes,
		},
		Request: &wcce.CertTransportBlob{
			Length: uint32(len(reqPEM)),
			Buffer: reqPEM,
		},
	}

	progf("[*]", "submitting CertServerRequest to %q (template %q)", opts.CAName, opts.Template)
	resp, err := cli.CertServerRequest(ctx, rpcReq)
	if err != nil {
		return nil, fmt.Errorf("req: CertServerRequest: %w", err)
	}
	progf("[+]", "CA disposition %d", resp.Disposition)
	if resp.Disposition != 3 /* CR_DISP_ISSUED */ {
		return nil, fmt.Errorf("req: CA returned disposition %d (want 3=issued)", resp.Disposition)
	}
	if resp.Cert == nil || len(resp.Cert.Buffer) == 0 {
		return nil, fmt.Errorf("req: empty cert payload in response")
	}
	cert, err := x509.ParseCertificate(resp.Cert.Buffer)
	if err != nil {
		return nil, fmt.Errorf("req: parse issued cert: %w", err)
	}
	return &pki.Certificate{Cert: cert, Key: key}, nil
}

// encodeUTF16LE returns s as UTF-16-LE bytes, optionally NUL-terminated.
func encodeUTF16LE(s string, nulTerminate bool) []byte {
	pts := utf16.Encode([]rune(s))
	if nulTerminate {
		pts = append(pts, 0)
	}
	out := make([]byte, 2*len(pts))
	for i, r := range pts {
		out[i*2] = byte(r)
		out[i*2+1] = byte(r >> 8)
	}
	return out
}
