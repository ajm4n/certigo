package req

// DCOM MS-WCCE (ICertRequestD / ICertRequestD2) path for cert enrollment.
// This is the flow Certipy uses by default: activate the CertSrvRequest
// coclass via IActivation::RemoteActivation on port 135, dial the OXID
// endpoint advertised back, bind the ICertRequestD2 interface against
// the returned IPID, and call Request2 with our CSR.

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"

	uuid "github.com/oiweiwei/go-msrpc/midl/uuid"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"
	wcce_client "github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce/client"
	icertrequestd2 "github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce/icertrequestd2/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	"github.com/ajm4n/certigo/internal/pki"
)

// CertSrvRequestClassID is the DCOM coclass GUID for CertSrv's request
// object. MS-WCCE 1.9, also referenced by the Microsoft ADCS samples.
var CertSrvRequestClassID = uuid.MustParse("d99e6e74-fc88-11d0-b498-00a0c90312f3")

// submitDCOM activates ICertRequestD2 via DCOM on the CA server and calls
// Request2 with our PEM-encoded CSR. Matches Certipy's default `req` flow.
func submitDCOM(opts Options) (*pki.Certificate, error) {
	if opts.CA == "" {
		return nil, fmt.Errorf("req: --ca required")
	}
	if opts.CAName == "" {
		return nil, fmt.Errorf("req: --ca-name required")
	}
	if opts.Username == "" {
		return nil, fmt.Errorf("req: --username required for DCOM")
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
	reqPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	cred := credential.NewFromPassword(opts.Username, opts.Password)
	ctx, cancel := context.WithTimeout(context.Background(), Timeout*2)
	defer cancel()
	ctx = gssapi.NewSecurityContext(ctx,
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.NTLM),
	)

	progf("[*]", "dcom: dialing %s:135 for IActivation", opts.CA)
	scmConn, err := dcerpc.Dial(ctx, net.JoinHostPort(opts.CA, "135"),
		dcerpc.WithTimeout(Timeout),
		dcerpc.WithSign(),
		dcerpc.WithMechanism(ssp.NTLM),
	)
	if err != nil {
		return nil, fmt.Errorf("req: dcom: dial %s:135: %w", opts.CA, err)
	}

	oxCli, err := iobjectexporter.NewObjectExporterClient(ctx, scmConn, dcerpc.WithSign())
	if err != nil {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("req: dcom: ObjectExporter: %w", err)
	}
	alive, err := oxCli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("req: dcom: ServerAlive2: %w", err)
	}

	actCli, err := iactivation.NewActivationClient(ctx, scmConn, dcerpc.WithSign())
	if err != nil {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("req: dcom: NewActivationClient: %w", err)
	}

	progf("[*]", "dcom: RemoteActivation for CertSrvRequest (CLSID %s)", CertSrvRequestClassID)
	act, err := actCli.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: alive.COMVersion},
		ClassID:                    dtyp.GUIDFromUUID(CertSrvRequestClassID),
		IIDs:                       []*dcom.IID{icertrequestd2.CertRequestD2IID},
		RequestedProtocolSequences: []uint16{7}, // ncacn_ip_tcp
	})
	if err != nil {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("req: dcom: RemoteActivation: %w", err)
	}
	if act.HResult != 0 {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("req: dcom: RemoteActivation hresult 0x%08x (%s)",
			uint32(act.HResult), hresult.FromCode(uint32(act.HResult)))
	}
	if len(act.InterfaceData) == 0 {
		_ = scmConn.Close(ctx)
		return nil, errors.New("req: dcom: RemoteActivation returned no InterfaceData")
	}

	ipidCtx := gssapi.NewSecurityContext(context.Background(),
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	)
	ipidOpts := append(act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp"),
		dcerpc.WithTimeout(Timeout),
		dcerpc.WithSign(),
		dcerpc.WithMechanism(ssp.NTLM),
	)
	progf("[*]", "dcom: dialing OXID endpoint on ncacn_ip_tcp")
	ipidConn, err := dcerpc.Dial(ipidCtx, opts.CA, ipidOpts...)
	if err != nil {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("req: dcom: dial OXID endpoint: %w", err)
	}

	wcli, err := wcce_client.NewClient(ipidCtx, ipidConn, dcerpc.WithSign())
	if err != nil {
		_ = scmConn.Close(ctx)
		_ = ipidConn.Close(ipidCtx)
		return nil, fmt.Errorf("req: dcom: wcce NewClient: %w", err)
	}
	wcli = wcli.IPID(ipidCtx, act.InterfaceData[0].IPID())

	progf("[*]", "dcom: calling ICertRequestD2::Request2 (authority=%q, template=%q)", opts.CAName, opts.Template)

	attribString := fmt.Sprintf("CertificateTemplate:%s", opts.Template)

	r2 := &icertrequestd2.Request2Request{
		Authority:  opts.CAName,
		Flags:      0x00000000,
		Attributes: attribString,
		Request: &wcce.CertTransportBlob{
			Length: uint32(len(reqPEM)),
			Buffer: reqPEM,
		},
	}
	resp, err := wcli.CertRequestD2().Request2(ipidCtx, r2)

	// Clean up connections regardless of outcome.
	_ = ipidConn.Close(ipidCtx)
	_ = scmConn.Close(ctx)

	if err != nil {
		return nil, fmt.Errorf("req: dcom: Request2: %w", err)
	}
	progf("[+]", "dcom: disposition %d (request id %d)", resp.Disposition, resp.RequestID)
	if resp.Disposition != 3 {
		msg := ""
		if resp.DispositionMessage != nil {
			msg = strings.TrimSpace(string(resp.DispositionMessage.Buffer))
		}
		return nil, fmt.Errorf("req: dcom: CA disposition %d: %s", resp.Disposition, msg)
	}
	if resp.EncodedCert == nil || len(resp.EncodedCert.Buffer) == 0 {
		return nil, errors.New("req: dcom: empty EncodedCert in response")
	}
	cert, err := x509.ParseCertificate(resp.EncodedCert.Buffer)
	if err != nil {
		return nil, fmt.Errorf("req: dcom: parse issued cert: %w", err)
	}
	return &pki.Certificate{Cert: cert, Key: key}, nil
}
