// Package ca — DCOM / MS-CSRA (ICertAdminD + ICertAdminD2) bindings.
//
// Activation flow (per MS-DCOM §3.2.4.1.1):
//
//  1. Dial port 135 and speak to IObjectExporter::ServerAlive2 to negotiate
//     COMVERSION.
//  2. Use IRemoteSCMActivator::RemoteCreateInstance (or the older
//     IActivation::RemoteActivation path) to obtain an IPID + OXID bindings
//     for the CertAdminD2 coclass (CLSID d99e6e73-fc88-11d0-b498-00a0c90312f3).
//  3. Dial the returned ncacn_ip_tcp endpoint and bind CertAdminD / D2
//     against the IPID.
//
// We use the `iactivation` package's RemoteActivation for step (2). MS-DCOM
// §1.3.5 treats it as equivalent to IRemoteSCMActivator::RemoteCreateInstance
// for single-class activation, and an official go-msrpc example
// (examples/samples_with_config/csra_enum_certdb.go) uses it against the
// exact same coclass we need. IRemoteSCMActivator is also re-exported from
// go-msrpc at msrpc/dcom/iremotescmactivator/v0 — kept as an option in
// iremotescmactivator-gated code paths upstream if we ever need
// RemoteCreateInstance's richer property set.
package ca

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	csra_client "github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/client"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/icertadmind/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/icertadmind2/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"

	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

// CertAdminD2ClassID is the DCOM coclass for ICertAdminD2 on an enterprise
// CA — registered by certsrv.exe. See MS-CSRA §1.9.
var CertAdminD2ClassID = uuid.MustParse("d99e6e73-fc88-11d0-b498-00a0c90312f3")

// CR_PROP_CASIGCERT is the MS-WCCE §3.2.1.4.3.2 property ID for retrieving
// a CA signing certificate as a binary DER blob.
const crPropCASigCert = 0x0000000F

// rpcDialTimeout bounds the port 135 dial + activation handshake.
const rpcDialTimeout = 30 * time.Second

// rpcClient wraps a live DCOM connection to an enterprise CA's ICertAdminD2
// coclass. The underlying RPC connection lives until Close is called.
type rpcClient struct {
	// authorityName is the CN of the CA (e.g. "corp-DC01-CA"). Every D/D2
	// method requires it as the pwszAuthority argument.
	authorityName string

	// server is the CA's DNS / IP, used for error messages.
	server string

	// comVersion is the negotiated DCOM version. D/D2 methods thread it
	// through the ORPCThis header.
	comVersion *dcom.COMVersion

	// csra is the single client bundle exposing both the v0 (CertAdminD)
	// and v2 (CertAdminD2) interfaces bound to the activation IPID.
	csra csra_client.Client

	// scmConn (port 135) is only used during activation; ipidConn (high-port
	// ncacn_ip_tcp) carries the D/D2 traffic. Both are closed by Close.
	scmConn  dcerpc.Conn
	ipidConn dcerpc.Conn
}

// Client is the exported handle returned by DialRPC / DialRPCWithNTHash.
// It wraps an internal *rpcClient (carrying the live DCOM conn) so the
// cmd/ layer can operate in package main without reaching into unexported
// types here.
type Client = rpcClient

// DialRPC is the exported constructor; see dialRPC for the contract.
func DialRPC(server, authority, user, password string) (*Client, error) {
	return dialRPC(server, authority, user, password)
}

// DialRPCWithNTHash is the exported NT-hash variant.
func DialRPCWithNTHash(server, authority, user string, hash []byte) (*Client, error) {
	return dialRPCWithNTHash(server, authority, user, hash)
}

// dialRPC establishes a DCOM connection to the CA server and binds the
// ICertAdminD / ICertAdminD2 interfaces. server is the CA's dNSHostName
// (no port). authority is the CA's CN — returned attribute names differ;
// see adcs.CertificateAuthority.Name. user is in "DOMAIN\\user" or plain
// "user" form. If useHash is true, password is treated as an NT hash
// (hex-encoded).
//
// dialRPC is a pure construction helper. It returns an *rpcClient on
// success; callers must call Close when done. If the CA is unreachable
// the returned error wraps the underlying dial / activation error so the
// caller can distinguish network vs. auth vs. activation failures.
func dialRPC(server, authority, user, password string) (*rpcClient, error) {
	if strings.TrimSpace(server) == "" {
		return nil, errors.New("ca: dialRPC: server is empty")
	}
	if strings.TrimSpace(authority) == "" {
		return nil, errors.New("ca: dialRPC: authority (CA name) is empty")
	}
	return dialRPCWithCred(server, authority, buildPasswordCredential(user, password))
}

// dialRPCWithNTHash is the NT-hash variant of dialRPC. hash must be the
// 16-byte binary NTLM hash.
func dialRPCWithNTHash(server, authority, user string, hash []byte) (*rpcClient, error) {
	if strings.TrimSpace(server) == "" {
		return nil, errors.New("ca: dialRPC: server is empty")
	}
	if strings.TrimSpace(authority) == "" {
		return nil, errors.New("ca: dialRPC: authority (CA name) is empty")
	}
	if len(hash) != 16 {
		return nil, fmt.Errorf("ca: dialRPC: NT hash must be 16 bytes, got %d", len(hash))
	}
	un, domain := splitUser(user)
	cred := credential.NewFromNTHashBytes(un, hash, credential.Domain(domain))
	return dialRPCWithCred(server, authority, cred)
}

// buildPasswordCredential honors "DOMAIN\\user" formatting. An empty
// domain is legal for workgroup / local-account authentication.
func buildPasswordCredential(user, password string) credential.Credential {
	un, domain := splitUser(user)
	return credential.NewFromPassword(un, password, credential.Domain(domain))
}

// splitUser accepts DOMAIN\\user, user@DOMAIN, or bare user.
func splitUser(raw string) (user, domain string) {
	if raw == "" {
		return "", ""
	}
	if i := strings.Index(raw, `\`); i >= 0 {
		return raw[i+1:], raw[:i]
	}
	if i := strings.Index(raw, "@"); i >= 0 {
		return raw[:i], raw[i+1:]
	}
	return raw, ""
}

// dialRPCWithCred is the shared body of the password / hash constructors.
// It performs the two-stage DCOM dial (port 135 activation, then the OXID
// endpoint advertised back) and returns a csra/client ready for D/D2 calls.
func dialRPCWithCred(server, authority string, cred credential.Credential) (*rpcClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcDialTimeout)
	defer cancel()

	// Credentials are installed into a fresh gssapi context so we don't
	// leak them into the caller's global state. SPNEGO picks the strongest
	// available mechanism (Kerberos if the target supports it, else NTLM).
	ctx = gssapi.NewSecurityContext(ctx,
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	)

	scmConn, err := dcerpc.Dial(ctx, net.JoinHostPort(server, "135"),
		dcerpc.WithTimeout(rpcDialTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("ca: rpc dial %s:135: %w", server, err)
	}

	// IObjectExporter::ServerAlive2 negotiates COMVERSION.
	oxCli, err := iobjectexporter.NewObjectExporterClient(ctx, scmConn,
		dcerpc.WithSign(),
	)
	if err != nil {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("ca: new object exporter: %w", err)
	}
	alive, err := oxCli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("ca: ServerAlive2: %w", err)
	}

	// Remote-activate the CertAdminD2 coclass. The older IActivation
	// interface is equivalent to IRemoteSCMActivator::RemoteCreateInstance
	// for single-class activation (MS-DCOM §3.2.4.1.1) and is what
	// go-msrpc's own csra example uses.
	actCli, err := iactivation.NewActivationClient(ctx, scmConn,
		dcerpc.WithSign(),
	)
	if err != nil {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("ca: new activation client: %w", err)
	}

	act, err := actCli.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis: &dcom.ORPCThis{Version: alive.COMVersion},
		ClassID:  dtyp.GUIDFromUUID(CertAdminD2ClassID),
		IIDs:     []*dcom.IID{icertadmind2.CertAdminD2IID},
		// 7 = ncacn_ip_tcp. We intentionally omit named pipes (15) —
		// AD CS always exposes ICertAdminD2 via TCP on modern Windows,
		// and keeping the protocol list minimal avoids the server
		// replying with a pipe endpoint we can't dial from Unix hosts.
		RequestedProtocolSequences: []uint16{7},
	})
	if err != nil {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("ca: RemoteActivation: %w", err)
	}
	if act.HResult != 0 {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("ca: RemoteActivation returned hresult 0x%08x (%s)",
			uint32(act.HResult), hresult.FromCode(uint32(act.HResult)))
	}
	if len(act.InterfaceData) == 0 {
		_ = scmConn.Close(ctx)
		return nil, errors.New("ca: RemoteActivation returned no interface data")
	}

	// Establish a fresh security context for the OXID-endpoint dial.
	ipidCtx := gssapi.NewSecurityContext(context.Background(),
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	)

	ipidOpts := append(act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp"),
		dcerpc.WithTimeout(rpcDialTimeout),
	)
	ipidConn, err := dcerpc.Dial(ipidCtx, server, ipidOpts...)
	if err != nil {
		_ = scmConn.Close(ctx)
		return nil, fmt.Errorf("ca: rpc dial ncacn_ip_tcp (OXID endpoint): %w", err)
	}

	cli, err := csra_client.NewClient(ipidCtx, ipidConn,
		dcerpc.WithSign(),
	)
	if err != nil {
		_ = scmConn.Close(ctx)
		_ = ipidConn.Close(ipidCtx)
		return nil, fmt.Errorf("ca: new csra client: %w", err)
	}
	cli = cli.IPID(ipidCtx, act.InterfaceData[0].IPID())

	return &rpcClient{
		authorityName: authority,
		server:        server,
		comVersion:    alive.COMVersion,
		csra:          cli,
		scmConn:       scmConn,
		ipidConn:      ipidConn,
	}, nil
}

// Close tears down both the activation and the OXID-endpoint connections.
// It is safe to call on a nil receiver (no-op).
func (c *rpcClient) Close() error {
	if c == nil {
		return nil
	}
	ctx := context.Background()
	var firstErr error
	if c.ipidConn != nil {
		if err := c.ipidConn.Close(ctx); err != nil && !errors.Is(err, io.EOF) {
			firstErr = err
		}
	}
	if c.scmConn != nil {
		if err := c.scmConn.Close(ctx); err != nil && !errors.Is(err, io.EOF) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// orpcThis returns a fresh ORPCThis header tagged with the negotiated
// COMVERSION. Every D/D2 call embeds one.
func (c *rpcClient) orpcThis() *dcom.ORPCThis {
	return &dcom.ORPCThis{Version: c.comVersion}
}

// d returns the ICertAdminD binding (v0 interface: DenyRequest,
// ResubmitRequest, Backup*).
func (c *rpcClient) d() icertadmind.CertAdminDClient {
	return c.csra.CertAdminD2().CertAdminD()
}

// d2 returns the ICertAdminD2 binding (GetOfficerRights, SetOfficerRights,
// GetCAProperty, etc.).
func (c *rpcClient) d2() icertadmind2.CertAdminD2Client {
	return c.csra.CertAdminD2()
}

// callCtx derives a per-call deadline. We don't want a hanging call to
// pin the connection forever.
func (c *rpcClient) callCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rpcDialTimeout)
}
