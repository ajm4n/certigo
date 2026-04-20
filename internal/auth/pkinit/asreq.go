package pkinit

import (
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/ajm4n/certigo/internal/pki"
)

// Options controls the PKINIT AS-REQ flow.
type Options struct {
	Realm      string           // e.g. "CTG.LOCAL" (uppercase)
	Principal  string           // sAMAccountName (e.g. "alice" or "alice$")
	Cert       *pki.Certificate // PFX-loaded: Cert, *rsa.PrivateKey
	Config     *config.Config   // gokrb5 config with [realms]/KDC
	DH         DHParams         // zero value = WellKnownGroup14 (RFC3526 group 14, 2048-bit)
	RequestPAC bool             // default true
}

// Result bundles the TGT and its decrypted enc-part returned from a
// successful PKINIT exchange. Callers that need a live gokrb5
// *client.Client can use AuthenticateWithPKINIT (which also returns Result)
// and feed it through SavePKINITTGTToCCache; callers that only need to
// persist the TGT to disk can skip the client.
type Result struct {
	Client          *client.Client
	CName           types.PrincipalName
	Realm           string
	Ticket          messages.Ticket
	DecryptedEncKDC messages.EncKDCRepPart
}

// AuthenticateWithPKINIT performs an AS-REQ with PA-PK-AS-REQ (RFC 4556 §3)
// against the KDC identified by opts.Config for opts.Realm, and returns a
// gokrb5 *client.Client with its TGT populated and ready for follow-up
// TGS-REQ or ccache write.
//
// gokrb5 v8's *client.Client exposes no public setter for the sessions map
// or credential secret material, so the returned Client is a thin wrapper
// that only carries Credentials and Config - the real TGT/sessionKey pair
// lives in the Result fields and can be written to ccache via
// SavePKINITTGTToCCache.
func AuthenticateWithPKINIT(opts Options) (*client.Client, error) {
	res, err := authenticateWithPKINIT(opts)
	if err != nil {
		return nil, err
	}
	return res.Client, nil
}

// AuthenticateWithPKINITResult is the expanded entry point used when the
// caller wants both the *client.Client and direct access to the TGT +
// EncKDCRepPart (e.g. to feed SavePKINITTGTToCCache without a second
// round-trip).
func AuthenticateWithPKINITResult(opts Options) (*Result, error) {
	return authenticateWithPKINIT(opts)
}

func authenticateWithPKINIT(opts Options) (*Result, error) {
	if err := validateOptions(&opts); err != nil {
		return nil, err
	}

	realm := strings.ToUpper(strings.TrimSpace(opts.Realm))
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{opts.Principal},
	}

	// Step 1: build a reasonable AS-REQ template via gokrb5, then adjust.
	asReq, err := messages.NewASReqForTGT(realm, opts.Config, cname)
	if err != nil {
		return nil, fmt.Errorf("pkinit: build AS-REQ template: %w", err)
	}
	asReq.PAData = types.PADataSequence{} // we will add our own PA-PK-AS-REQ
	// Drop any local host-addresses to avoid KDC_ERR_BADADDR against a KDC
	// that doesn't share our subnet; PKINIT clients routinely omit them.
	asReq.ReqBody.Addresses = nil
	// KDC options: canonicalize + forwardable + renewable, matching what
	// Impacket's gettgtpkinit.py sends. The RequestPAC flag is communicated
	// via pa-data of type PA_PAC_REQUEST rather than KDC options, but we
	// make no effort to strip PAC requests - Windows always issues PACs.
	if opts.RequestPAC {
		asReq.PAData = append(asReq.PAData, buildPACRequestPA())
	}
	types.SetFlag(&asReq.ReqBody.KDCOptions, flags.Forwardable)
	types.SetFlag(&asReq.ReqBody.KDCOptions, flags.Renewable)
	types.SetFlag(&asReq.ReqBody.KDCOptions, flags.Canonicalize)
	// Request AES enctypes only (RFC 4556 §3.2.3.1 key derivation here
	// assumes the AES-CTS-HMAC-SHA1 family; extending to RFC 8009 etypes
	// would require the alternate KDF in §3.2.3.1 of RFC 8009).
	asReq.ReqBody.EType = []int32{
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA1_96,
	}
	// A fresh nonce - also chained into the AuthPack PKAuthenticator so
	// the KDC can correlate the reply.
	nonce := asReq.ReqBody.Nonce

	// Step 2: compute paChecksum = SHA1(KDC-REQ-BODY DER).
	bodyDER, err := asReq.ReqBody.Marshal()
	if err != nil {
		return nil, fmt.Errorf("pkinit: marshal KDC-REQ-BODY: %w", err)
	}
	sum := sha1.Sum(bodyDER)
	paChecksum := sum[:]

	// Step 3: generate DH key pair.
	dh := opts.DH
	if dh.P == nil || dh.G == nil {
		dh = WellKnownGroup14()
	}
	priv, err := dh.GeneratePrivate()
	if err != nil {
		return nil, err
	}
	pub := dh.PublicFrom(priv)

	// Step 4: build AuthPack carrying paChecksum + our DH public Y.
	authPackDER, clientDHNonce, err := BuildAuthPack(dh, pub, paChecksum, int32(nonce))
	if err != nil {
		return nil, fmt.Errorf("pkinit: build AuthPack: %w", err)
	}

	// Step 5: wrap into CMS SignedData, signed by the client cert.
	rsaKey, ok := opts.Cert.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("pkinit: client key is not *rsa.PrivateKey (got %T)", opts.Cert.Key)
	}
	signedData, err := BuildSignedData(OIDPKINITAuthData, authPackDER, opts.Cert.Cert, rsaKey)
	if err != nil {
		return nil, fmt.Errorf("pkinit: sign AuthPack: %w", err)
	}

	// Step 6: wrap signedData in PA-PK-AS-REQ ASN.1 SEQUENCE.
	paPkAsReq, err := MarshalPAPKASReq(signedData)
	if err != nil {
		return nil, err
	}

	// Step 7: attach as PA_PK_AS_REQ (padata-type 16).
	asReq.PAData = append(asReq.PAData, types.PAData{
		PADataType:  patype.PA_PK_AS_REQ,
		PADataValue: paPkAsReq,
	})

	// Step 8: serialize and send over TCP to the configured KDC.
	reqBytes, err := asReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("pkinit: marshal AS-REQ: %w", err)
	}
	respBytes, err := sendAS(opts.Config, realm, reqBytes)
	if err != nil {
		return nil, err
	}

	// Step 9: try to parse AS-REP; a KRB-ERROR returns instead on failure.
	if krbErr, ok := checkKRBError(respBytes); ok {
		return nil, fmt.Errorf("pkinit: KDC returned KRB-ERROR: %v (code %d, %s)",
			krbErr.ErrorCode, krbErr.ErrorCode, strings.TrimSpace(krbErr.EText))
	}
	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBytes); err != nil {
		return nil, fmt.Errorf("pkinit: unmarshal AS-REP: %w", err)
	}

	// Step 10: locate PA-PK-AS-REP (padata-type 17) and extract the DH Y2.
	var paPkAsRep []byte
	for _, pa := range asRep.PAData {
		if pa.PADataType == patype.PA_PK_AS_REP {
			paPkAsRep = pa.PADataValue
			break
		}
	}
	if paPkAsRep == nil {
		return nil, errors.New("pkinit: AS-REP missing PA-PK-AS-REP padata (type 17)")
	}
	dhSignedData, serverDHNonce, err := ParsePAPKASRep(paPkAsRep)
	if err != nil {
		return nil, err
	}
	kdcContent, _, err := ParseSignedData(dhSignedData)
	if err != nil {
		return nil, fmt.Errorf("pkinit: parse KDC dhSignedData: %w", err)
	}
	yBytes, _, err := ParseKDCDHKeyInfo(kdcContent)
	if err != nil {
		return nil, err
	}
	// The KDC encodes Y as an INTEGER inside the SubjectPublicKey BIT STRING.
	var y *big.Int
	if _, perr := asn1.Unmarshal(yBytes, &y); perr != nil {
		return nil, fmt.Errorf("pkinit: unmarshal KDC DH Y: %w", perr)
	}

	// Step 10 (cont): compute shared secret, then derive AS reply key.
	shared := dh.SharedSecret(y, priv)
	replyKey, err := DeriveASReplyKey(asRep.EncPart.EType, shared, clientDHNonce, serverDHNonce)
	if err != nil {
		return nil, fmt.Errorf("pkinit: derive reply key: %w", err)
	}

	// Step 11: decrypt AS-REP.EncPart with the derived key.
	plain, err := crypto.DecryptEncPart(asRep.EncPart, replyKey, keyusage.AS_REP_ENCPART)
	if err != nil {
		return nil, fmt.Errorf("pkinit: decrypt AS-REP enc-part: %w", err)
	}
	var denc messages.EncKDCRepPart
	if err := denc.Unmarshal(plain); err != nil {
		return nil, fmt.Errorf("pkinit: unmarshal decrypted enc-part: %w", err)
	}
	if denc.Nonce != nonce {
		return nil, fmt.Errorf("pkinit: AS-REP nonce mismatch (req=%d rep=%d)", nonce, denc.Nonce)
	}

	// Step 12: synthesize a minimal *client.Client. gokrb5 v8 offers no way
	// to inject a pre-computed TGT into a client whose Credentials carry
	// neither keytab nor password, so IsConfigured() would fail. We return
	// a skeleton the caller can still consult for Config/Credentials and
	// rely on SavePKINITTGTToCCache for the actual ccache emission.
	cl := &client.Client{
		Config: opts.Config,
	}
	return &Result{
		Client:          cl,
		CName:           cname,
		Realm:           realm,
		Ticket:          asRep.Ticket,
		DecryptedEncKDC: denc,
	}, nil
}

// validateOptions asserts that the caller populated the mandatory fields.
// The DH params and RequestPAC default at call time (empty DHParams ->
// WellKnownGroup14, bool zero -> disabled) so only the inputs that have no
// safe zero value are checked here.
func validateOptions(opts *Options) error {
	if opts == nil {
		return errors.New("pkinit: nil Options")
	}
	if strings.TrimSpace(opts.Realm) == "" {
		return errors.New("pkinit: Options.Realm required")
	}
	if strings.TrimSpace(opts.Principal) == "" {
		return errors.New("pkinit: Options.Principal required")
	}
	if opts.Cert == nil || opts.Cert.Cert == nil || opts.Cert.Key == nil {
		return errors.New("pkinit: Options.Cert must carry both leaf certificate and private key")
	}
	if opts.Config == nil {
		return errors.New("pkinit: Options.Config required")
	}
	return nil
}

// buildPACRequestPA returns a PAData entry of type PA-PAC-REQUEST (128)
// requesting that the KDC embed a PAC in the issued ticket. Non-Microsoft
// KDCs silently ignore it.
func buildPACRequestPA() types.PAData {
	// PA-PAC-REQUEST ::= SEQUENCE { include-pac [0] BOOLEAN --# true if PAC
	// requested --} - we always emit the positive form.
	type pacRequest struct {
		IncludePAC bool `asn1:"explicit,tag:0"`
	}
	der, _ := asn1.Marshal(pacRequest{IncludePAC: true})
	return types.PAData{
		PADataType:  int32(128), // PA_PAC_REQUEST (not in iana/patype)
		PADataValue: der,
	}
}

// sendAS resolves the first KDC under opts.Config for realm, then sends
// reqBytes as a length-prefixed TCP packet (RFC 4120 §7.2.2). We skip UDP
// entirely - PKINIT messages routinely exceed the EDNS0 threshold and all
// modern KDCs accept TCP on 88.
func sendAS(cfg *config.Config, realm string, reqBytes []byte) ([]byte, error) {
	addr, err := resolveKDC(cfg, realm)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("pkinit: dial KDC %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(reqBytes)))
	if _, err := conn.Write(hdr); err != nil {
		return nil, fmt.Errorf("pkinit: write AS-REQ length prefix: %w", err)
	}
	if _, err := conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("pkinit: write AS-REQ body: %w", err)
	}

	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		return nil, fmt.Errorf("pkinit: read response length prefix: %w", err)
	}
	respLen := binary.BigEndian.Uint32(respHdr)
	if respLen == 0 || respLen > 1<<20 {
		return nil, fmt.Errorf("pkinit: unreasonable response length %d", respLen)
	}
	resp := make([]byte, int(respLen))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("pkinit: read response body: %w", err)
	}
	return resp, nil
}

// resolveKDC picks the first KDC entry for realm from cfg. If none is
// listed we return an error; PKINIT needs a deterministic target and
// there's no convenient way to query DNS SRV from outside gokrb5's
// unexported helpers.
func resolveKDC(cfg *config.Config, realm string) (string, error) {
	if cfg == nil {
		return "", errors.New("pkinit: nil krb config")
	}
	for _, r := range cfg.Realms {
		if strings.EqualFold(r.Realm, realm) && len(r.KDC) > 0 {
			addr := r.KDC[0]
			// gokrb5 config entries are "host:port"; if the port was
			// omitted default to 88.
			if !strings.Contains(addr, ":") {
				addr += ":88"
			}
			return addr, nil
		}
	}
	return "", fmt.Errorf("pkinit: no KDC configured for realm %q", realm)
}

// checkKRBError returns a populated KRBError if b decodes as one. The bool
// is true only when the response really is a KRB-ERROR (vs an AS-REP).
func checkKRBError(b []byte) (messages.KRBError, bool) {
	var e messages.KRBError
	if err := e.Unmarshal(b); err == nil {
		return e, true
	}
	return messages.KRBError{}, false
}

// Guardrails against unused-import errors if some codepath is refactored
// out; these constants anchor the iana imports.
var (
	_ = iana.PVNO
	_ = msgtype.KRB_AS_REQ
)
