// HTTP-layer authentication wiring for /certsrv/. Supports:
//   - HTTP Basic (HTTPS by default; HTTP-fallback handled in postCertSrv).
//   - NTLMv2 over HTTP with password (via go-ntlmssp's Negotiator).
//   - NTLMv2 over HTTP with NT hash (PtH) via a hand-rolled RoundTripper
//     that calls go-ntlmssp's NewAuthenticateMessage with PasswordHashed=true.
//
// The Negotiator path is preferred when a password is available because it
// exercises the upstream library's well-tested handshake state machine. The
// custom path is only used when opts.NTHash is set (Password is empty).

package req

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	ntlmssp "github.com/Azure/go-ntlmssp"
)

// wrapNTLMTransport returns an http.RoundTripper that handles both
// password-based NTLM/Negotiate and pass-the-hash. When opts has neither a
// password nor a hash, the wrapper still works as an unauthenticated
// pass-through (the underlying transport is just used directly).
func wrapNTLMTransport(base http.RoundTripper, opts Options) http.RoundTripper {
	if len(opts.NTHash) > 0 {
		return &ntlmHashTransport{
			Base:     base,
			Username: formatNTLMUser(opts.Username, opts.Domain),
			NTHashHex: hex.EncodeToString(opts.NTHash),
		}
	}
	// Password mode: use upstream Negotiator. AllowBasicAuth=true so /certsrv/
	// servers that still use Basic on HTTPS continue to work.
	return ntlmssp.Negotiator{
		RoundTripper:   base,
		AllowBasicAuth: true,
	}
}

// ntlmHashTransport is a minimal NTLM client that supports pass-the-hash.
// It mirrors what ntlmssp.Negotiator does, but routes the AUTHENTICATE
// message through ntlmssp.NewAuthenticateMessage with PasswordHashed=true.
//
// Flow per request:
//  1. Send the original request with no Authorization header. If the server
//     replies anything other than 401-NTLM/Negotiate, return that response.
//  2. Send NEGOTIATE message in Authorization header, expect 401 + challenge.
//  3. Send AUTHENTICATE message (computed from NT hash) in Authorization,
//     return whatever the server replies.
//
// Body handling: we buffer the body once on entry; each retry reuses the
// buffered copy. /certsrv/ requests are tiny so this is fine.
type ntlmHashTransport struct {
	Base      http.RoundTripper
	Username  string // DOMAIN\user
	NTHashHex string // 32-char lowercase hex
}

func (t *ntlmHashTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := t.Base
	if rt == nil {
		rt = http.DefaultTransport
	}
	if t.Username == "" || t.NTHashHex == "" {
		return rt.RoundTrip(req)
	}

	// Buffer the body once; we may need it up to three times.
	var bodyBytes []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("ntlm-pth: buffering body: %w", err)
		}
		_ = req.Body.Close()
		bodyBytes = b
	}
	clone := func() *http.Request {
		r := req.Clone(req.Context())
		if bodyBytes != nil {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			r.ContentLength = int64(len(bodyBytes))
		}
		return r
	}

	// Step 1 - probe.
	r1 := clone()
	r1.Header.Del("Authorization")
	resp, err := rt.RoundTrip(r1)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	scheme := pickNTLMScheme(resp.Header.Values("Www-Authenticate"))
	if scheme == "" {
		return resp, nil
	}
	drainAndClose(resp)

	// Step 2 - send NEGOTIATE.
	negotiate, err := ntlmssp.NewNegotiateMessage("", "")
	if err != nil {
		return nil, fmt.Errorf("ntlm-pth: negotiate: %w", err)
	}
	r2 := clone()
	r2.Header.Set("Authorization", scheme+" "+base64.StdEncoding.EncodeToString(negotiate))
	resp, err = rt.RoundTrip(r2)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		// Server skipped the challenge step (rare but legal per RFC 4559).
		return resp, nil
	}
	challenge := extractChallenge(resp.Header.Values("Www-Authenticate"), scheme)
	drainAndClose(resp)
	if challenge == nil {
		return nil, fmt.Errorf("ntlm-pth: server returned 401 but no %s challenge", scheme)
	}

	// Step 3 - send AUTHENTICATE with PasswordHashed=true.
	auth, err := ntlmssp.NewAuthenticateMessage(challenge, t.Username, t.NTHashHex,
		&ntlmssp.AuthenticateMessageOptions{PasswordHashed: true})
	if err != nil {
		return nil, fmt.Errorf("ntlm-pth: authenticate: %w", err)
	}
	r3 := clone()
	r3.Header.Set("Authorization", scheme+" "+base64.StdEncoding.EncodeToString(auth))
	return rt.RoundTrip(r3)
}

// pickNTLMScheme returns "NTLM" or "Negotiate" if the WWW-Authenticate
// header advertises one of them, preferring NTLM (matches Negotiator
// behavior). Empty string means neither is offered.
func pickNTLMScheme(headers []string) string {
	for _, h := range headers {
		if h == "NTLM" || (len(h) >= 5 && h[:4] == "NTLM" && h[4] == ' ') {
			return "NTLM"
		}
	}
	for _, h := range headers {
		if h == "Negotiate" || (len(h) >= 10 && h[:9] == "Negotiate" && h[9] == ' ') {
			return "Negotiate"
		}
	}
	return ""
}

// extractChallenge pulls the base64-decoded server challenge for the chosen
// scheme out of the WWW-Authenticate header set.
func extractChallenge(headers []string, scheme string) []byte {
	prefix := scheme + " "
	for _, h := range headers {
		if len(h) > len(prefix) && h[:len(prefix)] == prefix {
			b, err := base64.StdEncoding.DecodeString(h[len(prefix):])
			if err == nil {
				return b
			}
		}
	}
	return nil
}

func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
