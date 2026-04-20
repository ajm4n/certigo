// Package pkinit implements the client-side PKINIT (RFC 4556) pre-auth path
// for Kerberos AS exchanges. It builds the PA-PK-AS-REQ (AuthPack wrapped in
// CMS SignedData, using the caller's X.509 certificate and RSA key for the
// signature), performs the AS-REQ/AS-REP round-trip against a KDC, parses the
// PA-PK-AS-REP returned by the server, completes the ephemeral
// Diffie-Hellman exchange, derives the AS-reply key via RFC 4556 §3.2.3.1
// octetstring2key, decrypts the encrypted part of the AS-REP, and returns a
// populated gokrb5 *client.Client ready to issue TGS-REQs or export a TGT
// into a ccache. No live KDC tests live in this package; the end-to-end
// AuthenticateWithPKINIT flow is exercised only by integration tests.
package pkinit
