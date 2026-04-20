// Package krb provides AS-REQ / TGS-REQ Kerberos flows and ccache I/O for
// certigo. It wraps jcmturner/gokrb5/v8 with a small adapter layer that
// accepts certigo's auth.Credentials and emits ready-to-use TGT / service
// tickets. PKINIT (cert-based AS-REQ) is implemented separately in M3.
package krb
