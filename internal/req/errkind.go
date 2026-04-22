package req

import "strings"

// isDNSError reports whether err came from a DNS miss (OS resolver could
// not map the hostname). Matching is done on the error text because the
// inner error is wrapped by dcerpc.Dial.
func isDNSError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "no such host") ||
		strings.Contains(s, "lookup ") ||
		strings.Contains(s, "server misbehaving")
}

// isAccessDenied reports whether err is a DCOM / RPC ACCESS_DENIED. Used
// by --auto-fallback to decide whether to retry the same CA over /certsrv/
// instead of DCOM: ACCESS_DENIED on activation usually means the Windows
// host's local "Certificate Service DCOM Access" ACL rejects the principal
// even though AD-level template + CA ACLs allow enrollment.
func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "ERROR_ACCESS_DENIED") ||
		strings.Contains(s, "0x00000005") ||
		strings.Contains(s, "Access is denied")
}
