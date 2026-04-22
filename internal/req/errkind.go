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
