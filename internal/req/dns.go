package req

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// resolveWithDC resolves host via the DNS server at dcServer:53, used as a
// fallback when the local resolver can't find an AD internal name. The
// returned net.IP is the first A record; caller can substitute it into
// the CA endpoint so DCOM + HTTP dials succeed even without /etc/resolv.conf
// pointing at the DC.
func resolveWithDC(ctx context.Context, host, dcServer string, timeout time.Duration) (string, error) {
	if host == "" || dcServer == "" {
		return "", errors.New("req/dns: host and dcServer required")
	}
	// If host already is an IP, nothing to do.
	if net.ParseIP(host) != nil {
		return host, nil
	}
	// If the OS resolver can already find it, prefer that.
	if addrs, err := net.DefaultResolver.LookupHost(ctx, host); err == nil && len(addrs) > 0 {
		return addrs[0], nil
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, net.JoinHostPort(dcServer, "53"))
		},
	}
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return "", fmt.Errorf("req/dns: lookup %s @ %s:53: %w", host, dcServer, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("req/dns: no A records for %s", host)
	}
	return addrs[0], nil
}
