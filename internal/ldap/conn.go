package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// DialOptions carry user-controllable knobs for Dial.
type DialOptions struct {
	Server             string // "host:port", e.g. "dc01.ctg.local:389"
	UseTLS             bool   // LDAPS; auto-enabled if port is 636
	InsecureSkipVerify bool
	Timeout            time.Duration // 0 = library default
	Channel            string        // "tcp" or "udp"; default tcp
}

// Dial connects and returns an unbound *ldap.Conn. Caller must then Bind.
func Dial(opts DialOptions) (*goldap.Conn, error) {
	if opts.Server == "" {
		return nil, errors.New("ldap: dial: Server is required")
	}
	network := strings.ToLower(strings.TrimSpace(opts.Channel))
	if network == "" {
		network = "tcp"
	}

	useTLS := opts.UseTLS
	if strings.HasSuffix(opts.Server, ":636") {
		useTLS = true
	}

	url := buildDialURL(useTLS, network, opts.Server)

	dialOpts := []goldap.DialOpt{}
	if opts.Timeout > 0 {
		dialOpts = append(dialOpts, goldap.DialWithDialer(&net.Dialer{Timeout: opts.Timeout}))
	}
	if useTLS {
		//nolint:gosec // InsecureSkipVerify is an explicit user opt-in.
		tlsCfg := &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify}
		dialOpts = append(dialOpts, goldap.DialWithTLSConfig(tlsCfg))
	}

	conn, err := goldap.DialURL(url, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial %s: %w", opts.Server, err)
	}
	if opts.Timeout > 0 {
		conn.SetTimeout(opts.Timeout)
	}
	return conn, nil
}

// buildDialURL composes an RFC-1959 LDAP URL from the legacy network+addr
// pair used by go-ldap's deprecated Dial/DialTLS entry points.
func buildDialURL(useTLS bool, network, addr string) string {
	scheme := "ldap"
	if useTLS {
		scheme = "ldaps"
	}
	if network == "udp" {
		scheme = "cldap"
	}
	return scheme + "://" + addr
}
