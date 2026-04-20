package krb

import (
	"fmt"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/config"
)

// Path to the system-wide krb5.conf on POSIX hosts. Windows and non-standard
// layouts are expected to set KRB5CONF explicitly.
const systemKrb5Conf = "/etc/krb5.conf"

// LoadConfig returns a *config.Config suitable for constructing a gokrb5 client.
// Precedence:
//  1. KRB5CONF environment variable path (if set).
//  2. /etc/krb5.conf (if readable).
//  3. A synthesized in-memory config rooted at realm with defaults
//     matching Impacket's behavior (no default_realm, udp_preference_limit=0).
//
// If kdcOverride is non-empty, it's injected as [realms]/<realm>/kdc for the
// target realm so callers can force a specific KDC without writing a file.
func LoadConfig(realm, kdcOverride string) (*config.Config, error) {
	realm = strings.ToUpper(strings.TrimSpace(realm))

	cfg, err := loadBaseConfig(realm)
	if err != nil {
		return nil, err
	}

	if kdcOverride != "" {
		if realm == "" {
			return nil, fmt.Errorf("krb: kdc override %q requires a realm", kdcOverride)
		}
		applyKDCOverride(cfg, realm, kdcOverride)
	}

	return cfg, nil
}

// loadBaseConfig resolves krb5.conf using the documented precedence. When no
// file is available it synthesizes a minimal config rooted at realm.
func loadBaseConfig(realm string) (*config.Config, error) {
	if path := os.Getenv("KRB5CONF"); path != "" {
		cfg, err := config.Load(path)
		if err != nil {
			return nil, fmt.Errorf("krb: load KRB5CONF %q: %w", path, err)
		}
		return cfg, nil
	}

	if _, err := os.Stat(systemKrb5Conf); err == nil {
		cfg, err := config.Load(systemKrb5Conf)
		if err != nil {
			return nil, fmt.Errorf("krb: load %s: %w", systemKrb5Conf, err)
		}
		return cfg, nil
	}

	return synthesizeConfig(realm)
}

// synthesizeConfig creates a minimal krb5 config matching Impacket's defaults:
// no default_realm, udp_preference_limit=0, and (when a realm is provided) an
// empty [realms] entry ready for a KDC override.
func synthesizeConfig(realm string) (*config.Config, error) {
	var b strings.Builder
	b.WriteString("[libdefaults]\n")
	b.WriteString("  dns_lookup_kdc = false\n")
	b.WriteString("  dns_lookup_realm = false\n")
	b.WriteString("  udp_preference_limit = 0\n")
	b.WriteString("  rdns = false\n")

	if realm != "" {
		b.WriteString("\n[realms]\n")
		fmt.Fprintf(&b, "  %s = {\n", realm)
		b.WriteString("  }\n")
	}

	cfg, err := config.NewFromString(b.String())
	if err != nil {
		return nil, fmt.Errorf("krb: synthesize config: %w", err)
	}
	return cfg, nil
}

// applyKDCOverride ensures cfg contains a [realms]/<realm> entry with the given
// KDC listed first. If the realm already exists, the override is prepended so
// it wins over any other KDCs. If the realm does not exist, a new entry is
// created.
func applyKDCOverride(cfg *config.Config, realm, kdc string) {
	kdc = strings.TrimSpace(kdc)
	for i := range cfg.Realms {
		if strings.EqualFold(cfg.Realms[i].Realm, realm) {
			cfg.Realms[i].KDC = append([]string{kdc}, cfg.Realms[i].KDC...)
			return
		}
	}
	cfg.Realms = append(cfg.Realms, config.Realm{
		Realm: realm,
		KDC:   []string{kdc},
	})
	if cfg.DomainRealm == nil {
		cfg.DomainRealm = config.DomainRealm{}
	}
	cfg.DomainRealm["."+strings.ToLower(realm)] = realm
	cfg.DomainRealm[strings.ToLower(realm)] = realm
}
