package krb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleKrb5Conf is a minimal but valid krb5.conf used by the KRB5CONF test.
// It pins a single realm with a placeholder KDC so we can later assert that
// LoadConfig returned *this* content rather than a synthesized default.
const sampleKrb5Conf = `[libdefaults]
  default_realm = EXAMPLE.COM
  dns_lookup_kdc = false
  udp_preference_limit = 0

[realms]
  EXAMPLE.COM = {
    kdc = kdc.example.com
  }
`

func TestLoadConfig_FromKRB5CONF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(path, []byte(sampleKrb5Conf), 0o600); err != nil {
		t.Fatalf("write temp krb5.conf: %v", err)
	}

	t.Setenv("KRB5CONF", path)

	cfg, err := LoadConfig("EXAMPLE.COM", "")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.LibDefaults.DefaultRealm != "EXAMPLE.COM" {
		t.Fatalf("default_realm = %q, want EXAMPLE.COM", cfg.LibDefaults.DefaultRealm)
	}
	if len(cfg.Realms) != 1 || cfg.Realms[0].Realm != "EXAMPLE.COM" {
		t.Fatalf("realms = %+v, want single EXAMPLE.COM entry", cfg.Realms)
	}
	if len(cfg.Realms[0].KDC) == 0 || !strings.Contains(cfg.Realms[0].KDC[0], "kdc.example.com") {
		t.Fatalf("kdc = %v, want kdc.example.com", cfg.Realms[0].KDC)
	}
}

func TestLoadConfig_Synthesized(t *testing.T) {
	// Force the synthesized path: no KRB5CONF, and point HOME away so
	// nothing surprising happens. We can't easily hide /etc/krb5.conf on
	// every CI runner, so skip when it exists.
	t.Setenv("KRB5CONF", "")
	if _, err := os.Stat(systemKrb5Conf); err == nil {
		t.Skipf("system %s present; synthesized path not exercised on this host", systemKrb5Conf)
	}

	cfg, err := LoadConfig("CTG.LOCAL", "10.0.0.1")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.LibDefaults.DefaultRealm != "" {
		t.Fatalf("synthesized config should not set default_realm, got %q", cfg.LibDefaults.DefaultRealm)
	}
	if cfg.LibDefaults.UDPPreferenceLimit != 0 {
		t.Fatalf("udp_preference_limit = %d, want 0", cfg.LibDefaults.UDPPreferenceLimit)
	}
	if len(cfg.Realms) == 0 {
		t.Fatalf("expected synthesized realm, got none")
	}
	var found bool
	for _, r := range cfg.Realms {
		if r.Realm == "CTG.LOCAL" {
			found = true
			if len(r.KDC) == 0 || !strings.Contains(r.KDC[0], "10.0.0.1") {
				t.Fatalf("kdc override not applied: %+v", r.KDC)
			}
		}
	}
	if !found {
		t.Fatalf("realm CTG.LOCAL missing from synthesized config: %+v", cfg.Realms)
	}
}

func TestLoadConfig_WithKDCOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(path, []byte(sampleKrb5Conf), 0o600); err != nil {
		t.Fatalf("write temp krb5.conf: %v", err)
	}
	t.Setenv("KRB5CONF", path)

	cfg, err := LoadConfig("EXAMPLE.COM", "192.0.2.42")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if len(cfg.Realms) == 0 || cfg.Realms[0].Realm != "EXAMPLE.COM" {
		t.Fatalf("expected EXAMPLE.COM realm, got %+v", cfg.Realms)
	}
	kdcs := cfg.Realms[0].KDC
	if len(kdcs) < 2 {
		t.Fatalf("override should prepend to existing KDC list, got %v", kdcs)
	}
	if !strings.Contains(kdcs[0], "192.0.2.42") {
		t.Fatalf("override KDC not first, got %v", kdcs)
	}
	// The original file-provided KDC should still be present.
	joined := strings.Join(kdcs, ",")
	if !strings.Contains(joined, "kdc.example.com") {
		t.Fatalf("original kdc disappeared: %v", kdcs)
	}
}
