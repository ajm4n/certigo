package certcmd

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ajm4n/certigo/internal/pki"
)

// Options captures every flag Certipy's "cert" command accepts. One of
// PFXIn/PEMIn is required; the rest are optional and drive what Run emits.
type Options struct {
	// Input (exactly one required).
	PFXIn string
	PEMIn string

	// Output (at most one of the format-specific paths; generic Out is
	// resolved to whichever format matches the remaining data).
	PFXOut string
	PEMOut string
	Out    string

	// Passwords.
	PFXInPassword  string
	PFXOutPassword string

	// Extraction toggles. When either is true Run emits only the selected
	// PEM block (to stdout unless Out/PEMOut is set).
	ExtractKey  bool
	ExtractCert bool

	// NoOut suppresses stdout output. Useful with -out so the caller isn't
	// double-fed the same bytes.
	NoOut bool
}

// Run executes the conversion/extraction pipeline described by opts. Any
// data that isn't written to a file is written to stdout, unless NoOut is
// set.
func Run(opts Options, stdout io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}

	cert, err := loadInput(opts)
	if err != nil {
		return err
	}

	switch {
	case opts.ExtractKey && opts.ExtractCert:
		return errors.New("cert: --extract-key and --extract-cert are mutually exclusive")
	case opts.ExtractKey:
		return emitExtracted(cert, "PRIVATE KEY", opts, stdout)
	case opts.ExtractCert:
		return emitExtracted(cert, "CERTIFICATE", opts, stdout)
	}

	// Non-extract path: honour output flags, falling back to stdout PEM.
	if opts.PFXOut != "" {
		data, err := pki.SavePFX(cert, opts.PFXOutPassword)
		if err != nil {
			return fmt.Errorf("cert: encode output pfx: %w", err)
		}
		if err := os.WriteFile(opts.PFXOut, data, 0o600); err != nil {
			return fmt.Errorf("cert: write pfx: %w", err)
		}
	}

	if opts.PEMOut != "" {
		data, err := pki.EncodePEM(cert)
		if err != nil {
			return fmt.Errorf("cert: encode output pem: %w", err)
		}
		if err := os.WriteFile(opts.PEMOut, data, 0o600); err != nil {
			return fmt.Errorf("cert: write pem: %w", err)
		}
	}

	if opts.Out != "" && opts.PFXOut == "" && opts.PEMOut == "" {
		// Generic -out: pick format based on the original input. PFX in →
		// PFX out, anything else → PEM.
		if opts.PFXIn != "" {
			data, err := pki.SavePFX(cert, opts.PFXOutPassword)
			if err != nil {
				return fmt.Errorf("cert: encode output pfx: %w", err)
			}
			if err := os.WriteFile(opts.Out, data, 0o600); err != nil {
				return fmt.Errorf("cert: write output: %w", err)
			}
		} else {
			data, err := pki.EncodePEM(cert)
			if err != nil {
				return fmt.Errorf("cert: encode output pem: %w", err)
			}
			if err := os.WriteFile(opts.Out, data, 0o600); err != nil {
				return fmt.Errorf("cert: write output: %w", err)
			}
		}
	}

	// Echo PEM to stdout when no output target was configured and -noout
	// isn't set.
	if !opts.NoOut && opts.PFXOut == "" && opts.PEMOut == "" && opts.Out == "" {
		data, err := pki.EncodePEM(cert)
		if err != nil {
			return fmt.Errorf("cert: encode pem: %w", err)
		}
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("cert: write stdout: %w", err)
		}
	}

	return nil
}

// loadInput resolves PFXIn/PEMIn into a *pki.Certificate. Exactly one must
// be set; the helper returns a user-facing error otherwise.
func loadInput(opts Options) (*pki.Certificate, error) {
	switch {
	case opts.PFXIn != "" && opts.PEMIn != "":
		return nil, errors.New("cert: --pfx and --pem are mutually exclusive")
	case opts.PFXIn != "":
		data, err := os.ReadFile(opts.PFXIn)
		if err != nil {
			return nil, fmt.Errorf("cert: read pfx: %w", err)
		}
		cert, err := pki.LoadPFX(data, opts.PFXInPassword)
		if err != nil {
			if opts.PFXInPassword == "" && isEncryptedPFXErr(err) {
				return nil, errors.New("cert: PFX password required for encrypted input")
			}
			return nil, fmt.Errorf("cert: load pfx: %w", err)
		}
		return cert, nil
	case opts.PEMIn != "":
		data, err := os.ReadFile(opts.PEMIn)
		if err != nil {
			return nil, fmt.Errorf("cert: read pem: %w", err)
		}
		cert, err := pki.ParsePEM(data)
		if err != nil {
			return nil, fmt.Errorf("cert: parse pem: %w", err)
		}
		return cert, nil
	default:
		return nil, errors.New("cert: one of --pfx or --pem is required")
	}
}

// emitExtracted writes only the requested PEM block kind (PRIVATE KEY or
// CERTIFICATE) to the configured sink. For the key path we reuse
// pki.EncodePEM by zeroing the cert; for the cert path we encode raw DER
// directly so we don't pay the RSA PKCS#8 marshal cost a second time.
func emitExtracted(cert *pki.Certificate, kind string, opts Options, stdout io.Writer) error {
	var out []byte

	switch kind {
	case "PRIVATE KEY":
		if cert.Key == nil {
			return errors.New("cert: no private key found in input")
		}
		keyOnly := &pki.Certificate{Key: cert.Key}
		data, err := pki.EncodePEM(keyOnly)
		if err != nil {
			return fmt.Errorf("cert: encode private key: %w", err)
		}
		out = data
	case "CERTIFICATE":
		if cert.Cert == nil {
			return errors.New("cert: no certificate found in input")
		}
		var buf bytes.Buffer
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Cert.Raw}); err != nil {
			return fmt.Errorf("cert: encode certificate: %w", err)
		}
		out = buf.Bytes()
	default:
		return fmt.Errorf("cert: unknown extract kind %q", kind)
	}

	// Prefer explicit PEMOut, then generic Out, else stdout (unless NoOut).
	target := opts.PEMOut
	if target == "" {
		target = opts.Out
	}
	if target != "" {
		if err := os.WriteFile(target, out, 0o600); err != nil {
			return fmt.Errorf("cert: write output: %w", err)
		}
		return nil
	}

	if opts.NoOut {
		return nil
	}
	if _, err := stdout.Write(out); err != nil {
		return fmt.Errorf("cert: write stdout: %w", err)
	}
	return nil
}

// isEncryptedPFXErr sniffs the go-pkcs12 error text for the signal that
// decryption failed. The library doesn't export a typed error, so we rely
// on substring matching of its wrapped error chain.
func isEncryptedPFXErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "incorrect password") ||
		strings.Contains(msg, "decryption password") ||
		strings.Contains(msg, "mac verification")
}
