package output

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ajm4n/certigo/internal/adcs"
)

// ZipFormatter bundles the text report, the JSON report, each CA's DER
// certificate, and a per-template JSON breakdown into a single zip archive.
// The layout mirrors Certipy's `find -output <prefix>` zip idea with certigo
// branding:
//
//	certigo_find.txt
//	certigo_find.json
//	ca/<caname>.crt
//	templates/<template>.json
type ZipFormatter struct{}

// Name returns the format identifier.
func (ZipFormatter) Name() string { return "zip" }

func init() { register(ZipFormatter{}) }

// Format writes a zip archive to w.
func (ZipFormatter) Format(w io.Writer, cas []*adcs.CertificateAuthority, templates []*adcs.Template) error {
	zw := zip.NewWriter(w)

	// 1. certigo_find.txt — the text report.
	var textBuf bytes.Buffer
	if err := (TextFormatter{}).Format(&textBuf, cas, templates); err != nil {
		return fmt.Errorf("output/zip: render text: %w", err)
	}
	if err := writeZipFile(zw, "certigo_find.txt", textBuf.Bytes()); err != nil {
		return err
	}

	// 2. certigo_find.json — the JSON report.
	var jsonBuf bytes.Buffer
	if err := (JSONFormatter{}).Format(&jsonBuf, cas, templates); err != nil {
		return fmt.Errorf("output/zip: render json: %w", err)
	}
	if err := writeZipFile(zw, "certigo_find.json", jsonBuf.Bytes()); err != nil {
		return err
	}

	// 3. ca/<name>.crt — one DER cert per CA that has a Certificate.
	for _, ca := range cas {
		if ca == nil || ca.Certificate == nil {
			continue
		}
		path := "ca/" + sanitizeFilename(ca.Name) + ".crt"
		if err := writeZipFile(zw, path, ca.Certificate.Raw); err != nil {
			return err
		}
	}

	// 4. templates/<name>.json — one JSON blob per template.
	for _, t := range templates {
		if t == nil {
			continue
		}
		blob, err := json.MarshalIndent(templateToJSON(t), "", "  ")
		if err != nil {
			return fmt.Errorf("output/zip: marshal template %q: %w", t.Name, err)
		}
		path := "templates/" + sanitizeFilename(t.Name) + ".json"
		if err := writeZipFile(zw, path, blob); err != nil {
			return err
		}
	}

	if err := zw.Close(); err != nil {
		return fmt.Errorf("output/zip: close archive: %w", err)
	}
	return nil
}

func writeZipFile(zw *zip.Writer, name string, data []byte) error {
	f, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("output/zip: create %q: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("output/zip: write %q: %w", name, err)
	}
	return nil
}

// sanitizeFilename replaces characters that are awkward on common filesystems
// (Windows especially) with underscores. Names are compared case-sensitively
// inside zip archives so we keep the original casing.
func sanitizeFilename(s string) string {
	if s == "" {
		return "unnamed"
	}
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return replacer.Replace(s)
}
