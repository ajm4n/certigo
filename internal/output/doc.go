// Package output renders certigo's `find` enumeration results in a set of
// complementary formats: a human-readable text report modelled after
// Certipy's default pretty-printed output, a machine-friendly JSON document,
// a zip bundle combining both plus per-CA certificates, and a BloodHound CE
// OpenGraph edge set suitable for ingestion into the BloodHound UI.
//
// The Formatter interface is the single extension point. Each formatter
// consumes a slice of *adcs.CertificateAuthority and *adcs.Template (with
// ESC findings already attached by internal/esc) and writes a complete
// document to an io.Writer in one shot.
//
// Field names and layout deliberately track Certipy's `find` output so that
// downstream tooling (BloodHound plugins, report generators, diff harnesses)
// can treat certigo as a drop-in replacement.
package output
