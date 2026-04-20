# Changelog

All notable changes to Certigo are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-04-20

### Added
- **`certigo find`** — first end-to-end user-facing subcommand. Enumerates AD CS CAs and templates via LDAP, runs ESC1-16 detection, renders output in four formats.
- `internal/adcs` — LDAP enumeration of pKIEnrollmentService + pKICertificateTemplate with attribute parsing (ms-PKI flags, validity/renewal FILETIME deltas) and nTSecurityDescriptor ACE extraction.
- `internal/esc` — ESC1 through ESC11 + ESC13-16 detection rules. Each rule is a pluggable `Rule` implementation with its own file. ESC5/8-11/13-16 tagged as "probe-dependent" where runtime info is missing.
- `internal/output` — four formatters: `text` (Certipy-style section layout), `json` (snake_case structured), `zip` (bundle with per-CA certs + per-template JSON), `bloodhound` (BloodHound CE OpenGraph edges / nodes, ADCSESC1..16 kinds).

### Changed
- `cmd/certigo/find.go` upgraded from stub to full orchestrator wiring auth, LDAP, adcs, esc, and output.

## [0.1.0-alpha3] - 2026-04-20

### Added
- `internal/auth/krb` — Kerberos wrapper around `jcmturner/gokrb5/v8`: `LoadConfig` (KRB5CONF / `/etc/krb5.conf` / synthesized-in-memory), `NewClient` (password + NT-hash paths), `GetTGT`, `GetTGTFromCCache`, `SaveTGTToCCache` (hand-written MIT ccache v4 marshaler).
- `internal/auth/krb` kirbi codec — `ReadKirbi`, `WriteKirbi`, `CCacheToKirbi`, `KirbiToCCache` (ASN.1 KRB_CRED / EncKrbCredPart via gokrb5 messages).
- `internal/auth/spnego` — `Negotiator` interface with NTLM (`NewNTLM`) and gokrb5-backed Kerberos (`NewKerberos`) implementations; reusable across LDAP, HTTP, RPC.
- `internal/ldap` — `Dial` + credential-driven `Bind` selecting Simple / NTLM / `NTLMBindWithHash` / GSSAPI-SPNEGO based on `Credentials`. Cert-based LDAPS deferred to M3.

### Changed
- Go toolchain bumped to 1.24 (gokrb5 dep chain requirement).
- CI and goreleaser workflows updated to Go 1.24.

## [0.1.0-alpha2] - 2026-04-20

### Added
- `internal/auth.Credentials` — unified credential type for password / NT hash / PFX / ccache auth modes with `Validate`, `HasPassword`, `HasNTHash`, `HasCertificate`, `HasKerberosTicket` helpers.
- `internal/auth.ParseHashes` — parses `LMHASH:NTHASH` flag values.
- `internal/pki` package — `Certificate` type, `GenerateRSAKey` (2048/3072/4096), `LoadPFX`/`SavePFX` (go-pkcs12 Modern2023 + Legacy fallback), `ParsePEM`/`EncodePEM` (PKCS#1/#8/SEC1), `BuildCSR` with combined DNS + UPN SAN extensions (UPN OID `1.3.6.1.4.1.311.20.2.3`).
- `lab/docker/` — docker-compose test environment: `instantlinux/samba-dc` AD DC + in-repo Go `mock-adcs` HTTP stub. Makefile targets `lab-up`/`lab-down`/`lab-destroy`/`lab-logs`.

## [0.1.0-alpha1] - 2026-04-20

### Added
- `internal/auth/ntlm` — pure-Go NTLMv2 client library.
- MS-NLMP §4.2 golden vectors covering NTOWFv2, NTLMv2 response, LMv2 response, SessionBaseKey.
- NEGOTIATE/CHALLENGE/AUTHENTICATE message codec with security-buffer + AV_PAIR handling.
- Client handshake with optional signing/sealing and key derivation.

## [0.0.1] - 2026-04-19

### Added
- Project scaffold: cobra CLI with stubs for all 12 subcommands.
- Module path `github.com/ajm4n/certigo`.
- CI matrix across `linux/{amd64,arm64}`, `windows/{amd64,arm64}`, `darwin/{amd64,arm64}`.
- goreleaser v2 release pipeline.
- MIT LICENSE.
