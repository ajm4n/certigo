# Changelog

All notable changes to Certigo are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [Unreleased]

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
