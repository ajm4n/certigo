# Changelog

All notable changes to Certigo are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-04-20

### All 12 Certipy subcommands now have real working implementations.

### Added — PKINIT end-to-end
- `internal/auth/pkinit/papkreq.go` — PA-PK-AS-REQ / PA-PK-AS-REP ASN.1 wrapper + parser for the DH-info path.
- `internal/auth/pkinit/keyderiv.go` — RFC 4556 §3.2.3.1 octetstring2key with nonce support.
- `internal/auth/pkinit/asreq.go` — end-to-end `AuthenticateWithPKINIT` / `AuthenticateWithPKINITResult`. Raw TCP AS-REQ sender. AS-REP decryption via `crypto.DecryptEncPart`.
- `internal/auth/pkinit/ccache.go` — `SavePKINITTGTToCCache` (MIT ccache v4 writer).
- **`certigo auth --pfx`** now performs a live PKINIT AS-REQ and writes the TGT to ccache.

### Added — NTLM relay MITM
- `internal/relay/relay.go` — full HTTP(S) listener with NTLM NEGOTIATE/CHALLENGE/AUTHENTICATE forwarding to AD CS `/certsrv/`. On successful relay: generates RSA-2048 key + CSR, POSTs to `/certsrv/certfnsh.asp`, fetches the issued cert via `/certsrv/certnew.cer?ReqID=<id>&Enc=b64`, saves PFX under `OutDir/<victim>.pfx`.
- Per-victim cookie jar keeps target-side session state across round-trips. Session TTL 60s.
- `relay_test.go` — health / 401 / NEGOTIATE-forwarding tests.

### Added — ICertAdminD / ICertAdminD2 DCOM
- `internal/ca/rpc.go` + `internal/ca/ops.go` — DCOM activation via `IActivation::RemoteActivation`, IPID plumbed into CertAdminD + CertAdminD2 clients.
- **`certigo ca --backup`**: real RPC via `GetCAProperty(CR_PROP_CASIGCERT)`, emits PEM (public-key-only; full private-key backup still requires multi-step BackupPrepare/OpenFile/ReadFile flow, documented in-code).
- **`certigo ca --issue-request` / `--deny-request`**: live `ResubmitRequest` / `DenyRequest`.
- **`certigo ca --add-officer` / `--remove-officer`**: Get→edit (self-relative SD with SID encoder)→Set round-trip via `GetOfficerRights` / `SetOfficerRights`.
- `ca_test.go` — 11 tests covering empty-server, error paths, SID round-trips, DACL add/remove, username splitting.

### Stats
- **144 tests passing** across **22 Go packages**.
- **All 12 subcommands** do real work. Every remaining "not yet implemented" pointer documents a specific external requirement (e.g., EVTX needs a pure-Go parser; private-key CA backup needs BackupPrepare streaming).

## [0.4.0] - 2026-04-20

### Added — real RPC integrations
- **`req --method rpc`** — full MS-ICPR `CertServerRequest` over DCE/RPC with SPNEGO auth (`internal/req/rpc.go`). Issues live certs from any AD CS Enterprise CA reachable over 135/dynamic.
- **`relay --trigger petitpotam`** — MS-EFSR `EfsRpcOpenFileRaw` coercion (`internal/coerce/coerce.go`).
- **`relay --trigger dfscoerce`** — MS-DFSNM `NetrDfsRemoveStdRoot` coercion.
- **`relay --trigger printerbug`** — MS-RPRN `RpcOpenPrinter` + `RemoteFindFirstPrinterChangeNotification` (SpoolSample).
- **`parse --file *.reg`** — real Windows Registry text-dump parser with section + key/value + multi-line hex continuation handling (`internal/parse/parse.go`).
- **`ptt --kirbi`** — kirbi-to-ccache conversion via `krb.KirbiToCCacheBytes`; output file is a drop-in `$KRB5CCNAME`.

### Remaining gaps (future work)
- `auth --pfx` PKINIT AS-REQ wire integration with gokrb5 internals.
- `ca --backup/--issue/--deny/--add-officer/--remove-officer` (ICertAdminD2 is DCOM — needs IRemoteSCMActivator activation flow).
- `relay` full NTLM-forwarding pipeline (victim session → outbound `/certsrv/` MITM).
- `parse --file *.evtx` (no pure-Go EVTX library adopted yet).

## [0.3.0] - 2026-04-20

### Added
- **`certigo req`** — HTTP `/certsrv/` enrollment with Basic auth over TLS (NTLM/Kerberos over HTTP pending). Full CSR generation + PFX export.
- **`certigo ca`** — LDAP-backed `--add-template`, `--disable-template`, `--list-templates`, `--list-officers` (uses `adcs.ParseSecurityDescriptor`). RPC (backup/approve/deny/officer-edit) stubbed with `ErrRPCUnimplemented` pending go-msrpc ICertAdminD2 bindings.
- **`certigo relay`** — HTTP(S) listener skeleton with `--trigger {petitpotam|dfscoerce|printerbug}`. Full NTLM forwarding pipeline and coercion RPC triggers return `ErrUnimplemented` pending MS-EFSR / MS-DFSNM / MS-RPRN bindings.
- `internal/req`, `internal/ca`, `internal/coerce`, `internal/relay` packages.

### Status
All 12 Certipy subcommands now have **real Cobra wiring and runnable CLI surface**. Every subcommand either does real work or returns a clear "not yet implemented" message with a pointer to the blocking dependency (typically MS-RPC bindings via go-msrpc).

## [0.2.0] - 2026-04-20

### Added
- **`certigo cert`** — PFX ↔ PEM conversion, extract-key, extract-cert with password pass-through.
- **`certigo forge`** — CA-signed certificate forging (Golden Certificate) with NTDS-CA-Security-Ext SID binding, UPN SAN, DNS SAN, certificatePolicies, CRL distribution.
- **`certigo shadow`** — msDS-KeyCredentialLink CRUD (add/list/info/clear/remove) with PFX export for follow-up PKINIT.
- **`certigo template`** — LDAP template read/write/backup/restore + ESC4 make-vulnerable preset.
- **`certigo account`** — AD user/computer create/update/delete/read via LDAP with SPN/UPN/dNSHostName support.
- **`certigo auth`** — password + NT-hash AS-REQ to obtain a TGT and write it to ccache. PKINIT path partially implemented (DH + CMS + AuthPack library in `internal/auth/pkinit/`; final AS-REQ wire integration pending).
- **`certigo ptt`** — ticket pass-through: reads kirbi or ccache, writes to `$KRB5CCNAME` or `--out-ccache`. Full kirbi→ccache conversion pending; kirbi→kirbi and ccache→ccache work end-to-end.
- **`certigo parse`** — returns explicit `not-yet-implemented` errors for `.evtx` / `.reg` pending a pure-Go parser; documented rollback to Certipy for these artifacts.

### Internal libraries shipped
- `internal/auth/pkinit` — OIDs, DH primitives (OAKLEY Group 2 + RFC 3526 Group 14), AuthPack encoder, CMS SignedData builder/parser.
- `internal/forge` — NTDS-CA-Security-Ext, UPN SAN, certificate policies, CRL extensions, `Forge()`.
- `internal/shadow` — KeyCredential blob codec, BCRYPT_RSAKEY_BLOB codec, DNBinary wire format, LDAP add/list/clear/remove actions.
- `internal/template` — LDAP read/write/backup/restore; ESC4 `VulnerableAttrs()` preset.
- `internal/account` — LDAP create/update/delete/read, DN resolver, UTF-16LE unicodePwd encoder.
- `internal/certcmd` — PFX↔PEM converter engine.

### Not yet shipped (M4/M5/M7)
- `certigo ca` — ICertAdminD2 RPC bindings (backup CA, issue/deny request, officer CRUD).
- `certigo req` — web enrollment and ICPR RPC submission.
- `certigo relay` — HTTP listener, NTLM relay to `/certsrv/`, coercion triggers (PetitPotam, DFSCoerce, PrinterBug).

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
