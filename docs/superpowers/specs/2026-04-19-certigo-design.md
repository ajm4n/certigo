# Certigo — Go 1:1 Port of Certipy

**Status:** Draft for review
**Date:** 2026-04-19
**Owner:** aj.hammond@praetorian.com
**Repo (pending):** `github.com/ajm4n/certigo`
**Source of truth:** `certipy-ad` v5.0.3 (ly4k)

## Goal

Ship a pure-Go, single-binary replacement for Python `certipy-ad` with full feature parity across all twelve subcommands and bit-for-bit output compatibility. Replace day-to-day use of `certipy` on engagements with a tool that cross-compiles to `linux/{amd64,arm64}`, `windows/{amd64,arm64}`, and `darwin/{amd64,arm64}` from a single source tree.

## Non-goals

- General-purpose NTLM relay framework (`relay` is scoped to AD CS targets only — matching Certipy).
- A library API with API stability guarantees before v1.0 (`pkg/certigo` exists but is unstable until v1).
- Windows `ptt` LSA injection parity on non-Windows hosts (Linux/darwin `ptt` writes ccache only).
- New features beyond what Certipy 5.0.3 ships. Scope is *port*, not *extend*.

## Success criteria

1. Every Certipy 5.0.3 subcommand and every documented flag has a corresponding `certigo` implementation.
2. Parity harness reports ≥95% bit-for-bit output match per subcommand against a live AD CS lab.
3. Single binary, no cgo, no runtime dependencies. `go build ./cmd/certigo` on any supported host produces a working binary for any supported target.
4. CI green across all six OS/arch combinations on every PR.
5. User can replace `certipy` with `certigo` in existing wrapper scripts and pipelines without changes.

## Architectural principles

- **Own the stack.** We write our own Kerberos PKINIT/U2U, our own SPNEGO bridge, our own ASN.1 helpers for AD CS quirks. Reuse high-quality primitives (`gokrb5`, `go-ldap`, `go-msrpc`, stdlib crypto, `go-pkcs12`) but do not add libraries whose release cadence we don't control.
- **No cgo.** Static binaries only. This constraint is non-negotiable — it is the reason the port exists.
- **Bit-for-bit parity first, modernization later.** Default output matches Certipy exactly. A `--modern` opt-in may later improve formatting without breaking the default.
- **Small, focused packages.** Each `internal/*` package has one responsibility and a narrow public API. Subcommands compose them.
- **Evidence before claims.** Parity is proven by the harness, not asserted.

## Library selections

| Concern | Choice | Rationale |
|---|---|---|
| Kerberos | `jcmturner/gokrb5` base + in-house PKINIT / U2U / ccache / kirbi | Full pure-Go, no cgo; we control the hard offensive bits ourselves |
| LDAP | `go-ldap/ldap/v3` + in-house SPNEGO/GSSAPI bridge | Standard client, unified with our Kerberos stack |
| DCE/RPC | `oiweiwei/go-msrpc` as baseline; hand-roll gaps (ICertPassage, uncovered ICertAdminD2 methods) | Best-in-class Go MSRPC coverage; fill only what's missing |
| Crypto / X.509 / PFX | Go stdlib + `software.sslmate.com/src/go-pkcs12` + hand-rolled ASN.1 (`encoding/asn1` + `cryptobyte`) | Covers 95%; ASN.1 helpers for PKINIT AuthPack, CMS SignedData, NTDS-CA-Security-Ext SID, forge extensions |
| CLI | `spf13/cobra` | Industry standard, subcommands + completion + help out of the box |
| Config | `gokrb5` built-in `krb5.conf` reader + `KRB5CONF` env override | Matches Impacket/MIT discovery conventions |
| Ticket cache | In-house MIT ccache + kirbi writer/reader; `KRB5CCNAME` env support | Drop-in compatible with Impacket + OS tools |

## Repo layout

```
certigo/
├── cmd/certigo/              # single binary entrypoint; cobra root
├── internal/
│   ├── auth/                 # unified credential type + acquisition
│   │   ├── krb/              # gokrb5 wrapper, PKINIT, U2U, S4U, ccache/kirbi I/O
│   │   ├── ntlm/             # NTLMv2 client (LDAP, HTTP, RPC, relay)
│   │   └── spnego/           # SPNEGO wrapper shared by LDAP + MSRPC + HTTP
│   ├── ldap/                 # go-ldap/v3 wrapper; GSSAPI/SASL binds over TLS
│   ├── rpc/                  # go-msrpc glue + ICertPassage/ICertAdminD2 gap fillers
│   ├── pki/                  # X.509, CSR builder, PFX r/w, ASN.1 helpers
│   ├── adcs/                 # LDAP query layer: CAs, templates, enrollment rights, ACLs
│   ├── esc/                  # ESC1..16 detection rules (one file per ESC)
│   ├── coerce/               # PetitPotam, DFSCoerce, PrinterBug (used by relay)
│   ├── output/               # text / JSON / zip / BloodHound emitters (parity formatters)
│   └── target/               # DNS/SRV resolution, -dc-ip, -ns, target parsing
├── pkg/certigo/              # exported API (unstable until v1; optional library use)
├── test/
│   ├── unit/                 # Go unit tests (co-located with packages is preferred; this is for integration)
│   ├── parity/               # shell + Go harness comparing certipy vs certigo
│   └── fixtures/             # captured LDAP replies, RPC pcaps, HTTP enroll traces
├── tools/
│   └── capture/              # one-shot script to dump sanitized fixtures from user's GOAD
├── lab/
│   ├── docker/               # compose.yml: samba-ad-dc + mock-adcs containers
│   └── vm/                   # packer template for Windows Server 2022 Eval + AD CS
├── docs/                     # per-subcommand usage docs; matches man pages
├── .github/workflows/        # ci.yml, release.yml, parity.yml (opt-in)
├── CHANGELOG.md
├── LICENSE                   # MIT (match certipy-ad)
├── README.md
└── go.mod                    # go 1.22
```

### Package responsibilities

- **`internal/auth`** — one `Credentials` struct carrying all auth modes (password, NT hash, Kerberos TGT, certificate/PFX). Exposes `LDAPBinder()`, `RPCAuth()`, `HTTPTransport()` so every network layer uses the same credentials the same way.
- **`internal/auth/krb`** — AS-REQ, TGS-REQ, PKINIT (PA-PK-AS-REQ/REP + DH key derivation), U2U, S4U2Self/Proxy, ccache/kirbi I/O.
- **`internal/auth/ntlm`** — NTLMv2 client (~400 LoC); reused by LDAP signed binds, HTTP basic-auth alternative, RPC, relay.
- **`internal/auth/spnego`** — NegTokenInit / NegTokenResp wrappers; consumes either Kerberos AP-REQ or NTLM.
- **`internal/ldap`** — SASL bind selector; TLS channel binding; paging; modify/add/delete helpers.
- **`internal/rpc`** — binding builder (NCACN_IP_TCP, NCACN_NP), SPNEGO integration, RPC clients for: ICPR, ICertRequestD2, ICertAdminD2, ICertPassage, IWbemServices (DCOM).
- **`internal/pki`** — X.509 parsing/building, CSR builder with arbitrary extension encoding (SAN, SID OID, OID application policies), PFX read/write with Impacket-compatible parameters, ASN.1 for PKINIT AuthPack and CMS SignedData, cert forging primitives.
- **`internal/adcs`** — LDAP queries for pKIEnrollmentService objects (CAs), pKICertificateTemplate objects, enrollment ACLs on templates and CAs.
- **`internal/esc`** — one file per ESC rule (`esc1.go`..`esc16.go`). Each exports `Check(tpl *Template, ca *CA, acls *ACLs) []Finding`.
- **`internal/coerce`** — coercion RPC clients. One file per technique: `petitpotam.go` (EfsRpc), `dfscoerce.go` (NetrDfsRemoveStdRoot), `printerbug.go` (RpcRemoteFindFirstPrinterChangeNotificationEx).
- **`internal/output`** — golden-file-tested formatters. Matches Certipy text output line-for-line, JSON keys byte-for-byte, zip archives identically structured; BloodHound community-edition format (CEs = cert-abuse edges).
- **`internal/target`** — resolver: `-dc-ip`, `-ns`, SRV lookups for KDC, CNAME handling for CA DNS names.

## Subcommand mapping

| Certigo subcommand | Certipy parity surface | Primary internals |
|---|---|---|
| `find` | Enum CAs + templates via LDAP, ESC1-16 detection, text/JSON/zip/BloodHound, CA cert retrieval via RPC/DCOM, `-stdout`, `-dc-only`, `-vulnerable`, `-hide-admins`, `-sid` | `adcs`, `esc`, `ldap`, `rpc`, `output` |
| `req` | Request cert via RPC (ICPR/ICertRequestD2), Web (`certsrv`), DCOM, KDCEPROXY, Schannel; ESC1 SAN; `-on-behalf-of`, `-archive-key`, `-pfx-cert`, `-key-size`, `-retrieve`, `-renew` | `rpc`, `pki`, `auth`, HTTP |
| `auth` | PKINIT → TGT, unPAC-the-hash, Schannel LDAPS auth + NT hash extraction, `-ldap-shell`, `-kirbi`, `-print` | `auth/krb`, `ldap`, `pki` |
| `shadow` | `msDS-KeyCredentialLink` auto/add/list/clear/info/remove via LDAP, key-pair gen, key-credential ASN.1 | `ldap`, `pki` |
| `forge` | Read CA cert+key from PFX, forge cert with arbitrary SAN/SID/EKU, `-subject`, `-serial`, `-crl`, `-extensions` | `pki` |
| `ca` | `-backup`, `-list-templates`, `-list-officers`, `-add-officer`, `-remove-officer`, `-add-template`, `-enable-template`, `-disable-template`, `-issue-request`, `-deny-request`, officer flags, ACL edits | `rpc` (ICertAdminD2), `ldap`, `pki` |
| `template` | Read / write / backup template objects via LDAP (ESC4 write), `-save-old`, `-configuration` | `ldap` |
| `account` | Add/modify/delete computer or user via LDAP (`-user create`, `-user update`, `-dns`, `-spn`, `-upn`), MachineAccountQuota respect | `ldap` |
| `cert` | PFX ↔ PEM conversion, `-export`, `-extract`, `-key`, `-pfx`, `-pem`, passphrase handling | `pki` |
| `parse` | Read PKIAUTHEVENTS EVTX, read registry hives for CA config (offline forensics) | pure `pki` + local EVTX / hive parsers |
| `ptt` | Write ccache everywhere; inject into LSA on Windows only (via `golang.org/x/sys/windows` LSA calls) | `auth/krb` |
| `relay` | HTTP/HTTPS listener, NTLM relay → AD CS `/certsrv/` or ICPR RPC; coercion helpers (PetitPotam, DFSCoerce, PrinterBug); **AD CS targets only** | `auth/ntlm`, `rpc`, HTTP, `coerce` |

### CLI

`cobra` root `certigo`. Subcommand flags match Certipy's long names, short names, and defaults. Global flags (`-debug`, `-timeout`, `-dc-ip`, `-ns`, `-dns-tcp`) are inherited by all subcommands. Help strings are copied from Certipy where the text is functionally identical.

Binary name: `certigo`. (Users can symlink `certipy -> certigo` for muscle memory; we don't ship it to avoid name collision with `certipy-ad` when both are installed.)

### Auth flow

1. `auth.ParseFlags(cmd)` turns CLI flags into one `Credentials`.
2. If `-pfx` given, load PFX → materialize certificate.
3. If Kerberos required (`-k`, or implied by `-pfx`): `krb.GetTGT(creds)` runs AS-REQ or PKINIT. Ticket written to `$KRB5CCNAME` if set.
4. Callers obtain bound objects: LDAP connection, RPC binding, HTTP transport — all authed from the same `Credentials`.
5. `KRB5CONF` and `/etc/krb5.conf` drive realm/KDC discovery; `KRB5CCNAME` drives ticket cache I/O.

## Testing strategy

Three-tier local harness. User never shares lab access.

### Tier 1 — Fixture replay (CI-mandatory)

- `test/fixtures/` holds recorded LDAP replies, RPC pcaps, HTTP enrollment captures — produced once by `tools/capture/` run against user's own GOAD and committed (sanitized).
- `internal/ldap/mock`, `internal/rpc/mock`, and `httptest`-based HTTP mocks replay the fixtures.
- Covers: all of `find`, `esc/*`, `output`, `cert`, `forge`, `parse`, `pki` round-trips, ASN.1, PFX, ccache/kirbi I/O — roughly 70% of certigo.
- Runs in `go test ./...`. Seconds. Zero external deps. Required for every PR.

### Tier 2 — `docker compose` lab (one command, opt-in)

- `lab/docker/compose.yml` launches:
  - `samba-ad-dc` — real LDAP / Kerberos / DNS.
  - `mock-adcs` — in-repo Go service exposing fake `/certsrv/` + ICPR RPC + DCOM endpoints backed by replay corpus; returns pre-baked certs (no live CA signing).
- Covers: `auth` (real PKINIT against Samba), `shadow`, `account`, `template`, `ca`, Kerberos TGT/S4U, NTLM, partial `req`, partial `relay`.
- `make parity-docker` exercises every subcommand that doesn't need a real Windows CA.

### Tier 3 — Windows VM (manual, release-only)

- `lab/vm/` packer template builds Windows Server 2022 Eval arm64 under `qemu-system-aarch64` / UTM.
- Provisioning: AD DS + AD CS + deliberately vulnerable template set (ESC1/2/3/4 baseline).
- First boot: 10-20 minutes; cached thereafter.
- Covers: real `req` issuance, real Schannel, real ICPR/ICertAdminD2 against Microsoft code, `relay` smoke test.
- Invoked via `make lab` when adding a Windows-path feature or tagging a release.

### Parity harness

- `test/parity/` is directory-per-subcommand. Each test runs both `certipy <args>` and `certigo <args>`, captures stdout/stderr/exit/files, diffs with a per-test allowlist (strips timestamps, random serials, nonces).
- Output: `test/parity/report.md` with per-subcommand pass/fail and diff snippets.
- Ship when a subcommand is ≥95% parity; 100% is the target for v1.0.

### Unit coverage targets

- 80% for `pki`, `esc`, `output` (deterministic, fixture-driven).
- Lower for `auth/krb`, `rpc`, `relay` — those lean on Tier 2/3 for end-to-end coverage.

## CI & release

**`.github/workflows/ci.yml`** (every PR):
- `go vet`, `go test ./...`, `golangci-lint run`.
- Build matrix: `linux/{amd64,arm64}`, `windows/{amd64,arm64}`, `darwin/{amd64,arm64}`.
- Fails if any target fails to build.

**`.github/workflows/release.yml`** (on tag `v*`):
- `goreleaser` builds all six targets, checksums, SBOM, SLSA provenance.
- Publishes to GitHub Releases with changelog excerpt.

**`.github/workflows/parity.yml`** (manual / nightly, opt-in):
- Requires a self-hosted runner with access to a lab. Not required for contributors.
- Writes parity report artifact.

## Milestones

Each milestone ends with a tagged release, updated `CHANGELOG.md`, and an updated parity report.

| Milestone | Tag | Scope |
|---|---|---|
| M0 | v0.0.1 | Scaffold: repo, cobra root, CI green, all 12 subcommands stubbed |
| M1 | v0.1.0-alpha | `internal/auth` (AS-REQ/TGS-REQ/NTLM/SPNEGO/ccache/kirbi), `internal/ldap`, `internal/rpc`. No user-facing subcommands yet; Tier 1 + Tier 2 tests green |
| M2 | v0.1.0 | `find` with full ESC1-16 detection and all output formats. First shippable tool. |
| M3 | v0.2.0 | PKINIT + `auth` + `cert` + `shadow`. Core offensive path: find → shadow → auth |
| M4 | v0.3.0 | `req` + `forge`. ESC1/2/3/6/9/10 end-to-end |
| M5 | v0.4.0 | `ca` + `template` + `account`. ESC4/5/7 end-to-end |
| M6 | v0.5.0 | `ptt` + `parse` |
| M7 | v1.0.0 | `relay` + coercion + full parity harness green |

## Deliverables at v1.0.0

- Static Go binaries for `linux/{amd64,arm64}`, `windows/{amd64,arm64}`, `darwin/{amd64,arm64}` on GitHub Releases.
- SHA-256 checksums + SLSA provenance.
- `README.md` with install instructions, feature matrix, migration guide from `certipy`.
- `docs/` containing per-subcommand reference pages.
- `CHANGELOG.md` tracking every version back to v0.0.1.
- `test/parity/report.md` showing ≥95% bit-for-bit parity against Certipy 5.0.3.
- `tools/capture/` fixture-capture script so users can regenerate fixtures against their own lab.

## Out-of-scope / explicitly deferred

- A library API with stability guarantees (`pkg/certigo` may change until v1.0).
- Relay to targets other than AD CS (LDAP relay, SMB relay, etc.) — Certipy doesn't do this either.
- Windows `ptt` via `LsaCallAuthenticationPackage` on hosts without `golang.org/x/sys/windows` availability.
- UI/TUI.
- Self-updating binary.
- Detection-evasion enhancements beyond what Certipy already does.

## Risks

1. **PKINIT complexity.** Pure-Go PKINIT doesn't exist as a drop-in library. Mitigation: M1 budgets 3 weeks; if blocked, fallback options include (a) vendoring a Go PKINIT fork if one emerges, (b) piecewise porting impacket's ASN.1 definitions verbatim.
2. **go-msrpc gap coverage.** ICertPassage and some ICertAdminD2 methods may not be exposed. Mitigation: Q4=C — we hand-roll gaps using go-msrpc's lower-level NDR primitives.
3. **Fixture drift.** If certipy-ad ships a 5.0.4 with format changes, our fixtures go stale. Mitigation: `tools/capture/` makes re-baselining a one-command operation; we pin against a specific certipy-ad version in CI.
4. **Windows LSA for `ptt`.** `golang.org/x/sys/windows` LSA wrappers may be incomplete. Mitigation: accept Linux-only `ptt` if needed and document; add Windows support in a point release.
5. **Scope creep.** Certipy gets new ESCs periodically. Mitigation: we freeze parity against 5.0.3; new ESCs are v1.x features, not blockers for v1.0.

## Open questions

None at time of spec write — all Q1-Q9 resolved. Later review may surface implementation-level uncertainties that should be captured as design updates.
