# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-05-17

The v0.6.0 release aligns mcp-aguara with the Aguara v0.17.0 backend. It is a maintenance + hardening release: no new MCP tools, no change to the existing tools' input schemas, no breaking change to the binary name. What changes is the surface mcp-aguara accurately advertises, the redaction guarantee on tool output, and the trust artifacts on the release pipeline.

### Aligned

- **Aguara core v0.14.4 -> v0.17.0.** Aguara core v0.17.0 ships three relevant changes: multi-ecosystem threat intel (npm, PyPI, Go, crates.io, Packagist, RubyGems, Maven, NuGet) from an OSV-derived snapshot for repository-wide dependency checks via the CLI, analyzer-emitted rule metadata via the rulecatalog (jsrisk / toxicflow / pkgmeta / ci-trust / NLP / rug-pull), and sensitivity-based in-place redaction of `Finding.MatchedText`. The MCP inherits the rulecatalog (now resolvable via `explain_rule`) and the in-place redaction (mirrored by the MCP's defensive guard). The OSV threat-intel snapshot is **not** linked into the MCP binary because v0.6.0 does not expose `check_project` / `audit_project` MCP tools; the snapshot lives in `internal/incident` which the MCP's dependency graph does not reach. Use the Aguara CLI for repository-wide dependency checks until a future release adds the wrapping MCP tools (see Out of scope below).
- **Catalog count.** `list_rules` now returns 219 detections (193 YAML pattern rules + 26 analyzer-emitted), up from 138 in v0.5.x.
- **`explain_rule` resolves analyzer IDs.** Both YAML rule IDs and analyzer-emitted IDs (e.g. `JS_DNS_TXT_EXFIL_001`, `GHA_PWN_REQUEST_001`, `MCP_007`) now return full metadata. Previously only YAML IDs resolved.
- **Repository URL normalized to canonical.** Module path, install URL, README references, and SECURITY advisory URL now point at `github.com/garagon/mcp-aguara` (the canonical name; `aguara-mcp` was a redirect from a prior rename). The binary name (`aguara-mcp`) is unchanged so existing `claude mcp add aguara -- aguara-mcp` configurations keep working.

### Added

- **Defensive Sensitive guard in `formatScanResult`.** The MCP's output formatter now replaces `matched_text` with `[REDACTED]` whenever the finding's `Sensitive=true` flag OR `credential-leak` category is set, mirroring exactly the predicate Aguara core's `RedactSensitiveFindings` applies. Idempotent when core has already scrubbed; defense-in-depth against a future core regression or a bypass of the in-place scrub. Locked by `redaction_test.go` with five regression tests (`TestMCPFormatScanResult_RedactsSensitiveMatchedText`, `TestMCPFormatScanResult_RedactsLegacyCredentialLeakCategory`, `TestMCPFormatScanResult_RedactsSensitiveContext`, `TestMCPFormatScanResult_PreservesNonSensitiveMatchedText`, plus error-path tests `TestMCP_ErrorPath_DoesNotLeakScanContent` and `TestMCP_ErrorPath_DoesNotLeakAbsolutePaths`).
- **`.github/workflows/` filename preservation.** Aguara v0.17 registers the ci-trust analyzer which only fires when the target path contains `.github/workflows/`. `sanitizeFilename` now preserves that segment anywhere in the input (including Windows separators and repo-relative or absolute paths) while still falling back to a hardened basename strip for path traversal under the segment. Without this fix, scan_content would silently miss every `GHA_*` finding (`GHA_PWN_REQUEST_001`, `GHA_CACHE_001`, `GHA_OIDC_001`, `GHA_CHECKOUT_001`) even though `list_rules` and `explain_rule` advertised them.
- **Signed multi-arch Docker image at `ghcr.io/garagon/mcp-aguara`.** New `Dockerfile` + `.github/workflows/docker.yml` produces a `linux/amd64,linux/arm64` runtime image signed at digest with Cosign keyless OIDC, with SBOM (SPDX) and SLSA Provenance (`mode=max`) attestations attached. Base images pinned by multi-arch index digest. Runs as non-root uid 10001.
- **GoReleaser keyless signing + SBOM.** `.goreleaser.yml` adds `-trimpath` for reproducible builds, signs `checksums.txt` with Cosign keyless via the release workflow's OIDC identity, and attaches an SPDX SBOM per archive via syft.
- **End-to-end release acceptance test (`.github/scripts/verify-release.sh`).** 6/6 acceptance script: download artifacts, cosign verify-blob on checksums, sha256 match, binary `--version` matches the tag, cosign verify the Docker image, `docker pull --platform linux/${ARCH}` + run + verify SBOM and SLSA Provenance present for that platform. `--platform` is explicit so Apple Silicon Rosetta fallback cannot false-pass an arm64 verification.
- **install.sh hardening + docker test (`make test-install-sh-docker`).** `install.sh` now uses `tar -xzof` so extraction works under `--cap-drop ALL` (no CAP_CHOWN), and the checksum verification fails closed if no `sha256sum`/`shasum` is available (previously it logged a warning and installed the binary unverified). A two-stage docker target locks both contracts: happy path under `--cap-drop ALL` exits 0, and a companion image with sha256 utilities removed exits non-zero with the documented "no sha256 verifier available" message.

### Changed

- **Updated tool descriptions.** All five tools' `Description` fields now communicate the v0.17 surface accurately: `scan_content` enumerates the content types covered (skills, READMEs, tool definitions, `package.json`, `.github/workflows/*.yml`, etc.) and the redaction contract; `check_mcp_config` names what gets detected; `list_rules` reports 219 detections and lists analyzers; `explain_rule` documents the YAML-vs-analyzer metadata difference; `discover_mcp` calls out the read-only / no-network contract. Tool names, input schemas, and read-only annotations are unchanged.

### Removed

- **`make install` Makefile target.** With the canonical module path, `go install .` would have produced a `mcp-aguara` binary instead of `aguara-mcp`, breaking the documented `claude mcp add` configuration. The `install.sh` path is the supported install method.
- **`go install` from the README quick start.** Same reason: under the new module path, `go install github.com/garagon/mcp-aguara@latest` produces a binary named `mcp-aguara`, which does not match the binary name `aguara-mcp` referenced by the rest of the documentation. May return in a future release behind a `cmd/aguara-mcp/` package layout.

### Out of scope (deferred to v0.7.0)

- **`check_project` and `audit_project` MCP tools** that would wrap Aguara's `aguara check .` and `aguara audit . --ci` commands. These require Aguara core to first expose a stable public `Check` API; until then, the Aguara CLI remains the supported path for repository-wide dependency checks. Use:

  ```bash
  aguara check .          # one-shot dependency surface check
  aguara audit . --ci     # CI gate combining scan + check
  ```

- **`update_intel` MCP tool** that would refresh the embedded threat-intel snapshot at runtime. Network surface; needs the same public Check API design.
- **Restructure to `cmd/aguara-mcp/`** so `go install github.com/garagon/mcp-aguara/cmd/aguara-mcp@latest` produces the correct binary name. Mechanical change but defers to a future release where the binary name story is revisited holistically.
