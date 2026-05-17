#!/bin/sh
# verify-release.sh - Acceptance test for a published mcp-aguara release.
#
# Validates from a clean machine that the artifacts at
# github.com/garagon/mcp-aguara and ghcr.io/garagon/mcp-aguara for
# the given VERSION are:
#   1. signed by the release workflow (cosign verify-blob, cosign verify image)
#   2. consistent with their checksums (sha256 -c)
#   3. functionally working (aguara-mcp --version)
#
# Required tools: curl, tar, sha256sum or shasum, cosign, docker, jq.
# Auto-detects the host OS/arch for the binary download and pulls the
# matching Docker image manifest.
#
# Usage:
#   VERSION=v0.6.0 .github/scripts/verify-release.sh
#
# Exits 0 if every check passes, 1 on the first failure with a clear message.
set -eu

REPO="garagon/mcp-aguara"
IMAGE="ghcr.io/${REPO}"
VERSION="${VERSION:?VERSION env var required, e.g. VERSION=v0.6.0}"
VERSION_STRIPPED="${VERSION#v}"

green() { printf '\033[1;32m%s\033[0m\n' "$1"; }
red() { printf '\033[1;31m%s\033[0m\n' "$1" >&2; }
info() { printf '  %s\n' "$1"; }
err() { red "FAIL: $1"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "required tool not found: $1"; }

case "$(uname -s)" in
    Linux)  OS=linux ;;
    Darwin) OS=darwin ;;
    *) err "unsupported OS: $(uname -s)" ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) err "unsupported arch: $(uname -m)" ;;
esac

ARCHIVE="aguara-mcp_${VERSION_STRIPPED}_${OS}_${ARCH}.tar.gz"
# Used to scope multi-arch docker pulls / attestation lookups so the
# verification fails when the host-arch manifest is missing or when
# Apple Silicon falls back to emulating linux/amd64 under Rosetta.
PLATFORM="linux/${ARCH}"

need curl; need tar; need cosign; need docker; need jq
if command -v sha256sum >/dev/null 2>&1; then
    SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA="shasum -a 256"
else
    err "no sha256 tool (need sha256sum or shasum)"
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

green ">> 1/6 download release artifacts"
DOWNLOAD_BASE="https://github.com/${REPO}/releases/download/${VERSION}"
curl -fsSL --max-time 120 --retry 3 -O "${DOWNLOAD_BASE}/${ARCHIVE}" || err "archive download failed"
curl -fsSL --max-time 30  --retry 3 -O "${DOWNLOAD_BASE}/checksums.txt" || err "checksums download failed"
curl -fsSL --max-time 30  --retry 3 -O "${DOWNLOAD_BASE}/checksums.txt.bundle" || err "cosign bundle download failed"
info "downloaded: ${ARCHIVE} + checksums.txt + checksums.txt.bundle"

green ">> 2/6 cosign verify-blob (checksums.txt signed by release workflow)"
cosign verify-blob \
    --bundle checksums.txt.bundle \
    --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    checksums.txt >/dev/null || err "cosign verify-blob failed"
info "checksums.txt signature verified"

green ">> 3/6 sha256 of archive matches signed checksums"
EXPECTED=$(grep " ${ARCHIVE}$" checksums.txt | awk '{print $1}')
[ -n "$EXPECTED" ] || err "checksum entry for ${ARCHIVE} missing from checksums.txt"
ACTUAL=$($SHA "${ARCHIVE}" | awk '{print $1}')
[ "$ACTUAL" = "$EXPECTED" ] || err "sha256 mismatch: expected $EXPECTED got $ACTUAL"
info "sha256 ok: ${EXPECTED}"

green ">> 4/6 binary works and reports the right version"
tar -xzof "${ARCHIVE}"
[ -x ./aguara-mcp ] || err "binary not extracted or not executable"
# main.go prints `aguara-mcp <version>` so awk picks the second field.
BINARY_VERSION=$(./aguara-mcp --version | awk 'NR==1 {print $2}')
[ "$BINARY_VERSION" = "$VERSION_STRIPPED" ] || err "binary reports version '${BINARY_VERSION}', expected '${VERSION_STRIPPED}'"
info "binary version: ${BINARY_VERSION}"

green ">> 5/6 cosign verify Docker image"
cosign verify "${IMAGE}:${VERSION_STRIPPED}" \
    --certificate-identity "https://github.com/${REPO}/.github/workflows/docker.yml@refs/tags/${VERSION}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" >/dev/null 2>&1 \
    || err "cosign verify image failed"
info "image signature verified"

green ">> 6/6 Docker image runs natively on host arch and reports the right version"
# Force --platform so a missing linux/${ARCH} manifest cannot pass via
# Apple Silicon's Rosetta fallback to linux/amd64, and so a globally
# set DOCKER_DEFAULT_PLATFORM does not silently change what gets
# verified. The pull explicitly fails when the manifest is absent.
docker pull --platform "$PLATFORM" "${IMAGE}:${VERSION_STRIPPED}" >/dev/null 2>&1 \
    || err "docker pull --platform ${PLATFORM} failed (image likely missing the ${PLATFORM} manifest)"
DOCKER_VERSION=$(docker run --rm --platform "$PLATFORM" "${IMAGE}:${VERSION_STRIPPED}" --version | awk 'NR==1 {print $2}')
[ "$DOCKER_VERSION" = "$VERSION_STRIPPED" ] || err "docker image reports version '${DOCKER_VERSION}', expected '${VERSION_STRIPPED}'"
info "docker version: ${DOCKER_VERSION}"

# Multi-arch images publish SBOM and Provenance as a map keyed by
# platform (e.g. "linux/amd64", "linux/arm64"). Single-arch images
# publish them at the root with .SPDX / .SLSA. Try the per-platform
# path first, fall back to the legacy single-arch shape so this
# script keeps working if the image regresses to a single platform.
SBOM_JSON=$(docker buildx imagetools inspect "${IMAGE}:${VERSION_STRIPPED}" --format '{{json .SBOM}}')
echo "$SBOM_JSON" | jq -e --arg p "$PLATFORM" \
    'if has($p) then .[$p].SPDX.SPDXID == "SPDXRef-DOCUMENT"
     else .SPDX.SPDXID == "SPDXRef-DOCUMENT" end' >/dev/null \
    || err "Docker image SBOM (SPDX) missing or malformed for ${PLATFORM}"
info "image SBOM: SPDX present (${PLATFORM})"

# Provenance is also keyed by platform on multi-arch images. Scope
# the buildType grep to the platform's slice before greping so a
# regression that drops provenance for the host arch cannot pass
# just because the other arch still has it. Provenance JSON sometimes
# embeds raw commit messages with literal newlines that strict jq
# rejects as control chars, so the grep stays as the final check
# within the platform's extracted slice.
PROVENANCE_JSON=$(docker buildx imagetools inspect "${IMAGE}:${VERSION_STRIPPED}" --format '{{json .Provenance}}')
PLATFORM_PROVENANCE=$(echo "$PROVENANCE_JSON" \
    | jq -c --arg p "$PLATFORM" 'if has($p) then .[$p] else . end' 2>/dev/null || true)
[ -n "$PLATFORM_PROVENANCE" ] && [ "$PLATFORM_PROVENANCE" != "null" ] \
    || err "Docker image SLSA provenance missing for ${PLATFORM}"
echo "$PLATFORM_PROVENANCE" \
    | grep -q '"buildType":[[:space:]]*"https://' \
    || err "Docker image SLSA provenance missing or malformed for ${PLATFORM}"
info "image provenance: SLSA present (${PLATFORM})"

green ">> ALL CHECKS PASSED for ${VERSION} (${OS}/${ARCH})"
