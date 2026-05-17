# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Aguara MCP, please report it responsibly through [GitHub Security Advisories](https://github.com/garagon/mcp-aguara/security/advisories/new).

**Do not** open a public issue for security vulnerabilities.

### Scope

The following are in scope:

- MCP server (stdio transport, tool registration, request handling)
- Input validation (content size limits, filename sanitization, rule ID format)
- In-process Aguara scanner integration (library import, result handling)

The following are out of scope:

- Findings in third-party skills or MCP servers scanned by Aguara
- Vulnerabilities in Go standard library or dependencies (report upstream)
- The Aguara scanner engine itself (report at [garagon/aguara](https://github.com/garagon/aguara/security/advisories/new))

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix or mitigation:** Within 30 days for confirmed issues

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | Best effort |
