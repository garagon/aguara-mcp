package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/garagon/aguara"
)

// Aguara v0.18 alignment regressions. v0.18.2 marked MCPCFG_003
// ("Hardcoded secrets in MCP env block") as sensitive at the rule level
// so core's RedactSensitiveFindings now scrubs its MatchedText in place
// before the finding reaches the MCP formatter. v0.6.0 relied on the
// MCP-side defensive Sensitive guard for this case because the YAML
// rule did not yet opt in; v0.6.1 inherits the in-place scrub from
// core. This file pins the inheritance: if a future core change drops
// the sensitive flag on MCPCFG_003 the test fails and the bump should
// not land until the contract is restored.

func TestV018_MCPCFG_003_InheritsSensitiveFromCore(t *testing.T) {
	// A literal GitHub token in a JSON MCP server env block. The secret
	// is >=20 alphanumeric+underscore+hyphen chars to satisfy the rule's
	// second pattern. The env var is named GITHUB_TOKEN (rather than
	// GITHUB_API_KEY) because the pattern matcher's keyword prefilter
	// keys on literal substrings of >=4 chars: "token", "secret",
	// "password" and "credential" pass, but the "api" / "key" literals
	// in the API_KEY alternation are 3 chars and do not. A payload
	// containing only "API_KEY" would never reach the rule, masking the
	// sensitivity invariant this test pins.
	const secret = "ghp_real1234567890abcdefABCDEF"
	payload := `{
  "mcpServers": {
    "github": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "GITHUB_TOKEN": "` + secret + `"
      }
    }
  }
}`

	result, err := aguara.ScanContent(context.Background(), payload, "mcp.json")
	if err != nil {
		t.Fatalf("ScanContent failed: %v", err)
	}

	var mcpcfg003 *aguara.Finding
	for i := range result.Findings {
		if result.Findings[i].RuleID == "MCPCFG_003" {
			mcpcfg003 = &result.Findings[i]
			break
		}
	}
	if mcpcfg003 == nil {
		var ids []string
		for _, f := range result.Findings {
			ids = append(ids, f.RuleID)
		}
		t.Fatalf("expected MCPCFG_003 finding for hardcoded secret in MCP env block; got rule IDs %v", ids)
	}

	if !mcpcfg003.Sensitive {
		t.Fatalf("MCPCFG_003.Sensitive = false; core v0.18.2+ must mark this rule sensitive so RedactSensitiveFindings scrubs the matched text. Without this flag, the literal API key reaches MCP output.")
	}

	out := formatScanResult(result)
	if strings.Contains(out, secret) {
		t.Fatalf("LEAK: literal API key appears in MCP output despite MCPCFG_003 sensitive flag (out len=%d)", len(out))
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Errorf("expected %q placeholder in MCP output, did not find it", redactedPlaceholder)
	}

	// Output must still be parseable JSON with the redacted matched_text
	// on the MCPCFG_003 finding.
	var resp struct {
		Findings []struct {
			RuleID      string `json:"rule_id"`
			MatchedText string `json:"matched_text"`
			Sensitive   bool   `json:"sensitive"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("formatScanResult output is not valid JSON: %v", err)
	}
	var found bool
	for _, f := range resp.Findings {
		if f.RuleID != "MCPCFG_003" {
			continue
		}
		found = true
		if f.MatchedText != redactedPlaceholder {
			t.Errorf("MCPCFG_003.matched_text = %q, want %q", f.MatchedText, redactedPlaceholder)
		}
	}
	if !found {
		t.Fatalf("MCPCFG_003 finding not serialised in formatScanResult output")
	}
}
