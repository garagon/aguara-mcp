package main

import (
	"context"
	"strings"
	"testing"

	"github.com/garagon/aguara"
)

// Aguara v0.27 alignment regressions. The v0.25-v0.27 core releases add
// the npm-policy analyzer (NPM_* rules over `.npmrc` and the
// `package.json` allowScripts policy), all-versions and bounded-range
// intel matching, and terminal UX changes (CLI-only, no library
// surface). The analyzer keys on the exact `.npmrc` basename, leading
// dot included, so these tests pin BOTH the core behavior and the
// sanitizeFilename exception that lets the filename survive the MCP
// input path. Failures here mean the MCP silently dropped a detection
// surface it advertises.

func TestV027_SanitizeFilename_PreservesNpmrcDotfile(t *testing.T) {
	cases := []struct{ in, want string }{
		{".npmrc", ".npmrc"},
		{"repo/.npmrc", ".npmrc"},
		{`C:\repo\.npmrc`, ".npmrc"},
		{".NpmRC", ".npmrc"},
		// Unknown dotfiles keep the historical leading-dot strip.
		{".env", "env"},
		{".hidden", "hidden"},
	}
	for _, c := range cases {
		if got := sanitizeFilename(c.in); got != c.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestV027_ScanContent_FiresNpmPolicyOnNpmrc(t *testing.T) {
	// dangerously-allow-all-scripts=true is the HIGH npm-policy case: it
	// bypasses the npm v12 allowScripts policy entirely. The filename
	// must keep its leading dot for the analyzer to consider the file.
	const npmrc = "registry=https://registry.npmjs.org\ndangerously-allow-all-scripts=true\n"
	result, err := aguara.ScanContent(context.Background(), npmrc, sanitizeFilename("repo/.npmrc"))
	if err != nil {
		t.Fatalf("ScanContent failed: %v", err)
	}
	found := false
	var allIDs []string
	for _, f := range result.Findings {
		allIDs = append(allIDs, f.RuleID)
		if f.RuleID == "NPM_DANGEROUS_ALL_SCRIPTS_001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected NPM_DANGEROUS_ALL_SCRIPTS_001 on dangerously-allow-all-scripts=true; got %d findings with rule IDs %v",
			len(result.Findings), allIDs)
	}
}

func TestV027_ExplainRule_NpmPolicyRule(t *testing.T) {
	const ruleID = "NPM_DANGEROUS_ALL_SCRIPTS_001"
	detail, err := aguara.ExplainRule(ruleID)
	if err != nil {
		t.Fatalf("ExplainRule(%q) failed: %v", ruleID, err)
	}
	if detail.Category != "supply-chain" {
		t.Errorf("detail.Category = %q, want %q", detail.Category, "supply-chain")
	}
	if detail.Severity == "" || detail.Remediation == "" {
		t.Errorf("npm-policy rule must carry severity and remediation metadata")
	}
}

func TestV027_ListRules_IncludesNpmPolicyRules(t *testing.T) {
	rules := aguara.ListRules()
	npmPolicy := 0
	for _, r := range rules {
		if strings.HasPrefix(r.ID, "NPM_ALLOW_") || strings.HasPrefix(r.ID, "NPM_DANGEROUS_") {
			npmPolicy++
		}
	}
	if got, want := npmPolicy, 4; got != want {
		t.Errorf("npm-policy rules in catalog = %d, want %d", got, want)
	}
}
