package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/garagon/aguara"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const scanTimeout = 30 * time.Second

const maxContentSize = 10 << 20 // 10 MB

var validRuleID = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)

// RegisterTools registers all aguara tools on the MCP server.
func RegisterTools(s *mcp.Server, debug bool) {
	s.AddTool(scanContentTool(), handleScanContent(debug))
	s.AddTool(checkMCPConfigTool(), handleCheckMCPConfig(debug))
	s.AddTool(listRulesTool(), handleListRules())
	s.AddTool(explainRuleTool(), handleExplainRule())
	s.AddTool(discoverMCPTool(), handleDiscoverMCP(debug))
}

// --- Tool definitions ---

func boolPtr(b bool) *bool { return &b }

func prop(typ, desc string) map[string]any {
	return map[string]any{"type": typ, "description": desc}
}

func scanContentTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "scan_content",
		Description: "Scan the content of an AI agent skill or MCP server description for security issues. " +
			"Checks for prompt injection, credential leaks, exfiltration, command execution, and more. " +
			"Supports context-aware scanning with tool_name for false-positive reduction.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"content":        prop("string", "The text content to scan (e.g., skill description, README, tool definition)"),
				"filename":       prop("string", "Filename hint for the content (affects rule matching). Default: skill.md"),
				"tool_name":      prop("string", "Tool that generated the content (e.g., Bash, Edit, WebFetch). Enables context-aware false-positive reduction"),
				"scan_profile":   prop("string", "Scan profile: strict (default, all rules), content-aware (reduced FP for known tools), or minimal (flag-only mode)"),
				"min_severity":   prop("string", "Minimum severity to report: INFO, LOW, MEDIUM, HIGH, or CRITICAL"),
				"disabled_rules": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "List of rule IDs to disable (e.g., [\"PROMPT_INJECTION_001\"])"},
			},
			"required": []string{"content"},
		},
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
	}
}

func checkMCPConfigTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "check_mcp_config",
		Description: "Check an MCP server configuration (JSON) for security issues. " +
			"Detects dangerous command patterns, credential exposure, and unsafe settings.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"config":         prop("string", "The MCP configuration as a JSON string"),
				"scan_profile":   prop("string", "Scan profile: strict (default, all rules), content-aware (reduced FP for known tools), or minimal (flag-only mode)"),
				"min_severity":   prop("string", "Minimum severity to report: INFO, LOW, MEDIUM, HIGH, or CRITICAL"),
				"disabled_rules": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "List of rule IDs to disable (e.g., [\"PROMPT_INJECTION_001\"])"},
			},
			"required": []string{"config"},
		},
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
	}
}

func listRulesTool() *mcp.Tool {
	return &mcp.Tool{
		Name:        "list_rules",
		Description: "List available security rules. Optionally filter by category.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"category": prop("string", "Filter rules by category (e.g., prompt-injection, exfiltration, credential-leak)"),
			},
		},
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
	}
}

func explainRuleTool() *mcp.Tool {
	return &mcp.Tool{
		Name:        "explain_rule",
		Description: "Get detailed information about a specific security rule, including its patterns and examples.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"rule_id": prop("string", "The rule ID to explain (e.g., PROMPT_INJECTION_001)"),
			},
			"required": []string{"rule_id"},
		},
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
	}
}

func discoverMCPTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "discover_mcp",
		Description: "Discover MCP server configurations on the local machine. " +
			"Finds all known MCP client config files (Claude Desktop, Cursor, VS Code, etc.) " +
			"and extracts the server definitions, including commands, arguments, and environment variables.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
	}
}

// --- Argument helpers ---

func getString(raw json.RawMessage, key, defaultVal string) string {
	if len(raw) == 0 {
		return defaultVal
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return defaultVal
	}
	v, ok := m[key]
	if !ok {
		return defaultVal
	}
	s, ok := v.(string)
	if !ok {
		return defaultVal
	}
	return s
}

func getStringSlice(raw json.RawMessage, key string) []string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

var severityMap = map[string]aguara.Severity{
	"INFO":     aguara.SeverityInfo,
	"LOW":      aguara.SeverityLow,
	"MEDIUM":   aguara.SeverityMedium,
	"HIGH":     aguara.SeverityHigh,
	"CRITICAL": aguara.SeverityCritical,
}

var profileMap = map[string]aguara.ScanProfile{
	"STRICT":        aguara.ProfileStrict,
	"CONTENT-AWARE": aguara.ProfileContentAware,
	"CONTENT_AWARE": aguara.ProfileContentAware,
	"MINIMAL":       aguara.ProfileMinimal,
}

func buildScanOpts(args json.RawMessage) []aguara.Option {
	var opts []aguara.Option
	if sev := getString(args, "min_severity", ""); sev != "" {
		if s, ok := severityMap[strings.ToUpper(sev)]; ok {
			opts = append(opts, aguara.WithMinSeverity(s))
		}
	}
	if disabled := getStringSlice(args, "disabled_rules"); len(disabled) > 0 {
		opts = append(opts, aguara.WithDisabledRules(disabled...))
	}
	if profile := getString(args, "scan_profile", ""); profile != "" {
		if p, ok := profileMap[strings.ToUpper(profile)]; ok {
			opts = append(opts, aguara.WithScanProfile(p))
		}
	}
	return opts
}

func newToolResultText(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

func newToolResultError(msg string) *mcp.CallToolResult {
	var r mcp.CallToolResult
	r.SetError(fmt.Errorf("%s", msg))
	return &r
}

// --- Tool handlers ---

func handleScanContent(debug bool) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		content := getString(req.Params.Arguments, "content", "")
		if content == "" {
			return newToolResultError("content parameter is required"), nil
		}
		if len(content) > maxContentSize {
			return newToolResultError(fmt.Sprintf("content too large: %d bytes (max %d)", len(content), maxContentSize)), nil
		}

		filename := getString(req.Params.Arguments, "filename", "skill.md")
		filename = sanitizeFilename(filename)
		toolName := getString(req.Params.Arguments, "tool_name", "")

		if debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] scan_content: file=%s len=%d tool=%s\n", filename, len(content), toolName)
		}

		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, scanTimeout)
			defer cancel()
		}

		opts := buildScanOpts(req.Params.Arguments)

		var result *aguara.ScanResult
		var err error
		if toolName != "" {
			result, err = aguara.ScanContentAs(ctx, content, filename, toolName, opts...)
		} else {
			result, err = aguara.ScanContent(ctx, content, filename, opts...)
		}
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] scan_content error: %v\n", err)
			}
			return newToolResultError("scan failed"), nil
		}

		if debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] scan result: %d findings\n", len(result.Findings))
		}

		return newToolResultText(formatScanResult(result)), nil
	}
}

func handleCheckMCPConfig(debug bool) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		config := getString(req.Params.Arguments, "config", "")
		if config == "" {
			return newToolResultError("config parameter is required"), nil
		}
		if len(config) > maxContentSize {
			return newToolResultError(fmt.Sprintf("config too large: %d bytes (max %d)", len(config), maxContentSize)), nil
		}

		// Validate it's valid JSON.
		if !json.Valid([]byte(config)) {
			return newToolResultError("config is not valid JSON"), nil
		}

		if debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] check_mcp_config: len=%d\n", len(config))
		}

		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, scanTimeout)
			defer cancel()
		}

		opts := buildScanOpts(req.Params.Arguments)
		result, err := aguara.ScanContent(ctx, config, "config.json", opts...)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] check_mcp_config error: %v\n", err)
			}
			return newToolResultError("scan failed"), nil
		}

		if debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] scan result: %d findings\n", len(result.Findings))
		}

		return newToolResultText(formatScanResult(result)), nil
	}
}

func handleListRules() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		category := getString(req.Params.Arguments, "category", "")

		var opts []aguara.Option
		if category != "" {
			opts = append(opts, aguara.WithCategory(category))
		}

		rules := aguara.ListRules(opts...)

		out, err := json.MarshalIndent(rules, "", "  ")
		if err != nil {
			return newToolResultError("failed to format rules"), nil
		}

		return newToolResultText(string(out)), nil
	}
}

func handleExplainRule() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ruleID := getString(req.Params.Arguments, "rule_id", "")
		if ruleID == "" {
			return newToolResultError("rule_id parameter is required"), nil
		}
		if !validRuleID.MatchString(ruleID) {
			return newToolResultError("invalid rule_id format: must match [A-Z][A-Z0-9_]+ (e.g., PROMPT_INJECTION_001)"), nil
		}

		detail, err := aguara.ExplainRule(ruleID)
		if err != nil {
			return newToolResultError(fmt.Sprintf("rule %s not found", ruleID)), nil
		}

		out, err := json.MarshalIndent(detail, "", "  ")
		if err != nil {
			return newToolResultError("failed to format rule info"), nil
		}

		return newToolResultText(string(out)), nil
	}
}

func handleDiscoverMCP(debug bool) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] discover_mcp: scanning local configs\n")
		}

		result, err := aguara.Discover()
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] discover_mcp error: %v\n", err)
			}
			return newToolResultError("discovery failed"), nil
		}

		if debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] discover_mcp: found %d servers across %d clients\n",
				result.TotalServers(), result.TotalClients())
		}

		out, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return newToolResultError("failed to format discovery results"), nil
		}

		return newToolResultText(string(out)), nil
	}
}

// --- Formatting helpers ---

// formatScanResult produces a structured JSON response for scan results.
func formatScanResult(result *aguara.ScanResult) string {
	type findingOut struct {
		Severity    string  `json:"severity"`
		RuleID      string  `json:"rule_id"`
		Category    string  `json:"category"`
		RuleName    string  `json:"rule_name"`
		Description string  `json:"description"`
		Remediation string  `json:"remediation,omitempty"`
		Line        int     `json:"line"`
		Column      int     `json:"column,omitempty"`
		MatchedText string  `json:"matched_text"`
		InCodeBlock bool    `json:"in_code_block"`
		Score       float64 `json:"score"`
		Confidence  float64 `json:"confidence,omitempty"`
		Analyzer    string  `json:"analyzer,omitempty"`
	}

	type statsOut struct {
		FilesScanned int `json:"files_scanned"`
		RulesLoaded  int `json:"rules_loaded"`
	}

	type response struct {
		Summary  string       `json:"summary"`
		Verdict  string       `json:"verdict"`
		Findings []findingOut `json:"findings"`
		Stats    statsOut     `json:"stats"`
	}

	findings := make([]findingOut, 0, len(result.Findings))
	counts := make(map[string]int)

	for _, f := range result.Findings {
		sevName := f.Severity.String()
		counts[sevName]++
		findings = append(findings, findingOut{
			Severity:    sevName,
			RuleID:      f.RuleID,
			Category:    f.Category,
			RuleName:    f.RuleName,
			Description: f.Description,
			Remediation: f.Remediation,
			Line:        f.Line,
			Column:      f.Column,
			MatchedText: f.MatchedText,
			InCodeBlock: f.InCodeBlock,
			Score:       f.Score,
			Confidence:  f.Confidence,
			Analyzer:    f.Analyzer,
		})
	}

	resp := response{
		Summary:  formatSummary(len(result.Findings), counts),
		Verdict:  result.Verdict.String(),
		Findings: findings,
		Stats: statsOut{
			FilesScanned: result.FilesScanned,
			RulesLoaded:  result.RulesLoaded,
		},
	}

	out, _ := json.MarshalIndent(resp, "", "  ")
	return string(out)
}

// formatSummary creates a human-readable summary like "Found 3 issues: 1 critical, 2 high".
func formatSummary(total int, counts map[string]int) string {
	if total == 0 {
		return "No security issues found."
	}

	var parts []string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if n, ok := counts[sev]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(sev)))
		}
	}

	issue := "issue"
	if total != 1 {
		issue = "issues"
	}

	return fmt.Sprintf("Found %d %s: %s", total, issue, strings.Join(parts, ", "))
}

var safeFilenameChars = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// ghaWorkflowPrefix is preserved by sanitizeFilename so the v0.17 ci-trust
// analyzer can fire on workflow YAML passed through scan_content. The
// analyzer keys off the path component and would silently no-op if the
// filename were stripped to bare basename.
const ghaWorkflowPrefix = ".github/workflows/"

// sanitizeFilename strips path components, restricts to safe characters, and caps length.
// Exception: when `.github/workflows/` appears anywhere in the path, the
// canonical prefix plus a sanitized basename is preserved so the ci-trust
// analyzer registered by aguara v0.17 can match. Windows separators are
// normalized first so paths like `C:\repo\.github\workflows\ci.yml` and
// relative paths like `repo/.github/workflows/ci.yml` reach the analyzer
// with the segment intact. Anything after the segment that contains a
// further path separator (traversal or nested subdirs) falls back to the
// default basename strip.
func sanitizeFilename(name string) string {
	normalized := strings.ReplaceAll(name, `\`, `/`)
	if idx := strings.Index(normalized, ghaWorkflowPrefix); idx >= 0 {
		rest := normalized[idx+len(ghaWorkflowPrefix):]
		if rest != "" && !strings.Contains(rest, "/") {
			base := sanitizeBasename(rest)
			if base != "skill.md" {
				return ghaWorkflowPrefix + base
			}
		}
	}
	return sanitizeBasename(name)
}

// sanitizeBasename is the shared core of sanitizeFilename: strip directory
// components, drop leading dots, restrict to the allowlist, fall back to
// skill.md when nothing safe remains, and cap length.
func sanitizeBasename(name string) string {
	i := strings.LastIndexAny(name, `/\`)
	if i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimLeft(name, ".")
	name = safeFilenameChars.ReplaceAllString(name, "")
	if name == "" {
		return "skill.md"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}
