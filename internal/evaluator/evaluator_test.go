package evaluator_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahul-k-r/auto-permissions-mode/internal/config"
	"github.com/rahul-k-r/auto-permissions-mode/internal/evaluator"
	"github.com/rahul-k-r/auto-permissions-mode/internal/policy"
)

type mockProvider struct {
	response map[string]interface{}
	source   string
	err      error
}

func (m *mockProvider) Evaluate(systemPrompt, userPrompt string) (map[string]interface{}, string, error) {
	if m.err != nil {
		return nil, "", m.err
	}
	src := m.source
	if src == "" {
		src = "LOCAL"
	}
	return m.response, src, nil
}

func TestFastPathReadOnly(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{"decision": "allow", "reason": "Mocked safe"}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	e := evaluator.NewSecurityEvaluator(p, cfg)

	res := e.EvaluateToolCall("view_file", map[string]interface{}{"AbsolutePath": "test.txt"}, nil)
	if res.Decision != "allow" {
		t.Fatalf("expected allow, got %s", res.Decision)
	}
	if !strings.Contains(res.Reason, "Fast-path") {
		t.Fatalf("expected reason to mention Fast-path, got %s", res.Reason)
	}
}

func TestDestructiveCommandDeny(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{"decision": "deny", "reason": "Destructive disk wipe blocked."}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	e := evaluator.NewSecurityEvaluator(p, cfg)

	res := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "rm -rf /"}, nil)
	if res.Decision != "deny" {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
	if !strings.Contains(res.Reason, "Destructive") {
		t.Fatalf("expected reason to contain Destructive, got %s", res.Reason)
	}
}

func TestDenyWithAlternativesBuildsDirective(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{
		"decision": "deny",
		"reason":   "Hard reset will discard uncommitted local changes.",
		"alternatives": []interface{}{
			map[string]interface{}{"label": "Stash uncommitted changes to preserve work", "command": "git stash -u"},
			map[string]interface{}{"label": "Inspect changed files diff first", "command": "git status -s && git diff"},
		},
	}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	cfg.EnableRemediationDirectives = true
	e := evaluator.NewSecurityEvaluator(p, cfg)

	res := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "git reset --hard HEAD~1"}, nil)
	if res.Decision != "deny" {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
	if !strings.Contains(res.Reason, "```json:alternatives") {
		t.Fatalf("expected alternatives json block")
	}
	if !strings.Contains(res.Reason, "REMEDIATION DIRECTIVE") {
		t.Fatalf("expected REMEDIATION DIRECTIVE")
	}
	if !strings.Contains(res.Reason, "(Recommended) Stash uncommitted changes to preserve work") {
		t.Fatalf("expected (Recommended) label")
	}
	if !strings.Contains(res.Reason, "git stash -u") {
		t.Fatalf("expected git stash -u")
	}
	if len(res.Alternatives) != 2 {
		t.Fatalf("expected 2 alternatives, got %d", len(res.Alternatives))
	}
}

func TestAskWithAlternativesIncludesOriginalAction(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{
		"decision": "ask",
		"reason":   "Force-push rewrites remote history other collaborators may have pulled.",
		"alternatives": []interface{}{
			map[string]interface{}{"label": "Use a safer force-with-lease push instead", "command": "git push --force-with-lease origin main"},
			map[string]interface{}{"label": "Proceed with the force push as originally requested", "command": "git push --force origin main"},
		},
	}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	cfg.EnableRemediationDirectives = true
	e := evaluator.NewSecurityEvaluator(p, cfg)

	res := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "git push --force origin main"}, nil)
	// "ask" with alternatives is routed to "deny" so the agent receives the directive directly, and logged as ASK
	if res.Decision != "deny" {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
	if res.AuditDecision != "ASK" {
		t.Fatalf("expected audit decision ASK, got %s", res.AuditDecision)
	}
	if !strings.Contains(res.Reason, "```json:alternatives") {
		t.Fatalf("expected alternatives json block")
	}
	if !strings.Contains(res.Reason, "REMEDIATION DIRECTIVE") {
		t.Fatalf("expected REMEDIATION DIRECTIVE")
	}
	if !strings.Contains(res.Reason, "git push --force origin main") {
		t.Fatalf("expected original command in reason")
	}
	if len(res.Alternatives) != 2 {
		t.Fatalf("expected 2 alternatives, got %d", len(res.Alternatives))
	}
}

func TestAlternativesStringListAndDeduplication(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{
		"decision": "deny",
		"reason":   "Branch deletion blocked.",
		"alternatives": []interface{}{
			"(Recommended) Stash changes -> git stash",
			"Inspect diff -> git diff",
		},
	}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	cfg.EnableRemediationDirectives = true
	e := evaluator.NewSecurityEvaluator(p, cfg)

	res := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "git branch -D feature"}, nil)
	if res.Decision != "deny" {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
	if !strings.Contains(res.Reason, "```json:alternatives") {
		t.Fatalf("expected json:alternatives block")
	}
	if strings.Contains(res.Reason, "(Recommended) (Recommended)") {
		t.Fatalf("found duplicate (Recommended) prefix")
	}
	if !strings.Contains(res.Reason, "(Recommended) Stash changes") {
		t.Fatalf("expected recommended stash changes")
	}
	if !strings.Contains(res.Reason, "git stash") {
		t.Fatalf("expected git stash")
	}
}

func TestDisabledRemediationDirectivesConfig(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{
		"decision": "deny",
		"reason":   "Direct delete blocked.",
		"alternatives": []interface{}{
			map[string]interface{}{"label": "Trash instead", "command": "trash foo.txt"},
		},
	}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	cfg.EnableRemediationDirectives = false
	e := evaluator.NewSecurityEvaluator(p, cfg)

	res := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "rm foo.txt"}, nil)
	if res.Decision != "deny" {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
	if strings.Contains(res.Reason, "REMEDIATION DIRECTIVE") {
		t.Fatalf("unexpected REMEDIATION DIRECTIVE when disabled")
	}
	if strings.Contains(res.Reason, "```json:alternatives") {
		t.Fatalf("unexpected json:alternatives block when disabled")
	}
}

func TestDenyWithoutAlternativesKeyDegradesGracefully(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{
		"decision": "deny",
		"reason":   "Destructive disk wipe blocked.",
	}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	e := evaluator.NewSecurityEvaluator(p, cfg)

	res := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "rm -rf /"}, nil)
	if res.Decision != "deny" {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
	if strings.Contains(res.Reason, "REMEDIATION DIRECTIVE") {
		t.Fatalf("unexpected REMEDIATION DIRECTIVE")
	}
	if len(res.Alternatives) != 0 {
		t.Fatalf("expected 0 alternatives, got %d", len(res.Alternatives))
	}
}

func TestProviderOfflineFallback(t *testing.T) {
	p := &mockProvider{err: os.ErrInvalid}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = false
	cfg.FallbackAction = "ask"
	e := evaluator.NewSecurityEvaluator(p, cfg)

	res := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "npm run build"}, nil)
	if res.Decision != "ask" && res.Decision != "force_ask" {
		t.Fatalf("expected ask or force_ask, got %s", res.Decision)
	}
}

func TestProviderOfflineSourceTag(t *testing.T) {
	p := &mockProvider{err: os.ErrInvalid}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = false
	cfg.FallbackAction = "ask"
	e := evaluator.NewSecurityEvaluator(p, cfg)

	res := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "npm run build"}, nil)
	if res.Decision != "ask" && res.Decision != "force_ask" {
		t.Fatalf("expected ask or force_ask, got %s", res.Decision)
	}
	if res.Source != "OFFLINE" {
		t.Fatalf("expected OFFLINE source, got %s", res.Source)
	}
}

// Hardware tier logic test
func TierFromGB(memGB float64) string {
	if memGB < 5.0 {
		return "4gb"
	} else if memGB < 7.5 {
		return "6gb"
	} else if memGB < 11.0 {
		return "8gb"
	} else if memGB < 15.0 {
		return "12gb"
	} else if memGB < 22.0 {
		return "16gb"
	}
	return "24gb"
}

func TestTierFromGB(t *testing.T) {
	if TierFromGB(3.5) != "4gb" {
		t.Fatalf("expected 4gb")
	}
	if TierFromGB(5.0) != "6gb" {
		t.Fatalf("expected 6gb")
	}
	if TierFromGB(8.0) != "8gb" {
		t.Fatalf("expected 8gb")
	}
	if TierFromGB(12.0) != "12gb" {
		t.Fatalf("expected 12gb")
	}
	if TierFromGB(16.0) != "16gb" {
		t.Fatalf("expected 16gb")
	}
	if TierFromGB(24.0) != "24gb" {
		t.Fatalf("expected 24gb")
	}
}

// NOTE: audit-log helpers (ExtractProjectName, SummarizeArgs, TrimAuditLog) used to have a
// second, independent copy duplicated right here in the evaluator test file, and these
// "tests" exercised that copy — never the real internal/monitor/audit.go implementation
// that actually ships. That meant TestTrimAuditLogRetentionAndMaxLines could pass even if
// monitor.TrimAuditLog were completely broken. Real coverage now lives in
// internal/monitor/audit_test.go, against the actual package.

func TestUserApprovalFromAskQuestionTranscript(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{"decision": "deny", "reason": "Destructive action blocked"}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	e := evaluator.NewSecurityEvaluator(p, cfg)

	tmpDir, err := os.MkdirTemp("", "transcript-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	transcriptFile := filepath.Join(tmpDir, "transcript.jsonl")

	// Case 1: Matching approval
	steps := []map[string]interface{}{
		{
			"step_index": 10,
			"type":       "PLANNER_RESPONSE",
			"tool_calls": []map[string]interface{}{
				{
					"name": "ask_question",
					"args": map[string]interface{}{
						"questions": []map[string]interface{}{
							{
								"options": []string{
									"Discard all changes (git checkout -- .)",
									"Stash changes (git stash)",
								},
							},
						},
					},
				},
			},
		},
		{
			"step_index": 11,
			"type":       "GENERIC",
			"content":    "A1: Discard all changes (git checkout -- .)",
		},
	}

	writeTranscript := func(items []map[string]interface{}) {
		var lines []string
		for _, s := range items {
			b, _ := json.Marshal(s)
			lines = append(lines, string(b))
		}
		_ = os.WriteFile(transcriptFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
	}

	writeTranscript(steps)

	ctx := map[string]interface{}{"transcript_path": transcriptFile}
	res := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "git checkout -- ."}, ctx)
	if res.Decision != "allow" {
		t.Fatalf("expected allow, got %s", res.Decision)
	}
	if res.Source != "USER-APPROVED" {
		t.Fatalf("expected USER-APPROVED, got %s", res.Source)
	}
	if !strings.Contains(res.Reason, "Verified user authorization") {
		t.Fatalf("expected verified authorization reason")
	}

	// Case 2: Mismatch
	mismatch := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "git clean -fd"}, ctx)
	if mismatch.Decision != "deny" {
		t.Fatalf("expected deny on mismatch, got %s", mismatch.Decision)
	}

	// Case 3: Intervening step invalidates
	steps = append(steps, map[string]interface{}{
		"step_index": 12,
		"type":       "GENERIC",
		"content":    "intervening tool finished",
	})
	writeTranscript(steps)
	subsequent := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "git checkout -- ."}, ctx)
	if subsequent.Decision != "deny" {
		t.Fatalf("expected deny after intervening step, got %s", subsequent.Decision)
	}

	// Case 4: Arrow syntax option ("Preview files" -> git status -s)
	arrowSteps := []map[string]interface{}{
		{
			"step_index": 20,
			"type":       "PLANNER_RESPONSE",
			"tool_calls": []map[string]interface{}{
				{
					"name": "ask_question",
					"args": map[string]interface{}{
						"questions": []map[string]interface{}{
							{
								"options": []string{
									"- \"Preview files\" -> git status -s",
									"- \"Clean files\" -> git clean -fd",
								},
							},
						},
					},
				},
			},
		},
		{
			"step_index": 21,
			"type":       "GENERIC",
			"content":    "A1: - \"Clean files\" -> git clean -fd",
		},
	}
	writeTranscript(arrowSteps)
	arrowRes := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "git clean -fd"}, ctx)
	if arrowRes.Decision != "allow" {
		t.Fatalf("expected allow for arrow syntax, got %s", arrowRes.Decision)
	}
	if arrowRes.Source != "USER-APPROVED" {
		t.Fatalf("expected USER-APPROVED for arrow syntax")
	}

	// Case 5: Custom write-in command
	writeinSteps := []map[string]interface{}{
		{
			"step_index": 30,
			"type":       "PLANNER_RESPONSE",
			"tool_calls": []map[string]interface{}{
				{"name": "ask_question", "args": map[string]interface{}{}},
			},
		},
		{
			"step_index": 31,
			"type":       "GENERIC",
			"content":    "A1: git restore --staged src/app.py",
		},
	}
	writeTranscript(writeinSteps)
	writeinRes := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "git restore --staged src/app.py"}, ctx)
	if writeinRes.Decision != "allow" {
		t.Fatalf("expected allow for writein, got %s", writeinRes.Decision)
	}
	if writeinRes.Source != "USER-APPROVED" {
		t.Fatalf("expected USER-APPROVED for writein")
	}
	if len(writeinRes.PermissionOverrides) == 0 || writeinRes.PermissionOverrides[0] != "command(git restore --staged src/app.py)" {
		t.Fatalf("expected command override, got %v", writeinRes.PermissionOverrides)
	}
}

func TestMcpReadOnlyFastPath(t *testing.T) {
	p := &mockProvider{}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	e := evaluator.NewSecurityEvaluator(p, cfg)

	// 1. Generic dispatch call_mcp_tool get_issue
	res := e.EvaluateToolCall("call_mcp_tool", map[string]interface{}{
		"ServerName": "linear-mcp-server",
		"ToolName":   "get_issue",
		"Arguments":  map[string]interface{}{"id": "HD-120"},
	}, nil)
	if res.Decision != "allow" {
		t.Fatalf("expected allow, got %s", res.Decision)
	}
	if res.Source != "FAST-PATH" {
		t.Fatalf("expected FAST-PATH, got %s", res.Source)
	}
	if !strings.Contains(res.Reason, "linear-mcp-server/get_issue") {
		t.Fatalf("expected reason to contain tool path")
	}
	hasOverride := false
	for _, o := range res.PermissionOverrides {
		if o == "mcp(linear-mcp-server/get_issue)" {
			hasOverride = true
		}
	}
	if !hasOverride {
		t.Fatalf("missing scoped mcp override: %v", res.PermissionOverrides)
	}

	// 2. list_teams query
	resList := e.EvaluateToolCall("call_mcp_tool", map[string]interface{}{
		"ServerName": "linear-mcp-server",
		"ToolName":   "list_teams",
		"Arguments":  map[string]interface{}{},
	}, nil)
	if resList.Decision != "allow" {
		t.Fatalf("expected allow")
	}

	// 3. Direct eager MCP tool naming (mcp_linear_get_issue)
	resEager := e.EvaluateToolCall("mcp_linear_get_issue", map[string]interface{}{"id": "HD-120"}, nil)
	if resEager.Decision != "allow" {
		t.Fatalf("expected allow for eager mcp tool")
	}
}

func TestMcpMutatingToolsRequireLlmEvaluation(t *testing.T) {
	pDeny := &mockProvider{response: map[string]interface{}{
		"decision": "deny",
		"reason":   "Deleting issue HD-120 is destructive.",
	}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	eDeny := evaluator.NewSecurityEvaluator(pDeny, cfg)

	res := eDeny.EvaluateToolCall("call_mcp_tool", map[string]interface{}{
		"ServerName": "linear-mcp-server",
		"ToolName":   "delete_issue",
		"Arguments":  map[string]interface{}{"id": "HD-120"},
	}, nil)
	if res.Decision != "deny" {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
	if res.Source != "LOCAL" {
		t.Fatalf("expected LOCAL source, got %s", res.Source)
	}
	if len(res.PermissionOverrides) != 0 {
		t.Fatalf("no permission overrides should be emitted on deny")
	}

	pAllow := &mockProvider{response: map[string]interface{}{
		"decision": "allow",
		"reason":   "Updating issue title is safe.",
	}}
	eAllow := evaluator.NewSecurityEvaluator(pAllow, cfg)
	resAllow := eAllow.EvaluateToolCall("call_mcp_tool", map[string]interface{}{
		"ServerName": "linear-mcp-server",
		"ToolName":   "save_issue",
		"Arguments":  map[string]interface{}{"id": "HD-120", "title": "Refactor auth"},
	}, nil)
	if resAllow.Decision != "allow" {
		t.Fatalf("expected allow, got %s", resAllow.Decision)
	}
	hasSaveIssue := false
	hasBlanket := false
	for _, o := range resAllow.PermissionOverrides {
		if o == "mcp(linear-mcp-server/save_issue)" {
			hasSaveIssue = true
		}
		if o == "mcp(linear-mcp-server)" {
			hasBlanket = true
		}
	}
	if !hasSaveIssue || hasBlanket {
		t.Fatalf("override error, expected scoped tool without blanket: %v", resAllow.PermissionOverrides)
	}
}

func TestComputePermissionOverridesHelpers(t *testing.T) {
	// 1. MCP
	mcpOverrides := evaluator.ComputePermissionOverrides("call_mcp_tool", map[string]interface{}{
		"ServerName": "linear-mcp-server",
		"ToolName":   "get_issue",
	})
	found := false
	for _, o := range mcpOverrides {
		if o == "mcp(linear-mcp-server/get_issue)" {
			found = true
		}
		if o == "mcp(linear-mcp-server)" {
			t.Fatalf("blanket grant forbidden")
		}
	}
	if !found {
		t.Fatalf("expected scoped override")
	}

	// 2. URL
	urlOverrides := evaluator.ComputePermissionOverrides("read_url_content", map[string]interface{}{
		"Url": "https://antigravity.google/docs/hooks",
	})
	hasHost := false
	hasFull := false
	for _, o := range urlOverrides {
		if o == "read_url(antigravity.google)" {
			hasHost = true
		}
		if o == "url(https://antigravity.google/docs/hooks)" {
			hasFull = true
		}
	}
	if !hasHost || !hasFull {
		t.Fatalf("missing url overrides: %v", urlOverrides)
	}

	// 3. Command
	cmdOverrides := evaluator.ComputePermissionOverrides("run_command", map[string]interface{}{
		"CommandLine": "npm test -- --coverage",
	})
	if len(cmdOverrides) != 1 || cmdOverrides[0] != "command(npm test -- --coverage)" {
		t.Fatalf("unexpected command overrides: %v", cmdOverrides)
	}

	// 4. File edit — a single, precisely scoped write_file override (matches Python's
	// compute_permission_overrides; granting write_to_file/replace_file_content tokens too
	// would widen the resulting Antigravity permission scope beyond what was evaluated).
	fileOverrides := evaluator.ComputePermissionOverrides("write_to_file", map[string]interface{}{
		"TargetFile": "src/app.py",
	})
	if len(fileOverrides) != 1 || fileOverrides[0] != "write_file(src/app.py)" {
		t.Fatalf("unexpected file overrides: %v", fileOverrides)
	}

	// 5. Empty
	if len(evaluator.ComputePermissionOverrides("view_file", map[string]interface{}{})) != 0 {
		t.Fatalf("expected empty")
	}
	if len(evaluator.ComputePermissionOverrides("call_mcp_tool", nil)) != 0 {
		t.Fatalf("expected empty")
	}

	// 6. Malicious injection
	malicious := evaluator.ComputePermissionOverrides("call_mcp_tool", map[string]interface{}{
		"ServerName": "linear;rm -rf /",
		"ToolName":   "save) or (*",
	})
	if len(malicious) != 0 {
		t.Fatalf("expected empty on malicious injection, got %v", malicious)
	}

	// 7. Malformed URL
	badURL := evaluator.ComputePermissionOverrides("read_url_content", map[string]interface{}{
		"Url": "http://[invalid-ipv6",
	})
	if len(badURL) != 0 {
		t.Fatalf("expected empty on bad url, got %v", badURL)
	}
}

func TestEvaluatorRobustnessAndSecurityEdgeCases(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{"decision": "allow", "reason": "ok"}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	e := evaluator.NewSecurityEvaluator(p, cfg)

	// 1. Null / malformed inputs
	nullRes := e.EvaluateToolCall("", nil, nil)
	if nullRes.Decision != "ask" && nullRes.Decision != "force_ask" {
		t.Fatalf("expected ask or force_ask, got %s", nullRes.Decision)
	}

	// 2. Compound MCP tool names containing mutating verbs
	compoundCall := map[string]interface{}{
		"ServerName": "github-mcp",
		"ToolName":   "get_and_delete_repo",
		"Arguments":  map[string]interface{}{"repo": "test"},
	}
	compoundRes := e.EvaluateToolCall("call_mcp_tool", compoundCall, nil)
	if compoundRes.Source == "FAST-PATH" {
		t.Fatalf("compound mutating verb should never fast-path")
	}
	if compoundRes.Source != "LOCAL" {
		t.Fatalf("expected LOCAL source, got %s", compoundRes.Source)
	}

	// Legitimate read-only fast path
	safeReadRes := e.EvaluateToolCall("call_mcp_tool", map[string]interface{}{
		"ServerName": "github-mcp",
		"ToolName":   "get_issue",
		"Arguments":  map[string]interface{}{"id": 123},
	}, nil)
	if safeReadRes.Source != "FAST-PATH" {
		t.Fatalf("expected FAST-PATH for safe read")
	}

	// Empty ServerName or ToolName must not fast path
	emptyServerRes := e.EvaluateToolCall("call_mcp_tool", map[string]interface{}{
		"ServerName": "",
		"ToolName":   "get_issue",
	}, nil)
	if emptyServerRes.Source == "FAST-PATH" {
		t.Fatalf("empty server name should not fast-path")
	}
}

func TestUserApprovalNegationAndEmptyTarget(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{"decision": "deny", "reason": "blocked"}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	e := evaluator.NewSecurityEvaluator(p, cfg)

	tmpDir, err := os.MkdirTemp("", "negation-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	transcriptFile := filepath.Join(tmpDir, "transcript.jsonl")

	steps := []map[string]interface{}{
		{
			"step_index": 10,
			"type":       "PLANNER_RESPONSE",
			"tool_calls": []map[string]interface{}{
				{
					"name": "ask_question",
					"args": map[string]interface{}{
						"questions": []map[string]interface{}{
							{"options": []string{"Run git push --force", "Cancel"}},
						},
					},
				},
			},
		},
		{
			"step_index": 11,
			"type":       "USER_INPUT",
			"content":    "No, do not run git push --force under any circumstances!",
		},
	}

	var lines []string
	for _, s := range steps {
		b, _ := json.Marshal(s)
		lines = append(lines, string(b))
	}
	_ = os.WriteFile(transcriptFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)

	ctx := map[string]interface{}{"transcript_path": transcriptFile}
	res := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "git push --force"}, ctx)
	if res.Decision != "deny" {
		t.Fatalf("expected deny on user rejection, got %s", res.Decision)
	}
	if res.Source == "USER-APPROVED" {
		t.Fatalf("source should not be USER-APPROVED on rejection")
	}

	resFile := e.EvaluateToolCall("write_to_file", map[string]interface{}{"TargetFile": ""}, ctx)
	if resFile.Decision != "deny" {
		t.Fatalf("expected deny on empty target file")
	}
	if resFile.Source == "USER-APPROVED" {
		t.Fatalf("source should not be USER-APPROVED on empty target file")
	}
}

func TestWorkspaceTrustGate(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{"decision": "allow", "reason": "ok"}}
	cfg := config.NewDefaultConfig()
	cfg.FastPathReadOnly = true
	e := evaluator.NewSecurityEvaluator(p, cfg)

	fakeWS := filepath.Join(os.TempDir(), "untrusted_repo")
	ctx := map[string]interface{}{"workspace_paths": []string{fakeWS}}

	// 1. Untrusted workspace -> triggers WORKSPACE-TRUST deny on first tool call (including fast paths)
	evaluator.GetTrustedWorkspacesHook = func() map[string]bool { return make(map[string]bool) }
	evaluator.GetDeclinedWorkspacesHook = func() map[string]bool { return make(map[string]bool) }
	defer func() {
		evaluator.GetTrustedWorkspacesHook = nil
		evaluator.GetDeclinedWorkspacesHook = nil
	}()

	// Fast path read-only tool is intercepted upfront
	resView := e.EvaluateToolCall("view_file", map[string]interface{}{"AbsolutePath": filepath.Join(fakeWS, "main.py")}, ctx)
	if resView.Decision != "deny" {
		t.Fatalf("expected deny for untrusted workspace on view_file, got %s", resView.Decision)
	}
	if resView.Source != "WORKSPACE-TRUST" {
		t.Fatalf("expected WORKSPACE-TRUST source, got %s", resView.Source)
	}
	if !strings.Contains(resView.Reason, "trust-ide") {
		t.Fatalf("expected trust-ide in reason")
	}
	if !strings.Contains(resView.Reason, "REMEDIATION DIRECTIVE") {
		t.Fatalf("expected REMEDIATION DIRECTIVE in reason")
	}

	// Command is also intercepted upfront
	resCmd := e.EvaluateToolCall("run_command", map[string]interface{}{"CommandLine": "npm test"}, ctx)
	if resCmd.Decision != "deny" {
		t.Fatalf("expected deny for untrusted workspace on run_command, got %s", resCmd.Decision)
	}
	if resCmd.Source != "WORKSPACE-TRUST" {
		t.Fatalf("expected WORKSPACE-TRUST source, got %s", resCmd.Source)
	}

	// 2. Trusted workspace -> normal evaluation (fast path works)
	evaluator.GetTrustedWorkspacesHook = func() map[string]bool {
		return map[string]bool{strings.ToLower(fakeWS): true}
	}
	resViewTrusted := e.EvaluateToolCall("view_file", map[string]interface{}{"AbsolutePath": filepath.Join(fakeWS, "main.py")}, ctx)
	if resViewTrusted.Decision != "allow" {
		t.Fatalf("expected allow for trusted workspace on view_file, got %s", resViewTrusted.Decision)
	}
	if resViewTrusted.Source != "FAST-PATH" {
		t.Fatalf("expected FAST-PATH source for trusted workspace, got %s", resViewTrusted.Source)
	}

	// 3. Declined workspace -> normal evaluation (fast path works)
	evaluator.GetTrustedWorkspacesHook = func() map[string]bool { return make(map[string]bool) }
	evaluator.GetDeclinedWorkspacesHook = func() map[string]bool {
		return map[string]bool{strings.ToLower(fakeWS): true}
	}
	resViewDeclined := e.EvaluateToolCall("view_file", map[string]interface{}{"AbsolutePath": filepath.Join(fakeWS, "main.py")}, ctx)
	if resViewDeclined.Decision != "allow" {
		t.Fatalf("expected allow for declined workspace, got %s", resViewDeclined.Decision)
	}
	if resViewDeclined.Source != "FAST-PATH" {
		t.Fatalf("expected FAST-PATH source for declined workspace, got %s", resViewDeclined.Source)
	}

	// 4. trust-ide command itself fast-paths as ALLOW even in untrusted workspace
	evaluator.GetTrustedWorkspacesHook = func() map[string]bool { return make(map[string]bool) }
	evaluator.GetDeclinedWorkspacesHook = func() map[string]bool { return make(map[string]bool) }
	resTrust := e.EvaluateToolCall("run_command", map[string]interface{}{
		"CommandLine": `python -m auto_permissions.cli trust-ide --workspace "` + fakeWS + `"`,
	}, ctx)
	if resTrust.Decision != "allow" {
		t.Fatalf("expected allow for trust-ide command, got %s", resTrust.Decision)
	}
	if resTrust.Source != "FAST-PATH" {
		t.Fatalf("expected FAST-PATH source for trust-ide, got %s", resTrust.Source)
	}
}

func TestHealCorruptedGitIndex(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "git-heal-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	gitDir := filepath.Join(tmpDir, ".git")
	_ = os.MkdirAll(gitDir, 0755)
	indexFile := filepath.Join(gitDir, "index")
	_ = os.WriteFile(indexFile, []byte(""), 0644)

	called := false
	origRunner := evaluator.GitIndexRepairRunner
	evaluator.GitIndexRepairRunner = func(dir string) error {
		called = true
		return nil
	}
	defer func() { evaluator.GitIndexRepairRunner = origRunner }()

	healed := evaluator.HealCorruptedGitIndexIfNeeded("git status", tmpDir, map[string]interface{}{"workspace_paths": []string{tmpDir}})
	if !healed {
		t.Fatalf("expected index to be healed")
	}
	if _, err := os.Stat(indexFile); !os.IsNotExist(err) {
		t.Fatalf("expected corrupted index file to be deleted")
	}
	if !called {
		t.Fatalf("expected repair runner to be called")
	}
}

func TestDoNotHealValidGitIndex(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "git-heal-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	gitDir := filepath.Join(tmpDir, ".git")
	_ = os.MkdirAll(gitDir, 0755)
	indexFile := filepath.Join(gitDir, "index")
	_ = os.WriteFile(indexFile, []byte(strings.Repeat("x", 64)), 0644)

	called := false
	origRunner := evaluator.GitIndexRepairRunner
	evaluator.GitIndexRepairRunner = func(dir string) error {
		called = true
		return nil
	}
	defer func() { evaluator.GitIndexRepairRunner = origRunner }()

	healed := evaluator.HealCorruptedGitIndexIfNeeded("git status", tmpDir, map[string]interface{}{"workspace_paths": []string{tmpDir}})
	if healed {
		t.Fatalf("expected valid index not to be healed")
	}
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		t.Fatalf("expected valid index file to remain")
	}
	if called {
		t.Fatalf("repair runner should not have been called")
	}
}

// TestYoloModeDoesNotBypassProtectedPaths guards against a regression where YOLO mode's
// auto-allow fast-path returned before the protected-paths guard ever ran, letting a
// write to a credential file (.env, id_rsa, ...) through with zero review.
func TestYoloModeDoesNotBypassProtectedPaths(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{"decision": "deny", "reason": "Writes to .env require review."}}
	cfg := config.NewDefaultConfig()
	cfg.PolicyMode = policy.ModeYolo
	e := evaluator.NewSecurityEvaluator(p, cfg)

	res := e.EvaluateToolCall("write_to_file", map[string]interface{}{"TargetFile": ".env"}, nil)
	if res.Source == "FAST-PATH" {
		t.Fatalf("expected protected-path write to fall through to the provider in YOLO mode, got FAST-PATH auto-allow: %+v", res)
	}
	if res.Decision != "deny" {
		t.Fatalf("expected the provider's deny decision to be honored, got %s", res.Decision)
	}
}

// TestYoloModeStillFastPathsSafeWrites confirms the protected-path guard didn't turn into
// an accidental blanket LLM-routing for every YOLO write.
func TestYoloModeStillFastPathsSafeWrites(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{"decision": "deny", "reason": "should not be called"}}
	cfg := config.NewDefaultConfig()
	cfg.PolicyMode = policy.ModeYolo
	e := evaluator.NewSecurityEvaluator(p, cfg)

	res := e.EvaluateToolCall("write_to_file", map[string]interface{}{"TargetFile": "src/app.py"}, nil)
	if res.Decision != "allow" || res.Source != "FAST-PATH" {
		t.Fatalf("expected YOLO fast-path allow for a non-protected file, got %+v", res)
	}
}

// TestTranscriptApprovalRequiresExactPathMatch guards against a regression where file
// authorization was granted via substring matching against the raw approved-command text,
// letting an unrelated prior approval (mentioning any filename ending in ".env") silently
// authorize a write to an unrelated ".env" file.
func TestTranscriptApprovalRequiresExactPathMatch(t *testing.T) {
	p := &mockProvider{response: map[string]interface{}{"decision": "deny", "reason": "Writes to .env require review."}}
	cfg := config.NewDefaultConfig()
	e := evaluator.NewSecurityEvaluator(p, cfg)

	tmpDir, err := os.MkdirTemp("", "transcript-substring-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	transcriptFile := filepath.Join(tmpDir, "transcript.jsonl")
	steps := []map[string]interface{}{
		{
			"step_index": 10,
			"type":       "PLANNER_RESPONSE",
			"tool_calls": []map[string]interface{}{
				{
					"name": "ask_question",
					"args": map[string]interface{}{
						"questions": []map[string]interface{}{
							{"options": []string{"Diff the frontend config (git diff frontend.env)"}},
						},
					},
				},
			},
		},
		{
			"step_index": 11,
			"type":       "GENERIC",
			"content":    "A1: Diff the frontend config (git diff frontend.env)",
		},
	}
	var lines []string
	for _, s := range steps {
		b, _ := json.Marshal(s)
		lines = append(lines, string(b))
	}
	if err := os.WriteFile(transcriptFile, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := map[string]interface{}{"transcript_path": transcriptFile}
	res := e.EvaluateToolCall("write_to_file", map[string]interface{}{"TargetFile": ".env"}, ctx)
	if res.Source == "USER-APPROVED" {
		t.Fatalf("expected the unrelated 'frontend.env' approval NOT to authorize writing '.env', got %+v", res)
	}
	if res.Decision != "deny" {
		t.Fatalf("expected the provider's deny decision to be honored, got %s", res.Decision)
	}
}

// TestSafeLocalGitCommandHandlesQuotedArguments guards against a regression where a naive
// whitespace tokenizer (strings.Fields) shattered quoted commit messages into separate
// words, so an ordinary English word that also happens to be a risky git flag (reset,
// clean, drop, restore, remote, clear) inside a quoted -m argument spuriously disqualified
// an otherwise-safe local commit from the fast path.
func TestSafeLocalGitCommandHandlesQuotedArguments(t *testing.T) {
	safeCases := []string{
		`git commit -m "clean up dead code"`,
		`git commit -m "reset defaults to sane values"`,
		`git commit -m "drop unused import"`,
		`git commit -m 'restore the original behavior'`,
	}
	for _, c := range safeCases {
		if !evaluator.IsSafeLocalGitCommand(c) {
			t.Errorf("expected %q to be fast-path safe (quoted commit message), got unsafe", c)
		}
	}

	// A risky flag as a real standalone token (not inside quotes) must still be caught.
	unsafeCases := []string{
		`git push --force origin main`,
		`git checkout .`,
		`git checkout -- somefile.txt`,
	}
	for _, c := range unsafeCases {
		if evaluator.IsSafeLocalGitCommand(c) {
			t.Errorf("expected %q to be unsafe, got fast-path safe", c)
		}
	}
}
