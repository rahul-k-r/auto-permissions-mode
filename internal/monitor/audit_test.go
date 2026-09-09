package monitor_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahul-k-r/auto-permissions-mode/internal/monitor"
)

func TestExtractProjectNameAndSummarize(t *testing.T) {
	ctx := map[string]interface{}{"workspace_paths": []string{"/home/user/projects/my-app"}}
	if got := monitor.ExtractProjectName(ctx, nil); got != "my-app" {
		t.Fatalf("expected my-app, got %s", got)
	}
	if got := monitor.ExtractProjectName(nil, map[string]interface{}{"Cwd": `C:\projects\backend`}); got != "backend" {
		t.Fatalf("expected backend, got %s", got)
	}
	if got := monitor.ExtractProjectName(nil, map[string]interface{}{"TargetFile": `C:\projects\my-repo\src\main.go`}); got != "src" {
		t.Fatalf("expected src, got %s", got)
	}
	if got := monitor.ExtractProjectName(nil, map[string]interface{}{"DirectoryPath": `C:\projects\my-repo`}); got != "my-repo" {
		t.Fatalf("expected my-repo, got %s", got)
	}
	if got := monitor.ExtractProjectName(nil, nil); got != "workspace" {
		t.Fatalf("expected workspace fallback, got %s", got)
	}

	// Test SummarizeArgs
	if got := monitor.SummarizeArgs("run_command", map[string]interface{}{"CommandLine": "git status"}); got != "git status" {
		t.Fatalf("expected git status, got %s", got)
	}
	if got := monitor.SummarizeArgs("view_file", map[string]interface{}{"AbsolutePath": `C:\foo\bar\main.go`}); got != "main.go" {
		t.Fatalf("expected main.go, got %s", got)
	}
	if got := monitor.SummarizeArgs("write_to_file", map[string]interface{}{"TargetFile": `/home/user/code/index.ts`}); got != "index.ts" {
		t.Fatalf("expected index.ts, got %s", got)
	}
	if got := monitor.SummarizeArgs("list_dir", map[string]interface{}{"DirectoryPath": `/home/user/code`}); got != "code" {
		t.Fatalf("expected code, got %s", got)
	}
	if got := monitor.SummarizeArgs("grep_search", map[string]interface{}{"Query": "RecordAuditEvent"}); got != "query: RecordAuditEvent" {
		t.Fatalf("expected query: RecordAuditEvent, got %s", got)
	}
	if got := monitor.SummarizeArgs("read_url_content", map[string]interface{}{"Url": "https://example.com/api"}); got != "https://example.com/api" {
		t.Fatalf("expected url, got %s", got)
	}
}

func TestAuditEventSerialization(t *testing.T) {
	evt := monitor.AuditEvent{
		Timestamp:      1788980000.5,
		TimeStr:        "15:04:05",
		Project:        "my-project",
		Source:         "FAST-PATH",
		Tool:           "run_command",
		ArgsSummary:    "git status",
		Args:           "git status",
		Decision:       "ALLOW",
		Reason:         "Safe command",
		LatencyMS:      1.2,
		ConversationID: "abcdef12",
	}

	b, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("failed to marshal AuditEvent: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if m["time_str"] != "15:04:05" {
		t.Errorf("expected time_str 15:04:05, got %v", m["time_str"])
	}
	if m["args_summary"] != "git status" {
		t.Errorf("expected args_summary 'git status', got %v", m["args_summary"])
	}
	if m["args"] != "git status" {
		t.Errorf("expected args 'git status', got %v", m["args"])
	}
	if m["source"] != "FAST-PATH" {
		t.Errorf("expected source FAST-PATH, got %v", m["source"])
	}
	if m["decision"] != "ALLOW" {
		t.Errorf("expected decision ALLOW, got %v", m["decision"])
	}
}

func TestTrimAuditLogRetentionAndMaxLines(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "audit-trim-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	now := float64(time.Now().Unix())
	oldTs := now - float64(20*86400)
	recentTs := now - 100

	entries := []map[string]interface{}{
		{"timestamp": oldTs, "tool": "old_tool_1"},
		{"timestamp": oldTs, "tool": "old_tool_2"},
		{"timestamp": recentTs, "tool": "recent_1"},
		{"timestamp": recentTs, "tool": "recent_2"},
		{"timestamp": recentTs, "tool": "recent_3"},
	}

	var rawLines []string
	for _, e := range entries {
		b, _ := json.Marshal(e)
		rawLines = append(rawLines, string(b))
	}
	_ = os.WriteFile(auditPath, []byte(strings.Join(rawLines, "\n")+"\n"), 0644)

	pruned := monitor.TrimAuditLog(14, 10, auditPath)
	if pruned != 2 {
		t.Fatalf("expected 2 pruned, got %d", pruned)
	}

	data, _ := os.ReadFile(auditPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 remaining, got %d", len(lines))
	}

	prunedCap := monitor.TrimAuditLog(14, 2, auditPath)
	if prunedCap != 1 {
		t.Fatalf("expected 1 pruned by max_lines, got %d", prunedCap)
	}
	data2, _ := os.ReadFile(auditPath)
	lines2 := strings.Split(strings.TrimSpace(string(data2)), "\n")
	if len(lines2) != 2 {
		t.Fatalf("expected 2 remaining, got %d", len(lines2))
	}
}

// TestTrimAuditLogLeavesFileUntouchedOnRenameFailure guards against a regression where
// trimming wrote the audit file in place: a concurrent RecordAuditEvent append (or a second
// trim) racing an in-place WriteFile could lose the append or leave the file truncated. The
// fix writes to a temp file and renames it over the original; this test only checks the
// happy path leaves valid, complete JSONL behind (a real concurrent-writer race is
// inherently non-deterministic to reproduce in a unit test).
func TestTrimAuditLogProducesValidJSONLAfterTrim(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "audit-trim-atomic-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	now := float64(time.Now().Unix())
	var rawLines []string
	for i := 0; i < 20; i++ {
		b, _ := json.Marshal(map[string]interface{}{"timestamp": now, "tool": "t"})
		rawLines = append(rawLines, string(b))
	}
	_ = os.WriteFile(auditPath, []byte(strings.Join(rawLines, "\n")+"\n"), 0644)

	monitor.TrimAuditLog(14, 5, auditPath)

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("expected audit file to survive trim, got error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines after trim, got %d", len(lines))
	}
	for _, l := range lines {
		var item map[string]interface{}
		if err := json.Unmarshal([]byte(l), &item); err != nil {
			t.Fatalf("expected valid JSONL after trim, got invalid line %q: %v", l, err)
		}
	}
	// No leftover temp file.
	if _, err := os.Stat(auditPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected no leftover .tmp file after a successful trim")
	}
}

// The ~/.gemini/antigravity/logs path fix in RecordAuditEvent is intentionally not covered
// here: RecordAuditEvent has no injection point for the log directory, so a test exercising
// it for real would write into the developer's actual home directory as a side effect.
// Verified instead by direct code inspection and a one-off manual run.
