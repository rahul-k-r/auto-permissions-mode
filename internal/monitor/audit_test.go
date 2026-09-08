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
	if got := monitor.SummarizeArgs("run_command", map[string]interface{}{"CommandLine": "git status"}); got != "git status" {
		t.Fatalf("expected git status, got %s", got)
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
