package monitor_test

import (
	"strings"
	"testing"

	"github.com/rahul-k-r/auto-permissions-mode/internal/monitor"
)

func TestGetAuditFilePath(t *testing.T) {
	p, err := monitor.GetAuditFilePath()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.HasSuffix(p, "audit.jsonl") {
		t.Fatalf("expected path ending in audit.jsonl, got %s", p)
	}
}

func TestPrintEventLineDoesNotPanic(t *testing.T) {
	// Empty / invalid lines
	monitor.PrintEventLine("", 120)
	monitor.PrintEventLine("   ", 120)
	monitor.PrintEventLine("not json", 120)

	// Valid lines with various decisions & sources
	allowLine := `{"time_str":"12:00:00","project":"proj","source":"AUTO","decision":"ALLOW","latency_ms":0.5,"tool":"view_file","args_summary":"main.go"}`
	monitor.PrintEventLine(allowLine, 120)

	denyLine := `{"time_str":"12:00:01","project":"proj","source":"LOCAL","decision":"DENY","latency_ms":120.3,"tool":"run_command","args_summary":"rm -rf /","reason":"Catastrophic command"}`
	monitor.PrintEventLine(denyLine, 120)

	userAppLine := `{"time_str":"12:00:02","project":"proj","source":"USER-APPROVED","decision":"ALLOW","latency_ms":1.0,"tool":"run_command","args_summary":"git push","reason":"User clicked modal"}`
	monitor.PrintEventLine(userAppLine, 120)

	forceAskLine := `{"time_str":"12:00:03","project":"proj","source":"LOCAL","decision":"FORCE_ASK","latency_ms":50.0,"tool":"run_command","args_summary":"echo hello","reason":"Needs confirmation"}`
	monitor.PrintEventLine(forceAskLine, 80)

	fallbackTimeLine := `{"timestamp":1700000000,"project":"proj","source":"FAST-PATH","decision":"ALLOW","latency_ms":0.2,"tool":"list_dir","args":"my-dir"}`
	monitor.PrintEventLine(fallbackTimeLine, 100)
}
