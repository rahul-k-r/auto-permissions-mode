package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rahul-k-r/auto-permissions-mode/internal/config"
)

var (
	lastTrimCheckTime float64
	trimMutex         sync.Mutex
)

// AuditEvent represents an entry in audit.jsonl or engine-failures.jsonl.
type AuditEvent struct {
	Timestamp float64                `json:"timestamp"`
	Tool      string                 `json:"tool"`
	Args      string                 `json:"args"`
	Decision  string                 `json:"decision"`
	LatencyMS float64                `json:"latency_ms"`
	Source    string                 `json:"source"`
	Reason    string                 `json:"reason"`
	Project   string                 `json:"project"`
	RawArgs   map[string]interface{} `json:"raw_args,omitempty"`
}

func ExtractProjectName(context map[string]interface{}, toolArgs map[string]interface{}) string {
	if context != nil {
		if ws, ok := context["workspace_paths"].([]string); ok && len(ws) > 0 && ws[0] != "" {
			return filepath.Base(filepath.Clean(ws[0]))
		}
		if wsAny, ok := context["workspace_paths"].([]interface{}); ok && len(wsAny) > 0 {
			if s, ok := wsAny[0].(string); ok && s != "" {
				return filepath.Base(filepath.Clean(s))
			}
		}
	}
	if toolArgs != nil {
		if cwd, ok := toolArgs["Cwd"].(string); ok && cwd != "" {
			return filepath.Base(filepath.Clean(cwd))
		}
	}
	return "default"
}

func SummarizeArgs(toolName string, toolArgs map[string]interface{}) string {
	if toolArgs == nil {
		return ""
	}
	if toolName == "run_command" {
		if cmd, ok := toolArgs["CommandLine"].(string); ok {
			return cmd
		}
	}
	if strings.Contains(toolName, "file") {
		if f, ok := toolArgs["TargetFile"].(string); ok && f != "" {
			return f
		}
		if f, ok := toolArgs["AbsolutePath"].(string); ok && f != "" {
			return f
		}
	}
	if toolName == "call_mcp_tool" {
		s, _ := toolArgs["ServerName"].(string)
		t, _ := toolArgs["ToolName"].(string)
		return s + "/" + t
	}
	b, _ := json.Marshal(toolArgs)
	return string(b)
}

func TrimAuditLog(retentionDays, maxLines int, auditPath string) int {
	data, err := os.ReadFile(auditPath)
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return 0
	}
	totalBefore := len(lines)
	cutoff := float64(time.Now().Unix()) - float64(retentionDays*86400)

	var surviving []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		var item map[string]interface{}
		if err := json.Unmarshal([]byte(l), &item); err == nil {
			if ts, ok := item["timestamp"].(float64); ok && ts > 0 && ts < cutoff {
				continue
			}
		}
		surviving = append(surviving, l)
	}

	if maxLines > 0 && len(surviving) > maxLines {
		surviving = surviving[len(surviving)-maxLines:]
	}

	pruned := totalBefore - len(surviving)
	if pruned > 0 {
		out := strings.Join(surviving, "\n") + "\n"
		_ = os.WriteFile(auditPath, []byte(out), 0644)
	}
	return pruned
}

func MaybeTrimAuditLog(auditPath string, cfg config.Config) {
	trimMutex.Lock()
	defer trimMutex.Unlock()

	now := float64(time.Now().Unix())
	interval := float64(cfg.AuditTrimIntervalSeconds)
	if interval <= 0 {
		interval = 3600
	}
	if now-lastTrimCheckTime < interval {
		return
	}
	lastTrimCheckTime = now

	markerFile := filepath.Join(filepath.Dir(auditPath), ".audit_last_trim")
	if fi, err := os.Stat(markerFile); err == nil {
		if now-float64(fi.ModTime().Unix()) < interval {
			return
		}
	}
	_ = os.WriteFile(markerFile, []byte(fmt.Sprintf("%f", now)), 0644)

	retDays := cfg.AuditRetentionDays
	if retDays <= 0 {
		retDays = 14
	}
	maxLines := cfg.AuditMaxLines
	if maxLines <= 0 {
		maxLines = 5000
	}
	TrimAuditLog(retDays, maxLines, auditPath)
}

func RecordAuditEvent(toolName string, toolArgs map[string]interface{}, decision, reason string, latencyMS float64, source string, context map[string]interface{}, cfg config.Config) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	logDir := filepath.Join(home, ".gemini", "logs")
	_ = os.MkdirAll(logDir, 0755)

	auditFile := filepath.Join(logDir, "audit.jsonl")

	// Split telemetry: engine failure/timeout events also go to engine-failures.jsonl
	isEngineFailure := source == "OFFLINE" || source == "TIMEOUT" || source == "ERROR"

	evt := AuditEvent{
		Timestamp: float64(time.Now().Unix()),
		Tool:      toolName,
		Args:      SummarizeArgs(toolName, toolArgs),
		Decision:  decision,
		LatencyMS: latencyMS,
		Source:    source,
		Reason:    reason,
		Project:   ExtractProjectName(context, toolArgs),
	}

	b, err := json.Marshal(evt)
	if err != nil {
		return
	}
	line := string(b) + "\n"

	f, err := os.OpenFile(auditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		_, _ = f.WriteString(line)
		_ = f.Close()
	}

	if isEngineFailure {
		failFile := filepath.Join(logDir, "engine-failures.jsonl")
		ff, err := os.OpenFile(failFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			_, _ = ff.WriteString(line)
			_ = ff.Close()
		}
	}

	MaybeTrimAuditLog(auditFile, cfg)
}
