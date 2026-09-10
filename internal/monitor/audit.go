package monitor

import (
	"encoding/json"
	"fmt"
	"math"
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
	Timestamp      float64                `json:"timestamp"`
	TimeStr        string                 `json:"time_str"`
	Project        string                 `json:"project"`
	Source         string                 `json:"source"`
	Tool           string                 `json:"tool"`
	ArgsSummary    string                 `json:"args_summary"`
	Args           string                 `json:"args,omitempty"`
	Decision       string                 `json:"decision"`
	Reason         string                 `json:"reason"`
	LatencyMS      float64                `json:"latency_ms"`
	ConversationID string                 `json:"conversation_id,omitempty"`
	RawArgs        map[string]interface{} `json:"raw_args,omitempty"`
}

func cleanBase(p string) string {
	p = strings.TrimRight(p, `/\`)
	if idx := strings.LastIndexAny(p, `/\`); idx != -1 {
		return p[idx+1:]
	}
	return p
}

func cleanDirBase(p string) string {
	p = strings.TrimRight(p, `/\`)
	if idx := strings.LastIndexAny(p, `/\`); idx != -1 {
		parent := p[:idx]
		return cleanBase(parent)
	}
	return p
}

func ExtractProjectName(context map[string]interface{}, toolArgs map[string]interface{}) string {
	if context != nil {
		if ws, ok := context["workspace_paths"].([]string); ok && len(ws) > 0 && ws[0] != "" {
			return cleanBase(ws[0])
		}
		if wsAny, ok := context["workspace_paths"].([]interface{}); ok && len(wsAny) > 0 {
			if s, ok := wsAny[0].(string); ok && s != "" {
				return cleanBase(s)
			}
		}
	}
	if toolArgs != nil {
		if cwd, ok := toolArgs["Cwd"].(string); ok && cwd != "" {
			return cleanBase(cwd)
		}
		for _, key := range []string{"TargetFile", "AbsolutePath", "SearchPath"} {
			if p, ok := toolArgs[key].(string); ok && p != "" {
				return cleanDirBase(p)
			}
		}
		for _, key := range []string{"TargetDirectory", "DirectoryPath"} {
			if p, ok := toolArgs[key].(string); ok && p != "" {
				return cleanBase(p)
			}
		}
	}
	return "workspace"
}

func SummarizeArgs(toolName string, toolArgs map[string]interface{}) string {
	if toolArgs == nil {
		return ""
	}
	if cmd, ok := toolArgs["CommandLine"].(string); ok && cmd != "" {
		return cmd
	}
	if p, ok := toolArgs["AbsolutePath"].(string); ok && p != "" {
		return cleanBase(p)
	}
	if p, ok := toolArgs["TargetFile"].(string); ok && p != "" {
		return cleanBase(p)
	}
	if p, ok := toolArgs["DirectoryPath"].(string); ok && p != "" {
		return cleanBase(p)
	}
	if q, ok := toolArgs["Query"].(string); ok && q != "" {
		return "query: " + q
	}
	if u, ok := toolArgs["Url"].(string); ok && u != "" {
		return u
	}
	if toolName == "call_mcp_tool" {
		s, _ := toolArgs["ServerName"].(string)
		t, _ := toolArgs["ToolName"].(string)
		if s != "" || t != "" {
			return s + "/" + t
		}
	}
	b, err := json.Marshal(toolArgs)
	if err != nil {
		return ""
	}
	s := string(b)
	if len(s) <= 60 {
		return s
	}
	return s[:57] + "..."
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
		// Write-then-rename instead of writing the audit file in place: a concurrent
		// hook process's RecordAuditEvent append (or a second trim) racing an in-place
		// WriteFile could lose the append or leave the file truncated/corrupted. Renaming
		// a fully-written temp file over the original is atomic, and if it fails (e.g. a
		// locked file on Windows) the original is left untouched — safe to retry next
		// interval, matching the crash-safe behavior of the Python implementation.
		tmpPath := auditPath + ".tmp"
		if err := os.WriteFile(tmpPath, []byte(out), 0644); err == nil {
			if err := os.Rename(tmpPath, auditPath); err != nil {
				_ = os.Remove(tmpPath)
			}
		}
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
	logDir := filepath.Join(home, ".gemini", "antigravity", "logs")
	_ = os.MkdirAll(logDir, 0755)

	auditFile := filepath.Join(logDir, "audit.jsonl")

	srcUpper := strings.ToUpper(source)
	// Split telemetry: engine failure/timeout events also go to engine-failures.jsonl
	isEngineFailure := srcUpper == "OFFLINE" || srcUpper == "TIMEOUT" || srcUpper == "ERROR"

	now := time.Now()
	nowUnix := float64(now.Unix())

	var convID string
	if context != nil {
		if cid, ok := context["conversation_id"].(string); ok && cid != "" {
			if len(cid) > 8 {
				convID = cid[:8]
			} else {
				convID = cid
			}
		}
	}

	summary := SummarizeArgs(toolName, toolArgs)

	evt := AuditEvent{
		Timestamp:      nowUnix,
		TimeStr:        now.Format("15:04:05"),
		Project:        ExtractProjectName(context, toolArgs),
		Source:         srcUpper,
		Tool:           toolName,
		ArgsSummary:    summary,
		Args:           summary,
		Decision:       strings.ToUpper(decision),
		Reason:         reason,
		LatencyMS:      math.Round(latencyMS*10) / 10,
		ConversationID: convID,
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
