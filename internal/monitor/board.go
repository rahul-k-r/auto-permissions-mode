package monitor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rahul-k-r/auto-permissions-mode/internal/config"
)

// GetAuditFilePath returns the path to ~/.gemini/antigravity/logs/audit.jsonl
func GetAuditFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".gemini", "antigravity", "logs", "audit.jsonl"), nil
}

func getTerminalWidth() int {
	if c := os.Getenv("COLUMNS"); c != "" {
		if n, err := strconv.Atoi(c); err == nil && n >= 80 {
			return n
		}
	}
	return 120
}

// PrintEventLine renders a single audit event line with ANSI color badges and reason disclosure.
func PrintEventLine(rawJSONLine string, termWidth int) {
	line := strings.TrimSpace(rawJSONLine)
	if line == "" {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		return
	}

	dec, _ := data["decision"].(string)
	if dec == "" {
		dec = "UNKNOWN"
	}
	decUpper := strings.ToUpper(dec)

	src, _ := data["source"].(string)
	if src == "" {
		src = "LOCAL"
	}
	srcUpper := strings.ToUpper(src)

	timeStr, _ := data["time_str"].(string)
	if timeStr == "" {
		if ts, ok := data["timestamp"].(float64); ok && ts > 0 {
			timeStr = time.Unix(int64(ts), 0).Format("15:04:05")
		}
	}

	project, _ := data["project"].(string)
	if project == "" {
		project = "workspace"
	}
	if len(project) > 15 {
		project = project[:15]
	}

	latencyVal := 0.0
	if lat, ok := data["latency_ms"].(float64); ok {
		latencyVal = lat
	}
	latStr := fmt.Sprintf("%.1fms", latencyVal)

	tool, _ := data["tool"].(string)
	if len(tool) > 13 {
		tool = tool[:13]
	}

	summary, _ := data["args_summary"].(string)
	if summary == "" {
		summary, _ = data["args"].(string)
	}

	if termWidth < 80 {
		termWidth = 80
	}
	fixedPrefixLen := 9 + 3 + 16 + 3 + 10 + 3 + 10 + 3 + 8 + 3 + 14 + 3 // ~82
	availableTargetLen := termWidth - fixedPrefixLen - 2
	if availableTargetLen < 15 {
		availableTargetLen = 15
	}

	displaySummary := summary
	if len(summary) > availableTargetLen {
		maxLen := availableTargetLen - 3
		if maxLen < 10 {
			maxLen = 10
		}
		displaySummary = summary[:maxLen] + "..."
	}

	// Source Badges
	var srcBadge string
	switch {
	case srcUpper == "FAST-PATH" || srcUpper == "FASTPATH" || srcUpper == "RULES" || srcUpper == "RULE" || srcUpper == "AUTO":
		srcBadge = "\033[32mAUTO      \033[0m"
	case srcUpper == "USER-APPROVED" || srcUpper == "USER-APP" || srcUpper == "USER" || srcUpper == "APPROVED":
		srcBadge = "\033[92mUSER-APP  \033[0m"
	case srcUpper == "LOCAL":
		srcBadge = "\033[36mLOCAL-LLM \033[0m"
	case strings.Contains(srcUpper, "FAIL"):
		srcBadge = "\033[35mFAILOVER  \033[0m"
	case srcUpper == "CLOUD":
		srcBadge = "\033[34mCLOUD-LLM \033[0m"
	case srcUpper == "OFFLINE":
		srcBadge = "\033[31mOFFLINE   \033[0m"
	case srcUpper == "ERROR":
		srcBadge = "\033[31mHOOK ERR  \033[0m"
	case srcUpper == "TIMEOUT":
		srcBadge = "\033[33mTIMEOUT   \033[0m"
	default:
		srcBadge = fmt.Sprintf("%-10s", srcUpper)
	}

	// Decision Badges
	var decBadge string
	switch decUpper {
	case "ALLOW":
		decBadge = "\033[32mALLOW     \033[0m"
	case "DENY":
		decBadge = "\033[31mDENY      \033[0m"
	case "ASK", "QUESTION":
		decBadge = "\033[93mASK       \033[0m"
	case "FORCE_ASK", "FORCEASK":
		decBadge = "\033[33mFORCE_ASK \033[0m"
	default:
		decBadge = fmt.Sprintf("%-10s", decUpper)
	}

	fmt.Printf("%-9s | %-16s | %s | %s | %-8s | %-14s | %s\n", timeStr, project, srcBadge, decBadge, latStr, tool, displaySummary)

	// Reason / Full Payload expansion on non-ALLOW or USER-APPROVED
	isActionRequired := decUpper == "DENY" || decUpper == "FORCE_ASK" || decUpper == "FORCEASK" || decUpper == "ASK" || decUpper == "QUESTION"
	isUserApproved := srcUpper == "USER-APPROVED" || srcUpper == "USER-APP" || srcUpper == "APPROVED"

	if isActionRequired || isUserApproved {
		if len(summary) > availableTargetLen {
			fmt.Printf("   ↳ 📋 FULL PAYLOAD: \033[97m%s\033[0m\n", summary)
		}
		if reason, ok := data["reason"].(string); ok && strings.TrimSpace(reason) != "" {
			reasonText := strings.TrimSpace(reason)
			var prefix, color string
			if isUserApproved {
				prefix = "   ↳ 👤 USER-APPROVED: "
				color = "\033[92m"
			} else if decUpper == "DENY" {
				prefix = "   ↳ 🛑 REASON: "
				color = "\033[91m"
			} else if decUpper == "ASK" || decUpper == "QUESTION" {
				prefix = "   ↳ ❓ ALTERNATIVES: "
				color = "\033[93m"
			} else if decUpper == "FORCE_ASK" || decUpper == "FORCEASK" {
				prefix = "   ↳ ⚠️ CONFIRMATION: "
				color = "\033[33m"
			} else {
				prefix = "   ↳ ℹ️ INFO: "
				color = "\033[37m"
			}
			fmt.Printf("%s%s%s\033[0m\n", color, prefix, reasonText)
		}
	}
}

// RunLiveBoard streams live hook evaluations in a real-time terminal dashboard.
func RunLiveBoard() error {
	auditFile, err := GetAuditFilePath()
	if err != nil {
		return fmt.Errorf("unable to determine audit log path: %w", err)
	}

	// Handle SIGINT (Ctrl+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	termWidth := getTerminalWidth()

	// Clear screen ANSI
	fmt.Print("\033[2J\033[H")

	sep := strings.Repeat("=", termWidth)
	thinSep := strings.Repeat("-", termWidth)

	fmt.Println(sep)
	title := "AUTO PERMISSIONS MODE — LIVE AUDIT DASHBOARD"
	pad := (termWidth - len(title)) / 2
	if pad < 0 {
		pad = 0
	}
	fmt.Println(strings.Repeat(" ", pad) + title)
	fmt.Println(sep)
	fmt.Printf("Log File : %s\n", auditFile)
	fmt.Println("Surfaces : Antigravity IDE | Antigravity 2.0 | VS Code Extension | agy CLI (Multi-Workspace)")
	fmt.Println("Status   : STREAMING LIVE HOOK EVALUATIONS (Press Ctrl+C to stop)")
	fmt.Println(sep)
	fmt.Printf("%-9s | %-16s | %-10s | %-10s | %-8s | %-14s | %s\n", "TIME", "PROJECT", "SOURCE", "DECISION", "LATENCY", "TOOL", "TARGET / COMMAND")
	fmt.Println(thinSep)

	// Trim stale entries on startup
	cfg := config.LoadConfig()
	retDays := cfg.AuditRetentionDays
	if retDays <= 0 {
		retDays = 14
	}
	maxLines := cfg.AuditMaxLines
	if maxLines <= 0 {
		maxLines = 5000
	}
	TrimAuditLog(retDays, maxLines, auditFile)

	// Read recent entries (last 12)
	var lastPos int64 = 0
	if data, readErr := os.ReadFile(auditFile); readErr == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		start := len(lines) - 12
		if start < 0 {
			start = 0
		}
		for _, l := range lines[start:] {
			if strings.TrimSpace(l) != "" {
				PrintEventLine(l, termWidth)
			}
		}
		if fi, statErr := os.Stat(auditFile); statErr == nil {
			lastPos = fi.Size()
		}
	}

	// Tail loop with exit channel
	stopChan := make(chan struct{})
	go func() {
		<-sigChan
		close(stopChan)
	}()

	for {
		select {
		case <-stopChan:
			fmt.Println("\n✓ Live audit dashboard stopped.")
			return nil
		default:
			fi, err := os.Stat(auditFile)
			if err != nil {
				time.Sleep(200 * time.Millisecond)
				continue
			}

			currSize := fi.Size()
			if currSize < lastPos {
				// File was trimmed or rotated; reset to 0
				lastPos = 0
			}

			if currSize > lastPos {
				f, openErr := os.Open(auditFile)
				if openErr == nil {
					_, _ = f.Seek(lastPos, io.SeekStart)
					scanner := bufio.NewScanner(f)
					for scanner.Scan() {
						line := scanner.Text()
						if strings.TrimSpace(line) != "" {
							PrintEventLine(line, termWidth)
						}
					}
					lastPos, _ = f.Seek(0, io.SeekCurrent)
					_ = f.Close()
				}
			}

			time.Sleep(150 * time.Millisecond)
		}
	}
}
