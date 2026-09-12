package evaluator

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var recommendedPrefixPattern = regexp.MustCompile(`(?i)^\s*\(\s*recommended\s*\)\s*`)

func stripRecommendedPrefix(text string) string {
	return recommendedPrefixPattern.ReplaceAllString(text, "")
}

// ParseOptionString splits a "label -> command" or "label (command)" string into (label, command).
func ParseOptionString(raw string) (string, string) {
	text := strings.TrimSpace(raw)
	if strings.Contains(text, " -> ") {
		parts := strings.SplitN(text, " -> ", 2)
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	if strings.Contains(text, " (") && strings.HasSuffix(text, ")") {
		idx := strings.LastIndex(text, " (")
		label := strings.TrimSpace(text[:idx])
		command := strings.TrimSpace(strings.TrimSuffix(text[idx+2:], ")"))
		return label, command
	}
	return text, ""
}

// resolvePathBestEffort approximates Python's Path(p).resolve(): it makes p absolute
// relative to the working directory, falling back to the original string if that fails.
// Unlike Python's resolve(), it does not follow symlinks — a symlinked workspace path
// could fail to exact-match here where Python would consider it the same canonical path.
// That fails closed (a legitimate approval stops auto-matching, forcing an extra ask)
// rather than open, so it's a parity gap worth knowing about, not a security hole.
func resolvePathBestEffort(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func normalizeText(t string) string {
	s := regexp.MustCompile(`^\s*[-*]\s*`).ReplaceAllString(t, "")
	s = stripRecommendedPrefix(s)
	s = strings.Trim(strings.TrimSpace(s), "\"'")
	fields := strings.Fields(s)
	return strings.ToLower(strings.Join(fields, " "))
}

func extractCmdFromOption(optText string) string {
	opt := strings.TrimSpace(optText)
	_, command := ParseOptionString(opt)
	if command != "" {
		return command
	}
	if strings.Contains(opt, ": ") {
		parts := strings.SplitN(opt, ": ", 2)
		candidate := strings.TrimSpace(parts[1])
		fields := strings.Fields(candidate)
		if len(fields) > 0 {
			switch fields[0] {
			case "git", "gh", "npm", "cargo", "pip", "docker", "npx", "python", "make", "pytest", "rm", "del":
				return candidate
			}
		}
	}
	return ""
}

// CheckRecentUserApproval reads transcript.jsonl and verifies if the user explicitly authorized this action.
func CheckRecentUserApproval(toolName string, toolArgs map[string]interface{}, context map[string]interface{}) string {
	if context == nil {
		return ""
	}

	transcriptPathStr, _ := context["transcript_path"].(string)
	if strings.TrimSpace(transcriptPathStr) == "" {
		return ""
	}

	fi, err := os.Stat(transcriptPathStr)
	if err != nil || fi.IsDir() {
		return ""
	}

	// Read tail (last 64KB is <0.3ms even on multi-MB transcripts)
	fileSize := fi.Size()
	readSize := int64(65536)
	if fileSize < readSize {
		readSize = fileSize
	}

	f, err := os.Open(transcriptPathStr)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	if fileSize > readSize {
		if _, err := f.Seek(fileSize-readSize, io.SeekStart); err != nil {
			return ""
		}
	}

	rawBytes, err := io.ReadAll(f)
	if err != nil {
		return ""
	}

	lines := strings.Split(strings.TrimSpace(string(rawBytes)), "\n")
	if len(lines) == 0 {
		return ""
	}

	type stepRecord struct {
		Type      string                   `json:"type"`
		Content   string                   `json:"content"`
		ToolCalls []map[string]interface{} `json:"tool_calls"`
	}

	var steps []stepRecord
	startIdx := 0
	if len(lines) > 30 {
		startIdx = len(lines) - 30
	}

	for _, line := range lines[startIdx:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var s stepRecord
		if err := json.Unmarshal([]byte(line), &s); err == nil {
			steps = append(steps, s)
		}
	}

	if len(steps) < 2 {
		return ""
	}

	// Find the latest GENERIC step containing an ask_question answer ("A1:" or "A1")
	answerIdx := -1
	var answerStep stepRecord

	maxLookback := len(steps) - 6
	if maxLookback < 0 {
		maxLookback = 0
	}

	for i := len(steps) - 1; i >= maxLookback; i-- {
		st := steps[i]
		if st.Type == "GENERIC" {
			if strings.Contains(st.Content, "A1:") || strings.HasPrefix(strings.TrimSpace(st.Content), "A1") {
				answerStep = st
				answerIdx = i
				break
			}
		}
	}

	if answerIdx < 1 {
		return ""
	}

	// Enforce immediate predecessor & single-use:
	if answerIdx < len(steps)-2 {
		return ""
	}
	for j := answerIdx + 1; j < len(steps); j++ {
		if steps[j].Type == "GENERIC" || steps[j].Type == "TOOL_OUTPUT" || steps[j].Type == "USER_INPUT" {
			return ""
		}
	}

	// Step directly preceding answer_step must be the PLANNER_RESPONSE that invoked ask_question
	questionStep := steps[answerIdx-1]
	if questionStep.Type != "PLANNER_RESPONSE" {
		return ""
	}

	var askCall map[string]interface{}
	for _, tc := range questionStep.ToolCalls {
		if name, _ := tc["name"].(string); name == "ask_question" {
			askCall = tc
			break
		}
	}
	if askCall == nil {
		return ""
	}

	// Extract user selection text
	answerContent := answerStep.Content
	a1Idx := strings.Index(answerContent, "A1:")
	if a1Idx == -1 {
		a1Idx = strings.Index(answerContent, "A1")
	}
	userSelectionText := strings.TrimSpace(answerContent)
	if a1Idx != -1 {
		userSelectionText = strings.TrimSpace(answerContent[a1Idx:])
	}

	userClean := regexp.MustCompile(`^\s*A\d+:\s*`).ReplaceAllString(userSelectionText, "")
	userClean = strings.TrimSpace(userClean)

	// Reject explicit negations
	userCleanLower := strings.ToLower(userClean)
	if userCleanLower == "no" || userCleanLower == "cancel" || userCleanLower == "abort" ||
		userCleanLower == "reject" || userCleanLower == "deny" || userCleanLower == "stop" ||
		strings.HasPrefix(userCleanLower, "no,") || strings.HasPrefix(userCleanLower, "no ") ||
		strings.HasPrefix(userCleanLower, "don't") || strings.HasPrefix(userCleanLower, "dont") ||
		strings.HasPrefix(userCleanLower, "do not") {
		return ""
	}

	normUser := normalizeText(userClean)
	approvedCommands := make(map[string]bool)
	approvedFiles := make(map[string]bool)

	// 1. Match against questions.options defined in ask_question call
	argsMap, _ := askCall["args"].(map[string]interface{})
	if argsMap == nil {
		// Could be JSON string in args
		if argsStr, ok := askCall["args"].(string); ok {
			_ = json.Unmarshal([]byte(argsStr), &argsMap)
		}
	}

	if argsMap != nil {
		if questionsList, ok := argsMap["questions"].([]interface{}); ok {
			for _, qItem := range questionsList {
				if qMap, ok := qItem.(map[string]interface{}); ok {
					if optionsList, ok := qMap["options"].([]interface{}); ok {
						for _, optItem := range optionsList {
							if optStr, ok := optItem.(string); ok {
								cleanOpt := strings.TrimSpace(optStr)
								normOpt := normalizeText(cleanOpt)
								labelPart := normalizeText(strings.Split(cleanOpt, " -> ")[0])
								if normUser != "" && (normUser == normOpt || normUser == labelPart) {
									extracted := extractCmdFromOption(cleanOpt)
									if extracted != "" {
										approvedCommands[strings.Join(strings.Fields(extracted), " ")] = true
									}
									for _, tok := range strings.Fields(cleanOpt) {
										cleanTok := strings.Trim(tok, "'\"`")
										if strings.Contains(cleanTok, ".") && !strings.HasPrefix(cleanTok, "-") {
											approvedFiles[cleanTok] = true
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// 2. Extract command from user selection text if formatted with arrow or parens
	directCmd := extractCmdFromOption(userSelectionText)
	if directCmd != "" {
		approvedCommands[strings.Join(strings.Fields(directCmd), " ")] = true
	}

	// 3. Handle raw write-in (user typed command directly without shell metacharacters)
	if userClean != "" && !strings.ContainsAny(userClean, ShellMetachars) {
		fields := strings.Fields(userClean)
		if len(fields) > 0 {
			switch fields[0] {
			case "git", "gh", "npm", "cargo", "pip", "docker", "npx", "python", "make", "pytest":
				approvedCommands[strings.Join(fields, " ")] = true
			}
		}
	}

	if toolName == "run_command" {
		cmd, _ := toolArgs["CommandLine"].(string)
		normCmd := strings.Join(strings.Fields(cmd), " ")
		if normCmd != "" && approvedCommands[normCmd] {
			return "Verified user authorization via ask_question: '" + cmd + "'"
		}
	}

	if toolName == "write_to_file" || toolName == "replace_file_content" {
		target, _ := toolArgs["TargetFile"].(string)
		if target == "" {
			target, _ = toolArgs["AbsolutePath"].(string)
		}
		target = strings.TrimSpace(target)
		if target == "" {
			return ""
		}
		targetResolved := resolvePathBestEffort(target)

		// Exact resolved-path equality per approved token — not a substring/suffix match,
		// which would let an unrelated prior approval (e.g. one mentioning any ".env"-suffixed
		// filename) silently authorize writes to an unrelated protected file.
		for approvedCmd := range approvedCommands {
			for _, tok := range strings.Fields(approvedCmd) {
				cleanTok := strings.Trim(tok, "'\"`")
				if cleanTok == "" {
					continue
				}
				if resolvePathBestEffort(cleanTok) == targetResolved {
					return "Verified user authorization via ask_question for file: '" + target + "'"
				}
			}
		}
		for approvedFile := range approvedFiles {
			if resolvePathBestEffort(approvedFile) == targetResolved {
				return "Verified user authorization via ask_question for file: '" + target + "'"
			}
		}
	}

	return ""
}
