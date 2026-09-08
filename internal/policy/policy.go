package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Policy mode constants.
const (
	ModeBalanced = "balanced"
	ModeMild     = "mild" // Alias for balanced
	ModeYolo     = "yolo"
	ModeStrict   = "strict"
	ModeCustom   = "custom"
)

// Catastrophic command regexes for YOLO mode sanity gating.
var catastrophicPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+([/~]|(\$HOME)|\.\./|\.\.\\)`),
	// A named relative subdirectory (rm -rf ./build, rm -rf dist/) is treated as an
	// accepted YOLO-safe build-cleanup operation, but a bare wildcard, bare "." (the cwd
	// itself) — optionally spelled "./" or "./*" — or no target at all is just as
	// destructive as an absolute path and was previously missed entirely since it has no
	// leading "/", "~", or "../".
	regexp.MustCompile(`(?i)\brm\s+(-[a-z]*r[a-z]*f[a-z]*\b|-[a-z]*f[a-z]*r[a-z]*\b|--recursive\b.*--force\b|--force\b.*--recursive\b)\s*(\./)?[.*]?\s*$`),
	// Switch order is irrelevant to cmd.exe, so match /s and /q in either order.
	regexp.MustCompile(`(?i)\bdel\b.*(/s\b.*/q\b|/q\b.*/s\b)`),
	regexp.MustCompile(`(?i)\bdrop\s+database\s+(prod|production|main|master)\b`),
	regexp.MustCompile(`(?i)\bformat\s+[a-z]:`),
	regexp.MustCompile(`(?i)\bgit\s+push\b.*(--force|-f)\b.*\b(main|master)\b`),
	regexp.MustCompile(`(?i)\bgit\s+push\b.*\b(main|master)\b.*(--force|-f)\b`),
}

// NormalizeMode normalizes user input into one of the supported modes.
func NormalizeMode(mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	switch m {
	case ModeYolo:
		return ModeYolo
	case ModeStrict:
		return ModeStrict
	case ModeCustom:
		return ModeCustom
	case ModeMild, ModeBalanced:
		return ModeBalanced
	default:
		return ModeBalanced
	}
}

// ResolveCustomPolicyContent searches for custom policy.md file and returns its content.
func ResolveCustomPolicyContent(customPath string) (string, error) {
	candidates := []string{}
	if strings.TrimSpace(customPath) != "" {
		candidates = append(candidates, customPath)
	}

	cwd, err := os.Getwd()
	if err == nil {
		candidates = append(candidates, filepath.Join(cwd, ".agents", "policy.md"))
		candidates = append(candidates, filepath.Join(cwd, "policy.md"))
	}

	home, err := os.UserHomeDir()
	if err == nil {
		candidates = append(candidates, filepath.Join(home, ".gemini", "config", "policy.md"))
		candidates = append(candidates, filepath.Join(home, ".config", "auto-permissions", "policy.md"))
	}

	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			data, err := os.ReadFile(p)
			if err == nil && len(strings.TrimSpace(string(data))) > 0 {
				return string(data), nil
			}
		}
	}

	return "", fmt.Errorf("custom policy file not found in candidates: %v", candidates)
}

// BuildSystemPrompt constructs the full system prompt by combining the selected rules block
// with the immutable OutputContract.
func BuildSystemPrompt(mode string, customPath string) string {
	norm := NormalizeMode(mode)
	var rules string

	switch norm {
	case ModeYolo:
		rules = YoloRules
	case ModeStrict:
		rules = StrictRules
	case ModeCustom:
		customContent, err := ResolveCustomPolicyContent(customPath)
		if err == nil {
			rules = customContent
		} else {
			// Fall back to balanced rules if custom policy file is missing
			rules = BalancedRules
		}
	default:
		rules = BalancedRules
	}

	return strings.TrimSpace(rules) + "\n\n" + strings.TrimSpace(OutputContract) + "\n"
}

// IsCatastrophicCommand checks if a shell command matches extreme disaster patterns (used for YOLO gating).
func IsCatastrophicCommand(commandLine string) bool {
	cmd := strings.TrimSpace(commandLine)
	if cmd == "" {
		return false
	}
	for _, pattern := range catastrophicPatterns {
		if pattern.MatchString(cmd) {
			return true
		}
	}
	return false
}
