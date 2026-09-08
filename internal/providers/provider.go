package providers

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"time"
)

// Provider defines the common evaluation interface.
type Provider interface {
	Evaluate(systemPrompt, prompt string) (map[string]interface{}, string, error)
	GetEndpoint() string
}

// ResolveAPIKey mirrors Python's precedence exactly: a provider-specific config key first,
// then the generic api_key, and only then the environment variable. specificKey and
// genericKey are read from the already-loaded Config (whichever file — project-local or
// global — it came from), not re-read from a hardcoded global path, so a project-local
// auto-permissions.json setting api_key is honored the same way Python's config.get(...)
// dict lookup is, regardless of which config file it happened to be set in.
func ResolveAPIKey(envVar, specificKey, genericKey string) string {
	if specificKey != "" {
		return strings.TrimSpace(specificKey)
	}
	if genericKey != "" {
		return strings.TrimSpace(genericKey)
	}
	if val := os.Getenv(envVar); val != "" {
		return strings.TrimSpace(val)
	}
	return ""
}

var (
	thinkBlockClosedRegex   = regexp.MustCompile(`(?s)<think>.*?</think>`)
	thinkBlockUnclosedRegex = regexp.MustCompile(`(?s)<think>.*$`)
	decisionRegex           = regexp.MustCompile(`(?i)"decision"\s*:\s*"(allow|deny|ask|force_ask)"`)
	reasonRegex             = regexp.MustCompile(`"reason"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)`)
)

func ParseJSONSafely(rawText string) map[string]interface{} {
	trimmed := strings.TrimSpace(rawText)
	if trimmed == "" {
		return nil
	}

	// 1. Strip completed or unclosed <think> blocks
	cleaned := thinkBlockClosedRegex.ReplaceAllString(trimmed, "")
	cleaned = strings.TrimSpace(thinkBlockUnclosedRegex.ReplaceAllString(cleaned, ""))
	if cleaned == "" {
		return nil
	}

	// 2. Strip markdown code fence if wrapped
	if strings.HasPrefix(cleaned, "```") {
		lines := strings.Split(cleaned, "\n")
		if len(lines) >= 2 {
			endIdx := len(lines) - 1
			for i := len(lines) - 1; i > 0; i-- {
				if strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
					endIdx = i
					break
				}
			}
			cleaned = strings.TrimSpace(strings.Join(lines[1:endIdx], "\n"))
		}
	}

	// 3. Try direct parse
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(cleaned), &parsed); err == nil && parsed != nil {
		return parsed
	}

	// 4. Locate first '{' and parse from there
	idx := strings.Index(cleaned, "{")
	if idx != -1 {
		sub := cleaned[idx:]
		decoder := json.NewDecoder(strings.NewReader(sub))
		var subParsed map[string]interface{}
		if err := decoder.Decode(&subParsed); err == nil && subParsed != nil {
			return subParsed
		}
	}

	// 5. Resilient regex extraction for truncated JSON
	m := decisionRegex.FindStringSubmatch(cleaned)
	if len(m) > 1 {
		dec := strings.ToLower(m[1])
		reason := "Evaluated by security model."
		rm := reasonRegex.FindStringSubmatch(cleaned)
		if len(rm) > 1 {
			reason = strings.TrimSpace(rm[1])
		}
		return map[string]interface{}{
			"decision": dec,
			"reason":   reason,
		}
	}

	return nil
}

func IsInTTLCooldown(path string, key string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return false
	}
	until, ok := obj[key].(float64)
	if !ok {
		return false
	}
	return float64(time.Now().Unix()) < until
}

func WriteTTLCooldown(path string, durationSeconds float64, key string, extra map[string]interface{}) {
	now := float64(time.Now().Unix())
	data := map[string]interface{}{
		key: now + durationSeconds,
	}
	for k, v := range extra {
		data[k] = v
	}
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0644)
}
