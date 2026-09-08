package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// DefaultProtectedPaths contains the security-critical paths that can never be removed.
var DefaultProtectedPaths = []string{
	".git",
	".env",
	".ssh",
	"id_rsa",
	"id_ed25519",
	"/etc",
	"C:\\Windows",
	"C:\\Windows\\System32",
	".system_generated",
	"transcript.jsonl",
}

// Config represents the application configuration.
type Config struct {
	Provider                    string   `json:"provider"`
	Endpoint                    string   `json:"endpoint"`
	Model                       string   `json:"model"`
	NumCtx                      int      `json:"num_ctx"`
	Temperature                 float64  `json:"temperature"`
	TimeoutSeconds              float64  `json:"timeout_seconds"`
	FallbackToCloud             bool     `json:"fallback_to_cloud"`
	CloudProvider               string   `json:"cloud_provider"`
	CloudModel                  string   `json:"cloud_model"`
	CloudTimeoutSeconds         float64  `json:"cloud_timeout_seconds"`
	TotalDeadlineSeconds        float64  `json:"total_deadline_seconds"`
	FallbackAction              string   `json:"fallback_action"`
	FastPathReadOnly            bool     `json:"fast_path_read_only"`
	MaxTokens                   int      `json:"max_tokens"`
	EnableRemediationDirectives bool     `json:"enable_remediation_directives"`
	AuditRetentionDays          int      `json:"audit_retention_days"`
	AuditMaxLines               int      `json:"audit_max_lines"`
	AuditTrimIntervalSeconds    int      `json:"audit_trim_interval_seconds"`
	PolicyMode                  string   `json:"policy_mode"`
	AutoStartLocalEngine        bool     `json:"auto_start_local_engine"`
	CustomPolicyPath            string   `json:"custom_policy_path,omitempty"`
	DebugLog                    string   `json:"debug_log,omitempty"`
	ShadowMode                  bool     `json:"shadow_mode,omitempty"`
	ProtectedPaths              []string `json:"protected_paths"`
	APIKey                      string   `json:"api_key,omitempty"`
	GeminiAPIKey                string   `json:"gemini_api_key,omitempty"`
	AnthropicAPIKey             string   `json:"anthropic_api_key,omitempty"`
	OpenAIAPIKey                string   `json:"openai_api_key,omitempty"`
	OpenRouterAPIKey            string   `json:"openrouter_api_key,omitempty"`
}

// NewDefaultConfig returns a Config initialized with default settings.
func NewDefaultConfig() Config {
	return Config{
		Provider:                    "llamacpp",
		Endpoint:                    "http://127.0.0.1:9931/v1/chat/completions",
		Model:                       "auto",
		NumCtx:                      8192,
		Temperature:                 0.0,
		TimeoutSeconds:              6.0,
		FallbackToCloud:             true,
		CloudProvider:               "gemini",
		CloudModel:                  "gemini-flash-lite-latest",
		CloudTimeoutSeconds:         12.0,
		TotalDeadlineSeconds:        18.0,
		FallbackAction:              "force_ask",
		FastPathReadOnly:            true,
		MaxTokens:                   512,
		EnableRemediationDirectives: true,
		AuditRetentionDays:          14,
		AuditMaxLines:               5000,
		AuditTrimIntervalSeconds:    3600,
		PolicyMode:                  "balanced",
		AutoStartLocalEngine:        true,
		ProtectedPaths:              append([]string(nil), DefaultProtectedPaths...),
	}
}

// GetConfigSearchPaths returns the ordered list of configuration file paths.
func GetConfigSearchPaths() []string {
	var paths []string

	// 1. Project-local config (cwd)
	cwd, err := os.Getwd()
	if err == nil {
		paths = append(paths, filepath.Join(cwd, ".agents", "auto-permissions.json"))
		paths = append(paths, filepath.Join(cwd, "auto-permissions.json"))
	}

	// 2. Global user configs
	home, err := os.UserHomeDir()
	if err == nil {
		paths = append(paths, filepath.Join(home, ".gemini", "config", "auto-permissions.json"))
		paths = append(paths, filepath.Join(home, ".config", "auto-permissions", "config.json"))
	}

	// 3. Bundled default (source/executable dir)
	exePath, err := os.Executable()
	if err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exePath), "config.default.json"))
		paths = append(paths, filepath.Join(filepath.Dir(filepath.Dir(exePath)), "config.default.json"))
	}

	return paths
}

// ApplySecurityGuards enforces security invariants on the configuration.
func ApplySecurityGuards(cfg *Config) {
	// Invariant 1: fallback_action must never be 'allow'
	if strings.EqualFold(cfg.FallbackAction, "allow") {
		cfg.FallbackAction = "force_ask"
	}

	// Invariant 2: critical protected paths union merge
	protectedMap := make(map[string]bool)
	for _, p := range cfg.ProtectedPaths {
		protectedMap[p] = true
	}
	for _, def := range DefaultProtectedPaths {
		if !protectedMap[def] {
			cfg.ProtectedPaths = append(cfg.ProtectedPaths, def)
			protectedMap[def] = true
		}
	}
}

// LoadConfig reads the configuration file following search precedence and applies security guards.
func LoadConfig() Config {
	cfg := NewDefaultConfig()

	for _, path := range GetConfigSearchPaths() {
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var rawMap map[string]interface{}
			if err := json.Unmarshal(data, &rawMap); err != nil {
				// Malformed JSON syntax — the whole file is unusable, try the next
				// candidate (mirrors Python's json.load try/except continue).
				continue
			}
			mergeConfig(&cfg, rawMap)
			break
		}
	}

	ApplySecurityGuards(&cfg)
	return cfg
}

// mergeConfig applies each present, correctly-typed key from rawMap onto dst. Unlike
// unmarshaling the whole file into a typed Config struct, a single wrong-typed key (e.g.
// num_ctx given as a string) only skips that one key — every other override in the file
// still applies, matching Python's dict-based config.update() semantics instead of Go's
// unmarshal-the-whole-struct-or-nothing behavior.
func mergeConfig(dst *Config, rawMap map[string]interface{}) {
	str := func(field *string, key string) {
		if v, ok := rawMap[key]; ok {
			if s, ok := v.(string); ok {
				*field = s
			}
		}
	}
	boolean := func(field *bool, key string) {
		if v, ok := rawMap[key]; ok {
			if b, ok := v.(bool); ok {
				*field = b
			}
		}
	}
	num := func(field *float64, key string) {
		if v, ok := rawMap[key]; ok {
			if f, ok := v.(float64); ok {
				*field = f
			}
		}
	}
	intField := func(field *int, key string) {
		if v, ok := rawMap[key]; ok {
			if f, ok := v.(float64); ok {
				*field = int(f)
			}
		}
	}

	str(&dst.Provider, "provider")
	str(&dst.Endpoint, "endpoint")
	str(&dst.Model, "model")
	intField(&dst.NumCtx, "num_ctx")
	num(&dst.Temperature, "temperature")
	num(&dst.TimeoutSeconds, "timeout_seconds")
	boolean(&dst.FallbackToCloud, "fallback_to_cloud")
	str(&dst.CloudProvider, "cloud_provider")
	str(&dst.CloudModel, "cloud_model")
	num(&dst.CloudTimeoutSeconds, "cloud_timeout_seconds")
	num(&dst.TotalDeadlineSeconds, "total_deadline_seconds")
	str(&dst.FallbackAction, "fallback_action")
	boolean(&dst.FastPathReadOnly, "fast_path_read_only")
	intField(&dst.MaxTokens, "max_tokens")
	boolean(&dst.EnableRemediationDirectives, "enable_remediation_directives")
	intField(&dst.AuditRetentionDays, "audit_retention_days")
	intField(&dst.AuditMaxLines, "audit_max_lines")
	intField(&dst.AuditTrimIntervalSeconds, "audit_trim_interval_seconds")
	str(&dst.PolicyMode, "policy_mode")
	boolean(&dst.AutoStartLocalEngine, "auto_start_local_engine")
	str(&dst.CustomPolicyPath, "custom_policy_path")
	str(&dst.DebugLog, "debug_log")
	boolean(&dst.ShadowMode, "shadow_mode")
	str(&dst.APIKey, "api_key")
	str(&dst.GeminiAPIKey, "gemini_api_key")
	str(&dst.AnthropicAPIKey, "anthropic_api_key")
	str(&dst.OpenAIAPIKey, "openai_api_key")
	str(&dst.OpenRouterAPIKey, "openrouter_api_key")

	if v, ok := rawMap["protected_paths"]; ok {
		if list, ok := v.([]interface{}); ok {
			paths := make([]string, 0, len(list))
			for _, item := range list {
				if s, ok := item.(string); ok {
					paths = append(paths, s)
				}
			}
			dst.ProtectedPaths = paths
		}
	}
}
