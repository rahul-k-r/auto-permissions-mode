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
			if err == nil {
				var fileCfg Config
				if err := json.Unmarshal(data, &fileCfg); err == nil {
					// Merge non-zero fields
					mergeConfig(&cfg, &fileCfg, data)
					break
				}
			}
		}
	}

	ApplySecurityGuards(&cfg)
	return cfg
}

func mergeConfig(dst *Config, src *Config, raw []byte) {
	var rawMap map[string]interface{}
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return
	}

	if _, ok := rawMap["provider"]; ok {
		dst.Provider = src.Provider
	}
	if _, ok := rawMap["endpoint"]; ok {
		dst.Endpoint = src.Endpoint
	}
	if _, ok := rawMap["model"]; ok {
		dst.Model = src.Model
	}
	if _, ok := rawMap["num_ctx"]; ok {
		dst.NumCtx = src.NumCtx
	}
	if _, ok := rawMap["temperature"]; ok {
		dst.Temperature = src.Temperature
	}
	if _, ok := rawMap["timeout_seconds"]; ok {
		dst.TimeoutSeconds = src.TimeoutSeconds
	}
	if _, ok := rawMap["fallback_to_cloud"]; ok {
		dst.FallbackToCloud = src.FallbackToCloud
	}
	if _, ok := rawMap["cloud_provider"]; ok {
		dst.CloudProvider = src.CloudProvider
	}
	if _, ok := rawMap["cloud_model"]; ok {
		dst.CloudModel = src.CloudModel
	}
	if _, ok := rawMap["cloud_timeout_seconds"]; ok {
		dst.CloudTimeoutSeconds = src.CloudTimeoutSeconds
	}
	if _, ok := rawMap["total_deadline_seconds"]; ok {
		dst.TotalDeadlineSeconds = src.TotalDeadlineSeconds
	}
	if _, ok := rawMap["fallback_action"]; ok {
		dst.FallbackAction = src.FallbackAction
	}
	if _, ok := rawMap["fast_path_read_only"]; ok {
		dst.FastPathReadOnly = src.FastPathReadOnly
	}
	if _, ok := rawMap["max_tokens"]; ok {
		dst.MaxTokens = src.MaxTokens
	}
	if _, ok := rawMap["enable_remediation_directives"]; ok {
		dst.EnableRemediationDirectives = src.EnableRemediationDirectives
	}
	if _, ok := rawMap["audit_retention_days"]; ok {
		dst.AuditRetentionDays = src.AuditRetentionDays
	}
	if _, ok := rawMap["audit_max_lines"]; ok {
		dst.AuditMaxLines = src.AuditMaxLines
	}
	if _, ok := rawMap["audit_trim_interval_seconds"]; ok {
		dst.AuditTrimIntervalSeconds = src.AuditTrimIntervalSeconds
	}
	if _, ok := rawMap["policy_mode"]; ok {
		dst.PolicyMode = src.PolicyMode
	}
	if _, ok := rawMap["auto_start_local_engine"]; ok {
		dst.AutoStartLocalEngine = src.AutoStartLocalEngine
	}
	if _, ok := rawMap["custom_policy_path"]; ok {
		dst.CustomPolicyPath = src.CustomPolicyPath
	}
	if _, ok := rawMap["debug_log"]; ok {
		dst.DebugLog = src.DebugLog
	}
	if _, ok := rawMap["shadow_mode"]; ok {
		dst.ShadowMode = src.ShadowMode
	}
	if _, ok := rawMap["protected_paths"]; ok {
		dst.ProtectedPaths = src.ProtectedPaths
	}
}
