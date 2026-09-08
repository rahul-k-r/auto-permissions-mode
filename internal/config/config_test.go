package config

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg.Provider != "llamacpp" {
		t.Fatalf("expected llamacpp, got %s", cfg.Provider)
	}
	if cfg.FallbackAction != "force_ask" {
		t.Fatalf("expected force_ask, got %s", cfg.FallbackAction)
	}
	if len(cfg.ProtectedPaths) < len(DefaultProtectedPaths) {
		t.Fatalf("expected at least %d protected paths, got %d", len(DefaultProtectedPaths), len(cfg.ProtectedPaths))
	}
}

func TestSecurityGuardsFallbackAction(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.FallbackAction = "allow"
	ApplySecurityGuards(&cfg)
	if cfg.FallbackAction != "force_ask" {
		t.Fatalf("expected fallback_action to be coerced to force_ask, got %s", cfg.FallbackAction)
	}

	cfg.FallbackAction = "ALLOW"
	ApplySecurityGuards(&cfg)
	if cfg.FallbackAction != "force_ask" {
		t.Fatalf("expected case-insensitive coercion to force_ask, got %s", cfg.FallbackAction)
	}
}

func TestSecurityGuardsProtectedPathsUnion(t *testing.T) {
	cfg := NewDefaultConfig()
	// Simulate user trying to wipe out protected paths with only custom paths
	cfg.ProtectedPaths = []string{"/custom/secret"}
	ApplySecurityGuards(&cfg)

	foundCustom := false
	foundGit := false
	for _, p := range cfg.ProtectedPaths {
		if p == "/custom/secret" {
			foundCustom = true
		}
		if p == ".git" {
			foundGit = true
		}
	}

	if !foundCustom {
		t.Fatalf("expected custom path to be preserved")
	}
	if !foundGit {
		t.Fatalf("expected critical default path (.git) to be merged in via union")
	}
}

// TestMergeConfigToleratesSingleBadlyTypedField guards against a regression where
// unmarshaling the whole config file into a typed struct meant one wrong-typed field
// (e.g. num_ctx given as a string) discarded every other override in the file. A single
// bad key must only skip that key.
func TestMergeConfigToleratesSingleBadlyTypedField(t *testing.T) {
	cfg := NewDefaultConfig()
	rawMap := map[string]interface{}{
		"num_ctx":  "8192", // wrong type: should be a number
		"endpoint": "http://example.com/v1/chat/completions",
	}
	mergeConfig(&cfg, rawMap)

	if cfg.Endpoint != "http://example.com/v1/chat/completions" {
		t.Fatalf("expected endpoint override to still apply despite num_ctx's bad type, got %s", cfg.Endpoint)
	}
	if cfg.NumCtx != NewDefaultConfig().NumCtx {
		t.Fatalf("expected num_ctx to keep its default when given the wrong JSON type, got %d", cfg.NumCtx)
	}
}

// TestMergeConfigPreservesGenericAPIKeyFields guards against a regression where
// api_key/gemini_api_key/etc. set in a config file (not env, not the global config) were
// silently dropped because the Config struct had no field to receive them.
func TestMergeConfigPreservesGenericAPIKeyFields(t *testing.T) {
	cfg := NewDefaultConfig()
	rawMap := map[string]interface{}{
		"api_key":           "sk-generic",
		"gemini_api_key":    "gemini-key",
		"anthropic_api_key": "anthropic-key",
	}
	mergeConfig(&cfg, rawMap)

	if cfg.APIKey != "sk-generic" {
		t.Fatalf("expected api_key to be preserved, got %q", cfg.APIKey)
	}
	if cfg.GeminiAPIKey != "gemini-key" {
		t.Fatalf("expected gemini_api_key to be preserved, got %q", cfg.GeminiAPIKey)
	}
	if cfg.AnthropicAPIKey != "anthropic-key" {
		t.Fatalf("expected anthropic_api_key to be preserved, got %q", cfg.AnthropicAPIKey)
	}
}
