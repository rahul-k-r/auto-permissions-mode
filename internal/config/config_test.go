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
