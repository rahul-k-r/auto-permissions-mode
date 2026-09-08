package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeMode(t *testing.T) {
	cases := map[string]string{
		"yolo":     ModeYolo,
		"YOLO":     ModeYolo,
		"strict":   ModeStrict,
		"custom":   ModeCustom,
		"mild":     ModeBalanced,
		"balanced": ModeBalanced,
		"unknown":  ModeBalanced,
		"":         ModeBalanced,
	}

	for input, expected := range cases {
		if got := NormalizeMode(input); got != expected {
			t.Errorf("NormalizeMode(%q) = %q, expected %q", input, got, expected)
		}
	}
}

func TestBuildSystemPromptContainsOutputContract(t *testing.T) {
	modes := []string{ModeBalanced, ModeYolo, ModeStrict, ModeCustom}
	for _, m := range modes {
		prompt := BuildSystemPrompt(m, "")
		if !strings.Contains(prompt, "### Output JSON Format:") {
			t.Errorf("mode %q prompt missing OutputContract JSON format", m)
		}
		if !strings.Contains(prompt, "CRITICAL REQUIREMENT FOR \"deny\" AND \"ask\" ALTERNATIVES") {
			t.Errorf("mode %q prompt missing alternatives requirement", m)
		}
	}
}

func TestBuildSystemPromptCustomPolicy(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "policy-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	customPath := filepath.Join(tmpDir, "policy.md")
	customRules := "## My Custom Security Policy\n- Only allow python commands."
	if err := os.WriteFile(customPath, []byte(customRules), 0644); err != nil {
		t.Fatalf("failed to write custom policy: %v", err)
	}

	prompt := BuildSystemPrompt(ModeCustom, customPath)
	if !strings.Contains(prompt, "My Custom Security Policy") {
		t.Errorf("expected prompt to contain custom policy rules")
	}
	if !strings.Contains(prompt, "### Output JSON Format:") {
		t.Errorf("expected prompt to also contain immutable OutputContract")
	}
}

func TestIsCatastrophicCommand(t *testing.T) {
	catastrophic := []string{
		"rm -rf /",
		"rm -rf / --no-preserve-root",
		"rm -rf ~",
		"rm -rf $HOME",
		"del /s /q C:\\",
		"del /f /s /q c:\\windows",
		"DROP DATABASE prod",
		"drop database production",
		"format C:",
		"git push origin main --force",
	}

	for _, cmd := range catastrophic {
		if !IsCatastrophicCommand(cmd) {
			t.Errorf("expected %q to be flagged as catastrophic", cmd)
		}
	}

	safe := []string{
		"npm test",
		"git status",
		"git commit -m 'feat: test'",
		"rm -rf ./build",
		"rm -rf dist/",
		"git push origin feature-branch",
		"del test.txt",
	}

	for _, cmd := range safe {
		if IsCatastrophicCommand(cmd) {
			t.Errorf("expected %q NOT to be flagged as catastrophic", cmd)
		}
	}
}

// TestIsCatastrophicCommandCatchesBareWildcardDelete guards against a regression where the
// rm -rf pattern only matched absolute/home/parent-relative targets, so a bare wildcard or
// current-directory delete — just as destructive, and lacking any leading "/", "~", or
// "../" — slipped through YOLO mode's sanity gate entirely.
func TestIsCatastrophicCommandCatchesBareWildcardDelete(t *testing.T) {
	catastrophic := []string{
		"rm -rf *",
		"rm -rf .",
		"rm -rf",
		"rm -rf ./",
		"rm -rf ./*",
	}
	for _, cmd := range catastrophic {
		if !IsCatastrophicCommand(cmd) {
			t.Errorf("expected %q to be flagged as catastrophic", cmd)
		}
	}

	// Named relative subdirectories remain an accepted YOLO-safe build-cleanup operation.
	stillSafe := []string{
		"rm -rf ./build",
		"rm -rf dist/",
		"rm -rf node_modules",
	}
	for _, cmd := range stillSafe {
		if IsCatastrophicCommand(cmd) {
			t.Errorf("expected %q NOT to be flagged as catastrophic", cmd)
		}
	}
}

// TestIsCatastrophicCommandDelIgnoresSwitchOrder guards against a regression where the del
// pattern only matched "/s" appearing before "/q" in the command text, even though cmd.exe
// treats switch order as irrelevant.
func TestIsCatastrophicCommandDelIgnoresSwitchOrder(t *testing.T) {
	cases := []string{
		"del /s /q C:\\Windows",
		"del /q /s C:\\Windows",
	}
	for _, cmd := range cases {
		if !IsCatastrophicCommand(cmd) {
			t.Errorf("expected %q to be flagged as catastrophic regardless of switch order", cmd)
		}
	}
}
