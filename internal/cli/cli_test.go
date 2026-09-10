package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahul-k-r/auto-permissions-mode/internal/cli"
)

func TestRuleFilePaths(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cli-paths-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	cli.GetCwdHook = func() string { return tmpDir }
	cli.GetHomeHook = func() string { return tmpDir }
	defer func() {
		cli.GetCwdHook = nil
		cli.GetHomeHook = nil
	}()

	localRule := cli.GetRulesFile(false)
	expectedLocal := filepath.Join(tmpDir, ".agents", "rules", "interactive_decisions.md")
	if localRule != expectedLocal {
		t.Fatalf("expected local rule %s, got %s", expectedLocal, localRule)
	}

	globalRule := cli.GetRulesFile(true)
	expectedGlobal := filepath.Join(tmpDir, ".gemini", "config", "rules", "interactive_decisions.md")
	if globalRule != expectedGlobal {
		t.Fatalf("expected global rule %s, got %s", expectedGlobal, globalRule)
	}

	content := cli.GetBundledRuleContent()
	if len(content) == 0 {
		t.Fatalf("expected non-empty bundled rule content")
	}
}

func TestInstallUninstallHook(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cli-install-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	cli.GetCwdHook = func() string { return tmpDir }
	cli.GetHomeHook = func() string { return tmpDir }
	defer func() {
		cli.GetCwdHook = nil
		cli.GetHomeHook = nil
	}()

	// 1. Install local hook
	ok := cli.InstallHook(false)
	if !ok {
		t.Fatalf("failed to install hook")
	}

	hooksFile := filepath.Join(tmpDir, ".agents", "hooks.json")
	ruleFile := filepath.Join(tmpDir, ".agents", "rules", "interactive_decisions.md")

	if _, err := os.Stat(hooksFile); err != nil {
		t.Fatalf("hooks.json does not exist: %v", err)
	}
	if _, err := os.Stat(ruleFile); err != nil {
		t.Fatalf("rules file does not exist: %v", err)
	}

	data, _ := os.ReadFile(hooksFile)
	var hooksMap map[string]interface{}
	_ = json.Unmarshal(data, &hooksMap)
	if _, ok := hooksMap["auto-permissions-mode"]; !ok {
		t.Fatalf("auto-permissions-mode not in hooks.json")
	}

	// 2. Uninstall hook without purge
	cli.UninstallHook(false, false)
	dataAfter, _ := os.ReadFile(hooksFile)
	var hooksMapAfter map[string]interface{}
	_ = json.Unmarshal(dataAfter, &hooksMapAfter)
	if _, ok := hooksMapAfter["auto-permissions-mode"]; ok {
		t.Fatalf("auto-permissions-mode still present after uninstall")
	}
	if _, err := os.Stat(ruleFile); !os.IsNotExist(err) {
		t.Fatalf("rule file should have been removed")
	}

	// 3. Uninstall hook with purge
	configFile := filepath.Join(tmpDir, ".agents", "auto-permissions.json")
	_ = os.WriteFile(configFile, []byte("{}"), 0644)
	cli.InstallHook(false)
	cli.UninstallHook(false, true)
	if _, err := os.Stat(configFile); !os.IsNotExist(err) {
		t.Fatalf("config file should have been purged")
	}
}

func TestEnableIdeWildcardTrustCreatesNewSettingsFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cli-trust-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	fakeSettings := filepath.Join(tmpDir, ".gemini", "antigravity-cli", "settings.json")
	fakeConfig := filepath.Join(tmpDir, ".gemini", "config", "config.json")
	fakeTF := filepath.Join(tmpDir, ".gemini", "trustedFolders.json")

	cli.GetAntigravityCliSettingsFileHook = func() string { return fakeSettings }
	cli.GetAntigravityConfigFileHook = func() string { return fakeConfig }
	cli.GetAntigravityTrustedFoldersFileHook = func() string { return fakeTF }
	defer func() {
		cli.GetAntigravityCliSettingsFileHook = nil
		cli.GetAntigravityConfigFileHook = nil
		cli.GetAntigravityTrustedFoldersFileHook = nil
	}()

	myProj := filepath.Join(tmpDir, "my_project")
	ok := cli.EnableIdeWildcardTrust(myProj)
	if !ok {
		t.Fatalf("failed to enable ide wildcard trust")
	}

	// Verify CLI settings
	dataSettings, err := os.ReadFile(fakeSettings)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
		TrustedWorkspaces []string `json:"trustedWorkspaces"`
	}
	_ = json.Unmarshal(dataSettings, &st)

	hasMCP, hasURL, hasCmd, hasWrite, hasWS := false, false, false, false, false
	for _, a := range st.Permissions.Allow {
		if a == "mcp(*)" {
			hasMCP = true
		}
		if a == "read_url(*)" {
			hasURL = true
		}
		if a == "command(*)" {
			hasCmd = true
		}
		if a == "write_file(*)" {
			hasWrite = true
		}
	}
	for _, ws := range st.TrustedWorkspaces {
		if strings.EqualFold(ws, myProj) {
			hasWS = true
		}
	}
	if !hasMCP || !hasURL || !hasCmd || !hasWrite || !hasWS {
		t.Fatalf("missing expected entries in settings: %+v", st)
	}

	// Verify IDE config
	dataConfig, _ := os.ReadFile(fakeConfig)
	var cfg struct {
		UserSettings struct {
			GlobalPermissionGrants struct {
				Allow []string `json:"allow"`
			} `json:"globalPermissionGrants"`
			InternetPolicy string `json:"internetPolicy"`
		} `json:"userSettings"`
	}
	_ = json.Unmarshal(dataConfig, &cfg)
	hasCfgMCP := false
	hasCfgWrite := false
	for _, a := range cfg.UserSettings.GlobalPermissionGrants.Allow {
		if a == "mcp(*)" {
			hasCfgMCP = true
		}
		if a == "write_file(*)" {
			hasCfgWrite = true
		}
	}
	if !hasCfgMCP || !hasCfgWrite || cfg.UserSettings.InternetPolicy != "AGENT_SETTING_POLICY_ALLOW" {
		t.Fatalf("unexpected ide config: %+v", cfg)
	}

	// Verify trustedFolders
	dataTF, _ := os.ReadFile(fakeTF)
	var tfMap map[string]string
	_ = json.Unmarshal(dataTF, &tfMap)
	myProjNorm := strings.ToLower(strings.ReplaceAll(myProj, "\\", "/"))
	if tfMap[myProjNorm] != "TRUST_PARENT" {
		t.Fatalf("expected TRUST_PARENT in trustedFolders, got %v", tfMap[myProjNorm])
	}

	if !cli.IsWorkspaceTrusted(myProj) {
		t.Fatalf("expected workspace to be trusted")
	}
	if cli.IsWorkspaceTrusted(filepath.Join(tmpDir, "other_project")) {
		t.Fatalf("unrelated project should not be trusted")
	}
}

func TestEnableIdeWildcardTrustPreservesExistingRulesAndCreatesBackup(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cli-trust-bak-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	fakeSettings := filepath.Join(tmpDir, ".gemini", "antigravity-cli", "settings.json")
	fakeConfig := filepath.Join(tmpDir, ".gemini", "config", "config.json")
	fakeTF := filepath.Join(tmpDir, ".gemini", "trustedFolders.json")

	cli.GetAntigravityCliSettingsFileHook = func() string { return fakeSettings }
	cli.GetAntigravityConfigFileHook = func() string { return fakeConfig }
	cli.GetAntigravityTrustedFoldersFileHook = func() string { return fakeTF }
	defer func() {
		cli.GetAntigravityCliSettingsFileHook = nil
		cli.GetAntigravityConfigFileHook = nil
		cli.GetAntigravityTrustedFoldersFileHook = nil
	}()

	_ = os.MkdirAll(filepath.Dir(fakeSettings), 0755)
	initialData := map[string]interface{}{
		"permissions":       map[string]interface{}{"allow": []string{"command(git status)"}},
		"trustedWorkspaces": []string{filepath.Join(tmpDir, "existing_ws")},
	}
	b, _ := json.Marshal(initialData)
	_ = os.WriteFile(fakeSettings, b, 0644)

	_ = os.MkdirAll(filepath.Dir(fakeConfig), 0755)
	initialCfg := map[string]interface{}{
		"userSettings": map[string]interface{}{
			"globalPermissionGrants": map[string]interface{}{"allow": []string{"command(git status)"}},
		},
	}
	bCfg, _ := json.Marshal(initialCfg)
	_ = os.WriteFile(fakeConfig, bCfg, 0644)

	ok := cli.EnableIdeWildcardTrust(filepath.Join(tmpDir, "new_ws"))
	if !ok {
		t.Fatalf("expected true")
	}

	bakFile := strings.TrimSuffix(fakeSettings, ".json") + ".json.bak"
	if _, err := os.Stat(bakFile); err != nil {
		t.Fatalf("backup file does not exist")
	}

	updatedData, _ := os.ReadFile(fakeSettings)
	var st struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	_ = json.Unmarshal(updatedData, &st)
	hasStatus := false
	hasMCP := false
	for _, a := range st.Permissions.Allow {
		if a == "command(git status)" {
			hasStatus = true
		}
		if a == "mcp(*)" {
			hasMCP = true
		}
	}
	if !hasStatus || !hasMCP {
		t.Fatalf("missing status or mcp rule: %v", st.Permissions.Allow)
	}
}

func TestEnableIdeWildcardTrustHandlesUtf8BOM(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cli-bom-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	fakeSettings := filepath.Join(tmpDir, ".gemini", "antigravity-cli", "settings.json")
	fakeConfig := filepath.Join(tmpDir, ".gemini", "config", "config.json")
	fakeTF := filepath.Join(tmpDir, ".gemini", "trustedFolders.json")

	cli.GetAntigravityCliSettingsFileHook = func() string { return fakeSettings }
	cli.GetAntigravityConfigFileHook = func() string { return fakeConfig }
	cli.GetAntigravityTrustedFoldersFileHook = func() string { return fakeTF }
	defer func() {
		cli.GetAntigravityCliSettingsFileHook = nil
		cli.GetAntigravityConfigFileHook = nil
		cli.GetAntigravityTrustedFoldersFileHook = nil
	}()

	_ = os.MkdirAll(filepath.Dir(fakeSettings), 0755)
	bom := []byte{0xEF, 0xBB, 0xBF}
	raw := []byte(`{"trustedWorkspaces": []}`)
	_ = os.WriteFile(fakeSettings, append(bom, raw...), 0644)

	ok := cli.EnableIdeWildcardTrust(filepath.Join(tmpDir, "bom_ws"))
	if !ok {
		t.Fatalf("failed on utf8 bom")
	}

	updated, _ := os.ReadFile(fakeSettings)
	var st struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	_ = json.Unmarshal(updated, &st)
	hasMCP := false
	for _, a := range st.Permissions.Allow {
		if a == "mcp(*)" {
			hasMCP = true
		}
	}
	if !hasMCP {
		t.Fatalf("expected mcp(*) in allow list")
	}
}

func TestDeclineIdeWorkspaceTrust(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cli-decline-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	fakeDeclined := filepath.Join(tmpDir, ".gemini", "config", "declined_workspaces.json")
	target := filepath.Join(tmpDir, "declined_ws")

	cli.GetDeclinedWorkspacesFileHook = func() string { return fakeDeclined }
	defer func() { cli.GetDeclinedWorkspacesFileHook = nil }()

	ok := cli.DeclineIdeWorkspaceTrust(target)
	if !ok {
		t.Fatalf("expected true")
	}
	if _, err := os.Stat(fakeDeclined); err != nil {
		t.Fatalf("declined file does not exist")
	}

	if !cli.IsWorkspaceDeclined(target) {
		t.Fatalf("expected workspace to be declined")
	}
	if cli.IsWorkspaceDeclined(filepath.Join(tmpDir, "other_ws")) {
		t.Fatalf("other workspace should not be declined")
	}
}

func TestSetupVramProfile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cli-setup-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	cli.GetCwdHook = func() string { return tmpDir }
	cli.GetHomeHook = func() string { return tmpDir }
	defer func() {
		cli.GetCwdHook = nil
		cli.GetHomeHook = nil
	}()

	// Test valid tier
	if !cli.SetupVramProfile("6gb", false, false) {
		t.Fatalf("expected SetupVramProfile to succeed for 6gb")
	}

	cfgPath := filepath.Join(tmpDir, ".agents", "auto-permissions.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("expected config file to be created: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if cfg["model"] != "gemma-4-E4B-it-UD-Q4_K_XL.gguf" {
		t.Fatalf("expected model for 6gb, got %v", cfg["model"])
	}

	// Test invalid tier
	if cli.SetupVramProfile("invalid_tier", false, false) {
		t.Fatalf("expected SetupVramProfile to fail for invalid tier")
	}
}
