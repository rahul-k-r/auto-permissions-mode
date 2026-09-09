package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Hook overrides for unit tests
var (
	GetCwdHook  func() string
	GetHomeHook func() string
)

// appendIfMissing returns list with item appended, unless an exactly-equal entry is
// already present.
func appendIfMissing(list []string, item string) []string {
	if slices.Contains(list, item) {
		return list
	}
	return append(list, item)
}

// appendIfMissingFold is appendIfMissing with a case-insensitive comparison.
func appendIfMissingFold(list []string, item string) []string {
	if slices.ContainsFunc(list, func(existing string) bool { return strings.EqualFold(existing, item) }) {
		return list
	}
	return append(list, item)
}

func currentCwd() string {
	if GetCwdHook != nil {
		return GetCwdHook()
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

func currentHome() string {
	if GetHomeHook != nil {
		return GetHomeHook()
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}

func GetHooksFile(isGlobal bool) string {
	if isGlobal {
		return filepath.Join(currentHome(), ".gemini", "config", "hooks.json")
	}
	return filepath.Join(currentCwd(), ".agents", "hooks.json")
}

func GetRulesFile(isGlobal bool) string {
	if isGlobal {
		return filepath.Join(currentHome(), ".gemini", "config", "rules", "interactive_decisions.md")
	}
	return filepath.Join(currentCwd(), ".agents", "rules", "interactive_decisions.md")
}

// BundledRuleContent matches interactive_decisions.md
var BundledRuleContent = `# Rule: Autonomous Remediations & Interactive Decisions
When Auto Permissions Mode intercepts a tool call with a REMEDIATION DIRECTIVE, present an ask_question modal using the provided alternatives.
`

func GetBundledRuleContent() string {
	return BundledRuleContent
}

var (
	GetAntigravityCliSettingsFileHook    func() string
	GetAntigravityConfigFileHook         func() string
	GetAntigravityTrustedFoldersFileHook func() string
	GetDeclinedWorkspacesFileHook        func() string
)

func GetAntigravityCliSettingsFile() string {
	if GetAntigravityCliSettingsFileHook != nil {
		return GetAntigravityCliSettingsFileHook()
	}
	return filepath.Join(currentHome(), ".gemini", "antigravity-cli", "settings.json")
}

func GetAntigravityConfigFile() string {
	if GetAntigravityConfigFileHook != nil {
		return GetAntigravityConfigFileHook()
	}
	return filepath.Join(currentHome(), ".gemini", "config", "config.json")
}

func GetAntigravityTrustedFoldersFile() string {
	if GetAntigravityTrustedFoldersFileHook != nil {
		return GetAntigravityTrustedFoldersFileHook()
	}
	return filepath.Join(currentHome(), ".gemini", "trustedFolders.json")
}

func GetDeclinedWorkspacesFile() string {
	if GetDeclinedWorkspacesFileHook != nil {
		return GetDeclinedWorkspacesFileHook()
	}
	return filepath.Join(currentHome(), ".gemini", "config", "declined_workspaces.json")
}

func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

func IsWorkspaceTrusted(workspacePath string) bool {
	target := workspacePath
	if target == "" {
		target = currentCwd()
	}
	if abs, err := filepath.Abs(target); err == nil {
		target = abs
	}
	targetNorm := strings.ToLower(strings.ReplaceAll(target, "\\", "/"))

	// 1. Check IDE trustedFolders.json
	tfFile := GetAntigravityTrustedFoldersFile()
	if data, err := os.ReadFile(tfFile); err == nil {
		var tfMap map[string]string
		if err := json.Unmarshal(stripBOM(data), &tfMap); err == nil {
			for folder, trustVal := range tfMap {
				if trustVal == "TRUST_PARENT" || trustVal == "TRUST_FOLDER" || trustVal == "ALLOW" {
					fAbs := folder
					if abs, err := filepath.Abs(folder); err == nil {
						fAbs = abs
					}
					fNorm := strings.ToLower(strings.ReplaceAll(fAbs, "\\", "/"))
					if fNorm == targetNorm {
						return true
					}
				}
			}
		}
	}

	// 2. Check CLI settings.json
	settingsFile := GetAntigravityCliSettingsFile()
	if data, err := os.ReadFile(settingsFile); err == nil {
		var st struct {
			TrustedWorkspaces []string `json:"trustedWorkspaces"`
		}
		if err := json.Unmarshal(stripBOM(data), &st); err == nil {
			for _, p := range st.TrustedWorkspaces {
				pAbs := p
				if abs, err := filepath.Abs(p); err == nil {
					pAbs = abs
				}
				if strings.EqualFold(pAbs, target) {
					return true
				}
			}
		}
	}

	return false
}

func IsWorkspaceDeclined(workspacePath string) bool {
	target := workspacePath
	if target == "" {
		target = currentCwd()
	}
	if abs, err := filepath.Abs(target); err == nil {
		target = abs
	}

	declinedFile := GetDeclinedWorkspacesFile()
	data, err := os.ReadFile(declinedFile)
	if err != nil {
		return false
	}
	var d struct {
		Declined []string `json:"declined"`
	}
	if err := json.Unmarshal(stripBOM(data), &d); err != nil {
		return false
	}
	for _, p := range d.Declined {
		pAbs := p
		if abs, err := filepath.Abs(p); err == nil {
			pAbs = abs
		}
		if strings.EqualFold(pAbs, target) {
			return true
		}
	}
	return false
}

func EnableIdeWildcardTrust(workspacePath string) bool {
	targetWS := workspacePath
	if targetWS == "" {
		targetWS = currentCwd()
	}
	if abs, err := filepath.Abs(targetWS); err == nil {
		targetWS = abs
	}
	targetWSNorm := strings.ToLower(strings.ReplaceAll(targetWS, "\\", "/"))

	// 1. Update config.json
	configFile := GetAntigravityConfigFile()
	_ = os.MkdirAll(filepath.Dir(configFile), 0755)
	var configData map[string]interface{}
	if data, err := os.ReadFile(configFile); err == nil {
		_ = json.Unmarshal(stripBOM(data), &configData)
	}
	if configData == nil {
		configData = make(map[string]interface{})
	}
	userSettings, _ := configData["userSettings"].(map[string]interface{})
	if userSettings == nil {
		userSettings = make(map[string]interface{})
		configData["userSettings"] = userSettings
	}
	gpg, _ := userSettings["globalPermissionGrants"].(map[string]interface{})
	if gpg == nil {
		gpg = make(map[string]interface{})
		userSettings["globalPermissionGrants"] = gpg
	}
	var allows []string
	if aList, ok := gpg["allow"].([]interface{}); ok {
		for _, v := range aList {
			if s, ok := v.(string); ok {
				allows = append(allows, s)
			}
		}
	}
	for _, rule := range []string{"command(*)", "mcp(*)", "write_file(*)", "read_url(*)", "search_web(*)"} {
		allows = appendIfMissing(allows, rule)
	}
	gpg["allow"] = allows
	userSettings["internetPolicy"] = "AGENT_SETTING_POLICY_ALLOW"
	userSettings["nonWorkspaceFileAccessPolicy"] = "AGENT_SETTING_POLICY_ALLOW"

	bConfig, _ := json.MarshalIndent(configData, "", "  ")
	_ = os.WriteFile(configFile, bConfig, 0644)

	// 2. Update trustedFolders.json
	tfFile := GetAntigravityTrustedFoldersFile()
	_ = os.MkdirAll(filepath.Dir(tfFile), 0755)
	tfMap := make(map[string]string)
	if data, err := os.ReadFile(tfFile); err == nil {
		_ = json.Unmarshal(stripBOM(data), &tfMap)
		bakTF := tfFile + ".bak"
		_ = os.WriteFile(bakTF, data, 0644)
	}
	tfMap[targetWSNorm] = "TRUST_PARENT"
	bTF, _ := json.MarshalIndent(tfMap, "", "  ")
	_ = os.WriteFile(tfFile, bTF, 0644)

	// 3. Update settings.json
	settingsFile := GetAntigravityCliSettingsFile()
	_ = os.MkdirAll(filepath.Dir(settingsFile), 0755)
	var settingsData map[string]interface{}
	if data, err := os.ReadFile(settingsFile); err == nil {
		_ = json.Unmarshal(stripBOM(data), &settingsData)
		bakSettings := strings.TrimSuffix(settingsFile, ".json") + ".json.bak"
		_ = os.WriteFile(bakSettings, data, 0644)
	}
	if settingsData == nil {
		settingsData = make(map[string]interface{})
	}
	perms, _ := settingsData["permissions"].(map[string]interface{})
	if perms == nil {
		perms = make(map[string]interface{})
		settingsData["permissions"] = perms
	}
	var setAllows []string
	if saList, ok := perms["allow"].([]interface{}); ok {
		for _, v := range saList {
			if s, ok := v.(string); ok {
				setAllows = append(setAllows, s)
			}
		}
	}
	for _, w := range []string{"mcp(*)", "read_url(*)", "command(*)", "write_file(*)", "search_web(*)"} {
		setAllows = appendIfMissing(setAllows, w)
	}
	perms["allow"] = setAllows

	var twList []string
	if rawTW, ok := settingsData["trustedWorkspaces"].([]interface{}); ok {
		for _, v := range rawTW {
			if s, ok := v.(string); ok {
				twList = append(twList, s)
			}
		}
	}
	twList = appendIfMissingFold(twList, targetWS)
	settingsData["trustedWorkspaces"] = twList

	bSettings, _ := json.MarshalIndent(settingsData, "", "  ")
	_ = os.WriteFile(settingsFile, bSettings, 0644)
	return true
}

func DeclineIdeWorkspaceTrust(workspacePath string) bool {
	target := workspacePath
	if target == "" {
		target = currentCwd()
	}
	if abs, err := filepath.Abs(target); err == nil {
		target = abs
	}

	declinedFile := GetDeclinedWorkspacesFile()
	_ = os.MkdirAll(filepath.Dir(declinedFile), 0755)

	var d struct {
		Declined []string `json:"declined"`
	}
	if data, err := os.ReadFile(declinedFile); err == nil {
		_ = json.Unmarshal(stripBOM(data), &d)
	}

	set := make(map[string]bool)
	for _, p := range d.Declined {
		set[p] = true
	}
	set[target] = true

	var res []string
	for p := range set {
		res = append(res, p)
	}
	d.Declined = res

	b, _ := json.MarshalIndent(d, "", "  ")
	return os.WriteFile(declinedFile, b, 0644) == nil
}

func InstallHook(isGlobal bool) bool {
	hookFile := GetHooksFile(isGlobal)
	_ = os.MkdirAll(filepath.Dir(hookFile), 0755)

	currentData := make(map[string]interface{})
	if data, err := os.ReadFile(hookFile); err == nil {
		_ = json.Unmarshal(stripBOM(data), &currentData)
	}

	exe, err := os.Executable()
	if err != nil {
		exe = "auto-permissions"
	}
	cmdEntry := exe + " hook"
	if strings.Contains(exe, " ") {
		cmdEntry = fmt.Sprintf("\"%s\" hook", exe)
	}

	hookEntry := map[string]interface{}{
		"enabled": true,
		"PreToolUse": []map[string]interface{}{
			{
				"matcher": "*",
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": cmdEntry,
						"timeout": 30,
					},
				},
			},
		},
	}

	currentData["auto-permissions-mode"] = hookEntry
	b, err := json.MarshalIndent(currentData, "", "  ")
	if err != nil {
		return false
	}
	if err := os.WriteFile(hookFile, b, 0644); err != nil {
		return false
	}

	ruleFile := GetRulesFile(isGlobal)
	_ = os.MkdirAll(filepath.Dir(ruleFile), 0755)
	_ = os.WriteFile(ruleFile, []byte(GetBundledRuleContent()), 0644)
	return true
}

func UninstallHook(isGlobal, purge bool) bool {
	hookFile := GetHooksFile(isGlobal)
	if data, err := os.ReadFile(hookFile); err == nil {
		var currentData map[string]interface{}
		if err := json.Unmarshal(stripBOM(data), &currentData); err == nil {
			delete(currentData, "auto-permissions-mode")
			b, _ := json.MarshalIndent(currentData, "", "  ")
			_ = os.WriteFile(hookFile, b, 0644)
		}
	}

	ruleFile := GetRulesFile(isGlobal)
	_ = os.Remove(ruleFile)

	if purge {
		configFile := filepath.Join(filepath.Dir(hookFile), "auto-permissions.json")
		_ = os.Remove(configFile)
	}
	return true
}
