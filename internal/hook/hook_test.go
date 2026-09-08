package hook_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rahul-k-r/auto-permissions-mode/internal/config"
	"github.com/rahul-k-r/auto-permissions-mode/internal/hook"
	"github.com/rahul-k-r/auto-permissions-mode/internal/providers"
)

type fakeProvider struct{}

func (f *fakeProvider) Evaluate(systemPrompt, prompt string) (map[string]interface{}, string, error) {
	panic("provider.Evaluate() should not be called for a fast-path tool")
}

func (f *fakeProvider) GetEndpoint() string {
	return "http://fake"
}

func runHookWithStdin(payloadText string) map[string]interface{} {
	cfg := config.NewDefaultConfig()
	cfg.FallbackAction = "force_ask"
	cfg.FastPathReadOnly = true

	hook.ConfigLoader = func() config.Config { return cfg }
	hook.ProviderGetter = func(c config.Config) providers.Provider { return &fakeProvider{} }
	hook.AuditRecorder = func(toolName string, toolArgs map[string]interface{}, decision, reason string, latencyMS float64, source string, context map[string]interface{}, cfg config.Config) {
	}

	reader := strings.NewReader(payloadText)
	var writer bytes.Buffer
	_ = hook.RunHook(reader, &writer)

	var result map[string]interface{}
	_ = json.Unmarshal([]byte(strings.TrimSpace(writer.String())), &result)
	return result
}

func TestEmptyStdinDefersToUser(t *testing.T) {
	res := runHookWithStdin("")
	if res["decision"] != "force_ask" {
		t.Fatalf("expected force_ask, got %v", res["decision"])
	}
	reason, _ := res["reason"].(string)
	if !strings.Contains(reason, "No input received") {
		t.Fatalf("expected reason to contain 'No input received', got %s", reason)
	}
}

func TestMalformedJsonFallsBackToForceAsk(t *testing.T) {
	res := runHookWithStdin("not valid json{{{")
	if res["decision"] != "force_ask" {
		t.Fatalf("expected force_ask, got %v", res["decision"])
	}
	reason, _ := res["reason"].(string)
	if !strings.Contains(reason, "Hook evaluation error") {
		t.Fatalf("expected reason to contain 'Hook evaluation error', got %s", reason)
	}
}

func TestFastPathReadOnlyToolAllowsWithoutProviderCall(t *testing.T) {
	payload, _ := json.Marshal(map[string]interface{}{
		"toolCall": map[string]interface{}{
			"name": "view_file",
			"args": map[string]interface{}{"AbsolutePath": "README.md"},
		},
		"stepIdx":        1,
		"conversationId": "test-run",
	})
	res := runHookWithStdin(string(payload))
	if res["decision"] != "allow" {
		t.Fatalf("expected allow, got %v", res["decision"])
	}
	if _, ok := res["permissionOverrides"]; ok {
		t.Fatalf("did not expect permissionOverrides for view_file")
	}
}

func TestAllowedMcpCallIncludesPermissionOverrides(t *testing.T) {
	payload, _ := json.Marshal(map[string]interface{}{
		"toolCall": map[string]interface{}{
			"name": "call_mcp_tool",
			"args": map[string]interface{}{"ServerName": "linear", "ToolName": "get_issue"},
		},
	})
	res := runHookWithStdin(string(payload))
	if res["decision"] != "allow" {
		t.Fatalf("expected allow, got %v", res["decision"])
	}
	overrides, ok := res["permissionOverrides"].([]interface{})
	if !ok || len(overrides) == 0 {
		t.Fatalf("expected permissionOverrides, got %v", res["permissionOverrides"])
	}
	found := false
	for _, o := range overrides {
		if o == "mcp(linear/get_issue)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected mcp(linear/get_issue) in overrides, got %v", overrides)
	}
}

func TestMissingToolCallNameDefersToUser(t *testing.T) {
	payload, _ := json.Marshal(map[string]interface{}{
		"toolCall": map[string]interface{}{"args": map[string]interface{}{}},
	})
	res := runHookWithStdin(string(payload))
	if res["decision"] != "force_ask" {
		t.Fatalf("expected force_ask, got %v", res["decision"])
	}
}
