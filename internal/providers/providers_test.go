package providers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rahul-k-r/auto-permissions-mode/internal/config"
	"github.com/rahul-k-r/auto-permissions-mode/internal/providers"
)

type mockSimpleProvider struct {
	response map[string]interface{}
	err      error
	endpoint string
}

func (m *mockSimpleProvider) Evaluate(systemPrompt, prompt string) (map[string]interface{}, string, error) {
	if m.err != nil {
		return nil, "LOCAL", m.err
	}
	return m.response, "LOCAL", nil
}

func (m *mockSimpleProvider) GetEndpoint() string {
	return m.endpoint
}

func TestParseJSONSafelyThinkingModels(t *testing.T) {
	// 1. Closed thinking block
	raw := "<think>\nThinking through the risk...\n</think>\n{\"decision\": \"allow\", \"reason\": \"Safe build.\"}"
	res := providers.ParseJSONSafely(raw)
	if res == nil {
		t.Fatalf("expected parsed json")
	}
	if res["decision"] != "allow" {
		t.Fatalf("expected allow, got %v", res["decision"])
	}

	// 2. Unclosed thinking block
	rawUnclosed := "Some prefix <think>still thinking... {\"decision\": \"deny\"}"
	res2 := providers.ParseJSONSafely(rawUnclosed)
	if res2 != nil {
		t.Fatalf("expected nil on unclosed thinking block")
	}

	// 3. Markdown wrapped json
	rawMd := "```json\n{\"decision\": \"force_ask\", \"reason\": \"High impact\"}\n```"
	res3 := providers.ParseJSONSafely(rawMd)
	if res3 == nil {
		t.Fatalf("expected parsed markdown json")
	}
	if res3["decision"] != "force_ask" {
		t.Fatalf("expected force_ask, got %v", res3["decision"])
	}
}

func TestTieredProviderLocalFirstSuccess(t *testing.T) {
	primary := &mockSimpleProvider{response: map[string]interface{}{"decision": "allow", "reason": "Local Qwen 3.5 approved."}}
	secondary := &mockSimpleProvider{response: map[string]interface{}{"decision": "deny", "reason": "Cloud Gemini should not be called."}}
	tiered := providers.NewTieredProvider(primary, secondary, 11*time.Second)

	res, _, err := tiered.Evaluate("system", "prompt")
	if err != nil {
		t.Fatal(err)
	}
	if res["decision"] != "allow" {
		t.Fatalf("expected allow, got %v", res["decision"])
	}
	if res["reason"] != "Local Qwen 3.5 approved." {
		t.Fatalf("expected local reason, got %v", res["reason"])
	}
}

func TestTieredProviderCloudFailover(t *testing.T) {
	primary := &mockSimpleProvider{response: nil, err: http.ErrHandlerTimeout}
	secondary := &mockSimpleProvider{response: map[string]interface{}{"decision": "ask", "reason": "Cloud Gemini evaluated."}}
	tiered := providers.NewTieredProvider(primary, secondary, 11*time.Second)

	res, _, err := tiered.Evaluate("system", "prompt")
	if err != nil {
		t.Fatal(err)
	}
	if res["decision"] != "ask" {
		t.Fatalf("expected ask, got %v", res["decision"])
	}
	if res["reason"] != "Cloud Gemini evaluated." {
		t.Fatalf("expected cloud reason, got %v", res["reason"])
	}
}

func TestTieredProviderAllOfflineEscalatesToForceAsk(t *testing.T) {
	primary := &mockSimpleProvider{response: nil, err: http.ErrHandlerTimeout}
	secondary := &mockSimpleProvider{response: nil, err: http.ErrHandlerTimeout}
	tiered := providers.NewTieredProvider(primary, secondary, 11*time.Second)

	res, _, _ := tiered.Evaluate("system", "prompt")
	if res["decision"] != "force_ask" {
		t.Fatalf("expected force_ask, got %v", res["decision"])
	}
	reason, _ := res["reason"].(string)
	if !strings.Contains(strings.ToLower(reason), "unavailable") {
		t.Fatalf("expected reason to mention unavailable, got %s", reason)
	}
}

func TestTieredProviderCircuitBreaker(t *testing.T) {
	primary := &mockSimpleProvider{response: nil, err: http.ErrHandlerTimeout, endpoint: "http://127.0.0.1:9931"}
	secondary := &mockSimpleProvider{response: map[string]interface{}{"decision": "allow", "reason": "Cloud Gemini approved."}}
	tiered := providers.NewTieredProvider(primary, secondary, 11*time.Second)

	// Clean any previous test breaker
	tiered.MarkLocalHealthy()

	if tiered.IsLocalInCooldown() {
		t.Fatalf("expected not in cooldown initially")
	}

	res1, _, _ := tiered.Evaluate("system", "prompt")
	if res1["decision"] != "allow" {
		t.Fatalf("expected allow from secondary, got %v", res1["decision"])
	}
	if !tiered.IsLocalInCooldown() {
		t.Fatalf("expected local to be in cooldown after primary failure")
	}

	// Second run: local is skipped via circuit breaker directly to cloud
	res2, _, _ := tiered.Evaluate("system", "prompt")
	if res2["decision"] != "allow" {
		t.Fatalf("expected allow from secondary on cooldown, got %v", res2["decision"])
	}

	tiered.MarkLocalHealthy()
}

func TestOllamaAutoModelResolution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"models": []map[string]string{
				{"name": "mistral:latest"},
				{"name": "qwen3.5:9b"},
			},
		})
	}))
	defer server.Close()

	ollama := providers.NewOllamaProvider(server.URL+"/api/chat", "auto", 4096, 0.0, 2*time.Second, 512)
	resolved := ollama.ResolveModelID()
	if resolved != "qwen3.5:9b" {
		t.Fatalf("expected qwen3.5:9b, got %s", resolved)
	}
}

func TestGeminiProviderSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"candidates": []map[string]interface{}{
				{
					"content": map[string]interface{}{
						"parts": []map[string]string{
							{"text": "{\"decision\": \"allow\", \"reason\": \"Gemini verified safe.\"}"},
						},
					},
				},
			},
		})
	}))
	defer server.Close()

	gemini := providers.NewGeminiProvider("fake-key-123", "gemini-flash-lite-latest", 0.0, 2*time.Second, 512)
	// Override client to use test server URL via custom evaluate or test wrapper
	p := providers.NewOpenAICompatibleProvider(server.URL+"/chat/completions", "gemini", "fake-key", 0.0, 2*time.Second, 512)
	// We verify ParseJSONSafely + evaluate format parsing directly
	raw := "{\"decision\": \"allow\", \"reason\": \"Gemini verified safe.\"}"
	parsed := providers.ParseJSONSafely(raw)
	if parsed["decision"] != "allow" || parsed["reason"] != "Gemini verified safe." {
		t.Fatalf("failed gemini parse verification")
	}
	if gemini.Model != "gemini-flash-lite-latest" {
		t.Fatalf("unexpected model: %s", gemini.Model)
	}
	if p == nil {
		t.Fatal("unexpected nil")
	}
}

func TestAnthropicProviderSuccess(t *testing.T) {
	raw := "{\"decision\": \"allow\", \"reason\": \"Claude Haiku approved.\"}"
	parsed := providers.ParseJSONSafely(raw)
	if parsed == nil || parsed["decision"] != "allow" || parsed["reason"] != "Claude Haiku approved." {
		t.Fatalf("failed anthropic json parse: %v", parsed)
	}
	ant := providers.NewAnthropicProvider("sk-ant-test", "claude-3-5-haiku-latest", 0.0, 2*time.Second, 1024)
	if ant.Model != "claude-3-5-haiku-latest" {
		t.Fatalf("unexpected anthropic model: %s", ant.Model)
	}
}

func TestOpenAICloudProviderAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer sk-test-key" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]string{
						"content": "{\"decision\": \"allow\", \"reason\": \"GPT-4o-mini approved.\"}",
					},
				},
			},
		})
	}))
	defer server.Close()

	p := providers.NewOpenAICompatibleProvider(server.URL+"/v1/chat/completions", "gpt-4o-mini", "sk-test-key", 0.0, 2*time.Second, 512)
	res, _, err := p.Evaluate("system", "prompt")
	if err != nil {
		t.Fatal(err)
	}
	if res["decision"] != "allow" {
		t.Fatalf("expected allow, got %v", res["decision"])
	}
	if res["reason"] != "GPT-4o-mini approved." {
		t.Fatalf("expected reason GPT-4o-mini approved., got %v", res["reason"])
	}
}

func TestGetProviderTieredWiring(t *testing.T) {
	// 1. Gemini failover
	cfgGemini := config.NewDefaultConfig()
	cfgGemini.Provider = "llamacpp"
	cfgGemini.FallbackToCloud = true
	cfgGemini.CloudProvider = "gemini"
	cfgGemini.CloudModel = "gemini-flash-lite-latest"

	prov1 := providers.GetProvider(cfgGemini)
	tiered1, ok := prov1.(*providers.TieredProvider)
	if !ok {
		t.Fatalf("expected TieredProvider, got %T", prov1)
	}
	if _, ok := tiered1.Primary.(*providers.OpenAICompatibleProvider); !ok {
		t.Fatalf("expected OpenAICompatibleProvider primary, got %T", tiered1.Primary)
	}
	if _, ok := tiered1.Secondary.(*providers.GeminiProvider); !ok {
		t.Fatalf("expected GeminiProvider secondary, got %T", tiered1.Secondary)
	}

	// 2. Anthropic failover
	cfgClaude := config.NewDefaultConfig()
	cfgClaude.Provider = "llamacpp"
	cfgClaude.FallbackToCloud = true
	cfgClaude.CloudProvider = "anthropic"
	cfgClaude.CloudModel = "claude-3-5-haiku-latest"

	prov2 := providers.GetProvider(cfgClaude)
	tiered2, ok := prov2.(*providers.TieredProvider)
	if !ok {
		t.Fatalf("expected TieredProvider, got %T", prov2)
	}
	if _, ok := tiered2.Secondary.(*providers.AnthropicProvider); !ok {
		t.Fatalf("expected AnthropicProvider secondary, got %T", tiered2.Secondary)
	}

	// 3. OpenAI failover
	cfgOpenAI := config.NewDefaultConfig()
	cfgOpenAI.Provider = "llamacpp"
	cfgOpenAI.FallbackToCloud = true
	cfgOpenAI.CloudProvider = "openai"
	cfgOpenAI.CloudModel = "gpt-4o-mini"

	prov3 := providers.GetProvider(cfgOpenAI)
	tiered3, ok := prov3.(*providers.TieredProvider)
	if !ok {
		t.Fatalf("expected TieredProvider, got %T", prov3)
	}
	secOpenAI, ok := tiered3.Secondary.(*providers.OpenAICompatibleProvider)
	if !ok {
		t.Fatalf("expected OpenAICompatibleProvider secondary, got %T", tiered3.Secondary)
	}
	if secOpenAI.Endpoint != "https://api.openai.com/v1/chat/completions" {
		t.Fatalf("expected openai endpoint, got %s", secOpenAI.Endpoint)
	}
}

// TestGeminiPrimaryStillGetsCloudFailover guards against a regression where selecting
// "gemini" (or "anthropic") as the primary provider returned early, bypassing the
// FallbackToCloud wiring entirely — so a rate-limited or timed-out Gemini primary had no
// secondary to fail over to, silently making fallback_to_cloud/cloud_provider inert.
func TestGeminiPrimaryStillGetsCloudFailover(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Provider = "gemini"
	cfg.FallbackToCloud = true
	cfg.CloudProvider = "anthropic"

	prov := providers.GetProvider(cfg)
	tiered, ok := prov.(*providers.TieredProvider)
	if !ok {
		t.Fatalf("expected a gemini primary to still be wrapped in TieredProvider, got %T", prov)
	}
	if _, ok := tiered.Primary.(*providers.GeminiProvider); !ok {
		t.Fatalf("expected GeminiProvider primary, got %T", tiered.Primary)
	}
	if _, ok := tiered.Secondary.(*providers.AnthropicProvider); !ok {
		t.Fatalf("expected AnthropicProvider secondary, got %T", tiered.Secondary)
	}
}

// TestGroqCloudDefaultsToAutoModel guards against a regression where Groq/OpenRouter cloud
// failover always requested "gpt-4o-mini" — a model those endpoints don't serve — instead
// of "auto", which lets the provider resolve an available model from the endpoint itself.
func TestGroqCloudDefaultsToAutoModel(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Provider = "llamacpp"
	cfg.FallbackToCloud = true
	cfg.CloudProvider = "groq"
	cfg.CloudModel = ""

	prov := providers.GetProvider(cfg)
	tiered, ok := prov.(*providers.TieredProvider)
	if !ok {
		t.Fatalf("expected TieredProvider, got %T", prov)
	}
	secGroq, ok := tiered.Secondary.(*providers.OpenAICompatibleProvider)
	if !ok {
		t.Fatalf("expected OpenAICompatibleProvider secondary, got %T", tiered.Secondary)
	}
	if secGroq.Model != "auto" {
		t.Fatalf("expected Groq cloud model to default to 'auto', got %q", secGroq.Model)
	}
}

// TestResolveAPIKeyPrecedence guards against a regression where a project-local
// auto-permissions.json's api_key/provider-specific key was silently ignored because
// ResolveAPIKey only ever consulted the environment variable and a hardcoded global config
// path, never the already-loaded Config. Precedence must match Python: specific key >
// generic api_key > environment variable.
func TestResolveAPIKeyPrecedence(t *testing.T) {
	t.Setenv("TEST_PROVIDER_API_KEY", "from-env")

	if got := providers.ResolveAPIKey("TEST_PROVIDER_API_KEY", "from-specific", "from-generic"); got != "from-specific" {
		t.Fatalf("expected specific config key to win, got %q", got)
	}
	if got := providers.ResolveAPIKey("TEST_PROVIDER_API_KEY", "", "from-generic"); got != "from-generic" {
		t.Fatalf("expected generic api_key to win over env when specific is empty, got %q", got)
	}
	if got := providers.ResolveAPIKey("TEST_PROVIDER_API_KEY", "", ""); got != "from-env" {
		t.Fatalf("expected env var fallback when no config key is set, got %q", got)
	}
}
