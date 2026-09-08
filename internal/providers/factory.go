package providers

import (
	"strings"
	"time"

	"github.com/rahul-k-r/auto-permissions-mode/internal/config"
)

// GetProvider wires the provider hierarchy based on application configuration.
func GetProvider(cfg config.Config) Provider {
	provName := strings.ToLower(strings.TrimSpace(cfg.Provider))
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "http://127.0.0.1:9931/v1/chat/completions"
	}
	model := cfg.Model
	timeout := time.Duration(cfg.TimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}
	temp := cfg.Temperature
	numCtx := cfg.NumCtx
	if numCtx <= 0 {
		numCtx = 4096
	}
	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 512
	}

	var primary Provider

	if provName == "gemini" {
		apiKey := ResolveAPIKey("GEMINI_API_KEY", cfg.GeminiAPIKey, cfg.APIKey)
		primary = NewGeminiProvider(apiKey, model, temp, timeout, maxTokens)
	} else if provName == "anthropic" {
		apiKey := ResolveAPIKey("ANTHROPIC_API_KEY", cfg.AnthropicAPIKey, cfg.APIKey)
		primary = NewAnthropicProvider(apiKey, model, temp, timeout, maxTokens)
	} else if provName == "ollama" {
		primary = NewOllamaProvider(endpoint, model, numCtx, temp, timeout, maxTokens)
	} else {
		// llamacpp, openai, or generic openai-compatible
		apiKey := ResolveAPIKey("OPENAI_API_KEY", cfg.OpenAIAPIKey, cfg.APIKey)
		primary = NewOpenAICompatibleProvider(endpoint, model, apiKey, temp, timeout, maxTokens)
	}

	if cfg.FallbackToCloud {
		cloudProv := strings.ToLower(strings.TrimSpace(cfg.CloudProvider))
		cloudTimeout := time.Duration(cfg.CloudTimeoutSeconds * float64(time.Second))
		if cloudTimeout <= 0 {
			cloudTimeout = 12 * time.Second
		}
		cloudModel := cfg.CloudModel

		var secondary Provider
		if cloudProv == "anthropic" {
			apiKey := ResolveAPIKey("ANTHROPIC_API_KEY", cfg.AnthropicAPIKey, cfg.APIKey)
			secondary = NewAnthropicProvider(apiKey, cloudModel, temp, cloudTimeout, maxTokens)
		} else if cloudProv == "openai" || cloudProv == "openrouter" || cloudProv == "groq" {
			cloudEP := "https://api.openai.com/v1/chat/completions"
			if cloudProv == "openrouter" {
				cloudEP = "https://openrouter.ai/api/v1/chat/completions"
			} else if cloudProv == "groq" {
				cloudEP = "https://api.groq.com/openai/v1/chat/completions"
			}
			apiKey := ResolveAPIKey("OPENAI_API_KEY", cfg.OpenAIAPIKey, cfg.APIKey)
			if cloudProv == "openrouter" {
				if k := ResolveAPIKey("OPENROUTER_API_KEY", cfg.OpenRouterAPIKey, cfg.APIKey); k != "" {
					apiKey = k
				}
			}
			// Only OpenAI itself defaults to gpt-4o-mini; Groq/OpenRouter get "auto" so
			// the provider resolves an available model via the endpoint's /models list
			// instead of requesting a model name ("gpt-4o-mini") that endpoint doesn't serve.
			defModel := "auto"
			if cloudProv == "openai" {
				defModel = "gpt-4o-mini"
			}
			if cloudModel != "" {
				defModel = cloudModel
			}
			secondary = NewOpenAICompatibleProvider(cloudEP, defModel, apiKey, temp, cloudTimeout, maxTokens)
		} else {
			// default gemini
			apiKey := ResolveAPIKey("GEMINI_API_KEY", cfg.GeminiAPIKey, cfg.APIKey)
			secondary = NewGeminiProvider(apiKey, cloudModel, temp, cloudTimeout, maxTokens)
		}

		totalDeadline := time.Duration(cfg.TotalDeadlineSeconds * float64(time.Second))
		if totalDeadline <= 0 {
			totalDeadline = 18 * time.Second
		}
		return NewTieredProvider(primary, secondary, totalDeadline)
	}

	return primary
}
