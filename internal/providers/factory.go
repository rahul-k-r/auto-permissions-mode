package providers

import (
	"os"
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
		apiKey := ResolveAPIKey("GEMINI_API_KEY", "gemini_api_key")
		return NewGeminiProvider(apiKey, model, temp, timeout, maxTokens)
	} else if provName == "anthropic" {
		apiKey := ResolveAPIKey("ANTHROPIC_API_KEY", "anthropic_api_key")
		return NewAnthropicProvider(apiKey, model, temp, timeout, maxTokens)
	} else if provName == "ollama" {
		primary = NewOllamaProvider(endpoint, model, numCtx, temp, timeout, maxTokens)
	} else {
		// llamacpp, openai, or generic openai-compatible
		apiKey := ResolveAPIKey("OPENAI_API_KEY", "openai_api_key")
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
			apiKey := ResolveAPIKey("ANTHROPIC_API_KEY", "anthropic_api_key")
			secondary = NewAnthropicProvider(apiKey, cloudModel, temp, cloudTimeout, maxTokens)
		} else if cloudProv == "openai" || cloudProv == "openrouter" || cloudProv == "groq" {
			cloudEP := "https://api.openai.com/v1/chat/completions"
			if cloudProv == "openrouter" {
				cloudEP = "https://openrouter.ai/api/v1/chat/completions"
			} else if cloudProv == "groq" {
				cloudEP = "https://api.groq.com/openai/v1/chat/completions"
			}
			apiKey := ResolveAPIKey("OPENAI_API_KEY", "openai_api_key")
			if cloudProv == "openrouter" {
				if k := os.Getenv("OPENROUTER_API_KEY"); k != "" {
					apiKey = k
				}
			}
			defModel := "gpt-4o-mini"
			if cloudModel != "" {
				defModel = cloudModel
			}
			secondary = NewOpenAICompatibleProvider(cloudEP, defModel, apiKey, temp, cloudTimeout, maxTokens)
		} else {
			// default gemini
			apiKey := ResolveAPIKey("GEMINI_API_KEY", "gemini_api_key")
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
