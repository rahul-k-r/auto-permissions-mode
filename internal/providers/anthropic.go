package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AnthropicProvider connects to Anthropic Messages API.
type AnthropicProvider struct {
	APIKey      string
	Model       string
	Temperature float64
	Timeout     time.Duration
	MaxTokens   int
	client      *http.Client
}

func NewAnthropicProvider(apiKey, model string, temp float64, timeout time.Duration, maxTokens int) *AnthropicProvider {
	if apiKey == "" {
		apiKey = ResolveAPIKey("ANTHROPIC_API_KEY", "", "")
	}
	if model == "" || model == "auto" || model == "default" {
		model = "claude-3-5-haiku-latest"
	}
	if timeout <= 0 {
		timeout = 4500 * time.Millisecond
	}
	if maxTokens <= 0 {
		maxTokens = 1024
	}
	return &AnthropicProvider{
		APIKey:      apiKey,
		Model:       model,
		Temperature: temp,
		Timeout:     timeout,
		MaxTokens:   maxTokens,
		client:      &http.Client{Timeout: timeout},
	}
}

func (p *AnthropicProvider) GetEndpoint() string {
	return "https://api.anthropic.com"
}

func (p *AnthropicProvider) Evaluate(systemPrompt, prompt string) (map[string]interface{}, string, error) {
	if p.APIKey == "" {
		return nil, "CLOUD", fmt.Errorf("anthropic api key not configured")
	}

	url := "https://api.anthropic.com/v1/messages"
	payload := map[string]interface{}{
		"model":       p.Model,
		"max_tokens":  p.MaxTokens,
		"system":      systemPrompt,
		"temperature": p.Temperature,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, "CLOUD", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, "CLOUD", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-api-key", p.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, "CLOUD", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "CLOUD", fmt.Errorf("anthropic returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "CLOUD", err
	}

	var dataResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.Unmarshal(body, &dataResp); err == nil && len(dataResp.Content) > 0 {
		text := dataResp.Content[0].Text
		parsed := ParseJSONSafely(text)
		if parsed != nil {
			return parsed, "CLOUD", nil
		}
	}

	return nil, "CLOUD", fmt.Errorf("failed to parse anthropic response")
}
