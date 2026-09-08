package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GeminiProvider connects to Google Gemini Generative Language REST API.
type GeminiProvider struct {
	APIKey      string
	Model       string
	Temperature float64
	Timeout     time.Duration
	MaxTokens   int
	client      *http.Client
}

func NewGeminiProvider(apiKey, model string, temp float64, timeout time.Duration, maxTokens int) *GeminiProvider {
	if apiKey == "" {
		apiKey = ResolveAPIKey("GEMINI_API_KEY", "", "")
	}
	if model == "" || model == "auto" || model == "default" {
		model = "gemini-flash-lite-latest"
	}
	if timeout <= 0 {
		timeout = 4500 * time.Millisecond
	}
	if maxTokens <= 0 {
		maxTokens = 512
	}
	return &GeminiProvider{
		APIKey:      apiKey,
		Model:       model,
		Temperature: temp,
		Timeout:     timeout,
		MaxTokens:   maxTokens,
		client:      &http.Client{Timeout: timeout},
	}
}

func (p *GeminiProvider) GetEndpoint() string {
	return "https://generativelanguage.googleapis.com"
}

func (p *GeminiProvider) cooldownFile() string {
	return filepath.Join(os.TempDir(), "auto_permissions_gemini_cooldown.json")
}

func (p *GeminiProvider) IsInCooldown() bool {
	return IsInTTLCooldown(p.cooldownFile(), "cooldown_until")
}

func (p *GeminiProvider) setCooldown(seconds float64, reason string) {
	WriteTTLCooldown(p.cooldownFile(), seconds, "cooldown_until", map[string]interface{}{"reason": reason})
}

func (p *GeminiProvider) Evaluate(systemPrompt, prompt string) (map[string]interface{}, string, error) {
	if p.APIKey == "" || p.IsInCooldown() {
		return nil, "CLOUD", fmt.Errorf("gemini unavailable: missing api key or in cooldown")
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", p.Model, p.APIKey)
	payload := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"role": "user",
				"parts": []map[string]string{
					{"text": fmt.Sprintf("%s\n\n%s", systemPrompt, prompt)},
				},
			},
		},
		"generationConfig": map[string]interface{}{
			"responseMimeType": "application/json",
			"responseSchema": map[string]interface{}{
				"type": "OBJECT",
				"properties": map[string]interface{}{
					"decision": map[string]interface{}{
						"type": "STRING",
						"enum": []string{"allow", "deny", "ask", "force_ask"},
					},
					"reason": map[string]string{"type": "STRING"},
					"alternatives": map[string]interface{}{
						"type": "ARRAY",
						"items": map[string]interface{}{
							"type": "OBJECT",
							"properties": map[string]interface{}{
								"label":   map[string]string{"type": "STRING"},
								"command": map[string]string{"type": "STRING"},
							},
							"required": []string{"label"},
						},
					},
				},
				"required": []string{"decision", "reason"},
			},
			"temperature":     p.Temperature,
			"maxOutputTokens": p.MaxTokens,
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

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, "CLOUD", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp.Body)
		bodyStr := strings.ToLower(string(body))
		isDaily := strings.Contains(bodyStr, "daily") || strings.Contains(bodyStr, "limit: 500")
		cooldownSec := 60.0
		if isDaily {
			cooldownSec = 86400.0
		}
		p.setCooldown(cooldownSec, "HTTP 429 Rate Limit")
		return nil, "CLOUD", fmt.Errorf("gemini rate limited (429)")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "CLOUD", fmt.Errorf("gemini returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "CLOUD", err
	}

	var dataResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.Unmarshal(body, &dataResp); err == nil && len(dataResp.Candidates) > 0 {
		parts := dataResp.Candidates[0].Content.Parts
		if len(parts) > 0 {
			parsed := ParseJSONSafely(parts[0].Text)
			if parsed != nil {
				return parsed, "CLOUD", nil
			}
		}
	}

	return nil, "CLOUD", fmt.Errorf("failed to parse gemini response")
}
