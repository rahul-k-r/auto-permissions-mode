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
	"sync"
	"time"
)

// OpenAICompatibleProvider connects to llama-server, vLLM, LM Studio, Groq, OpenRouter, or OpenAI.
type OpenAICompatibleProvider struct {
	Endpoint        string
	Model           string
	APIKey          string
	Temperature     float64
	Timeout         time.Duration
	MaxTokens       int
	cachedModelID   string
	cachedModelTime time.Time
	mu              sync.Mutex
	client          *http.Client
}

func NewOpenAICompatibleProvider(endpoint, model, apiKey string, temp float64, timeout time.Duration, maxTokens int) *OpenAICompatibleProvider {
	if endpoint == "" {
		endpoint = "http://127.0.0.1:9931/v1/chat/completions"
	}
	endpoint = strings.ReplaceAll(endpoint, "localhost", "127.0.0.1")
	if maxTokens <= 0 {
		maxTokens = 512
	}
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}
	return &OpenAICompatibleProvider{
		Endpoint:    endpoint,
		Model:       model,
		APIKey:      apiKey,
		Temperature: temp,
		Timeout:     timeout,
		MaxTokens:   maxTokens,
		client:      &http.Client{Timeout: timeout},
	}
}

func (p *OpenAICompatibleProvider) GetEndpoint() string {
	return p.Endpoint
}

func (p *OpenAICompatibleProvider) ResolveModelID() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	isRemote := strings.HasPrefix(p.Endpoint, "https://")
	if p.Model != "" && p.Model != "auto" && p.Model != "default" {
		return p.Model
	}

	if isRemote && strings.Contains(p.Endpoint, "api.openai.com") {
		return "gpt-4o-mini"
	}

	if p.cachedModelID != "" && time.Since(p.cachedModelTime) < 60*time.Second {
		return p.cachedModelID
	}

	cacheFile := filepath.Join(os.TempDir(), "auto_permissions_model_llama.json")
	if !isRemote {
		if data, err := os.ReadFile(cacheFile); err == nil {
			var cd struct {
				ModelID  string  `json:"model_id"`
				CachedAt float64 `json:"cached_at"`
			}
			if err := json.Unmarshal(data, &cd); err == nil {
				if float64(time.Now().Unix())-cd.CachedAt < 60 && cd.ModelID != "" {
					p.cachedModelID = cd.ModelID
					p.cachedModelTime = time.Now()
					return cd.ModelID
				}
			}
		}
	}

	candidateEndpoints := []string{p.Endpoint}
	if !isRemote && strings.Contains(p.Endpoint, ":9931") {
		candidateEndpoints = append(candidateEndpoints, strings.ReplaceAll(p.Endpoint, ":9931", ":8080"))
	}

	client := &http.Client{Timeout: 1000 * time.Millisecond}
	for _, ep := range candidateEndpoints {
		base := ep
		if idx := strings.LastIndex(base, "/chat/completions"); idx != -1 {
			base = base[:idx]
		}
		modelsURL := base + "/models"

		req, err := http.NewRequest("GET", modelsURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		if p.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.APIKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			var respData map[string]interface{}
			if err := json.Unmarshal(body, &respData); err == nil {
				var list []interface{}
				if d, ok := respData["data"].([]interface{}); ok {
					list = d
				} else if m, ok := respData["models"].([]interface{}); ok {
					list = m
				}
				if len(list) > 0 {
					if first, ok := list[0].(map[string]interface{}); ok {
						name, _ := first["id"].(string)
						if name == "" {
							name, _ = first["name"].(string)
						}
						if name != "" {
							p.cachedModelID = name
							p.cachedModelTime = time.Now()
							if !isRemote {
								p.Endpoint = ep
								b, _ := json.Marshal(map[string]interface{}{
									"model_id":  name,
									"cached_at": float64(time.Now().Unix()),
								})
								_ = os.WriteFile(cacheFile, b, 0644)
							}
							return name
						}
					}
				}
			}
		}
	}

	if isRemote {
		return "gpt-4o-mini"
	}
	return "default"
}

func (p *OpenAICompatibleProvider) Evaluate(systemPrompt, prompt string) (map[string]interface{}, string, error) {
	resolvedModel := p.ResolveModelID()
	payload := map[string]interface{}{
		"model": resolvedModel,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": prompt},
		},
		"max_tokens":  p.MaxTokens,
		"temperature": p.Temperature,
		"response_format": map[string]string{
			"type": "json_object",
		},
		"chat_template_kwargs": map[string]bool{
			"enable_thinking": false,
		},
		"reasoning_effort": "none",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}

	endpointsToTry := []string{p.Endpoint}
	if !strings.HasPrefix(p.Endpoint, "https://") && strings.Contains(p.Endpoint, ":9931") {
		fallback8080 := strings.ReplaceAll(p.Endpoint, ":9931", ":8080")
		if fallback8080 != p.Endpoint {
			endpointsToTry = append(endpointsToTry, fallback8080)
		}
	}

	source := "LOCAL"
	if strings.HasPrefix(p.Endpoint, "https://") {
		source = "CLOUD"
	}

	for _, ep := range endpointsToTry {
		req, err := http.NewRequest("POST", ep, bytes.NewReader(data))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if p.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.APIKey)
		}

		resp, err := p.client.Do(req)
		if err != nil {
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			var respData map[string]interface{}
			if err := json.Unmarshal(body, &respData); err == nil {
				if choices, ok := respData["choices"].([]interface{}); ok && len(choices) > 0 {
					if firstChoice, ok := choices[0].(map[string]interface{}); ok {
						if msg, ok := firstChoice["message"].(map[string]interface{}); ok {
							content, _ := msg["content"].(string)
							parsed := ParseJSONSafely(content)
							if parsed != nil {
								p.Endpoint = ep
								return parsed, source, nil
							}
						}
					}
				}
			}
		}
	}

	return nil, source, fmt.Errorf("openai compatible provider failed across endpoints: %v", endpointsToTry)
}
