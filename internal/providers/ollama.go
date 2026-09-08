package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OllamaProvider connects to Ollama /api/chat.
type OllamaProvider struct {
	Endpoint        string
	Model           string
	NumCtx          int
	Temperature     float64
	Timeout         time.Duration
	MaxTokens       int
	cachedModelID   string
	cachedModelTime time.Time
	mu              sync.Mutex
	client          *http.Client
}

func NewOllamaProvider(endpoint, model string, numCtx int, temp float64, timeout time.Duration, maxTokens int) *OllamaProvider {
	if endpoint == "" {
		endpoint = "http://127.0.0.1:11434/api/chat"
	}
	endpoint = strings.ReplaceAll(endpoint, "localhost", "127.0.0.1")
	if strings.HasSuffix(endpoint, "/api/generate") {
		endpoint = strings.ReplaceAll(endpoint, "/api/generate", "/api/chat")
	}
	if numCtx <= 0 {
		numCtx = 4096
	}
	if maxTokens <= 0 {
		maxTokens = 512
	}
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}
	return &OllamaProvider{
		Endpoint:    endpoint,
		Model:       model,
		NumCtx:      numCtx,
		Temperature: temp,
		Timeout:     timeout,
		MaxTokens:   maxTokens,
		client:      &http.Client{Timeout: timeout},
	}
}

func (p *OllamaProvider) GetEndpoint() string {
	return p.Endpoint
}

func (p *OllamaProvider) ResolveModelID() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Model != "" && p.Model != "auto" && p.Model != "default" {
		return p.Model
	}

	if p.cachedModelID != "" && time.Since(p.cachedModelTime) < 60*time.Second {
		return p.cachedModelID
	}

	tagsURL := strings.ReplaceAll(p.Endpoint, "/api/chat", "/api/tags")
	client := &http.Client{Timeout: 1000 * time.Millisecond}
	req, err := http.NewRequest("GET", tagsURL, nil)
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				var data struct {
					Models []struct {
						Name string `json:"name"`
					} `json:"models"`
				}
				if err := json.Unmarshal(body, &data); err == nil && len(data.Models) > 0 {
					var names []string
					for _, m := range data.Models {
						if m.Name != "" {
							names = append(names, m.Name)
						}
					}
					for _, pref := range []string{"qwen3.5:9b", "qwen2.5:7b", "gemma4:e4b", "gemma4:12b", "gemma4:e2b"} {
						prefBase := strings.Split(pref, ":")[0]
						for _, n := range names {
							if n == pref || strings.HasPrefix(n, prefBase) {
								p.cachedModelID = n
								p.cachedModelTime = time.Now()
								return n
							}
						}
					}
					if len(names) > 0 {
						p.cachedModelID = names[0]
						p.cachedModelTime = time.Now()
						return names[0]
					}
				}
			}
		}
	}

	return "qwen3.5:9b"
}

func (p *OllamaProvider) Evaluate(systemPrompt, prompt string) (map[string]interface{}, string, error) {
	resolvedModel := p.ResolveModelID()
	payload := map[string]interface{}{
		"model": resolvedModel,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": prompt},
		},
		"format": "json",
		"stream": false,
		"options": map[string]interface{}{
			"num_ctx":     p.NumCtx,
			"num_predict": p.MaxTokens,
			"temperature": p.Temperature,
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, "LOCAL", err
	}

	req, err := http.NewRequest("POST", p.Endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, "LOCAL", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, "LOCAL", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "LOCAL", fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "LOCAL", err
	}

	var dataResp map[string]interface{}
	if err := json.Unmarshal(body, &dataResp); err != nil {
		return nil, "LOCAL", err
	}

	var content string
	if msg, ok := dataResp["message"].(map[string]interface{}); ok {
		content, _ = msg["content"].(string)
	}
	if content == "" {
		content, _ = dataResp["response"].(string)
	}

	parsed := ParseJSONSafely(content)
	if parsed == nil {
		return nil, "LOCAL", fmt.Errorf("failed to parse ollama json response")
	}
	return parsed, "LOCAL", nil
}
