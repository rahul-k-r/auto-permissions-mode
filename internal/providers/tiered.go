package providers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TieredProvider coordinates local-first execution with circuit-breaking and cloud failover.
type TieredProvider struct {
	Primary       Provider
	Secondary     Provider
	TotalDeadline time.Duration
}

func NewTieredProvider(primary Provider, secondary Provider, totalDeadline time.Duration) *TieredProvider {
	if totalDeadline <= 0 {
		totalDeadline = 15 * time.Second
	}
	return &TieredProvider{
		Primary:       primary,
		Secondary:     secondary,
		TotalDeadline: totalDeadline,
	}
}

func (p *TieredProvider) GetEndpoint() string {
	if p.Primary != nil {
		return p.Primary.GetEndpoint()
	}
	return ""
}

func (p *TieredProvider) circuitBreakerFile() string {
	keySrc := "TieredProvider"
	if p.Primary != nil && p.Primary.GetEndpoint() != "" {
		keySrc = p.Primary.GetEndpoint()
	}
	h := sha256.Sum256([]byte(keySrc))
	key := hex.EncodeToString(h[:])[:12]
	return filepath.Join(os.TempDir(), fmt.Sprintf("auto_permissions_cb_%s.json", key))
}

func (p *TieredProvider) IsLocalInCooldown() bool {
	return IsInTTLCooldown(p.circuitBreakerFile(), "down_until")
}

func (p *TieredProvider) MarkLocalDown(durationSeconds float64) {
	WriteTTLCooldown(p.circuitBreakerFile(), durationSeconds, "down_until", nil)
}

func (p *TieredProvider) MarkLocalHealthy() {
	WriteTTLCooldown(p.circuitBreakerFile(), 0, "down_until", nil)
}

func (p *TieredProvider) Evaluate(systemPrompt, prompt string) (map[string]interface{}, string, error) {
	t0 := time.Now()
	localDown := p.IsLocalInCooldown()

	// 1. Try Primary if not in cooldown
	if !localDown && p.Primary != nil {
		res, src, err := p.Primary.Evaluate(systemPrompt, prompt)
		if err == nil && res != nil {
			p.MarkLocalHealthy()
			if src == "" {
				src = "LOCAL"
				if strings.HasPrefix(p.Primary.GetEndpoint(), "https://") {
					src = "CLOUD"
				}
			}
			return res, src, nil
		}
		// Trip circuit breaker on failure
		p.MarkLocalDown(30.0)
	}

	// If secondary is not configured, fail immediately
	if p.Secondary == nil {
		return nil, "OFFLINE", fmt.Errorf("primary offline and no secondary cloud provider configured")
	}

	// 2. Check remaining deadline budget
	elapsed := time.Since(t0)
	remaining := p.TotalDeadline - elapsed
	if remaining < 1*time.Second {
		return map[string]interface{}{
			"decision": "force_ask",
			"reason":   fmt.Sprintf("Local server offline and deadline budget expired (%.1fs elapsed). Escalating to manual confirmation.", elapsed.Seconds()),
		}, "TIMEOUT", nil
	}

	// 3. Failover to cloud secondary
	resCloud, _, err := p.Secondary.Evaluate(systemPrompt, prompt)
	if err == nil && resCloud != nil {
		return resCloud, "FAILOVER", nil
	}

	// 4. Both failed
	return map[string]interface{}{
		"decision": "force_ask",
		"reason":   "Local server and cloud failover both unavailable or rate-limited. Escalating to manual confirmation.",
	}, "OFFLINE", nil
}
