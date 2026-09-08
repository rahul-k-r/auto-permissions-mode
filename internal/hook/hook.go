package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rahul-k-r/auto-permissions-mode/internal/config"
	"github.com/rahul-k-r/auto-permissions-mode/internal/evaluator"
	"github.com/rahul-k-r/auto-permissions-mode/internal/monitor"
	"github.com/rahul-k-r/auto-permissions-mode/internal/providers"
)

type HookOutput struct {
	Decision            string   `json:"decision"`
	Reason              string   `json:"reason"`
	PermissionOverrides []string `json:"permissionOverrides,omitempty"`
}

// ConfigLoader allows injecting configuration in tests.
var ConfigLoader = func() config.Config {
	return config.LoadConfig()
}

// ProviderGetter allows injecting providers in tests.
var ProviderGetter = func(cfg config.Config) providers.Provider {
	return providers.GetProvider(cfg)
}

// AuditRecorder allows injecting audit recording in tests.
var AuditRecorder = func(toolName string, toolArgs map[string]interface{}, decision, reason string, latencyMS float64, source string, context map[string]interface{}, cfg config.Config) {
	monitor.RecordAuditEvent(toolName, toolArgs, decision, reason, latencyMS, source, context, cfg)
}

func RunHook(reader io.Reader, writer io.Writer) error {
	rawInput, err := io.ReadAll(reader)
	if err != nil || len(strings.TrimSpace(string(rawInput))) == 0 {
		out := HookOutput{
			Decision: "force_ask",
			Reason:   "No input received on hook stdin.",
		}
		b, _ := json.Marshal(out)
		fmt.Fprintln(writer, string(b))
		return nil
	}

	cfg := ConfigLoader()
	var (
		toolName  string
		toolArgs  map[string]interface{}
		context   map[string]interface{}
		result    evaluator.DecisionResult
		latencyMS float64
	)

	var data map[string]interface{}
	if err := json.Unmarshal(rawInput, &data); err != nil {
		fallback := cfg.FallbackAction
		if strings.EqualFold(fallback, "ask") || fallback == "" {
			fallback = "force_ask"
		}
		out := HookOutput{
			Decision: fallback,
			Reason:   fmt.Sprintf("Hook evaluation error (%v). Deferring to '%s'.", err, fallback),
		}
		b, _ := json.Marshal(out)
		fmt.Fprintln(writer, string(b))
		return nil
	}

	if tc, ok := data["toolCall"].(map[string]interface{}); ok {
		if n, ok := tc["name"].(string); ok && n != "" {
			toolName = n
		}
		if a, ok := tc["args"].(map[string]interface{}); ok {
			toolArgs = a
		}
	}
	if toolArgs == nil {
		toolArgs = make(map[string]interface{})
	}

	context = make(map[string]interface{})
	if wp, ok := data["workspacePaths"].([]interface{}); ok {
		var paths []string
		for _, p := range wp {
			if s, ok := p.(string); ok {
				paths = append(paths, s)
			}
		}
		context["workspace_paths"] = paths
	}
	if ad, ok := data["artifactDirectoryPath"].(string); ok {
		context["artifact_dir"] = ad
	}
	if cid, ok := data["conversationId"].(string); ok {
		context["conversation_id"] = cid
	}
	if tp, ok := data["transcriptPath"].(string); ok {
		context["transcript_path"] = tp
	}

	prov := ProviderGetter(cfg)
	eval := evaluator.NewSecurityEvaluator(prov, cfg)

	t0 := time.Now()
	result = eval.EvaluateToolCall(toolName, toolArgs, context)
	latencyMS = float64(time.Since(t0).Microseconds()) / 1000.0

	AuditRecorder(
		toolName,
		toolArgs,
		result.AuditDecision,
		result.Reason,
		latencyMS,
		result.Source,
		context,
		cfg,
	)

	if cfg.DebugLog != "" {
		if f, err := os.OpenFile(cfg.DebugLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			_, _ = fmt.Fprintf(f, "INPUT: %s\nOUTPUT: %s\n\n", strings.TrimSpace(string(rawInput)), result.Decision)
			_ = f.Close()
		}
	}

	hookOutput := HookOutput{
		Decision: result.Decision,
		Reason:   result.Reason,
	}
	if result.Decision == "allow" && len(result.PermissionOverrides) > 0 {
		hookOutput.PermissionOverrides = result.PermissionOverrides
	}

	b, _ := json.Marshal(hookOutput)
	fmt.Fprintln(writer, string(b))
	return nil
}
