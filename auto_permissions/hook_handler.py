"""Hook handler script executed by Antigravity / agy PreToolUse lifecycle event."""

import sys
import json
import time

# Ensure UTF-8 output and input on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace") # type: ignore
    except Exception:
        pass
if hasattr(sys.stdin, "reconfigure"):
    try:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace") # type: ignore
    except Exception:
        pass

from auto_permissions.config import load_config
from auto_permissions.providers import get_provider
from auto_permissions.evaluator import SecurityEvaluator

def run_hook() -> None:
    raw_input = sys.stdin.read()
    if not raw_input.strip():
        print(json.dumps({"decision": "force_ask", "reason": "No input received on hook stdin."}))
        return

    config = {}
    tool_name = "unknown"
    tool_args = {}
    context = {}

    try:
        config = load_config()
        provider = get_provider(config)
        evaluator = SecurityEvaluator(provider, config)

        data = json.loads(raw_input)
        tool_call = data.get("toolCall", {})
        tool_name = tool_call.get("name", "unknown")
        tool_args = tool_call.get("args", {})

        context = {
            "workspace_paths": data.get("workspacePaths", []),
            "artifact_dir": data.get("artifactDirectoryPath", ""),
            "conversation_id": data.get("conversationId") or "",
            "transcript_path": data.get("transcriptPath", ""),
        }

        t0 = time.time()
        result = evaluator.evaluate_tool_call(tool_name, tool_args, context=context)
        latency_ms = (time.time() - t0) * 1000
    except Exception as e:
        fallback = config.get("fallback_action", "ask") if isinstance(config, dict) else "ask"
        if fallback == "ask":
            fallback = "force_ask"
        result = {
            "decision": fallback,
            "reason": f"Hook error ({str(e)}). Deferring to '{fallback}'.",
            "source": "ERROR",
        }
        latency_ms = 0.0

    # Non-blocking telemetry recording (<0.3ms)
    try:
        from auto_permissions.monitor import record_audit_event
        record_audit_event(
            tool_name=tool_name,
            tool_args=tool_args,
            decision=result.get("decision", "unknown"),
            reason=result.get("reason", ""),
            latency_ms=latency_ms,
            source=result.get("source", "LOCAL"),
            context=context
        )
    except Exception:
        pass

    # Only log debug output if explicitly configured
    debug_log = config.get("debug_log")
    if debug_log:
        try:
            with open(debug_log, "a", encoding="utf-8") as f:
                f.write(f"INPUT: {raw_input.strip()}\n")
                f.write(f"OUTPUT: {json.dumps(result)}\n\n")
        except Exception:
            pass

    hook_output = {
        "decision": result.get("decision", "force_ask"),
        "reason": result.get("reason", "")
    }
    print(json.dumps(hook_output))

if __name__ == "__main__":
    run_hook()
