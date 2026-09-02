"""Hook handler script executed by Antigravity / agy PreToolUse lifecycle event."""

import sys
import json

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from auto_permissions.config import load_config
from auto_permissions.providers import get_provider
from auto_permissions.evaluator import SecurityEvaluator

def run_hook() -> None:
    raw_input = sys.stdin.read()
    if not raw_input.strip():
        return

    config = load_config()
    provider = get_provider(config)
    evaluator = SecurityEvaluator(provider, config)

    try:
        data = json.loads(raw_input)
        tool_call = data.get("toolCall", {})
        tool_name = tool_call.get("name", "")
        tool_args = tool_call.get("args", {})

        result = evaluator.evaluate_tool_call(tool_name, tool_args)
    except Exception as e:
        fallback = config.get("fallback_action", "ask")
        if fallback == "ask":
            fallback = "force_ask"
        result = {
            "decision": fallback,
            "reason": f"Hook error ({str(e)}). Deferring to '{fallback}'."
        }

    # Only log debug output if explicitly configured
    debug_log = config.get("debug_log")
    if debug_log:
        try:
            with open(debug_log, "a", encoding="utf-8") as f:
                f.write(f"INPUT: {raw_input.strip()}\n")
                f.write(f"OUTPUT: {json.dumps(result)}\n\n")
        except Exception:
            pass

    print(json.dumps(result))

if __name__ == "__main__":
    run_hook()
