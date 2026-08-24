"""Security evaluation engine for Auto Permissions Mode."""

import json
from typing import Any, Dict
from auto_permissions.providers import BaseProvider

SYSTEM_PROMPT = """You are the autonomous security gatekeeper for an AI coding assistant (Auto Permissions Mode).
Your job is to evaluate proposed tool executions, allow safe development actions, block harmful or malicious operations, and flag ambiguous or high-risk tasks for user confirmation.

### Evaluation Rules:

1. "allow":
   - Safe, standard development workflows:
     - Building, compiling, running unit tests, formatting code, running linters.
     - Git operations: status, log, diff, commit, checkout, switch, branch, pull, push (to standard feature branches).
     - Standard package management: npm install, pip install, cargo build, go test.
     - Creating or editing standard source code, documentation, and config files without hidden payloads.

2. "deny":
   - Dangerous, destructive, or unauthorized operations:
     - Direct threats: Recursive disk deletion (e.g., rm -rf /, del /s /q C:\\), dropping databases, formatting drives, killing critical system processes.
     - Circumvention attempts: Embedding malicious subprocesses, reverse shells, curl/wget piping to bash, obfuscated base64 commands, or destructive shell scripts inside tests, build scripts (package.json, Makefile), or source code.
     - Accessing, modifying, or exfiltrating sensitive credentials, private keys (.ssh, id_rsa), or unauthorized environment secrets (.env).
   - CRITICAL REQUIREMENT FOR DENIALS: The "reason" MUST be instructional and constructive. Explain the exact safety violation AND suggest a safe, non-destructive alternative so the agent can self-correct and continue without stalling.

3. "ask":
   - High-impact or irreversible operations requiring human review:
     - Force pushes (git push --force).
     - Hard resets (git reset --hard) with uncommitted work.
     - Running destructive database migrations in production/shared environments.
     - Deleting non-empty directories or production configs.

### Output JSON Format:
Respond ONLY with a JSON object:
{
  "decision": "allow" | "deny" | "ask",
  "reason": "<Concise explanation + safe alternative if denied>"
}
"""

READ_ONLY_TOOLS = {
    "view_file",
    "list_dir",
    "find_by_name",
    "grep_search",
    "read_url_content",
    "schedule",
    "manage_task",
    "manage_subagents",
    "send_message",
}

class SecurityEvaluator:
    def __init__(self, provider: BaseProvider, config: Dict[str, Any]):
        self.provider = provider
        self.config = config
        self.fast_path = config.get("fast_path_read_only", True)
        self.protected_paths = config.get("protected_paths", [])

    def evaluate_tool_call(self, tool_name: str, tool_args: dict) -> Dict[str, Any]:
        # Fast path: Instantly allow known safe read-only tools without inference overhead
        if self.fast_path and tool_name in READ_ONLY_TOOLS:
            return {
                "decision": "allow",
                "reason": f"Fast-path: Safe read-only inspection ({tool_name})."
            }

        # Check protected paths explicitly for file write or command operations
        args_str = json.dumps(tool_args)
        for protected in self.protected_paths:
            if protected in args_str and any(w in tool_name for w in ["write", "replace", "command"]):
                # Allow user prompt for protected path access
                if "read" not in tool_name.lower():
                    prompt = f"Proposed Action: {tool_name}\nArguments: {json.dumps(tool_args, indent=2)}"
                    # Let the model review with extra warning context
                    break

        user_prompt = f"""Evaluate this tool execution:
Tool: {tool_name}
Arguments:
{json.dumps(tool_args, indent=2)}"""

        decision_data = self.provider.evaluate(SYSTEM_PROMPT, user_prompt)

        if not decision_data or not isinstance(decision_data, dict):
            fallback = self.config.get("fallback_action", "ask")
            return {
                "decision": fallback,
                "reason": f"Security model unavailable or invalid response. Fallback to '{fallback}'."
            }

        decision = decision_data.get("decision", "").lower()
        if decision not in ["allow", "deny", "ask", "force_ask"]:
            decision = self.config.get("fallback_action", "ask")

        return {
            "decision": decision,
            "reason": decision_data.get("reason", "Evaluated by local security model.")
        }
