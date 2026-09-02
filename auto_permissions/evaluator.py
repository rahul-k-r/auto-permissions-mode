"""Security evaluation engine for Auto Permissions Mode."""

import json
from typing import Any, Dict
from auto_permissions.providers import BaseProvider

SYSTEM_PROMPT = """You are the autonomous security gatekeeper for an AI coding assistant (Auto Permissions Mode).
Your job is to evaluate proposed tool executions, allow safe development actions, block harmful or malicious operations, and flag ambiguous or high-risk tasks for user confirmation.

### Evaluation Rules:

1. "allow":
   - Safe, standard local development workflows:
     - Local Git operations: `git add`, `git commit`, `git status`, `git diff`, `git log`, `git branch`, `git checkout`, `git switch`, `git stash`. Always ALLOW local repository staging and commits without user interruption.
     - Building, compiling, running unit tests, formatting code, running linters.
     - Standard package management: `npm install`, `pip install`, `cargo build`, `go test`.
     - Creating or editing standard source code, documentation, and config files without hidden payloads.

2. "ask":
   - Operations that modify remote GitHub repositories, destroy uncommitted data, or require human review:
     - Remote Git repository operations: `git push`, `git push origin <branch>`, `git push --force`. All pushes to remote repositories require explicit user confirmation.
     - Destructive or rollback Git operations: `git reset --hard`, `git clean -fd`, `git restore` (reverting uncommitted work across files).
     - Infrastructure teardown: `docker system prune`, dropping database tables, deleting production configs.

3. "deny":
   - Dangerous, destructive, or unauthorized operations:
     - Direct threats: Recursive disk deletion (e.g., rm -rf /, del /s /q C:\\), dropping databases, formatting drives, killing critical system processes.
     - Circumvention attempts: Embedding malicious subprocesses, reverse shells, curl/wget piping to bash, obfuscated base64 commands, or destructive shell scripts inside tests, build scripts (package.json, Makefile), or source code.
     - Accessing, modifying, or exfiltrating sensitive credentials, private keys (.ssh, id_rsa), or unauthorized environment secrets (.env).
   - CRITICAL REQUIREMENT FOR DENIALS: The "reason" MUST be instructional and constructive. Explain the exact safety violation AND suggest a safe, non-destructive alternative so the agent can self-correct and continue without stalling.

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

SAFE_LOCAL_GIT_PREFIXES = (
    "git add",
    "git commit",
    "git status",
    "git diff",
    "git log",
    "git branch",
    "git checkout",
    "git switch",
    "git stash",
    "git show",
    "git tag",
)

REMOTE_OR_RISKY_GIT_FLAGS = (
    "push",
    "--force",
    "-f",
    "--hard",
    "clean",
    "reset",
    "rebase",
    "remote",
    "restore",
)

class SecurityEvaluator:
    def __init__(self, provider: BaseProvider, config: Dict[str, Any]):
        self.provider = provider
        self.config = config
        self.fast_path = config.get("fast_path_read_only", True)
        self.protected_paths = config.get("protected_paths", [])

    def evaluate_tool_call(self, tool_name: str, tool_args: dict) -> Dict[str, Any]:
        # Fast path 1: Instantly allow known safe read-only tools
        if self.fast_path and tool_name in READ_ONLY_TOOLS:
            return {
                "decision": "allow",
                "reason": f"Fast-path: Safe read-only inspection ({tool_name})."
            }

        # Fast path 2: Instantly allow safe local git operations (git add, git commit, etc.)
        if tool_name == "run_command":
            cmd = tool_args.get("CommandLine", "").strip()
            if cmd.startswith("git "):
                # If command contains remote push or destructive flags, pass to safety evaluation
                cmd_tokens = set(cmd.split())
                has_risky_flag = any(flag in cmd_tokens or f" {flag} " in f" {cmd} " for flag in REMOTE_OR_RISKY_GIT_FLAGS)
                if not has_risky_flag and any(cmd.startswith(prefix) for prefix in SAFE_LOCAL_GIT_PREFIXES):
                    return {
                        "decision": "allow",
                        "reason": f"Fast-path: Safe local git operation ({cmd.split()[0]} {cmd.split()[1] if len(cmd.split()) > 1 else ''})."
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

        # Escalate 'ask' to 'force_ask' to override cached permissions on high-impact actions
        if decision == "ask":
            decision = "force_ask"

        return {
            "decision": decision,
            "reason": decision_data.get("reason", "Evaluated by local security model.")
        }
