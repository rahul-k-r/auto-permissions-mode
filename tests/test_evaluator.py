"""Unit tests for Auto Permissions Security Evaluator."""

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from typing import Optional, Dict, Any
from auto_permissions.providers import BaseProvider
from auto_permissions.evaluator import SecurityEvaluator, compute_permission_overrides

class MockProvider(BaseProvider):
    def __init__(self, mock_response: Any = "DEFAULT"):
        if mock_response == "DEFAULT":
            self.mock_response = {"decision": "allow", "reason": "Mocked safe"}
        else:
            self.mock_response = mock_response

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        return self.mock_response

class TestSecurityEvaluator(unittest.TestCase):
    def test_fast_path_read_only(self):
        provider = MockProvider()
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})
        
        # view_file should be allowed immediately via fast path
        result = evaluator.evaluate_tool_call("view_file", {"AbsolutePath": "test.txt"})
        self.assertEqual(result["decision"], "allow")
        self.assertIn("Fast-path", result["reason"])

    def test_destructive_command_deny(self):
        provider = MockProvider({"decision": "deny", "reason": "Destructive disk wipe blocked."})
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})
        
        result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "rm -rf /"})
        self.assertEqual(result["decision"], "deny")
        self.assertIn("Destructive", result["reason"])

    def test_deny_with_alternatives_builds_directive(self):
        provider = MockProvider({
            "decision": "deny",
            "reason": "Hard reset will discard uncommitted local changes.",
            "alternatives": [
                {"label": "Stash uncommitted changes to preserve work", "command": "git stash -u"},
                {"label": "Inspect changed files diff first", "command": "git status -s && git diff"}
            ]
        })
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})

        result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "git reset --hard HEAD~1"})
        self.assertEqual(result["decision"], "deny")
        self.assertIn("```json:alternatives", result["reason"])
        self.assertIn("REMEDIATION DIRECTIVE", result["reason"])
        self.assertIn("(Recommended) Stash uncommitted changes to preserve work", result["reason"])
        self.assertIn("git stash -u", result["reason"])
        self.assertEqual(len(result["alternatives"]), 2)

    def test_ask_with_alternatives_includes_original_action(self):
        provider = MockProvider({
            "decision": "ask",
            "reason": "Force-push rewrites remote history other collaborators may have pulled.",
            "alternatives": [
                {"label": "Use a safer force-with-lease push instead", "command": "git push --force-with-lease origin main"},
                {"label": "Proceed with the force push as originally requested", "command": "git push --force origin main"}
            ]
        })
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})

        result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "git push --force origin main"})
        # "ask" with alternatives is routed to "deny" so the agent receives the directive directly, and logged as ASK
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["audit_decision"], "ASK")
        self.assertIn("```json:alternatives", result["reason"])
        self.assertIn("REMEDIATION DIRECTIVE", result["reason"])
        self.assertIn("git push --force origin main", result["reason"])
        self.assertEqual(len(result["alternatives"]), 2)

    def test_alternatives_string_list_and_deduplication(self):
        provider = MockProvider({
            "decision": "deny",
            "reason": "Branch deletion blocked.",
            "alternatives": [
                "(Recommended) Stash changes -> git stash",
                "Inspect diff -> git diff"
            ]
        })
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})

        result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "git branch -D feature"})
        self.assertEqual(result["decision"], "deny")
        self.assertIn("```json:alternatives", result["reason"])
        # Should not have double (Recommended) (Recommended)
        self.assertNotIn("(Recommended) (Recommended)", result["reason"])
        self.assertIn('(Recommended) Stash changes', result["reason"])
        self.assertIn("git stash", result["reason"])

    def test_disabled_remediation_directives_config(self):
        provider = MockProvider({
            "decision": "deny",
            "reason": "Direct delete blocked.",
            "alternatives": [{"label": "Trash instead", "command": "trash foo.txt"}]
        })
        evaluator = SecurityEvaluator(provider, {"enable_remediation_directives": False, "fast_path_read_only": True})

        result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "rm foo.txt"})
        self.assertEqual(result["decision"], "deny")
        self.assertNotIn("REMEDIATION DIRECTIVE", result["reason"])
        self.assertNotIn("```json:alternatives", result["reason"])

    def test_deny_without_alternatives_key_degrades_gracefully(self):
        provider = MockProvider({"decision": "deny", "reason": "Destructive disk wipe blocked."})
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})

        result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "rm -rf /"})
        self.assertEqual(result["decision"], "deny")
        self.assertNotIn("REMEDIATION DIRECTIVE", result["reason"])
        self.assertEqual(result["alternatives"], [])

    def test_provider_offline_fallback(self):
        # Provider returns None (offline / timeout)
        provider = MockProvider(None)
        evaluator = SecurityEvaluator(provider, {"fallback_action": "ask", "fast_path_read_only": False})
        
        result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "npm run build"})
        self.assertIn(result["decision"], ("ask", "force_ask"))

    def test_provider_offline_source_tag(self):
        # Provider returns None (offline / timeout)
        provider = MockProvider(None)
        evaluator = SecurityEvaluator(provider, {"fallback_action": "ask", "fast_path_read_only": False})

        result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "npm run build"})
        self.assertIn(result["decision"], ("ask", "force_ask"))
        self.assertEqual(result.get("source"), "OFFLINE")

    def test_tier_from_gb(self):
        from auto_permissions.hardware import _tier_from_gb
        self.assertEqual(_tier_from_gb(3.5), "4gb")
        self.assertEqual(_tier_from_gb(5.0), "6gb")
        self.assertEqual(_tier_from_gb(8.0), "8gb")
        self.assertEqual(_tier_from_gb(12.0), "12gb")
        self.assertEqual(_tier_from_gb(16.0), "16gb")
        self.assertEqual(_tier_from_gb(24.0), "24gb")

    def test_extract_project_name_and_summarize(self):
        from auto_permissions.monitor import _extract_project_name, _summarize_args
        ctx = {"workspace_paths": ["/home/user/projects/my-app"]}
        self.assertEqual(_extract_project_name(ctx, {}), "my-app")
        self.assertEqual(_extract_project_name(None, {"Cwd": "C:\\projects\\backend"}), "backend")
        self.assertEqual(_summarize_args("run_command", {"CommandLine": "git status"}), "git status")

    def test_trim_audit_log_retention_and_max_lines(self):
        import time
        import json
        import tempfile
        from pathlib import Path
        from auto_permissions.monitor import trim_audit_log

        with tempfile.TemporaryDirectory() as tmpdir:
            test_audit = Path(tmpdir) / "audit.jsonl"
            now = time.time()
            old_ts = now - (20 * 86400) # 20 days old (should be pruned with 14-day retention)
            recent_ts = now - 100 # recent

            entries = [
                {"timestamp": old_ts, "tool": "old_tool_1"},
                {"timestamp": old_ts, "tool": "old_tool_2"},
                {"timestamp": recent_ts, "tool": "recent_1"},
                {"timestamp": recent_ts, "tool": "recent_2"},
                {"timestamp": recent_ts, "tool": "recent_3"},
            ]
            with open(test_audit, "w", encoding="utf-8") as f:
                for entry in entries:
                    f.write(json.dumps(entry) + "\n")

            # Prune entries older than 14 days
            pruned = trim_audit_log(retention_days=14, max_lines=10, audit_path=test_audit)
            self.assertEqual(pruned, 2)

            with open(test_audit, "r", encoding="utf-8") as f:
                lines = [json.loads(l) for l in f if l.strip()]
            self.assertEqual(len(lines), 3)
            self.assertEqual(lines[0]["tool"], "recent_1")

            # Test max_lines cap
            pruned_cap = trim_audit_log(retention_days=14, max_lines=2, audit_path=test_audit)
            self.assertEqual(pruned_cap, 1)
            with open(test_audit, "r", encoding="utf-8") as f:
                remaining = [json.loads(l) for l in f if l.strip()]
            self.assertEqual(len(remaining), 2)
            self.assertEqual(remaining[0]["tool"], "recent_2")
            self.assertEqual(remaining[1]["tool"], "recent_3")

    def test_user_approval_from_ask_question_transcript(self):
        import tempfile
        import json
        from pathlib import Path
        provider = MockProvider({"decision": "deny", "reason": "Destructive action blocked"})
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})

        with tempfile.TemporaryDirectory() as tmpdir:
            transcript_file = Path(tmpdir) / "transcript.jsonl"

            # Case 1: Matching approval
            steps = [
                {
                    "step_index": 10,
                    "type": "PLANNER_RESPONSE",
                    "tool_calls": [{
                        "name": "ask_question",
                        "args": {
                            "questions": [{
                                "options": [
                                    "Discard all changes (git checkout -- .)",
                                    "Stash changes (git stash)"
                                ]
                            }]
                        }
                    }]
                },
                {
                    "step_index": 11,
                    "type": "GENERIC",
                    "content": "A1: Discard all changes (git checkout -- .)"
                }
            ]
            with open(transcript_file, "w", encoding="utf-8") as f:
                for s in steps:
                    f.write(json.dumps(s) + "\n")

            ctx = {"transcript_path": str(transcript_file)}
            result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "git checkout -- ."}, context=ctx)
            self.assertEqual(result["decision"], "allow")
            self.assertEqual(result["source"], "USER-APPROVED")
            self.assertIn("Verified user authorization", result["reason"])

            # Case 2: Mismatch (user approved git checkout -- ., agent tries git clean -fd)
            mismatch_result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "git clean -fd"}, context=ctx)
            self.assertEqual(mismatch_result["decision"], "deny")
            self.assertNotEqual(mismatch_result.get("source"), "USER-APPROVED")

            # Case 3: Intervening execution (single-use / one-shot invalidated)
            steps.append({
                "step_index": 12,
                "type": "GENERIC",
                "content": "intervening tool finished"
            })
            with open(transcript_file, "w", encoding="utf-8") as f:
                for s in steps:
                    f.write(json.dumps(s) + "\n")

            subsequent_result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "git checkout -- ."}, context=ctx)
            self.assertEqual(subsequent_result["decision"], "deny")
            self.assertNotEqual(subsequent_result.get("source"), "USER-APPROVED")

            # Case 4: Arrow syntax option ("Preview files" -> git status -s)
            arrow_steps = [
                {
                    "step_index": 20,
                    "type": "PLANNER_RESPONSE",
                    "tool_calls": [{
                        "name": "ask_question",
                        "args": {
                            "questions": [{
                                "options": [
                                    "- \"Preview files\" -> git status -s",
                                    "- \"Clean files\" -> git clean -fd"
                                ]
                            }]
                        }
                    }]
                },
                {
                    "step_index": 21,
                    "type": "GENERIC",
                    "content": "A1: - \"Clean files\" -> git clean -fd"
                }
            ]
            with open(transcript_file, "w", encoding="utf-8") as f:
                for s in arrow_steps:
                    f.write(json.dumps(s) + "\n")

            arrow_result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "git clean -fd"}, context=ctx)
            self.assertEqual(arrow_result["decision"], "allow")
            self.assertEqual(arrow_result["source"], "USER-APPROVED")

            # Case 5: Custom write-in command
            writein_steps = [
                {
                    "step_index": 30,
                    "type": "PLANNER_RESPONSE",
                    "tool_calls": [{"name": "ask_question", "args": {}}]
                },
                {
                    "step_index": 31,
                    "type": "GENERIC",
                    "content": "A1: git restore --staged src/app.py"
                }
            ]
            with open(transcript_file, "w", encoding="utf-8") as f:
                for s in writein_steps:
                    f.write(json.dumps(s) + "\n")

            writein_result = evaluator.evaluate_tool_call("run_command", {"CommandLine": "git restore --staged src/app.py"}, context=ctx)
            self.assertEqual(writein_result["decision"], "allow")
            self.assertEqual(writein_result["source"], "USER-APPROVED")
            self.assertEqual(writein_result["permission_overrides"], ["command(git restore --staged src/app.py)"])

    def test_mcp_read_only_fast_path(self):
        provider = MockProvider()
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})

        # 1. Generic dispatch call_mcp_tool get_issue
        result = evaluator.evaluate_tool_call("call_mcp_tool", {
            "ServerName": "linear-mcp-server",
            "ToolName": "get_issue",
            "Arguments": {"id": "HD-120"}
        })
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["source"], "FAST-PATH")
        self.assertIn("linear-mcp-server/get_issue", result["reason"])
        self.assertIn("mcp(linear-mcp-server/get_issue)", result["permission_overrides"])

        # 2. list_teams query
        result_list = evaluator.evaluate_tool_call("call_mcp_tool", {
            "ServerName": "linear-mcp-server",
            "ToolName": "list_teams",
            "Arguments": {}
        })
        self.assertEqual(result_list["decision"], "allow")
        self.assertEqual(result_list["source"], "FAST-PATH")
        self.assertIn("mcp(linear-mcp-server/list_teams)", result_list["permission_overrides"])

        # 3. Direct eager MCP tool naming (mcp_linear_get_issue)
        result_eager = evaluator.evaluate_tool_call("mcp_linear_get_issue", {"id": "HD-120"})
        self.assertEqual(result_eager["decision"], "allow")
        self.assertEqual(result_eager["source"], "FAST-PATH")
        self.assertIn("mcp(linear/get_issue)", result_eager["permission_overrides"])

    def test_mcp_mutating_tools_require_llm_evaluation(self):
        # When model denies a destructive MCP operation
        provider_deny = MockProvider({
            "decision": "deny",
            "reason": "Deleting issue HD-120 is destructive."
        })
        evaluator_deny = SecurityEvaluator(provider_deny, {"fast_path_read_only": True})

        result = evaluator_deny.evaluate_tool_call("call_mcp_tool", {
            "ServerName": "linear-mcp-server",
            "ToolName": "delete_issue",
            "Arguments": {"id": "HD-120"}
        })
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["source"], "LOCAL")
        # No permission overrides must ever be emitted on deny!
        self.assertEqual(result.get("permission_overrides"), [])

        # When model allows a valid MCP modification (e.g. save_issue)
        provider_allow = MockProvider({
            "decision": "allow",
            "reason": "Updating issue title is safe."
        })
        evaluator_allow = SecurityEvaluator(provider_allow, {"fast_path_read_only": True})

        result_allow = evaluator_allow.evaluate_tool_call("call_mcp_tool", {
            "ServerName": "linear-mcp-server",
            "ToolName": "save_issue",
            "Arguments": {"id": "HD-120", "title": "Refactor auth"}
        })
        self.assertEqual(result_allow["decision"], "allow")
        self.assertEqual(result_allow["source"], "LOCAL")
        # Strictly scoped override for save_issue (never blanket server grant)
        self.assertIn("mcp(linear-mcp-server/save_issue)", result_allow["permission_overrides"])
        self.assertNotIn("mcp(linear-mcp-server)", result_allow["permission_overrides"])

    def test_compute_permission_overrides_helpers(self):
        # 1. MCP - must be strictly scoped to tool, no blanket server grant
        mcp_overrides = compute_permission_overrides("call_mcp_tool", {
            "ServerName": "linear-mcp-server",
            "ToolName": "get_issue"
        })
        self.assertIn("mcp(linear-mcp-server/get_issue)", mcp_overrides)
        self.assertNotIn("mcp(linear-mcp-server)", mcp_overrides)

        # 2. URL
        url_overrides = compute_permission_overrides("read_url_content", {
            "Url": "https://antigravity.google/docs/hooks"
        })
        self.assertIn("read_url(antigravity.google)", url_overrides)
        self.assertIn("url(https://antigravity.google/docs/hooks)", url_overrides)

        # 3. Command
        cmd_overrides = compute_permission_overrides("run_command", {
            "CommandLine": "npm test -- --coverage"
        })
        self.assertEqual(cmd_overrides, ["command(npm test -- --coverage)"])

        # 4. File edit
        file_overrides = compute_permission_overrides("write_to_file", {
            "TargetFile": "src/app.py"
        })
        self.assertEqual(file_overrides, ["write_file(src/app.py)"])

        # 5. Empty or non-dict args
        self.assertEqual(compute_permission_overrides("view_file", {}), [])
        self.assertEqual(compute_permission_overrides("call_mcp_tool", None), [])

        # 6. Malicious identifiers with syntax breakout characters
        malicious_overrides = compute_permission_overrides("call_mcp_tool", {
            "ServerName": "linear;rm -rf /",
            "ToolName": "save) or (*"
        })
        self.assertEqual(malicious_overrides, [])

        # 7. Malformed URL should not crash
        bad_url_overrides = compute_permission_overrides("read_url_content", {
            "Url": "http://[invalid-ipv6"
        })
        self.assertEqual(bad_url_overrides, [])

    def test_evaluator_robustness_and_security_edge_cases(self):
        provider = MockProvider({"decision": "allow", "reason": "ok"})
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})

        # 1. Null / malformed inputs
        null_res = evaluator.evaluate_tool_call(None, None)
        self.assertIn(null_res["decision"], ("ask", "force_ask"))

        # 2. Compound MCP tool names containing mutating verbs (must NOT fast-path)
        compound_call = {
            "ServerName": "github-mcp",
            "ToolName": "get_and_delete_repo",
            "Arguments": {"repo": "test"}
        }
        # In our MockProvider, if it hits the provider, decision is "allow" but source is LOCAL, NOT FAST-PATH
        compound_res = evaluator.evaluate_tool_call("call_mcp_tool", compound_call)
        self.assertNotEqual(compound_res["source"], "FAST-PATH")
        self.assertEqual(compound_res["source"], "LOCAL")

        # Legitimate read-only fast-path
        safe_read_res = evaluator.evaluate_tool_call("call_mcp_tool", {
            "ServerName": "github-mcp",
            "ToolName": "get_issue",
            "Arguments": {"id": 123}
        })
        self.assertEqual(safe_read_res["source"], "FAST-PATH")

        # Empty ServerName or ToolName must not fast path
        empty_server_res = evaluator.evaluate_tool_call("call_mcp_tool", {
            "ServerName": "",
            "ToolName": "get_issue"
        })
        self.assertNotEqual(empty_server_res["source"], "FAST-PATH")

    def test_user_approval_negation_and_empty_target(self):
        import tempfile
        import json
        from pathlib import Path
        provider = MockProvider({"decision": "deny", "reason": "blocked"})
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})

        with tempfile.TemporaryDirectory() as tmpdir:
            transcript_file = Path(tmpdir) / "transcript.jsonl"

            # Case: User explicitly said NO or DON'T in transcript
            steps = [
                {
                    "step_index": 10,
                    "type": "PLANNER_RESPONSE",
                    "tool_calls": [{
                        "name": "ask_question",
                        "args": {"questions": [{"options": ["Run git push --force", "Cancel"]}]}
                    }]
                },
                {
                    "step_index": 11,
                    "type": "USER_INPUT",
                    "content": "No, do not run git push --force under any circumstances!"
                }
            ]
            with open(transcript_file, "w", encoding="utf-8") as f:
                for s in steps:
                    f.write(json.dumps(s) + "\n")

            ctx = {"transcript_path": str(transcript_file)}
            res = evaluator.evaluate_tool_call("run_command", {"CommandLine": "git push --force"}, context=ctx)
            self.assertEqual(res["decision"], "deny")
            self.assertNotEqual(res.get("source"), "USER-APPROVED")

            # Case: Empty TargetFile must not match
            res_file = evaluator.evaluate_tool_call("write_to_file", {"TargetFile": ""}, context=ctx)
            self.assertEqual(res_file["decision"], "deny")
            self.assertNotEqual(res_file.get("source"), "USER-APPROVED")

    def test_workspace_trust_gate(self):
        provider = MockProvider({"decision": "allow", "reason": "ok"})
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})

        with tempfile.TemporaryDirectory() as tmp:
            fake_ws = str((Path(tmp) / "untrusted_repo").resolve())
            ctx = {"workspace_paths": [fake_ws]}

            # 1. Untrusted workspace -> triggers WORKSPACE-TRUST ask with remediation directive
            with patch("auto_permissions.evaluator._get_trusted_workspaces", return_value=set()), \
                 patch("auto_permissions.evaluator._get_declined_workspaces", return_value=set()):
                res = evaluator.evaluate_tool_call("run_command", {"CommandLine": "npm test"}, context=ctx)
                self.assertEqual(res["decision"], "ask")
                self.assertEqual(res.get("source"), "WORKSPACE-TRUST")
                self.assertIn("trust-ide", res["reason"])
                self.assertIn("REMEDIATION DIRECTIVE", res["reason"])

            # 2. Trusted workspace -> normal evaluation (does not prompt workspace trust)
            with patch("auto_permissions.evaluator._get_trusted_workspaces", return_value={fake_ws}), \
                 patch("auto_permissions.evaluator._get_declined_workspaces", return_value=set()):
                res = evaluator.evaluate_tool_call("run_command", {"CommandLine": "npm test"}, context=ctx)
                self.assertNotEqual(res.get("source"), "WORKSPACE-TRUST")

            # 3. Declined workspace -> does not prompt for workspace trust
            with patch("auto_permissions.evaluator._get_trusted_workspaces", return_value=set()), \
                 patch("auto_permissions.evaluator._get_declined_workspaces", return_value={fake_ws}):
                res = evaluator.evaluate_tool_call("run_command", {"CommandLine": "npm test"}, context=ctx)
                self.assertNotEqual(res.get("source"), "WORKSPACE-TRUST")

            # 4. trust-ide command itself fast-paths as ALLOW even in untrusted workspace
            with patch("auto_permissions.evaluator._get_trusted_workspaces", return_value=set()), \
                 patch("auto_permissions.evaluator._get_declined_workspaces", return_value=set()):
                res_trust = evaluator.evaluate_tool_call(
                    "run_command",
                    {"CommandLine": f"python -m auto_permissions.cli trust-ide --workspace \"{fake_ws}\""},
                    context=ctx
                )
                self.assertEqual(res_trust["decision"], "allow")
                self.assertEqual(res_trust.get("source"), "FAST-PATH")


if __name__ == "__main__":
    unittest.main()


