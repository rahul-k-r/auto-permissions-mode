"""Unit tests for Auto Permissions Security Evaluator."""

import unittest
from typing import Optional, Dict, Any
from auto_permissions.providers import BaseProvider
from auto_permissions.evaluator import SecurityEvaluator

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

if __name__ == "__main__":
    unittest.main()

