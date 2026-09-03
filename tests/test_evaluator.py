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

if __name__ == "__main__":
    unittest.main()
