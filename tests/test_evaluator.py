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

    def test_antigravity_artifact_whitelist(self):
        provider = MockProvider(None)  # Provider is offline, but fast path handles it
        evaluator = SecurityEvaluator(provider, {"fast_path_read_only": True})

        context = {
            "artifact_dir": "C:\\Users\\rahul\\.gemini\\antigravity\\brain\\e12e4eb8-70c7-4f1f-aa37-81ce65eb678e"
        }
        target_file = "C:\\Users\\rahul\\.gemini\\antigravity\\brain\\e12e4eb8-70c7-4f1f-aa37-81ce65eb678e\\implementation_plan.md"
        result = evaluator.evaluate_tool_call(
            "write_to_file",
            {"TargetFile": target_file, "CodeContent": "# Plan"},
            context=context
        )
        self.assertEqual(result["decision"], "allow")
        self.assertIn("Safe Antigravity brain artifact", result["reason"])

if __name__ == "__main__":
    unittest.main()
