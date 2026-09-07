"""Unit tests for the PreToolUse hook entrypoint (auto_permissions.hook_handler)."""

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from auto_permissions import hook_handler


class FakeProvider:
    """Provider stub that fails the test if the LLM is ever actually invoked."""

    def evaluate(self, system_prompt, prompt):
        raise AssertionError("provider.evaluate() should not be called for a fast-path tool")


def run_hook_with_stdin(payload_text: str) -> dict:
    stdout = io.StringIO()
    with patch("sys.stdin", io.StringIO(payload_text)), \
         patch(
             "auto_permissions.hook_handler.load_config",
             return_value={"fallback_action": "force_ask", "fast_path_read_only": True},
         ), \
         patch("auto_permissions.hook_handler.get_provider", return_value=FakeProvider()), \
         patch("auto_permissions.monitor.record_audit_event"), \
         redirect_stdout(stdout):
        hook_handler.run_hook()
    return json.loads(stdout.getvalue().strip())


class TestRunHook(unittest.TestCase):
    def test_empty_stdin_defers_to_user(self):
        result = run_hook_with_stdin("")
        self.assertEqual(result["decision"], "force_ask")
        self.assertIn("No input received", result["reason"])

    def test_malformed_json_falls_back_to_force_ask(self):
        result = run_hook_with_stdin("not valid json{{{")
        self.assertEqual(result["decision"], "force_ask")
        self.assertIn("Hook evaluation error", result["reason"])

    def test_fast_path_read_only_tool_allows_without_provider_call(self):
        payload = json.dumps({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "README.md"}},
            "stepIdx": 1,
            "conversationId": "test-run",
        })
        result = run_hook_with_stdin(payload)
        self.assertEqual(result["decision"], "allow")
        self.assertNotIn("permissionOverrides", result)

    def test_allowed_mcp_call_includes_permission_overrides(self):
        payload = json.dumps({
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {"ServerName": "linear", "ToolName": "get_issue"},
            },
        })
        result = run_hook_with_stdin(payload)
        self.assertEqual(result["decision"], "allow")
        self.assertIn("permissionOverrides", result)
        self.assertIn("mcp(linear/get_issue)", result["permissionOverrides"])

    def test_missing_tool_call_name_defers_to_user(self):
        payload = json.dumps({"toolCall": {"args": {}}})
        result = run_hook_with_stdin(payload)
        self.assertEqual(result["decision"], "force_ask")


if __name__ == "__main__":
    unittest.main()
