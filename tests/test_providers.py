"""Unit tests for Auto Permissions Provider connectors and Tiered failover."""
import json
import unittest
from unittest.mock import patch, MagicMock
from auto_permissions.providers import (
    parse_json_safely,
    BaseProvider,
    OpenAICompatibleProvider,
    OllamaProvider,
    GeminiProvider,
    TieredProvider,
    get_provider,
)

class MockSimpleProvider(BaseProvider):
    def __init__(self, response=None, delay=0.0):
        self.response = response
        self.delay = delay

    def evaluate(self, system_prompt: str, prompt: str):
        return self.response

class TestProviders(unittest.TestCase):
    def test_parse_json_safely_thinking_models(self):
        # 1. Closed thinking block
        raw = "<think>\nThinking through the risk...\n</think>\n{\"decision\": \"allow\", \"reason\": \"Safe build.\"}"
        res = parse_json_safely(raw)
        self.assertIsNotNone(res)
        self.assertEqual(res.get("decision"), "allow")

        # 2. Unclosed thinking block
        raw_unclosed = "Some prefix <think>still thinking... {\"decision\": \"deny\"}"
        res2 = parse_json_safely(raw_unclosed)
        self.assertIsNone(res2)

        # 3. Markdown wrapped json
        raw_md = "```json\n{\"decision\": \"force_ask\", \"reason\": \"High impact\"}\n```"
        res3 = parse_json_safely(raw_md)
        self.assertIsNotNone(res3)
        self.assertEqual(res3.get("decision"), "force_ask")

    def test_tiered_provider_local_first_success(self):
        primary = MockSimpleProvider({"decision": "allow", "reason": "Local Qwen 3.5 approved."})
        secondary = MockSimpleProvider({"decision": "deny", "reason": "Cloud Gemini should not be called."})
        tiered = TieredProvider(primary, secondary, total_deadline=11.0)

        res = tiered.evaluate("system", "prompt")
        self.assertEqual(res["decision"], "allow")
        self.assertEqual(res["reason"], "Local Qwen 3.5 approved.")

    def test_tiered_provider_cloud_failover(self):
        # Primary is offline (returns None)
        primary = MockSimpleProvider(None)
        secondary = MockSimpleProvider({"decision": "ask", "reason": "Cloud Gemini evaluated."})
        tiered = TieredProvider(primary, secondary, total_deadline=11.0)

        res = tiered.evaluate("system", "prompt")
        self.assertEqual(res["decision"], "ask")
        self.assertEqual(res["reason"], "Cloud Gemini evaluated.")

    def test_tiered_provider_all_offline_escalates_to_force_ask(self):
        # Both primary and secondary are offline
        primary = MockSimpleProvider(None)
        secondary = MockSimpleProvider(None)
        tiered = TieredProvider(primary, secondary, total_deadline=11.0)

        res = tiered.evaluate("system", "prompt")
        self.assertEqual(res["decision"], "force_ask")
        self.assertIn("unavailable", res["reason"].lower())

    @patch("urllib.request.urlopen")
    def test_gemini_provider_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "candidates": [{
                "content": {
                    "parts": [{"text": "{\"decision\": \"allow\", \"reason\": \"Gemini verified safe.\"}"}]
                }
            }]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        provider = GeminiProvider(api_key="fake-key-123", model="gemini-flash-lite-latest")
        res = provider.evaluate("system", "prompt")
        self.assertIsNotNone(res)
        self.assertEqual(res["decision"], "allow")
        self.assertEqual(res["reason"], "Gemini verified safe.")

    def test_get_provider_tiered_wiring(self):
        cfg = {
            "provider": "llamacpp",
            "endpoint": "http://127.0.0.1:9931/v1/chat/completions",
            "model": "auto",
            "fallback_to_cloud": True,
            "cloud_model": "gemini-flash-lite-latest",
        }
        provider = get_provider(cfg)
        self.assertIsInstance(provider, TieredProvider)
        self.assertIsInstance(provider.primary, OpenAICompatibleProvider)
        self.assertIsInstance(provider.secondary, GeminiProvider)

if __name__ == "__main__":
    unittest.main()
