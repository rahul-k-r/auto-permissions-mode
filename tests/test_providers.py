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
    AnthropicProvider,
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
    def setUp(self):
        TieredProvider._circuit_breaker_file().unlink(missing_ok=True)

    def tearDown(self):
        TieredProvider._circuit_breaker_file().unlink(missing_ok=True)
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

    def test_tiered_provider_circuit_breaker(self):
        primary = MockSimpleProvider(None)
        secondary = MockSimpleProvider({"decision": "allow", "reason": "Cloud Gemini approved."})
        tiered = TieredProvider(primary, secondary, total_deadline=11.0)

        # First run: primary fails, secondary runs, trips circuit breaker
        self.assertFalse(tiered.is_local_in_cooldown())
        res1 = tiered.evaluate("system", "prompt")
        self.assertEqual(res1["decision"], "allow")
        self.assertTrue(tiered.is_local_in_cooldown())

        # Second run: local is skipped via circuit breaker directly to cloud
        res2 = tiered.evaluate("system", "prompt")
        self.assertEqual(res2["decision"], "allow")

    @patch("urllib.request.urlopen")
    def test_ollama_auto_model_resolution(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "models": [
                {"name": "mistral:latest"},
                {"name": "qwen3.5:9b"}
            ]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        ollama = OllamaProvider(model="auto")
        resolved = ollama._resolve_model_id()
        self.assertEqual(resolved, "qwen3.5:9b")

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

    @patch("urllib.request.urlopen")
    def test_anthropic_provider_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "content": [{"text": "{\"decision\": \"allow\", \"reason\": \"Claude Haiku approved.\"}"}]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        provider = AnthropicProvider(api_key="sk-ant-test", model="claude-3-5-haiku-latest")
        res = provider.evaluate("system", "prompt")
        self.assertIsNotNone(res)
        self.assertEqual(res["decision"], "allow")
        self.assertEqual(res["reason"], "Claude Haiku approved.")

    @patch("urllib.request.urlopen")
    def test_openai_cloud_provider_auth(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "choices": [{"message": {"content": "{\"decision\": \"allow\", \"reason\": \"GPT-4o-mini approved.\"}"}}]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        provider = OpenAICompatibleProvider(
            endpoint="https://api.openai.com/v1/chat/completions",
            model="gpt-4o-mini",
            api_key="sk-test-key"
        )
        res = provider.evaluate("system", "prompt")
        self.assertIsNotNone(res)
        self.assertEqual(res["decision"], "allow")
        self.assertEqual(res["reason"], "GPT-4o-mini approved.")

    def test_get_provider_tiered_wiring(self):
        # 1. Gemini failover
        cfg_gemini = {
            "provider": "llamacpp",
            "endpoint": "http://127.0.0.1:9931/v1/chat/completions",
            "model": "auto",
            "fallback_to_cloud": True,
            "cloud_provider": "gemini",
            "cloud_model": "gemini-flash-lite-latest",
        }
        prov1 = get_provider(cfg_gemini)
        self.assertIsInstance(prov1, TieredProvider)
        self.assertIsInstance(prov1.primary, OpenAICompatibleProvider)
        self.assertIsInstance(prov1.secondary, GeminiProvider)

        # 2. Anthropic failover
        cfg_claude = {
            "provider": "llamacpp",
            "endpoint": "http://127.0.0.1:9931/v1/chat/completions",
            "model": "auto",
            "fallback_to_cloud": True,
            "cloud_provider": "anthropic",
            "cloud_model": "claude-3-5-haiku-latest",
        }
        prov2 = get_provider(cfg_claude)
        self.assertIsInstance(prov2, TieredProvider)
        self.assertIsInstance(prov2.secondary, AnthropicProvider)

        # 3. OpenAI failover
        cfg_openai = {
            "provider": "llamacpp",
            "endpoint": "http://127.0.0.1:9931/v1/chat/completions",
            "model": "auto",
            "fallback_to_cloud": True,
            "cloud_provider": "openai",
            "cloud_model": "gpt-4o-mini",
        }
        prov3 = get_provider(cfg_openai)
        self.assertIsInstance(prov3, TieredProvider)
        self.assertIsInstance(prov3.secondary, OpenAICompatibleProvider)
        self.assertEqual(prov3.secondary.endpoint, "https://api.openai.com/v1/chat/completions")

if __name__ == "__main__":
    unittest.main()
