"""OpenAI-compatible connector for llama.cpp / llama-server, vLLM, and LM Studio."""
import json
import time
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from .base import BaseProvider, parse_json_safely

class OpenAICompatibleProvider(BaseProvider):
    """Connects to OpenAI-compatible endpoints with auto model resolution, remote cloud auth, and dual-port fallback."""
    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:9931/v1/chat/completions",
        model: str = "auto",
        api_key: Optional[str] = None,
        temperature: float = 0.0,
        timeout: float = 3.5,
    ):
        # Normalize localhost to 127.0.0.1 to avoid Windows IPv6/NetBIOS 1-2.5s DNS delays
        self.endpoint = endpoint.replace("localhost", "127.0.0.1")
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.timeout = timeout
        self._cached_model_id: Optional[str] = None

    def _resolve_model_id(self) -> str:
        """Resolve model name; auto-detects from /v1/models if model is 'auto' or 'default'."""
        is_remote = self.endpoint.startswith("https://")

        if self.model and self.model not in ("auto", "default"):
            return self.model

        if is_remote and "api.openai.com" in self.endpoint:
            # OpenAI's own /v1/models list isn't a useful "pick a chat model" source.
            # Other remote endpoints below (Groq, OpenRouter, custom relays) expose an
            # OpenAI-compatible /v1/models we CAN auto-detect from, so they fall
            # through instead of also being guessed as "gpt-4o-mini".
            return "gpt-4o-mini"

        if self._cached_model_id:
            return self._cached_model_id

        # Check cross-process temp cache file with 60s TTL (local endpoints only —
        # a remote cloud model shouldn't be cached under this shared local-only key)
        cache_file = Path(tempfile.gettempdir()) / "auto_permissions_model_llama.json"
        now = time.time()
        if not is_remote and cache_file.is_file():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)
                if now - cache_data.get("cached_at", 0) < 60:
                    model_id = cache_data.get("model_id")
                    if model_id:
                        self._cached_model_id = model_id
                        return model_id
            except Exception:
                pass

        # Query /v1/models with strict 1.0s timeout (local: try primary endpoint
        # first, then legacy 8080; remote: query the configured endpoint directly,
        # authenticated, since Groq/OpenRouter require a key even for /v1/models)
        candidate_endpoints = [self.endpoint]
        if not is_remote and ":9931" in self.endpoint:
            candidate_endpoints.append(self.endpoint.replace(":9931", ":8080"))

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        for ep in candidate_endpoints:
            models_endpoint = ep.rsplit("/chat/completions", 1)[0] + "/models"
            try:
                req = urllib.request.Request(models_endpoint, headers=headers)
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    model_list = data.get("data") or data.get("models") or []
                    if model_list and isinstance(model_list, list):
                        detected = model_list[0].get("id") or model_list[0].get("name") or "default"
                        self._cached_model_id = detected
                        if not is_remote:
                            self.endpoint = ep  # Switch to active port
                            try:
                                with open(cache_file, "w", encoding="utf-8") as f:
                                    json.dump({"model_id": detected, "cached_at": now}, f)
                            except Exception:
                                pass
                        return detected
            except Exception:
                continue

        return "gpt-4o-mini" if is_remote else "default"

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        resolved_model = self._resolve_model_id()
        payload = {
            "model": resolved_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 300,
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
            "chat_template_kwargs": {"enable_thinking": False},
            "reasoning_effort": "none",
        }
        data = json.dumps(payload).encode("utf-8")

        endpoints_to_try = [self.endpoint]
        if not self.endpoint.startswith("https://"):
            if ":9931" in self.endpoint and self.endpoint.replace(":9931", ":8080") not in endpoints_to_try:
                endpoints_to_try.append(self.endpoint.replace(":9931", ":8080"))

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        for ep in endpoints_to_try:
            req = urllib.request.Request(ep, data=data, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    choices = resp_data.get("choices", [])
                    if choices:
                        content = choices[0].get("message", {}).get("content", "")
                        parsed = parse_json_safely(content)
                        if parsed:
                            self.endpoint = ep
                            return parsed
            except Exception:
                continue

        return None
