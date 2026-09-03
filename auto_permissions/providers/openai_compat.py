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
        """Resolve model name; auto-detects from /v1/models if local model is 'auto' or 'default'."""
        if self.endpoint.startswith("https://"):
            # Remote cloud endpoint (OpenAI, OpenRouter, Groq)
            return self.model if self.model not in ("auto", "default") else "gpt-4o-mini"

        if self.model and self.model not in ("auto", "default"):
            return self.model

        if self._cached_model_id:
            return self._cached_model_id

        # Check cross-process temp cache file with 60s TTL
        cache_file = Path(tempfile.gettempdir()) / "auto_permissions_model_llama.json"
        now = time.time()
        if cache_file.is_file():
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

        # Query /v1/models with strict 1.0s timeout (try primary endpoint first, then legacy 8080)
        candidate_endpoints = [self.endpoint]
        if ":9931" in self.endpoint:
            candidate_endpoints.append(self.endpoint.replace(":9931", ":8080"))

        for ep in candidate_endpoints:
            models_endpoint = ep.rsplit("/chat/completions", 1)[0] + "/models"
            try:
                req = urllib.request.Request(models_endpoint, headers={"Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    model_list = data.get("data") or data.get("models") or []
                    if model_list and isinstance(model_list, list):
                        detected = model_list[0].get("id") or model_list[0].get("name") or "default"
                        self._cached_model_id = detected
                        self.endpoint = ep  # Switch to active port
                        try:
                            with open(cache_file, "w", encoding="utf-8") as f:
                                json.dump({"model_id": detected, "cached_at": now}, f)
                        except Exception:
                            pass
                        return detected
            except Exception:
                continue

        return "default"

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        resolved_model = self._resolve_model_id()
        payload = {
            "model": resolved_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
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
