"""Ollama provider connector using /api/chat with discrete system and user roles."""
import json
import urllib.request
from typing import Any, Dict, Optional

from .base import BaseProvider, parse_json_safely

class OllamaProvider(BaseProvider):
    """Connects to Ollama using /api/chat with discrete system and user roles."""
    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:11434/api/chat",
        model: str = "qwen3.5:9b",
        num_ctx: int = 4096,
        temperature: float = 0.0,
        timeout: float = 3.5,
    ):
        self.endpoint = endpoint.replace("localhost", "127.0.0.1")
        if self.endpoint.endswith("/api/generate"):
            self.endpoint = self.endpoint.replace("/api/generate", "/api/chat")
        self.model = model
        self.num_ctx = num_ctx
        self.temperature = temperature
        self.timeout = timeout

        self._cached_model_id: Optional[str] = None

    def _resolve_model_id(self) -> str:
        """Resolve Ollama model tag; queries /api/tags if model is 'auto' or 'default'."""
        if self.model and self.model not in ("auto", "default"):
            return self.model

        if self._cached_model_id:
            return self._cached_model_id

        tags_endpoint = self.endpoint.replace("/api/chat", "/api/tags")
        req = urllib.request.Request(tags_endpoint, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
                if models:
                    # Preference order for Auto Permissions Mode
                    for pref in ("qwen3.5:9b", "qwen2.5:7b", "gemma4:e4b", "gemma4:12b", "gemma4:e2b"):
                        for m in models:
                            if m == pref or m.startswith(pref.split(":")[0]):
                                self._cached_model_id = m
                                return m
                    self._cached_model_id = models[0]
                    return models[0]
        except Exception:
            pass

        return "qwen3.5:9b"

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        resolved_model = self._resolve_model_id()
        payload = {
            "model": resolved_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "format": "json",
            "stream": False,
            "options": {
                "num_ctx": self.num_ctx,
                "num_predict": 160,
                "temperature": self.temperature,
            }
        }
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                content = data.get("message", {}).get("content") or data.get("response", "")
                return parse_json_safely(content)
        except Exception:
            return None
