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

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        payload = {
            "model": self.model,
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
