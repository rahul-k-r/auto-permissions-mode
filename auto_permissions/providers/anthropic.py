"""Anthropic Claude REST API connector with support for Haiku 4.5 and 3.5."""
import os
import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, Optional

from .base import BaseProvider, parse_json_safely

class AnthropicProvider(BaseProvider):
    """Connects to Anthropic Messages API using standard urllib."""
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-3-5-haiku-latest",
        temperature: float = 0.0,
        timeout: float = 4.5,
    ):
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.api_key = api_key or self._resolve_api_key()

    @staticmethod
    def _resolve_api_key() -> str:
        # 1. Environment variable
        env_key = os.environ.get("ANTHROPIC_API_KEY")
        if env_key:
            return env_key.strip()

        # 2. Global user config (~/.gemini/config/auto-permissions.json)
        global_config_path = Path.home() / ".gemini" / "config" / "auto-permissions.json"
        if global_config_path.is_file():
            try:
                with open(global_config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                key = cfg.get("anthropic_api_key") or cfg.get("api_key")
                if key:
                    return str(key).strip()
            except Exception:
                pass
        return ""

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            return None

        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": self.model,
            "max_tokens": 1024,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": self.temperature,
        }
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                contents = resp_data.get("content", [])
                if contents:
                    text = contents[0].get("text", "")
                    return parse_json_safely(text)
        except Exception:
            return None
        return None
