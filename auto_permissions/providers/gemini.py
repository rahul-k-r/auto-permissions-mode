"""Google Gemini REST API connector with OpenAPI schema and HTTP 429 cooldown detection."""
import os
import json
import time
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, Optional

from .base import BaseProvider, parse_json_safely

class GeminiProvider(BaseProvider):
    """Connects to Google Gemini Flash Lite via generative language REST API."""
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-flash-lite-latest",
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
        env_key = os.environ.get("GEMINI_API_KEY")
        if env_key:
            return env_key.strip()

        # 2. Global user config (~/.gemini/config/auto-permissions.json)
        global_config_path = Path.home() / ".gemini" / "config" / "auto-permissions.json"
        if global_config_path.is_file():
            try:
                with open(global_config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                key = cfg.get("gemini_api_key") or cfg.get("api_key")
                if key:
                    return str(key).strip()
            except Exception:
                pass
        return ""

    @staticmethod
    def _get_cooldown_file() -> Path:
        return Path(tempfile.gettempdir()) / "auto_permissions_gemini_cooldown.json"

    def is_in_cooldown(self) -> bool:
        cooldown_file = self._get_cooldown_file()
        if not cooldown_file.is_file():
            return False
        try:
            with open(cooldown_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            until = data.get("cooldown_until", 0)
            return time.time() < until
        except Exception:
            return False

    def _set_cooldown(self, seconds: int = 60, reason: str = "HTTP 429 Rate Limit") -> None:
        try:
            with open(self._get_cooldown_file(), "w", encoding="utf-8") as f:
                json.dump({"cooldown_until": time.time() + seconds, "reason": reason}, f)
        except Exception:
            pass

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        if not self.api_key or self.is_in_cooldown():
            return None

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": f"{system_prompt}\n\n{prompt}"}]}
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": {
                    "type": "OBJECT",
                    "properties": {
                        "decision": {
                            "type": "STRING",
                            "enum": ["allow", "deny", "ask", "force_ask"]
                        },
                        "reason": {"type": "STRING"}
                    },
                    "required": ["decision", "reason"]
                },
                "temperature": self.temperature,
            }
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        text = parts[0].get("text", "")
                        return parse_json_safely(text)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                err_body = ""
                try:
                    err_body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                is_daily = "daily" in err_body.lower() or "limit: 500" in err_body.lower()
                cooldown_sec = 86400 if is_daily else 60
                self._set_cooldown(seconds=cooldown_sec, reason=f"Gemini 429 ({'Daily limit' if is_daily else 'RPM limit'})")
            return None
        except Exception:
            return None
        return None
