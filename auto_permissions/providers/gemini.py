"""Google Gemini REST API connector with OpenAPI schema and HTTP 429 cooldown detection."""
import json
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, Optional

from .base import BaseProvider, parse_json_safely, resolve_api_key, is_in_ttl_cooldown, write_ttl_cooldown

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
        self.api_key = api_key or resolve_api_key("GEMINI_API_KEY", "gemini_api_key")

    @staticmethod
    def _get_cooldown_file() -> Path:
        return Path(tempfile.gettempdir()) / "auto_permissions_gemini_cooldown.json"

    def is_in_cooldown(self) -> bool:
        return is_in_ttl_cooldown(self._get_cooldown_file(), key="cooldown_until")

    def _set_cooldown(self, seconds: int = 60, reason: str = "HTTP 429 Rate Limit") -> None:
        write_ttl_cooldown(self._get_cooldown_file(), seconds, key="cooldown_until", extra={"reason": reason})

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
