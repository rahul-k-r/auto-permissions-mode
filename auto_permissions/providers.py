"""LLM Provider connectors for local models."""
import os
import json
import re
import time
import tempfile
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional

def parse_json_safely(raw_text: str) -> Optional[Dict[str, Any]]:
    """Sanitize <think> tags and extract valid JSON payload reliably."""
    if not raw_text or not raw_text.strip():
        return None

    # 1. Strip completed or unclosed <think> blocks
    cleaned = re.sub(r'<think>.*?</think>', '', raw_text, flags=re.DOTALL)
    cleaned = re.sub(r'<think>.*$', '', cleaned, flags=re.DOTALL).strip()

    # 2. Try direct parse
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # 3. Locate the first '{' and decode using JSONDecoder.raw_decode
    idx = cleaned.find('{')
    if idx != -1:
        try:
            obj, _ = json.JSONDecoder().raw_decode(cleaned[idx:])
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass

    return None

class BaseProvider(ABC):
    @abstractmethod
    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        pass

class OpenAICompatibleProvider(BaseProvider):
    """Connects to OpenAI-compatible endpoints like llama.cpp / llama-server, vLLM, or LM Studio."""
    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:8080/v1/chat/completions",
        model: str = "auto",
        temperature: float = 0.0,
        timeout: float = 3.5,
    ):
        # Normalize localhost to 127.0.0.1 to avoid Windows IPv6/NetBIOS 1-2.5s DNS delays
        self.endpoint = endpoint.replace("localhost", "127.0.0.1")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self._cached_model_id: Optional[str] = None

    def _resolve_model_id(self) -> str:
        """Resolve model name; auto-detects from /v1/models if model is 'auto' or 'default'."""
        if self.model and self.model not in ("auto", "default"):
            return self.model

        if self._cached_model_id:
            return self._cached_model_id

        # Check cross-process temp cache file with 60s TTL
        cache_file = Path(tempfile.gettempdir()) / "auto_permissions_model_8080.json"
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

        # Query /v1/models with strict 1.0s timeout
        models_endpoint = self.endpoint.rsplit("/chat/completions", 1)[0] + "/models"
        try:
            req = urllib.request.Request(models_endpoint, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                model_list = data.get("data") or data.get("models") or []
                if model_list and isinstance(model_list, list):
                    detected = model_list[0].get("id") or model_list[0].get("name") or "default"
                    self._cached_model_id = detected
                    try:
                        with open(cache_file, "w", encoding="utf-8") as f:
                            json.dump({"model_id": detected, "cached_at": now}, f)
                    except Exception:
                        pass
                    return detected
        except Exception:
            pass

        return "default"

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        resolved_model = self._resolve_model_id()
        payload = {
            "model": resolved_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"},
            "chat_template_kwargs": {"enable_thinking": False},
            "temperature": self.temperature,
        }
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choices = data.get("choices", [])
                choice = choices[0] if choices else {}
                content = choice.get("message", {}).get("content", "")
                return parse_json_safely(content)
        except Exception:
            return None

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

class TieredProvider(BaseProvider):
    """Local-first provider with dynamic deadline budgeting and cloud failover.
    
    Pipeline:
      1. Primary: Local Server (llama.cpp or Ollama, timeout ~3.5s)
      2. Secondary: Cloud Gemini Flash Lite (failover on offline/timeout, timeout min(4.5s, remaining))
      3. Tertiary: Fallback to force_ask if both unavailable or remaining deadline < 2.0s
    """
    def __init__(
        self,
        primary: BaseProvider,
        secondary: Optional[BaseProvider] = None,
        total_deadline: float = 11.0,
    ):
        self.primary = primary
        self.secondary = secondary
        self.total_deadline = total_deadline

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        t0 = time.time()

        # 1. Try Primary (Local Server)
        res = self.primary.evaluate(system_prompt, prompt)
        if res and isinstance(res, dict):
            return res

        # If no cloud secondary configured, return None (evaluator will trigger fallback_action)
        if not self.secondary:
            return None

        # 2. Check remaining budget
        elapsed = time.time() - t0
        remaining = self.total_deadline - elapsed
        if remaining < 2.0:
            return {
                "decision": "force_ask",
                "reason": f"Local server offline and deadline budget expired ({elapsed:.1f}s elapsed). Escalating to manual confirmation."
            }

        # 3. Failover to Cloud Secondary
        if hasattr(self.secondary, "timeout"):
            orig_timeout = getattr(self.secondary, "timeout", 4.5)
            setattr(self.secondary, "timeout", min(orig_timeout, remaining))

        res_cloud = self.secondary.evaluate(system_prompt, prompt)
        if res_cloud and isinstance(res_cloud, dict):
            return res_cloud

        # 4. Tertiary fallback
        return {
            "decision": "force_ask",
            "reason": "Local server and cloud failover both unavailable or rate-limited. Escalating to manual confirmation."
        }

def get_provider(config: Dict[str, Any]) -> BaseProvider:
    """Instantiate and wire up providers based on config."""
    provider_name = config.get("provider", "llamacpp").lower()
    endpoint = config.get("endpoint", "http://127.0.0.1:8080/v1/chat/completions")
    model = config.get("model", "auto")
    timeout = float(config.get("timeout_seconds", 3.5))
    temperature = float(config.get("temperature", 0.0))
    num_ctx = int(config.get("num_ctx", 4096))

    # Construct primary provider
    if provider_name in ("llamacpp", "openai") or "v1/chat/completions" in endpoint:
        primary = OpenAICompatibleProvider(
            endpoint=endpoint,
            model=model,
            temperature=temperature,
            timeout=timeout,
        )
    elif provider_name == "gemini":
        api_key = config.get("api_key") or config.get("gemini_api_key")
        return GeminiProvider(
            api_key=api_key,
            model=model if model not in ("auto", "default") else "gemini-flash-lite-latest",
            temperature=temperature,
            timeout=timeout,
        )
    else:
        primary = OllamaProvider(
            endpoint=endpoint,
            model=model if model not in ("auto", "default") else "qwen3.5:9b",
            num_ctx=num_ctx,
            temperature=temperature,
            timeout=timeout,
        )

    # Check for cloud failover
    if config.get("fallback_to_cloud", True):
        cloud_model = config.get("cloud_model", "gemini-flash-lite-latest")
        cloud_timeout = float(config.get("cloud_timeout_seconds", 4.5))
        cloud_api_key = config.get("gemini_api_key") or config.get("api_key")
        secondary = GeminiProvider(
            api_key=cloud_api_key,
            model=cloud_model,
            temperature=temperature,
            timeout=cloud_timeout,
        )
        total_deadline = float(config.get("total_deadline_seconds", 11.0))
        return TieredProvider(primary, secondary, total_deadline=total_deadline)

    return primary