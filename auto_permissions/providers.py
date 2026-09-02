"""LLM Provider connectors for local models."""
import json
import re
import urllib.request
from abc import ABC, abstractmethod
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

class OllamaProvider(BaseProvider):
    def __init__(self, endpoint: str, model: str, num_ctx: int = 1024, temperature: float = 0.0, timeout: int = 15):
        self.endpoint = endpoint
        self.model = model
        self.num_ctx = num_ctx
        self.temperature = temperature
        self.timeout = timeout

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        full_prompt = f"{system_prompt}\n\n{prompt}"
        payload = {
            "model": self.model,
            "prompt": full_prompt,
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
                response_text = data.get("response", "")
                return parse_json_safely(response_text)
        except Exception:
            return None

class OpenAICompatibleProvider(BaseProvider):
    def __init__(self, endpoint: str, model: str, temperature: float = 0.0, timeout: int = 15):
        self.endpoint = endpoint
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        payload = {
            "model": self.model,
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
def get_provider(config: Dict[str, Any]) -> BaseProvider:
    provider_name = config.get("provider", "ollama").lower()
    endpoint = config.get("endpoint", "http://localhost:11434/api/generate")
    model = config.get("model", "gemma4:12b")
    timeout = config.get("timeout_seconds", 15)
    temperature = config.get("temperature", 0.0)
    num_ctx = config.get("num_ctx", 1024)
    if provider_name == "openai" or "v1/chat/completions" in endpoint:
        return OpenAICompatibleProvider(
            endpoint=endpoint,
            model=model,
            temperature=temperature,
            timeout=timeout
        )
    return OllamaProvider(
        endpoint=endpoint,
        model=model,
        num_ctx=num_ctx,
        temperature=temperature,
        timeout=timeout
    )