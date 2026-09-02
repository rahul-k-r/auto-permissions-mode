"""LLM Provider connectors for local models."""
import json
import re
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
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
                return json.loads(response_text)
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
                choice = data.get("choices", [{}])[0]
                content = choice.get("message", {}).get("content", "")
                if not content:
                    return None
                clean_content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
                json_match = re.search(r'\{.*\}', clean_content, flags=re.DOTALL)
                if json_match:
                    clean_content = json_match.group(0)
                return json.loads(clean_content)
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