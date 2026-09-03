"""Base provider abstract class and JSON sanitization utilities."""
import json
import re
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
    """Abstract base class for all LLM permission evaluators."""
    @abstractmethod
    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        """Evaluate prompt and return structured JSON decision or None on failure."""
        pass
