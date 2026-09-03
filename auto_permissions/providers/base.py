"""Base provider abstract class and JSON sanitization utilities."""
import json
import os
import re
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional

def resolve_api_key(env_var: str, config_key: str) -> str:
    """Resolve an API key from an env var, then the global user config file."""
    env_key = os.environ.get(env_var)
    if env_key:
        return env_key.strip()

    global_config_path = Path.home() / ".gemini" / "config" / "auto-permissions.json"
    if global_config_path.is_file():
        try:
            with open(global_config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            key = cfg.get(config_key) or cfg.get("api_key")
            if key:
                return str(key).strip()
        except Exception:
            pass
    return ""

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

    # 4. Resilient regex extraction for truncated JSON (e.g. hit max_tokens mid-reason)
    m = re.search(r'"decision"\s*:\s*"(allow|deny|ask|force_ask)"', cleaned, re.IGNORECASE)
    if m:
        dec = m.group(1).lower()
        rm = re.search(r'"reason"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)', cleaned)
        reason = rm.group(1).strip() if rm else "Evaluated by security model."
        return {"decision": dec, "reason": reason}

    return None

def is_in_ttl_cooldown(path: Path, key: str = "until") -> bool:
    """Best-effort check of a JSON TTL-flag file shared across processes."""
    if not path.is_file():
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return time.time() < data.get(key, 0)
    except Exception:
        return False

def write_ttl_cooldown(path: Path, duration: float, key: str = "until", extra: Optional[Dict[str, Any]] = None) -> None:
    """Best-effort atomic write of a JSON TTL-flag file (write-temp + replace avoids torn reads)."""
    try:
        data: Dict[str, Any] = {key: time.time() + duration}
        if extra:
            data.update(extra)
        tmp = path.parent / f"{path.name}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except Exception:
        pass

class BaseProvider(ABC):
    """Abstract base class for all LLM permission evaluators."""
    @abstractmethod
    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        """Evaluate prompt and return structured JSON decision or None on failure."""
        pass
