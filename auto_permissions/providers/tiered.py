"""Tiered provider coordinator for local-first execution with cloud failover."""
import hashlib
import json
import os
import time
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from .base import BaseProvider

class TieredProvider(BaseProvider):
    """Local-first provider with dynamic deadline budgeting, circuit breaker, and cloud failover.
    
    Pipeline:
      1. Primary: Local Server (llama.cpp or Ollama, timeout ~3.5s)
      2. Circuit Breaker: 30s cooldown when local is down to avoid repeat probing delays
      3. Secondary: Cloud Gemini / Anthropic / OpenAI (timeout min(4.5s, remaining))
      4. Tertiary: Fallback to force_ask if both unavailable or remaining deadline < 1.0s
    """
    def __init__(
        self,
        primary: BaseProvider,
        secondary: Optional[BaseProvider] = None,
        total_deadline: float = 15.0,
    ):
        self.primary = primary
        self.secondary = secondary
        self.total_deadline = total_deadline

    def _circuit_breaker_file(self) -> Path:
        # Scope the breaker file to the primary endpoint so unrelated local
        # servers (different port/config) don't share cooldown state.
        key_src = getattr(self.primary, "endpoint", self.primary.__class__.__name__)
        key = hashlib.sha256(str(key_src).encode("utf-8")).hexdigest()[:12]
        return Path(tempfile.gettempdir()) / f"auto_permissions_cb_{key}.json"

    @staticmethod
    def _atomic_write_json(path: Path, data: dict) -> None:
        tmp = path.parent / f"{path.name}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)

    def is_local_in_cooldown(self) -> bool:
        """Check if local server is marked as down (30s TTL)."""
        cb_file = self._circuit_breaker_file()
        if not cb_file.is_file():
            return False
        try:
            with open(cb_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            until = data.get("down_until", 0)
            return time.time() < until
        except Exception:
            return False

    def mark_local_down(self, duration: float = 30.0) -> None:
        """Mark local server down for duration seconds."""
        cb_file = self._circuit_breaker_file()
        try:
            self._atomic_write_json(cb_file, {"down_until": time.time() + duration})
        except Exception:
            pass

    def mark_local_healthy(self) -> None:
        """Clear circuit breaker when local server succeeds."""
        cb_file = self._circuit_breaker_file()
        try:
            self._atomic_write_json(cb_file, {"down_until": 0})
        except Exception:
            pass

    def evaluate(self, system_prompt: str, prompt: str) -> Optional[Dict[str, Any]]:
        t0 = time.time()

        local_down = self.is_local_in_cooldown()

        # 1. Try Primary (Local Server) if not in circuit breaker cooldown
        if not local_down:
            # Clamp primary local timeout to at most 6.0s so cloud always has guaranteed budget
            if hasattr(self.primary, "timeout"):
                orig_prim_timeout = getattr(self.primary, "timeout", 6.0)
                setattr(self.primary, "timeout", min(orig_prim_timeout, 6.0))

            res = self.primary.evaluate(system_prompt, prompt)
            if res and isinstance(res, dict):
                self.mark_local_healthy()
                res.setdefault("source", "LOCAL")
                return res
            # Primary failed or timed out; trip circuit breaker
            self.mark_local_down(30.0)

        # If no cloud secondary configured, return None (evaluator will trigger fallback_action)
        if not self.secondary:
            return None

        # 2. Check remaining budget
        elapsed = time.time() - t0
        remaining = self.total_deadline - elapsed
        if remaining < 1.0:
            return {
                "decision": "force_ask",
                "reason": f"Local server offline and deadline budget expired ({elapsed:.1f}s elapsed). Escalating to manual confirmation.",
                "source": "TIMEOUT"
            }

        # 3. Failover to Cloud Secondary
        if hasattr(self.secondary, "timeout"):
            orig_timeout = getattr(self.secondary, "timeout", 4.5)
            setattr(self.secondary, "timeout", min(orig_timeout, max(1.0, remaining - 0.2)))

        res_cloud = self.secondary.evaluate(system_prompt, prompt)
        if res_cloud and isinstance(res_cloud, dict):
            # Clearly mark as cloud failover
            res_cloud["source"] = "FAILOVER"
            return res_cloud

        # 4. Tertiary fallback
        return {
            "decision": "force_ask",
            "reason": "Local server and cloud failover both unavailable or rate-limited. Escalating to manual confirmation.",
            "source": "OFFLINE"
        }
