"""Tiered provider coordinator for local-first execution with cloud failover."""
import time
from typing import Any, Dict, Optional

from .base import BaseProvider

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
