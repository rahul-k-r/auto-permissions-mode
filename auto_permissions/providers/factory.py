"""Factory function for initializing and configuring provider hierarchies."""
from typing import Any, Dict

from .base import BaseProvider
from .openai_compat import OpenAICompatibleProvider
from .ollama import OllamaProvider
from .gemini import GeminiProvider
from .tiered import TieredProvider

def get_provider(config: Dict[str, Any]) -> BaseProvider:
    """Instantiate and wire up providers based on config."""
    provider_name = config.get("provider", "llamacpp").lower()
    endpoint = config.get("endpoint", "http://127.0.0.1:9931/v1/chat/completions")
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
