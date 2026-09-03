"""Factory function for initializing and configuring provider hierarchies."""
import os
from typing import Any, Dict

from .base import BaseProvider
from .openai_compat import OpenAICompatibleProvider
from .ollama import OllamaProvider
from .gemini import GeminiProvider
from .anthropic import AnthropicProvider
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
    elif provider_name == "anthropic":
        api_key = config.get("api_key") or config.get("anthropic_api_key")
        return AnthropicProvider(
            api_key=api_key,
            model=model if model not in ("auto", "default") else "claude-3-5-haiku-latest",
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
        cloud_provider_name = config.get("cloud_provider", "gemini").lower()
        cloud_timeout = float(config.get("cloud_timeout_seconds", 12.0))
        cloud_model = config.get("cloud_model", "")

        secondary: BaseProvider
        if cloud_provider_name == "anthropic":
            cloud_api_key = config.get("anthropic_api_key") or config.get("api_key")
            secondary = AnthropicProvider(
                api_key=cloud_api_key,
                model=cloud_model or "claude-3-5-haiku-latest",
                temperature=temperature,
                timeout=cloud_timeout,
            )
        elif cloud_provider_name in ("openai", "openrouter", "groq"):
            cloud_endpoint = config.get("cloud_endpoint")
            if not cloud_endpoint:
                if cloud_provider_name == "openrouter":
                    cloud_endpoint = "https://openrouter.ai/api/v1/chat/completions"
                elif cloud_provider_name == "groq":
                    cloud_endpoint = "https://api.groq.com/openai/v1/chat/completions"
                else:
                    cloud_endpoint = "https://api.openai.com/v1/chat/completions"

            cloud_api_key = (
                config.get("openai_api_key")
                or config.get("openrouter_api_key")
                or config.get("api_key")
                or os.environ.get("OPENAI_API_KEY")
                or os.environ.get("OPENROUTER_API_KEY")
            )
            default_model = "gpt-4o-mini" if cloud_provider_name == "openai" else "auto"
            secondary = OpenAICompatibleProvider(
                endpoint=cloud_endpoint,
                model=cloud_model or default_model,
                api_key=cloud_api_key,
                temperature=temperature,
                timeout=cloud_timeout,
            )
        else:
            # Default to Gemini
            cloud_api_key = config.get("gemini_api_key") or config.get("api_key")
            secondary = GeminiProvider(
                api_key=cloud_api_key,
                model=cloud_model or "gemini-flash-lite-latest",
                temperature=temperature,
                timeout=cloud_timeout,
            )

        total_deadline = float(config.get("total_deadline_seconds", 18.0))
        return TieredProvider(primary, secondary, total_deadline=total_deadline)

    return primary
