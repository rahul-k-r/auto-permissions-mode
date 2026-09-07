"""Configuration manager for Auto Permissions Mode."""

import os
import json
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "provider": "llamacpp",
    "endpoint": "http://127.0.0.1:9931/v1/chat/completions",
    "model": "auto",
    "num_ctx": 8192,
    "temperature": 0.0,
    "timeout_seconds": 6.0,
    "fallback_to_cloud": True,
    "cloud_provider": "gemini",
    "cloud_model": "gemini-flash-lite-latest",
    "cloud_timeout_seconds": 12.0,
    "total_deadline_seconds": 18.0,
    "fallback_action": "force_ask",
    "fast_path_read_only": True,
    "max_tokens": 512,
    "enable_remediation_directives": True,
    "audit_retention_days": 14,
    "audit_max_lines": 5000,
    "audit_trim_interval_seconds": 3600,
    "protected_paths": [
        ".git",
        ".env",
        ".ssh",
        "id_rsa",
        "id_ed25519",
        "/etc",
        "C:\\Windows",
        "C:\\Windows\\System32",
        ".system_generated",
        "transcript.jsonl",
    ],
}

def get_config_search_paths() -> list[Path]:
    paths = []
    # 1. Project-local config (written by `setup --local` / the wizard; overrides global)
    cwd = Path.cwd()
    paths.append(cwd / ".agents" / "auto-permissions.json")
    paths.append(cwd / "auto-permissions.json")

    # 2. Global user configs
    home = Path.home()
    paths.append(home / ".gemini" / "config" / "auto-permissions.json")
    paths.append(home / ".config" / "auto-permissions" / "config.json")

    # 3. Bundled default (source repo fallback)
    script_dir = Path(__file__).resolve().parent.parent
    paths.append(script_dir / "config.default.json")
    return paths

def load_config() -> Dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    for path in get_config_search_paths():
        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    user_data = json.load(f)
                    if isinstance(user_data, dict):
                        config.update(user_data)
                        break
            except Exception:
                continue

    # Security guardrails: fallback_action must never be 'allow'
    if config.get("fallback_action") == "allow":
        config["fallback_action"] = "force_ask"

    # Ensure critical protected paths are never completely eliminated
    current_protected = set(config.get("protected_paths", []))
    default_protected = set(DEFAULT_CONFIG["protected_paths"])
    config["protected_paths"] = list(current_protected | default_protected)

    return config
