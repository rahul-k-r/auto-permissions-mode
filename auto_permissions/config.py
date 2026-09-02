"""Configuration manager for Auto Permissions Mode."""

import os
import json
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "provider": "llamacpp",
    "endpoint": "http://127.0.0.1:8080/v1/chat/completions",
    "model": "auto",
    "num_ctx": 8192,
    "temperature": 0.0,
    "timeout_seconds": 3.5,
    "fallback_to_cloud": True,
    "cloud_provider": "gemini",
    "cloud_model": "gemini-flash-lite-latest",
    "cloud_timeout_seconds": 4.5,
    "total_deadline_seconds": 11.0,
    "fallback_action": "force_ask",
    "fast_path_read_only": True,
    "protected_paths": [
        ".git",
        ".env",
        ".ssh",
        "id_rsa",
        "id_ed25519",
        "/etc",
        "C:\\Windows",
        "C:\\Windows\\System32",
    ],
}

def get_config_search_paths() -> list[Path]:
    paths = []
    # 1. Current working directory / workspace
    cwd = Path.cwd()
    paths.append(cwd / "auto-permissions.json")
    paths.append(cwd / ".agents" / "auto-permissions.json")
    
    # 2. Global user configs
    home = Path.home()
    paths.append(home / ".gemini" / "config" / "auto-permissions.json")
    paths.append(home / ".config" / "auto-permissions" / "config.json")
    
    # 3. Bundled default
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
    return config
