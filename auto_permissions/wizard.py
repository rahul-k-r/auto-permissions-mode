"""Interactive onboarding wizard for Auto Permissions Mode."""
import os
import sys
import json
from pathlib import Path
from typing import Any, Dict

from auto_permissions.config import load_config
from auto_permissions.hardware import (
    VRAM_PROFILES,
    detect_hardware,
    download_model,
    create_launcher_script,
    install_desktop_shortcuts,
)

def run_wizard(is_global: bool = True) -> None:
    """Guided interactive setup for Auto Permissions Mode."""
    print("===============================================================")
    print("       🛡️ Auto Permissions Mode - Configuration Wizard")
    print("===============================================================\n")

    # 1. Hardware Detection
    hw = detect_hardware()
    rec_tier = hw.get("recommended_tier", "8gb")
    print(f"🔍 Detected Hardware : {hw['name']} ({hw['memory_gb']} GB)")
    print(f"💡 Recommended Tier  : {rec_tier.upper()} ({VRAM_PROFILES[rec_tier]['description']})\n")

    print("Select your preferred deployment mode:")
    print(" [1] 🏆 Local-First with Cloud Failover (Recommended)")
    print("     Runs locally on your GPU/RAM; automatically fails over to free cloud if local server is down.")
    print(" [2] ⚡ Instant Cloud Gatekeeper (0 VRAM, Zero Local Setup)")
    print("     Uses Google Gemini 2.0 Flash Lite, Claude, or GPT-4o-mini directly.")
    print(" [3] 🔒 Pure Local-Only (Airgapped / Zero Cloud Calls)")
    print("     Strictly local llama.cpp or Ollama; prompts manually if server is down.\n")

    try:
        choice = input("Choice [1/2/3] (Default: 1): ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        choice = "1"

    if is_global:
        config_path = Path.home() / ".gemini" / "config" / "auto-permissions.json"
    else:
        config_path = Path.cwd() / ".agents" / "auto-permissions.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    cfg = load_config()

    if choice == "2":
        # Cloud-Only Mode
        cfg["fallback_to_cloud"] = False
        print("\n--- Cloud Provider Setup ---")
        print(" [1] Google Gemini (Gemini 2.0 Flash Lite - Free 1,500 req/day) [Recommended]")
        print(" [2] Anthropic (Claude 3.5 / 4.5 Haiku)")
        print(" [3] OpenAI (GPT-4o-mini)")
        try:
            c_prov = input("Select provider [1/2/3] (Default: 1): ").strip() or "1"
        except (EOFError, KeyboardInterrupt):
            c_prov = "1"

        if c_prov == "2":
            cfg["provider"] = "anthropic"
            cfg["model"] = "claude-3-5-haiku-latest"
            try:
                key = input("Enter Anthropic API Key (or press Enter to use $ANTHROPIC_API_KEY): ").strip()
            except (EOFError, KeyboardInterrupt):
                key = ""
            if key:
                cfg["anthropic_api_key"] = key
        elif c_prov == "3":
            cfg["provider"] = "openai"
            cfg["model"] = "gpt-4o-mini"
            try:
                key = input("Enter OpenAI API Key (or press Enter to use $OPENAI_API_KEY): ").strip()
            except (EOFError, KeyboardInterrupt):
                key = ""
            if key:
                cfg["openai_api_key"] = key
        else:
            cfg["provider"] = "gemini"
            cfg["model"] = "gemini-flash-lite-latest"
            try:
                key = input("Enter Gemini API Key (or press Enter to use $GEMINI_API_KEY): ").strip()
            except (EOFError, KeyboardInterrupt):
                key = ""
            if key:
                cfg["gemini_api_key"] = key

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        print(f"\n✓ Saved cloud configuration to {config_path}!")
        return

    # Local-First or Pure Local Mode
    print("\n--- Local Model Selection ---")
    print(f"Available Tiers (Press Enter to accept detected {rec_tier.upper()}):")
    for t_key, t_val in VRAM_PROFILES.items():
        prefix = "👉 (Recommended) " if t_key == rec_tier else "   "
        print(f"{prefix}[{t_key}] : {t_val['description']}")

    try:
        tier_sel = input(f"\nEnter VRAM tier [{rec_tier}]: ").strip().lower() or rec_tier
    except (EOFError, KeyboardInterrupt):
        tier_sel = rec_tier

    if tier_sel not in VRAM_PROFILES:
        tier_sel = rec_tier

    cfg["provider"] = "llamacpp"
    cfg["model"] = VRAM_PROFILES[tier_sel]["model"]
    cfg["num_ctx"] = VRAM_PROFILES[tier_sel]["num_ctx"]

    # Offer to download model now via Hugging Face public endpoint
    try:
        dl_choice = input(f"\nWould you like to download '{VRAM_PROFILES[tier_sel]['model']}' now from Hugging Face? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        dl_choice = "n"

    model_path = None
    if dl_choice == "y":
        model_path = download_model(tier_sel)

    launcher_path = create_launcher_script(tier_sel, model_path)
    print(f"✓ One-click model launcher script created at: {launcher_path}")

    # Cloud Failover setup
    if choice == "1":
        cfg["fallback_to_cloud"] = True
        print("\n--- Cloud Failover Setup ---")
        print(" [1] Google Gemini (Gemini 2.0 Flash Lite - Free tier) [Recommended]")
        print(" [2] Anthropic (Claude 3.5 / 4.5 Haiku)")
        print(" [3] OpenAI (GPT-4o-mini)")
        print(" [4] Skip Cloud Failover")
        try:
            cf_choice = input("Select cloud failover [1/2/3/4] (Default: 1): ").strip() or "1"
        except (EOFError, KeyboardInterrupt):
            cf_choice = "1"

        if cf_choice == "2":
            cfg["cloud_provider"] = "anthropic"
            cfg["cloud_model"] = "claude-3-5-haiku-latest"
            try:
                key = input("Enter Anthropic API Key (or press Enter to use $ANTHROPIC_API_KEY): ").strip()
            except (EOFError, KeyboardInterrupt):
                key = ""
            if key:
                cfg["anthropic_api_key"] = key
        elif cf_choice == "3":
            cfg["cloud_provider"] = "openai"
            cfg["cloud_model"] = "gpt-4o-mini"
            try:
                key = input("Enter OpenAI API Key (or press Enter to use $OPENAI_API_KEY): ").strip()
            except (EOFError, KeyboardInterrupt):
                key = ""
            if key:
                cfg["openai_api_key"] = key
        elif cf_choice == "4":
            cfg["fallback_to_cloud"] = False
        else:
            cfg["cloud_provider"] = "gemini"
            cfg["cloud_model"] = "gemini-flash-lite-latest"
            try:
                key = input("Enter Gemini API Key (or press Enter to use $GEMINI_API_KEY): ").strip()
            except (EOFError, KeyboardInterrupt):
                key = ""
            if key:
                cfg["gemini_api_key"] = key
    else:
        cfg["fallback_to_cloud"] = False

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    print(f"\n✓ Saved configuration to {config_path}!")

    # Offer to place shortcuts on user's desktop
    try:
        dt_choice = input("\nWould you like to place convenient shortcuts on your Desktop? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        dt_choice = "y"

    if dt_choice != "n":
        created = install_desktop_shortcuts()
        if created:
            print("✓ Created Desktop shortcuts:")
            for name, path in created.items():
                print(f"   • {name} -> {path}")

    print(f"\n👉 Launch your local security gatekeeper anytime with:")
    print(f"   {launcher_path}\n")
