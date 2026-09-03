"""Hardware probing and model acquisition utilities."""
import os
import sys
import struct
import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

VRAM_PROFILES: Dict[str, Dict[str, Any]] = {
    "4gb": {
        "model": "gemma-4-E2B-it-UD-Q3_K_XL.gguf",
        "num_ctx": 8192,
        "modelfile": "Modelfile.4gb-gemma4-e2b",
        "url": "https://huggingface.co/unsloth/gemma-4-E2B-it-GGUF/resolve/main/gemma-4-E2B-it-UD-Q3_K_XL.gguf",
        "description": "Ultra-lightweight edge profile (Gemma 4 E2B, ~2.9 GB VRAM, leaves headroom for OS)",
    },
    "6gb": {
        "model": "gemma-4-E4B-it-qat-UD-Q4_K_XL.gguf",
        "num_ctx": 8192,
        "modelfile": "Modelfile.6gb-gemma4-e4b",
        "url": "https://huggingface.co/unsloth/gemma-4-E4B-it-GGUF/resolve/main/gemma-4-E4B-it-qat-UD-Q4_K_XL.gguf",
        "description": "Ultra-low latency profile (Gemma 4 E4B QAT with MTP, <20ms latency)",
    },
    "8gb": {
        "model": "Qwen3.5-9B-UD-Q4_K_XL.gguf",
        "num_ctx": 8192,
        "modelfile": "Modelfile.8gb-qwen3.5-9b",
        "url": "https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/resolve/main/Qwen3.5-9B-UD-Q4_K_XL.gguf",
        "description": "Sweet spot daily driver (Qwen 3.5 9B, 82.7% LiveCodeBench, top security detection)",
    },
    "12gb": {
        "model": "gemma-4-12B-it-qat-UD-Q4_K_XL.gguf",
        "num_ctx": 8192,
        "modelfile": "Modelfile.12gb-gemma4-12b",
        "url": "https://huggingface.co/unsloth/gemma-4-12B-it-GGUF/resolve/main/gemma-4-12B-it-qat-UD-Q4_K_XL.gguf",
        "description": "Maximum threat reasoning on 12GB cards (Gemma 4 12B QAT with MTP)",
    },
    "16gb": {
        "model": "gemma-4-26B-A4B-it-qat-UD-Q4_K_XL.gguf",
        "num_ctx": 8192,
        "modelfile": "Modelfile.16gb-gemma4-26b",
        "url": "https://huggingface.co/unsloth/gemma-4-26B-A4B-it-GGUF/resolve/main/gemma-4-26B-A4B-it-qat-UD-Q4_K_XL.gguf",
        "description": "Mixture-of-Experts frontier profile (Gemma 4 26B A4B MoE, 4B active speed)",
    },
    "24gb": {
        "model": "Qwen3.8-35B-UD-Q4_K_XL.gguf",
        "num_ctx": 8192,
        "modelfile": "Modelfile.24gb-qwen3.8-35b",
        "url": "https://huggingface.co/unsloth/Qwen3.8-35B-GGUF/resolve/main/Qwen3.8-35B-UD-Q4_K_XL.gguf",
        "description": "Flagship enterprise dense reasoning profile (Qwen 3.8 35B / Gemma 4 31B)",
    },
}

def _tier_from_gb(mem_gb: float) -> str:
    """Helper to map memory in GB to the optimal model tier."""
    if mem_gb < 5.0:
        return "4gb"
    elif mem_gb < 7.5:
        return "6gb"
    elif mem_gb < 11.0:
        return "8gb"
    elif mem_gb < 15.0:
        return "12gb"
    elif mem_gb < 22.0:
        return "16gb"
    else:
        return "24gb"

def detect_hardware() -> Dict[str, Any]:
    """Auto-detect NVIDIA, AMD, Intel GPU VRAM or Apple Silicon Unified Memory."""
    result: Dict[str, Any] = {
        "type": "cpu",
        "name": "Generic CPU / System RAM",
        "memory_gb": 4.0,
        "recommended_tier": "8gb"
    }

    # 1. NVIDIA GPUs (Windows / Linux)
    nvsmi = shutil.which("nvidia-smi")
    if nvsmi:
        try:
            out = subprocess.check_output(
                [nvsmi, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
                text=True,
                timeout=2.0
            ).strip()
            if out:
                lines = out.splitlines()
                name, mem_mb_str = [x.strip() for x in lines[0].split(",")]
                mem_gb = round(float(mem_mb_str) / 1024.0, 1)
                result["type"] = "nvidia"
                result["name"] = name
                result["memory_gb"] = mem_gb
                result["recommended_tier"] = _tier_from_gb(mem_gb)
                return result
        except Exception:
            pass

    # 2. AMD GPUs via ROCm rocm-smi (Linux / Windows ROCm)
    rocmsmi = shutil.which("rocm-smi")
    if rocmsmi:
        try:
            out = subprocess.check_output(
                [rocmsmi, "--showmeminfo", "vram", "--csv"],
                text=True,
                timeout=2.0
            ).strip()
            if out:
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                if len(lines) >= 2:
                    headers = [h.strip() for h in lines[0].split(",")]
                    values = [v.strip() for v in lines[1].split(",")]
                    for idx, h in enumerate(headers):
                        if "total" in h.lower() and "used" not in h.lower() and idx < len(values):
                            val_str = values[idx]
                            if val_str.isdigit():
                                bytes_val = int(val_str)
                                mem_gb = round(bytes_val / (1024.0 ** 3), 1)
                                result["type"] = "amd"
                                result["name"] = "AMD Radeon GPU (ROCm)"
                                result["memory_gb"] = mem_gb
                                result["recommended_tier"] = _tier_from_gb(mem_gb)
                                return result
        except Exception:
            pass

    # 3. Windows Native Registry (Detects NVIDIA, AMD Radeon, Intel Arc / Iris / Xe)
    if sys.platform == "win32":
        try:
            import winreg
            base = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
            best_gpu = None
            max_vram = 0

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
                num_subkeys = winreg.QueryInfoKey(k)[0]
                for i in range(num_subkeys):
                    try:
                        sub = winreg.EnumKey(k, i)
                        with winreg.OpenKey(k, sub) as sk:
                            vals = {}
                            for j in range(winreg.QueryInfoKey(sk)[1]):
                                try:
                                    vn, vv, _ = winreg.EnumValue(sk, j)
                                    vals[vn] = vv
                                except OSError:
                                    continue

                            desc = vals.get("DriverDesc")
                            if not desc or any(x in str(desc).lower() for x in ["virtual", "parsec", "superdisplay", "remote", "vga"]):
                                continue

                            qw = vals.get("HardwareInformation.qwMemorySize")
                            mem_size = vals.get("HardwareInformation.MemorySize")
                            bytes_val = 0
                            if isinstance(qw, int):
                                bytes_val = qw
                            elif isinstance(qw, bytes) and len(qw) == 8:
                                bytes_val = struct.unpack("<Q", qw)[0]
                            elif isinstance(mem_size, int):
                                bytes_val = mem_size
                            elif isinstance(mem_size, bytes) and len(mem_size) == 4:
                                bytes_val = struct.unpack("<I", mem_size)[0]

                            if bytes_val > max_vram:
                                max_vram = bytes_val
                                best_gpu = str(desc)
                    except (OSError, struct.error, ValueError):
                        continue

            if best_gpu and max_vram >= 2 * (1024 ** 3):
                mem_gb = round(max_vram / (1024.0 ** 3), 1)
                lower_name = best_gpu.lower()
                if "radeon" in lower_name or "amd" in lower_name:
                    gpu_type = "amd"
                elif "intel" in lower_name:
                    gpu_type = "intel"
                elif "nvidia" in lower_name or "geforce" in lower_name or "rtx" in lower_name:
                    gpu_type = "nvidia"
                else:
                    gpu_type = "gpu"

                result["type"] = gpu_type
                result["name"] = best_gpu
                result["memory_gb"] = mem_gb
                result["recommended_tier"] = _tier_from_gb(mem_gb)
                return result
        except Exception:
            pass

    # 4. Apple Silicon Unified Memory (macOS ARM64 only)
    if sys.platform == "darwin":
        import platform
        if platform.machine().lower() in ("arm64", "aarch64"):
            sysctl_bin = shutil.which("sysctl")
            if sysctl_bin:
                try:
                    out = subprocess.check_output([sysctl_bin, "-n", "hw.memsize"], text=True, timeout=2.0).strip()
                    if out:
                        bytes_mem = int(out)
                        mem_gb = round(bytes_mem / (1024.0 ** 3), 1)
                        result["type"] = "apple_silicon"
                        result["name"] = "Apple Silicon (Unified Memory)"
                        result["memory_gb"] = mem_gb
                        result["recommended_tier"] = _tier_from_gb(mem_gb * 0.75) # 75% for LLM, 25% for OS/apps
                        return result
                except Exception:
                    pass

    return result

def download_model(tier: str, target_dir: Optional[Path] = None) -> Optional[Path]:
    """Download the recommended GGUF model with live progress bar."""
    tier = tier.lower()
    if tier not in VRAM_PROFILES:
        print(f"Unknown tier '{tier}'.")
        return None

    profile = VRAM_PROFILES[tier]
    url = profile.get("url")
    if not url:
        print("No direct download URL configured for this tier.")
        return None

    if not target_dir:
        target_dir = Path.home() / ".gemini" / "antigravity" / "models"
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / profile["model"]
    part_file = target_file.with_suffix(".part")

    if target_file.is_file() and target_file.stat().st_size > 100 * 1024 * 1024:
        print(f"✓ Model file already exists: {target_file}")
        return target_file

    print(f"\n📥 Downloading {profile['model']} from Hugging Face...")
    print(f"   Destination: {target_file}")

    def reporthook(count: int, block_size: int, total_size: int):
        if total_size > 0:
            percent = int(count * block_size * 100 / total_size)
            mb_downloaded = (count * block_size) / (1024 * 1024)
            mb_total = total_size / (1024 * 1024)
            sys.stdout.write(f"\r   Progress: {percent}% [{mb_downloaded:.1f} MB / {mb_total:.1f} MB]")
            sys.stdout.flush()

    try:
        if part_file.is_file():
            part_file.unlink(missing_ok=True)
        urllib.request.urlretrieve(url, part_file, reporthook=reporthook)
        part_file.replace(target_file)
        print("\n✓ Model downloaded successfully!")
        return target_file
    except BaseException as e:
        print(f"\n❌ Error downloading model: {e}")
        if part_file.is_file():
            part_file.unlink(missing_ok=True)
        if isinstance(e, KeyboardInterrupt):
            raise
        return None

def create_launcher_script(tier: str, model_path: Optional[Path] = None) -> Path:
    """Generate a custom one-click launcher script to run llama serve with optimal flags."""
    profile = VRAM_PROFILES.get(tier.lower(), VRAM_PROFILES["8gb"])
    model_name = profile["model"]
    tools_dir = Path.home() / ".gemini" / "antigravity" / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)

    if model_path and model_path.is_file():
        resolved_model = str(model_path.resolve())
    else:
        resolved_model = f"models/{model_name}"

    if sys.platform == "win32":
        launcher_file = tools_dir / "start-local-gatekeeper.bat"
        content = f"""@echo off
title Auto Permissions Gatekeeper (Port 9931)
echo Starting local security gatekeeper on port 9931...
llama serve -m "{resolved_model}" -c {profile['num_ctx']} -ctk q4_0 -ctv q4_0 -ngl 99 --flash-attn on --port 9931
pause
"""
        # Also create a double-clickable monitor dashboard shortcut
        monitor_file = tools_dir / "open-monitor-board.bat"
        venv_py = tools_dir / "auto-permissions-env" / "Scripts" / "python.exe"
        python_bin = str(venv_py) if venv_py.is_file() else sys.executable
        monitor_content = f"""@echo off
title Auto Permissions Live Audit Dashboard
"{python_bin}" -m auto_permissions.cli monitor
pause
"""
        with open(monitor_file, "w", encoding="utf-8") as f:
            f.write(monitor_content)
    else:
        launcher_file = tools_dir / "start-local-gatekeeper.sh"
        content = f"""#!/usr/bin/env bash
echo "Starting local security gatekeeper on port 9931..."
llama serve -m "{resolved_model}" -c {profile['num_ctx']} -ctk q4_0 -ctv q4_0 -ngl 99 --flash-attn on --port 9931
"""
        monitor_file = tools_dir / "open-monitor-board.sh"
        venv_py = tools_dir / "auto-permissions-env" / "bin" / "python"
        python_bin = str(venv_py) if venv_py.is_file() else sys.executable
        monitor_content = f"""#!/usr/bin/env bash
"{python_bin}" -m auto_permissions.cli monitor
"""
        with open(monitor_file, "w", encoding="utf-8") as f:
            f.write(monitor_content)
        try:
            monitor_file.chmod(0o755)
        except Exception:
            pass

    with open(launcher_file, "w", encoding="utf-8") as f:
        f.write(content)

    if sys.platform != "win32":
        try:
            launcher_file.chmod(0o755)
        except Exception:
            pass

    return launcher_file

def install_desktop_shortcuts() -> Dict[str, str]:
    """Copy or create convenient shortcuts on the User's Desktop."""
    tools_dir = Path.home() / ".gemini" / "antigravity" / "tools"
    desktop = Path.home() / "Desktop"
    created = {}

    if not desktop.is_dir():
        return created

    # Ensure launcher scripts exist before copying
    start_script = tools_dir / ("start-local-gatekeeper.bat" if sys.platform == "win32" else "start-local-gatekeeper.sh")
    if not start_script.is_file():
        hw = detect_hardware()
        create_launcher_script(hw.get("recommended_tier", "8gb"))

    if sys.platform == "win32":
        for src_name, dst_name in [
            ("open-monitor-board.bat", "Auto Permissions Monitor.bat"),
            ("start-local-gatekeeper.bat", "Start Local Gatekeeper.bat")
        ]:
            src = tools_dir / src_name
            dst = desktop / dst_name
            if src.is_file():
                try:
                    shutil.copy2(src, dst)
                    created[dst_name] = str(dst)
                except Exception:
                    pass
    else:
        for src_name, dst_name in [
            ("open-monitor-board.sh", "Auto Permissions Monitor.sh"),
            ("start-local-gatekeeper.sh", "Start Local Gatekeeper.sh")
        ]:
            src = tools_dir / src_name
            dst = desktop / dst_name
            if src.is_file():
                try:
                    shutil.copy2(src, dst)
                    try:
                        dst.chmod(0o755)
                    except Exception:
                        pass
                    created[dst_name] = str(dst)
                except Exception:
                    pass

    return created
