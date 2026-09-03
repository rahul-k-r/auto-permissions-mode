#!/usr/bin/env bash
#
# Auto Permissions Mode Installer for macOS and Linux
# Installs Auto Permissions Mode into an isolated virtual environment,
# configures hardware profiles / cloud failover, and registers the global
# Antigravity PreToolUse security hook.
#

set -e

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

write_step() { echo -e "\n${CYAN}👉 $1${NC}"; }
write_success() { echo -e "${GREEN}✓ $1${NC}"; }
write_warn() { echo -e "${YELLOW}⚠️ $1${NC}"; }
write_err() { echo -e "${RED}❌ $1${NC}"; }

echo -e "${CYAN}==============================================================="
echo -e "       🛡️ Auto Permissions Mode - Setup & Installer"
echo -e "   Autonomous Local LLM Security Gatekeeper for AI Agents"
echo -e "===============================================================${NC}"

# Reconnect stdin to controlling terminal if piped via curl | bash
if [ ! -t 0 ]; then
    if [ -c /dev/tty ]; then
        exec < /dev/tty
    else
        NON_INTERACTIVE=1
    fi
fi

INSTALL_ROOT="${HOME}/.gemini/antigravity/tools"
VENV_DIR="${INSTALL_ROOT}/auto-permissions-env"
VENV_PYTHON="${VENV_DIR}/bin/python"
GLOBAL_CONFIG="${HOME}/.gemini/config/auto-permissions.json"

# -------------------------------------------------------------
# Handle Uninstallation
# -------------------------------------------------------------
if [ "$1" = "--uninstall" ] || [ "$1" = "-Uninstall" ]; then
    write_step "Uninstalling Auto Permissions Mode..."
    if [ -x "$VENV_PYTHON" ]; then
        "$VENV_PYTHON" -m auto_permissions.cli uninstall --global --purge
    fi
    if [ -d "$VENV_DIR" ]; then
        write_step "Removing virtual environment: $VENV_DIR"
        rm -rf "$VENV_DIR"
        write_success "Virtual environment deleted."
    fi
    write_success "Uninstallation complete."
    exit 0
fi

# -------------------------------------------------------------
# 1. Discover Python Interpreter
# -------------------------------------------------------------
write_step "Discovering Python interpreter..."
PYTHON_BIN=""

for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        if "$cmd" -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
            PYTHON_BIN="$(command -v "$cmd")"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    write_err "Python 3.9+ was not found on your system."
    echo -e "${YELLOW}Please install Python 3 using your package manager:${NC}"
    echo -e "  macOS : brew install python@3.12"
    echo -e "  Debian/Ubuntu: sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
    exit 1
fi

PY_VER="$("$PYTHON_BIN" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")"
write_success "Found Python $PY_VER ($PYTHON_BIN)"

# Pre-flight check for python3-venv / ensurepip
if ! "$PYTHON_BIN" -c "import venv, ensurepip" >/dev/null 2>&1; then
    write_err "The 'venv' or 'ensurepip' module is missing in $PYTHON_BIN."
    echo -e "${YELLOW}On Debian/Ubuntu systems, install the venv package:${NC}"
    echo -e "  sudo apt update && sudo apt install -y python3-venv python3-pip"
    exit 1
fi

# -------------------------------------------------------------
# 2. Manage Isolated Virtual Environment
# -------------------------------------------------------------
write_step "Managing isolated virtual environment..."
mkdir -p "$INSTALL_ROOT"

NEEDS_CREATE=1
if [ -x "$VENV_PYTHON" ]; then
    if "$VENV_PYTHON" -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
        NEEDS_CREATE=0
        write_success "Existing virtual environment is healthy."
    else
        write_warn "Existing virtual environment is corrupted. Recreating..."
        rm -rf "$VENV_DIR"
    fi
fi

if [ "$NEEDS_CREATE" -eq 1 ]; then
    echo "Creating virtual environment at $VENV_DIR..."
    "$PYTHON_BIN" -m venv "$VENV_DIR" --clear
    write_success "Virtual environment created."
fi

# -------------------------------------------------------------
# 3. Install Package
# -------------------------------------------------------------
write_step "Installing Auto Permissions Mode package..."
SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
fi

if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
    echo "Installing from local source: $SCRIPT_DIR..."
    "$VENV_PYTHON" -m pip install --no-cache-dir "$SCRIPT_DIR" >/dev/null
else
    echo "Downloading latest release from GitHub..."
    TEMP_ZIP="$(mktemp -t auto-permissions-XXXXXX.zip)"
    trap 'rm -f "$TEMP_ZIP"' EXIT
    curl -fsSL "https://github.com/rahul-k-r/auto-permissions-mode/archive/refs/heads/main.zip" -o "$TEMP_ZIP"
    "$VENV_PYTHON" -m pip install --no-cache-dir --force-reinstall "$TEMP_ZIP" >/dev/null
    rm -f "$TEMP_ZIP"
    trap - EXIT
fi

INSTALLED_VER="$("$VENV_PYTHON" -m auto_permissions.cli version 2>/dev/null || echo 'v0.3.3')"
write_success "Installed $INSTALLED_VER"

# -------------------------------------------------------------
# 4. Hardware Detection & Configuration
# -------------------------------------------------------------
write_step "Detecting system hardware & VRAM..."
"$VENV_PYTHON" -m auto_permissions.cli detect

if [ -z "$NON_INTERACTIVE" ]; then
    # Interactive Onboarding Wizard
    "$VENV_PYTHON" -m auto_permissions.cli configure --global
else
    # Non-interactive / Default setup
    VRAM_TIER="${VRAM:-}"
    if [ -z "$VRAM_TIER" ]; then
        VRAM_TIER="$("$VENV_PYTHON" -c "import json; from auto_permissions.hardware import detect_hardware; print(detect_hardware().get('recommended_tier', '8gb'))")"
    else
        VRAM_TIER="$(echo "$VRAM_TIER" | tr '[:upper:]' '[:lower:]')"
        case "$VRAM_TIER" in
            4gb|6gb|8gb|12gb|16gb|24gb) ;;
            *)
                write_err "Invalid VRAM tier '$VRAM_TIER' (expected one of: 4gb, 6gb, 8gb, 12gb, 16gb, 24gb)"
                exit 1
                ;;
        esac
    fi
    "$VENV_PYTHON" -m auto_permissions.cli setup --vram "$VRAM_TIER" --global
fi

# -------------------------------------------------------------
# 5. Hook Registration & Verification
# -------------------------------------------------------------
write_step "Registering Antigravity PreToolUse hook..."
"$VENV_PYTHON" -m auto_permissions.cli install --global

write_step "Testing hook bridge integrity..."
"$VENV_PYTHON" -m auto_permissions.cli verify

echo -e "${GREEN}==============================================================="
echo -e "  🎉 Installation & Configuration Complete!"
echo -e "==============================================================="
echo -e "Antigravity Surfaces Protected:"
echo -e "  • Antigravity IDE"
echo -e "  • Antigravity 2.0"
echo -e "  • Antigravity VS Code Extension"
echo -e "  • Antigravity CLI (agy)"
echo -e ""
echo -e "Management Commands:"
echo -e "  Live board   : $VENV_PYTHON -m auto_permissions.cli monitor"
echo -e "  Shortcuts    : $VENV_PYTHON -m auto_permissions.cli shortcuts"
echo -e "  Check status : $VENV_PYTHON -m auto_permissions.cli status"
echo -e "  Run wizard   : $VENV_PYTHON -m auto_permissions.cli configure"
echo -e "  Run tests    : $VENV_PYTHON -m auto_permissions.cli test"
echo -e "  Uninstall    : ./install.sh --uninstall"
echo -e "===============================================================${NC}"
