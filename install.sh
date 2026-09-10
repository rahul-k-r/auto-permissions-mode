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

BIN_DIR="${HOME}/.gemini/antigravity/bin"
INSTALLED_BIN="${BIN_DIR}/auto-permissions"

# -------------------------------------------------------------
# Handle Uninstallation
# -------------------------------------------------------------
if [ "$1" = "--uninstall" ] || [ "$1" = "-Uninstall" ]; then
    write_step "Uninstalling Auto Permissions Mode..."
    if [ -x "${INSTALLED_BIN}" ]; then
        "${INSTALLED_BIN}" uninstall --global --purge
        rm -f "${INSTALLED_BIN}"
    fi
    write_success "Uninstallation complete."
    exit 0
fi

# -------------------------------------------------------------
# 1. Acquire Native Go Binary
# -------------------------------------------------------------
write_step "Setting up native Go binary..."
mkdir -p "${BIN_DIR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/cmd/auto-permissions/main.go" ]; then
    if command -v go >/dev/null 2>&1; then
        echo "Building with Go compiler from local source..."
        (cd "$SCRIPT_DIR" && go build -trimpath -ldflags="-s -w" -o "${INSTALLED_BIN}" ./cmd/auto-permissions)
    elif [ -f "${SCRIPT_DIR}/auto-permissions" ]; then
        cp "${SCRIPT_DIR}/auto-permissions" "${INSTALLED_BIN}"
        chmod +x "${INSTALLED_BIN}"
    else
        write_err "Neither 'go' compiler nor prebuilt binary found."
        exit 1
    fi
else
    write_err "Please run install.sh from the repository root."
    exit 1
fi

INSTALLED_VER="$("${INSTALLED_BIN}" version 2>/dev/null || echo "installed")"
write_success "Installed ${INSTALLED_VER}"

# -------------------------------------------------------------
# 2. Hardware Detection & Configuration
# -------------------------------------------------------------
write_step "Detecting system hardware..."
"${INSTALLED_BIN}" detect

if [ "$1" = "--non-interactive" ] || [ -n "$NON_INTERACTIVE" ]; then
    "${INSTALLED_BIN}" setup
else
    "${INSTALLED_BIN}" configure
fi

# -------------------------------------------------------------
# 3. Register Antigravity Hook & Verify
# -------------------------------------------------------------
write_step "Registering Antigravity PreToolUse hook..."
"${INSTALLED_BIN}" install --global

write_step "Testing hook bridge integrity..."
"${INSTALLED_BIN}" verify

echo -e "${GREEN}==============================================================="
echo -e "  🎉 Native Go Installation Complete!"
echo -e "==============================================================="
echo -e "Antigravity Surfaces Protected:"
echo -e "  • Antigravity IDE"
echo -e "  • Antigravity 2.0"
echo -e "  • Antigravity VS Code Extension"
echo -e "  • Antigravity CLI (agy)"
echo -e ""
echo -e "Management Commands:"
echo -e "  Live board   : ${INSTALLED_BIN} monitor"
echo -e "  Check status : ${INSTALLED_BIN} status"
echo -e "  Verify hook  : ${INSTALLED_BIN} verify"
echo -e "  Self-tests   : ${INSTALLED_BIN} test"
echo -e "  Shortcuts    : ${INSTALLED_BIN} shortcuts"
echo -e "  Policy mode  : ${INSTALLED_BIN} policy [balanced|strict|yolo]"
echo -e "  Uninstall    : ./install.sh --uninstall"
echo -e "===============================================================${NC}"
