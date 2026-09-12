<#
.SYNOPSIS
    Auto Permissions Mode Native Go Installer for Windows (PowerShell)
.DESCRIPTION
    Installs the native compiled Auto Permissions Mode security engine, configures
    hardware VRAM profiles or cloud failover, and registers the global PreToolUse
    security hook for Google Antigravity IDE, Antigravity 2.0, Antigravity VS Code
    Extension, and agy CLI with ZERO Python dependencies.
.PARAMETER Uninstall
    Uninstalls the hook and purges configuration.
.PARAMETER NonInteractive
    Runs with auto-detected defaults without interactive prompts.
.PARAMETER Vram
    Preset VRAM tier: 4gb, 6gb, 8gb, 12gb, 16gb, 24gb. Default: auto-detected.
.PARAMETER Download
    Automatically download the recommended GGUF model from Hugging Face.
.PARAMETER DesktopShortcuts
    Creates convenient one-click shortcuts on your Desktop.
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$NonInteractive,
    [switch]$Download,
    [switch]$DesktopShortcuts,
    [string]$Vram = ""
)

$ErrorActionPreference = "Stop"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

function Write-Step { param([string]$msg) Write-Host "`n👉 $msg" -ForegroundColor Cyan }
function Write-Success { param([string]$msg) Write-Host "✓ $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "⚠️ $msg" -ForegroundColor Yellow }
function Write-Err { param([string]$msg) Write-Host "❌ $msg" -ForegroundColor Red }

Write-Host @"
===============================================================
       🛡️ Auto Permissions Mode (Native Go) - Installer
   Zero-Latency Local LLM Security Gatekeeper for AI Agents
===============================================================
"@ -ForegroundColor Blue

$binDir = Join-Path $HOME ".gemini\antigravity\bin"
$installedExe = Join-Path $binDir "auto-permissions.exe"

# -------------------------------------------------------------
# Handle Uninstallation
# -------------------------------------------------------------
if ($Uninstall) {
    Write-Step "Uninstalling Auto Permissions Mode..."
    if (Test-Path $installedExe) {
        & "$installedExe" uninstall --global --purge
    } else {
        $hookFile = Join-Path $HOME ".gemini\config\hooks.json"
        if (Test-Path $hookFile) {
            try {
                $content = Get-Content $hookFile -Raw -Encoding utf8 | ConvertFrom-Json
                if ($content."auto-permissions-mode") {
                    $content.PSObject.Properties.Remove("auto-permissions-mode")
                    $content | ConvertTo-Json -Depth 10 | Set-Content $hookFile -Encoding utf8
                    Write-Success "Removed hook from $hookFile"
                }
            } catch {
                Write-Warn "Could not parse $hookFile"
            }
        }
    }

    if (Test-Path $installedExe) {
        Remove-Item -Force $installedExe -ErrorAction SilentlyContinue
        Write-Success "Removed binary: $installedExe"
    }

    Write-Success "Uninstallation complete."
    exit 0
}

# -------------------------------------------------------------
# 1. Acquire Native Go Binary
# -------------------------------------------------------------
Write-Step "Setting up native Go binary..."
if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}

$isLocalClone = ($PSScriptRoot) -and (Test-Path (Join-Path $PSScriptRoot "cmd\auto-permissions\main.go"))

if ($isLocalClone) {
    Write-Host "Installing from local source: $PSScriptRoot..." -ForegroundColor DarkGray
    $localBuilt = Join-Path $PSScriptRoot "auto-permissions.exe"
    
    $hasGo = Get-Command "go" -ErrorAction SilentlyContinue
    if ($hasGo) {
        Write-Host "Building with Go compiler..." -ForegroundColor DarkGray
        Push-Location $PSScriptRoot
        try {
            & go build -trimpath -ldflags="-s -w" -o "$installedExe" ./cmd/auto-permissions
            if ($LASTEXITCODE -ne 0) { throw "go build failed" }
        } finally {
            Pop-Location
        }
    } elseif (Test-Path $localBuilt) {
        Copy-Item -Force $localBuilt $installedExe
    } else {
        Write-Err "Neither 'go' compiler nor prebuilt 'auto-permissions.exe' found."
        exit 1
    }
} else {
    Write-Host "Downloading latest release binary from GitHub..." -ForegroundColor DarkGray
    $releaseUrl = "https://github.com/rahul-k-r/auto-permissions-mode/releases/latest/download/auto-permissions-windows-amd64.exe"
    Invoke-RestMethod -Uri $releaseUrl -OutFile $installedExe
}

if (-not (Test-Path $installedExe)) {
    Write-Err "Binary installation failed: $installedExe not found."
    exit 1
}

$installedVer = & "$installedExe" version
Write-Success "Installed $installedVer"

# -------------------------------------------------------------
# 2. Hardware Detection & Configuration
# -------------------------------------------------------------
Write-Step "Detecting system hardware..."
& "$installedExe" detect

if (-not $NonInteractive -and -not $Vram) {
    & "$installedExe" configure
} else {
    $setupArgs = @("setup")
    if ($Vram) {
        $setupArgs += @("--vram", $Vram)
    }
    if ($Download) {
        $setupArgs += "--download"
    }
    & "$installedExe" @setupArgs
}

# -------------------------------------------------------------
# 3. Register Antigravity Hook & Verify
# -------------------------------------------------------------
Write-Step "Registering Antigravity PreToolUse hook..."
& "$installedExe" install --global
if ($LASTEXITCODE -ne 0) {
    Write-Err "Hook registration failed with exit code $LASTEXITCODE"
    exit 1
}

Write-Step "Testing hook bridge integrity..."
& "$installedExe" verify
if ($LASTEXITCODE -ne 0) {
    Write-Err "Hook verification failed"
    exit 1
}

if ($DesktopShortcuts) {
    Write-Step "Creating Desktop shortcuts..."
    & "$installedExe" shortcuts
}

Write-Host @"
===============================================================
  🎉 Native Go Installation Complete!
===============================================================
Antigravity Surfaces Protected:
  • Antigravity IDE
  • Antigravity 2.0
  • Antigravity VS Code Extension
  • Antigravity CLI (agy)

Management Commands:
  Live board   : & "$installedExe" monitor
  Check status : & "$installedExe" status
  Verify hook  : & "$installedExe" verify
  Self-tests   : & "$installedExe" test
  Shortcuts    : & "$installedExe" shortcuts
  Policy mode  : & "$installedExe" policy [balanced|strict|yolo]
  Uninstall    : .\install.ps1 -Uninstall
===============================================================
"@ -ForegroundColor Green
