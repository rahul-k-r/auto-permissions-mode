<#
.SYNOPSIS
    Auto Permissions Mode Installer for Windows (PowerShell)
.DESCRIPTION
    Installs Auto Permissions Mode into an isolated environment, configures hardware VRAM
    profiles or cloud failover, and registers the global PreToolUse security hook for
    Google Antigravity IDE, Antigravity 2.0, Antigravity VS Code Extension, and agy CLI.
.PARAMETER Uninstall
    Uninstalls the hook and optionally purges configuration.
.PARAMETER NonInteractive
    Runs with auto-detected defaults without interactive prompts.
.PARAMETER Vram
    Preset VRAM tier: 4gb, 6gb, 8gb, 12gb, 16gb, 24gb. Default: auto-detected.
.PARAMETER Download
    Automatically download the recommended GGUF model from Hugging Face.
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

# Enforce strongest available TLS. Tls13 is not a defined enum member on older
# .NET/PowerShell hosts and would abort the whole script under $ErrorActionPreference
# = "Stop", so fall back to Tls12-only rather than failing the install outright.
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
       🛡️ Auto Permissions Mode - Setup & Installer
   Autonomous Local LLM Security Gatekeeper for AI Agents
===============================================================
"@ -ForegroundColor Blue

$isPiped = [Console]::IsInputRedirected
if ($isPiped -or $env:NON_INTERACTIVE -eq "1") {
    $NonInteractive = $true
}

if (-not $Vram -and $env:VRAM) {
    $Vram = $env:VRAM
}

$installRoot = Join-Path $HOME ".gemini\antigravity\tools"
$venvDir = Join-Path $installRoot "auto-permissions-env"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$globalConfig = Join-Path $HOME ".gemini\config\auto-permissions.json"

# -------------------------------------------------------------
# Handle Uninstallation
# -------------------------------------------------------------
if ($Uninstall) {
    Write-Step "Uninstalling Auto Permissions Mode..."
    if (Test-Path $venvPython) {
        & "$venvPython" -m auto_permissions.cli uninstall --global --purge
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

    if (Test-Path $venvDir) {
        Write-Step "Removing virtual environment: $venvDir"
        Remove-Item -Recurse -Force $venvDir -ErrorAction SilentlyContinue
        Write-Success "Virtual environment deleted."
    }

    Write-Success "Uninstallation complete."
    exit 0
}

# -------------------------------------------------------------
# 1. Discover Python Interpreter
# -------------------------------------------------------------
Write-Step "Discovering Python interpreter..."
$pyExe = $null

$pyLauncher = Get-Command "py.exe" -ErrorAction SilentlyContinue
if ($pyLauncher) {
    $testPy = & py -3 -c "import sys; print(sys.executable)" 2>$null
    if ($testPy -and (Test-Path $testPy)) {
        $pyExe = "py.exe"
    }
}

if (-not $pyExe) {
    $candidates = Get-Command "python.exe" -All -ErrorAction SilentlyContinue | Where-Object {
        $_.Source -notlike "*WindowsApps*"
    }
    foreach ($cand in $candidates) {
        $null = & $cand.Source -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $pyExe = $cand.Source
            break
        }
    }
}

if (-not $pyExe) {
    Write-Err "Python 3.9+ was not found on your system."
    Write-Host "Please install Python using winget:" -ForegroundColor Yellow
    Write-Host "  winget install Python.Python.3.12" -ForegroundColor White
    exit 1
}

$pyVersion = if ($pyExe -eq "py.exe") { & py -3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" } else { & "$pyExe" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" }
Write-Success "Found Python $pyVersion ($pyExe)"

# Pre-flight check for venv module
$hasVenv = if ($pyExe -eq "py.exe") { & py -3 -c "import venv; print('ok')" 2>$null } else { & "$pyExe" -c "import venv; print('ok')" 2>$null }
if ($hasVenv -ne "ok") {
    Write-Err "The 'venv' module is missing from your Python installation."
    exit 1
}

# -------------------------------------------------------------
# 2. Manage Isolated Virtual Environment
# -------------------------------------------------------------
$installRoot = Join-Path $HOME ".gemini\antigravity\tools"
$venvDir = Join-Path $installRoot "auto-permissions-env"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

if (-not (Test-Path $installRoot)) {
    New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
}

$needsVenv = $true
if (Test-Path $venvPython) {
    $venvPyVer = & "$venvPython" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
    if ($venvPyVer -eq $pyVersion) {
        $needsVenv = $false
        Write-Success "Reusing existing virtual environment: $venvDir"
    } else {
        Write-Warn "Existing venv used Python $venvPyVer, but active is $pyVersion. Rebuilding..."
        Remove-Item -Recurse -Force $venvDir -ErrorAction SilentlyContinue
    }
}

if ($needsVenv) {
    Write-Step "Creating isolated virtual environment at $venvDir..."
    if ($pyExe -eq "py.exe") {
        & py -3 -m venv "$venvDir"
    } else {
        & "$pyExe" -m venv "$venvDir"
    }
    if (-not (Test-Path $venvPython)) {
        Write-Err "Failed to create virtual environment."
        exit 1
    }
}

# -------------------------------------------------------------
# 3. Install Package
# -------------------------------------------------------------
Write-Step "Installing Auto Permissions Mode package..."
$isLocalClone = ($PSScriptRoot) -and (Test-Path (Join-Path $PSScriptRoot "pyproject.toml"))

if ($isLocalClone) {
    Write-Host "Installing from local source: $PSScriptRoot..." -ForegroundColor DarkGray
    & "$venvPython" -m pip install --no-cache-dir "$PSScriptRoot"
    if ($LASTEXITCODE -ne 0) {
        Write-Err "pip install failed with exit code $LASTEXITCODE"
        exit 1
    }
} else {
    Write-Host "Downloading latest release from GitHub..." -ForegroundColor DarkGray
    $tempZip = Join-Path $env:TEMP "auto-permissions-main.zip"
    try {
        Invoke-RestMethod -Uri "https://github.com/rahul-k-r/auto-permissions-mode/archive/refs/heads/main.zip" -OutFile $tempZip
        & "$venvPython" -m pip install --no-cache-dir --force-reinstall "$tempZip"
        if ($LASTEXITCODE -ne 0) {
            Write-Err "pip install failed with exit code $LASTEXITCODE"
            exit 1
        }
    } finally {
        if (Test-Path $tempZip) { Remove-Item -Force $tempZip -ErrorAction SilentlyContinue }
    }
}

$installedVer = & "$venvPython" -m auto_permissions.cli version 2>$null
Write-Success "Installed $installedVer"

# -------------------------------------------------------------
# 4. Hardware Detection & Configuration
# -------------------------------------------------------------
Write-Step "Detecting system hardware & VRAM..."
& "$venvPython" -m auto_permissions.cli detect

if (-not $NonInteractive) {
    # Interactive Onboarding Wizard
    & "$venvPython" -m auto_permissions.cli configure --global
} else {
    # Automated / Silent Setup Mode
    if (-not $Vram) {
        $detectedJson = & "$venvPython" -c "import json; from auto_permissions.hardware import detect_hardware; print(json.dumps(detect_hardware()))"
        try {
            $parsed = $detectedJson | ConvertFrom-Json
            $Vram = $parsed.recommended_tier
        } catch {
            $Vram = "8gb"
        }
    }
    
    $setupArgs = @("-m", "auto_permissions.cli", "setup", "--vram", $Vram, "--global")
    if ($Download) {
        $setupArgs += "--download"
    }
    & "$venvPython" @setupArgs
}

# -------------------------------------------------------------
# 5. Register Antigravity Hook & Verify
# -------------------------------------------------------------
Write-Step "Registering Antigravity PreToolUse hook..."
& "$venvPython" -m auto_permissions.cli install --global
if ($LASTEXITCODE -ne 0) {
    Write-Err "Hook registration failed with exit code $LASTEXITCODE"
    exit 1
}

Write-Step "Testing hook bridge integrity..."
& "$venvPython" -m auto_permissions.cli verify
if ($LASTEXITCODE -ne 0) {
    Write-Err "Hook verification failed"
    exit 1
}

if ($DesktopShortcuts) {
    Write-Step "Creating Desktop shortcuts..."
    & "$venvPython" -m auto_permissions.cli shortcuts
}

Write-Host @"
===============================================================
  🎉 Installation & Configuration Complete!
===============================================================
Antigravity Surfaces Protected:
  • Antigravity IDE
  • Antigravity 2.0
  • Antigravity VS Code Extension
  • Antigravity CLI (agy)

Management Commands:
  Live board   : & "$venvPython" -m auto_permissions.cli monitor
  Shortcuts    : & "$venvPython" -m auto_permissions.cli shortcuts
  Check status : & "$venvPython" -m auto_permissions.cli status
  Run wizard   : & "$venvPython" -m auto_permissions.cli configure
  Run tests    : & "$venvPython" -m auto_permissions.cli test
  Uninstall    : .\install.ps1 -Uninstall
===============================================================
"@ -ForegroundColor Green
