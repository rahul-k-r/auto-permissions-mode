package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rahul-k-r/auto-permissions-mode/internal/cli"
	"github.com/rahul-k-r/auto-permissions-mode/internal/config"
	"github.com/rahul-k-r/auto-permissions-mode/internal/hardware"
	"github.com/rahul-k-r/auto-permissions-mode/internal/hook"
	"github.com/rahul-k-r/auto-permissions-mode/internal/monitor"
	"github.com/rahul-k-r/auto-permissions-mode/internal/policy"
)

const version = "0.4.3-go"

func printUsage() {
	fmt.Print(`Auto Permissions Mode (Go Native) ` + version + `
Manage zero-latency autonomous permissions for Google Antigravity.

Usage:
  auto-permissions <command> [arguments]

Commands:
  hook           Execute the PreToolUse security evaluator hook (stdin -> stdout)
  install        Install hook and interactive decision rules into Antigravity
  uninstall      Remove hook and rules from Antigravity
  setup          Configure hardware VRAM preset, model launcher, and optional download
  configure      Run interactive guided setup wizard (alias: wizard)
  shortcuts      Create or refresh one-click desktop shortcuts for Monitor and Gatekeeper
  detect         Detect GPU VRAM and hardware tier
  policy         Inspect or switch active policy mode (balanced, strict, yolo)
  monitor        Open live terminal audit dashboard showing real-time tool calls & decisions (alias: board)
  status         Show installation state and security policy status
  verify         Verify live Antigravity hook pipeline bridge
  test           Run built-in security test cases against the active provider
  trust-ide      Enable IDE wildcard trust or decline for specified workspace
  version        Print binary version
`)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "hook":
		if err := hook.RunHook(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "install":
		installCmd := flag.NewFlagSet("install", flag.ExitOnError)
		globalFlag := installCmd.Bool("global", false, "Install globally in ~/.gemini")
		_ = installCmd.Parse(os.Args[2:])
		if cli.InstallHook(*globalFlag) {
			fmt.Println("✓ Installed successfully.")
		} else {
			fmt.Fprintln(os.Stderr, "Installation failed.")
			os.Exit(1)
		}
	case "uninstall":
		uninstallCmd := flag.NewFlagSet("uninstall", flag.ExitOnError)
		globalFlag := uninstallCmd.Bool("global", false, "Uninstall globally from ~/.gemini")
		purgeFlag := uninstallCmd.Bool("purge", false, "Purge local config")
		_ = uninstallCmd.Parse(os.Args[2:])
		cli.UninstallHook(*globalFlag, *purgeFlag)
	case "setup":
		setupCmd := flag.NewFlagSet("setup", flag.ExitOnError)
		vramFlag := setupCmd.String("vram", "", "VRAM tier (4gb, 6gb, 8gb, 12gb, 16gb, 24gb)")
		downloadFlag := setupCmd.Bool("download", false, "Download recommended model GGUF")
		localFlag := setupCmd.Bool("local", false, "Configure locally in .agents")
		_ = setupCmd.Parse(os.Args[2:])

		tier := *vramFlag
		if tier == "" {
			hw := hardware.DetectHardware()
			tier = hw.RecommendedTier
			if tier == "" {
				tier = "8gb"
			}
		}
		if !cli.SetupVramProfile(tier, !*localFlag, *downloadFlag) {
			os.Exit(1)
		}
	case "configure", "wizard":
		wizardCmd := flag.NewFlagSet("configure", flag.ExitOnError)
		localFlag := wizardCmd.Bool("local", false, "Configure locally in .agents")
		_ = wizardCmd.Parse(os.Args[2:])
		cli.RunWizard(!*localFlag)
	case "shortcuts":
		if !cli.InstallDesktopShortcutsCLI() {
			os.Exit(1)
		}
	case "test":
		if !cli.RunSelfTests() {
			os.Exit(1)
		}
	case "trust-ide":
		trustCmd := flag.NewFlagSet("trust-ide", flag.ExitOnError)
		wsFlag := trustCmd.String("workspace", "", "Target workspace path")
		declineFlag := trustCmd.Bool("decline", false, "Decline workspace trust")
		_ = trustCmd.Parse(os.Args[2:])
		if *declineFlag {
			if cli.DeclineIdeWorkspaceTrust(*wsFlag) {
				fmt.Println("✓ Workspace marked as declined.")
			}
		} else {
			if cli.EnableIdeWildcardTrust(*wsFlag) {
				fmt.Println("✓ Enabled IDE wildcard trust.")
			}
		}
	case "detect":
		info := hardware.DetectHardware()
		b, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(b))
	case "policy":
		cfg := config.LoadConfig()
		if len(os.Args) >= 3 {
			m := policy.NormalizeMode(os.Args[2])
			fmt.Printf("Normalized policy mode: %s\n", m)
		} else {
			fmt.Printf("Active policy mode: %s\n", cfg.PolicyMode)
		}
	case "monitor", "board":
		if err := monitor.RunLiveBoard(); err != nil {
			fmt.Fprintf(os.Stderr, "Monitor error: %v\n", err)
			os.Exit(1)
		}
	case "status":
		cli.ShowStatus()
	case "verify":
		if !cli.VerifyHook() {
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Printf("auto-permissions %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", subcmd)
		printUsage()
		os.Exit(1)
	}
}
