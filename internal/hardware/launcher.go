package hardware

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DownloadModel downloads the recommended GGUF model for the specified tier from Hugging Face.
func DownloadModel(tier string, targetDir string) (string, error) {
	normTier := strings.ToLower(strings.TrimSpace(tier))
	profile, ok := VRAMProfiles[normTier]
	if !ok {
		profile = VRAMProfiles["8gb"]
	}

	if targetDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		targetDir = filepath.Join(home, ".gemini", "antigravity", "models")
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return "", err
	}

	targetFile := filepath.Join(targetDir, profile.Model)
	if fi, err := os.Stat(targetFile); err == nil && fi.Size() > 0 {
		fmt.Printf("✓ Model already exists at: %s\n", targetFile)
		return targetFile, nil
	}

	partFile := targetFile + ".part"
	_ = os.Remove(partFile)

	fmt.Printf("📥 Downloading %s (~%s)...\n", profile.Model, profile.Description)
	fmt.Printf("   Source: %s\n", profile.URL)

	resp, err := http.Get(profile.URL)
	if err != nil {
		return "", fmt.Errorf("failed to initiate download: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad HTTP status: %s", resp.Status)
	}

	out, err := os.Create(partFile)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary download file: %w", err)
	}
	defer func() {
		_ = out.Close()
	}()

	totalSize := resp.ContentLength
	var downloaded int64

	buf := make([]byte, 64*1024)
	lastPrint := 0

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
				_ = os.Remove(partFile)
				return "", fmt.Errorf("write error: %w", writeErr)
			}
			downloaded += int64(n)

			if totalSize > 0 {
				percent := int(downloaded * 100 / totalSize)
				if percent != lastPrint || downloaded == totalSize {
					lastPrint = percent
					mbDownloaded := float64(downloaded) / (1024.0 * 1024.0)
					mbTotal := float64(totalSize) / (1024.0 * 1024.0)
					fmt.Printf("\r   Progress: %d%% [%.1f MB / %.1f MB]", percent, mbDownloaded, mbTotal)
				}
			} else {
				mbDownloaded := float64(downloaded) / (1024.0 * 1024.0)
				fmt.Printf("\r   Progress: %.1f MB downloaded", mbDownloaded)
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			_ = os.Remove(partFile)
			return "", fmt.Errorf("download interrupted: %w", readErr)
		}
	}

	_ = out.Close()
	if err := os.Rename(partFile, targetFile); err != nil {
		return "", fmt.Errorf("failed to finalize downloaded model file: %w", err)
	}

	fmt.Println("\n✓ Model downloaded successfully!")
	return targetFile, nil
}

// CreateLauncherScript generates the one-click local gatekeeper launch script and monitor script.
func CreateLauncherScript(tier string, modelPath string) (string, error) {
	normTier := strings.ToLower(strings.TrimSpace(tier))
	profile, ok := VRAMProfiles[normTier]
	if !ok {
		profile = VRAMProfiles["8gb"]
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	toolsDir := filepath.Join(home, ".gemini", "antigravity", "tools")
	if err := os.MkdirAll(toolsDir, 0755); err != nil {
		return "", err
	}

	resolvedModel := modelPath
	if resolvedModel == "" {
		resolvedModel = filepath.Join(home, ".gemini", "antigravity", "models", profile.Model)
	}

	exe, err := os.Executable()
	if err != nil {
		exe = "auto-permissions"
	}

	var launcherPath string
	if runtime.GOOS == "windows" {
		launcherPath = filepath.Join(toolsDir, "start-local-gatekeeper.bat")
		gatekeeperContent := fmt.Sprintf(`@echo off
title Auto Permissions Gatekeeper (Port 9931)
echo Starting local security gatekeeper on port 9931...
llama serve -m "%s" -c %d -ctk q4_0 -ctv q4_0 -ngl 99 --flash-attn on --port 9931
pause
`, resolvedModel, profile.NumCtx)

		if err := os.WriteFile(launcherPath, []byte(gatekeeperContent), 0644); err != nil {
			return "", err
		}

		monitorPath := filepath.Join(toolsDir, "open-monitor-board.bat")
		monitorContent := fmt.Sprintf(`@echo off
title Auto Permissions Live Audit Dashboard (Go Native)
"%s" monitor
pause
`, exe)
		_ = os.WriteFile(monitorPath, []byte(monitorContent), 0644)
	} else {
		launcherPath = filepath.Join(toolsDir, "start-local-gatekeeper.sh")
		gatekeeperContent := fmt.Sprintf(`#!/usr/bin/env bash
echo "Starting local security gatekeeper on port 9931..."
llama serve -m "%s" -c %d -ctk q4_0 -ctv q4_0 -ngl 99 --flash-attn on --port 9931
`, resolvedModel, profile.NumCtx)

		if err := os.WriteFile(launcherPath, []byte(gatekeeperContent), 0755); err != nil {
			return "", err
		}

		monitorPath := filepath.Join(toolsDir, "open-monitor-board.sh")
		monitorContent := fmt.Sprintf(`#!/usr/bin/env bash
"%s" monitor
`, exe)
		_ = os.WriteFile(monitorPath, []byte(monitorContent), 0755)
	}

	return launcherPath, nil
}

// CopyFile copies a file from src to dst.
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		_ = in.Close()
	}()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// InstallDesktopShortcuts copies start-local-gatekeeper and open-monitor-board to the user's Desktop.
func InstallDesktopShortcuts() (map[string]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	desktop := filepath.Join(home, "Desktop")
	if fi, err := os.Stat(desktop); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("desktop directory not found at: %s", desktop)
	}

	toolsDir := filepath.Join(home, ".gemini", "antigravity", "tools")
	created := make(map[string]string)

	if runtime.GOOS == "windows" {
		pairs := [][2]string{
			{"open-monitor-board.bat", "Auto Permissions Monitor.bat"},
			{"start-local-gatekeeper.bat", "Start Local Gatekeeper.bat"},
		}
		for _, pair := range pairs {
			src := filepath.Join(toolsDir, pair[0])
			dst := filepath.Join(desktop, pair[1])
			if _, err := os.Stat(src); err == nil {
				if err := CopyFile(src, dst); err == nil {
					created[pair[1]] = dst
				}
			}
		}
	} else {
		pairs := [][2]string{
			{"open-monitor-board.sh", "Auto Permissions Monitor.sh"},
			{"start-local-gatekeeper.sh", "Start Local Gatekeeper.sh"},
		}
		for _, pair := range pairs {
			src := filepath.Join(toolsDir, pair[0])
			dst := filepath.Join(desktop, pair[1])
			if _, err := os.Stat(src); err == nil {
				if err := CopyFile(src, dst); err == nil {
					_ = os.Chmod(dst, 0755)
					created[pair[1]] = dst
				}
			}
		}
	}

	return created, nil
}
