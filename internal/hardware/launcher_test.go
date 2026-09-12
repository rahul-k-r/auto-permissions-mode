package hardware_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rahul-k-r/auto-permissions-mode/internal/hardware"
)

func TestCreateLauncherScript(t *testing.T) {
	scriptPath, err := hardware.CreateLauncherScript("6gb", "C:\\models\\test.gguf")
	if err != nil {
		t.Fatalf("unexpected error creating launcher script: %v", err)
	}
	if scriptPath == "" {
		t.Fatal("expected non-empty launcher path")
	}

	data, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("failed to read generated launcher script: %v", err)
	}
	content := string(data)
	if !filepath.IsAbs(scriptPath) {
		t.Errorf("expected absolute script path, got %s", scriptPath)
	}
	if len(content) == 0 {
		t.Error("expected non-empty script content")
	}
}

func TestCopyFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "copyfile-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	src := filepath.Join(tmpDir, "source.txt")
	dst := filepath.Join(tmpDir, "dest.txt")

	if err := os.WriteFile(src, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := hardware.CopyFile(src, dst); err != nil {
		t.Fatalf("CopyFile failed: %v", err)
	}

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("failed to read copied file: %v", err)
	}
	if string(data) != "hello world" {
		t.Fatalf("expected 'hello world', got %s", string(data))
	}
}
