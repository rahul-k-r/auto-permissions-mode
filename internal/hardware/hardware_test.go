package hardware_test

import (
	"testing"

	"github.com/rahul-k-r/auto-permissions-mode/internal/hardware"
)

func TestDetectHardware(t *testing.T) {
	info := hardware.DetectHardware()
	if info.Type == "" {
		t.Fatalf("expected non-empty hardware type")
	}
	if info.Name == "" {
		t.Fatalf("expected non-empty hardware name")
	}
	if info.MemoryGB <= 0 {
		t.Fatalf("expected positive memory GB, got %f", info.MemoryGB)
	}
	if info.RecommendedTier == "" {
		t.Fatalf("expected non-empty recommended tier")
	}
}

func TestHardwareTierFromGB(t *testing.T) {
	if hardware.TierFromGB(3.5) != "4gb" {
		t.Fatalf("expected 4gb")
	}
	if hardware.TierFromGB(5.0) != "6gb" {
		t.Fatalf("expected 6gb")
	}
	if hardware.TierFromGB(8.0) != "8gb" {
		t.Fatalf("expected 8gb")
	}
	if hardware.TierFromGB(12.0) != "12gb" {
		t.Fatalf("expected 12gb")
	}
	if hardware.TierFromGB(16.0) != "16gb" {
		t.Fatalf("expected 16gb")
	}
	if hardware.TierFromGB(24.0) != "24gb" {
		t.Fatalf("expected 24gb")
	}
}
