//go:build !windows

package hardware

func DetectHardware() HardwareInfo {
	return HardwareInfo{
		Type:            "cpu",
		Name:            "Generic CPU / System RAM",
		MemoryGB:        4.0,
		RecommendedTier: "cpu",
	}
}
