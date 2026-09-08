//go:build windows

package hardware

import (
	"encoding/binary"
	"math"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func DetectHardware() HardwareInfo {
	result := HardwareInfo{
		Type:            "cpu",
		Name:            "Generic CPU / System RAM",
		MemoryGB:        4.0,
		RecommendedTier: "cpu",
	}

	// 1. Check nvidia-smi
	if nvsmi, err := exec.LookPath("nvidia-smi"); err == nil {
		cmd := exec.Command(nvsmi, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits")
		if out, err := cmd.Output(); err == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			if len(lines) > 0 {
				parts := strings.Split(lines[0], ",")
				if len(parts) >= 2 {
					name := strings.TrimSpace(parts[0])
					if mb, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
						memGB := math.Round(mb/1024.0*10) / 10
						return HardwareInfo{
							Type:            "nvidia",
							Name:            name,
							MemoryGB:        memGB,
							RecommendedTier: TierFromGB(memGB),
						}
					}
				}
			}
		}
	}

	// 2. Windows Native Registry Walk
	baseKey := `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, baseKey, registry.READ)
	if err == nil {
		defer func() { _ = k.Close() }()
		subkeys, err := k.ReadSubKeyNames(-1)
		if err == nil {
			var bestGPU string
			var maxVRAM uint64

			for _, sub := range subkeys {
				sk, err := registry.OpenKey(k, sub, registry.READ)
				if err != nil {
					continue
				}

				desc, _, err := sk.GetStringValue("DriverDesc")
				if err != nil || desc == "" {
					_ = sk.Close()
					continue
				}
				lowerDesc := strings.ToLower(desc)
				if strings.Contains(lowerDesc, "virtual") || strings.Contains(lowerDesc, "remote") || strings.Contains(lowerDesc, "vga") {
					_ = sk.Close()
					continue
				}

				var bytesVal uint64
				qw, _, err := sk.GetIntegerValue("HardwareInformation.qwMemorySize")
				if err == nil {
					bytesVal = qw
				} else {
					rawBytes, _, err := sk.GetBinaryValue("HardwareInformation.qwMemorySize")
					if err == nil && len(rawBytes) == 8 {
						bytesVal = binary.LittleEndian.Uint64(rawBytes)
					} else {
						mem32, _, err := sk.GetIntegerValue("HardwareInformation.MemorySize")
						if err == nil {
							bytesVal = mem32
						} else {
							raw32, _, err := sk.GetBinaryValue("HardwareInformation.MemorySize")
							if err == nil && len(raw32) == 4 {
								bytesVal = uint64(binary.LittleEndian.Uint32(raw32))
							}
						}
					}
				}
				_ = sk.Close()

				if bytesVal > maxVRAM {
					maxVRAM = bytesVal
					bestGPU = desc
				}
			}

			if bestGPU != "" && maxVRAM >= 2*(1024*1024*1024) {
				memGB := math.Round(float64(maxVRAM)/(1024.0*1024.0*1024.0)*10) / 10
				gpuType := "gpu"
				lowerName := strings.ToLower(bestGPU)
				if strings.Contains(lowerName, "radeon") || strings.Contains(lowerName, "amd") {
					gpuType = "amd"
				} else if strings.Contains(lowerName, "intel") {
					gpuType = "intel"
				} else if strings.Contains(lowerName, "nvidia") || strings.Contains(lowerName, "geforce") || strings.Contains(lowerName, "rtx") {
					gpuType = "nvidia"
				}

				return HardwareInfo{
					Type:            gpuType,
					Name:            bestGPU,
					MemoryGB:        memGB,
					RecommendedTier: TierFromGB(memGB),
				}
			}
		}
	}

	return result
}
