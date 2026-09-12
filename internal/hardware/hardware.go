package hardware

// HardwareInfo represents detected system capabilities.
type HardwareInfo struct {
	Type            string  `json:"type"`
	Name            string  `json:"name"`
	MemoryGB        float64 `json:"memory_gb"`
	RecommendedTier string  `json:"recommended_tier"`
}

type ModelProfile struct {
	Model       string `json:"model"`
	NumCtx      int    `json:"num_ctx"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

var VRAMProfiles = map[string]ModelProfile{
	"cpu": {
		Model:       "gemma-4-E2B-it-UD-Q3_K_XL.gguf",
		NumCtx:      4096,
		URL:         "https://huggingface.co/unsloth/gemma-4-E2B-it-GGUF/resolve/main/gemma-4-E2B-it-UD-Q3_K_XL.gguf",
		Description: "CPU-optimized lightweight profile",
	},
	"4gb": {
		Model:       "gemma-4-E4B-it-qat-UD-Q4_K_XL.gguf",
		NumCtx:      10240,
		URL:         "https://huggingface.co/unsloth/gemma-4-E4B-it-GGUF/resolve/main/gemma-4-E4B-it-qat-UD-Q4_K_XL.gguf",
		Description: "Fast reasoning profile (Gemma 4 E4B QAT + MTP, <20ms latency, 10k context)",
	},
	"6gb": {
		Model:       "gemma-4-E4B-it-qat-UD-Q4_K_XL.gguf",
		NumCtx:      16384,
		URL:         "https://huggingface.co/unsloth/gemma-4-E4B-it-GGUF/resolve/main/gemma-4-E4B-it-qat-UD-Q4_K_XL.gguf",
		Description: "Expanded context profile (Gemma 4 E4B QAT + MTP, 16k context)",
	},
	"8gb": {
		Model:       "Qwen3.5-9B-UD-Q4_K_XL.gguf",
		NumCtx:      36864,
		URL:         "https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/resolve/main/Qwen3.5-9B-UD-Q4_K_XL.gguf",
		Description: "Sweet spot daily driver (Qwen 3.5 9B, top code reasoning, 36k multi-agent pool)",
	},
	"12gb": {
		Model:       "gemma-4-12B-it-qat-UD-Q4_K_XL.gguf",
		NumCtx:      32768,
		URL:         "https://huggingface.co/unsloth/gemma-4-12B-it-GGUF/resolve/main/gemma-4-12B-it-qat-UD-Q4_K_XL.gguf",
		Description: "Maximum threat reasoning on 12GB cards (Gemma 4 12B QAT with MTP, 32k context)",
	},
	"16gb": {
		Model:       "gemma-4-26B-A4B-it-qat-UD-Q4_K_XL.gguf",
		NumCtx:      32768,
		URL:         "https://huggingface.co/unsloth/gemma-4-26B-A4B-it-GGUF/resolve/main/gemma-4-26B-A4B-it-qat-UD-Q4_K_XL.gguf",
		Description: "Mixture-of-Experts frontier profile (Gemma 4 26B A4B MoE, 32k context)",
	},
	"24gb": {
		Model:       "Qwen3.8-35B-UD-Q4_K_XL.gguf",
		NumCtx:      32768,
		URL:         "https://huggingface.co/unsloth/Qwen3.8-35B-GGUF/resolve/main/Qwen3.8-35B-UD-Q4_K_XL.gguf",
		Description: "Flagship enterprise dense reasoning profile (Qwen 3.8 35B, 32k context)",
	},
}

func TierFromGB(memGB float64) string {
	if memGB < 5.0 {
		return "4gb"
	} else if memGB < 7.5 {
		return "6gb"
	} else if memGB < 11.0 {
		return "8gb"
	} else if memGB < 15.0 {
		return "12gb"
	} else if memGB < 22.0 {
		return "16gb"
	}
	return "24gb"
}
